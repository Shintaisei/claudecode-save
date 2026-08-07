from __future__ import annotations

import argparse
import ast
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_gpt55_low_3rep_20260613"
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_salvage_20260614"
LEDGER = SCORE_ROOT / "codex_salvage_double_reviews.jsonl"
QUEUE = SCORE_ROOT / "review_queue_valid_unreviewed.jsonl"
STATUS = SCORE_ROOT / "review_queue_status.json"
GOLD_STEPS = ROOT / "data/current_experiment/gold/cbc_non_alert_behavior_chain_gold_2026-06-11/all_chain_steps.jsonl"
REPLICATES = ["replicate_01", "replicate_02", "replicate_03"]
MODELS = ["gpt-5.5"]

sys.path.insert(0, str(ROOT / "src" / "clouseau_process_time"))
import run_formal_27_chain_run_only_guarded as guarded  # noqa: E402


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def review_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("replicate") or ""),
        str(row.get("model") or ""),
        str(row.get("stage") or ""),
        str(row.get("instance_id") or ""),
    )


def extract_text(raw_output_text: str) -> tuple[str, str]:
    if not raw_output_text:
        return "", "empty"
    try:
        parsed = ast.literal_eval(raw_output_text)
    except Exception:
        return raw_output_text, "raw_string_not_literal"
    if isinstance(parsed, list):
        parts: list[str] = []
        for item in parsed:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        if parts:
            return "\n\n".join(parts), "responses_content_text_literal"
    return raw_output_text, "literal_without_text"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build GPT-5.5 raw-text salvage review queue.")
    parser.add_argument("--limit", type=int, default=0, help="Also write a timestamped batch with at most this many rows.")
    parser.add_argument("--min-batch-size", type=int, default=1)
    parser.add_argument("--flush-small-batch", action="store_true")
    args = parser.parse_args()

    cases = read_jsonl(CASE_FILE)
    gold_rows = read_jsonl(GOLD_STEPS)
    gold_by_chain: dict[str, list[dict[str, Any]]] = {}
    for row in gold_rows:
        gold_by_chain.setdefault(str(row.get("chain_id") or ""), []).append(row)
    for rows in gold_by_chain.values():
        rows.sort(key=lambda row: int(row.get("order") or 0))

    adopted_keys = {review_key(row) for row in read_jsonl(LEDGER) if row.get("two_review_adoptable") is True}
    valid_rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []

    for replicate in REPLICATES:
        for model in MODELS:
            for case in cases:
                path = RUN_ROOT / replicate / "runs" / model / case["stage"] / f"{case['instance_id']}_run.json"
                key = (replicate, model, case["stage"], case["instance_id"])
                if not path.exists():
                    missing_rows.append({"replicate": replicate, "model": model, "stage": case["stage"], "instance_id": case["instance_id"], "chain_id": case["chain_id"]})
                    continue
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    validation_errors = guarded.validate_run(payload, case, model, path)
                except Exception as exc:  # noqa: BLE001
                    payload = {}
                    validation_errors = [f"parse_error: {exc}"]
                if validation_errors:
                    invalid_rows.append({"replicate": replicate, "model": model, "stage": case["stage"], "instance_id": case["instance_id"], "chain_id": case["chain_id"], "path": path.relative_to(ROOT).as_posix(), "validation_errors": validation_errors})
                    continue
                if key in adopted_keys:
                    continue
                extracted_text, extraction_method = extract_text(str(payload.get("output_text") or ""))
                valid_rows.append(
                    {
                        "replicate": replicate,
                        "model": model,
                        "stage": case["stage"],
                        "instance_id": case["instance_id"],
                        "chain_id": case["chain_id"],
                        "chain_type": case.get("chain_type"),
                        "run_json": path.relative_to(ROOT).as_posix(),
                        "gold_steps_jsonl": GOLD_STEPS.relative_to(ROOT).as_posix(),
                        "gold_step_count": len(gold_by_chain.get(str(case["chain_id"]), [])),
                        "evaluation_unit": "salvage_raw_text_behavior_plus_evidence_step",
                        "format_failure_note": "正式出力契約のJSON/code_stepsではないため、本文から読み取れる行動・証跡だけをCodexが手動採点する。",
                        "output_text_extraction_method": extraction_method,
                        "extracted_text_char_count": len(extracted_text),
                    }
                )

    SCORE_ROOT.mkdir(parents=True, exist_ok=True)
    QUEUE.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in valid_rows), encoding="utf-8")
    batch_path = None
    should_write_batch = args.limit > 0 and valid_rows and (len(valid_rows) >= args.min_batch_size or args.flush_small_batch)
    if should_write_batch:
        batch_dir = SCORE_ROOT / "review_batches"
        batch_dir.mkdir(parents=True, exist_ok=True)
        batch_path = batch_dir / f"batch_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{min(args.limit, len(valid_rows))}.jsonl"
        batch_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in valid_rows[: args.limit]), encoding="utf-8")

    status = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_run_count": len(cases) * len(MODELS) * len(REPLICATES),
        "valid_unreviewed_count": len(valid_rows),
        "invalid_run_count": len(invalid_rows),
        "missing_run_count": len(missing_rows),
        "adopted_review_count": len(adopted_keys),
        "queue_path": QUEUE.relative_to(ROOT).as_posix(),
        "batch_path": batch_path.relative_to(ROOT).as_posix() if batch_path else None,
        "batch_limit": args.limit,
        "min_batch_size": args.min_batch_size,
        "flush_small_batch": args.flush_small_batch,
        "invalid_runs": invalid_rows[:20],
    }
    STATUS.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
