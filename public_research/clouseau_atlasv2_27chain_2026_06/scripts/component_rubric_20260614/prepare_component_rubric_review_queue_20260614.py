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
GOLD_STEPS = ROOT / "data/current_experiment/gold/cbc_non_alert_behavior_chain_gold_2026-06-11/all_chain_steps.jsonl"
SCORE_ROOT = ROOT / "data/current_experiment/scores/component_rubric_20260614"
LEDGER = SCORE_ROOT / "codex_component_double_reviews.jsonl"
QUEUE = SCORE_ROOT / "review_queue_valid_unreviewed.jsonl"
STATUS = SCORE_ROOT / "review_queue_status.json"

RUN_SPECS = [
    {
        "dataset_label": "gpt-4.1-mini_2rep_component",
        "run_root": ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_2rep_20260612",
        "replicates": ["replicate_01", "replicate_02"],
        "models": ["gpt-4.1-mini"],
        "contract": "formal_json_code_steps",
    },
    {
        "dataset_label": "gpt-5.4-mini_2rep_component",
        "run_root": ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_2rep_20260612",
        "replicates": ["replicate_01", "replicate_02"],
        "models": ["gpt-5.4-mini"],
        "contract": "formal_json_code_steps",
    },
    {
        "dataset_label": "gpt-4.1-mini_rep3_component",
        "run_root": ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_replicate03_20260614",
        "replicates": ["replicate_03"],
        "models": ["gpt-4.1-mini"],
        "contract": "formal_json_code_steps",
    },
    {
        "dataset_label": "gpt-5.4-mini_rep3_component",
        "run_root": ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_replicate03_20260614",
        "replicates": ["replicate_03"],
        "models": ["gpt-5.4-mini"],
        "contract": "formal_json_code_steps",
    },
    {
        "dataset_label": "gpt-5.5_low_raw_component",
        "run_root": ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_gpt55_low_3rep_20260613",
        "replicates": ["replicate_01", "replicate_02", "replicate_03"],
        "models": ["gpt-5.5"],
        "contract": "raw_text_contract_failed",
    },
]

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


def parse_code_steps(payload: dict[str, Any]) -> tuple[int | None, str]:
    text = str(payload.get("output_text") or "")
    if not text.strip():
        return 0, "empty_output_text"
    try:
        parsed = json.loads(text)
    except Exception:
        return None, "output_text_not_json"
    steps = parsed.get("code_steps") if isinstance(parsed, dict) else None
    if not isinstance(steps, list):
        return None, "json_without_code_steps"
    return len(steps), "formal_json_code_steps"


def extract_raw_text(payload: dict[str, Any]) -> tuple[str, str]:
    raw_output_text = str(payload.get("output_text") or "")
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
    parser = argparse.ArgumentParser(description="Build component-rubric Codex review queue.")
    parser.add_argument("--limit", type=int, default=0, help="Also write a timestamped batch with at most this many rows.")
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
    available_counts: dict[str, int] = {}

    for spec in RUN_SPECS:
        run_root = Path(spec["run_root"])
        for replicate in spec["replicates"]:
            for model in spec["models"]:
                for case in cases:
                    stage = str(case["stage"])
                    instance_id = str(case["instance_id"])
                    chain_id = str(case["chain_id"])
                    path = run_root / replicate / "runs" / model / stage / f"{instance_id}_run.json"
                    key = (replicate, model, stage, instance_id)
                    count_key = f"{spec['dataset_label']}::{replicate}::{model}::{stage}"
                    if not path.exists():
                        missing_rows.append(
                            {
                                "dataset_label": spec["dataset_label"],
                                "replicate": replicate,
                                "model": model,
                                "stage": stage,
                                "instance_id": instance_id,
                                "chain_id": chain_id,
                            }
                        )
                        continue
                    try:
                        payload = json.loads(path.read_text(encoding="utf-8"))
                        validation_errors = guarded.validate_run(payload, case, model, path)
                    except Exception as exc:  # noqa: BLE001
                        payload = {}
                        validation_errors = [f"parse_error: {exc}"]
                    if validation_errors:
                        invalid_rows.append(
                            {
                                "dataset_label": spec["dataset_label"],
                                "replicate": replicate,
                                "model": model,
                                "stage": stage,
                                "instance_id": instance_id,
                                "chain_id": chain_id,
                                "path": path.relative_to(ROOT).as_posix(),
                                "validation_errors": validation_errors,
                            }
                        )
                        continue
                    available_counts[count_key] = available_counts.get(count_key, 0) + 1
                    if key in adopted_keys:
                        continue

                    gold_step_count = len(gold_by_chain.get(chain_id, []))
                    candidate_step_count, output_parse_mode = parse_code_steps(payload)
                    raw_text, raw_text_mode = extract_raw_text(payload)
                    needs_raw_normalization = spec["contract"] == "raw_text_contract_failed" or candidate_step_count is None

                    valid_rows.append(
                        {
                            "dataset_label": spec["dataset_label"],
                            "replicate": replicate,
                            "model": model,
                            "stage": stage,
                            "instance_id": instance_id,
                            "chain_id": chain_id,
                            "chain_type": case.get("chain_type"),
                            "run_json": path.relative_to(ROOT).as_posix(),
                            "gold_steps_jsonl": GOLD_STEPS.relative_to(ROOT).as_posix(),
                            "evaluation_unit": "component_rubric_subject_action_object_evidence",
                            "contract": spec["contract"],
                            "format_failure_note": "GPT-5.5 is raw-text salvage when contract=raw_text_contract_failed; report it separately from formal JSON compliance.",
                            "needs_raw_normalization": needs_raw_normalization,
                            "output_parse_mode": output_parse_mode,
                            "raw_text_extraction_method": raw_text_mode,
                            "raw_text_char_count": len(raw_text),
                            "gold_step_count": gold_step_count,
                            "action_step_recall_total": gold_step_count * 3,
                            "critical_evidence_recall_total": gold_step_count,
                            "behavior_sequence_order_total": max(gold_step_count - 1, 0),
                            "candidate_step_count_hint": candidate_step_count,
                        }
                    )

    SCORE_ROOT.mkdir(parents=True, exist_ok=True)
    QUEUE.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in valid_rows), encoding="utf-8")

    batch_path = None
    if args.limit > 0 and valid_rows:
        batch_dir = SCORE_ROOT / "review_batches"
        batch_dir.mkdir(parents=True, exist_ok=True)
        batch_path = batch_dir / f"component_batch_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{min(args.limit, len(valid_rows))}.jsonl"
        batch_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in valid_rows[: args.limit]), encoding="utf-8")

    status = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "available_run_count": sum(available_counts.values()),
        "valid_unreviewed_count": len(valid_rows),
        "adopted_review_count": len(adopted_keys),
        "invalid_run_count": len(invalid_rows),
        "missing_run_count": len(missing_rows),
        "available_counts": dict(sorted(available_counts.items())),
        "queue_path": QUEUE.relative_to(ROOT).as_posix(),
        "batch_path": batch_path.relative_to(ROOT).as_posix() if batch_path else None,
        "missing_examples": missing_rows[:20],
        "invalid_examples": invalid_rows[:20],
    }
    STATUS.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
