from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_2rep_20260612"
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"
QUEUE = SCORE_ROOT / "review_queue_valid_unreviewed.jsonl"
STATUS = SCORE_ROOT / "review_queue_status.json"
GOLD_ROOT = ROOT / "data/current_experiment/gold/cbc_non_alert_behavior_chain_gold_2026-06-11"
REPLICATES = ["replicate_01", "replicate_02"]
MODELS = ["gpt-4.1-mini", "gpt-5.4-mini"]

sys.path.insert(0, str(ROOT / "src" / "clouseau_process_time"))
import run_formal_27_chain_run_only_guarded as guarded  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def review_key(row: dict) -> tuple[str, str, str, str]:
    return (
        row.get("replicate") or "",
        row.get("model") or "",
        row.get("stage") or "",
        row.get("instance_id") or "",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build valid-unreviewed Codex review queue for the 23-chain experiment.")
    parser.add_argument("--limit", type=int, default=0, help="Also write a timestamped batch with at most this many rows.")
    args = parser.parse_args()

    cases = read_jsonl(CASE_FILE)
    cases_by_instance = {case["instance_id"]: case for case in cases}
    adopted_keys = {
        review_key(row)
        for row in read_jsonl(LEDGER)
        if row.get("two_review_adoptable") is True
    }

    valid_rows: list[dict] = []
    invalid_rows: list[dict] = []
    missing_rows: list[dict] = []
    for replicate in REPLICATES:
        for model in MODELS:
            for case in cases:
                path = RUN_ROOT / replicate / "runs" / model / case["stage"] / f"{case['instance_id']}_run.json"
                key = (replicate, model, case["stage"], case["instance_id"])
                if not path.exists():
                    missing_rows.append(
                        {
                            "replicate": replicate,
                            "model": model,
                            "stage": case["stage"],
                            "instance_id": case["instance_id"],
                            "chain_id": case["chain_id"],
                        }
                    )
                    continue
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except Exception as exc:  # noqa: BLE001
                    invalid_rows.append(
                        {
                            "replicate": replicate,
                            "model": model,
                            "stage": case["stage"],
                            "instance_id": case["instance_id"],
                            "path": path.relative_to(ROOT).as_posix(),
                            "validation_errors": [f"parse_error: {exc}"],
                        }
                    )
                    continue
                validation_errors = guarded.validate_run(payload, case, model, path)
                if validation_errors:
                    invalid_rows.append(
                        {
                            "replicate": replicate,
                            "model": model,
                            "stage": case["stage"],
                            "instance_id": case["instance_id"],
                            "chain_id": case["chain_id"],
                            "path": path.relative_to(ROOT).as_posix(),
                            "validation_errors": validation_errors,
                        }
                    )
                    continue
                if key in adopted_keys:
                    continue
                valid_rows.append(
                    {
                        "replicate": replicate,
                        "model": model,
                        "stage": case["stage"],
                        "instance_id": case["instance_id"],
                        "chain_id": case["chain_id"],
                        "run_json": path.relative_to(ROOT).as_posix(),
                        "gold_steps_jsonl": (GOLD_ROOT / "all_chain_steps.jsonl").relative_to(ROOT).as_posix(),
                        "gold_index_json": (GOLD_ROOT / "chain_gold_index.json").relative_to(ROOT).as_posix(),
                        "evaluation_unit": "behavior_plus_evidence_step",
                    }
                )

    SCORE_ROOT.mkdir(parents=True, exist_ok=True)
    QUEUE.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in valid_rows),
        encoding="utf-8",
    )

    batch_path = None
    if args.limit > 0 and valid_rows:
        batch_dir = SCORE_ROOT / "review_batches"
        batch_dir.mkdir(parents=True, exist_ok=True)
        batch_path = batch_dir / f"batch_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{min(args.limit, len(valid_rows))}.jsonl"
        batch_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in valid_rows[: args.limit]),
            encoding="utf-8",
        )

    status = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_run_count": len(cases) * len(MODELS) * len(REPLICATES),
        "valid_unreviewed_count": len(valid_rows),
        "invalid_run_count": len(invalid_rows),
        "missing_run_count": len(missing_rows),
        "adopted_review_count": len(adopted_keys),
        "queue_path": QUEUE.relative_to(ROOT).as_posix(),
        "batch_path": batch_path.relative_to(ROOT).as_posix() if batch_path else None,
        "invalid_runs": invalid_rows,
    }
    STATUS.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
