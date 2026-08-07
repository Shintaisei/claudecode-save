from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_replicate03_20260614"
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_replicate03_20260614"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"
PROGRESS = SCORE_ROOT / "progress.json"
REPLICATES = ["replicate_03"]
MODELS = ["gpt-4.1-mini", "gpt-5.4-mini"]

sys.path.insert(0, str(ROOT / "src" / "clouseau_process_time"))
import run_formal_27_chain_run_only_guarded as guarded  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_records(cases: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for replicate in REPLICATES:
        for model in MODELS:
            for case in cases:
                path = RUN_ROOT / replicate / "runs" / model / case["stage"] / f"{case['instance_id']}_run.json"
                if not path.exists():
                    rows.append({"replicate": replicate, "model": model, "stage": case["stage"], "instance_id": case["instance_id"], "valid": False, "missing": True, "validation_errors": ["missing run"]})
                    continue
                try:
                    obj = json.loads(path.read_text(encoding="utf-8"))
                    errors = guarded.validate_run(obj, case, model, path)
                except Exception as exc:  # noqa: BLE001
                    obj = {}
                    errors = [f"parse_error: {exc}"]
                rows.append(
                    {
                        "replicate": replicate,
                        "model": model,
                        "stage": case["stage"],
                        "instance_id": case["instance_id"],
                        "path": path.relative_to(ROOT).as_posix(),
                        "valid": not errors,
                        "missing": False,
                        "validation_errors": errors,
                        "estimated_cost_usd": ((obj.get("usage") or {}).get("estimated_cost_usd")) if isinstance(obj, dict) else None,
                    }
                )
    return rows


def review_key(row: dict) -> tuple[str, str, str, str]:
    return (row.get("replicate") or "", row.get("model") or "", row.get("stage") or "", row.get("instance_id") or "")


def main() -> None:
    cases = read_jsonl(CASE_FILE)
    runs = run_records(cases)
    reviews = read_jsonl(LEDGER)
    adopted_keys = {review_key(row) for row in reviews if row.get("two_review_adoptable") is True}
    valid_runs = [row for row in runs if row.get("valid")]
    invalid_runs = [row for row in runs if not row.get("valid") and not row.get("missing")]
    missing_runs = [row for row in runs if row.get("missing")]

    by_model_stage: dict[str, Counter] = defaultdict(Counter)
    for row in valid_runs:
        by_model_stage[row["replicate"]][(row["model"], row["stage"])] += 1

    progress = {
        "experiment": "formal_23_chain_replicate03_20260614",
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "case_count": len(cases),
        "model_count": len(MODELS),
        "replicate_count": len(REPLICATES),
        "expected_run_count": len(cases) * len(MODELS) * len(REPLICATES),
        "raw_run_file_count": sum(1 for row in runs if not row.get("missing")),
        "valid_completed_run_count": len(valid_runs),
        "invalid_run_file_count": len(invalid_runs),
        "missing_run_count": len(missing_runs),
        "adopted_review_count": len(adopted_keys),
        "review_remaining_valid_run_count": len(valid_runs) - len(adopted_keys),
        "estimated_completed_cost_usd": round(sum(float(row.get("estimated_cost_usd") or 0.0) for row in valid_runs), 6),
        "runs_by_replicate_model_stage": {
            rep: {f"{model}_{stage}": count for (model, stage), count in sorted(counter.items())}
            for rep, counter in by_model_stage.items()
        },
        "invalid_runs": invalid_runs[:20],
        "missing_examples": missing_runs[:20],
    }
    SCORE_ROOT.mkdir(parents=True, exist_ok=True)
    PROGRESS.write_text(json.dumps(progress, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(progress, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
