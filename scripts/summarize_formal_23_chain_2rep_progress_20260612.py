from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_2rep_20260612"
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"
PROGRESS = SCORE_ROOT / "progress.json"
REPLICATES = ["replicate_01", "replicate_02"]
MODELS = ["gpt-4.1-mini", "gpt-5.4-mini"]
sys.path.insert(0, str(ROOT / "src" / "clouseau_process_time"))
import run_formal_27_chain_run_only_guarded as guarded  # noqa: E402


def load_cases() -> list[dict]:
    rows: list[dict] = []
    with CASE_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def run_records() -> list[dict]:
    records: list[dict] = []
    cases_by_instance = {case["instance_id"]: case for case in load_cases()}
    for replicate in REPLICATES:
        for path in (RUN_ROOT / replicate / "runs").glob("*/*/*_run.json"):
            rel = path.relative_to(RUN_ROOT).as_posix()
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                records.append(
                    {
                        "replicate": replicate,
                        "path": rel,
                        "parse_error": str(exc),
                    }
                )
                continue
            model = obj.get("model")
            instance_id = obj.get("instance_id")
            case = cases_by_instance.get(instance_id or "")
            validation_errors = guarded.validate_run(obj, case, model, path) if case and model else ["missing case/model"]
            records.append(
                {
                    "replicate": replicate,
                    "path": rel,
                    "model": model,
                    "stage": obj.get("experiment_stage"),
                    "instance_id": instance_id,
                    "estimated_cost_usd": ((obj.get("usage") or {}).get("estimated_cost_usd")),
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                }
            )
    return records


def ledger_records() -> list[dict]:
    if not LEDGER.exists():
        return []
    rows: list[dict] = []
    with LEDGER.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def logged_cost_by_run() -> dict[tuple[str, str], float]:
    costs: dict[tuple[str, str], float] = {}
    for replicate in REPLICATES:
        log_path = RUN_ROOT / replicate / "run_only_parallel_guard_log.jsonl"
        if not log_path.exists():
            continue
        with log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("status") != "completed":
                    continue
                key = (replicate, obj.get("instance_id") or "")
                costs[key] = float(obj.get("estimated_cost_usd") or 0.0)
    return costs


def main() -> None:
    cases = load_cases()
    runs = run_records()
    reviews = ledger_records()
    log_costs = logged_cost_by_run()

    expected_per_replicate = len(cases) * len(MODELS)
    expected_total = expected_per_replicate * len(REPLICATES)
    runs_by_rep = Counter(r["replicate"] for r in runs)
    valid_runs = [r for r in runs if r.get("valid")]
    invalid_runs = [r for r in runs if not r.get("valid")]
    valid_runs_by_rep = Counter(r["replicate"] for r in valid_runs)
    runs_by_model_stage: dict[str, Counter] = defaultdict(Counter)
    for r in valid_runs:
        runs_by_model_stage[r["replicate"]][(r.get("model"), r.get("stage"))] += 1

    cost_total = sum(
        log_costs.get((r["replicate"], r.get("instance_id") or ""), float(r.get("estimated_cost_usd") or 0.0))
        for r in valid_runs
    )
    adopted = sum(1 for r in reviews if r.get("two_review_adoptable") is True)

    progress = {
        "experiment": "formal_23_chain_2rep_20260612",
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "case_count": len(cases),
        "model_count": len(MODELS),
        "replicate_count": len(REPLICATES),
        "expected_run_count": expected_total,
        "raw_run_file_count": len(runs),
        "valid_completed_run_count": len(valid_runs),
        "invalid_run_file_count": len(invalid_runs),
        "remaining_valid_run_count": expected_total - len(valid_runs),
        "raw_run_file_count_by_replicate": {r: runs_by_rep.get(r, 0) for r in REPLICATES},
        "valid_completed_run_count_by_replicate": {r: valid_runs_by_rep.get(r, 0) for r in REPLICATES},
        "expected_run_count_per_replicate": expected_per_replicate,
        "reviewed_run_count": len(reviews),
        "adopted_review_count": adopted,
        "review_remaining_valid_run_count": len(valid_runs) - adopted,
        "estimated_completed_cost_usd": round(cost_total, 6),
        "invalid_runs": [
            {
                "replicate": r["replicate"],
                "path": r["path"],
                "model": r.get("model"),
                "stage": r.get("stage"),
                "instance_id": r.get("instance_id"),
                "validation_errors": r.get("validation_errors"),
            }
            for r in invalid_runs
        ],
        "runs_by_replicate_model_stage": {
            rep: {
                f"{model}_{stage}": count
                for (model, stage), count in sorted(counter.items())
            }
            for rep, counter in runs_by_model_stage.items()
        },
    }

    PROGRESS.write_text(json.dumps(progress, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(progress, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
