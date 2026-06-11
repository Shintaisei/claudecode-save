#!/usr/bin/env python3
"""Double-review score completed formal 27-chain CLOUSEAU runs.

This is intentionally separate from the run-only guard. It watches completed
formal run JSON files and scores each one twice with independent judge calls.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "data" / "current_experiment" / "cases" / "cbc_27_chain_stage_cases_2026-06-09.jsonl"
RESULT_ROOT = ROOT / "docs" / "current_experiment" / "results_2026-06-09" / "formal_27_chain_experiment_20260609"
GOLD_ROOT = ROOT / "data" / "current_experiment" / "gold" / "cbc_alert_behavior_chain_gold"
SCORER = ROOT / "src" / "clouseau_process_time" / "score_element_order_with_gpt.py"
VALIDATION_STEPS = (
    ROOT
    / "docs"
    / "current_experiment"
    / "chain_gold_validation_2026-06-09"
    / "chain_gold_db_validation_steps_2026-06-09.csv"
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def case_index(cases_path: Path) -> dict[str, dict[str, Any]]:
    return {case["instance_id"]: case for case in read_jsonl(cases_path)}


def discover_run_jsons(result_root: Path) -> list[Path]:
    return sorted((result_root / "runs").glob("*/*/*_run.json"))


def run_identity(run_json: Path, result_root: Path) -> tuple[str, str, str]:
    rel = run_json.relative_to(result_root / "runs")
    model = rel.parts[0]
    stage = rel.parts[1]
    instance_id = run_json.stem.removesuffix("_run")
    return model, stage, instance_id


def score_out_dir(score_root: Path, review_name: str, model: str, stage: str, instance_id: str) -> Path:
    return score_root / review_name / model / stage / instance_id


def score_result_path(score_root: Path, review_name: str, model: str, stage: str, instance_id: str) -> Path:
    return score_out_dir(score_root, review_name, model, stage, instance_id) / "score_result.json"


def totals_from_score(path: Path) -> dict[str, Any]:
    result = read_json(path)
    score = result.get("score") or {}
    return score.get("totals") or {}


def normalized_total(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 12)
    return value


def compare_reviews(review1: Path, review2: Path) -> dict[str, Any]:
    totals1 = totals_from_score(review1)
    totals2 = totals_from_score(review2)
    keys = sorted(set(totals1) | set(totals2))
    diffs: dict[str, dict[str, Any]] = {}
    for key in keys:
        left = normalized_total(totals1.get(key))
        right = normalized_total(totals2.get(key))
        if left != right:
            diffs[key] = {"review1": totals1.get(key), "review2": totals2.get(key)}
    return {
        "review1": str(review1),
        "review2": str(review2),
        "totals_match": not diffs,
        "total_differences": diffs,
    }


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def append_summary_csv(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "time_utc",
        "model",
        "stage",
        "instance_id",
        "review1_score_result",
        "review2_score_result",
        "totals_match",
        "different_total_keys",
    ]
    exists = path.exists()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})


def run_scorer(
    run_json: Path,
    out_dir: Path,
    gold: Path,
    stage: str,
    validation_steps: Path,
    judge_model: str | None,
    reasoning_effort: str,
) -> None:
    cmd = [
        sys.executable,
        str(SCORER),
        "--gold",
        str(gold),
        "--run-json",
        str(run_json),
        "--out-dir",
        str(out_dir),
        "--stage",
        stage,
        "--validation-steps",
        str(validation_steps),
        "--reasoning-effort",
        reasoning_effort,
    ]
    if judge_model:
        cmd.extend(["--model", judge_model])
    completed = subprocess.run(cmd, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"scorer failed for {run_json} (exit {completed.returncode})\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def score_one_pair(
    run_json: Path,
    case: dict[str, Any],
    score_root: Path,
    validation_steps: Path,
    judge_model: str | None,
    reasoning_effort: str,
    force: bool,
) -> dict[str, Any]:
    model, stage, instance_id = run_identity(run_json, RESULT_ROOT)
    gold = GOLD_ROOT / case["gold_chain_file"]
    review_paths = [
        score_result_path(score_root, "review1", model, stage, instance_id),
        score_result_path(score_root, "review2", model, stage, instance_id),
    ]
    for i, score_path in enumerate(review_paths, start=1):
        if score_path.exists() and not force:
            continue
        out_dir = score_out_dir(score_root, f"review{i}", model, stage, instance_id)
        run_scorer(run_json, out_dir, gold, stage, validation_steps, judge_model, reasoning_effort)
    comparison = compare_reviews(review_paths[0], review_paths[1])
    comparison_path = score_root / "comparisons" / model / stage / instance_id / "review_pair_summary.json"
    payload = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "stage": stage,
        "instance_id": instance_id,
        "run_json": str(run_json),
        "gold": str(gold),
        **comparison,
    }
    write_json(comparison_path, payload)
    append_jsonl(score_root / "double_review_log.jsonl", payload)
    append_summary_csv(
        score_root / "double_review_summary.csv",
        {
            "time_utc": payload["time_utc"],
            "model": model,
            "stage": stage,
            "instance_id": instance_id,
            "review1_score_result": str(review_paths[0]),
            "review2_score_result": str(review_paths[1]),
            "totals_match": comparison["totals_match"],
            "different_total_keys": ",".join(comparison["total_differences"].keys()),
        },
    )
    return payload


def completed_pair_count(score_root: Path) -> int:
    count = 0
    for first in (score_root / "review1").glob("*/*/*/score_result.json"):
        rel = first.relative_to(score_root / "review1")
        second = score_root / "review2" / rel
        if second.exists():
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--result-root", type=Path, default=RESULT_ROOT)
    parser.add_argument("--score-root", type=Path, default=RESULT_ROOT / "scores_double_review")
    parser.add_argument("--validation-steps", type=Path, default=VALIDATION_STEPS)
    parser.add_argument("--judge-model", default=None)
    parser.add_argument("--reasoning-effort", default="high")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=120)
    parser.add_argument("--target-count", type=int, default=162)
    parser.add_argument("--max-idle-polls", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    cases = case_index(args.cases)
    args.score_root.mkdir(parents=True, exist_ok=True)
    write_json(
        args.score_root / "double_review_manifest.json",
        {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "cases": str(args.cases),
            "result_root": str(args.result_root),
            "score_root": str(args.score_root),
            "validation_steps": str(args.validation_steps),
            "judge_model": args.judge_model,
            "reasoning_effort": args.reasoning_effort,
            "reviews_per_run": 2,
            "target_count": args.target_count,
        },
    )

    idle_polls = 0
    while True:
        scored_this_poll = 0
        run_jsons = discover_run_jsons(args.result_root)
        if args.limit is not None:
            run_jsons = run_jsons[: args.limit]
        for run_json in run_jsons:
            model, stage, instance_id = run_identity(run_json, args.result_root)
            case = cases.get(instance_id)
            if not case:
                raise KeyError(f"case not found for {instance_id}")
            first = score_result_path(args.score_root, "review1", model, stage, instance_id)
            second = score_result_path(args.score_root, "review2", model, stage, instance_id)
            if first.exists() and second.exists() and not args.force:
                continue
            payload = score_one_pair(
                run_json,
                case,
                args.score_root,
                args.validation_steps,
                args.judge_model,
                args.reasoning_effort,
                args.force,
            )
            scored_this_poll += 1
            print(json.dumps(payload, ensure_ascii=False), flush=True)
        done_pairs = completed_pair_count(args.score_root)
        status = {
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "completed_double_review_pairs": done_pairs,
            "available_run_jsons": len(discover_run_jsons(args.result_root)),
            "scored_this_poll": scored_this_poll,
            "watch": args.watch,
        }
        append_jsonl(args.score_root / "double_review_status.jsonl", status)
        print(json.dumps(status, ensure_ascii=False), flush=True)
        if not args.watch:
            break
        if done_pairs >= args.target_count:
            break
        if scored_this_poll:
            idle_polls = 0
        else:
            idle_polls += 1
            if args.max_idle_polls and idle_polls >= args.max_idle_polls:
                break
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
