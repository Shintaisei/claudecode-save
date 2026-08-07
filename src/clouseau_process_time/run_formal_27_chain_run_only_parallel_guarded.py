#!/usr/bin/env python3
"""Parallel resume runner for the formal 27-chain run-only experiment."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import run_formal_27_chain_run_only_guarded as base


def valid_existing(path: Path, case: dict[str, Any], model: str) -> bool:
    if not path.exists():
        return False
    payload = base.read_json(path)
    return not base.validate_run(payload, case, model, path)


def build_tasks(cases: list[dict[str, Any]], models: list[str], args: argparse.Namespace) -> list[tuple[str, dict[str, Any]]]:
    skip_instances = set(base.split_csv(args.skip_instances))
    tasks: list[tuple[str, dict[str, Any]]] = []
    for model in models:
        for case in cases:
            if case["instance_id"] in skip_instances:
                continue
            dest = base.expected_run_path(args.result_root, model, case)
            if args.resume and valid_existing(dest, case, model):
                continue
            tasks.append((model, case))
    return tasks


def worker_run(model: str, case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    dest, payload, status = base.run_one(case, model, args)
    cost = base.run_cost(model, payload)
    return {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": started,
        "status": status,
        "model": model,
        "stage": case["stage"],
        "instance_id": case["instance_id"],
        "run_json": str(dest),
        "estimated_cost_usd": cost,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=base.CASES)
    parser.add_argument("--result-root", type=Path, default=base.RESULT_ROOT)
    parser.add_argument("--models", default=base.DEFAULT_MODELS)
    parser.add_argument("--max-investigations", type=int, default=300)
    parser.add_argument("--max-questions", type=int, default=800)
    parser.add_argument("--max-queries", type=int, default=1600)
    parser.add_argument("--max-tokens", type=int, default=24576)
    parser.add_argument("--reasoning-effort", choices=["low", "medium", "high", "xhigh"], default=None)
    parser.add_argument("--sql-playbook", choices=["none", "generic"], default="none")
    parser.add_argument("--cost-check-usd", type=float, default=10.0)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--skip-instances", default="")
    parser.add_argument("--log-cost", action="store_true")
    args = parser.parse_args()

    cases = base.read_jsonl(args.cases)
    models = base.split_csv(args.models)
    args.result_root.mkdir(parents=True, exist_ok=True)

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "case_file": str(args.cases),
        "case_count": len(cases),
        "stage_counts": {stage: sum(1 for case in cases if case.get("stage") == stage) for stage in ["stage1", "stage2", "stage3"]},
        "models": models,
        "run_command_count": len(cases) * len(models),
        "max_investigations": args.max_investigations,
        "max_questions": args.max_questions,
        "max_queries": args.max_queries,
        "max_tokens": args.max_tokens,
        "reasoning_effort": args.reasoning_effort,
        "score_api_used": False,
        "cost_check_usd": args.cost_check_usd,
        "workers": args.workers,
        "skip_instances": base.split_csv(args.skip_instances),
        "parallel_run_only_guarded": True,
    }
    base.write_json(args.result_root / "run_only_parallel_guard_manifest.json", manifest)

    completed_cost = base.summarize(args.result_root, cases, models)["estimated_cost_usd"]
    if completed_cost >= args.cost_check_usd:
        summary = base.summarize(args.result_root, cases, models)
        base.write_json(args.result_root / "run_only_guard_summary.json", summary)
        raise SystemExit(
            f"Estimated run-only cost ${completed_cost:.4f} reached check threshold ${args.cost_check_usd:.2f}. "
            "Stopping before launching parallel runs."
        )

    tasks = build_tasks(cases, models, args)
    plan = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "status": "parallel_plan",
        "workers": args.workers,
        "missing_task_count": len(tasks),
        "completed_cost_before_usd": completed_cost,
        "first_tasks": [{"model": model, "stage": case["stage"], "instance_id": case["instance_id"]} for model, case in tasks[:20]],
    }
    log_path = args.result_root / "run_only_parallel_guard_log.jsonl"
    base.append_jsonl(log_path, plan)
    base.emit(plan)

    failures: list[str] = []
    workers = max(args.workers, 1)
    next_task = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_task: dict[concurrent.futures.Future[dict[str, Any]], tuple[str, dict[str, Any]]] = {}
        while next_task < len(tasks) and len(future_to_task) < workers:
            model, case = tasks[next_task]
            future_to_task[executor.submit(worker_run, model, case, args)] = (model, case)
            next_task += 1

        while future_to_task:
            done, _ = concurrent.futures.wait(future_to_task, return_when=concurrent.futures.FIRST_COMPLETED)
            future = next(iter(done))
            model, case = future_to_task[future]
            del future_to_task[future]
            try:
                event = future.result()
            except Exception as exc:  # noqa: BLE001 - preserve runner failure context.
                event = {
                    "time_utc": datetime.now(timezone.utc).isoformat(),
                    "status": "failed",
                    "model": model,
                    "stage": case["stage"],
                    "instance_id": case["instance_id"],
                    "error": str(exc),
                }
                failures.append(str(exc))
            else:
                completed_cost += event["estimated_cost_usd"] if event["status"] == "completed" else 0.0
                event["cumulative_estimated_cost_usd"] = completed_cost
            base.append_jsonl(log_path, event)
            base.emit(event)
            if failures:
                break
            if completed_cost >= args.cost_check_usd:
                failures.append(
                    f"Estimated run-only cost ${completed_cost:.4f} reached check threshold ${args.cost_check_usd:.2f}."
                )
                break
            while next_task < len(tasks) and len(future_to_task) < workers:
                model, case = tasks[next_task]
                future_to_task[executor.submit(worker_run, model, case, args)] = (model, case)
                next_task += 1

        for future in future_to_task:
            future.cancel()

    summary = base.summarize(args.result_root, cases, models)
    base.write_json(args.result_root / "run_only_guard_summary.json", summary)
    if failures:
        raise SystemExit("parallel run-only failed/stopped:\n" + "\n".join(failures))
    if summary["errors"]:
        raise SystemExit("run-only validation failed:\n" + "\n".join(summary["errors"]))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
