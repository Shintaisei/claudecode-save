#!/usr/bin/env python3
"""Run the formal 27-chain experiment without judge scoring, with per-run guards."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "data" / "current_experiment" / "cases" / "cbc_27_chain_stage_cases_2026-06-09.jsonl"
RUNNER = ROOT / "src" / "clouseau_process_time" / "run_clouseau_official_cbc_dense_eval.py"
RESULT_ROOT = ROOT / "docs" / "current_experiment" / "results_2026-06-09" / "formal_27_chain_experiment_20260609"
DEFAULT_MODELS = "gpt-4.1-mini,gpt-5.4-mini"

PRICES = {
    "gpt-4.1-mini": {"input": 0.40, "cached": 0.10, "output": 1.60},
    "gpt-5.4-mini": {"input": 0.75, "cached": 0.075, "output": 4.50},
}


def writable_path(path: Path) -> Path:
    if sys.platform != "win32":
        return path
    resolved = str(path.resolve())
    if resolved.startswith("\\\\?\\"):
        return Path(resolved)
    if resolved.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + resolved.lstrip("\\"))
    return Path("\\\\?\\" + resolved)


def write_json(path: Path, payload: Any) -> None:
    writable_path(path.parent).mkdir(parents=True, exist_ok=True)
    writable_path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_jsonl(path: Path, payload: Any) -> None:
    writable_path(path.parent).mkdir(parents=True, exist_ok=True)
    with writable_path(path).open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def emit(payload: Any) -> None:
    try:
        print(json.dumps(payload, ensure_ascii=False), flush=True)
    except (BrokenPipeError, OSError):
        pass


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def command_text(cmd: list[str]) -> str:
    return " ".join(f'"{part}"' if " " in part else part for part in cmd)


def build_run_command(case: dict[str, Any], model: str, args: argparse.Namespace) -> list[str]:
    cmd = [
        sys.executable,
        str(RUNNER),
        "--cases",
        str(args.cases),
        "--instance-id",
        case["instance_id"],
        "--model",
        model,
        "--difficulty",
        case["difficulty"],
        "--max-investigations",
        str(args.max_investigations),
        "--max-questions",
        str(args.max_questions),
        "--max-queries",
        str(args.max_queries),
        "--max-tokens",
        str(args.max_tokens),
        "--sql-playbook",
        args.sql_playbook,
    ]
    if case.get("stage") == "stage3":
        cmd.append("--exclude-cbc-alert-summary")
    if args.log_cost:
        cmd.append("--log-cost")
    return cmd


def expected_run_path(result_root: Path, model: str, case: dict[str, Any]) -> Path:
    return result_root / "runs" / model / case["stage"] / f"{case['instance_id']}_run.json"


def run_cost(model: str, payload: dict[str, Any]) -> float:
    usage = payload.get("usage") or {}
    prices = PRICES.get(model)
    if not prices:
        return 0.0
    input_tokens = usage.get("input_tokens") or 0
    cached_tokens = usage.get("cached_input_tokens") or 0
    output_tokens = usage.get("output_tokens") or 0
    noncached = max(input_tokens - cached_tokens, 0)
    return (
        noncached / 1_000_000 * prices["input"]
        + cached_tokens / 1_000_000 * prices["cached"]
        + output_tokens / 1_000_000 * prices["output"]
    )


def validate_run(payload: dict[str, Any], case: dict[str, Any], model: str, path: Path) -> list[str]:
    errors: list[str] = []
    if payload.get("dry_run") is not False:
        errors.append("dry_run is not false")
    if payload.get("error"):
        errors.append(f"top-level error present: {payload.get('error')}")
    if not payload.get("output_text"):
        errors.append("output_text is empty")
    if not payload.get("official_messages"):
        errors.append("official_messages is empty")
    usage = payload.get("usage") or {}
    if not ((usage.get("input_tokens") or 0) > 0 or (usage.get("output_tokens") or 0) > 0):
        errors.append("usage tokens are not positive")
    if payload.get("model") != model:
        errors.append(f"model mismatch: {payload.get('model')} != {model}")
    formal = payload.get("formal_27_chain_experiment") or {}
    if formal.get("stage") != case.get("stage"):
        errors.append(f"formal stage mismatch: {formal.get('stage')} != {case.get('stage')}")
    if formal.get("chain_id") != case.get("chain_id"):
        errors.append(f"formal chain_id mismatch: {formal.get('chain_id')} != {case.get('chain_id')}")
    if case.get("stage") == "stage3":
        counts = payload.get("adapter_counts") or {}
        if counts.get("cbc_alert_summary_filter_mode") != "sql_tool_temp_view":
            errors.append("Stage3 filter mode is not sql_tool_temp_view")
        if counts.get("post_filter_cbc_alert_summary_rows") != 0:
            errors.append("Stage3 post_filter_cbc_alert_summary_rows is not zero")
        if not ((counts.get("cbc_alert_summary_rows_hidden_from_stage3_sql") or 0) > 0):
            errors.append("Stage3 hidden alert summary rows are not positive")
        if not ((counts.get("post_filter_cbc_event_telemetry_rows") or 0) > 0):
            errors.append("Stage3 telemetry rows are not positive")
    if errors:
        errors.insert(0, f"invalid run: {path}")
    return errors


def copy_and_tag_run(source: Path, dest: Path, case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    writable_path(dest.parent).mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    payload = read_json(dest)
    payload["formal_27_chain_experiment"] = {
        "case_file": str(args.cases),
        "chain_id": case.get("chain_id"),
        "stage": case.get("stage"),
        "gold_chain_file": case.get("gold_chain_file"),
        "copied_from": str(source),
        "run_only_guarded": True,
    }
    write_json(dest, payload)
    return payload


def run_one(case: dict[str, Any], model: str, args: argparse.Namespace) -> tuple[Path, dict[str, Any], str]:
    dest = expected_run_path(args.result_root, model, case)
    if args.resume and dest.exists():
        payload = read_json(dest)
        errors = validate_run(payload, case, model, dest)
        if not errors:
            return dest, payload, "skipped_existing_valid"

    cmd = build_run_command(case, model, args)
    completed = subprocess.run(cmd, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "runner process failed for "
            f"{case['instance_id']} {model} (exit {completed.returncode})\n"
            f"COMMAND:\n{command_text(cmd)}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    output_paths = [Path(line.strip()) for line in completed.stdout.splitlines() if line.strip().endswith("run.json")]
    if not output_paths:
        raise RuntimeError(f"runner did not print a run.json path for {case['instance_id']} {model}")
    source = output_paths[-1]
    payload = copy_and_tag_run(source, dest, case, args)
    errors = validate_run(payload, case, model, dest)
    if errors:
        raise RuntimeError("\n".join(errors))
    return dest, payload, "completed"


def summarize(result_root: Path, cases: list[dict[str, Any]], models: list[str]) -> dict[str, Any]:
    rows = []
    total_cost = 0.0
    errors: list[str] = []
    for model in models:
        for case in cases:
            path = expected_run_path(result_root, model, case)
            if not path.exists():
                errors.append(f"missing run: {path}")
                continue
            payload = read_json(path)
            validation_errors = validate_run(payload, case, model, path)
            errors.extend(validation_errors)
            cost = run_cost(model, payload)
            total_cost += cost
            rows.append(
                {
                    "model": model,
                    "stage": case["stage"],
                    "instance_id": case["instance_id"],
                    "path": str(path),
                    "input_tokens": (payload.get("usage") or {}).get("input_tokens"),
                    "output_tokens": (payload.get("usage") or {}).get("output_tokens"),
                    "cached_input_tokens": (payload.get("usage") or {}).get("cached_input_tokens"),
                    "estimated_cost_usd": cost,
                }
            )
    stage3_rows = [row for row in rows if row["stage"] == "stage3"]
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "result_root": str(result_root),
        "expected_runs": len(cases) * len(models),
        "completed_runs": len(rows),
        "stage3_runs": len(stage3_rows),
        "estimated_cost_usd": total_cost,
        "errors": errors,
        "runs": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--result-root", type=Path, default=RESULT_ROOT)
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument("--max-investigations", type=int, default=300)
    parser.add_argument("--max-questions", type=int, default=800)
    parser.add_argument("--max-queries", type=int, default=1600)
    parser.add_argument("--max-tokens", type=int, default=24576)
    parser.add_argument("--sql-playbook", choices=["none", "generic"], default="none")
    parser.add_argument("--cost-check-usd", type=float, default=10.0)
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--log-cost", action="store_true")
    args = parser.parse_args()

    cases = read_jsonl(args.cases)
    models = split_csv(args.models)
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
        "score_api_used": False,
        "cost_check_usd": args.cost_check_usd,
    }
    write_json(args.result_root / "run_only_guard_manifest.json", manifest)

    log_path = args.result_root / "run_only_guard_log.jsonl"
    completed_cost = summarize(args.result_root, cases, models)["estimated_cost_usd"]
    for model in models:
        for case in cases:
            if completed_cost >= args.cost_check_usd:
                summary = summarize(args.result_root, cases, models)
                write_json(args.result_root / "run_only_guard_summary.json", summary)
                raise SystemExit(
                    f"Estimated run-only cost ${completed_cost:.4f} reached check threshold ${args.cost_check_usd:.2f}. "
                    "Stopping before next run."
                )
            started = datetime.now(timezone.utc).isoformat()
            dest, payload, status = run_one(case, model, args)
            cost = run_cost(model, payload)
            completed_cost += cost if status == "completed" else 0.0
            event = {
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "started_at_utc": started,
                "status": status,
                "model": model,
                "stage": case["stage"],
                "instance_id": case["instance_id"],
                "run_json": str(dest),
                "estimated_cost_usd": cost,
                "cumulative_estimated_cost_usd": completed_cost,
            }
            append_jsonl(log_path, event)
            emit(event)

    summary = summarize(args.result_root, cases, models)
    write_json(args.result_root / "run_only_guard_summary.json", summary)
    if summary["errors"]:
        raise SystemExit("run-only validation failed:\n" + "\n".join(summary["errors"]))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
