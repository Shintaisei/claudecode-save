#!/usr/bin/env python3
"""Prepare, run, and score the finalized 27-chain CLOUSEAU experiment."""

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
CASE_BUILDER = ROOT / "src" / "clouseau_process_time" / "build_chain_experiment_cases.py"
RUNNER = ROOT / "src" / "clouseau_process_time" / "run_clouseau_official_cbc_dense_eval.py"
SCORER = ROOT / "src" / "clouseau_process_time" / "score_element_order_with_gpt.py"
GOLD_ROOT = ROOT / "data" / "current_experiment" / "gold" / "cbc_alert_behavior_chain_gold"
VALIDATION_STEPS = (
    ROOT
    / "docs"
    / "current_experiment"
    / "chain_gold_validation_2026-06-09"
    / "chain_gold_db_validation_steps_2026-06-09.csv"
)
RESULT_ROOT = ROOT / "docs" / "current_experiment" / "results_2026-06-09" / "formal_27_chain_experiment_20260609"
DEFAULT_MODELS = "gpt-4.1-mini,gpt-5.4-mini"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def ensure_cases(path: Path, force: bool) -> None:
    if path.exists() and not force:
        return
    subprocess.run([sys.executable, str(CASE_BUILDER), "--out", str(path)], cwd=ROOT, check=True)


def select_cases(cases: list[dict[str, Any]], stages: list[str], limit: int | None) -> list[dict[str, Any]]:
    selected = [case for case in cases if case.get("stage") in stages]
    if limit is not None:
        selected = selected[:limit]
    return selected


def build_run_command(case: dict[str, Any], model: str, args: argparse.Namespace, dry_run: bool) -> list[str]:
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
    if dry_run:
        cmd.append("--dry-run")
    if args.log_cost:
        cmd.append("--log-cost")
    return cmd


def run_runner(case: dict[str, Any], model: str, args: argparse.Namespace, dry_run: bool) -> Path:
    cmd = build_run_command(case, model, args, dry_run)
    completed = subprocess.run(cmd, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "runner failed for "
            f"{case['instance_id']} {model} (exit {completed.returncode})\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    output_paths = [Path(line.strip()) for line in completed.stdout.splitlines() if line.strip().endswith("run.json")]
    if not output_paths:
        raise RuntimeError(f"runner did not print a run.json path for {case['instance_id']} {model}")
    source = output_paths[-1]
    bucket = "dry_runs" if dry_run else "runs"
    dest = args.result_root / bucket / model / case["stage"] / f"{case['instance_id']}_run.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    payload = json.loads(dest.read_text(encoding="utf-8"))
    payload["formal_27_chain_experiment"] = {
        "case_file": str(args.cases),
        "chain_id": case.get("chain_id"),
        "stage": case.get("stage"),
        "gold_chain_file": case.get("gold_chain_file"),
        "copied_from": str(source),
    }
    write_json(dest, payload)
    return dest


def score_one(run_json: Path, case: dict[str, Any], model: str, args: argparse.Namespace) -> Path:
    out_dir = args.result_root / "scores" / model / case["stage"] / case["instance_id"]
    gold = GOLD_ROOT / case["gold_chain_file"]
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
        case["stage"],
        "--validation-steps",
        str(args.validation_steps),
    ]
    subprocess.run(cmd, cwd=ROOT, check=True)
    return out_dir / "score_result.json"


def command_text(cmd: list[str]) -> str:
    return " ".join(f'"{part}"' if " " in part else part for part in cmd)


def build_manifest(cases: list[dict[str, Any]], models: list[str], args: argparse.Namespace) -> dict[str, Any]:
    stage_counts: dict[str, int] = {}
    for case in cases:
        stage_counts[case["stage"]] = stage_counts.get(case["stage"], 0) + 1
    run_commands = [
        command_text(build_run_command(case, model, args, dry_run=False))
        for model in models
        for case in cases
    ]
    dry_run_commands = [
        command_text(build_run_command(case, model, args, dry_run=True))
        for model in models
        for case in cases
    ]
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "case_file": str(args.cases),
        "case_count": len(cases),
        "stage_counts": stage_counts,
        "models": models,
        "result_root": str(args.result_root),
        "validation_steps": str(args.validation_steps),
        "run_command_count": len(run_commands),
        "score_policy": {
            "stage1_stage2": "score every chain against its by_chain/chain_gold.json",
            "stage3": "score only validation rows with stage3_status=pass; chains with zero answerable steps are marked skipped with zero denominator",
        },
        "sample_dry_run_commands": dry_run_commands[: min(6, len(dry_run_commands))],
        "sample_run_commands": run_commands[: min(6, len(run_commands))],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--result-root", type=Path, default=RESULT_ROOT)
    parser.add_argument("--validation-steps", type=Path, default=VALIDATION_STEPS)
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument("--stage", action="append", choices=["stage1", "stage2", "stage3"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--prepare-cases", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--score", action="store_true")
    parser.add_argument("--max-investigations", type=int, default=100)
    parser.add_argument("--max-questions", type=int, default=200)
    parser.add_argument("--max-queries", type=int, default=400)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--sql-playbook", choices=["none", "generic"], default="none")
    parser.add_argument("--log-cost", action="store_true")
    args = parser.parse_args()

    ensure_cases(args.cases, args.prepare_cases)
    all_cases = select_cases(read_jsonl(args.cases), ["stage1", "stage2", "stage3"], None)
    cases = select_cases(read_jsonl(args.cases), args.stage or ["stage1", "stage2", "stage3"], args.limit)
    models = split_csv(args.models)
    args.result_root.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(all_cases, split_csv(DEFAULT_MODELS), args)
    write_json(args.result_root / "manifest.json", manifest)
    selection_manifest = build_manifest(cases, models, args)
    write_json(args.result_root / "selection_manifest.json", selection_manifest)

    run_outputs: list[tuple[Path, dict[str, Any], str]] = []
    if args.dry_run:
        for model in models:
            for case in cases:
                run_outputs.append((run_runner(case, model, args, dry_run=True), case, model))
    if args.run:
        for model in models:
            for case in cases:
                run_outputs.append((run_runner(case, model, args, dry_run=False), case, model))

    score_outputs: list[Path] = []
    if args.score:
        if not run_outputs:
            for model in models:
                for case in cases:
                    candidate = args.result_root / "runs" / model / case["stage"] / f"{case['instance_id']}_run.json"
                    if candidate.exists():
                        run_outputs.append((candidate, case, model))
        for run_json, case, model in run_outputs:
            if "dry_runs" in run_json.parts:
                continue
            score_outputs.append(score_one(run_json, case, model, args))

    print(
        json.dumps(
            {
                "manifest": str(args.result_root / "manifest.json"),
                "selected_cases": len(cases),
                "models": models,
                "dry_run_outputs": sum(1 for item in run_outputs if "dry_runs" in item[0].parts),
                "run_outputs": sum(1 for item in run_outputs if "runs" in item[0].parts and "dry_runs" not in item[0].parts),
                "score_outputs": len(score_outputs),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
