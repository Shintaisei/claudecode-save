#!/usr/bin/env python3
"""Prepare, run, and score the ATLASv2 S3/S4 CBC attack-reconstruction suite.

The suite has 24 Stage-1 alert-target inputs plus 8 deduplicated process/time
inputs for each of Stages 2 and 3.  It deliberately keeps the 27-chain formal
experiment driver unchanged while applying the same fail-fast execution model.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack24_stage_cases_20260723.jsonl"
RUNNER = ROOT / "src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py"
SCORER = ROOT / "src/clouseau_process_time/score_element_order_with_gpt.py"
DEFAULT_VALIDATION = ROOT / "docs/current_experiment/atlasv2_s3_s4_attack24_stage3_validation_steps_20260723.csv"
DEFAULT_RESULTS = ROOT / "docs/current_experiment/results_2026-07-23/atlasv2_s3_s4_attack24"
DEFAULT_MODELS = "gpt-5.4-mini"
STAGES = ("stage1", "stage2", "stage3")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def split_csv(value: str) -> list[str]:
    values = [item.strip() for item in value.split(",") if item.strip()]
    if not values:
        raise ValueError("at least one model is required")
    return values


def resolve_gold(case: dict[str, Any]) -> Path:
    root_text = str(case.get("formal_gold_root") or "").replace("\\", "/")
    file_text = str(case.get("gold_chain_file") or "").replace("\\", "/")
    if not root_text or not file_text:
        raise ValueError(f"{case.get('instance_id')}: formal_gold_root and gold_chain_file are required")
    gold = ROOT / Path(root_text) / Path(file_text)
    if not gold.is_file():
        raise FileNotFoundError(f"{case.get('instance_id')}: gold file not found: {gold}")
    return gold


def select_cases(cases: list[dict[str, Any]], stages: list[str], limit: int | None) -> list[dict[str, Any]]:
    selected = [case for case in cases if case.get("stage") in stages]
    if limit is not None:
        selected = selected[:limit]
    if not selected:
        raise ValueError("selection contains no cases")
    return selected


def load_scorer_module() -> Any:
    spec = importlib.util.spec_from_file_location("attack24_scorer", SCORER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scorer: {SCORER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize_pair(pair: Any, chain_id: str) -> tuple[str, str]:
    if isinstance(pair, dict):
        before, after = pair.get("before_step_id"), pair.get("after_step_id")
    elif isinstance(pair, (list, tuple)) and len(pair) == 2:
        before, after = pair
    else:
        raise ValueError(f"{chain_id}: unsupported gold_order_pairs entry {pair!r}")
    if not isinstance(before, str) or not isinstance(after, str) or not before or not after:
        raise ValueError(f"{chain_id}: invalid gold_order_pairs entry {pair!r}")
    return before, after


def stage3_rows(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Create Stage-3 applicability rows from canonical, non-alert telemetry gold."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for case in cases:
        if case["stage"] != "stage3":
            continue
        gold = json.loads(resolve_gold(case).read_text(encoding="utf-8"))
        chain_id = str(gold.get("chain_id") or case.get("chain_id") or "")
        if not chain_id:
            raise ValueError(f"{case['instance_id']}: Gold chain_id is required")
        for step in gold.get("gold_steps") or gold.get("behavior_timeline") or []:
            step_id = step.get("step_id")
            evidence = step.get("canonical_evidence") or []
            if not isinstance(step_id, str) or not step_id:
                raise ValueError(f"{case['instance_id']}: Gold step has no step_id")
            if not evidence:
                raise ValueError(f"{case['instance_id']} {step_id}: Stage-3 Gold requires canonical evidence")
            if any(item.get("source_table") == "cbc_alerts" for item in evidence if isinstance(item, dict)):
                raise ValueError(f"{case['instance_id']} {step_id}: Stage-3 Gold must not require cbc_alerts")
            if any(not isinstance(item, dict) or item.get("source_table") != "cbc_events" for item in evidence):
                raise ValueError(f"{case['instance_id']} {step_id}: Stage-3 Gold must use cbc_events only")
            key = (chain_id, step_id)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "chain_id": chain_id,
                    "step_id": step_id,
                    "stage3_status": "pass",
                    "validation_basis": "canonical cbc_events evidence; CBC alert summary excluded",
                    "source_case": case["instance_id"],
                }
            )
    if not rows:
        raise ValueError("no Stage-3 validation rows were generated")
    return rows


def write_stage3_validation(path: Path, cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows = stage3_rows(cases)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def preflight(cases: list[dict[str, Any]], validation_steps: Path) -> dict[str, Any]:
    stage_counts = Counter(case.get("stage") for case in cases)
    if dict(stage_counts) != {"stage1": 24, "stage2": 8, "stage3": 8}:
        raise ValueError(f"unexpected stage counts: {dict(stage_counts)}")
    ids = [str(case.get("instance_id")) for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate instance_id in case file")
    for case in cases:
        if case.get("enforce_time_scope") is not True:
            raise ValueError(f"{case['instance_id']}: enforce_time_scope must be true")
        resolve_gold(case)
        if case["stage"] == "stage3" and case.get("input_alert_rows"):
            raise ValueError(f"{case['instance_id']}: Stage 3 must not expose alert-summary rows")
    rows = write_stage3_validation(validation_steps, cases)
    scorer = load_scorer_module()
    stage3_gold_summaries: list[dict[str, Any]] = []
    for case in cases:
        gold_path = resolve_gold(case)
        gold = json.loads(gold_path.read_text(encoding="utf-8"))
        chains = scorer.normalize_gold(gold, gold_path)
        for chain in chains:
            for pair in chain.get("gold_order_pairs") or []:
                normalize_pair(pair, str(chain.get("chain_id")))
        filtered = scorer.filter_chains_for_stage(chains, case["stage"], validation_steps)
        maxima = scorer.gold_maxima(filtered)
        if not maxima["gold_step_count"] or not maxima["gold_action_required_item_count"]:
            raise ValueError(f"{case['instance_id']}: scorer preflight found no evaluable Gold steps")
        if case["stage"] == "stage3":
            stage3_gold_summaries.append(
                {
                    "instance_id": case["instance_id"],
                    "gold": str(gold_path),
                    "gold_steps": maxima["gold_step_count"],
                    "required_action_items": maxima["gold_action_required_item_count"],
                    "order_pairs": maxima["gold_order_pair_count"],
                }
            )
    return {
        "status": "pass",
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "gold_paths_resolved": len(cases),
        "stage3_validation_rows": len(rows),
        "stage3_scorer_preflight": stage3_gold_summaries,
        "checks": [
            "all case Gold paths resolve through formal_gold_root + gold_chain_file",
            "all cases opt into the physical time scope",
            "all Stage-3 Gold steps have canonical cbc_events evidence and no cbc_alerts evidence",
            "all Gold order pairs are supported list pairs or mapping pairs",
            "the scorer can filter each Stage-3 case using the generated validation CSV",
        ],
    }


def build_run_command(case: dict[str, Any], model: str, args: argparse.Namespace, dry_run: bool) -> list[str]:
    cmd = [
        sys.executable, str(RUNNER), "--cases", str(args.cases), "--instance-id", case["instance_id"],
        "--model", model, "--difficulty", case["difficulty"],
        "--max-investigations", str(args.max_investigations),
        "--max-questions", str(args.max_questions), "--max-queries", str(args.max_queries),
        "--max-tokens", str(args.max_tokens), "--sql-playbook", args.sql_playbook,
    ]
    if case["stage"] == "stage3":
        cmd.append("--exclude-cbc-alert-summary")
    if dry_run:
        cmd.append("--dry-run")
    if args.log_cost:
        cmd.append("--log-cost")
    return cmd


def command_text(command: list[str]) -> str:
    return " ".join(json.dumps(part) if any(char.isspace() for char in part) else part for part in command)


def run_runner(case: dict[str, Any], model: str, args: argparse.Namespace, dry_run: bool) -> Path:
    command = build_run_command(case, model, args, dry_run)
    completed = subprocess.run(command, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(f"runner failed for {case['instance_id']} {model} (exit {completed.returncode})\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
    paths = [Path(line.strip()) for line in completed.stdout.splitlines() if line.strip().endswith("run.json")]
    if not paths:
        raise RuntimeError(f"runner did not print a run.json path for {case['instance_id']} {model}\n{completed.stdout}")
    source = paths[-1]
    bucket = "dry_runs" if dry_run else "runs"
    dest = args.result_root / bucket / model / case["stage"] / f"{case['instance_id']}_run.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    payload = json.loads(dest.read_text(encoding="utf-8"))
    payload["atlasv2_s3_s4_attack24_experiment"] = {
        "case_file": str(args.cases), "stage": case["stage"],
        "formal_gold_root": case["formal_gold_root"], "gold_chain_file": case["gold_chain_file"],
        "copied_from": str(source),
    }
    write_json(dest, payload)
    return dest


def existing_output(case: dict[str, Any], model: str, args: argparse.Namespace, dry_run: bool) -> Path | None:
    bucket = "dry_runs" if dry_run else "runs"
    path = args.result_root / bucket / model / case["stage"] / f"{case['instance_id']}_run.json"
    if not path.is_file():
        return None
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"resume output is invalid: {path}: {exc}") from exc
    return path


def score_one(run_json: Path, case: dict[str, Any], model: str, args: argparse.Namespace) -> Path:
    out_dir = args.result_root / "scores" / model / case["stage"] / case["instance_id"]
    command = [sys.executable, str(SCORER), "--gold", str(resolve_gold(case)), "--run-json", str(run_json), "--out-dir", str(out_dir), "--stage", case["stage"]]
    if case["stage"] == "stage3":
        command.extend(["--validation-steps", str(args.validation_steps)])
    completed = subprocess.run(command, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(f"scoring failed for {case['instance_id']} {model} (exit {completed.returncode})\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
    return out_dir / "score_result.json"


def manifest(cases: list[dict[str, Any]], models: list[str], args: argparse.Namespace) -> dict[str, Any]:
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "suite": "atlasv2_s3_s4_cbc_attack_reconstruction_20260723",
        "case_file": str(args.cases),
        "case_count": len(cases),
        "stage_counts": dict(Counter(case["stage"] for case in cases)),
        "models": models,
        "result_root": str(args.result_root),
        "stage3_validation_steps": str(args.validation_steps),
        "stage3_contract": "Stage 3 runner commands always include --exclude-cbc-alert-summary; score commands always include the generated Stage-3 validation CSV.",
        "execution_commands": [command_text(build_run_command(case, model, args, False)) for model in models for case in cases],
        "dry_run_commands": [command_text(build_run_command(case, model, args, True)) for model in models for case in cases],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--result-root", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--validation-steps", type=Path, default=DEFAULT_VALIDATION)
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument("--stage", action="append", choices=STAGES)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--score", action="store_true")
    parser.add_argument("--resume", action="store_true", help="Reuse existing valid outputs in result-root.")
    parser.add_argument("--max-investigations", type=int, default=100)
    parser.add_argument("--max-questions", type=int, default=200)
    parser.add_argument("--max-queries", type=int, default=400)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--sql-playbook", choices=["none", "generic"], default="none")
    parser.add_argument("--log-cost", action="store_true")
    args = parser.parse_args()

    all_cases = read_jsonl(args.cases)
    selected = select_cases(all_cases, args.stage or list(STAGES), args.limit)
    models = split_csv(args.models)
    args.result_root.mkdir(parents=True, exist_ok=True)
    preflight_result = preflight(all_cases, args.validation_steps)
    for case in selected:
        command = build_run_command(case, models[0], args, dry_run=False)
        if case["stage"] == "stage3" and "--exclude-cbc-alert-summary" not in command:
            raise RuntimeError(f"{case['instance_id']}: Stage 3 command is missing alert-summary exclusion")
    write_json(args.result_root / "preflight.json", preflight_result)
    write_json(args.result_root / "manifest.json", manifest(selected, models, args))

    outputs: list[tuple[Path, dict[str, Any], str]] = []
    if args.dry_run:
        for model in models:
            for case in selected:
                output = existing_output(case, model, args, True) if args.resume else None
                outputs.append((output or run_runner(case, model, args, True), case, model))
    if args.run:
        for model in models:
            for case in selected:
                output = existing_output(case, model, args, False) if args.resume else None
                outputs.append((output or run_runner(case, model, args, False), case, model))
    scores: list[Path] = []
    if args.score:
        if not outputs:
            for model in models:
                for case in selected:
                    path = args.result_root / "runs" / model / case["stage"] / f"{case['instance_id']}_run.json"
                    if path.exists():
                        outputs.append((path, case, model))
        if not outputs:
            raise RuntimeError("--score requires existing --run outputs; dry-run outputs are never scored")
        for run_json, case, model in outputs:
            if "dry_runs" not in run_json.parts:
                scores.append(score_one(run_json, case, model, args))
    print(json.dumps({"preflight": str(args.result_root / "preflight.json"), "selected_cases": len(selected), "models": models, "dry_run_outputs": sum("dry_runs" in path.parts for path, _, _ in outputs), "run_outputs": sum("runs" in path.parts and "dry_runs" not in path.parts for path, _, _ in outputs), "score_outputs": len(scores)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
