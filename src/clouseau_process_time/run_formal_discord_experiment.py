#!/usr/bin/env python3
"""Run the formal Discord Run key Stage 1/2/3 experiment matrix.

The 2026-06-07 review fixed the experiment direction:
- Stage 1: CBC alert input.
- Stage 2: host/process/timestamp only, full DB.
- Stage 3: host/process/timestamp only, CBC alert summary rows removed.

This wrapper keeps that six-run matrix in one place and prevents accidental
reuse of older pilot conditions.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "src" / "clouseau_process_time" / "run_clouseau_official_cbc_dense_eval.py"
SCORER = ROOT / "src" / "clouseau_process_time" / "score_element_order_with_gpt.py"
GOLD = ROOT / "data" / "current_experiment" / "gold" / "discord_reg_runkey" / "gold_behavior_node.json"
INSTANCE_ID = "gold_reviewed_10_regexe_20220716t150700z"
DEFAULT_RESULT_ROOT = (
    ROOT
    / "docs"
    / "current_experiment"
    / "results_2026-06-04"
    / "formal_gpt41mini_gpt54mini_action_claim_eval_20260605"
)


@dataclass(frozen=True)
class MatrixRun:
    run_id: str
    model: str
    stage: str
    condition: str
    difficulty: str
    exclude_alert_summary: bool = False


RUN_MATRIX: tuple[MatrixRun, ...] = (
    MatrixRun("gpt41mini_stage1_alert_input", "gpt-4.1-mini", "Stage 1", "CBC alert input", "alert_input"),
    MatrixRun("gpt41mini_stage2_full_db", "gpt-4.1-mini", "Stage 2", "process-time full DB", "process_time"),
    MatrixRun(
        "gpt41mini_stage3_alert_summary_removed",
        "gpt-4.1-mini",
        "Stage 3",
        "process-time alert summary removed",
        "process_time",
        exclude_alert_summary=True,
    ),
    MatrixRun("gpt54mini_stage1_alert_input", "gpt-5.4-mini", "Stage 1", "CBC alert input", "alert_input"),
    MatrixRun("gpt54mini_stage2_full_db", "gpt-5.4-mini", "Stage 2", "process-time full DB", "process_time"),
    MatrixRun(
        "gpt54mini_stage3_alert_summary_removed",
        "gpt-5.4-mini",
        "Stage 3",
        "process-time alert summary removed",
        "process_time",
        exclude_alert_summary=True,
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true", help="Create runner dry-run JSON without model API calls.")
    parser.add_argument("--run", action="store_true", help="Execute the six CLOUSEAU runs.")
    parser.add_argument("--score", action="store_true", help="Score copied run JSON files with the GPT judge.")
    parser.add_argument("--judge-model", default="gpt-5.5")
    parser.add_argument("--reasoning-effort", default="medium")
    parser.add_argument("--sql-playbook", choices=["none", "generic"], default="generic")
    parser.add_argument("--max-investigations", type=int, default=100)
    parser.add_argument("--max-questions", type=int, default=200)
    parser.add_argument("--max-queries", type=int, default=400)
    parser.add_argument("--max-tokens", type=int, default=8192)
    args = parser.parse_args()
    if args.dry_run and args.run:
        raise SystemExit("--dry-run and --run are mutually exclusive. Use --dry-run for API-free materialization or --run for real model runs.")
    return args


def runner_command(item: MatrixRun, args: argparse.Namespace) -> list[str]:
    cmd = [
        sys.executable,
        str(RUNNER),
        "--instance-id",
        INSTANCE_ID,
        "--model",
        item.model,
        "--difficulty",
        item.difficulty,
        "--sql-playbook",
        args.sql_playbook,
        "--max-investigations",
        str(args.max_investigations),
        "--max-questions",
        str(args.max_questions),
        "--max-queries",
        str(args.max_queries),
        "--max-tokens",
        str(args.max_tokens),
        "--log-cost",
    ]
    if args.dry_run:
        cmd.append("--dry-run")
    if item.exclude_alert_summary:
        cmd.append("--exclude-cbc-alert-summary")
    return cmd


def score_command(run_json: Path, out_dir: Path, args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        str(SCORER),
        "--gold",
        str(GOLD),
        "--run-json",
        str(run_json),
        "--out-dir",
        str(out_dir),
        "--model",
        args.judge_model,
        "--reasoning-effort",
        args.reasoning_effort,
    ]


def parse_runner_output(stdout: str) -> Path:
    for line in stdout.splitlines():
        text = line.strip()
        if text.endswith("run.json"):
            return Path(text)
    raise RuntimeError(f"Runner did not print a run.json path:\n{stdout}")


def copy_run_json(source: Path, target: Path, item: MatrixRun) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["formal_matrix_run_id"] = item.run_id
    payload["formal_matrix_model"] = item.model
    payload["formal_matrix_stage"] = item.stage
    payload["formal_matrix_condition"] = item.condition
    payload["formal_matrix_difficulty"] = item.difficulty
    if payload.get("difficulty") != item.difficulty:
        payload["legacy_runner_difficulty"] = payload.get("difficulty")
    else:
        payload.pop("legacy_runner_difficulty", None)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_manifest(result_root: Path) -> None:
    manifest = {
        "instance_id": INSTANCE_ID,
        "gold": str(GOLD.relative_to(ROOT)),
        "run_matrix": [item.__dict__ for item in RUN_MATRIX],
        "notes": [
            "Stage 1 uses --difficulty alert_input.",
            "Stage 2 uses --difficulty process_time.",
            "Stage 3 uses --difficulty process_time --exclude-cbc-alert-summary.",
            "CBC database removed is intentionally not part of this formal matrix.",
        ],
    }
    path = result_root / "formal_discord_matrix_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    result_root = (args.result_root or DEFAULT_RESULT_ROOT).resolve()
    if args.dry_run:
        result_root = result_root if result_root.name == "dry_runs" else result_root / "dry_runs"
    write_manifest(result_root)

    if not args.run and not args.score and not args.dry_run:
        for item in RUN_MATRIX:
            print(" ".join(runner_command(item, args)))
        print(f"Manifest: {result_root / 'formal_discord_matrix_manifest.json'}")
        return

    copied_runs: list[Path] = []
    if args.run or args.dry_run:
        for item in RUN_MATRIX:
            try:
                completed = subprocess.run(
                    runner_command(item, args),
                    cwd=ROOT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                if exc.stdout:
                    print(exc.stdout, end="")
                raise
            source = parse_runner_output(completed.stdout)
            target = result_root / "runs" / f"{item.run_id}_run.json"
            copy_run_json(source, target, item)
            copied_runs.append(target)
            print(target)

    if args.score:
        for item in RUN_MATRIX:
            run_json = result_root / "runs" / f"{item.run_id}_run.json"
            if not run_json.exists():
                raise FileNotFoundError(run_json)
            out_dir = result_root / "scores_gpt55_raw_rerun_14denom_20260605" / item.run_id
            subprocess.run(score_command(run_json, out_dir, args), cwd=ROOT, check=True)

    if copied_runs:
        print(f"Copied {len(copied_runs)} run JSON file(s).")


if __name__ == "__main__":
    main()
