"""Run the 12-run full-ledger pilot without re-running completed work.

Design: four case/model pairs x three stages = twelve model runs.
Each model receives one normal and one attack case.  This is an operational
pilot, not a paired model-superiority experiment because the models receive
different cases.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = (
    ROOT
    / "src"
    / "clouseau_process_time"
    / "run_atlasv2_s3_s4_attack8_paired_experiment.py"
)
RESULT_ROOT = (
    ROOT
    / "docs"
    / "current_experiment"
    / "results_2026-07-30"
    / "normal_attack_full_ledger_pilot_04"
)
NORMAL_CASES = (
    ROOT
    / "data"
    / "current_experiment"
    / "cases"
    / "normal8_observable_component_v3_stage_cases_20260726.jsonl"
)
NORMAL_VALIDATION = (
    ROOT
    / "docs"
    / "current_experiment"
    / "normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
)
ATTACK_CASES = (
    ROOT
    / "data"
    / "current_experiment"
    / "cases"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
)
ATTACK_VALIDATION = (
    ROOT
    / "docs"
    / "current_experiment"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv"
)
REUSED_SOURCE = (
    ROOT
    / "docs"
    / "current_experiment"
    / "results_2026-07-30"
    / "normal_attack_full_ledger_pilot_03"
    / "normal"
    / "runs"
    / "gpt-4.1-mini"
    / "stage1"
    / "chain_04_e03_dns_packet_capture_batch_chain_stage1_run.json"
)

PAIRS = [
    {
        "pair_id": "normal_chain04_gpt41",
        "scenario_group": "normal",
        "chain_id": "chain_04_e03_dns_packet_capture_batch_chain",
        "model": "gpt-4.1-mini",
        "cases": NORMAL_CASES,
        "validation": NORMAL_VALIDATION,
    },
    {
        "pair_id": "normal_chain02_gpt54",
        "scenario_group": "normal",
        "chain_id": "chain_02_e01_python_simplehttpserver_network_chain",
        "model": "gpt-5.4-mini",
        "cases": NORMAL_CASES,
        "validation": NORMAL_VALIDATION,
    },
    {
        "pair_id": "attack_s4pt03_gpt41",
        "scenario_group": "attack",
        "chain_id": "s4_pt_03_mshta_c1",
        "model": "gpt-4.1-mini",
        "cases": ATTACK_CASES,
        "validation": ATTACK_VALIDATION,
    },
    {
        "pair_id": "attack_s3pt01_gpt54",
        "scenario_group": "attack",
        "chain_id": "s3_pt_01_word_document_processing",
        "model": "gpt-5.4-mini",
        "cases": ATTACK_CASES,
        "validation": ATTACK_VALIDATION,
    },
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def instances(chain_id: str) -> list[str]:
    return [f"{chain_id}_stage{stage}" for stage in (1, 2, 3)]


def expected_path(pair: dict, stage: int) -> Path:
    instance_id = f"{pair['chain_id']}_stage{stage}"
    return (
        RESULT_ROOT
        / pair["pair_id"]
        / "runs"
        / pair["model"]
        / f"stage{stage}"
        / f"{instance_id}_run.json"
    )


def validate_run(path: Path, pair: dict, stage: int) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected_instance = f"{pair['chain_id']}_stage{stage}"
    issues: list[str] = []
    if payload.get("instance_id") != expected_instance:
        issues.append("instance_id")
    if payload.get("model") != pair["model"]:
        issues.append("model")
    if payload.get("error"):
        issues.append("error")
    try:
        json.loads(payload.get("output_text") or "")
    except json.JSONDecodeError:
        issues.append("output_text_json")
    if payload.get("usage_scope") != "full_pipeline_callback_v1":
        issues.append("usage_scope")
    audit = payload.get("usage_audit") or {}
    for field in (
        "full_pipeline_equals_role_total",
        "full_pipeline_equals_call_ledger",
        "callback_aggregate_equals_call_ledger",
    ):
        if audit.get(field) is not True:
            issues.append(f"usage_audit.{field}")
    cost = payload.get("cost_estimate") or {}
    if cost.get("call_count") != audit.get("full_pipeline_call_count"):
        issues.append("cost_call_count")
    activity = payload.get("investigation_activity") or {}
    if not activity.get("events"):
        issues.append("investigation_activity")
    configs = payload.get("configs") or {}
    if any(
        configs.get(name) is not None
        for name in ("max_investigations", "max_questions", "max_queries")
    ):
        issues.append("experiment_call_limit")
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        issues.append("agent_call_limit_policy")
    guard = configs.get("lead_expansion_guard") or {}
    if guard.get("max_investigator_questions_per_lead") != 20:
        issues.append("lead_guard_question_limit")
    if guard.get("max_wall_seconds_per_lead") != 1200.0:
        issues.append("lead_guard_wall_limit")
    tree_guard = configs.get("process_tree_guard") or {}
    if tree_guard.get("pid_plus_observed_time_instance_resolution") is not True:
        issues.append("process_tree_instance_resolution")
    if stage == 3:
        clue = payload.get("clue") or ""
        if "alert_name=" in clue or "alert_reason=" in clue:
            issues.append("stage3_alert_summary_visible")
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256(path),
        "issues": issues,
        "status": "PASS" if not issues else "FAIL",
    }


def prepare_reuse() -> dict:
    if not REUSED_SOURCE.is_file():
        raise FileNotFoundError(REUSED_SOURCE)
    pair = PAIRS[0]
    destination = expected_path(pair, 1)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256(destination) != sha256(REUSED_SOURCE):
            raise FileExistsError(
                f"reuse destination exists with a different hash: {destination}"
            )
    else:
        shutil.copy2(REUSED_SOURCE, destination)
    return {
        "source": str(REUSED_SOURCE.relative_to(ROOT)),
        "source_sha256": sha256(REUSED_SOURCE),
        "destination": str(destination.relative_to(ROOT)),
        "destination_sha256": sha256(destination),
        "policy": "immutable completed pilot03 run reused; no API re-run",
    }


def build_command(pair: dict) -> list[str]:
    command = [
        sys.executable,
        str(WRAPPER),
        "--cases",
        str(pair["cases"]),
        "--validation-steps",
        str(pair["validation"]),
        "--result-root",
        str(RESULT_ROOT / pair["pair_id"]),
        "--models",
        pair["model"],
    ]
    for instance_id in instances(pair["chain_id"]):
        command.extend(["--instance-id", instance_id])
    command.extend(
        [
            "--run",
            "--resume",
            "--max-tokens",
            "24576",
            "--sql-playbook",
            "none",
            "--log-cost",
        ]
    )
    return command


def write_json_create_only(path: Path, payload: dict) -> None:
    if path.exists():
        raise FileExistsError(f"create-only target already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()

    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    logs = RESULT_ROOT / "_logs"
    logs.mkdir(parents=True, exist_ok=True)
    reuse = prepare_reuse()

    manifest_path = RESULT_ROOT / "pilot_selection_manifest.json"
    if not manifest_path.exists():
        write_json_create_only(
            manifest_path,
            {
                "schema_version": "normal_attack_full_ledger_pilot04_v1",
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "result_root": str(RESULT_ROOT.relative_to(ROOT)),
                "design": "four case/model pairs x three stages = 12 runs",
                "interpretation_limit": (
                    "operational and within-model Stage pilot; model superiority "
                    "is confounded by different assigned cases"
                ),
                "normal_population_transition": {
                    "formal_case_count": 21,
                    "excluded_chain_ids": [
                        "chain_07_e05_sublime_python_script_execution_chain",
                        "chain_13_e09_dns_packet_capture_batch_chain",
                    ],
                    "remaining_window_minutes": 5,
                    "manifest": (
                        "docs/current_experiment/"
                        "cbc_21_five_minute_normal_suite_manifest_20260730.json"
                    ),
                },
                "pairs": [
                    {
                        **{
                            key: value
                            for key, value in pair.items()
                            if key not in {"cases", "validation"}
                        },
                        "cases": str(pair["cases"].relative_to(ROOT)),
                        "cases_sha256": sha256(pair["cases"]),
                        "validation": str(pair["validation"].relative_to(ROOT)),
                        "validation_sha256": sha256(pair["validation"]),
                        "instance_ids": instances(pair["chain_id"]),
                    }
                    for pair in PAIRS
                ],
                "models": ["gpt-4.1-mini", "gpt-5.4-mini"],
                "stage_count": 3,
                "run_count": 12,
                "replicates_per_case_model_stage": 1,
                "gpt_5_5_excluded": True,
                "execution_contract": {
                    "max_tokens": 24576,
                    "sql_playbook": "none",
                    "agent_call_limit_policy": "unbounded_by_experiment",
                    "lead_guard": {
                        "max_investigator_questions_per_lead": 20,
                        "max_wall_seconds_per_lead": 1200,
                        "on_trigger": (
                            "return collected evidence and unresolved frontier to Chief"
                        ),
                    },
                    "full_pipeline_usage_required": True,
                    "stage3_alert_summary_hidden": True,
                },
                "reused_run": reuse,
            },
        )

    if not args.run:
        for pair in PAIRS:
            print(subprocess.list2cmdline(build_command(pair)))
        return

    progress_path = RESULT_ROOT / "progress.json"
    progress = {
        "schema_version": "normal_attack_full_ledger_pilot04_progress_v1",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "pairs": [],
    }
    for pair in PAIRS:
        command = build_command(pair)
        stdout_path = logs / f"{pair['pair_id']}_stdout.log"
        stderr_path = logs / f"{pair['pair_id']}_stderr.log"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                stdout=stdout,
                stderr=stderr,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        pair_result = {
            "pair_id": pair["pair_id"],
            "returncode": completed.returncode,
            "stdout": str(stdout_path.relative_to(ROOT)),
            "stderr": str(stderr_path.relative_to(ROOT)),
            "runs": [
                validate_run(expected_path(pair, stage), pair, stage)
                for stage in (1, 2, 3)
                if expected_path(pair, stage).is_file()
            ],
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        progress["pairs"].append(pair_result)
        progress_path.write_text(
            json.dumps(progress, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"{pair['pair_id']} failed; see {stderr_path.relative_to(ROOT)}"
            )
        if len(pair_result["runs"]) != 3 or any(
            run["status"] != "PASS" for run in pair_result["runs"]
        ):
            raise SystemExit(f"{pair['pair_id']} deterministic run audit failed")
    progress["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    progress["status"] = "PASS"
    progress_path.write_text(
        json.dumps(progress, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(progress_path)


if __name__ == "__main__":
    main()
