"""Run the corrected 12-run normal/attack full-ledger pilot.

The prior pilot04 was stopped before its second run completed because the
persisted ledger lacked exact per-role LLM API call counts and total wall time.
Pilot05 uses different normal cases, never re-runs the completed pilot03/04
case, and executes one model-run per wrapper invocation for exact resume and
progress accounting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
    / "normal_attack_full_ledger_pilot_05"
)
NORMAL_CASES = (
    ROOT
    / "data/current_experiment/cases/"
    / "normal8_observable_component_v3_stage_cases_20260726.jsonl"
)
NORMAL_VALIDATION = (
    ROOT
    / "docs/current_experiment/"
    / "normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
)
ATTACK_CASES = (
    ROOT
    / "data/current_experiment/cases/"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
)
ATTACK_VALIDATION = (
    ROOT
    / "docs/current_experiment/"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv"
)

PAIRS = [
    {
        "pair_id": "normal_chain10_gpt41",
        "scenario_group": "normal",
        "chain_id": "chain_10_e07_discord_run_key_registry_chain",
        "model": "gpt-4.1-mini",
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
        "pair_id": "normal_chain02_gpt54",
        "scenario_group": "normal",
        "chain_id": "chain_02_e01_python_simplehttpserver_network_chain",
        "model": "gpt-5.4-mini",
        "cases": NORMAL_CASES,
        "validation": NORMAL_VALIDATION,
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
RETRY_STAGE_ROOTS = {
    ("normal_chain10_gpt41", 3): (
        RESULT_ROOT
        / "executions"
        / "normal_chain10_gpt41"
        / "s3r2"
    ),
}
ROLES = ("chief", "investigator", "sql_qa")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def add_usage(*items: dict[str, int]) -> dict[str, int]:
    return {
        key: sum(int(item.get(key, 0)) for item in items)
        for key in (
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "total_tokens",
        )
    }


def stage_root(pair: dict[str, Any], stage: int) -> Path:
    retry_root = RETRY_STAGE_ROOTS.get((pair["pair_id"], stage))
    if retry_root is not None:
        return retry_root
    return RESULT_ROOT / "executions" / pair["pair_id"] / f"stage{stage}"


def run_path(pair: dict[str, Any], stage: int) -> Path:
    instance_id = f"{pair['chain_id']}_stage{stage}"
    return (
        stage_root(pair, stage)
        / "runs"
        / pair["model"]
        / f"stage{stage}"
        / f"{instance_id}_run.json"
    )


def command(pair: dict[str, Any], stage: int) -> list[str]:
    instance_id = f"{pair['chain_id']}_stage{stage}"
    return [
        sys.executable,
        str(WRAPPER),
        "--cases",
        str(pair["cases"]),
        "--validation-steps",
        str(pair["validation"]),
        "--result-root",
        str(stage_root(pair, stage)),
        "--models",
        pair["model"],
        "--instance-id",
        instance_id,
        "--run",
        "--resume",
        "--max-tokens",
        "24576",
        "--sql-playbook",
        "none",
        "--log-cost",
    ]


def valid_json_text(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        json.loads(value)
    except json.JSONDecodeError:
        return False
    return True


def validate_run(
    path: Path,
    pair: dict[str, Any],
    stage: int,
) -> dict[str, Any]:
    payload = read_json(path)
    usage = payload.get("usage") or {}
    breakdown = payload.get("usage_breakdown") or {}
    audit = payload.get("usage_audit") or {}
    activity = payload.get("investigation_activity") or {}
    configs = payload.get("configs") or {}
    role_counts = breakdown.get("role_call_counts") or {}
    role_calls = breakdown.get("role_calls") or {}
    role_durations = breakdown.get("role_llm_duration_seconds") or {}
    issues: list[str] = []

    if payload.get("instance_id") != f"{pair['chain_id']}_stage{stage}":
        issues.append("instance_id")
    if payload.get("model") != pair["model"]:
        issues.append("model")
    if payload.get("error"):
        issues.append("error")
    if not valid_json_text(payload.get("output_text")):
        issues.append("output_text_json")
    if payload.get("usage_scope") != "full_pipeline_callback_v1":
        issues.append("usage_scope")
    if not payload.get("started_at_utc") or not payload.get("finished_at_utc"):
        issues.append("wall_timestamps")
    if not isinstance(payload.get("elapsed_seconds"), (int, float)):
        issues.append("elapsed_seconds")
    window = (
        (payload.get("gold_reference") or {}).get("time_window_utc") or {}
    )
    try:
        start = datetime.fromisoformat(
            str(window["episode_start"]).replace("Z", "+00:00")
        )
        end = datetime.fromisoformat(
            str(window["episode_end"]).replace("Z", "+00:00")
        )
        if (end - start).total_seconds() != 300.0:
            issues.append("five_minute_window")
    except (KeyError, TypeError, ValueError):
        issues.append("five_minute_window")

    for field in (
        "full_pipeline_equals_role_total",
        "full_pipeline_equals_call_ledger",
        "callback_aggregate_equals_call_ledger",
    ):
        if audit.get(field) is not True:
            issues.append(f"usage_audit.{field}")

    if set(role_counts) != set(ROLES):
        issues.append("role_call_counts.keys")
    if set(role_calls) != set(ROLES):
        issues.append("role_calls.keys")
    if any(
        role_counts.get(role) != len(role_calls.get(role) or [])
        for role in ROLES
    ):
        issues.append("role_call_counts.length")
    if sum(int(role_counts.get(role, 0)) for role in ROLES) != audit.get(
        "full_pipeline_call_count"
    ):
        issues.append("role_call_counts.total")
    if role_counts != audit.get("role_call_count_by_role"):
        issues.append("role_call_counts.audit")
    if role_counts != audit.get("role_timed_call_count_by_role"):
        issues.append("role_call_timing.audit")
    if audit.get("full_pipeline_timed_call_count") != audit.get(
        "full_pipeline_call_count"
    ):
        issues.append("full_pipeline_call_timing")

    for role in ROLES:
        calls = role_calls.get(role) or []
        if any(
            not isinstance(call.get("duration_seconds"), (int, float))
            or not call.get("started_at_utc")
            or not call.get("finished_at_utc")
            for call in calls
        ):
            issues.append(f"role_timing.{role}")
        call_total = add_usage(
            *[
                call.get("usage") or {}
                for call in calls
            ]
        )
        if call_total != breakdown.get(role):
            issues.append(f"role_usage.{role}")
        duration_total = round(
            sum(float(call["duration_seconds"]) for call in calls),
            3,
        )
        if duration_total != role_durations.get(role):
            issues.append(f"role_duration_total.{role}")
    if add_usage(*[breakdown.get(role) or {} for role in ROLES]) != usage:
        issues.append("role_usage.total")

    cost = payload.get("cost_estimate") or {}
    if cost.get("call_count") != audit.get("full_pipeline_call_count"):
        issues.append("cost_call_count")
    if not activity.get("events"):
        issues.append("investigation_activity")
    if any(
        configs.get(field) is not None
        for field in ("max_investigations", "max_questions", "max_queries")
    ):
        issues.append("experiment_call_limit")
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        issues.append("agent_call_limit_policy")
    lead_guard = configs.get("lead_expansion_guard") or {}
    if lead_guard.get("max_investigator_questions_per_lead") != 20:
        issues.append("lead_guard.question_limit")
    if lead_guard.get("max_wall_seconds_per_lead") != 1200.0:
        issues.append("lead_guard.wall_limit")
    tree_guard = configs.get("process_tree_guard") or {}
    if tree_guard.get("pid_plus_observed_time_instance_resolution") is not True:
        issues.append("process_tree_instance_resolution")
    sql_guard = configs.get("sql_execution_guard") or {}
    if sql_guard.get("timeout_seconds") != 1200:
        issues.append("sql_guard.timeout_seconds")
    if sql_guard.get("vm_step_limit") != 50_000_000:
        issues.append("sql_guard.vm_step_limit")
    if sql_guard.get("result_row_limit") != 30:
        issues.append("sql_guard.result_row_limit")
    if sql_guard.get("query_only") is not True:
        issues.append("sql_guard.query_only")
    if stage == 3:
        clue = payload.get("clue") or ""
        if "alert_name=" in clue or "alert_reason=" in clue:
            issues.append("stage3_alert_summary_visible")
        counts = payload.get("adapter_counts") or {}
        is_retained_legacy_run = (
            pair["pair_id"] == "normal_chain10_gpt41"
            and "s3r2" in path.parts
        )
        expected_filter_mode = (
            "sql_tool_temp_view"
            if is_retained_legacy_run
            else "physical_adapter_copy_v2"
        )
        if counts.get("cbc_alert_summary_filter_mode") != expected_filter_mode:
            issues.append("stage3_filter_mode")
        if counts.get("post_filter_cbc_alert_summary_rows") != 0:
            issues.append("stage3_alert_summary_rows")
        if int(counts.get("post_filter_cbc_event_telemetry_rows") or 0) <= 0:
            issues.append("stage3_primary_telemetry")
        if not is_retained_legacy_run:
            if counts.get("shared_guarded_sql_tools_preserved") is not True:
                issues.append("stage3_shared_sql_guard")
            if (
                counts.get(
                    "shared_guarded_process_tree_tools_preserved"
                )
                is not True
            ):
                issues.append("stage3_shared_process_tree_guard")

    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256(path),
        "issues": issues,
        "status": "PASS" if not issues else "FAIL",
    }


def create_manifest() -> Path:
    path = RESULT_ROOT / "pilot_selection_manifest.json"
    if path.exists():
        return path
    payload = {
        "schema_version": "normal_attack_full_ledger_pilot05_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "design": "four case/model pairs x three stages = 12 runs",
        "purpose": (
            "verify unrestricted multi-lead operation, full role-level LLM "
            "ledger, runtime accounting, and scoring readiness"
        ),
        "interpretation_limit": (
            "Cases are assigned to models, so cross-model score differences "
            "are case-confounded and are not a model-superiority comparison."
        ),
        "supersedes_incomplete_pilot": {
            "pilot": "normal_attack_full_ledger_pilot_04",
            "reason": (
                "missing persisted per-role LLM API call counts and exact "
                "run wall-clock timestamps"
            ),
            "completed_runs_reexecuted": 0,
        },
        "normal_population": {
            "chain_count": 21,
            "all_case_windows_minutes": 5,
            "exclusion_manifest": (
                "docs/current_experiment/"
                "cbc_21_five_minute_normal_suite_manifest_20260730.json"
            ),
        },
        "pairs": [
            {
                "pair_id": pair["pair_id"],
                "scenario_group": pair["scenario_group"],
                "chain_id": pair["chain_id"],
                "model": pair["model"],
                "cases": str(pair["cases"].relative_to(ROOT)),
                "cases_sha256": sha256(pair["cases"]),
                "validation": str(pair["validation"].relative_to(ROOT)),
                "validation_sha256": sha256(pair["validation"]),
                "instance_ids": [
                    f"{pair['chain_id']}_stage{stage}"
                    for stage in (1, 2, 3)
                ],
            }
            for pair in PAIRS
        ],
        "run_count": 12,
        "replicates_per_case_model_stage": 1,
        "gpt_5_5_excluded": True,
        "required_run_ledger": {
            "roles": list(ROLES),
            "per_role_llm_call_count": True,
            "per_role_input_output_cached_tokens": True,
            "per_role_cost_derivable_from_call_ledger": True,
            "per_role_llm_api_duration_seconds": True,
            "started_finished_elapsed_time": True,
            "cross_agent_activity": True,
        },
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
            "stage3_alert_summary_hidden": True,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def create_instrumentation_contract() -> Path:
    path = RESULT_ROOT / "instrumentation_contract_v2.json"
    if path.exists():
        return path
    payload = {
        "schema_version": "full_pipeline_role_ledger_v2",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "reason": (
            "Persist exact role-level LLM API call counts, per-call timing, "
            "tokens, and exact total run wall time."
        ),
        "required_roles": list(ROLES),
        "required_per_role_fields": [
            "role_call_counts",
            "role_calls[].started_at_utc",
            "role_calls[].finished_at_utc",
            "role_calls[].duration_seconds",
            "role_calls[].usage.input_tokens",
            "role_calls[].usage.output_tokens",
            "role_calls[].usage.cached_input_tokens",
            "role_llm_duration_seconds",
        ],
        "required_run_fields": [
            "started_at_utc",
            "finished_at_utc",
            "elapsed_seconds",
        ],
        "audit_invariants": [
            "role call counts equal role call ledger lengths",
            "every role call has measured timing",
            "sum of role call counts equals full pipeline call count",
            "sum of per-role tokens equals full pipeline tokens",
            "cost call count equals full pipeline call count",
        ],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def save_progress(payload: dict[str, Any]) -> None:
    (RESULT_ROOT / "progress.json").write_text(
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
    manifest = create_manifest()
    instrumentation = create_instrumentation_contract()
    print(manifest)
    print(instrumentation)

    if not args.run:
        for pair in PAIRS:
            for stage in (1, 2, 3):
                print(subprocess.list2cmdline(command(pair, stage)))
        return

    progress_path = RESULT_ROOT / "progress.json"
    if progress_path.exists():
        progress = read_json(progress_path)
    else:
        progress = {
            "schema_version": "normal_attack_full_ledger_pilot05_progress_v1",
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "runs": [],
        }

    completed_keys = {
        (item["pair_id"], int(item["stage"]))
        for item in progress.get("runs", [])
        if item.get("status") == "PASS"
    }
    for pair in PAIRS:
        for stage in (1, 2, 3):
            key = (pair["pair_id"], stage)
            path = run_path(pair, stage)
            if path.is_file():
                audit = validate_run(path, pair, stage)
                if audit["status"] == "PASS":
                    if key not in completed_keys:
                        recovered = {
                            "pair_id": pair["pair_id"],
                            "scenario_group": pair["scenario_group"],
                            "chain_id": pair["chain_id"],
                            "model": pair["model"],
                            "stage": stage,
                            "returncode": 0,
                            "finished_at_utc": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "recovered_existing_run": True,
                            **audit,
                        }
                        progress["runs"] = [
                            item
                            for item in progress.get("runs", [])
                            if (
                                item["pair_id"],
                                int(item["stage"]),
                            )
                            != key
                        ]
                        progress["runs"].append(recovered)
                        save_progress(progress)
                        completed_keys.add(key)
                    continue
            progress["active"] = {
                "pair_id": pair["pair_id"],
                "stage": stage,
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            save_progress(progress)

            stdout_path = logs / f"{pair['pair_id']}_stage{stage}_stdout.log"
            stderr_path = logs / f"{pair['pair_id']}_stage{stage}_stderr.log"
            with stdout_path.open("a", encoding="utf-8") as stdout, stderr_path.open(
                "a", encoding="utf-8"
            ) as stderr:
                completed = subprocess.run(
                    command(pair, stage),
                    cwd=ROOT,
                    stdout=stdout,
                    stderr=stderr,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
            record = {
                "pair_id": pair["pair_id"],
                "scenario_group": pair["scenario_group"],
                "chain_id": pair["chain_id"],
                "model": pair["model"],
                "stage": stage,
                "returncode": completed.returncode,
                "stdout": str(stdout_path.relative_to(ROOT)),
                "stderr": str(stderr_path.relative_to(ROOT)),
                "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            if path.is_file():
                record.update(validate_run(path, pair, stage))
            else:
                record["status"] = "FAIL"
                record["issues"] = ["missing_run_json"]
            progress["runs"] = [
                item
                for item in progress.get("runs", [])
                if (item["pair_id"], int(item["stage"])) != key
            ]
            progress["runs"].append(record)
            progress.pop("active", None)
            save_progress(progress)
            if completed.returncode != 0 or record["status"] != "PASS":
                raise SystemExit(
                    f"{pair['pair_id']} stage{stage} failed deterministic audit"
                )

    progress["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    progress["status"] = "PASS"
    save_progress(progress)
    print(progress_path)


if __name__ == "__main__":
    main()
