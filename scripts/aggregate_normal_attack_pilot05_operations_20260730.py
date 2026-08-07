"""Create the deterministic operational ledger for full-ledger pilot05.

No model or judge API is used.  The script reads only completed run JSON files,
verifies role/call/token/timing invariants, calculates role-level token cost
from the run's frozen price card, and writes create-only JSON/CSV artifacts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-30/"
    / "normal_attack_full_ledger_pilot_05"
)
MANIFEST = RESULT_ROOT / "pilot_selection_manifest.json"
ROLES = ("chief", "investigator", "sql_qa")
TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "total_tokens",
)
RETRY_STAGE_ROOTS = {
    ("normal_chain10_gpt41", 3): (
        RESULT_ROOT
        / "executions"
        / "normal_chain10_gpt41"
        / "s3r2"
    ),
}
LEGACY_STAGE3_GUARD_BYPASS_RUN = (
    "normal_chain10_gpt41",
    "stage3",
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def add_usage(*items: dict[str, int]) -> dict[str, int]:
    return {
        key: sum(int(item.get(key, 0)) for item in items)
        for key in TOKEN_KEYS
    }


def role_cost(calls: list[dict[str, Any]], rates: dict[str, float]) -> float:
    total = 0.0
    for call in calls:
        usage = call["usage"]
        input_tokens = int(usage.get("input_tokens", 0))
        cached = min(
            int(usage.get("cached_input_tokens", 0)),
            input_tokens,
        )
        uncached = input_tokens - cached
        output = int(usage.get("output_tokens", 0))
        total += uncached / 1_000_000.0 * float(rates["input"])
        total += cached / 1_000_000.0 * float(rates["cached_input"])
        total += output / 1_000_000.0 * float(rates["output"])
    return round(total, 9)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def expected_runs() -> list[dict[str, Any]]:
    manifest = read_json(MANIFEST)
    expected: list[dict[str, Any]] = []
    for pair in manifest["pairs"]:
        for stage in (1, 2, 3):
            instance_id = f"{pair['chain_id']}_stage{stage}"
            stage_root = RETRY_STAGE_ROOTS.get(
                (pair["pair_id"], stage),
                (
                    RESULT_ROOT
                    / "executions"
                    / pair["pair_id"]
                    / f"stage{stage}"
                ),
            )
            path = (
                stage_root
                / "runs"
                / pair["model"]
                / f"stage{stage}"
                / f"{instance_id}_run.json"
            )
            expected.append(
                {
                    **pair,
                    "stage": stage,
                    "instance_id": instance_id,
                    "run_path": path,
                }
            )
    return expected


def summarize_run(spec: dict[str, Any]) -> dict[str, Any]:
    path = spec["run_path"]
    run = read_json(path)
    breakdown = run["usage_breakdown"]
    audit = run["usage_audit"]
    activity = run["investigation_activity"]["summary"]
    cost = run["cost_estimate"]
    rates = cost["base_rates_per_1m_tokens"]
    events = run["investigation_activity"]["events"]
    lead_guard = run["lead_expansion_guard"]
    configs = run["configs"]
    role_rows: dict[str, dict[str, Any]] = {}
    issues: list[str] = []
    technical_defects: list[dict[str, Any]] = []
    role_cost_total = 0.0

    for role in ROLES:
        calls = breakdown["role_calls"][role]
        tokens = breakdown[role]
        count = breakdown["role_call_counts"][role]
        duration = breakdown["role_llm_duration_seconds"][role]
        calculated_tokens = add_usage(
            *[call.get("usage") or {} for call in calls]
        )
        calculated_duration = round(
            sum(float(call["duration_seconds"]) for call in calls),
            3,
        )
        calculated_cost = role_cost(calls, rates)
        role_cost_total += calculated_cost
        if count != len(calls):
            issues.append(f"{role}.call_count")
        if calculated_tokens != tokens:
            issues.append(f"{role}.tokens")
        if calculated_duration != duration:
            issues.append(f"{role}.duration")
        if any(
            not call.get("started_at_utc")
            or not call.get("finished_at_utc")
            or not isinstance(call.get("duration_seconds"), (int, float))
            for call in calls
        ):
            issues.append(f"{role}.call_timing")
        role_rows[role] = {
            "llm_api_call_count": count,
            **tokens,
            "llm_api_duration_seconds_sum": duration,
            "estimated_cost_usd": calculated_cost,
            "cross_agent_tool_call_count": int(
                (activity.get("tool_call_count_by_role") or {}).get(role, 0)
            ),
        }

    if round(role_cost_total, 9) != round(float(cost["total_cost_usd"]), 9):
        issues.append("role_cost_total")
    if sum(role_rows[role]["llm_api_call_count"] for role in ROLES) != audit[
        "full_pipeline_call_count"
    ]:
        issues.append("role_call_total")
    if add_usage(*[breakdown[role] for role in ROLES]) != run["usage"]:
        issues.append("role_token_total")
    for field in (
        "full_pipeline_equals_role_total",
        "full_pipeline_equals_call_ledger",
        "callback_aggregate_equals_call_ledger",
    ):
        if audit.get(field) is not True:
            issues.append(field)

    try:
        json.loads(run["output_text"])
    except (TypeError, json.JSONDecodeError):
        issues.append("output_text_json")
    if run.get("error") not in (None, ""):
        issues.append("run_error")
    if run.get("usage_scope") != "full_pipeline_callback_v1":
        issues.append("usage_scope")
    if any(configs.get(key) is not None for key in (
        "max_investigations",
        "max_questions",
        "max_queries",
    )):
        issues.append("agent_call_limit")
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        issues.append("agent_call_limit_policy")
    sql_guard = configs.get("sql_execution_guard") or {}
    for key, expected_value in (
        ("timeout_seconds", 1200),
        ("vm_step_limit", 50_000_000),
        ("result_row_limit", 30),
        ("recursive_union_all_policy", "rejected"),
        ("query_only", True),
    ):
        if sql_guard.get(key) != expected_value:
            issues.append(f"sql_guard.{key}")
    process_guard = configs.get("process_tree_guard") or {}
    if process_guard.get("pid_plus_observed_time_instance_resolution") is not True:
        issues.append("process_tree_guard.instance_resolution")
    expected_lead_guard = {
        "enabled": True,
        "max_investigator_questions_per_lead": 20,
        "max_sql_tool_calls_per_question": 12,
        "max_sql_tool_calls_per_lead": 80,
        "max_wall_seconds_per_lead": 1200.0,
    }
    for key, expected_value in expected_lead_guard.items():
        if (lead_guard.get("config") or {}).get(key) != expected_value:
            issues.append(f"lead_guard.{key}")

    window = run["gold_reference"]["time_window_utc"]
    window_seconds = (
        parse_utc(window["episode_end"]) - parse_utc(window["episode_start"])
    ).total_seconds()
    if window_seconds != 300.0:
        issues.append("five_minute_window")

    exception_events = [
        {
            key: event.get(key)
            for key in ("sequence", "role", "tool_name", "error")
        }
        for event in events
        if event.get("outcome") == "tool_exception" or event.get("error")
    ]
    sql_guard_events = [
        {
            key: event.get(key)
            for key in (
                "sequence",
                "role",
                "tool_name",
                "outcome",
                "result_preview",
                "error",
            )
        }
        for event in events
        if (
            "guard" in str(event.get("outcome", "")).lower()
            or "execution guard" in str(event.get("result_preview", "")).lower()
            or "query was interrupted" in str(event.get("result_preview", "")).lower()
        )
    ]
    adapter_counts = run.get("adapter_counts") or {}
    stage_name = f"stage{spec['stage']}"
    if spec["stage"] == 3:
        filter_mode = adapter_counts.get("cbc_alert_summary_filter_mode")
        if (
            spec["pair_id"],
            stage_name,
        ) == LEGACY_STAGE3_GUARD_BYPASS_RUN:
            technical_defects.append(
                {
                    "defect_id": "legacy_stage3_temp_view_guard_bypass",
                    "effect": (
                        "Stage3 TEMP VIEW monkeypatch bypassed the shared SQL "
                        "and process-tree guards during this already-completed "
                        "thought."
                    ),
                    "tool_exception_count": len(exception_events),
                    "scoring_treatment": (
                        "included once as observed architecture behavior; "
                        "reported separately and not silently rerun"
                    ),
                }
            )
        else:
            if filter_mode != "physical_adapter_copy_v2":
                issues.append("stage3_filter_mode")
            if adapter_counts.get("post_filter_cbc_alert_summary_rows") != 0:
                issues.append("stage3_alert_summary_rows")
            if adapter_counts.get("shared_guarded_sql_tools_preserved") is not True:
                issues.append("stage3_shared_sql_guard")
            if (
                adapter_counts.get(
                    "shared_guarded_process_tree_tools_preserved"
                )
                is not True
            ):
                issues.append("stage3_shared_process_tree_guard")

    return {
        "pair_id": spec["pair_id"],
        "scenario_group": spec["scenario_group"],
        "chain_id": spec["chain_id"],
        "model": spec["model"],
        "stage": stage_name,
        "instance_id": spec["instance_id"],
        "run_path": str(path.relative_to(ROOT)),
        "run_sha256": sha256(path),
        "started_at_utc": run["started_at_utc"],
        "finished_at_utc": run["finished_at_utc"],
        "elapsed_seconds": run["elapsed_seconds"],
        "time_window": {
            "episode_start": window["episode_start"],
            "episode_end": window["episode_end"],
            "duration_seconds": window_seconds,
        },
        "roles": role_rows,
        "total": {
            "llm_api_call_count": audit["full_pipeline_call_count"],
            **run["usage"],
            "llm_api_duration_seconds_sum": breakdown[
                "full_pipeline_llm_duration_seconds"
            ],
            "estimated_cost_usd": cost["total_cost_usd"],
            "cross_agent_tool_call_count": activity["total_tool_call_count"],
            "cross_agent_tool_duration_seconds_sum": activity[
                "total_tool_duration_seconds"
            ],
            "max_tool_duration_seconds": activity["max_tool_duration_seconds"],
            "chief_lead_count": activity["lead_call_count"],
            "chief_unique_lead_count": activity["unique_lead_count"],
            "investigator_question_count": activity[
                "investigator_question_count"
            ],
            "investigator_unique_question_count": activity[
                "unique_investigator_question_count"
            ],
            "sql_query_count": activity["sql_query_count"],
            "sql_unique_query_count": activity["unique_sql_query_count"],
            "lead_guard_trigger_count": run["lead_expansion_guard"][
                "trigger_count"
            ],
        },
        "guard_evidence": {
            "sql_execution_guard_config": sql_guard,
            "process_tree_guard_config": process_guard,
            "lead_expansion_guard_config": lead_guard.get("config") or {},
            "lead_expansion_records": lead_guard.get("records") or [],
            "sql_guard_events": sql_guard_events,
            "tool_exception_events": exception_events,
            "stage3_filter_mode": adapter_counts.get(
                "cbc_alert_summary_filter_mode"
            ),
            "post_filter_cbc_alert_summary_rows": adapter_counts.get(
                "post_filter_cbc_alert_summary_rows"
            ),
        },
        "known_technical_defects": technical_defects,
        "audit": {
            "issues": issues,
            "status": "PASS" if not issues else "FAIL",
        },
    }


def aggregate(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[key] for key in keys)].append(row)
    output: list[dict[str, Any]] = []
    for group_key, members in sorted(groups.items()):
        item = {key: value for key, value in zip(keys, group_key)}
        item["run_count"] = len(members)
        item["elapsed_seconds"] = round(
            sum(float(row["elapsed_seconds"]) for row in members),
            3,
        )
        item["estimated_cost_usd"] = round(
            sum(float(row["total"]["estimated_cost_usd"]) for row in members),
            9,
        )
        item["llm_api_call_count"] = sum(
            int(row["total"]["llm_api_call_count"]) for row in members
        )
        for token_key in TOKEN_KEYS:
            item[token_key] = sum(
                int(row["total"][token_key]) for row in members
            )
        for field in (
            "chief_lead_count",
            "chief_unique_lead_count",
            "investigator_question_count",
            "investigator_unique_question_count",
            "sql_query_count",
            "sql_unique_query_count",
            "lead_guard_trigger_count",
        ):
            item[field] = sum(
                int(row["total"][field]) for row in members
            )
        for role in ROLES:
            item[f"{role}_api_calls"] = sum(
                int(row["roles"][role]["llm_api_call_count"])
                for row in members
            )
            item[f"{role}_cost_usd"] = round(
                sum(
                    float(row["roles"][role]["estimated_cost_usd"])
                    for row in members
                ),
                9,
            )
            item[f"{role}_api_duration_seconds_sum"] = round(
                sum(
                    float(
                        row["roles"][role]["llm_api_duration_seconds_sum"]
                    )
                    for row in members
                ),
                3,
            )
            for token_key in TOKEN_KEYS:
                item[f"{role}_{token_key}"] = sum(
                    int(row["roles"][role][token_key])
                    for row in members
                )
        output.append(item)
    return output


def csv_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for row in rows:
        item = {
            key: row[key]
            for key in (
                "pair_id",
                "scenario_group",
                "chain_id",
                "model",
                "stage",
                "instance_id",
                "elapsed_seconds",
            )
        }
        for role in ROLES:
            for field in (
                "llm_api_call_count",
                "input_tokens",
                "output_tokens",
                "cached_input_tokens",
                "total_tokens",
                "llm_api_duration_seconds_sum",
                "estimated_cost_usd",
                "cross_agent_tool_call_count",
            ):
                item[f"{role}_{field}"] = row["roles"][role][field]
        for field, value in row["total"].items():
            item[f"total_{field}"] = value
        item["audit_status"] = row["audit"]["status"]
        flattened.append(item)
    return flattened


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=RESULT_ROOT / "analysis_codex_single_review_v1",
    )
    args = parser.parse_args()
    missing = [
        str(spec["run_path"].relative_to(ROOT))
        for spec in expected_runs()
        if not spec["run_path"].is_file()
    ]
    if missing:
        raise SystemExit(
            f"expected 12 completed runs; missing {len(missing)}: "
            + ", ".join(missing)
        )
    rows = [summarize_run(spec) for spec in expected_runs()]
    if any(row["audit"]["status"] != "PASS" for row in rows):
        raise SystemExit("one or more operational run audits failed")

    output = {
        "schema_version": "normal_attack_pilot05_operational_ledger_v1",
        "source_manifest": str(MANIFEST.relative_to(ROOT)),
        "source_manifest_sha256": sha256(MANIFEST),
        "run_count": len(rows),
        "runs": rows,
        "aggregates": {
            "by_model": aggregate(rows, ("model",)),
            "by_stage": aggregate(rows, ("stage",)),
            "by_scenario_group": aggregate(rows, ("scenario_group",)),
            "by_model_stage": aggregate(rows, ("model", "stage")),
            "by_model_scenario": aggregate(
                rows, ("model", "scenario_group")
            ),
        },
        "deterministic_audit": {
            "run_count_12": len(rows) == 12,
            "all_run_audits_pass": all(
                row["audit"]["status"] == "PASS" for row in rows
            ),
            "all_windows_exactly_five_minutes": all(
                row["time_window"]["duration_seconds"] == 300.0
                for row in rows
            ),
            "known_technical_defect_run_count": sum(
                bool(row["known_technical_defects"]) for row in rows
            ),
            "known_technical_defect_runs": [
                row["instance_id"]
                for row in rows
                if row["known_technical_defects"]
            ],
            "status": "PASS",
        },
    }
    args.output_root.mkdir(parents=True, exist_ok=True)
    json_path = args.output_root / "operational_ledger_v1.json"
    csv_path = args.output_root / "operational_ledger_v1.csv"
    for path in (json_path, csv_path):
        if path.exists():
            raise FileExistsError(f"create-only target already exists: {path}")
    json_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    flat = csv_rows(rows)
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(flat[0]))
        writer.writeheader()
        writer.writerows(flat)
    print(json_path)
    print(csv_path)


if __name__ == "__main__":
    main()
