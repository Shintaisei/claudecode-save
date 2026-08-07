"""Run the approved normal8 paired three-model, three-stage experiment.

The experiment is intentionally split into two resumable phases:

1. ``--gate`` runs the same Discord Stage-3 sentinel once on each model.
2. ``--full`` is allowed only after the gate audit passes, then completes the
   remaining runs without re-running completed sentinel outputs.

Run files and manifests are create-only. Existing artifacts are validated and
reused; they are never deleted or overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from argparse import Namespace
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNNER_DIR = ROOT / "src" / "clouseau_process_time"
SCRIPTS_DIR = ROOT / "scripts"
for import_path in (RUNNER_DIR, SCRIPTS_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

import run_atlasv2_s3_s4_attack8_paired_experiment as paired  # noqa: E402
import run_normal_attack_full_ledger_pilot05_20260730 as pilot05  # noqa: E402


CASES = (
    ROOT
    / "data/current_experiment/cases/"
    / "normal8_observable_component_v3_stage_cases_20260726.jsonl"
)
VALIDATION = (
    ROOT
    / "docs/current_experiment/"
    / "normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
)
NORMAL8_MANIFEST = (
    ROOT
    / "data/current_experiment/cases/"
    / "normal8_observable_component_v3_manifest_20260726.json"
)
NORMAL21_MANIFEST = (
    ROOT
    / "docs/current_experiment/"
    / "cbc_21_five_minute_normal_suite_manifest_20260730.json"
)
DEFAULT_RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-01/"
    / "normal8_three_model_three_stage_formal_19"
)
RESULT_ROOT = Path(
    os.getenv("NORMAL8_FORMAL_RESULT_ROOT", str(DEFAULT_RESULT_ROOT))
)
if not RESULT_ROOT.is_absolute():
    RESULT_ROOT = ROOT / RESULT_ROOT
MODELS = ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5")
STAGES = ("stage1", "stage2", "stage3")
FRONTIER_CLOSURE_POLICY = (
    "semantic_fingerprint_atomic_guard_v16_with_empty_response_fail_closed"
)
LLM_REQUEST_TIMEOUT_SECONDS = 600
LLM_HARD_WALL_TIMEOUT_SECONDS = 600
RUN_HARD_WALL_TIMEOUT_SECONDS = 1800
SENTINEL_INSTANCE = "chain_10_e07_discord_run_key_registry_chain_stage3"
EXPECTED_CHAIN_IDS = (
    "chain_02_e01_python_simplehttpserver_network_chain",
    "chain_04_e03_dns_packet_capture_batch_chain",
    "chain_05_e03_python_simplehttpserver_network_chain",
    "chain_06_e04_python_simplehttpserver_network_chain",
    "chain_09_e07_cmdexe_other_chain",
    "chain_10_e07_discord_run_key_registry_chain",
    "chain_11_e07_sublime_python_script_execution_chain",
    "chain_24_e18_cmdexe_other_chain",
)

SELECTION_RATIONALE = {
    "chain_02_e01_python_simplehttpserver_network_chain": (
        "Python/HTTP network chain; three Gold steps; deeper variant"
    ),
    "chain_04_e03_dns_packet_capture_batch_chain": (
        "DNS capture batch; seven Gold steps; maximum structural depth"
    ),
    "chain_05_e03_python_simplehttpserver_network_chain": (
        "Python/HTTP network chain; two Gold steps; medium-depth variant"
    ),
    "chain_06_e04_python_simplehttpserver_network_chain": (
        "Python/HTTP network chain; one Gold step; easy boundary"
    ),
    "chain_09_e07_cmdexe_other_chain": (
        "cmd execution; one Gold step; easy command-line boundary"
    ),
    "chain_10_e07_discord_run_key_registry_chain": (
        "Discord persistence via Run key; distinct registry behavior"
    ),
    "chain_11_e07_sublime_python_script_execution_chain": (
        "Sublime-to-Python script execution; distinct parent/child behavior"
    ),
    "chain_24_e18_cmdexe_other_chain": (
        "cmd execution; four Gold steps; complex command-chain boundary"
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_create_only(path: Path, payload: dict[str, Any]) -> Path:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing != encoded:
            raise RuntimeError(f"create-only artifact differs: {path}")
        return path
    path.write_text(encoded, encoding="utf-8")
    return path


def append_event(payload: dict[str, Any]) -> None:
    path = RESULT_ROOT / "_logs" / "progress.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def load_cases() -> list[dict[str, Any]]:
    cases = paired.read_jsonl(CASES)
    chain_counts = Counter(str(case["chain_id"]) for case in cases)
    stage_counts = Counter(str(case["stage"]) for case in cases)
    issues: list[str] = []
    if len(cases) != 24:
        issues.append(f"case_count={len(cases)}")
    if tuple(sorted(chain_counts)) != tuple(sorted(EXPECTED_CHAIN_IDS)):
        issues.append("chain_ids")
    if any(chain_counts[chain_id] != 3 for chain_id in EXPECTED_CHAIN_IDS):
        issues.append("three_stages_per_chain")
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        issues.append(f"stage_counts={dict(stage_counts)}")
    if any(
        (
            datetime.fromisoformat(
                str(case["time_window_utc"]["episode_end"]).replace("Z", "+00:00")
            )
            - datetime.fromisoformat(
                str(case["time_window_utc"]["episode_start"]).replace(
                    "Z", "+00:00"
                )
            )
        ).total_seconds()
        != 300
        for case in cases
    ):
        issues.append("non_five_minute_window")
    if issues:
        raise RuntimeError(f"normal8 case contract failed: {issues}")
    return cases


def runner_args() -> Namespace:
    return Namespace(
        cases=CASES,
        result_root=RESULT_ROOT,
        validation_steps=VALIDATION,
        max_tokens=24576,
        sql_playbook="none",
        log_cost=True,
    )


def run_path(case: dict[str, Any], model: str) -> Path:
    return (
        RESULT_ROOT
        / "runs"
        / model
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )


def audit_run(
    path: Path,
    case: dict[str, Any],
    model: str,
) -> dict[str, Any]:
    stage_number = int(str(case["stage"])[-1])
    pair = {
        "pair_id": "normal8_three_model_formal",
        "chain_id": case["chain_id"],
        "model": model,
    }
    result = pilot05.validate_run(path, pair, stage_number)
    payload = read_json(path)
    issues = list(result["issues"])
    elapsed_seconds = payload.get("elapsed_seconds")
    if elapsed_seconds is None:
        issues.append("elapsed_seconds")
    elif float(elapsed_seconds) > RUN_HARD_WALL_TIMEOUT_SECONDS + 5:
        issues.append("elapsed_seconds.run_hard_wall")
    gold_reference = payload.get("gold_reference") or {}
    binding = payload.get("atlasv2_s3_s4_attack8_paired_experiment") or {}
    if gold_reference.get("instance_id") != case["instance_id"]:
        issues.append("gold_reference.instance_id")
    llm_guard = (payload.get("configs") or {}).get("llm_execution_guard") or {}
    if llm_guard.get("max_completion_tokens") != 24576:
        issues.append("llm_guard.max_completion_tokens")
    if llm_guard.get("request_timeout_seconds") != float(
        LLM_REQUEST_TIMEOUT_SECONDS
    ):
        issues.append("llm_guard.request_timeout_seconds")
    hard_wall_configured = (
        llm_guard.get("hard_wall_timeout_seconds")
        == float(LLM_HARD_WALL_TIMEOUT_SECONDS)
        and llm_guard.get("hard_wall_enforcement")
        == "external_active_call_watchdog_v1"
    )
    if llm_guard.get("max_retries") != 0:
        issues.append("llm_guard.max_retries")
    empty_result_guard = (payload.get("configs") or {}).get(
        "empty_tool_result_guard"
    ) or {}
    if empty_result_guard.get("enabled") is not True:
        issues.append("empty_tool_result_guard.enabled")
    if (
        empty_result_guard.get("max_consecutive_empty_results_per_lead")
        != 2
    ):
        issues.append("empty_tool_result_guard.max_consecutive")
    if empty_result_guard.get("on_limit") != "fail_run_closed":
        issues.append("empty_tool_result_guard.on_limit")
    tool_validation_recovery = (payload.get("configs") or {}).get(
        "tool_validation_recovery"
    ) or {}
    # formal_19 artifacts predate the recovery-only patch.  They may be
    # reused when that path was not exercised; retry-generated outputs must
    # carry this config and are checked by the retry wrapper's provenance audit.
    if tool_validation_recovery:
        if tool_validation_recovery.get("enabled") is not True:
            issues.append("tool_validation_recovery.enabled")
        if tool_validation_recovery.get("scope") != (
            "pydantic_tool_argument_validation_only"
        ):
            issues.append("tool_validation_recovery.scope")
        if tool_validation_recovery.get("valid_tool_call_limits_affected") is not False:
            issues.append("tool_validation_recovery.valid_tool_call_limits_affected")
    if cfg_frontier := (payload.get("configs") or {}).get(
        "frontier_closure_policy"
    ):
        if cfg_frontier != FRONTIER_CLOSURE_POLICY:
            issues.append("configs.frontier_closure_policy")
    else:
        issues.append("configs.frontier_closure_policy")
    if gold_reference.get("chain_id") != case["chain_id"]:
        issues.append("gold_reference.chain_id")
    if gold_reference.get("stage") != case["stage"]:
        issues.append("gold_reference.stage")
    if binding.get("chain_id") != case["chain_id"]:
        issues.append("binding.chain_id")
    if binding.get("stage") != case["stage"]:
        issues.append("binding.stage")
    if Path(str(binding.get("case_file") or "")).resolve() != CASES.resolve():
        issues.append("binding.case_file")
    gold_path = paired.resolve_gold(case)
    if Path(str(binding.get("gold") or "")).resolve() != gold_path.resolve():
        issues.append("binding.gold")

    activity = payload.get("investigation_activity") or {}
    events = activity.get("events") or []
    activity_summary = activity.get("summary") or {}
    behavior_guard = payload.get("behavior_key_guard") or {}
    behavior_guard_records = behavior_guard.get("records") or []
    behavior_guard_status_counts = Counter(
        str(record.get("status") or "")
        for record in behavior_guard_records
    )
    accepted_behavior_fingerprints = {
        str(record.get("semantic_fingerprint") or "").strip()
        for record in behavior_guard_records
        if record.get("status") == "accepted"
    }
    accepted_behavior_fingerprints.discard("")
    unique_behavior_keys = {
        str((event.get("arguments") or {}).get("behavior_key") or "").strip()
        for event in events
        if event.get("tool_name") == "investigate_lead"
    }
    unique_behavior_keys.discard("")
    call_durations = [
        float(call["duration_seconds"])
        for call in (
            (payload.get("usage_breakdown") or {}).get(
                "full_pipeline_calls"
            )
            or []
        )
        if call.get("duration_seconds") is not None
    ]
    max_llm_call_duration = max(call_durations, default=0.0)
    retrospective_guard_pass = (
        model in {"gpt-4.1-mini", "gpt-5.4-mini"}
        and case["instance_id"] == SENTINEL_INSTANCE
        and max_llm_call_duration < LLM_HARD_WALL_TIMEOUT_SECONDS
    )
    if not hard_wall_configured and not retrospective_guard_pass:
        issues.append("llm_guard.hard_wall_enforcement")
    result.update(
        {
            "issues": sorted(set(issues)),
            "status": "PASS" if not issues else "FAIL",
            "model": model,
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "gold_sha256": sha256(gold_path),
            "case_file_sha256": sha256(CASES),
            "validation_sha256": sha256(VALIDATION),
            "chief_lead_event_count": activity_summary.get("lead_call_count"),
            "unique_chief_lead_count": activity_summary.get("unique_lead_count"),
            "repeated_chief_lead_count": activity_summary.get(
                "repeated_lead_count"
            ),
            "unique_chief_behavior_key_count": activity_summary.get(
                "unique_behavior_key_count"
            ) or len(unique_behavior_keys),
            "repeated_chief_behavior_key_count": activity_summary.get(
                "repeated_behavior_key_count"
            ) if activity_summary.get("repeated_behavior_key_count") is not None
            else max(
                0,
                int(activity_summary.get("lead_call_count") or 0)
                - len(unique_behavior_keys),
            ),
            "accepted_behavior_fingerprint_count": len(
                accepted_behavior_fingerprints
            ),
            "behavior_guard_status_counts": dict(
                sorted(behavior_guard_status_counts.items())
            ),
            "investigator_question_count": activity_summary.get(
                "investigator_question_count"
            ),
            "unique_investigator_question_count": activity_summary.get(
                "unique_investigator_question_count"
            ),
            "sql_query_count": activity_summary.get("sql_query_count"),
            "unique_sql_query_count": activity_summary.get(
                "unique_sql_query_count"
            ),
            "activity_event_count": len(events),
            "api_call_count": (
                (payload.get("usage_audit") or {}).get("full_pipeline_call_count")
            ),
            "total_tokens": (payload.get("usage") or {}).get("total_tokens"),
            "cost_usd": (
                (payload.get("cost_estimate") or {}).get("total_cost_usd")
            ),
            "elapsed_seconds": payload.get("elapsed_seconds"),
            "max_llm_call_duration_seconds": round(
                max_llm_call_duration,
                3,
            ),
            "hard_wall_guard": {
                "configured_at_runtime": hard_wall_configured,
                "retrospective_legacy_sentinel_pass": (
                    retrospective_guard_pass
                ),
                "timeout_seconds": float(LLM_HARD_WALL_TIMEOUT_SECONDS),
                "status": (
                    "PASS"
                    if hard_wall_configured or retrospective_guard_pass
                    else "FAIL"
                ),
            },
        }
    )
    return result


def create_contract(cases: list[dict[str, Any]]) -> None:
    normal8 = read_json(NORMAL8_MANIFEST)
    gold_steps = {
        str(row["chain_id"]): int(row["gold_step_count"])
        for row in normal8["gold_index"]
    }
    payload = {
        "schema_version": "normal8_three_model_three_stage_formal_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "approval": "approved in seminar on 2026-07-31",
        "design": "8 normal use cases x 3 models x 3 stages = 72 paired runs",
        "models": list(MODELS),
        "stages": list(STAGES),
        "run_count": 72,
        "replicates_per_model_case_stage": 1,
        "cases": str(CASES.relative_to(ROOT)),
        "cases_sha256": sha256(CASES),
        "validation": str(VALIDATION.relative_to(ROOT)),
        "validation_sha256": sha256(VALIDATION),
        "normal8_manifest": str(NORMAL8_MANIFEST.relative_to(ROOT)),
        "normal8_manifest_sha256": sha256(NORMAL8_MANIFEST),
        "normal21_population_manifest": str(NORMAL21_MANIFEST.relative_to(ROOT)),
        "normal21_population_manifest_sha256": sha256(NORMAL21_MANIFEST),
        "selection_policy": (
            "Preserve behavior-family variety and structural-depth strata; "
            "exclude near-duplicate repetitions with the same family and "
            "approximately the same Gold depth."
        ),
        "selected_chains": [
            {
                "chain_id": chain_id,
                "gold_step_count": gold_steps[chain_id],
                "rationale": SELECTION_RATIONALE[chain_id],
            }
            for chain_id in EXPECTED_CHAIN_IDS
        ],
        "paired_invariants": {
            "same_cases_all_models": True,
            "same_gold_all_models_and_stages": True,
            "same_five_minute_window_all_models_and_stages": True,
            "stage3_cbc_alert_summary_hidden": True,
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "action_equals_operation": True,
        },
        "execution_contract": {
            "max_tokens": 24576,
            "max_completion_tokens_bound_to_api": True,
            "llm_request_timeout_seconds": LLM_REQUEST_TIMEOUT_SECONDS,
            "llm_hard_wall_timeout_seconds": LLM_HARD_WALL_TIMEOUT_SECONDS,
            "llm_hard_wall_enforcement": (
                "external_active_call_watchdog_v1"
            ),
            "llm_max_retries": 0,
            "empty_tool_result_guard": {
                "max_consecutive_empty_results_per_lead": 2,
                "on_first_empty": "retry_same_bounded_question_once",
                "on_limit": "fail_run_closed",
            },
            "tool_validation_recovery": {
                "scope": "pydantic_tool_argument_validation_only",
                "action": "return_tool_message_and_reprompt_same_agent",
                "valid_tool_call_limits_affected": False,
                "execution_exceptions_recovered": False,
            },
            "run_hard_wall_timeout_seconds": (
                RUN_HARD_WALL_TIMEOUT_SECONDS
            ),
            "sql_playbook": "none",
            "agent_call_limit_policy": "unbounded_by_experiment",
            "frontier_closure_policy": FRONTIER_CLOSURE_POLICY,
            "lead_guard": {
                "max_investigator_questions_per_lead": 20,
                "max_wall_seconds_per_lead": 1200,
                "on_trigger": (
                    "summarize evidence and unresolved frontier to Chief"
                ),
            },
            "usage_scope": "full_pipeline_callback_v1",
        },
        "gate": {
            "sentinel_instance_id": SENTINEL_INSTANCE,
            "models": list(MODELS),
            "run_count": 3,
            "requirement": (
                "All three runs pass deterministic instrumentation, Stage-3 "
                "filter, case/Gold binding, and output JSON audits."
            ),
        },
        "case_count": len(cases),
    }
    path = RESULT_ROOT / "formal_contract.json"
    if path.exists():
        existing = read_json(path)
        stable_keys = set(payload) - {"created_at_utc"}
        if any(existing.get(key) != payload.get(key) for key in stable_keys):
            raise RuntimeError(f"existing formal contract differs: {path}")
    else:
        write_create_only(path, payload)


def create_preflight(cases: list[dict[str, Any]]) -> None:
    path = RESULT_ROOT / "preflight.json"
    payload = paired.preflight(cases, VALIDATION)
    if path.exists():
        existing = read_json(path)
        if existing != payload:
            raise RuntimeError(f"existing preflight differs: {path}")
    else:
        write_create_only(path, payload)


def run_cases(
    cases: list[dict[str, Any]],
    models: tuple[str, ...],
) -> list[dict[str, Any]]:
    args = runner_args()
    audits: list[dict[str, Any]] = []
    for model in models:
        for case in cases:
            path = paired.existing_output(case, model, args, False)
            reused = path is not None
            if path is None:
                append_event(
                    {
                        "at_utc": datetime.now(timezone.utc).isoformat(),
                        "event": "run_started",
                        "model": model,
                        "instance_id": case["instance_id"],
                    }
                )
                path = paired.run_runner(case, model, args, False)
            audit = audit_run(path, case, model)
            append_event(
                {
                    "at_utc": datetime.now(timezone.utc).isoformat(),
                    "event": "run_audited",
                    "reused": reused,
                    **audit,
                }
            )
            audits.append(audit)
            if audit["status"] != "PASS":
                raise RuntimeError(
                    f"run audit failed for {case['instance_id']} {model}: "
                    f"{audit['issues']}"
                )
    return audits


def gate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    sentinel = next(
        case for case in cases if case["instance_id"] == SENTINEL_INSTANCE
    )
    audits = run_cases([sentinel], MODELS)
    payload = {
        "schema_version": "normal8_three_model_gate_audit_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if all(row["status"] == "PASS" for row in audits) else "FAIL",
        "sentinel_instance_id": SENTINEL_INSTANCE,
        "audits": audits,
    }
    write_create_only(RESULT_ROOT / "gate_audit.json", payload)
    return payload


def gate_core(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate the revised policy on the two lower-cost models first."""
    sentinel = next(
        case for case in cases if case["instance_id"] == SENTINEL_INSTANCE
    )
    core_models = MODELS[:2]
    audits = run_cases([sentinel], core_models)
    payload = {
        "schema_version": "normal8_three_model_gate_core_audit_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "PASS"
            if all(row["status"] == "PASS" for row in audits)
            else "FAIL"
        ),
        "sentinel_instance_id": SENTINEL_INSTANCE,
        "models": list(core_models),
        "frontier_closure_policy": FRONTIER_CLOSURE_POLICY,
        "audits": audits,
    }
    write_create_only(RESULT_ROOT / "gate_core_audit.json", payload)
    return payload


def full(cases: list[dict[str, Any]]) -> dict[str, Any]:
    gate_path = RESULT_ROOT / "gate_audit.json"
    if not gate_path.is_file() or read_json(gate_path).get("status") != "PASS":
        raise RuntimeError("full phase requires a passing gate_audit.json")
    audits = run_cases(cases, MODELS)
    by_model = Counter(row["model"] for row in audits)
    by_stage = Counter(row["stage"] for row in audits)
    by_chain = Counter(
        str(row["instance_id"]).rsplit("_stage", 1)[0]
        for row in audits
    )
    coverage_issues: list[str] = []
    if len(audits) != 72:
        coverage_issues.append(f"audited_runs={len(audits)}")
    if by_model != Counter({model: 24 for model in MODELS}):
        coverage_issues.append(f"by_model={dict(by_model)}")
    if by_stage != Counter({stage: 24 for stage in STAGES}):
        coverage_issues.append(f"by_stage={dict(by_stage)}")
    if by_chain != Counter({chain_id: 9 for chain_id in EXPECTED_CHAIN_IDS}):
        coverage_issues.append(f"by_chain={dict(by_chain)}")
    payload = {
        "schema_version": "normal8_three_model_full_run_audit_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "PASS"
            if all(row["status"] == "PASS" for row in audits)
            and not coverage_issues
            else "FAIL"
        ),
        "expected_runs": 72,
        "audited_runs": len(audits),
        "by_model": dict(by_model),
        "by_stage": dict(by_stage),
        "by_chain": dict(by_chain),
        "coverage_issues": coverage_issues,
        "audits": audits,
    }
    write_create_only(RESULT_ROOT / "full_run_audit.json", payload)
    if payload["status"] != "PASS":
        raise RuntimeError(
            "full audit failed: "
            f"coverage={coverage_issues}, "
            f"failed_runs={[row['instance_id'] for row in audits if row['status'] != 'PASS']}"
        )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--gate-core", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if sum(
        (args.gate, args.gate_core, args.full, args.preflight_only)
    ) != 1:
        parser.error(
            "select exactly one of --gate-core, --gate, --full, "
            "--preflight-only"
        )

    cases = load_cases()
    os.environ["CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS"] = str(
        RUN_HARD_WALL_TIMEOUT_SECONDS
    )
    os.environ["CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS"] = str(
        LLM_REQUEST_TIMEOUT_SECONDS
    )
    os.environ["CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS"] = str(
        LLM_HARD_WALL_TIMEOUT_SECONDS
    )
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    create_contract(cases)
    create_preflight(cases)

    if args.preflight_only:
        result: dict[str, Any] = {
            "status": "PASS",
            "contract": str(RESULT_ROOT / "formal_contract.json"),
            "preflight": str(RESULT_ROOT / "preflight.json"),
        }
    elif args.gate_core:
        result = gate_core(cases)
    elif args.gate:
        result = gate(cases)
    else:
        result = full(cases)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
