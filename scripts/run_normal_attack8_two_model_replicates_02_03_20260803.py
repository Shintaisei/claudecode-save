"""Run create-only replicates 02 and 03 for the two-model formal matrix.

Each replicate contains normal8 and attack8, all three stages, for
gpt-4.1-mini and gpt-5.4-mini (96 runs/replicate, 192 new runs total).
Replicate 01 remains immutable in its original roots and is referenced only
as provenance for the eventual three-replicate aggregate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
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


MODELS = ("gpt-4.1-mini", "gpt-5.4-mini")
STAGES = ("stage1", "stage2", "stage3")
REPLICATES = ("replicate_02", "replicate_03")
FRONTIER_CLOSURE_POLICY = (
    "semantic_fingerprint_atomic_guard_v16_with_empty_response_fail_closed"
)
TIMEOUTS = {
    "llm_request_seconds": 600,
    "llm_hard_wall_seconds": 600,
    "run_hard_wall_seconds": 1800,
    "lead_wall_seconds": 1200,
}
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-03"
    / "mini_reps_02_03_v2"
)
INITIAL_ATTEMPT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-03"
    / "normal_attack8_two_model_three_stage_replicates_02_03"
)
BASELINE_ROOTS = {
    "normal8": (
        ROOT
        / "docs/current_experiment/results_2026-08-01"
        / "normal8_three_model_three_stage_formal_19_retry_02"
    ),
    "attack8": (
        ROOT
        / "docs/current_experiment/results_2026-08-01"
        / "attack8_two_model_three_stage_formal_20"
    ),
    "attack8_retry": (
        ROOT
        / "docs/current_experiment/results_2026-08-02"
        / "attack8_two_model_three_stage_formal_20_retry_01"
    ),
}
PHASES = (
    {
        "name": "normal8",
        "cases": (
            ROOT
            / "data/current_experiment/cases"
            / "normal8_observable_component_v3_stage_cases_20260726.jsonl"
        ),
        "validation": (
            ROOT
            / "docs/current_experiment"
            / "normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
        ),
    },
    {
        "name": "attack8",
        "cases": (
            ROOT
            / "data/current_experiment/cases"
            / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
        ),
        "validation": (
            ROOT
            / "docs/current_experiment"
            / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv"
        ),
    },
)
CODE_FILES = (
    Path(__file__).resolve(),
    RUNNER_DIR / "run_atlasv2_s3_s4_attack8_paired_experiment.py",
    RUNNER_DIR / "run_clouseau_official_cbc_dense_eval.py",
    RUNNER_DIR / "run_clouseau_official_normal_behavior.py",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_create_only(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise RuntimeError(f"create-only artifact differs: {path}")
        return
    path.write_text(encoded, encoding="utf-8")


def append_progress(payload: dict[str, Any]) -> None:
    path = RESULT_ROOT / "_logs" / "progress.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def configure_environment() -> None:
    values = {
        "CLOUSEAU_RUN_BUDGET_GUARD_ENABLED": "0",
        "CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS": TIMEOUTS[
            "llm_request_seconds"
        ],
        "CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS": TIMEOUTS[
            "llm_hard_wall_seconds"
        ],
        "CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS": TIMEOUTS[
            "run_hard_wall_seconds"
        ],
        "CLOUSEAU_MAX_INVESTIGATOR_QUESTIONS_PER_LEAD": 20,
        "CLOUSEAU_MAX_LEAD_WALL_SECONDS": TIMEOUTS["lead_wall_seconds"],
    }
    os.environ.update({key: str(value) for key, value in values.items()})


def load_phase_cases(phase: dict[str, Any]) -> list[dict[str, Any]]:
    cases = paired.read_jsonl(phase["cases"])
    stage_counts = Counter(str(case.get("stage")) for case in cases)
    chain_counts = Counter(str(case.get("chain_id")) for case in cases)
    issues: list[str] = []
    if len(cases) != 24:
        issues.append(f"case_count={len(cases)}")
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        issues.append(f"stage_counts={dict(stage_counts)}")
    if len(chain_counts) != 8 or any(
        count != 3 for count in chain_counts.values()
    ):
        issues.append(f"chain_counts={dict(chain_counts)}")
    for case in cases:
        window = case.get("time_window_utc") or {}
        try:
            start = datetime.fromisoformat(
                str(window["episode_start"]).replace("Z", "+00:00")
            )
            end = datetime.fromisoformat(
                str(window["episode_end"]).replace("Z", "+00:00")
            )
            if (end - start).total_seconds() != 300:
                issues.append(f"non_five_minute_window.{case['instance_id']}")
        except (KeyError, TypeError, ValueError):
            issues.append(f"invalid_window.{case.get('instance_id')}")
    if issues:
        raise RuntimeError(f"{phase['name']} case contract failed: {issues}")
    return sorted(
        cases,
        key=lambda case: (
            STAGES.index(str(case["stage"])),
            str(case["chain_id"]),
            str(case["instance_id"]),
        ),
    )


def replicate_root(replicate: str) -> Path:
    return RESULT_ROOT / replicate


def phase_root(replicate: str, phase: dict[str, Any]) -> Path:
    return replicate_root(replicate) / str(phase["name"])


def runner_args(replicate: str, phase: dict[str, Any]) -> Namespace:
    return Namespace(
        cases=phase["cases"],
        result_root=phase_root(replicate, phase),
        validation_steps=phase["validation"],
        max_tokens=24576,
        sql_playbook="none",
        log_cost=True,
    )


def run_path(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
) -> Path:
    return (
        phase_root(replicate, phase)
        / "runs"
        / model
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )


def audit_path(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
) -> Path:
    model_slug = {
        "gpt-4.1-mini": "g41",
        "gpt-5.4-mini": "g54",
    }[model]
    audit_id = hashlib.sha256(
        (
            f"{replicate}|{phase['name']}|{model}|{case['instance_id']}"
        ).encode("utf-8")
    ).hexdigest()[:16]
    return (
        replicate_root(replicate)
        / "audits"
        / str(phase["name"])
        / model_slug
        / f"{audit_id}.json"
    )


def import_initial_attempt_run(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
    destination: Path,
) -> bool:
    """Reuse a completed run from the path-length-failed first invocation."""
    if replicate != "replicate_02":
        return False
    source = (
        INITIAL_ATTEMPT_ROOT
        / replicate
        / str(phase["name"])
        / "runs"
        / model
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256(destination) != sha256(source):
            raise RuntimeError(
                f"create-only imported run differs: {destination}"
            )
    else:
        shutil.copy2(source, destination)
    append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "initial_attempt_run_imported",
            "replicate": replicate,
            "phase": phase["name"],
            "model": model,
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "source": str(source),
            "source_sha256": sha256(source),
            "destination": str(destination),
        }
    )
    return True


def audit_run(
    path: Path,
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
) -> dict[str, Any]:
    stage_number = int(str(case["stage"])[-1])
    base = pilot05.validate_run(
        path,
        {
            "pair_id": f"{replicate}_{phase['name']}_{model}",
            "chain_id": case["chain_id"],
            "model": model,
        },
        stage_number,
    )
    payload = read_json(path)
    issues = list(base.get("issues") or [])
    binding = payload.get("atlasv2_s3_s4_attack8_paired_experiment") or {}
    configs = payload.get("configs") or {}
    llm_guard = configs.get("llm_execution_guard") or {}
    empty_guard = configs.get("empty_tool_result_guard") or {}
    recovery = configs.get("tool_validation_recovery") or {}
    budget = configs.get("run_budget_guard") or payload.get("run_budget_guard") or {}

    if Path(str(binding.get("case_file") or "")).resolve() != Path(
        phase["cases"]
    ).resolve():
        issues.append("binding.case_file")
    if binding.get("chain_id") != case["chain_id"]:
        issues.append("binding.chain_id")
    if binding.get("stage") != case["stage"]:
        issues.append("binding.stage")
    expected_gold = paired.resolve_gold(case).resolve()
    if Path(str(binding.get("gold") or "")).resolve() != expected_gold:
        issues.append("binding.gold")
    if llm_guard.get("max_completion_tokens") != 24576:
        issues.append("llm_guard.max_completion_tokens")
    if llm_guard.get("request_timeout_seconds") != 600.0:
        issues.append("llm_guard.request_timeout_seconds")
    if llm_guard.get("hard_wall_timeout_seconds") != 600.0:
        issues.append("llm_guard.hard_wall_timeout_seconds")
    if llm_guard.get("hard_wall_enforcement") != (
        "external_active_call_watchdog_v1"
    ):
        issues.append("llm_guard.hard_wall_enforcement")
    if llm_guard.get("max_retries") != 0:
        issues.append("llm_guard.max_retries")
    if configs.get("frontier_closure_policy") != FRONTIER_CLOSURE_POLICY:
        issues.append("configs.frontier_closure_policy")
    if empty_guard.get("enabled") is not True:
        issues.append("empty_tool_result_guard.enabled")
    if empty_guard.get("max_consecutive_empty_results_per_lead") != 2:
        issues.append("empty_tool_result_guard.max_consecutive")
    if empty_guard.get("on_limit") != "fail_run_closed":
        issues.append("empty_tool_result_guard.on_limit")
    if recovery.get("enabled") is not True:
        issues.append("tool_validation_recovery.enabled")
    if recovery.get("scope") != "pydantic_tool_argument_validation_only":
        issues.append("tool_validation_recovery.scope")
    if recovery.get("valid_tool_call_limits_affected") is not False:
        issues.append("tool_validation_recovery.valid_tool_call_limits_affected")
    if bool(budget.get("enabled")):
        issues.append("run_budget_guard.enabled")
    elapsed = payload.get("elapsed_seconds")
    if not isinstance(elapsed, (int, float)):
        issues.append("elapsed_seconds")
    elif float(elapsed) > TIMEOUTS["run_hard_wall_seconds"] + 5:
        issues.append("elapsed_seconds.run_hard_wall")

    activity = payload.get("investigation_activity") or {}
    summary = activity.get("summary") or {}
    usage = payload.get("usage") or {}
    cost = payload.get("cost_estimate") or {}
    usage_audit = payload.get("usage_audit") or {}
    calls = (payload.get("usage_breakdown") or {}).get(
        "full_pipeline_calls"
    ) or []
    durations = [
        float(call["duration_seconds"])
        for call in calls
        if call.get("duration_seconds") is not None
    ]
    issues = sorted(set(issues))
    return {
        "schema_version": "normal_attack8_two_model_replicate_run_audit_v1",
        "replicate": replicate,
        "phase": phase["name"],
        "model": model,
        "stage": case["stage"],
        "chain_id": case["chain_id"],
        "instance_id": case["instance_id"],
        "path": str(path),
        "sha256": sha256(path),
        "case_file_sha256": sha256(phase["cases"]),
        "validation_sha256": sha256(phase["validation"]),
        "gold_sha256": sha256(expected_gold),
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "usage": usage,
        "api_call_count": usage_audit.get("full_pipeline_call_count"),
        "cost_usd": cost.get("total_cost_usd"),
        "elapsed_seconds": elapsed,
        "max_llm_call_duration_seconds": round(max(durations, default=0.0), 3),
        "activity": {
            "chief_leads": summary.get("lead_call_count"),
            "unique_chief_leads": summary.get("unique_lead_count"),
            "investigator_questions": summary.get("investigator_question_count"),
            "unique_investigator_questions": summary.get(
                "unique_investigator_question_count"
            ),
            "sql_queries": summary.get("sql_query_count"),
            "unique_sql_queries": summary.get("unique_sql_query_count"),
        },
    }


def contract_payload(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> dict[str, Any]:
    return {
        "schema_version": "normal_attack8_two_model_replicates_02_03_v1",
        "purpose": (
            "replicates 02 and 03 for final three-replicate presentation; "
            "replicate 01 stays frozen for the current interim report"
        ),
        "models": list(MODELS),
        "forbidden_models": ["gpt-5.5"],
        "replicates": list(REPLICATES),
        "phase_order": [phase["name"] for phase, _ in phase_cases],
        "stage_order": list(STAGES),
        "runs_per_phase_per_replicate": 48,
        "runs_per_replicate": 96,
        "new_run_count": 192,
        "replicate_01_run_count": 96,
        "final_three_replicate_run_count": 288,
        "create_only": True,
        "budget_guard_enabled": False,
        "execution_contract": {
            "max_tokens": 24576,
            "sql_playbook": "none",
            "agent_call_limit_policy": "unbounded_by_experiment",
            "frontier_closure_policy": FRONTIER_CLOSURE_POLICY,
            "five_minute_window": True,
            "stage3_cbc_alert_summary_hidden": True,
            "usage_scope": "full_pipeline_callback_v1",
            "max_investigator_questions_per_lead": 20,
            "timeouts": TIMEOUTS,
        },
        "replicate_01_provenance": {
            key: str(path) for key, path in BASELINE_ROOTS.items()
        },
        "initial_path_length_attempt": {
            "root": str(INITIAL_ATTEMPT_ROOT),
            "policy": (
                "freeze; import completed valid runs by hash; never rerun them"
            ),
        },
        "phases": [
            {
                "name": phase["name"],
                "case_file": str(phase["cases"]),
                "case_file_sha256": sha256(phase["cases"]),
                "validation_file": str(phase["validation"]),
                "validation_file_sha256": sha256(phase["validation"]),
                "case_count": len(cases),
                "instance_ids": [case["instance_id"] for case in cases],
            }
            for phase, cases in phase_cases
        ],
        "code_files": {
            str(path): sha256(path) for path in CODE_FILES
        },
    }


def create_contract(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> None:
    path = RESULT_ROOT / "experiment_contract.json"
    payload = contract_payload(phase_cases)
    if path.exists():
        if read_json(path) != payload:
            raise RuntimeError(f"existing experiment contract differs: {path}")
        return
    write_create_only(path, payload)


def create_preflight(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> dict[str, Any]:
    issues: list[str] = []
    if MODELS != ("gpt-4.1-mini", "gpt-5.4-mini"):
        issues.append("models")
    if len(REPLICATES) != 2:
        issues.append("replicates")
    if sum(len(cases) for _, cases in phase_cases) != 48:
        issues.append("phase_case_total")
    for phase, _ in phase_cases:
        if not phase["cases"].is_file():
            issues.append(f"missing_cases.{phase['name']}")
        if not phase["validation"].is_file():
            issues.append(f"missing_validation.{phase['name']}")
    for key, baseline in BASELINE_ROOTS.items():
        if not baseline.is_dir():
            issues.append(f"missing_baseline.{key}")
    payload = {
        "schema_version": "normal_attack8_two_model_replicates_preflight_v1",
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "api_calls_issued": 0,
        "models": list(MODELS),
        "replicates": list(REPLICATES),
        "expected_new_runs": 192,
        "budget_guard_enabled": False,
        "contract_sha256": sha256(RESULT_ROOT / "experiment_contract.json"),
    }
    path = RESULT_ROOT / "preflight.json"
    if path.exists():
        if read_json(path) != payload:
            raise RuntimeError(f"existing preflight differs: {path}")
    else:
        write_create_only(path, payload)
    if issues:
        raise RuntimeError(f"preflight failed: {issues}")
    return payload


def failure_audit(
    exc: Exception,
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "normal_attack8_two_model_replicate_run_audit_v1",
        "replicate": replicate,
        "phase": phase["name"],
        "model": model,
        "stage": case["stage"],
        "chain_id": case["chain_id"],
        "instance_id": case["instance_id"],
        "path": None,
        "sha256": None,
        "status": "FAIL",
        "issues": ["runner_exception"],
        "runner_exception": f"{type(exc).__name__}: {exc}",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def execute_replicate(
    replicate: str,
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> dict[str, Any]:
    audits: list[dict[str, Any]] = []
    failure_policy = os.getenv(
        "CLOUSEAU_MATRIX_FAILURE_POLICY", "fail_closed"
    )
    if failure_policy not in {"fail_closed", "record_and_continue"}:
        raise RuntimeError(
            f"unsupported CLOUSEAU_MATRIX_FAILURE_POLICY={failure_policy!r}"
        )
    consecutive_connectivity_failures = 0
    for phase, cases in phase_cases:
        args = runner_args(replicate, phase)
        for model in MODELS:
            for case in cases:
                path = run_path(replicate, phase, model, case)
                audit_file = audit_path(replicate, phase, model, case)
                imported_initial = False
                if not path.exists():
                    imported_initial = import_initial_attempt_run(
                        replicate, phase, model, case, path
                    )
                if path.exists() and audit_file.exists():
                    audit = read_json(audit_file)
                    if audit.get("sha256") != sha256(path):
                        raise RuntimeError(
                            f"existing run/audit hash mismatch: {audit_file}"
                        )
                elif audit_file.exists():
                    audit = read_json(audit_file)
                    if audit.get("status") != "FAIL" or audit.get("path"):
                        raise RuntimeError(
                            f"orphan audit is not an immutable failure: {audit_file}"
                        )
                elif path.exists():
                    audit = audit_run(
                        path, replicate, phase, model, case
                    )
                    audit["origin"] = (
                        "initial_path_length_attempt_import"
                        if imported_initial
                        else "existing_create_only"
                    )
                    write_create_only(audit_file, audit)
                else:
                    append_progress(
                        {
                            "at_utc": datetime.now(timezone.utc).isoformat(),
                            "event": "run_started",
                            "replicate": replicate,
                            "phase": phase["name"],
                            "model": model,
                            "stage": case["stage"],
                            "instance_id": case["instance_id"],
                        }
                    )
                    try:
                        path = paired.run_runner(case, model, args, False)
                        audit = audit_run(
                            path, replicate, phase, model, case
                        )
                    except Exception as exc:
                        audit = failure_audit(
                            exc, replicate, phase, model, case
                        )
                    write_create_only(audit_file, audit)
                audits.append(audit)
                append_progress(
                    {
                        "at_utc": datetime.now(timezone.utc).isoformat(),
                        "event": "run_audited",
                        "completed_in_replicate": len(audits),
                        "expected_in_replicate": 96,
                        "replicate": replicate,
                        "phase": phase["name"],
                        "model": model,
                        "stage": case["stage"],
                        "instance_id": case["instance_id"],
                        "status": audit["status"],
                        "cost_usd": audit.get("cost_usd"),
                    }
                )
                print(
                    json.dumps(
                        {
                            "replicate": replicate,
                            "completed": len(audits),
                            "expected": 96,
                            "phase": phase["name"],
                            "model": model,
                            "stage": case["stage"],
                            "instance_id": case["instance_id"],
                            "status": audit["status"],
                            "cost_usd": audit.get("cost_usd"),
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
                if audit["status"] == "PASS":
                    consecutive_connectivity_failures = 0
                else:
                    failure_text = str(
                        audit.get("runner_exception") or audit.get("issues")
                    )
                    if any(
                        marker in failure_text
                        for marker in (
                            "APITimeoutError",
                            "APIConnectionError",
                            "insufficient_quota",
                        )
                    ):
                        consecutive_connectivity_failures += 1
                    else:
                        consecutive_connectivity_failures = 0
                if (
                    audit["status"] != "PASS"
                    and failure_policy == "fail_closed"
                ):
                    raise RuntimeError(
                        "fail-closed: stopping the experiment after the first "
                        f"failed audit ({replicate}/{phase['name']}/{model}/"
                        f"{case['instance_id']}); audit={audit_file}"
                    )
                if consecutive_connectivity_failures >= 3:
                    raise RuntimeError(
                        "connectivity circuit breaker: stopping after three "
                        "consecutive API connectivity/quota failures; "
                        f"last_audit={audit_file}"
                    )
    counts = Counter(str(audit["status"]) for audit in audits)
    summary = {
        "schema_version": "normal_attack8_two_model_replicate_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "replicate": replicate,
        "status": (
            "PASS"
            if len(audits) == 96 and counts == Counter({"PASS": 96})
            else "COMPLETE_WITH_FAILURES"
        ),
        "expected_runs": 96,
        "audited_runs": len(audits),
        "status_counts": dict(sorted(counts.items())),
        "total_cost_usd": round(
            sum(float(audit.get("cost_usd") or 0) for audit in audits), 12
        ),
        "audits": audits,
    }
    write_create_only(
        replicate_root(replicate) / "replicate_summary.json", summary
    )
    return summary


def execute(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> dict[str, Any]:
    summaries = [
        execute_replicate(replicate, phase_cases)
        for replicate in REPLICATES
    ]
    counts = Counter(
        audit["status"]
        for summary in summaries
        for audit in summary["audits"]
    )
    final = {
        "schema_version": "normal_attack8_two_model_replicates_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "PASS"
            if len(summaries) == 2 and counts == Counter({"PASS": 192})
            else "COMPLETE_WITH_FAILURES"
        ),
        "expected_new_runs": 192,
        "audited_new_runs": sum(
            int(summary["audited_runs"]) for summary in summaries
        ),
        "status_counts": dict(sorted(counts.items())),
        "total_cost_usd": round(
            sum(float(summary["total_cost_usd"]) for summary in summaries),
            12,
        ),
        "replicate_summaries": [
            {
                key: value
                for key, value in summary.items()
                if key != "audits"
            }
            for summary in summaries
        ],
    }
    write_create_only(RESULT_ROOT / "experiment_summary.json", final)
    return final


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.preflight_only == args.run:
        parser.error("select exactly one of --preflight-only or --run")

    configure_environment()
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    phase_cases = [(phase, load_phase_cases(phase)) for phase in PHASES]
    create_contract(phase_cases)
    preflight = create_preflight(phase_cases)
    if args.preflight_only:
        print(json.dumps(preflight, ensure_ascii=False, indent=2))
        return
    summary_path = RESULT_ROOT / "experiment_summary.json"
    if summary_path.exists():
        print(summary_path.read_text(encoding="utf-8"), end="")
        return
    final = execute(phase_cases)
    print(json.dumps(final, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
