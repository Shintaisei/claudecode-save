#!/usr/bin/env python3
"""Run GPT-5.5 normal8 + attack8, three stages, for three replicates.

The matrix has 144 logical runs.  Replicate-01 reuses only legacy GPT-5.5
runs whose budget guard never triggered (45 runs, SHA-bound); the remaining
99 runs are new.  A cost-only $20 guard is used for new runs: soft and hard
cost thresholds are identical and all other budget thresholds are set well
above practical values.  Therefore a completed PASS run has not experienced
soft frontier truncation; a threshold crossing is retained as CENSORED.

All artifacts are create-only.  Run-scoped failures are recorded and the
first pass continues; three consecutive connectivity/quota failures open the
circuit breaker.
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
RUNNER_DIR = ROOT / "src/clouseau_process_time"
SCRIPTS_DIR = ROOT / "scripts"
for candidate in (RUNNER_DIR, SCRIPTS_DIR):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import run_atlasv2_s3_s4_attack8_paired_experiment as paired  # noqa: E402
import run_normal_attack_full_ledger_pilot05_20260730 as pilot05  # noqa: E402


MODEL = "gpt-5.5"
REPLICATES = ("replicate_01", "replicate_02", "replicate_03")
STAGES = ("stage1", "stage2", "stage3")
FRONTIER_POLICY = "semantic_fingerprint_atomic_guard_v16_with_empty_response_fail_closed"
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-06"
    / "gpt55_normal_attack8_three_replicates_cost20_formal_01"
)
LEGACY_MAIN = (
    ROOT
    / "docs/current_experiment/results_2026-08-02"
    / "gpt55_normal8_attack8_three_stage_budget10_pilot_01"
)
LEGACY_NORMAL_RETRY = (
    ROOT
    / "docs/current_experiment/results_2026-08-03"
    / "gpt55_normal8_attack8_budget10_retry_01"
)
PHASES = (
    {
        "name": "normal8",
        "cases": ROOT / "data/current_experiment/cases/normal8_observable_component_v3_stage_cases_20260726.jsonl",
        "validation": ROOT / "docs/current_experiment/normal8_observable_component_v3_stage3_validation_steps_20260726.csv",
    },
    {
        "name": "attack8",
        "cases": ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl",
        "validation": ROOT / "docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv",
    },
)
TIMEOUTS = {
    "llm_request_seconds": 600,
    "llm_hard_wall_seconds": 600,
    "run_hard_wall_seconds": 1800,
    "lead_wall_seconds": 1200,
}
BUDGET = {
    "soft_api_calls": 1_000_000,
    "hard_api_calls": 1_000_000,
    "soft_total_tokens": 1_000_000_000,
    "hard_total_tokens": 1_000_000_000,
    "soft_cost_usd": 20.0,
    "hard_cost_usd": 20.0,
    "soft_chief_leads": 10_000,
    "hard_chief_leads": 10_000,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
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
    path = RESULT_ROOT / "_logs/progress.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")


def configure_environment() -> None:
    values = {
        "CLOUSEAU_RUN_BUDGET_GUARD_ENABLED": "1",
        "CLOUSEAU_RUN_BUDGET_SOFT_API_CALLS": BUDGET["soft_api_calls"],
        "CLOUSEAU_RUN_BUDGET_HARD_API_CALLS": BUDGET["hard_api_calls"],
        "CLOUSEAU_RUN_BUDGET_SOFT_TOTAL_TOKENS": BUDGET["soft_total_tokens"],
        "CLOUSEAU_RUN_BUDGET_HARD_TOTAL_TOKENS": BUDGET["hard_total_tokens"],
        "CLOUSEAU_RUN_BUDGET_SOFT_COST_USD": BUDGET["soft_cost_usd"],
        "CLOUSEAU_RUN_BUDGET_HARD_COST_USD": BUDGET["hard_cost_usd"],
        "CLOUSEAU_RUN_BUDGET_SOFT_CHIEF_LEADS": BUDGET["soft_chief_leads"],
        "CLOUSEAU_RUN_BUDGET_HARD_CHIEF_LEADS": BUDGET["hard_chief_leads"],
        "CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS": TIMEOUTS["llm_request_seconds"],
        "CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS": TIMEOUTS["llm_hard_wall_seconds"],
        "CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS": TIMEOUTS["run_hard_wall_seconds"],
        "CLOUSEAU_MAX_INVESTIGATOR_QUESTIONS_PER_LEAD": 20,
        "CLOUSEAU_MAX_LEAD_WALL_SECONDS": TIMEOUTS["lead_wall_seconds"],
        "CLOUSEAU_MATRIX_FAILURE_POLICY": "record_and_continue",
    }
    os.environ.update({key: str(value) for key, value in values.items()})


def load_cases(phase: dict[str, Any]) -> list[dict[str, Any]]:
    cases = paired.read_jsonl(phase["cases"])
    stage_counts = Counter(str(case.get("stage")) for case in cases)
    chain_counts = Counter(str(case.get("chain_id")) for case in cases)
    issues: list[str] = []
    if len(cases) != 24:
        issues.append(f"case_count={len(cases)}")
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        issues.append(f"stage_counts={dict(stage_counts)}")
    if len(chain_counts) != 8 or any(count != 3 for count in chain_counts.values()):
        issues.append(f"chain_counts={dict(chain_counts)}")
    for case in cases:
        window = case.get("time_window_utc") or {}
        try:
            start = datetime.fromisoformat(str(window["episode_start"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(window["episode_end"]).replace("Z", "+00:00"))
            if (end - start).total_seconds() != 300:
                issues.append(f"non_five_minute_window.{case['instance_id']}")
        except (KeyError, TypeError, ValueError):
            issues.append(f"invalid_window.{case.get('instance_id')}")
    if issues:
        raise RuntimeError(f"{phase['name']} case contract failed: {issues}")
    return sorted(cases, key=lambda c: (STAGES.index(str(c["stage"])), str(c["chain_id"])))


def phase_root(replicate: str, phase: dict[str, Any]) -> Path:
    return RESULT_ROOT / replicate / str(phase["name"])


def run_path(replicate: str, phase: dict[str, Any], case: dict[str, Any]) -> Path:
    return phase_root(replicate, phase) / "runs" / MODEL / str(case["stage"]) / f"{case['instance_id']}_run.json"


def audit_path(replicate: str, phase: dict[str, Any], case: dict[str, Any]) -> Path:
    key = f"{replicate}|{phase['name']}|{MODEL}|{case['instance_id']}"
    audit_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return RESULT_ROOT / replicate / "audits" / str(phase["name"]) / "g55" / f"{audit_id}.json"


def runner_args(replicate: str, phase: dict[str, Any]) -> Namespace:
    return Namespace(
        cases=phase["cases"],
        result_root=phase_root(replicate, phase),
        validation_steps=phase["validation"],
        max_tokens=24576,
        sql_playbook="none",
        log_cost=True,
    )


def legacy_candidates(phase: dict[str, Any], case: dict[str, Any]) -> list[Path]:
    relative = Path(str(phase["name"])) / "runs" / MODEL / str(case["stage"]) / f"{case['instance_id']}_run.json"
    return [LEGACY_NORMAL_RETRY / relative, LEGACY_MAIN / relative]


def eligible_legacy_source(phase: dict[str, Any], case: dict[str, Any]) -> Path | None:
    for source in legacy_candidates(phase, case):
        if not source.is_file():
            continue
        payload = read_json(source)
        guard = payload.get("run_budget_guard") or {}
        configs = payload.get("configs") or {}
        if (
            payload.get("model") == MODEL
            and payload.get("instance_id") == case["instance_id"]
            and payload.get("error") is None
            and configs.get("frontier_closure_policy") == FRONTIER_POLICY
            and not guard.get("soft_triggered")
            and not guard.get("hard_triggered")
            and not guard.get("budget_censored")
        ):
            try:
                output = json.loads(str(payload.get("output_text") or ""))
            except json.JSONDecodeError:
                continue
            if isinstance(output, dict):
                return source
    return None


def import_legacy(replicate: str, phase: dict[str, Any], case: dict[str, Any], destination: Path) -> Path | None:
    if replicate != "replicate_01":
        return None
    source = eligible_legacy_source(phase, case)
    if source is None:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256(destination) != sha256(source):
            raise RuntimeError(f"import differs: {destination}")
    else:
        shutil.copy2(source, destination)
    provenance = {
        "schema_version": "gpt55_three_replicate_import_v1",
        "replicate": replicate,
        "phase": phase["name"],
        "instance_id": case["instance_id"],
        "source": str(source),
        "source_sha256": sha256(source),
        "destination": str(destination),
        "destination_sha256": sha256(destination),
        "eligibility": "legacy budget guard never soft/hard triggered",
    }
    write_create_only(RESULT_ROOT / replicate / "imports" / str(phase["name"]) / f"{case['instance_id']}.json", provenance)
    return source


def audit_run(path: Path, replicate: str, phase: dict[str, Any], case: dict[str, Any], origin: str) -> dict[str, Any]:
    stage_number = int(str(case["stage"])[-1])
    base = pilot05.validate_run(path, {"pair_id": f"{replicate}_{phase['name']}_{MODEL}", "chain_id": case["chain_id"], "model": MODEL}, stage_number)
    payload = read_json(path)
    issues = list(base.get("issues") or [])
    binding = payload.get("atlasv2_s3_s4_attack8_paired_experiment") or {}
    configs = payload.get("configs") or {}
    llm = configs.get("llm_execution_guard") or {}
    empty = configs.get("empty_tool_result_guard") or {}
    recovery = configs.get("tool_validation_recovery") or {}
    guard = payload.get("run_budget_guard") or {}
    guard_config = guard.get("config") or configs.get("run_budget_guard") or {}
    expected_gold = paired.resolve_gold(case).resolve()
    if payload.get("model") != MODEL:
        issues.append("model")
    if Path(str(binding.get("case_file") or "")).resolve() != Path(phase["cases"]).resolve():
        issues.append("binding.case_file")
    if binding.get("chain_id") != case["chain_id"] or binding.get("stage") != case["stage"]:
        issues.append("binding.case_or_stage")
    if Path(str(binding.get("gold") or "")).resolve() != expected_gold:
        issues.append("binding.gold")
    if configs.get("frontier_closure_policy") != FRONTIER_POLICY:
        issues.append("configs.frontier_closure_policy")
    for key in ("max_investigations", "max_questions", "max_queries"):
        if configs.get(key) is not None:
            issues.append(f"configs.{key}")
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        issues.append("configs.agent_call_limit_policy")
    if llm.get("max_completion_tokens") != 24576 or llm.get("request_timeout_seconds") != 600.0 or llm.get("hard_wall_timeout_seconds") != 600.0:
        issues.append("llm_execution_guard")
    if empty.get("enabled") is not True or empty.get("on_limit") != "fail_run_closed":
        issues.append("empty_tool_result_guard")
    if recovery.get("enabled") is not True:
        issues.append("tool_validation_recovery")
    if guard_config.get("enabled") is not True:
        issues.append("run_budget_guard.disabled")
    if origin == "new_run":
        for key, expected in BUDGET.items():
            if guard_config.get(key) != expected:
                issues.append(f"run_budget_guard.config.{key}")
    else:
        if guard.get("soft_triggered") or guard.get("hard_triggered") or guard.get("budget_censored"):
            issues.append("legacy_budget_triggered")
    elapsed = payload.get("elapsed_seconds")
    if not isinstance(elapsed, (int, float)) or float(elapsed) > TIMEOUTS["run_hard_wall_seconds"] + 5:
        issues.append("elapsed_seconds")
    usage_audit = payload.get("usage_audit") or {}
    for key in ("full_pipeline_equals_role_total", "full_pipeline_equals_call_ledger", "callback_aggregate_equals_call_ledger"):
        if usage_audit.get(key) is not True:
            issues.append(f"usage_audit.{key}")
    censored = bool(guard.get("hard_triggered") or guard.get("budget_censored"))
    if censored:
        status = "CENSORED"
    elif payload.get("error") is not None:
        issues.append("error")
        status = "FAIL"
    else:
        try:
            output = json.loads(str(payload.get("output_text") or ""))
            if not isinstance(output, dict):
                issues.append("output_text.not_object")
        except json.JSONDecodeError:
            issues.append("output_text.invalid_json")
        status = "FAIL" if issues else "PASS"
    activity = (payload.get("investigation_activity") or {}).get("summary") or {}
    usage = payload.get("usage") or {}
    cost = payload.get("cost_estimate") or {}
    return {
        "schema_version": "gpt55_normal_attack8_three_replicate_run_audit_v1",
        "origin": origin,
        "replicate": replicate,
        "phase": phase["name"],
        "model": MODEL,
        "stage": case["stage"],
        "chain_id": case["chain_id"],
        "instance_id": case["instance_id"],
        "path": str(path),
        "sha256": sha256(path),
        "case_file_sha256": sha256(phase["cases"]),
        "validation_sha256": sha256(phase["validation"]),
        "gold_sha256": sha256(expected_gold),
        "status": status,
        "issues": sorted(set(issues)),
        "usage": usage,
        "api_call_count": usage_audit.get("full_pipeline_call_count"),
        "cost_usd": cost.get("total_cost_usd"),
        "elapsed_seconds": elapsed,
        "activity": {
            "chief_leads": activity.get("lead_call_count"),
            "unique_chief_leads": activity.get("unique_lead_count"),
            "investigator_questions": activity.get("investigator_question_count"),
            "unique_investigator_questions": activity.get("unique_investigator_question_count"),
            "sql_queries": activity.get("sql_query_count"),
            "unique_sql_queries": activity.get("unique_sql_query_count"),
        },
        "run_budget_guard": guard,
    }


def failure_audit(exc: Exception, replicate: str, phase: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "gpt55_normal_attack8_three_replicate_run_audit_v1",
        "origin": "runner_exception",
        "replicate": replicate,
        "phase": phase["name"],
        "model": MODEL,
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


def contract_payload(phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> dict[str, Any]:
    eligible = []
    for phase, cases in phase_cases:
        for case in cases:
            source = eligible_legacy_source(phase, case)
            if source:
                eligible.append({"phase": phase["name"], "instance_id": case["instance_id"], "source": str(source), "sha256": sha256(source)})
    return {
        "schema_version": "gpt55_normal_attack8_three_replicates_cost20_formal_v1",
        "model": MODEL,
        "role_models": {"chief": MODEL, "investigator": MODEL, "sql_qa": MODEL},
        "replicates": list(REPLICATES),
        "logical_run_count": 144,
        "legacy_import_count": len(eligible),
        "expected_new_run_count": 144 - len(eligible),
        "create_only": True,
        "matrix_failure_policy": "record_and_continue_then_versioned_failure_retry",
        "connectivity_circuit_breaker": 3,
        "execution_contract": {
            "max_tokens": 24576,
            "sql_playbook": "none",
            "five_minute_window": True,
            "stage3_cbc_alert_summary_hidden": True,
            "agent_call_limit_policy": "unbounded_by_experiment",
            "frontier_closure_policy": FRONTIER_POLICY,
            "usage_scope": "full_pipeline_callback_v1",
            "max_investigator_questions_per_lead": 20,
            "timeouts": TIMEOUTS,
            "budget_guard": BUDGET,
            "budget_semantics": "cost-only; soft equals hard, so no PASS run is frontier-truncated before the hard threshold; crossing run is CENSORED",
        },
        "legacy_sources": {"main": str(LEGACY_MAIN), "normal_retry": str(LEGACY_NORMAL_RETRY)},
        "eligible_legacy_runs": eligible,
        "phases": [{"name": phase["name"], "case_file": str(phase["cases"]), "case_file_sha256": sha256(phase["cases"]), "validation_file": str(phase["validation"]), "validation_sha256": sha256(phase["validation"]), "case_count": len(cases)} for phase, cases in phase_cases],
        "code_files": {str(Path(__file__).resolve()): sha256(Path(__file__).resolve()), str(RUNNER_DIR / "run_atlasv2_s3_s4_attack8_paired_experiment.py"): sha256(RUNNER_DIR / "run_atlasv2_s3_s4_attack8_paired_experiment.py"), str(RUNNER_DIR / "run_clouseau_official_normal_behavior.py"): sha256(RUNNER_DIR / "run_clouseau_official_normal_behavior.py")},
    }


def create_preflight(phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> dict[str, Any]:
    issues: list[str] = []
    if sum(len(cases) for _, cases in phase_cases) != 48:
        issues.append("phase_case_total")
    eligible = sum(eligible_legacy_source(phase, case) is not None for phase, cases in phase_cases for case in cases)
    if eligible != 45:
        issues.append(f"legacy_eligible={eligible}, expected=45")
    if BUDGET["soft_cost_usd"] != BUDGET["hard_cost_usd"]:
        issues.append("soft_hard_cost_not_equal")
    payload = {
        "schema_version": "gpt55_normal_attack8_three_replicates_preflight_v1",
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "api_calls_issued": 0,
        "logical_runs": 144,
        "legacy_imports": eligible,
        "expected_new_runs": 144 - eligible,
        "model": MODEL,
        "budget_guard": BUDGET,
        "contract_sha256": sha256(RESULT_ROOT / "experiment_contract.json"),
    }
    write_create_only(RESULT_ROOT / "preflight.json", payload)
    if issues:
        raise RuntimeError(f"preflight failed: {issues}")
    return payload


def execute(phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> dict[str, Any]:
    all_audits: list[dict[str, Any]] = []
    consecutive_connectivity_failures = 0
    for replicate in REPLICATES:
        rep_audits: list[dict[str, Any]] = []
        for phase, cases in phase_cases:
            args = runner_args(replicate, phase)
            for case in cases:
                path = run_path(replicate, phase, case)
                audit_file = audit_path(replicate, phase, case)
                imported = None
                if not path.exists():
                    imported = import_legacy(replicate, phase, case, path)
                if path.exists() and audit_file.exists():
                    audit = read_json(audit_file)
                    if audit.get("sha256") != sha256(path):
                        raise RuntimeError(f"existing run/audit hash mismatch: {audit_file}")
                elif audit_file.exists():
                    audit = read_json(audit_file)
                    if audit.get("status") not in {"FAIL", "CENSORED"} or audit.get("path"):
                        raise RuntimeError(f"unexpected orphan audit: {audit_file}")
                elif path.exists():
                    audit = audit_run(path, replicate, phase, case, "legacy_import" if imported else "existing_create_only")
                    write_create_only(audit_file, audit)
                else:
                    append_progress({"at_utc": datetime.now(timezone.utc).isoformat(), "event": "run_started", "replicate": replicate, "phase": phase["name"], "stage": case["stage"], "instance_id": case["instance_id"], "model": MODEL})
                    try:
                        produced = paired.run_runner(case, MODEL, args, False)
                        audit = audit_run(produced, replicate, phase, case, "new_run")
                    except Exception as exc:
                        audit = failure_audit(exc, replicate, phase, case)
                    write_create_only(audit_file, audit)
                rep_audits.append(audit)
                all_audits.append(audit)
                append_progress({"at_utc": datetime.now(timezone.utc).isoformat(), "event": "run_audited", "completed": len(all_audits), "expected": 144, "replicate": replicate, "phase": phase["name"], "stage": case["stage"], "instance_id": case["instance_id"], "status": audit["status"], "cost_usd": audit.get("cost_usd")})
                print(json.dumps({"completed": len(all_audits), "expected": 144, "replicate": replicate, "phase": phase["name"], "stage": case["stage"], "instance_id": case["instance_id"], "status": audit["status"], "cost_usd": audit.get("cost_usd")}, ensure_ascii=False), flush=True)
                if audit["status"] == "PASS":
                    consecutive_connectivity_failures = 0
                else:
                    text = str(audit.get("runner_exception") or audit.get("issues"))
                    if any(marker in text for marker in ("APITimeoutError", "APIConnectionError", "insufficient_quota")):
                        consecutive_connectivity_failures += 1
                    else:
                        consecutive_connectivity_failures = 0
                if consecutive_connectivity_failures >= 3:
                    raise RuntimeError(f"connectivity circuit breaker after three consecutive failures; last={audit_file}")
        counts = Counter(a["status"] for a in rep_audits)
        rep_summary = {
            "schema_version": "gpt55_normal_attack8_three_replicate_summary_v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "replicate": replicate,
            "status": "PASS" if counts == Counter({"PASS": 48}) else "COMPLETE_WITH_NONPASS",
            "expected_runs": 48,
            "audited_runs": len(rep_audits),
            "status_counts": dict(sorted(counts.items())),
            "total_cost_usd": round(sum(float(a.get("cost_usd") or 0) for a in rep_audits), 12),
            "audits": rep_audits,
        }
        write_create_only(RESULT_ROOT / replicate / "replicate_summary.json", rep_summary)
    counts = Counter(a["status"] for a in all_audits)
    summary = {
        "schema_version": "gpt55_normal_attack8_three_replicates_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if counts == Counter({"PASS": 144}) else "COMPLETE_WITH_NONPASS",
        "expected_runs": 144,
        "audited_runs": len(all_audits),
        "status_counts": dict(sorted(counts.items())),
        "total_cost_usd": round(sum(float(a.get("cost_usd") or 0) for a in all_audits), 12),
    }
    write_create_only(RESULT_ROOT / "experiment_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.preflight_only == args.run:
        parser.error("select exactly one of --preflight-only or --run")
    configure_environment()
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    phase_cases = [(phase, load_cases(phase)) for phase in PHASES]
    write_create_only(RESULT_ROOT / "experiment_contract.json", contract_payload(phase_cases))
    preflight = create_preflight(phase_cases)
    if args.preflight_only:
        print(json.dumps(preflight, ensure_ascii=False, indent=2))
        return
    summary_file = RESULT_ROOT / "experiment_summary.json"
    if summary_file.exists():
        print(summary_file.read_text(encoding="utf-8"), end="")
        return
    print(json.dumps(execute(phase_cases), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
