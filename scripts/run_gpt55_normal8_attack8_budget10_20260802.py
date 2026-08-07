"""Run normal8 + attack8, all three stages, with GPT-5.5 and a $10/run cap.

The 48-run matrix is executed sequentially and create-only.  A run stopped by
the budget guard is retained as ``CENSORED`` and does not stop later cases.
Existing PASS/CENSORED artifacts are audited and reused; failed artifacts are
never overwritten or automatically retried in the same root.
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
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

import run_atlasv2_s3_s4_attack8_paired_experiment as paired  # noqa: E402


MODEL = "gpt-5.5"
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-02/"
    / "gpt55_normal8_attack8_three_stage_budget10_pilot_01"
)
PHASES = (
    {
        "name": "normal8",
        "cases": ROOT
        / "data/current_experiment/cases/"
        / "normal8_observable_component_v3_stage_cases_20260726.jsonl",
        "validation": ROOT
        / "docs/current_experiment/"
        / "normal8_observable_component_v3_stage3_validation_steps_20260726.csv",
    },
    {
        "name": "attack8",
        "cases": ROOT
        / "data/current_experiment/cases/"
        / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl",
        "validation": ROOT
        / "docs/current_experiment/"
        / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv",
    },
)
STAGES = ("stage1", "stage2", "stage3")
BUDGET = {
    "soft_api_calls": 350,
    "hard_api_calls": 400,
    "soft_total_tokens": 2_500_000,
    "hard_total_tokens": 3_000_000,
    "soft_cost_usd": 8.0,
    "hard_cost_usd": 10.0,
    "soft_chief_leads": 20,
    "hard_chief_leads": 24,
}
TIMEOUTS = {
    "llm_request_seconds": 600,
    "llm_hard_wall_seconds": 600,
    "run_hard_wall_seconds": 1800,
}


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
        "CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS": TIMEOUTS[
            "llm_hard_wall_seconds"
        ],
        "CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS": TIMEOUTS[
            "run_hard_wall_seconds"
        ],
    }
    os.environ.update({key: str(value) for key, value in values.items()})


def load_phase_cases(phase: dict[str, Any]) -> list[dict[str, Any]]:
    cases = paired.read_jsonl(phase["cases"])
    stage_counts = Counter(str(case.get("stage")) for case in cases)
    chain_counts = Counter(str(case.get("chain_id")) for case in cases)
    if len(cases) != 24:
        raise RuntimeError(f"{phase['name']} case_count={len(cases)}")
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        raise RuntimeError(
            f"{phase['name']} stage_counts={dict(stage_counts)}"
        )
    if len(chain_counts) != 8 or any(count != 3 for count in chain_counts.values()):
        raise RuntimeError(
            f"{phase['name']} chain_counts={dict(chain_counts)}"
        )
    return sorted(
        cases,
        key=lambda case: (
            STAGES.index(str(case["stage"])),
            str(case["chain_id"]),
            str(case["instance_id"]),
        ),
    )


def phase_root(phase: dict[str, Any]) -> Path:
    return RESULT_ROOT / str(phase["name"])


def runner_args(phase: dict[str, Any]) -> Namespace:
    return Namespace(
        cases=phase["cases"],
        result_root=phase_root(phase),
        validation_steps=phase["validation"],
        max_tokens=24576,
        sql_playbook="none",
        log_cost=True,
    )


def run_path(phase: dict[str, Any], case: dict[str, Any]) -> Path:
    return (
        phase_root(phase)
        / "runs"
        / MODEL
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )


def audit_path(phase: dict[str, Any], case: dict[str, Any]) -> Path:
    return (
        RESULT_ROOT
        / "audits"
        / str(phase["name"])
        / str(case["stage"])
        / f"{case['instance_id']}_audit.json"
    )


def audit_run(
    path: Path,
    phase: dict[str, Any],
    case: dict[str, Any],
) -> dict[str, Any]:
    payload = read_json(path)
    issues: list[str] = []
    if payload.get("model") != MODEL:
        issues.append("model")
    if payload.get("instance_id") != case["instance_id"]:
        issues.append("instance_id")
    if payload.get("error") is not None:
        issues.append("error")
    try:
        output = json.loads(str(payload.get("output_text") or ""))
        if not isinstance(output, dict):
            issues.append("output_text.not_object")
    except json.JSONDecodeError:
        issues.append("output_text.invalid_json")

    usage_audit = payload.get("usage_audit") or {}
    for key in (
        "full_pipeline_equals_role_total",
        "full_pipeline_equals_call_ledger",
        "callback_aggregate_equals_call_ledger",
    ):
        if usage_audit.get(key) is not True:
            issues.append(f"usage_audit.{key}")

    guard = payload.get("run_budget_guard") or {}
    config = guard.get("config") or {}
    if config.get("enabled") is not True:
        issues.append("run_budget_guard.disabled")
    for key, expected in BUDGET.items():
        if config.get(key) != expected:
            issues.append(f"run_budget_guard.config.{key}")

    configs = payload.get("configs") or {}
    if configs.get("max_investigations") is not None:
        issues.append("configs.max_investigations")
    if configs.get("max_questions") is not None:
        issues.append("configs.max_questions")
    if configs.get("max_queries") is not None:
        issues.append("configs.max_queries")
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        issues.append("configs.agent_call_limit_policy")

    cost = payload.get("cost_estimate") or {}
    usage = payload.get("usage") or {}
    if cost.get("call_count") != usage_audit.get("full_pipeline_call_count"):
        issues.append("cost_call_count")
    censored = bool(guard.get("budget_censored") or guard.get("hard_triggered"))
    # A hard budget stop can intentionally interrupt final JSON emission.
    # Preserve validation issues for diagnosis, but classify the run by the
    # experiment's predeclared censoring policy instead of treating the
    # expected partial output as an unrelated execution failure.
    if censored:
        status = "CENSORED"
    elif issues:
        status = "FAIL"
    else:
        status = "PASS"
    return {
        "schema_version": "gpt55_budget10_run_audit_v1",
        "audited_at_utc": payload.get("finished_at_utc"),
        "phase": phase["name"],
        "model": MODEL,
        "stage": case["stage"],
        "chain_id": case["chain_id"],
        "instance_id": case["instance_id"],
        "path": str(path),
        "sha256": sha256(path),
        "status": status,
        "issues": sorted(set(issues)),
        "usage": usage,
        "cost_estimate": {
            "call_count": cost.get("call_count"),
            "total_cost_usd": cost.get("total_cost_usd"),
        },
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "activity_summary": (
            payload.get("investigation_activity") or {}
        ).get("summary"),
        "run_budget_guard": guard,
    }


def create_contract(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> None:
    payload = {
        "schema_version": "gpt55_normal8_attack8_budget10_pilot_v1",
        "created_at_utc": "2026-08-02T00:00:00+00:00",
        "model": MODEL,
        "role_models": {
            "chief": MODEL,
            "investigator": MODEL,
            "sql_qa": MODEL,
        },
        "mixed_model_pipeline": False,
        "run_count": sum(len(cases) for _, cases in phase_cases),
        "phase_order": [phase["name"] for phase, _ in phase_cases],
        "stage_order": list(STAGES),
        "budget_per_run": BUDGET,
        "timeouts": TIMEOUTS,
        "budget_censored_scoring_policy": (
            "retain_artifact_and_exclude_from_headline_formal_accuracy"
        ),
        "create_only": True,
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
    }
    write_create_only(RESULT_ROOT / "experiment_contract.json", payload)


def create_preflight(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> None:
    issues: list[str] = []
    if MODEL != "gpt-5.5":
        issues.append("model")
    if BUDGET["soft_cost_usd"] != 8.0:
        issues.append("soft_cost")
    if BUDGET["hard_cost_usd"] != 10.0:
        issues.append("hard_cost")
    if sum(len(cases) for _, cases in phase_cases) != 48:
        issues.append("run_count")
    for phase, _ in phase_cases:
        if not phase["cases"].is_file():
            issues.append(f"missing_cases.{phase['name']}")
        if not phase["validation"].is_file():
            issues.append(f"missing_validation.{phase['name']}")
    payload = {
        "schema_version": "gpt55_normal8_attack8_budget10_preflight_v1",
        "created_at_utc": "2026-08-02T00:00:00+00:00",
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "api_calls_issued": 0,
        "expected_runs": 48,
        "model": MODEL,
        "budget_per_run": BUDGET,
    }
    write_create_only(RESULT_ROOT / "preflight.json", payload)
    if issues:
        raise RuntimeError(f"preflight failed: {issues}")


def execute(
    phase_cases: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> dict[str, Any]:
    audits: list[dict[str, Any]] = []
    for phase, cases in phase_cases:
        args = runner_args(phase)
        for case in cases:
            path = run_path(phase, case)
            audit_file = audit_path(phase, case)
            if path.exists() and audit_file.exists():
                audit = read_json(audit_file)
                if (
                    audit.get("sha256") != sha256(path)
                    or audit.get("instance_id") != case["instance_id"]
                    or audit.get("model") != MODEL
                ):
                    raise RuntimeError(
                        f"existing audit provenance mismatch: {audit_file}"
                    )
            elif path.exists():
                audit = audit_run(path, phase, case)
                audit = {"origin": "existing_create_only", **audit}
            else:
                append_progress(
                    {
                        "at_utc": datetime.now(timezone.utc).isoformat(),
                        "event": "run_started",
                        "phase": phase["name"],
                        "stage": case["stage"],
                        "instance_id": case["instance_id"],
                        "model": MODEL,
                    }
                )
                try:
                    path = paired.run_runner(case, MODEL, args, False)
                    audit = audit_run(path, phase, case)
                    audit = {"origin": "new_run", **audit}
                except Exception as exc:  # retain exact failure and continue matrix
                    audit = {
                        "origin": "runner_exception",
                        "schema_version": "gpt55_budget10_run_audit_v1",
                        "audited_at_utc": datetime.now(timezone.utc).isoformat(),
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
                    }
            if not audit_file.exists():
                write_create_only(audit_file, audit)
            audits.append(audit)
            append_progress(
                {
                    "at_utc": datetime.now(timezone.utc).isoformat(),
                    "event": "run_audited",
                    "audit_path": str(audit_file),
                    "status": audit["status"],
                    "phase": phase["name"],
                    "stage": case["stage"],
                    "instance_id": case["instance_id"],
                    "cost_usd": (
                        audit.get("cost_estimate") or {}
                    ).get("total_cost_usd"),
                }
            )
            print(
                json.dumps(
                    {
                        "completed": len(audits),
                        "expected": 48,
                        "phase": phase["name"],
                        "stage": case["stage"],
                        "instance_id": case["instance_id"],
                        "status": audit["status"],
                        "cost_usd": (
                            audit.get("cost_estimate") or {}
                        ).get("total_cost_usd"),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

    status_counts = Counter(str(audit["status"]) for audit in audits)
    cumulative_cost = round(
        sum(
            float((audit.get("cost_estimate") or {}).get("total_cost_usd") or 0)
            for audit in audits
        ),
        12,
    )
    summary = {
        "schema_version": "gpt55_normal8_attack8_budget10_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "COMPLETE"
            if len(audits) == 48 and not status_counts.get("FAIL")
            else "INCOMPLETE"
        ),
        "expected_runs": 48,
        "audited_runs": len(audits),
        "status_counts": dict(status_counts),
        "cumulative_cost_usd": cumulative_cost,
        "audits": audits,
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
    phase_cases = [(phase, load_phase_cases(phase)) for phase in PHASES]
    create_contract(phase_cases)
    create_preflight(phase_cases)
    if args.preflight_only:
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "expected_runs": 48,
                    "api_calls_issued": 0,
                    "result_root": str(RESULT_ROOT),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    summary_path = RESULT_ROOT / "experiment_summary.json"
    if summary_path.exists():
        print(summary_path.read_text(encoding="utf-8"), end="")
        return
    summary = execute(phase_cases)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
