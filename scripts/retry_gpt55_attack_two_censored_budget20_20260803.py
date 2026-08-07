"""Create-only retry for the two GPT-5.5 attack runs censored at $10.

The source artifacts remain frozen.  This runner executes only the two missing
attack strata after the active two-model replicate runner has stopped.  Every
role remains GPT-5.5.  The retry uses a $15 soft cost guard and a $20 hard cost
guard; the token guard is widened only enough to keep the cost guard active.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_gpt55_normal8_attack8_budget10_20260802 as base  # noqa: E402


INSTANCE_IDS = (
    "s4_pt_04_powershell_c1_stage1",
    "s4_pt_03_mshta_c1_stage3",
)
SOURCE_ROOT = base.RESULT_ROOT
RETRY_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-03"
    / "gpt55_attack_two_censored_budget20_retry_01"
)
RETRY_BUDGET = {
    "soft_api_calls": 350,
    "hard_api_calls": 400,
    "soft_total_tokens": 4_500_000,
    "hard_total_tokens": 6_000_000,
    "soft_cost_usd": 15.0,
    "hard_cost_usd": 20.0,
    "soft_chief_leads": 20,
    "hard_chief_leads": 24,
}
ACTIVE_PREDECESSOR = "run_normal_attack8_two_model_replicates_02_03_20260803.py"


def attack_phase() -> dict[str, Any]:
    matches = [phase for phase in base.PHASES if phase["name"] == "attack8"]
    if len(matches) != 1:
        raise RuntimeError(f"expected one attack8 phase, found {len(matches)}")
    return matches[0]


def selected_cases(phase: dict[str, Any]) -> list[dict[str, Any]]:
    by_id = {case["instance_id"]: case for case in base.load_phase_cases(phase)}
    missing = [instance_id for instance_id in INSTANCE_IDS if instance_id not in by_id]
    if missing:
        raise RuntimeError(f"retry cases missing from formal case file: {missing}")
    return [by_id[instance_id] for instance_id in INSTANCE_IDS]


def source_audit_path(case: dict[str, Any]) -> Path:
    return (
        SOURCE_ROOT
        / "audits/attack8"
        / str(case["stage"])
        / f"{case['instance_id']}_audit.json"
    )


def source_run_path(case: dict[str, Any]) -> Path:
    return (
        SOURCE_ROOT
        / "attack8/runs"
        / base.MODEL
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )


def validate_source(case: dict[str, Any]) -> dict[str, Any]:
    audit_file = source_audit_path(case)
    run_file = source_run_path(case)
    if not audit_file.is_file() or not run_file.is_file():
        raise RuntimeError(f"missing frozen source artifact: {audit_file} {run_file}")
    audit = base.read_json(audit_file)
    guard = audit.get("run_budget_guard") or {}
    if audit.get("instance_id") != case["instance_id"]:
        raise RuntimeError(f"source instance mismatch: {audit_file}")
    if not bool(guard.get("budget_censored") and guard.get("hard_triggered")):
        raise RuntimeError(f"source is not the expected hard-budget censor: {audit_file}")
    if audit.get("sha256") != base.sha256(run_file):
        raise RuntimeError(f"source run hash mismatch: {run_file}")
    return {
        "instance_id": case["instance_id"],
        "stage": case["stage"],
        "source_audit": str(audit_file),
        "source_audit_sha256": base.sha256(audit_file),
        "source_run": str(run_file),
        "source_run_sha256": base.sha256(run_file),
        "source_cost_usd": (audit.get("cost_estimate") or {}).get(
            "total_cost_usd"
        ),
        "source_status": audit.get("status"),
        "source_budget_censored": True,
    }


def predecessor_pids() -> list[int]:
    """Return active predecessor PIDs without treating inspection failure as safe."""
    command = (
        "$needle='" + ACTIVE_PREDECESSOR + "'; "
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.ProcessId -ne " + str(os.getpid()) + " -and "
        "$_.Name -like 'python*' -and "
        "$_.CommandLine -like ('*' + $needle + '*') } | "
        "ForEach-Object { $_.ProcessId }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "could not verify predecessor process state: " + result.stderr.strip()
        )
    return [int(line) for line in result.stdout.splitlines() if line.strip().isdigit()]


def contract_payload(
    phase: dict[str, Any],
    cases: list[dict[str, Any]],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "gpt55_attack_two_censored_budget20_retry_v1",
        "created_at_utc": "2026-08-03T00:00:00+00:00",
        "source_root": str(SOURCE_ROOT),
        "source_experiment_contract_sha256": base.sha256(
            SOURCE_ROOT / "experiment_contract.json"
        ),
        "retry_root": str(RETRY_ROOT),
        "model": base.MODEL,
        "role_models": {
            "chief": base.MODEL,
            "investigator": base.MODEL,
            "sql_qa": base.MODEL,
        },
        "mixed_model_pipeline": False,
        "phase": "attack8",
        "case_file": str(phase["cases"]),
        "case_file_sha256": base.sha256(phase["cases"]),
        "validation_file": str(phase["validation"]),
        "validation_file_sha256": base.sha256(phase["validation"]),
        "instance_ids": [case["instance_id"] for case in cases],
        "frozen_sources": sources,
        "budget_per_run": RETRY_BUDGET,
        "timeouts": base.TIMEOUTS,
        "max_tokens": 24576,
        "sql_playbook": "none",
        "create_only": True,
        "nominal_combined_hard_cap_usd": 40.0,
        "hard_cap_semantics": (
            "checked before each new model call; the final recorded total may "
            "slightly exceed the nominal cap by the cost of the last call"
        ),
        "reason": "complete the two attack strata censored by the original $10 hard cap",
    }


def runner_exception_audit(
    phase: dict[str, Any], case: dict[str, Any], exc: Exception
) -> dict[str, Any]:
    return {
        "origin": "retry_runner_exception",
        "schema_version": "gpt55_attack_two_censored_budget20_run_audit_v1",
        "audited_at_utc": datetime.now(timezone.utc).isoformat(),
        "phase": phase["name"],
        "model": base.MODEL,
        "stage": case["stage"],
        "chain_id": case["chain_id"],
        "instance_id": case["instance_id"],
        "path": None,
        "sha256": None,
        "status": "FAIL",
        "issues": ["runner_exception"],
        "runner_exception": f"{type(exc).__name__}: {exc}",
    }


def execute_case(
    phase: dict[str, Any], case: dict[str, Any]
) -> dict[str, Any]:
    audit_file = base.audit_path(phase, case)
    run_file = base.run_path(phase, case)
    if audit_file.exists():
        if not run_file.exists():
            raise RuntimeError(f"retry audit exists without run: {audit_file}")
        audit = base.read_json(audit_file)
        if audit.get("sha256") != base.sha256(run_file):
            raise RuntimeError(f"retry provenance mismatch: {audit_file}")
        return audit
    if run_file.exists():
        audit = {"origin": "retry_existing_create_only", **base.audit_run(run_file, phase, case)}
        base.write_create_only(audit_file, audit)
        return audit

    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "retry_started",
            "phase": "attack8",
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "model": base.MODEL,
        }
    )
    try:
        produced = base.paired.run_runner(
            case, base.MODEL, base.runner_args(phase), False
        )
        audit = {"origin": "retry_new_run", **base.audit_run(produced, phase, case)}
    except Exception as exc:
        audit = runner_exception_audit(phase, case, exc)
    base.write_create_only(audit_file, audit)
    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "retry_audited",
            "instance_id": case["instance_id"],
            "status": audit["status"],
            "cost_usd": (audit.get("cost_estimate") or {}).get("total_cost_usd"),
        }
    )
    return audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.preflight_only == args.run:
        parser.error("select exactly one of --preflight-only or --run")

    phase = attack_phase()
    cases = selected_cases(phase)
    sources = [validate_source(case) for case in cases]
    preflight = {
        "status": "PASS",
        "api_calls_issued": 0,
        "retry_root": str(RETRY_ROOT),
        "instance_ids": list(INSTANCE_IDS),
        "budget_per_run": RETRY_BUDGET,
        "source_cost_usd": round(
            sum(float(item["source_cost_usd"] or 0) for item in sources), 12
        ),
    }
    if args.preflight_only:
        print(json.dumps(preflight, ensure_ascii=False, indent=2))
        return

    active = predecessor_pids()
    if active:
        raise RuntimeError(
            f"predecessor experiment is still active (PIDs={active}); retry not started"
        )

    base.RESULT_ROOT = RETRY_ROOT
    base.BUDGET = dict(RETRY_BUDGET)
    base.configure_environment()
    RETRY_ROOT.mkdir(parents=True, exist_ok=True)
    base.write_create_only(
        RETRY_ROOT / "retry_contract.json",
        contract_payload(phase, cases, sources),
    )

    summary_file = RETRY_ROOT / "retry_summary.json"
    if summary_file.exists():
        print(summary_file.read_text(encoding="utf-8"), end="")
        return

    audits = [execute_case(phase, case) for case in cases]
    statuses = Counter(str(audit["status"]) for audit in audits)
    cumulative_cost = round(
        sum(
            float((audit.get("cost_estimate") or {}).get("total_cost_usd") or 0)
            for audit in audits
        ),
        12,
    )
    summary = {
        "schema_version": "gpt55_attack_two_censored_budget20_retry_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "COMPLETE" if statuses == Counter({"PASS": 2}) else "INCOMPLETE",
        "expected_runs": 2,
        "audited_runs": len(audits),
        "status_counts": dict(statuses),
        "cumulative_cost_usd": cumulative_cost,
        "nominal_combined_hard_cap_usd": 40.0,
        "hard_cap_semantics": (
            "checked before each new model call; the final recorded total may "
            "slightly exceed the nominal cap by the cost of the last call"
        ),
        "audits": audits,
    }
    base.write_create_only(summary_file, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
