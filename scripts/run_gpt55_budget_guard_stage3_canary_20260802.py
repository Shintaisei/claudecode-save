"""Run the two sequential GPT-5.5 Stage-3 budget-guard canaries.

The normal Discord canary must pass the deterministic run/ledger/guard audit
before the attack mshta canary is started.  Every artifact is written under a
new versioned root; prior formal runs are never modified or reused.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNNER = (
    ROOT
    / "src/clouseau_process_time/"
    / "run_atlasv2_s3_s4_attack8_paired_experiment.py"
)
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-02/"
    / "gpt55_budget_guard_stage3_canary_01"
)
MODEL = "gpt-5.5"
PHASES = (
    {
        "name": "normal_discord_stage3",
        "instance_id": "chain_10_e07_discord_run_key_registry_chain_stage3",
        "cases": ROOT / "data/current_experiment/cases/normal8_observable_component_v3_stage_cases_20260726.jsonl",
        "validation": ROOT / "docs/current_experiment/normal8_observable_component_v3_stage3_validation_steps_20260726.csv",
    },
    {
        "name": "attack_mshta_stage3",
        "instance_id": "s4_pt_03_mshta_c1_stage3",
        "cases": ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl",
        "validation": ROOT / "docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv",
    },
)
BUDGET = {
    "soft_api_calls": 350,
    "hard_api_calls": 400,
    "soft_total_tokens": 1_600_000,
    "hard_total_tokens": 2_000_000,
    "soft_cost_usd": 6.0,
    "hard_cost_usd": 8.0,
    "soft_chief_leads": 20,
    "hard_chief_leads": 24,
    "batch_cost_usd": 20.0,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_create_only(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise RuntimeError(f"create-only artifact differs: {path}")
        return
    path.write_text(encoded, encoding="utf-8")


def guard_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "CLOUSEAU_RUN_BUDGET_GUARD_ENABLED": "1",
            "CLOUSEAU_RUN_BUDGET_SOFT_API_CALLS": str(BUDGET["soft_api_calls"]),
            "CLOUSEAU_RUN_BUDGET_HARD_API_CALLS": str(BUDGET["hard_api_calls"]),
            "CLOUSEAU_RUN_BUDGET_SOFT_TOTAL_TOKENS": str(BUDGET["soft_total_tokens"]),
            "CLOUSEAU_RUN_BUDGET_HARD_TOTAL_TOKENS": str(BUDGET["hard_total_tokens"]),
            "CLOUSEAU_RUN_BUDGET_SOFT_COST_USD": str(BUDGET["soft_cost_usd"]),
            "CLOUSEAU_RUN_BUDGET_HARD_COST_USD": str(BUDGET["hard_cost_usd"]),
            "CLOUSEAU_RUN_BUDGET_SOFT_CHIEF_LEADS": str(BUDGET["soft_chief_leads"]),
            "CLOUSEAU_RUN_BUDGET_HARD_CHIEF_LEADS": str(BUDGET["hard_chief_leads"]),
            "CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS": "600",
            "CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS": "600",
            "CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS": "1800",
        }
    )
    return env


def command_for(phase: dict[str, Any], phase_root: Path) -> list[str]:
    return [
        sys.executable,
        str(RUNNER),
        "--cases",
        str(phase["cases"]),
        "--result-root",
        str(phase_root),
        "--validation-steps",
        str(phase["validation"]),
        "--models",
        MODEL,
        "--stage",
        "stage3",
        "--instance-id",
        str(phase["instance_id"]),
        "--run",
        "--resume",
        "--max-tokens",
        "24576",
        "--sql-playbook",
        "none",
        "--log-cost",
    ]


def audit_run(path: Path, phase: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    issues: list[str] = []
    if payload.get("error") is not None:
        issues.append("error")
    try:
        parsed_output = json.loads(str(payload.get("output_text") or ""))
        if not isinstance(parsed_output, dict):
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
        if key == "batch_cost_usd":
            continue
        if config.get(key) != expected:
            issues.append(f"run_budget_guard.config.{key}")
    if guard.get("hard_triggered") is True or guard.get("budget_censored") is True:
        issues.append("run_budget_guard.budget_censored")
    cost = payload.get("cost_estimate") or {}
    usage = payload.get("usage") or {}
    if cost.get("call_count") != usage_audit.get("full_pipeline_call_count"):
        issues.append("cost_call_count")
    if float(cost.get("total_cost_usd") or 0.0) > BUDGET["hard_cost_usd"]:
        issues.append("cost.hard_limit")
    if int(usage.get("total_tokens") or 0) > BUDGET["hard_total_tokens"]:
        issues.append("tokens.hard_limit")
    if int(cost.get("call_count") or 0) > BUDGET["hard_api_calls"]:
        issues.append("calls.hard_limit")
    configs = payload.get("configs") or {}
    if configs.get("max_investigations") is not None:
        issues.append("configs.max_investigations")
    if configs.get("max_questions") is not None:
        issues.append("configs.max_questions")
    if configs.get("max_queries") is not None:
        issues.append("configs.max_queries")
    return {
        "phase": phase["name"],
        "instance_id": phase["instance_id"],
        "model": MODEL,
        "path": str(path),
        "sha256": sha256(path),
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "usage": usage,
        "cost_estimate": {
            "call_count": cost.get("call_count"),
            "total_cost_usd": cost.get("total_cost_usd"),
        },
        "elapsed_seconds": payload.get("elapsed_seconds"),
        "run_budget_guard": guard,
    }


def run_phase(phase: dict[str, Any]) -> dict[str, Any]:
    phase_root = RESULT_ROOT / phase["name"]
    run_path = (
        phase_root
        / "runs"
        / MODEL
        / "stage3"
        / f"{phase['instance_id']}_run.json"
    )
    if not run_path.exists():
        log_dir = RESULT_ROOT / "_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        command = command_for(phase, phase_root)
        with (
            (log_dir / f"{phase['name']}_stdout.log").open(
                "a", encoding="utf-8"
            ) as stdout,
            (log_dir / f"{phase['name']}_stderr.log").open(
                "a", encoding="utf-8"
            ) as stderr,
        ):
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=guard_environment(),
                stdout=stdout,
                stderr=stderr,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        if completed.returncode != 0:
            raise RuntimeError(
                f"phase runner failed ({completed.returncode}): {phase['name']}"
            )
    if not run_path.is_file():
        raise RuntimeError(f"run output missing: {run_path}")
    return audit_run(run_path, phase)


def main() -> None:
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    write_create_only(
        RESULT_ROOT / "canary_contract.json",
        {
            "schema_version": "gpt55_budget_guard_stage3_canary_v1",
            "created_at_utc": "2026-08-02T00:00:00+00:00",
            "model": MODEL,
            "sequence": [phase["name"] for phase in PHASES],
            "normal_must_pass_before_attack": True,
            "cases": [
                {
                    "name": phase["name"],
                    "instance_id": phase["instance_id"],
                    "case_file": str(phase["cases"]),
                    "case_file_sha256": sha256(phase["cases"]),
                    "validation_file": str(phase["validation"]),
                    "validation_file_sha256": sha256(phase["validation"]),
                }
                for phase in PHASES
            ],
            "budget": BUDGET,
            "budget_censored_scoring_policy": "exclude_pending_separate_review",
            "prior_formal_runs_modified": False,
        },
    )
    audits: list[dict[str, Any]] = []
    cumulative_cost = 0.0
    for phase in PHASES:
        audit = run_phase(phase)
        audits.append(audit)
        cumulative_cost += float(
            audit["cost_estimate"].get("total_cost_usd") or 0.0
        )
        write_create_only(
            RESULT_ROOT / f"{phase['name']}_audit.json",
            audit,
        )
        if audit["status"] != "PASS":
            break
        if cumulative_cost > BUDGET["batch_cost_usd"]:
            break
    summary = {
        "schema_version": "gpt55_budget_guard_stage3_canary_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "PASS"
            if len(audits) == len(PHASES)
            and all(audit["status"] == "PASS" for audit in audits)
            and cumulative_cost <= BUDGET["batch_cost_usd"]
            else "STOPPED"
        ),
        "audits": audits,
        "cumulative_cost_usd": round(cumulative_cost, 12),
        "batch_cost_limit_usd": BUDGET["batch_cost_usd"],
    }
    write_create_only(RESULT_ROOT / "canary_summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
