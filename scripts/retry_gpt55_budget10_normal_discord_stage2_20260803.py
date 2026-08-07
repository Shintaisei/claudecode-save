"""Create-only retry for the one non-budget timeout in the GPT-5.5 matrix.

The source artifact remains frozen.  This runner executes only
``chain_10_e07_discord_run_key_registry_chain_stage2`` with the same model,
budget guard, token limit, and wall-clock limits as the 48-run experiment.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_gpt55_normal8_attack8_budget10_20260802 as base  # noqa: E402


INSTANCE_ID = "chain_10_e07_discord_run_key_registry_chain_stage2"
SOURCE_ROOT = base.RESULT_ROOT
RETRY_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-03"
    / "gpt55_normal8_attack8_budget10_retry_01"
)
SOURCE_AUDIT = (
    SOURCE_ROOT
    / "audits/normal8/stage2"
    / f"{INSTANCE_ID}_audit.json"
)


def contract_payload() -> dict[str, object]:
    return {
        "schema_version": "gpt55_budget10_single_timeout_retry_v1",
        "created_at_utc": "2026-08-03T00:00:00+00:00",
        "source_root": str(SOURCE_ROOT),
        "source_experiment_contract_sha256": base.sha256(
            SOURCE_ROOT / "experiment_contract.json"
        ),
        "source_failed_audit": str(SOURCE_AUDIT),
        "source_failed_audit_sha256": base.sha256(SOURCE_AUDIT),
        "retry_root": str(RETRY_ROOT),
        "model": base.MODEL,
        "role_models": {
            "chief": base.MODEL,
            "investigator": base.MODEL,
            "sql_qa": base.MODEL,
        },
        "mixed_model_pipeline": False,
        "instance_ids": [INSTANCE_ID],
        "budget_per_run": base.BUDGET,
        "timeouts": base.TIMEOUTS,
        "max_tokens": 24576,
        "sql_playbook": "none",
        "create_only": True,
        "reason": "retry only the non-budget total_run_wall timeout",
    }


def select_case(phase: dict[str, object]) -> dict[str, object]:
    matches = [
        case
        for case in base.load_phase_cases(phase)
        if case["instance_id"] == INSTANCE_ID
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one retry case, found {len(matches)}")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required")

    source = base.read_json(SOURCE_AUDIT)
    if source.get("status") != "FAIL" or "total_run_wall" not in str(
        source.get("runner_exception")
    ):
        raise RuntimeError("source audit is not the expected run-wall timeout")

    base.RESULT_ROOT = RETRY_ROOT
    base.configure_environment()
    phase = base.PHASES[0]
    case = select_case(phase)
    RETRY_ROOT.mkdir(parents=True, exist_ok=True)
    base.write_create_only(RETRY_ROOT / "retry_contract.json", contract_payload())

    audit_file = base.audit_path(phase, case)
    run_file = base.run_path(phase, case)
    summary_file = RETRY_ROOT / "retry_summary.json"
    if summary_file.exists():
        print(summary_file.read_text(encoding="utf-8"), end="")
        return
    if audit_file.exists() or run_file.exists():
        raise RuntimeError(
            "partial retry artifacts already exist; diagnose without overwrite: "
            f"{audit_file} {run_file}"
        )

    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "retry_started",
            "instance_id": INSTANCE_ID,
            "model": base.MODEL,
        }
    )
    try:
        produced = base.paired.run_runner(
            case, base.MODEL, base.runner_args(phase), False
        )
        audit = {"origin": "retry_new_run", **base.audit_run(produced, phase, case)}
    except Exception as exc:
        audit = {
            "origin": "retry_runner_exception",
            "schema_version": "gpt55_budget10_run_audit_v1",
            "audited_at_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "normal8",
            "model": base.MODEL,
            "stage": "stage2",
            "chain_id": "chain_10_e07_discord_run_key_registry_chain",
            "instance_id": INSTANCE_ID,
            "path": None,
            "sha256": None,
            "status": "FAIL",
            "issues": ["runner_exception"],
            "runner_exception": f"{type(exc).__name__}: {exc}",
        }

    base.write_create_only(audit_file, audit)
    summary = {
        "schema_version": "gpt55_budget10_single_timeout_retry_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": audit["status"],
        "source_failed_audit": str(SOURCE_AUDIT),
        "retry_audit": audit,
    }
    base.write_create_only(summary_file, summary)
    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "retry_audited",
            "instance_id": INSTANCE_ID,
            "status": audit["status"],
        }
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
