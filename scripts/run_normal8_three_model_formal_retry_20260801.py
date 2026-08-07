"""Create-only recovery run for normal8 formal_19.

The source root contains immutable valid runs produced before the narrowly
scoped tool-argument recovery patch.  This runner imports only source runs
that pass the deterministic audit, then executes the failed/missing matrix in
a versioned retry root.  No source artifact is modified or rerun.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNNER_DIR = ROOT / "src" / "clouseau_process_time"
SCRIPTS_DIR = ROOT / "scripts"
for import_path in (RUNNER_DIR, SCRIPTS_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

SOURCE_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-01"
    / "normal8_three_model_three_stage_formal_19"
)
DEFAULT_RETRY_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-01"
    / "normal8_three_model_three_stage_formal_19_retry_01"
)
os.environ.setdefault("NORMAL8_FORMAL_RESULT_ROOT", str(DEFAULT_RETRY_ROOT))

CANONICAL_MODELS = (
    "gpt-4.1-mini",
    "gpt-5.4-mini",
    "gpt-5.5",
)

import run_atlasv2_s3_s4_attack8_paired_experiment as paired  # noqa: E402
import run_normal8_three_model_formal_20260731 as formal  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_path(case: dict[str, Any], model: str) -> Path:
    return (
        SOURCE_ROOT
        / "runs"
        / model
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )


def recovery_config_pass(path: Path) -> bool:
    payload = formal.read_json(path)
    config = (payload.get("configs") or {}).get(
        "tool_validation_recovery"
    ) or {}
    return (
        config.get("enabled") is True
        and config.get("scope") == "pydantic_tool_argument_validation_only"
        and config.get("valid_tool_call_limits_affected") is False
        and config.get("execution_exceptions_recovered") is False
    )


def import_valid_source_runs(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    imported: list[dict[str, Any]] = []
    for model in formal.MODELS:
        for case in cases:
            source = source_path(case, model)
            if not source.is_file():
                continue
            audit = formal.audit_run(source, case, model)
            if audit["status"] != "PASS":
                continue
            destination = formal.run_path(case, model)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if sha256(destination) != sha256(source):
                    raise RuntimeError(
                        "create-only imported run differs from source: "
                        f"{destination}"
                    )
            else:
                shutil.copy2(source, destination)
            imported.append(
                {
                    "model": model,
                    "instance_id": case["instance_id"],
                    "source_path": str(source),
                    "source_sha256": sha256(source),
                    "destination_path": str(destination),
                    "source_audit": audit,
                    "recovery_path_exercised": False,
                }
            )
    return imported


def execute_missing(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    args = formal.runner_args()
    audits: list[dict[str, Any]] = []
    for model in formal.MODELS:
        for case in cases:
            path = paired.existing_output(case, model, args, False)
            if path is not None:
                audit = formal.audit_run(path, case, model)
                audits.append(
                    {
                        "origin": "imported_valid_source",
                        "path": str(path),
                        **audit,
                    }
                )
                continue
            formal.append_event(
                {
                    "at_utc": datetime.now(timezone.utc).isoformat(),
                    "event": "retry_run_started",
                    "model": model,
                    "instance_id": case["instance_id"],
                }
            )
            path = paired.run_runner(case, model, args, False)
            audit = formal.audit_run(path, case, model)
            if not recovery_config_pass(path):
                audit["issues"] = sorted(
                    set(list(audit.get("issues") or []) + [
                        "tool_validation_recovery.config"
                    ])
                )
                audit["status"] = "FAIL"
            formal.append_event(
                {
                    "at_utc": datetime.now(timezone.utc).isoformat(),
                    "event": "retry_run_audited",
                    "origin": "new_recovery_code",
                    **audit,
                }
            )
            audits.append({"origin": "new_recovery_code", "path": str(path), **audit})
            if audit["status"] != "PASS":
                raise RuntimeError(
                    f"retry run audit failed for {case['instance_id']} {model}: "
                    f"{audit['issues']}"
                )
    return audits


def write_retry_contract(
    cases: list[dict[str, Any]], imported: list[dict[str, Any]]
) -> None:
    contract_path = formal.RESULT_ROOT / "formal_retry_contract.json"
    if contract_path.exists():
        existing = formal.read_json(contract_path)
        expected_source_sha = sha256(SOURCE_ROOT / "formal_contract.json")
        if (
            existing.get("schema_version")
            != "normal8_formal19_create_only_retry_v1"
            or existing.get("source_root") != str(SOURCE_ROOT)
            or existing.get("source_formal_contract_sha256") != expected_source_sha
            or existing.get("source_valid_run_count") != len(imported)
        ):
            raise RuntimeError(
                f"existing retry contract is incompatible: {contract_path}"
            )
        return
    payload = {
        "schema_version": "normal8_formal19_create_only_retry_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(SOURCE_ROOT),
        "source_formal_contract_sha256": sha256(
            SOURCE_ROOT / "formal_contract.json"
        ),
        "design": "reuse source runs that audit PASS; execute only failed or missing runs",
        "source_valid_run_count": len(imported),
        "source_failed_run_retained": {
            "path": str(
                source_path(
                    next(
                        case for case in cases
                        if case["instance_id"]
                        == "chain_05_e03_python_simplehttpserver_network_chain_stage2"
                    ),
                    "gpt-4.1-mini",
                )
            ),
            "reason": "Chief investigate_lead call omitted required behavior_key",
        },
        "recovery_patch": {
            "scope": "pydantic_tool_argument_validation_only",
            "action": "return_tool_message_and_reprompt_same_agent",
            "valid_tool_call_limits_affected": False,
            "execution_exceptions_recovered": False,
        },
        "imported_source_runs": imported,
        "scoring_reviewer_model": "gpt-5.6-sol",
    }
    formal.write_create_only(contract_path, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="create and audit the retry provenance without issuing model calls",
    )
    parser.add_argument(
        "--models",
        default="gpt-4.1-mini,gpt-5.4-mini",
        help="comma-separated ordered subset of the formal model set",
    )
    args = parser.parse_args()
    if not args.run and not args.plan_only:
        parser.error("--run or --plan-only is required")
    if not SOURCE_ROOT.is_dir():
        raise RuntimeError(f"source root does not exist: {SOURCE_ROOT}")

    models = tuple(
        model.strip() for model in args.models.split(",") if model.strip()
    )
    if not models or len(set(models)) != len(models) or any(
        model not in CANONICAL_MODELS for model in models
    ):
        raise RuntimeError(f"invalid --models: {args.models}")
    # The imported formal module consistently reads this list for contracts,
    # execution, and denominator creation.  Deliberately selecting a subset
    # here makes this retry phase auditable as a two-model phase and prevents
    # an accidental gpt-5.5 API call.
    formal.MODELS = models

    cases = formal.load_cases()
    os.environ["CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS"] = str(
        formal.RUN_HARD_WALL_TIMEOUT_SECONDS
    )
    os.environ["CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS"] = str(
        formal.LLM_REQUEST_TIMEOUT_SECONDS
    )
    os.environ["CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS"] = str(
        formal.LLM_HARD_WALL_TIMEOUT_SECONDS
    )
    formal.RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    formal.create_contract(cases)
    formal.create_preflight(cases)
    imported = import_valid_source_runs(cases)
    write_retry_contract(cases, imported)
    if args.plan_only:
        planned = len(cases) * len(formal.MODELS) - len(imported)
        print(
            json.dumps(
                {
                    "status": "PLAN_PASS",
                    "source_valid_run_count": len(imported),
                    "new_recovery_code_runs_planned": planned,
                    "api_calls_issued": 0,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    audits = execute_missing(cases)
    failures = [row for row in audits if row.get("status") != "PASS"]
    payload = {
        "schema_version": "normal8_formal19_create_only_retry_audit_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_runs": len(cases) * len(formal.MODELS),
        "audited_runs": len(audits),
        "imported_source_runs": sum(
            1 for row in audits if row["origin"] == "imported_valid_source"
        ),
        "new_recovery_code_runs": sum(
            1 for row in audits if row["origin"] == "new_recovery_code"
        ),
        "status": "PASS"
        if len(audits) == len(cases) * len(formal.MODELS) and not failures
        else "FAIL",
        "failed_runs": [
            {"model": row["model"], "instance_id": row["instance_id"], "issues": row["issues"]}
            for row in failures
        ],
        "audits": audits,
    }
    formal.write_create_only(formal.RESULT_ROOT / "full_retry_audit.json", payload)
    if payload["status"] != "PASS":
        raise RuntimeError(
            f"retry coverage failed: runs={len(audits)}, failures={len(failures)}"
        )
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
