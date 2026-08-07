"""Complete the first pass while deferring abnormal runs until the end.

Imports only SHA-verified PASS runs from the v3 retry root. Existing FAIL
audits are carried forward as deferred failures without re-execution. Missing
matrix cells run create-only. Run-scoped failures are recorded and execution
continues; three consecutive API connectivity/quota failures trip a circuit
breaker in the base runner.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_normal_attack8_two_model_replicates_02_03_20260803 as base  # noqa: E402


SOURCE_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-04"
    / "mini_reps_02_03_v3_retry_02"
)
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-05"
    / "mini_reps_02_03_v4_first_pass_01"
)


def source_audit_path(
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
        f"{replicate}|{phase['name']}|{model}|{case['instance_id']}".encode(
            "utf-8"
        )
    ).hexdigest()[:16]
    return (
        SOURCE_ROOT
        / replicate
        / "audits"
        / str(phase["name"])
        / model_slug
        / f"{audit_id}.json"
    )


def import_source_artifact(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
    destination: Path,
) -> bool:
    source_audit_file = source_audit_path(
        replicate, phase, model, case
    )
    if not source_audit_file.is_file():
        return False
    source_audit = base.read_json(source_audit_file)
    status = source_audit.get("status")
    if status == "FAIL":
        destination_audit = base.audit_path(
            replicate, phase, model, case
        )
        deferred = {
            "schema_version": (
                "normal_attack8_two_model_deferred_failure_audit_v1"
            ),
            "replicate": replicate,
            "phase": phase["name"],
            "model": model,
            "stage": case["stage"],
            "chain_id": case["chain_id"],
            "instance_id": case["instance_id"],
            "path": None,
            "sha256": None,
            "status": "FAIL",
            "issues": ["deferred_source_failure"],
            "runner_exception": source_audit.get("runner_exception"),
            "source_audit": str(source_audit_file),
            "source_audit_sha256": base.sha256(source_audit_file),
            "retry_phase": "after_first_pass",
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        base.write_create_only(destination_audit, deferred)
        base.append_progress(
            {
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "event": "source_failure_deferred",
                "replicate": replicate,
                "phase": phase["name"],
                "model": model,
                "stage": case["stage"],
                "instance_id": case["instance_id"],
                "source_audit": str(source_audit_file),
            }
        )
        return False
    if status != "PASS":
        raise RuntimeError(
            f"unexpected source audit status {status!r}: {source_audit_file}"
        )
    source = (
        SOURCE_ROOT
        / replicate
        / str(phase["name"])
        / "runs"
        / model
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )
    if not source.is_file():
        raise RuntimeError(f"source PASS run missing: {source}")
    source_sha256 = base.sha256(source)
    if source_audit.get("sha256") != source_sha256:
        raise RuntimeError(
            f"source PASS hash mismatch: {source_audit_file} -> {source}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if base.sha256(destination) != source_sha256:
            raise RuntimeError(f"imported PASS differs: {destination}")
    else:
        shutil.copy2(source, destination)
    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "source_pass_imported",
            "replicate": replicate,
            "phase": phase["name"],
            "model": model,
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "source": str(source),
            "source_audit": str(source_audit_file),
            "source_sha256": source_sha256,
        }
    )
    return True


def write_continuation_contract() -> None:
    path = RESULT_ROOT / "continuation_contract.json"
    if path.exists():
        return
    payload = {
        "schema_version": "normal_attack8_two_model_first_pass_continue_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(SOURCE_ROOT),
        "result_root": str(RESULT_ROOT),
        "expected_imported_pass": 54,
        "expected_deferred_failures": 1,
        "expected_missing_runs_to_execute": 137,
        "matrix_failure_policy": "record_and_continue",
        "connectivity_circuit_breaker_consecutive_failures": 3,
        "deferred_failures_retry_phase": "after_first_pass",
        "models": list(base.MODELS),
        "forbidden_models": ["gpt-5.5"],
        "runner_sha256": base.sha256(Path(__file__).resolve()),
        "base_runner_sha256": base.sha256(Path(base.__file__).resolve()),
    }
    base.write_create_only(path, payload)


def main() -> None:
    if not SOURCE_ROOT.is_dir():
        raise RuntimeError(f"missing source root: {SOURCE_ROOT}")
    base.RESULT_ROOT = RESULT_ROOT
    base.INITIAL_ATTEMPT_ROOT = SOURCE_ROOT
    base.CODE_FILES = (*base.CODE_FILES, Path(__file__).resolve())
    base.import_initial_attempt_run = import_source_artifact
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    write_continuation_contract()
    base.os.environ["CLOUSEAU_MATRIX_FAILURE_POLICY"] = (
        "record_and_continue"
    )
    base.main()


if __name__ == "__main__":
    main()
