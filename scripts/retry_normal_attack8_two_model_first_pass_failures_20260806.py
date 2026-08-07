"""Retry only failed cells after the complete 192-cell first pass."""

from __future__ import annotations

import hashlib
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
    / "docs/current_experiment/results_2026-08-05"
    / "mini_reps_02_03_v4_first_pass_01"
)
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-06"
    / "mini_reps_02_03_v5_failure_retry_01"
)


def source_audit_path(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
) -> Path:
    slug = {"gpt-4.1-mini": "g41", "gpt-5.4-mini": "g54"}[model]
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
        / slug
        / f"{audit_id}.json"
    )


def import_source_pass(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
    destination: Path,
) -> bool:
    audit_file = source_audit_path(replicate, phase, model, case)
    if not audit_file.is_file():
        raise RuntimeError(f"missing source audit: {audit_file}")
    audit = base.read_json(audit_file)
    if audit.get("status") == "FAIL":
        base.append_progress(
            {
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "event": "source_failure_selected_for_retry",
                "replicate": replicate,
                "phase": phase["name"],
                "model": model,
                "stage": case["stage"],
                "instance_id": case["instance_id"],
                "source_audit": str(audit_file),
            }
        )
        return False
    if audit.get("status") != "PASS":
        raise RuntimeError(f"unexpected source audit status: {audit_file}")
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
        raise RuntimeError(f"missing source PASS run: {source}")
    digest = base.sha256(source)
    if audit.get("sha256") != digest:
        raise RuntimeError(f"source PASS hash mismatch: {audit_file}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if base.sha256(destination) != digest:
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
            "source_audit": str(audit_file),
            "source_sha256": digest,
        }
    )
    return True


def write_retry_contract() -> None:
    path = RESULT_ROOT / "failure_retry_contract.json"
    if path.exists():
        return
    base.write_create_only(
        path,
        {
            "schema_version": "normal_attack8_first_pass_failure_retry_v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_root": str(SOURCE_ROOT),
            "result_root": str(RESULT_ROOT),
            "expected_imported_pass": 190,
            "expected_failure_retries": 2,
            "source_failures": [
                {
                    "replicate": "replicate_02",
                    "phase": "attack8",
                    "model": "gpt-4.1-mini",
                    "instance_id": "s4_pt_03_mshta_c1_stage1",
                },
                {
                    "replicate": "replicate_02",
                    "phase": "attack8",
                    "model": "gpt-4.1-mini",
                    "instance_id": "s3_pt_04_powershell_mid_chain_stage2",
                },
            ],
            "create_only": True,
            "matrix_failure_policy": "record_and_continue",
            "models": list(base.MODELS),
            "forbidden_models": ["gpt-5.5"],
            "runner_sha256": base.sha256(Path(__file__).resolve()),
            "base_runner_sha256": base.sha256(Path(base.__file__).resolve()),
        },
    )


def main() -> None:
    if not SOURCE_ROOT.is_dir():
        raise RuntimeError(f"missing source root: {SOURCE_ROOT}")
    base.RESULT_ROOT = RESULT_ROOT
    base.INITIAL_ATTEMPT_ROOT = SOURCE_ROOT
    base.CODE_FILES = (*base.CODE_FILES, Path(__file__).resolve())
    base.import_initial_attempt_run = import_source_pass
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    write_retry_contract()
    base.os.environ["CLOUSEAU_MATRIX_FAILURE_POLICY"] = (
        "record_and_continue"
    )
    base.main()


if __name__ == "__main__":
    main()
