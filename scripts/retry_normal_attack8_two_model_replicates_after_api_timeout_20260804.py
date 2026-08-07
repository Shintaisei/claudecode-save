"""Resume mini replicates 02/03 after the 2026-08-03 API timeout.

Only deterministic PASS artifacts from the frozen v2 root are imported.
Failed artifacts remain frozen in place.  New work is create-only in a new
versioned root, and the underlying runner stops on the first failed audit.
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


FROZEN_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-03"
    / "mini_reps_02_03_v2"
)
RETRY_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-04"
    / "mini_reps_02_03_v3_retry_02"
)


def frozen_audit_path(
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
        FROZEN_ROOT
        / replicate
        / "audits"
        / str(phase["name"])
        / model_slug
        / f"{audit_id}.json"
    )


def import_frozen_pass(
    replicate: str,
    phase: dict[str, Any],
    model: str,
    case: dict[str, Any],
    destination: Path,
) -> bool:
    source = (
        FROZEN_ROOT
        / replicate
        / str(phase["name"])
        / "runs"
        / model
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )
    source_audit = frozen_audit_path(replicate, phase, model, case)
    if not source.is_file() or not source_audit.is_file():
        return False
    audit = base.read_json(source_audit)
    if audit.get("status") != "PASS":
        return False
    source_sha256 = base.sha256(source)
    if audit.get("sha256") != source_sha256:
        raise RuntimeError(
            f"frozen PASS hash mismatch: {source_audit} -> {source}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if base.sha256(destination) != source_sha256:
            raise RuntimeError(
                f"create-only imported PASS differs: {destination}"
            )
    else:
        shutil.copy2(source, destination)
    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "frozen_pass_imported",
            "replicate": replicate,
            "phase": phase["name"],
            "model": model,
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "source": str(source),
            "source_audit": str(source_audit),
            "source_sha256": source_sha256,
            "destination": str(destination),
        }
    )
    return True


def write_retry_contract() -> None:
    path = RETRY_ROOT / "retry_contract.json"
    if path.exists():
        existing = base.read_json(path)
        required = {
            "frozen_root": str(FROZEN_ROOT),
            "retry_root": str(RETRY_ROOT),
            "reuse_policy": "import_only_deterministic_pass_with_sha256",
            "expected_imported_pass": 14,
            "expected_new_runs": 178,
            "failed_artifacts_copied": False,
            "fail_closed_on_first_failed_audit": True,
        }
        mismatches = {
            key: {"expected": value, "actual": existing.get(key)}
            for key, value in required.items()
            if existing.get(key) != value
        }
        if mismatches:
            raise RuntimeError(
                f"existing retry contract differs: {mismatches}"
            )
        return
    payload = {
        "schema_version": "normal_attack8_two_model_api_timeout_retry_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "frozen_root": str(FROZEN_ROOT),
        "retry_root": str(RETRY_ROOT),
        "reuse_policy": "import_only_deterministic_pass_with_sha256",
        "expected_imported_pass": 14,
        "expected_new_runs": 178,
        "failed_artifacts_copied": False,
        "fail_closed_on_first_failed_audit": True,
        "models": list(base.MODELS),
        "forbidden_models": ["gpt-5.5"],
        "source_incident": str(
            FROZEN_ROOT / "api_timeout_incident_20260803.json"
        ),
        "runner_sha256": base.sha256(Path(__file__).resolve()),
        "base_runner_sha256": base.sha256(Path(base.__file__).resolve()),
    }
    base.write_create_only(path, payload)


def main() -> None:
    if not FROZEN_ROOT.is_dir():
        raise RuntimeError(f"missing frozen root: {FROZEN_ROOT}")
    base.RESULT_ROOT = RETRY_ROOT
    base.INITIAL_ATTEMPT_ROOT = FROZEN_ROOT
    base.CODE_FILES = (*base.CODE_FILES, Path(__file__).resolve())
    base.import_initial_attempt_run = import_frozen_pass
    RETRY_ROOT.mkdir(parents=True, exist_ok=True)
    write_retry_contract()
    base.main()


if __name__ == "__main__":
    main()
