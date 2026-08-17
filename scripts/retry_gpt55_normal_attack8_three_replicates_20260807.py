#!/usr/bin/env python3
"""Create-only retry for non-PASS GPT-5.5 three-replicate cells.

The first-pass root is immutable.  Its PASS runs are imported with SHA-256
provenance and only its FAIL/CENSORED cells are executed.  A quota exhaustion
error stops the retry immediately; API timeout/connection failures stop after
three consecutive cells.  A non-PASS artifact in this retry root is immutable
and must be handled by a later versioned retry root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_gpt55_normal_attack8_three_replicates_20260806 as base  # noqa: E402


SOURCE_ROOT = base.RESULT_ROOT
RETRY_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-08-07"
    / "gpt55_normal_attack8_three_replicates_cost20_retry_01"
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def preserve_created_at(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Keep create-only metadata byte-stable across resume invocations."""
    if path.is_file():
        existing = read_json(path)
        if existing.get("created_at_utc"):
            payload["created_at_utc"] = existing["created_at_utc"]
    return payload


def source_audit_map() -> dict[tuple[str, str, str], tuple[Path, dict[str, Any]]]:
    result: dict[tuple[str, str, str], tuple[Path, dict[str, Any]]] = {}
    for path in SOURCE_ROOT.glob("replicate_*/audits/*/g55/*.json"):
        payload = read_json(path)
        key = (
            str(payload.get("replicate")),
            str(payload.get("phase")),
            str(payload.get("instance_id")),
        )
        if key in result:
            raise RuntimeError(f"duplicate source audit key: {key}")
        result[key] = (path, payload)
    return result


def matrix() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    cells: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for replicate in base.REPLICATES:
        for phase in base.PHASES:
            for case in base.load_cases(phase):
                cells.append((replicate, phase, case))
    if len(cells) != 144:
        raise RuntimeError(f"logical matrix size is {len(cells)}, expected 144")
    return cells


def destination_audit_path(
    replicate: str, phase: dict[str, Any], case: dict[str, Any]
) -> Path:
    key = f"{replicate}|{phase['name']}|{base.MODEL}|{case['instance_id']}"
    audit_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return (
        RETRY_ROOT
        / replicate
        / "audits"
        / str(phase["name"])
        / "g55"
        / f"{audit_id}.json"
    )


def destination_run_path(
    replicate: str, phase: dict[str, Any], case: dict[str, Any]
) -> Path:
    return (
        RETRY_ROOT
        / replicate
        / str(phase["name"])
        / "runs"
        / base.MODEL
        / str(case["stage"])
        / f"{case['instance_id']}_run.json"
    )


def validate_source(
    cells: list[tuple[str, dict[str, Any], dict[str, Any]]],
    audits: dict[tuple[str, str, str], tuple[Path, dict[str, Any]]],
) -> Counter[str]:
    if len(audits) != 144:
        raise RuntimeError(f"source audit count is {len(audits)}, expected 144")
    counts: Counter[str] = Counter()
    for replicate, phase, case in cells:
        key = (replicate, str(phase["name"]), str(case["instance_id"]))
        if key not in audits:
            raise RuntimeError(f"missing source audit: {key}")
        audit_file, audit = audits[key]
        status = str(audit.get("status"))
        counts[status] += 1
        if status == "PASS":
            run_file = Path(str(audit.get("path") or ""))
            if not run_file.is_file():
                raise RuntimeError(f"source PASS run missing: {audit_file}")
            if audit.get("sha256") != base.sha256(run_file):
                raise RuntimeError(f"source PASS hash mismatch: {run_file}")
    return counts


def import_pass(
    replicate: str,
    phase: dict[str, Any],
    case: dict[str, Any],
    source_audit_file: Path,
    source_audit: dict[str, Any],
) -> dict[str, Any]:
    source_run = Path(str(source_audit["path"]))
    run_file = destination_run_path(replicate, phase, case)
    audit_file = destination_audit_path(replicate, phase, case)
    run_file.parent.mkdir(parents=True, exist_ok=True)
    if run_file.exists():
        if base.sha256(run_file) != base.sha256(source_run):
            raise RuntimeError(f"retry import differs: {run_file}")
    else:
        shutil.copy2(source_run, run_file)

    provenance = {
        "schema_version": "gpt55_three_replicate_retry_pass_import_v1",
        "replicate": replicate,
        "phase": phase["name"],
        "instance_id": case["instance_id"],
        "source_audit": str(source_audit_file),
        "source_audit_sha256": base.sha256(source_audit_file),
        "source_run": str(source_run),
        "source_run_sha256": base.sha256(source_run),
        "destination_run": str(run_file),
        "destination_run_sha256": base.sha256(run_file),
        "eligibility": "source deterministic audit status PASS",
    }
    base.write_create_only(
        RETRY_ROOT
        / replicate
        / "imports"
        / str(phase["name"])
        / f"{case['instance_id']}.json",
        provenance,
    )

    audit = base.audit_run(run_file, replicate, phase, case, "source_pass_import")
    audit["source_audit"] = str(source_audit_file)
    audit["source_audit_sha256"] = base.sha256(source_audit_file)
    if audit["status"] != "PASS":
        raise RuntimeError(f"imported PASS failed retry audit: {run_file}")
    base.write_create_only(audit_file, audit)
    return audit


def source_failure_summary(audit: dict[str, Any]) -> dict[str, Any]:
    error: dict[str, Any] = {}
    path_text = str(audit.get("path") or "")
    if path_text and Path(path_text).is_file():
        error = read_json(Path(path_text)).get("error") or {}
    return {
        "status": audit.get("status"),
        "issues": audit.get("issues"),
        "runner_exception": audit.get("runner_exception"),
        "error": error,
    }


def contract_payload(
    counts: Counter[str], pending: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "schema_version": "gpt55_normal_attack8_three_replicates_retry_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(SOURCE_ROOT),
        "source_contract_sha256": base.sha256(SOURCE_ROOT / "experiment_contract.json"),
        "source_summary_sha256": base.sha256(SOURCE_ROOT / "experiment_summary.json"),
        "retry_root": str(RETRY_ROOT),
        "model": base.MODEL,
        "role_models": {"chief": base.MODEL, "investigator": base.MODEL, "sql_qa": base.MODEL},
        "logical_run_count": 144,
        "source_status_counts": dict(sorted(counts.items())),
        "pass_import_count": counts.get("PASS", 0),
        "retry_cell_count": len(pending),
        "retry_cells": pending,
        "execution_contract": {
            "max_tokens": 24576,
            "sql_playbook": "none",
            "five_minute_window": True,
            "stage3_cbc_alert_summary_hidden": True,
            "frontier_closure_policy": base.FRONTIER_POLICY,
            "agent_call_limit_policy": "unbounded_by_experiment",
            "usage_scope": "full_pipeline_callback_v1",
            "timeouts": base.TIMEOUTS,
            "budget_guard": base.BUDGET,
        },
        "create_only": True,
        "quota_policy": "one insufficient_quota/credit_balance_exhausted result stops the retry immediately",
        "transient_api_policy": "three consecutive APITimeoutError/APIConnectionError results stop the retry",
        "nonpass_policy": "freeze this retry root and use a later versioned retry root for residual non-PASS cells",
    }


def prepare() -> tuple[
    list[tuple[str, dict[str, Any], dict[str, Any]]],
    dict[tuple[str, str, str], tuple[Path, dict[str, Any]]],
    Counter[str],
]:
    cells = matrix()
    audits = source_audit_map()
    counts = validate_source(cells, audits)
    pending: list[dict[str, Any]] = []

    base.RESULT_ROOT = RETRY_ROOT
    base.configure_environment()
    RETRY_ROOT.mkdir(parents=True, exist_ok=True)
    imported = 0
    for replicate, phase, case in cells:
        key = (replicate, str(phase["name"]), str(case["instance_id"]))
        source_audit_file, source_audit = audits[key]
        if source_audit["status"] == "PASS":
            import_pass(replicate, phase, case, source_audit_file, source_audit)
            imported += 1
        else:
            pending.append(
                {
                    "replicate": replicate,
                    "phase": phase["name"],
                    "stage": case["stage"],
                    "chain_id": case["chain_id"],
                    "instance_id": case["instance_id"],
                    "source_audit": str(source_audit_file),
                    "source_audit_sha256": base.sha256(source_audit_file),
                    "source_failure": source_failure_summary(source_audit),
                }
            )
    contract_path = RETRY_ROOT / "retry_contract.json"
    contract = preserve_created_at(
        contract_path, contract_payload(counts, pending)
    )
    base.write_create_only(contract_path, contract)
    preflight = {
        "schema_version": "gpt55_three_replicate_retry_preflight_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS",
        "api_calls_issued": 0,
        "source_status_counts": dict(sorted(counts.items())),
        "pass_import_count": imported,
        "retry_cell_count": len(pending),
        "retry_root": str(RETRY_ROOT),
    }
    preflight_path = RETRY_ROOT / "preflight.json"
    base.write_create_only(
        preflight_path, preserve_created_at(preflight_path, preflight)
    )
    return cells, audits, counts


def audit_error_text(audit: dict[str, Any]) -> str:
    parts = [str(audit.get("runner_exception") or ""), json.dumps(audit.get("issues") or [], ensure_ascii=False)]
    path_text = str(audit.get("path") or "")
    if path_text and Path(path_text).is_file():
        payload = read_json(Path(path_text))
        parts.append(json.dumps(payload.get("error") or {}, ensure_ascii=False))
    return " ".join(parts)


def retry_case(
    replicate: str,
    phase: dict[str, Any],
    case: dict[str, Any],
    source_audit_file: Path,
) -> dict[str, Any]:
    run_file = destination_run_path(replicate, phase, case)
    audit_file = destination_audit_path(replicate, phase, case)
    if audit_file.exists():
        audit = read_json(audit_file)
        if audit.get("status") != "PASS":
            raise RuntimeError(
                f"immutable non-PASS retry artifact exists; use the next versioned root: {audit_file}"
            )
        if not run_file.is_file() or audit.get("sha256") != base.sha256(run_file):
            raise RuntimeError(f"retry run/audit mismatch: {audit_file}")
        return audit
    if run_file.exists():
        raise RuntimeError(f"retry run exists without audit: {run_file}")

    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "retry_started",
            "replicate": replicate,
            "phase": phase["name"],
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "model": base.MODEL,
        }
    )
    try:
        produced = base.paired.run_runner(
            case, base.MODEL, base.runner_args(replicate, phase), False
        )
        audit = base.audit_run(produced, replicate, phase, case, "new_run")
        audit["origin"] = "retry_new_run"
        audit["source_nonpass_audit"] = str(source_audit_file)
        audit["source_nonpass_audit_sha256"] = base.sha256(source_audit_file)
    except Exception as exc:
        audit = base.failure_audit(exc, replicate, phase, case)
        audit["origin"] = "retry_runner_exception"
        audit["source_nonpass_audit"] = str(source_audit_file)
        audit["source_nonpass_audit_sha256"] = base.sha256(source_audit_file)
    base.write_create_only(audit_file, audit)
    base.append_progress(
        {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "event": "retry_audited",
            "replicate": replicate,
            "phase": phase["name"],
            "stage": case["stage"],
            "instance_id": case["instance_id"],
            "status": audit["status"],
            "cost_usd": audit.get("cost_usd"),
        }
    )
    return audit


def execute(
    cells: list[tuple[str, dict[str, Any], dict[str, Any]]],
    source_audits: dict[tuple[str, str, str], tuple[Path, dict[str, Any]]],
    summary_file: Path,
) -> dict[str, Any]:
    transient_failures = 0
    results: list[dict[str, Any]] = []
    for replicate, phase, case in cells:
        key = (replicate, str(phase["name"]), str(case["instance_id"]))
        source_audit_file, source_audit = source_audits[key]
        if source_audit["status"] == "PASS":
            audit = read_json(destination_audit_path(replicate, phase, case))
        else:
            audit = retry_case(replicate, phase, case, source_audit_file)
        results.append(audit)

        if audit["status"] == "PASS":
            transient_failures = 0
            continue
        error_text = audit_error_text(audit)
        if "insufficient_quota" in error_text or "credit_balance_exhausted" in error_text:
            raise RuntimeError(
                f"quota exhausted; retry stopped after {case['instance_id']}"
            )
        if "APITimeoutError" in error_text or "APIConnectionError" in error_text:
            transient_failures += 1
            if transient_failures >= 3:
                raise RuntimeError(
                    f"transient API circuit breaker after three failures; last={case['instance_id']}"
                )
        else:
            transient_failures = 0

    counts = Counter(str(item["status"]) for item in results)
    expected_runs = len(cells)
    summary = {
        "schema_version": "gpt55_three_replicate_retry_summary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "PASS"
            if counts == Counter({"PASS": expected_runs})
            else "COMPLETE_WITH_NONPASS"
        ),
        "phase_filter": (
            sorted({str(phase["name"]) for _, phase, _ in cells})
        ),
        "expected_runs": expected_runs,
        "audited_runs": len(results),
        "status_counts": dict(sorted(counts.items())),
        "total_cost_usd": round(sum(float(item.get("cost_usd") or 0) for item in results), 12),
    }
    base.write_create_only(summary_file, summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument(
        "--phase",
        choices=("normal8", "attack8"),
        help="Run only the selected phase; imported PASS artifacts remain shared.",
    )
    args = parser.parse_args()
    if args.prepare_only == args.run:
        parser.error("select exactly one of --prepare-only or --run")
    cells, audits, counts = prepare()
    if args.prepare_only:
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "api_calls_issued": 0,
                    "source_status_counts": dict(sorted(counts.items())),
                    "retry_root": str(RETRY_ROOT),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if args.phase:
        cells = [
            cell for cell in cells if str(cell[1]["name"]) == args.phase
        ]
    summary_name = (
        f"retry_summary_{args.phase}.json"
        if args.phase
        else "retry_summary.json"
    )
    summary_file = RETRY_ROOT / summary_name
    if summary_file.exists():
        print(summary_file.read_text(encoding="utf-8"), end="")
        return
    print(
        json.dumps(
            execute(cells, audits, summary_file),
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
