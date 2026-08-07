#!/usr/bin/env python3
"""Deterministically audit the formally reviewed attack process-chain Gold."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import build_atlasv2_s3_s4_attack8_observable_component_v3_suite as evidence_utils


ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
)
GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727"
)
NORMAL_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "cbc_23_chain_stage_cases_2026-06-12.jsonl"
)
NORMAL_GOLD_ROOT = (
    ROOT / "data/current_experiment/gold/cbc_alert_behavior_chain_gold"
)
DEFAULT_REPORT = (
    ROOT
    / "docs/current_experiment"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_review_20260727.json"
)
CONTRACT_VERSION = "process_behavior_chain_normal23_parity_v5_formal"
PID_TOKEN = re.compile(r"\(\s*PID\s+\d+\s*\)", re.IGNORECASE)
BANNED_INFERENCE_TERMS = (
    "c2",
    "候補",
    "payload取得先",
    "スクリプト取得先",
    "コンテンツ取得先",
    "文書処理用",
    "攻撃者",
    "悪性",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def process_name(value: Any) -> str:
    return str(value or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def normalized_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lower()


def resolve_gold(case: dict[str, Any]) -> Path:
    return (
        ROOT
        / Path(str(case["formal_gold_root"]).replace("\\", "/"))
        / Path(str(case["gold_chain_file"]).replace("\\", "/"))
    )


def evidence_rows(step: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        *(step.get("canonical_evidence") or []),
        *((step.get("supporting_evidence") or {}).get(
            "supporting_canonical_rows", []
        )),
    ]


def semantic_step_errors(step: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    primary = (step.get("canonical_evidence") or [{}])[0]
    subject = process_name(step.get("subject"))
    object_text = normalized_path(step.get("object"))
    raw_process = process_name(primary.get("process_path"))
    raw_child = process_name(primary.get("childproc_name"))
    raw_action = str(primary.get("action") or "")
    kind = str(step.get("evidence_kind") or "")

    if subject != raw_process:
        errors.append(f"subject/raw process mismatch: {subject} != {raw_process}")
    if kind in {"process_creation", "command_process_creation"}:
        if "ACTION_CREATE_PROCESS" not in raw_action:
            errors.append("process-creation step lacks ACTION_CREATE_PROCESS")
        if not raw_child or raw_child not in object_text:
            errors.append(f"object/raw child mismatch: {object_text} != {raw_child}")
        if kind == "command_process_creation":
            command = str(primary.get("process_cmdline") or "").lower()
            if "/i:http" not in command or ".sct" not in command:
                errors.append("remote-SCT command evidence is missing")
    elif kind in {"network", "command_network"}:
        if "ACTION_CONNECTION_CREATE" not in raw_action:
            errors.append("network step lacks ACTION_CONNECTION_CREATE")
        remote_ip = str(primary.get("remote_ip") or "").lower()
        remote_port = str(primary.get("remote_port") or "")
        domain = str(primary.get("netconn_domain") or "").lower()
        if remote_ip and remote_ip not in object_text:
            errors.append("network object omits remote_ip")
        if remote_port and remote_port not in object_text:
            errors.append("network object omits remote_port")
        if domain and domain not in object_text:
            errors.append("network object omits domain")
        if kind == "command_network":
            command = str(primary.get("process_cmdline") or "").lower()
            if "/i:http" not in command or ".sct" not in command:
                errors.append("command-network step lacks remote-SCT command")
    elif kind == "document_input":
        if "ACTION_FILE" not in raw_action or "OPEN" not in raw_action:
            errors.append("document-input step lacks file-open telemetry")
        if normalized_path(primary.get("object_name")) != object_text:
            errors.append("document object does not equal raw object")
    else:
        errors.append(f"unsupported evidence_kind: {kind}")

    action_lower = str(step.get("action") or "").lower()
    for term in BANNED_INFERENCE_TERMS:
        if term in action_lower:
            errors.append(f"inference-laden action term remains: {term}")
    if PID_TOKEN.search(str(step.get("subject") or "")) or PID_TOKEN.search(
        str(step.get("object") or "")
    ):
        errors.append("PID token appears in scored subject/object")
    return errors


def validate_db_rows(
    gold: dict[str, Any],
    steps: list[dict[str, Any]],
) -> tuple[int, list[dict[str, Any]]]:
    comparisons = 0
    mismatches: list[dict[str, Any]] = []
    connection = sqlite3.connect(evidence_utils.db_path(gold))
    connection.row_factory = sqlite3.Row
    try:
        for step in steps:
            for evidence in evidence_rows(step):
                row_id = int(evidence["source_row_id"])
                db_row = connection.execute(
                    "SELECT * FROM cbc_events WHERE id = ?",
                    (row_id,),
                ).fetchone()
                if db_row is None:
                    mismatches.append(
                        {
                            "step_id": step["step_id"],
                            "source_row_id": row_id,
                            "field": "row",
                        }
                    )
                    continue
                for gold_field, db_field in evidence_utils.CANONICAL_DB_FIELDS.items():
                    comparisons += 1
                    if not evidence_utils.values_equal(
                        evidence.get(gold_field), db_row[db_field]
                    ):
                        mismatches.append(
                            {
                                "step_id": step["step_id"],
                                "source_row_id": row_id,
                                "field": gold_field,
                                "gold": evidence.get(gold_field),
                                "database": db_row[db_field],
                            }
                        )
    finally:
        connection.close()
    return comparisons, mismatches


def focus_scope_uniqueness(
    gold: dict[str, Any],
    focus_process: str,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    focus = process_name(focus_process)
    expected_pids: set[int] = set()
    for step in gold["gold_steps"]:
        for row in evidence_rows(step):
            if process_name(row.get("process_path")) == focus and row.get("process_pid"):
                expected_pids.add(int(row["process_pid"]))
            if process_name(row.get("childproc_name")) == focus and row.get(
                "childproc_pid"
            ):
                expected_pids.add(int(row["childproc_pid"]))

    connection = sqlite3.connect(evidence_utils.db_path(gold))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT id, timestamp_utc, action, process_path, process_pid,
                   object_name, childproc_name, childproc_pid
            FROM cbc_events
            WHERE timestamp_utc >= ? AND timestamp_utc < ?
            ORDER BY timestamp_utc, id
            """,
            (
                start.isoformat().replace("+00:00", "Z"),
                end.isoformat().replace("+00:00", "Z"),
            ),
        ).fetchall()
    finally:
        connection.close()

    observed_pids: set[int] = set()
    major_rows: list[int] = []
    for row in rows:
        raw_action = str(row["action"] or "")
        object_text = normalized_path(row["object_name"])
        object_basename = object_text.rstrip("/").rsplit("/", 1)[-1]
        subject_is_focus = process_name(row["process_path"]) == focus
        child_is_focus = process_name(row["childproc_name"]) == focus
        major = (
            (
                "ACTION_CREATE_PROCESS" in raw_action
                and subject_is_focus
            )
            or (
                "ACTION_CONNECTION_CREATE" in raw_action
                and subject_is_focus
            )
            or (
                "ACTION_FILE" in raw_action
                and "OPEN" in raw_action
                and object_basename in {"msf.doc", "msf.rtf"}
                and subject_is_focus
            )
        )
        if not major:
            continue
        touched = False
        if subject_is_focus and row["process_pid"]:
            observed_pids.add(int(row["process_pid"]))
            touched = True
        if child_is_focus and subject_is_focus and row["childproc_pid"]:
            observed_pids.add(int(row["childproc_pid"]))
            touched = True
        if touched:
            major_rows.append(int(row["id"]))
    unexpected = sorted(observed_pids - expected_pids)
    return {
        "focus_process": focus,
        "expected_gold_focus_pids_provenance_only": sorted(expected_pids),
        "observed_major_focus_pids_in_scope": sorted(observed_pids),
        "unexpected_focus_pids": unexpected,
        "major_focus_row_ids": major_rows,
        "status": "pass" if not unexpected else "fail",
    }


def normal_reference_summary() -> dict[str, Any]:
    cases = read_jsonl(NORMAL_CASES)
    stage_counts = Counter(case["stage"] for case in cases)
    durations = {
        (
            parse_time(case["time_window_utc"]["episode_end"])
            - parse_time(case["time_window_utc"]["episode_start"])
        ).total_seconds()
        / 60
        for case in cases
    }
    stage1 = [case for case in cases if case["stage"] == "stage1"]
    gold_paths = {resolve_gold(case) for case in stage1}
    steps = []
    for path in gold_paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        steps.extend(payload.get("gold_steps") or payload.get("behavior_timeline") or [])
    pid_tokens = sum(
        bool(PID_TOKEN.search(str(step.get(field) or "")))
        for step in steps
        for field in ("subject", "object")
    )
    return {
        "case_file": str(NORMAL_CASES.relative_to(ROOT)),
        "gold_root": str(NORMAL_GOLD_ROOT.relative_to(ROOT)),
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "unique_chain_count": len(gold_paths),
        "gold_step_count": len(steps),
        "window_minutes": sorted(durations),
        "window_minutes_case_counts": dict(
            sorted(
                Counter(
                    (
                        parse_time(case["time_window_utc"]["episode_end"])
                        - parse_time(case["time_window_utc"]["episode_start"])
                    ).total_seconds()
                    / 60
                    for case in cases
                ).items()
            )
        ),
        "scored_pid_token_count": pid_tokens,
        "component_rubric": {
            "action_components": ["subject", "action", "object"],
            "critical_evidence": "separate diagnostic in component-rubric comparison",
            "order": "adjacent Gold pairs",
            "candidate_precision": True,
        },
    }


def audit(cases_path: Path, gold_root: Path) -> dict[str, Any]:
    cases = read_jsonl(cases_path)
    failures: list[dict[str, Any]] = []
    stage_counts = Counter(case["stage"] for case in cases)
    if stage_counts != Counter({stage: 8 for stage in ("stage1", "stage2", "stage3")}):
        failures.append({"check": "stage_counts", "actual": dict(stage_counts)})

    stage1 = [case for case in cases if case["stage"] == "stage1"]
    gold_by_chain: dict[str, dict[str, Any]] = {}
    total_steps = 0
    total_pairs = 0
    total_comparisons = 0
    total_db_mismatches = 0
    step_reviews: list[dict[str, Any]] = []
    chain_reviews: list[dict[str, Any]] = []
    for case in stage1:
        path = resolve_gold(case)
        if gold_root not in path.parents:
            failures.append({"check": "unexpected_gold_root", "path": str(path)})
        gold = json.loads(path.read_text(encoding="utf-8"))
        chain_id = str(gold["chain_id"])
        gold_by_chain[chain_id] = gold
        contract = gold.get("paired_stage_contract") or {}
        if contract.get("contract_version") != CONTRACT_VERSION:
            failures.append({"check": "contract_version", "chain_id": chain_id})
        steps = gold.get("gold_steps") or []
        total_steps += len(steps)
        total_pairs += max(0, len(steps) - 1)
        expected_pairs = [
            [steps[index]["step_id"], steps[index + 1]["step_id"]]
            for index in range(len(steps) - 1)
        ]
        if gold.get("gold_order_pairs") != expected_pairs:
            failures.append({"check": "order_pairs", "chain_id": chain_id})
        times = [
            parse_time(str((step.get("canonical_evidence") or [{}])[0]["timestamp_utc"]))
            for step in steps
        ]
        if times != sorted(times):
            failures.append({"check": "chronology", "chain_id": chain_id})
        for step in steps:
            errors = semantic_step_errors(step)
            step_reviews.append(
                {
                    "chain_id": chain_id,
                    "step_id": step["step_id"],
                    "subject": step["subject"],
                    "action": step["action"],
                    "object": step["object"],
                    "primary_row_id": int(
                        (step.get("canonical_evidence") or [{}])[0]["source_row_id"]
                    ),
                    "supporting_not_scored_row_ids": (
                        step.get("supporting_evidence") or {}
                    ).get("supporting_source_row_ids", []),
                    "semantic_evidence_status": "pass" if not errors else "fail",
                    "errors": errors,
                }
            )
            if errors:
                failures.append(
                    {
                        "check": "semantic_step",
                        "chain_id": chain_id,
                        "step_id": step["step_id"],
                        "errors": errors,
                    }
                )
        comparisons, mismatches = validate_db_rows(gold, steps)
        total_comparisons += comparisons
        total_db_mismatches += len(mismatches)
        if mismatches:
            failures.append(
                {
                    "check": "database_equality",
                    "chain_id": chain_id,
                    "mismatches": mismatches,
                }
            )
        start = parse_time(gold["input_scope"]["chain_window_start_utc"])
        end = parse_time(gold["input_scope"]["chain_window_end_utc"])
        if (end - start).total_seconds() != 300:
            failures.append({"check": "window_length", "chain_id": chain_id})
        if any(
            not start <= parse_time(str(row["timestamp_utc"])) < end
            for step in steps
            for row in evidence_rows(step)
        ):
            failures.append({"check": "evidence_outside_scope", "chain_id": chain_id})
        uniqueness = focus_scope_uniqueness(
            gold, str(case["process_name"]), start, end
        )
        if uniqueness["status"] != "pass":
            failures.append(
                {"check": "focus_scope_uniqueness", "chain_id": chain_id}
            )
        chain_reviews.append(
            {
                "chain_id": chain_id,
                "step_count": len(steps),
                "window_start_utc": gold["input_scope"]["chain_window_start_utc"],
                "window_end_utc": gold["input_scope"]["chain_window_end_utc"],
                "focus_scope_uniqueness": uniqueness,
                "granularity_audit_status": (
                    gold.get("gold_granularity_audit") or {}
                ).get("status"),
                "pid_identity_scored": (
                    gold.get("paired_stage_contract") or {}
                ).get("pid_identity_scored"),
            }
        )

    for chain_id in sorted(gold_by_chain):
        paired = [case for case in cases if case["chain_id"] == chain_id]
        if len(paired) != 3:
            failures.append({"check": "paired_cases", "chain_id": chain_id})
            continue
        signatures = {
            (
                case["host"],
                case["process_name"],
                case["time_window_utc"]["episode_start"],
                case["time_window_utc"]["episode_end"],
                case["gold_chain_file"],
            )
            for case in paired
        }
        if len(signatures) != 1:
            failures.append({"check": "paired_scope", "chain_id": chain_id})
        for case in paired:
            model_input = case["model_ready_input"]["input"]
            expected_keys = {
                "host",
                "focus_processes",
                "chain_window_start_utc",
                "chain_window_end_utc",
            } | ({"alerts"} if case["stage"] == "stage1" else set())
            if set(model_input) != expected_keys:
                failures.append(
                    {"check": "normal23_input_shape", "instance_id": case["instance_id"]}
                )
            if case["stage"] == "stage1":
                alerts = case.get("input_alert_rows") or []
                if len(alerts) != 1:
                    failures.append(
                        {"check": "stage1_alert_count", "instance_id": case["instance_id"]}
                    )
                else:
                    alert = alerts[0]
                    connection = sqlite3.connect(evidence_utils.db_path(gold_by_chain[chain_id]))
                    connection.row_factory = sqlite3.Row
                    try:
                        db_alert = connection.execute(
                            "SELECT * FROM cbc_alerts WHERE id = ?",
                            (int(alert["source_row_id"]),),
                        ).fetchone()
                    finally:
                        connection.close()
                    if (
                        db_alert is None
                        or db_alert["alert_id"] != alert["alert_id"]
                        or process_name(db_alert["process_path"])
                        != process_name(case["process_name"])
                    ):
                        failures.append(
                            {"check": "stage1_alert_provenance", "instance_id": case["instance_id"]}
                        )
            elif case.get("input_alert_rows"):
                failures.append(
                    {"check": "stage23_alert_leak", "instance_id": case["instance_id"]}
                )

    normal = normal_reference_summary()
    if (
        normal["case_count"] != 69
        or normal["stage_counts"]
        != {"stage1": 23, "stage2": 23, "stage3": 23}
        or normal["unique_chain_count"] != 23
        or normal["window_minutes"] != [5.0, 10.0, 15.0]
        or normal["window_minutes_case_counts"]
        != {5.0: 63, 10.0: 3, 15.0: 3}
        or normal["scored_pid_token_count"] != 0
    ):
        failures.append({"check": "normal_reference_contract"})
    gold_files = sorted(gold_root.glob("by_chain/*/chain_gold.json"))
    return {
        "status": "pass" if not failures else "fail",
        "review_kind": "deterministic evidence-and-contract review",
        "contract_version": CONTRACT_VERSION,
        "case_file": str(cases_path.relative_to(ROOT)),
        "gold_root": str(gold_root.relative_to(ROOT)),
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "chain_count": len(gold_by_chain),
        "gold_step_count_unique": total_steps,
        "action_component_denominator_per_stage": total_steps * 3,
        "critical_evidence_denominator_per_stage": total_steps,
        "order_pair_denominator_per_stage": total_pairs,
        "reviewed_step_count": len(step_reviews),
        "semantic_step_pass_count": sum(
            review["semantic_evidence_status"] == "pass" for review in step_reviews
        ),
        "database_field_comparisons": total_comparisons,
        "database_mismatch_count": total_db_mismatches,
        "focus_scope_uniqueness_pass_count": sum(
            review["focus_scope_uniqueness"]["status"] == "pass"
            for review in chain_reviews
        ),
        "hidden_alert_mapping_scored": False,
        "pid_identity_scored": False,
        "normal23_reference": normal,
        "chain_reviews": chain_reviews,
        "step_reviews": step_reviews,
        "artifact_hashes": {
            "case_file_sha256": sha256(cases_path),
            "gold_files": {
                str(path.relative_to(ROOT)): sha256(path) for path in gold_files
            },
        },
        "failure_count": len(failures),
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--gold-root", type=Path, default=GOLD_ROOT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    report = audit(args.cases, args.gold_root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
