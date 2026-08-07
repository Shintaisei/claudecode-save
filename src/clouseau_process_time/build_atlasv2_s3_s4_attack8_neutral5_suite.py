#!/usr/bin/env python3
"""Build the versioned ATLASv2 attack8 neutral-anchor, five-minute suite.

This suite keeps the eight Gold behavior chains from the validated paired
attack suite, but replaces the legacy 30-minute alert-centered scope with a
five-minute, evidence-aligned local scope.  The same neutral process/time
anchor, focus process, window, and Gold are used in all three stages.

The representative Stage-1 alert is an additional observed triage clue.  Its
correspondence to a hidden alert is explicitly outside the scoring target.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SOURCE_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_paired_stage_cases_20260724.jsonl"
)
SOURCE_GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "atlasv2_s3_s4_attack8_paired_gold_20260724"
)
OUT_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_neutral5_stage_cases_20260726.jsonl"
)
OUT_GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "atlasv2_s3_s4_attack8_neutral5_gold_20260726"
)
OUT_MANIFEST = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_neutral5_manifest_20260726.json"
)
OUT_VALIDATION = (
    ROOT
    / "docs/current_experiment"
    / "atlasv2_s3_s4_attack8_neutral5_build_validation_20260726.json"
)

STAGES = ("stage1", "stage2", "stage3")
WINDOW_MINUTES = 5
SUITE_GROUP = "atlasv2_s3_s4_attack8_neutral5"
CONTRACT_VERSION = "neutral_anchor_local_window_v1"
TARGET_COMPONENT_RULE = (
    "Reconstruct the evidence-connected component that contains the focus "
    "process observation at, or nearest to, the neutral anchor. Use only "
    "observed parent/child, command, process-identity, and target-object edges. "
    "Keep other nearby components separate."
)
CANONICAL_DB_FIELDS = {
    "source_stream": "stream_name",
    "timestamp_utc": "timestamp_utc",
    "action": "action",
    "process_path": "process_path",
    "process_pid": "process_pid",
    "parent_path": "parent_path",
    "parent_pid": "parent_pid",
    "process_cmdline": "process_cmdline",
    "object_name": "object_name",
    "remote_ip": "remote_ip",
    "remote_port": "remote_port",
    "netconn_domain": "netconn_domain",
    "childproc_name": "childproc_name",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def compact_db_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def normalize_process(value: Any) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def canonical_evidence(gold: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        evidence
        for step in gold.get("behavior_timeline") or []
        for evidence in step.get("canonical_evidence") or []
    ]


def focus_touch(evidence: dict[str, Any], focus_process: str) -> bool:
    focus = normalize_process(focus_process)
    fields = (
        evidence.get("process_path"),
        evidence.get("parent_path"),
        evidence.get("childproc_name"),
        evidence.get("object_name"),
    )
    return any(normalize_process(value) == focus for value in fields if value)


def choose_neutral_anchor(
    gold: dict[str, Any],
    focus_process: str,
) -> dict[str, Any]:
    evidence = canonical_evidence(gold)
    touching = [item for item in evidence if focus_touch(item, focus_process)]
    if not touching:
        raise ValueError(
            f"{gold.get('chain_id')}: no canonical evidence touches {focus_process}"
        )
    anchor = min(evidence, key=lambda item: parse_time(str(item["timestamp_utc"])))
    return {
        "timestamp_utc": str(anchor["timestamp_utc"]),
        "database_time": compact_db_time(str(anchor["timestamp_utc"])),
        "source_stream": anchor.get("source_stream"),
        "source_table": anchor.get("source_table"),
        "source_row_id": anchor.get("source_row_id"),
        "process_name": focus_process,
        "selection_policy": (
            "earliest canonical primary-telemetry row in the target component; "
            "the component must contain the declared focus process"
        ),
    }


def neutral_anchor_event(anchor: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_stream": "scope",
        "source_table": None,
        "source_row_id": None,
        "timestamp_utc": anchor["timestamp_utc"],
        "database_time": anchor["database_time"],
        "alert_id": None,
        "alert_name": None,
        "process_name": anchor["process_name"],
        "process_path": None,
        "process_cmdline": None,
        "parent_path": None,
        "parent_cmdline": None,
        "severity": None,
        "reason": None,
        "event_record_id": None,
        "action": "neutral_scope_anchor",
    }


def update_gold(
    source_gold: dict[str, Any],
    anchor: dict[str, Any],
    window_start: str,
    window_end: str,
    representative_alert: dict[str, Any],
) -> dict[str, Any]:
    gold = copy.deepcopy(source_gold)
    gold["case_group"] = "attack_behavior_chain_neutral5"
    gold["suite_group"] = SUITE_GROUP
    gold["stages_present"] = list(STAGES)
    scope = gold.setdefault("input_scope", {})
    scope.update(
        {
            "chain_window_start_utc": window_start,
            "chain_window_end_utc": window_end,
            "window_minutes": WINDOW_MINUTES,
            "window_selection_policy": (
                "evidence-aligned chain-complete five-minute local window"
            ),
            "neutral_anchor_utc": anchor["timestamp_utc"],
            "neutral_anchor_policy": anchor["selection_policy"],
            "target_component_rule": TARGET_COMPONENT_RULE,
            "input_policy": (
                "All stages use the same host, focus process, neutral timestamp, "
                "five-minute window, target-component rule, and Gold. Stage 1 "
                "adds one observed CBC alert clue; Stage 2 leaves alert summaries "
                "discoverable; Stage 3 hides alert-summary rows."
            ),
        }
    )
    gold["alert_timing"] = {
        "representative_alert_time_utc": representative_alert.get("time"),
        "neutral_anchor_utc": anchor["timestamp_utc"],
        "chain_window_start_utc": window_start,
        "chain_window_end_utc": window_end,
        "note": (
            "Alert issue time may follow the reconstructed telemetry. The alert "
            "is a Stage-1 clue only; alert-to-chain correspondence is not scored."
        ),
    }
    gold["paired_stage_contract"] = {
        "contract_version": CONTRACT_VERSION,
        "evaluation_unit": "evidence-connected behavior component",
        "same_gold_all_stages": True,
        "same_neutral_anchor_all_stages": True,
        "same_five_minute_window_all_stages": True,
        "target_component_rule": TARGET_COMPONENT_RULE,
        "alert_mapping_scored": False,
        "representative_alert_row_id": representative_alert.get("source_row_id"),
        "representative_alert_id": representative_alert.get("alert_id"),
        "hard_time_scope": False,
    }
    gold["scoring_exclusions"] = [
        "inferring which unavailable CBC alert corresponds to the Gold chain",
        "predicting a hidden alert id, alert title, alert reason, or alert-to-chain mapping",
    ]
    return gold


def build_case(
    source_case: dict[str, Any],
    gold: dict[str, Any],
    gold_file: str,
    gold_root: Path,
    anchor: dict[str, Any],
    window_start: str,
    window_end: str,
    stage: str,
    chain_index: int,
) -> dict[str, Any]:
    case = copy.deepcopy(source_case)
    chain_id = str(case["chain_id"])
    instance_id = f"{chain_id}_{stage}"
    representative_alerts = (
        copy.deepcopy(source_case.get("input_alert_rows") or [])
        if stage == "stage1"
        else []
    )
    if stage == "stage1" and len(representative_alerts) != 1:
        raise ValueError(f"{chain_id}: Stage 1 must retain exactly one alert clue")
    focus_processes = list(
        (gold.get("input_scope") or {}).get("focus_processes")
        or [case.get("process_name")]
    )
    model_input: dict[str, Any] = {
        "host": case.get("host"),
        "focus_processes": focus_processes,
        "neutral_anchor_utc": anchor["timestamp_utc"],
        "chain_window_start_utc": window_start,
        "chain_window_end_utc": window_end,
        "target_component_rule": TARGET_COMPONENT_RULE,
        "alert_mapping_scored": False,
    }
    if stage == "stage1":
        model_input["alerts"] = copy.deepcopy(representative_alerts)

    case.update(
        {
            "instance_id": instance_id,
            "case_id": instance_id,
            "input_id": f"atlasv2_attack8_neutral5_{chain_index:02d}_{stage}",
            "stage": stage,
            "difficulty": "alert_input" if stage == "stage1" else "process_time",
            "context_label": "attack_behavior_chain_neutral5",
            "suite_group": SUITE_GROUP,
            "quality": "neutral_anchor_normal_parity_20260726",
            "time_window_utc": {
                "episode_start": window_start,
                "episode_end": window_end,
                "analysis_scope": (
                    "Primary five-minute evaluation scope. Enumerate the complete "
                    "window and reconstruct only the neutral-anchor-connected "
                    "focus-process component; separate unconnected nearby behavior."
                ),
            },
            "anchor_event": neutral_anchor_event(anchor),
            "investigation_time_anchor_utc": anchor["timestamp_utc"],
            "investigation_time_anchor_policy": anchor["selection_policy"],
            "neutral_anchor_all_stages": True,
            "neutral_anchor_provenance": copy.deepcopy(anchor),
            "input_alert_rows": representative_alerts,
            "model_ready_input": {
                "input_id": f"atlasv2_attack8_neutral5_{chain_index:02d}",
                "stage": stage,
                "input": model_input,
            },
            "gold_chain_file": gold_file,
            "formal_gold_root": str(gold_root.relative_to(ROOT)),
            "stage_input_policy": (
                "Stage 1: common neutral host/process/time/window plus one "
                "representative CBC alert clue; alert mapping is not scored."
                if stage == "stage1"
                else (
                    "Stage 2: common neutral host/process/time/window only; CBC "
                    "alert summaries remain discoverable but their mapping is not scored."
                    if stage == "stage2"
                    else (
                        "Stage 3: common neutral host/process/time/window; CBC alert "
                        "summaries are hidden and their mapping is not scored."
                    )
                )
            ),
            "stage3_answerable_policy": (
                "All Gold steps use canonical cbc_events telemetry and remain "
                "answerable without CBC alert-summary rows."
            ),
            "paired_stage_contract": {
                "contract_version": CONTRACT_VERSION,
                "evaluation_unit": "evidence-connected behavior component",
                "chain_index": chain_index,
                "same_gold_all_stages": True,
                "same_neutral_anchor_all_stages": True,
                "same_five_minute_window_all_stages": True,
                "target_component_rule": TARGET_COMPONENT_RULE,
                "alert_mapping_scored": False,
                "hard_time_scope": False,
            },
        }
    )
    case.pop("enforce_time_scope", None)
    case.pop("input_provenance", None)
    if stage == "stage3":
        case["model_ready_input"]["db_filter"] = (
            "hide cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; "
            "retain cbc_events telemetry"
        )
    return case


def database_path(case: dict[str, Any]) -> Path:
    return ROOT / Path(str(case["database"]).replace("\\", "/"))


def values_equal(gold_value: Any, db_value: Any) -> bool:
    if gold_value is None or db_value is None:
        return gold_value is None and db_value is None
    if isinstance(gold_value, str):
        return gold_value == str(db_value)
    return gold_value == db_value


def validate_source_rows(
    stage1_cases: list[dict[str, Any]],
    gold_by_chain: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    connections: dict[Path, sqlite3.Connection] = {}
    comparisons = 0
    mismatches: list[dict[str, Any]] = []
    rows_checked = 0
    try:
        for case in stage1_cases:
            path = database_path(case)
            connection = connections.setdefault(path, sqlite3.connect(path))
            connection.row_factory = sqlite3.Row
            gold = gold_by_chain[str(case["chain_id"])]
            for evidence in canonical_evidence(gold):
                if evidence.get("source_table") != "cbc_events":
                    mismatches.append(
                        {
                            "chain_id": case["chain_id"],
                            "source_row_id": evidence.get("source_row_id"),
                            "field": "source_table",
                            "gold": evidence.get("source_table"),
                            "database": "cbc_events required",
                        }
                    )
                    continue
                row = connection.execute(
                    "SELECT * FROM cbc_events WHERE id = ?",
                    (int(evidence["source_row_id"]),),
                ).fetchone()
                rows_checked += 1
                if row is None:
                    mismatches.append(
                        {
                            "chain_id": case["chain_id"],
                            "source_row_id": evidence.get("source_row_id"),
                            "field": "row",
                            "gold": "present",
                            "database": "missing",
                        }
                    )
                    continue
                for gold_field, db_field in CANONICAL_DB_FIELDS.items():
                    comparisons += 1
                    if not values_equal(evidence.get(gold_field), row[db_field]):
                        mismatches.append(
                            {
                                "chain_id": case["chain_id"],
                                "source_row_id": evidence.get("source_row_id"),
                                "field": gold_field,
                                "gold": evidence.get(gold_field),
                                "database": row[db_field],
                            }
                        )
    finally:
        for connection in connections.values():
            connection.close()
    return {
        "rows_checked": rows_checked,
        "field_comparisons": comparisons,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "status": "pass" if not mismatches else "fail",
    }


def validate(
    cases: list[dict[str, Any]],
    gold_by_chain: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    chain_reports: list[dict[str, Any]] = []
    stage_counts = Counter(case["stage"] for case in cases)
    if dict(stage_counts) != {stage: 8 for stage in STAGES}:
        failures.append({"check": "stage_counts", "actual": dict(stage_counts)})
    instance_ids = [case["instance_id"] for case in cases]
    if len(instance_ids) != len(set(instance_ids)):
        failures.append({"check": "instance_ids_unique"})

    chain_sets = {
        stage: {case["chain_id"] for case in cases if case["stage"] == stage}
        for stage in STAGES
    }
    if not (chain_sets["stage1"] == chain_sets["stage2"] == chain_sets["stage3"]):
        failures.append({"check": "same_chain_set_all_stages"})

    anchor_keys: dict[tuple[str, str, str, str], str] = {}
    total_gold_steps = 0
    total_canonical_rows = 0
    for chain_id in sorted(chain_sets["stage1"]):
        paired = [case for case in cases if case["chain_id"] == chain_id]
        gold = gold_by_chain[chain_id]
        evidence = canonical_evidence(gold)
        steps = gold.get("behavior_timeline") or []
        total_gold_steps += len(steps)
        total_canonical_rows += len(evidence)
        signatures = {
            (
                case["host"],
                case["process_name"],
                case["investigation_time_anchor_utc"],
                case["time_window_utc"]["episode_start"],
                case["time_window_utc"]["episode_end"],
                case["gold_chain_file"],
            )
            for case in paired
        }
        if len(paired) != 3 or len(signatures) != 1:
            failures.append({"check": "paired_signature", "chain_id": chain_id})
            continue

        start = parse_time(paired[0]["time_window_utc"]["episode_start"])
        end = parse_time(paired[0]["time_window_utc"]["episode_end"])
        anchor_time = parse_time(paired[0]["investigation_time_anchor_utc"])
        timestamps = [parse_time(str(item["timestamp_utc"])) for item in evidence]
        coverage_ok = bool(timestamps) and min(timestamps) >= start and max(timestamps) <= end
        duration_ok = end - start == timedelta(minutes=WINDOW_MINUTES)
        anchor_ok = start <= anchor_time <= end
        visibility_ok = all(
            (
                len(case.get("input_alert_rows") or []) == 1
                and len(
                    ((case.get("model_ready_input") or {}).get("input") or {}).get(
                        "alerts"
                    )
                    or []
                )
                == 1
            )
            if case["stage"] == "stage1"
            else not (case.get("input_alert_rows") or [])
            and "alerts"
            not in ((case.get("model_ready_input") or {}).get("input") or {})
            for case in paired
        )
        no_alert_mapping_score = all(
            case["paired_stage_contract"].get("alert_mapping_scored") is False
            for case in paired
        )
        key = (
            str(paired[0]["scenario"]),
            str(paired[0]["host"]),
            normalize_process(paired[0]["process_name"]),
            compact_db_time(paired[0]["investigation_time_anchor_utc"]),
        )
        prior = anchor_keys.get(key)
        if prior:
            failures.append(
                {
                    "check": "neutral_anchor_uniqueness",
                    "chain_id": chain_id,
                    "collides_with": prior,
                    "key": key,
                }
            )
        anchor_keys[key] = chain_id
        if not all(
            (coverage_ok, duration_ok, anchor_ok, visibility_ok, no_alert_mapping_score)
        ):
            failures.append(
                {
                    "check": "chain_contract",
                    "chain_id": chain_id,
                    "coverage_ok": coverage_ok,
                    "duration_ok": duration_ok,
                    "anchor_ok": anchor_ok,
                    "visibility_ok": visibility_ok,
                    "no_alert_mapping_score": no_alert_mapping_score,
                }
            )
        chain_reports.append(
            {
                "chain_id": chain_id,
                "focus_process": paired[0]["process_name"],
                "neutral_anchor_utc": paired[0]["investigation_time_anchor_utc"],
                "window_start_utc": iso_time(start),
                "window_end_utc": iso_time(end),
                "window_seconds": int((end - start).total_seconds()),
                "gold_step_count": len(steps),
                "canonical_row_count": len(evidence),
                "first_gold_utc": iso_time(min(timestamps)),
                "last_gold_utc": iso_time(max(timestamps)),
                "gold_span_seconds": (max(timestamps) - min(timestamps)).total_seconds(),
                "all_gold_inside_window": coverage_ok,
                "anchor_uniqueness_key": list(key),
                "representative_alert_time_utc": (
                    paired[0]["input_alert_rows"][0].get("time")
                ),
                "alert_mapping_scored": False,
                "status": "pass"
                if all(
                    (
                        coverage_ok,
                        duration_ok,
                        anchor_ok,
                        visibility_ok,
                        no_alert_mapping_score,
                    )
                )
                else "fail",
            }
        )

    if total_gold_steps != 45:
        failures.append(
            {"check": "gold_step_total", "expected": 45, "actual": total_gold_steps}
        )
    if total_canonical_rows != 45:
        failures.append(
            {
                "check": "canonical_row_total",
                "expected": 45,
                "actual": total_canonical_rows,
            }
        )
    source_validation = validate_source_rows(
        [case for case in cases if case["stage"] == "stage1"],
        gold_by_chain,
    )
    if source_validation["status"] != "pass":
        failures.append({"check": "canonical_source_rows"})

    return {
        "status": "pass" if not failures else "fail",
        "suite": SUITE_GROUP,
        "contract_version": CONTRACT_VERSION,
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "chain_count": len(chain_sets["stage1"]),
        "gold_step_count_unique": total_gold_steps,
        "gold_step_count_across_stages": total_gold_steps * len(STAGES),
        "canonical_row_count_unique": total_canonical_rows,
        "canonical_row_count_across_stages": total_canonical_rows * len(STAGES),
        "neutral_anchor_key_count": len(anchor_keys),
        "alert_mapping_scored": False,
        "source_database_validation": source_validation,
        "chain_reports": chain_reports,
        "failures": failures,
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cases", type=Path, default=SOURCE_CASES)
    parser.add_argument("--source-gold-root", type=Path, default=SOURCE_GOLD_ROOT)
    parser.add_argument("--out-cases", type=Path, default=OUT_CASES)
    parser.add_argument("--out-gold-root", type=Path, default=OUT_GOLD_ROOT)
    parser.add_argument("--manifest", type=Path, default=OUT_MANIFEST)
    parser.add_argument("--validation", type=Path, default=OUT_VALIDATION)
    args = parser.parse_args()

    source_cases = read_jsonl(args.source_cases)
    source_stage1 = [case for case in source_cases if case.get("stage") == "stage1"]
    if len(source_stage1) != 8:
        raise ValueError(f"expected eight source Stage-1 cases, found {len(source_stage1)}")

    cases: list[dict[str, Any]] = []
    gold_by_chain: dict[str, dict[str, Any]] = {}
    gold_index: list[dict[str, Any]] = []
    for index, source_case in enumerate(source_stage1, 1):
        chain_id = str(source_case["chain_id"])
        source_gold_path = args.source_gold_root / str(source_case["gold_chain_file"])
        source_gold = json.loads(source_gold_path.read_text(encoding="utf-8"))
        focus_process = str(source_case["process_name"])
        anchor = choose_neutral_anchor(source_gold, focus_process)
        start = parse_time(anchor["timestamp_utc"])
        end = start + timedelta(minutes=WINDOW_MINUTES)
        window_start = iso_time(start)
        window_end = iso_time(end)
        representative_alert = copy.deepcopy(source_case["input_alert_rows"][0])
        gold = update_gold(
            source_gold,
            anchor,
            window_start,
            window_end,
            representative_alert,
        )
        gold_file = f"by_chain/{chain_id}/chain_gold.json"
        target_gold_path = args.out_gold_root / gold_file
        write_json(target_gold_path, gold)
        gold_by_chain[chain_id] = gold
        gold_index.append(
            {
                "chain_id": chain_id,
                "gold_chain_file": gold_file,
                "source_gold": str(source_gold_path.relative_to(ROOT)),
                "source_gold_sha256": sha256(source_gold_path),
                "neutral_anchor_utc": anchor["timestamp_utc"],
                "neutral_anchor_source_table": anchor["source_table"],
                "neutral_anchor_source_row_id": anchor["source_row_id"],
                "window_start_utc": window_start,
                "window_end_utc": window_end,
                "alert_mapping_scored": False,
            }
        )
        for stage in STAGES:
            cases.append(
                build_case(
                    source_case,
                    gold,
                    gold_file,
                    args.out_gold_root,
                    anchor,
                    window_start,
                    window_end,
                    stage,
                    index,
                )
            )

    validation = validate(cases, gold_by_chain)
    if validation["status"] != "pass":
        write_json(args.validation, validation)
        raise SystemExit(
            json.dumps(
                {"status": "fail", "failures": validation["failures"]},
                ensure_ascii=False,
                indent=2,
            )
        )

    args.out_cases.parent.mkdir(parents=True, exist_ok=True)
    args.out_cases.write_text(
        "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases),
        encoding="utf-8",
    )
    write_json(args.out_gold_root / "chain_gold_index.json", gold_index)
    write_json(
        args.manifest,
        {
            "suite": SUITE_GROUP,
            "contract_version": CONTRACT_VERSION,
            "purpose": (
                "Attack behavior reconstruction under the normal-reconstruction "
                "local-window and component-rubric contract."
            ),
            "source_case_file": str(args.source_cases.relative_to(ROOT)),
            "source_gold_root": str(args.source_gold_root.relative_to(ROOT)),
            "case_file": str(args.out_cases.relative_to(ROOT)),
            "gold_root": str(args.out_gold_root.relative_to(ROOT)),
            "stage_counts": {stage: 8 for stage in STAGES},
            "total_model_inputs": len(cases),
            "evaluation_unit": "eight evidence-connected behavior components",
            "window_policy": (
                "five-minute evidence-aligned chain-complete local window, "
                "identical across stages"
            ),
            "neutral_anchor_policy": (
                "earliest canonical primary-telemetry row in the target component; "
                "the component must contain the declared focus process"
            ),
            "target_component_rule": TARGET_COMPONENT_RULE,
            "alert_mapping_scored": False,
            "scoring_policy": (
                "Use the same subject/action/object component rubric, Gold step "
                "recall, order-pair recall, critical-evidence diagnostic, and "
                "candidate precision as normal reconstruction. Do not score "
                "hidden alert id/title/reason or alert-to-chain mapping."
            ),
            "agent_call_limit_policy": "unbounded_by_experiment",
            "gold_index": gold_index,
            "validation": str(args.validation.relative_to(ROOT)),
        },
    )
    write_json(args.validation, validation)
    print(
        json.dumps(
            {
                "status": "pass",
                "cases": str(args.out_cases),
                "case_count": len(cases),
                "stage_counts": dict(Counter(case["stage"] for case in cases)),
                "gold_step_count_unique": validation["gold_step_count_unique"],
                "source_field_comparisons": validation[
                    "source_database_validation"
                ]["field_comparisons"],
                "alert_mapping_scored": False,
                "validation": str(args.validation),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
