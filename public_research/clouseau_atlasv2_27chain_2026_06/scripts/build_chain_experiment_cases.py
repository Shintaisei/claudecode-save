#!/usr/bin/env python3
"""Build runner-ready JSONL cases for the finalized 27-chain experiment."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
VALIDATION_DIR = ROOT / "docs" / "current_experiment" / "chain_gold_validation_2026-06-09"
MODEL_READY = VALIDATION_DIR / "chain_stage_inputs_model_ready_2026-06-09.json"
AUDIT_MAP = VALIDATION_DIR / "chain_stage_input_audit_map_2026-06-09.csv"
CHAIN_SUMMARY = ROOT / "data" / "current_experiment" / "gold" / "cbc_alert_behavior_chain_gold" / "chain_summary.csv"
DEFAULT_OUT = ROOT / "data" / "current_experiment" / "cases" / "cbc_27_chain_stage_cases_2026-06-09.jsonl"
SOURCE_DB = "Clouseau/artifact/scenarios/atlasv2/benign/h1/benign-1/incident.db"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv_keyed(path: Path, key: str) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return {row[key]: row for row in csv.DictReader(handle)}


def compact_db_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def stage_to_difficulty(stage: str) -> str:
    if stage == "stage1":
        return "alert_input"
    if stage in {"stage2", "stage3"}:
        return "process_time"
    raise ValueError(stage)


def build_anchor(stage_input: dict[str, Any], focus_processes: list[str]) -> dict[str, Any]:
    alerts = stage_input.get("alerts") or []
    if alerts:
        first = alerts[0]
        return {
            "source_stream": first.get("source_stream"),
            "timestamp_utc": first.get("time"),
            "database_time": compact_db_time(first.get("time") or ""),
            "alert_id": first.get("alert_id"),
            "alert_name": first.get("alert_name"),
            "process_name": first.get("process") or (focus_processes[0] if focus_processes else None),
            "process_path": None,
            "process_cmdline": None,
            "parent_path": None,
            "parent_cmdline": None,
            "severity": first.get("severity"),
            "reason": first.get("alert_reason"),
            "event_record_id": first.get("alert_id"),
            "action": "cbc_alert",
        }
    start = stage_input["chain_window_start_utc"]
    return {
        "source_stream": "scope",
        "timestamp_utc": start,
        "database_time": compact_db_time(start),
        "alert_id": None,
        "alert_name": None,
        "process_name": focus_processes[0] if focus_processes else None,
        "process_path": None,
        "process_cmdline": None,
        "parent_path": None,
        "parent_cmdline": None,
        "severity": None,
        "reason": None,
        "event_record_id": None,
        "action": "scope",
    }


def build_cases(model_ready: list[dict[str, Any]], audit_map: dict[str, dict[str, str]], chain_summary: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for row in model_ready:
        input_id = row["input_id"]
        stage = row["stage"]
        audit = audit_map[input_id]
        chain_id = audit["chain_id"]
        summary = chain_summary[chain_id]
        stage_input = row["input"]
        focus_processes = stage_input.get("focus_processes") or []
        instance_id = f"{chain_id}_{stage}"
        case = {
            "instance_id": instance_id,
            "case_id": instance_id,
            "input_id": input_id,
            "stage": stage,
            "scenario": "benign-h1-cbc-27-chain",
            "database": SOURCE_DB,
            "host": stage_input.get("host"),
            "process_name": "; ".join(focus_processes),
            "actor": "; ".join(focus_processes),
            "expected_behavior": summary.get("chain_title") or chain_id,
            "expected_behavior_category": audit.get("chain_type"),
            "context_label": "cbc_alert_behavior_chain_gold",
            "quality": "finalized_2026-06-09",
            "difficulty": stage_to_difficulty(stage),
            "time_window_utc": {
                "episode_start": stage_input["chain_window_start_utc"],
                "episode_end": stage_input["chain_window_end_utc"],
                "analysis_scope": "finalized chain window; runner may inspect surrounding DB evidence but primary chain must stay in scope",
            },
            "anchor_event": build_anchor(stage_input, focus_processes),
            "input_alert_rows": stage_input.get("alerts") or [],
            "model_ready_input": row,
            "gold_chain_file": summary.get("chain_gold_file"),
            "chain_id": chain_id,
            "chain_type": audit.get("chain_type"),
            "source_window_ids": summary.get("source_window_ids"),
            "formal_gold_root": "data/current_experiment/gold/cbc_alert_behavior_chain_gold",
            "stage3_answerable_policy": "For stage3, use validation stage3_status=pass steps as answerable gold; alert-only unsupported steps are reported separately.",
        }
        cases.append(case)
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-ready", type=Path, default=MODEL_READY)
    parser.add_argument("--audit-map", type=Path, default=AUDIT_MAP)
    parser.add_argument("--chain-summary", type=Path, default=CHAIN_SUMMARY)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    cases = build_cases(
        read_json(args.model_ready),
        read_csv_keyed(args.audit_map, "input_id"),
        read_csv_keyed(args.chain_summary, "chain_id"),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False) + "\n")
    print(json.dumps({"out": str(args.out), "case_count": len(cases)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
