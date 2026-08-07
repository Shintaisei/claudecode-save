#!/usr/bin/env python3
"""Audit whether each visible Stage-1 alert is tied to its Gold component.

The alert may be emitted after the five-minute primary-telemetry window because
of detector latency.  It is acceptable only when its observed PID is present in
the Gold component (including a child PID expressed in the Gold step text).
Alert title/reason correspondence remains outside the scoring target.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PID_PATTERN = re.compile(r"\bPID\s+(\d+)\b", re.IGNORECASE)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def gold_component_pids(gold: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for step in gold.get("behavior_timeline") or []:
        for field in ("subject", "object"):
            result.update(PID_PATTERN.findall(str(step.get(field) or "")))
        for evidence in step.get("canonical_evidence") or []:
            for field in ("process_pid", "parent_pid"):
                value = evidence.get(field)
                if value is not None:
                    result.add(str(value))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--gold-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if args.out.exists():
        raise SystemExit(f"refusing to overwrite {args.out}")
    stage1 = [
        case for case in read_jsonl(args.cases) if case.get("stage") == "stage1"
    ]
    reports: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for case in stage1:
        alerts = case.get("input_alert_rows") or []
        if len(alerts) != 1:
            failures.append(
                {
                    "chain_id": case.get("chain_id"),
                    "reason": f"expected one Stage-1 alert, found {len(alerts)}",
                }
            )
            continue
        alert = alerts[0]
        gold_path = args.gold_root / str(case["gold_chain_file"])
        gold = json.loads(gold_path.read_text(encoding="utf-8"))
        component_pids = gold_component_pids(gold)
        alert_pid = str(alert.get("pid") or "")
        connected = bool(alert_pid) and alert_pid in component_pids
        start = parse_time(case["time_window_utc"]["episode_start"])
        end = parse_time(case["time_window_utc"]["episode_end"])
        alert_time = parse_time(str(alert["time"]))
        if alert_time < start:
            offset_seconds = (alert_time - start).total_seconds()
        elif alert_time > end:
            offset_seconds = (alert_time - end).total_seconds()
        else:
            offset_seconds = 0.0
        report = {
            "chain_id": case["chain_id"],
            "alert_id": alert.get("alert_id"),
            "alert_pid": alert_pid,
            "gold_component_pids": sorted(component_pids, key=int),
            "alert_pid_connected_to_gold_component": connected,
            "alert_time_utc": alert.get("time"),
            "window_start_utc": case["time_window_utc"]["episode_start"],
            "window_end_utc": case["time_window_utc"]["episode_end"],
            "alert_outside_window_offset_seconds": offset_seconds,
            "alert_mapping_scored": case["paired_stage_contract"].get(
                "alert_mapping_scored"
            ),
            "status": "pass" if connected else "fail",
        }
        reports.append(report)
        if not connected:
            failures.append(
                {
                    "chain_id": case["chain_id"],
                    "reason": "visible Stage-1 alert PID is absent from Gold component",
                    "alert_pid": alert_pid,
                }
            )

    payload = {
        "status": "pass" if not failures and len(reports) == 8 else "fail",
        "case_file": str(args.cases.resolve()),
        "gold_root": str(args.gold_root.resolve()),
        "stage1_case_count": len(stage1),
        "connected_alert_count": sum(
            report["alert_pid_connected_to_gold_component"] for report in reports
        ),
        "alert_mapping_scored": False,
        "reports": reports,
        "failures": failures,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if payload["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
