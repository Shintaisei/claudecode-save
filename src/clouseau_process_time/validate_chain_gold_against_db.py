#!/usr/bin/env python3
"""Validate all CBC alert behavior-chain gold files against the source DB.

This script checks two things for the 27 chain-level gold files:
- Stage 1/2/3 input conditions are concretely materialized per chain.
- Each gold step has at least one supporting DB row in CBC alert/event or Sysmon
  evidence near the chain window.

It intentionally does not copy or mutate the multi-GB scenario database.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
GOLD_ROOT = ROOT / "data" / "current_experiment" / "gold" / "cbc_alert_behavior_chain_gold"
DEFAULT_DB = ROOT / "Clouseau" / "artifact" / "scenarios" / "atlasv2" / "benign" / "h1" / "benign-1" / "incident.db"
DEFAULT_OUT = ROOT / "docs" / "current_experiment" / "chain_gold_validation_2026-06-09"


@dataclass(frozen=True)
class EvidenceHit:
    table: str
    count: int
    sample: dict[str, Any] | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-root", type=Path, default=GOLD_ROOT)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--window-pad-minutes", type=int, default=5)
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def model_ready_inputs(input_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    model_rows: list[dict[str, Any]] = []
    audit_map: list[dict[str, Any]] = []
    for index, row in enumerate(input_rows, 1):
        input_id = f"chain_input_{index:03d}"
        common = {
            "host": row["host"],
            "focus_processes": row["focus_processes"],
            "chain_window_start_utc": row["chain_window_start_utc"],
            "chain_window_end_utc": row["chain_window_end_utc"],
        }
        model_rows.append(
            {
                "input_id": input_id,
                "stage": "stage1",
                "input": {
                    **common,
                    "alerts": row["stage1_input"]["alert_rows"],
                },
            }
        )
        model_rows.append({"input_id": input_id, "stage": "stage2", "input": common})
        model_rows.append(
            {
                "input_id": input_id,
                "stage": "stage3",
                "input": common,
                "db_filter": row["stage3_input"]["db_filter"],
            }
        )
        audit_map.append(
            {
                "input_id": input_id,
                "chain_id": row["chain_id"],
                "episode_id": row["episode_id"],
                "chain_type": row["chain_type"],
            }
        )
    return model_rows, audit_map


def parse_utc(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def lower_time_bound(value: str) -> str:
    return value[:-1] if value.endswith("Z") else value


def upper_time_bound(value: str) -> str:
    return lower_time_bound(value) + "~"


def split_terms(*values: Any) -> list[str]:
    terms: list[str] = []
    stop = {
        "",
        "c",
        "windows",
        "system32",
        "users",
        "aalsahee",
        "program",
        "files",
        "x86",
        "exe",
        "bat",
        "py",
        "dll",
        "hkcu",
        "hku",
        "software",
        "microsoft",
        "currentversion",
        "run",
    }
    for value in values:
        if value is None:
            continue
        text = str(value)
        for match in re.findall(r"[A-Za-z0-9_.:-]+", text):
            token = match.strip("._-").lower()
            if len(token) < 3 or token in stop:
                continue
            terms.append(token)
    priority = []
    for term in terms:
        if term not in priority:
            priority.append(term)
    return priority[:8]


def focus_terms(step: dict[str, Any]) -> list[str]:
    terms = split_terms(
        step.get("focus_process"),
        step.get("subject"),
        step.get("object"),
        step.get("process_code_object"),
    )
    preferred = [
        term
        for term in terms
        if term.endswith(".exe")
        or term.endswith(".bat")
        or term.endswith(".py")
        or term in {"simplehttpserver", "xmltodict", "discord", "update.exe", "tshark.exe", "python.exe", "cmd.exe"}
        or re.match(r"\d+\.\d+\.\d+\.\d+:\d+", term)
    ]
    return preferred[:5] or terms[:5]


def like_clause(columns: list[str], terms: list[str]) -> tuple[str, list[str]]:
    clauses: list[str] = []
    params: list[str] = []
    for term in terms:
        term_clauses = [f"lower(coalesce({column}, '')) LIKE ?" for column in columns]
        clauses.append("(" + " OR ".join(term_clauses) + ")")
        params.extend([f"%{term.lower()}%"] * len(columns))
    return " AND ".join(clauses), params


def query_count_and_sample(
    conn: sqlite3.Connection,
    table: str,
    time_col: str,
    columns: list[str],
    start: str,
    end: str,
    terms: list[str],
) -> EvidenceHit:
    if not terms:
        return EvidenceHit(table, 0, None)
    where, params = like_clause(columns, terms)
    sql = f"""
        SELECT *
        FROM {table}
        WHERE {time_col} >= ? AND {time_col} <= ?
          AND {where}
        ORDER BY {time_col}, id
        LIMIT 3
    """
    rows = conn.execute(sql, [lower_time_bound(start), upper_time_bound(end), *params]).fetchall()
    if not rows:
        return EvidenceHit(table, 0, None)
    count_sql = f"""
        SELECT COUNT(*)
        FROM {table}
        WHERE {time_col} >= ? AND {time_col} <= ?
          AND {where}
    """
    count = int(conn.execute(count_sql, [lower_time_bound(start), upper_time_bound(end), *params]).fetchone()[0])
    sample = dict(rows[0])
    sample["_match_mode"] = "all_terms"
    return EvidenceHit(table, count, sample)


def extract_gold_alert_ids(chain: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    patterns = [
        re.compile(r"alert_id=([^\s]+)"),
        re.compile(r"\b([A-Za-z0-9_-]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"),
    ]
    for step in chain.get("gold_steps", []):
        for line in (step.get("supporting_evidence") or {}).get("sample_logs", []):
            for pattern in patterns:
                for match in pattern.findall(line):
                    if match not in ids:
                        ids.append(match)
    return ids


def get_stage1_alert_rows(conn: sqlite3.Connection, chain: dict[str, Any]) -> list[dict[str, Any]]:
    scope = chain["input_scope"]
    start = scope["chain_window_start_utc"]
    end = scope["chain_window_end_utc"]
    ids = extract_gold_alert_ids(chain)
    if not ids:
        return []
    placeholders = ", ".join(["?"] * len(ids))
    rows = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT create_time_utc, stream_name, alert_id, severity, reason, report_name,
                   process_name, process_pid, device_name
            FROM cbc_alerts
            WHERE create_time_utc >= ? AND create_time_utc <= ?
              AND alert_id IN ({placeholders})
            ORDER BY create_time_utc, alert_id, id
            """,
            [lower_time_bound(start), upper_time_bound(end), *ids],
        )
    ]
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        key = (
            row.get("create_time_utc"),
            row.get("stream_name"),
            row.get("alert_id"),
            row.get("severity"),
            row.get("reason"),
            row.get("report_name"),
            row.get("process_name"),
            row.get("process_pid"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def count_raw_window_alert_rows(conn: sqlite3.Connection, chain: dict[str, Any]) -> int:
    scope = chain["input_scope"]
    return int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM cbc_alerts
            WHERE create_time_utc >= ? AND create_time_utc <= ?
            """,
            [lower_time_bound(scope["chain_window_start_utc"]), upper_time_bound(scope["chain_window_end_utc"])],
        ).fetchone()[0]
    )


def input_manifest_row(conn: sqlite3.Connection, chain: dict[str, Any]) -> dict[str, Any]:
    scope = chain["input_scope"]
    alert_rows = get_stage1_alert_rows(conn, chain)
    stage1_alerts = [
        {
            "time": row["create_time_utc"],
            "source_stream": row["stream_name"],
            "alert_id": row["alert_id"],
            "alert_name": row["report_name"] or row["reason"],
            "alert_reason": row["reason"],
            "process": row["process_name"],
            "pid": row["process_pid"],
            "severity": row["severity"],
        }
        for row in alert_rows
    ]
    return {
        "chain_id": chain["chain_id"],
        "episode_id": chain["episode_id"],
        "chain_type": chain["chain_type"],
        "host": scope.get("host"),
        "focus_processes": scope.get("focus_processes") or [],
        "chain_window_start_utc": scope.get("chain_window_start_utc"),
        "chain_window_end_utc": scope.get("chain_window_end_utc"),
        "stage1_input": {
            "condition": "CBC alert input",
            "allowed_fields": [
                "host",
                "focus_processes",
                "chain_window_start_utc",
                "chain_window_end_utc",
                "alert_time",
                "alert_id",
                "alert_name",
                "alert_reason",
                "alert_process",
                "alert_pid",
                "alert_source_stream",
                "alert_severity",
            ],
            "forbidden_fields": [
                "gold_steps",
                "chain_type",
                "expected_behavior_label",
                "parent_process",
                "command_line",
                "child_process",
                "registry_object",
                "file_object",
                "network_object",
            ],
            "alert_rows": stage1_alerts,
        },
        "stage2_input": {
            "condition": "process-time full DB",
            "allowed_fields": ["host", "focus_processes", "chain_window_start_utc", "chain_window_end_utc"],
            "forbidden_fields": ["alert_id", "alert_name", "alert_reason", "command_line", "parent_process", "target_object", "gold_steps"],
        },
        "stage3_input": {
            "condition": "process-time alert summary removed",
            "allowed_fields": ["host", "focus_processes", "chain_window_start_utc", "chain_window_end_utc"],
            "db_filter": "remove cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; retain cbc_events telemetry",
            "forbidden_fields": ["alert_id", "alert_name", "alert_reason", "command_line", "parent_process", "target_object", "gold_steps"],
        },
        "db_stage1_alert_row_count": len(stage1_alerts),
        "stage1_status": "pass" if extract_gold_alert_ids(chain) and stage1_alerts else "fail",
        "db_raw_window_alert_row_count": count_raw_window_alert_rows(conn, chain),
        "gold_sample_alert_ids": extract_gold_alert_ids(chain),
        "gold_alert_count": scope.get("alert_count"),
    }


def validate_step(conn: sqlite3.Connection, chain: dict[str, Any], step: dict[str, Any], pad_minutes: int) -> dict[str, Any]:
    scope = chain["input_scope"]
    start_dt = parse_utc(scope["chain_window_start_utc"]) - timedelta(minutes=pad_minutes)
    end_dt = parse_utc(scope["chain_window_end_utc"]) + timedelta(minutes=pad_minutes)
    start_iso = iso_z(start_dt)
    end_iso = iso_z(end_dt)
    start_db = db_time(start_iso)
    end_db = db_time(end_iso)
    terms = focus_terms(step)

    checks = [
        query_count_and_sample(
            conn,
            "cbc_alerts",
            "create_time_utc",
            [
                "process_path",
                "process_name",
                "process_cmdline",
                "parent_path",
                "parent_cmdline",
                "reason",
                "report_name",
                "alert_id",
            ],
            start_iso,
            end_iso,
            terms,
        ),
        query_count_and_sample(
            conn,
            "cbc_events",
            "timestamp_utc",
            [
                "process_path",
                "process_cmdline",
                "parent_path",
                "parent_cmdline",
                "object_name",
                "childproc_name",
                "filemod_name",
                "regmod_name",
                "modload_name",
                "netconn_domain",
                "remote_ip",
                "local_ip",
                "action",
            ],
            start_iso,
            end_iso,
            terms,
        ),
        query_count_and_sample(
            conn,
            "sysmon_logs",
            "timestamp_utc",
            ["image", "command_line", "parent_image", "parent_command_line", "target_filename", "query_name", "object_name"],
            start_iso,
            end_iso,
            terms,
        ),
    ]
    hits = [hit for hit in checks if hit.count > 0]
    status = "pass" if hits else "fail"
    best = max(hits, key=lambda h: h.count) if hits else None
    stage3_hits = [hit for hit in checks[1:] if hit.count > 0]
    stage3_status = "pass" if stage3_hits else "unsupported_after_alert_summary_removal"
    stage3_best = max(stage3_hits, key=lambda h: h.count) if stage3_hits else None
    return {
        "chain_id": chain["chain_id"],
        "step_id": step["step_id"],
        "order": step.get("order"),
        "subject": step.get("subject"),
        "action": step.get("action"),
        "object": step.get("object"),
        "evidence_basis": step.get("evidence_basis"),
        "search_window_start_utc": start_iso,
        "search_window_end_utc": end_iso,
        "terms": "; ".join(terms),
        "status": status,
        "best_table": best.table if best else "",
        "best_count": best.count if best else 0,
        "cbc_alert_hits": checks[0].count,
        "cbc_event_hits": checks[1].count,
        "sysmon_hits": checks[2].count,
        "stage3_status": stage3_status,
        "stage3_best_table": stage3_best.table if stage3_best else "",
        "stage3_best_count": stage3_best.count if stage3_best else 0,
        "sample": json.dumps(best.sample, ensure_ascii=False) if best and best.sample else "",
        "stage3_sample": json.dumps(stage3_best.sample, ensure_ascii=False) if stage3_best and stage3_best.sample else "",
    }


def main() -> None:
    args = parse_args()
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    chain_paths = sorted((args.gold_root / "by_chain").glob("*/chain_gold.json"))
    chains = [read_json(path) for path in chain_paths]

    input_rows = [input_manifest_row(conn, chain) for chain in chains]
    step_rows: list[dict[str, Any]] = []
    for chain in chains:
        for step in chain.get("gold_steps", []):
            step_rows.append(validate_step(conn, chain, step, args.window_pad_minutes))

    conn.close()

    fail_steps = [row for row in step_rows if row["status"] != "pass"]
    stage1_fail_chains = [row for row in input_rows if row["stage1_status"] != "pass"]
    stage3_unsupported_steps = [row for row in step_rows if row["stage3_status"] != "pass"]
    status = "passed"
    if fail_steps or stage1_fail_chains:
        status = "needs_review"
    elif stage3_unsupported_steps:
        status = "passed_with_stage3_partial_support"
    summary = {
        "status": status,
        "chain_count": len(chains),
        "gold_step_count": len(step_rows),
        "step_pass_count": len(step_rows) - len(fail_steps),
        "step_fail_count": len(fail_steps),
        "stage1_input_pass_count": len(input_rows) - len(stage1_fail_chains),
        "stage1_input_fail_count": len(stage1_fail_chains),
        "stage3_supported_step_count": len(step_rows) - len(stage3_unsupported_steps),
        "stage3_unsupported_step_count": len(stage3_unsupported_steps),
        "stage3_unsupported_steps": [row["step_id"] for row in stage3_unsupported_steps],
        "db": str(args.db.relative_to(ROOT) if args.db.is_relative_to(ROOT) else args.db),
        "window_pad_minutes": args.window_pad_minutes,
        "notes": [
            "Stage 1 inputs include CBC alert triage fields only, not command lines or gold behavior.",
            "Stage 1 alert rows are chain-specific rows identified from gold supporting alert IDs when available.",
            "Stage 1 no longer falls back to all alerts in the time window when gold alert IDs are absent.",
            "db_raw_window_alert_row_count is retained for auditing nearby unrelated alerts; it is not the Stage 1 input count.",
            "Stage 2/3 inputs include host, focus_processes, and chain time window only.",
            "Stage 3 removes alert summary rows but retains cbc_events telemetry.",
            "Gold step pass/fail requires all extracted material terms to match in the same DB row; any-term matches are not counted as pass.",
        ],
    }

    out = args.out_dir
    stage_input_rows, stage_input_audit_map = model_ready_inputs(input_rows)
    write_json(out / "chain_input_conditions_2026-06-09.json", input_rows)
    write_json(out / "chain_stage_inputs_model_ready_2026-06-09.json", stage_input_rows)
    write_json(out / "chain_gold_db_validation_summary_2026-06-09.json", summary)
    write_json(out / "chain_gold_db_validation_steps_2026-06-09.json", step_rows)
    write_csv(
        out / "chain_stage_input_audit_map_2026-06-09.csv",
        stage_input_audit_map,
        ["input_id", "chain_id", "episode_id", "chain_type"],
    )
    write_csv(
        out / "chain_input_conditions_2026-06-09.csv",
        [
            {
                "chain_id": row["chain_id"],
                "episode_id": row["episode_id"],
                "chain_type": row["chain_type"],
                "host": row["host"],
                "focus_processes": "; ".join(row["focus_processes"]),
                "chain_window_start_utc": row["chain_window_start_utc"],
                "chain_window_end_utc": row["chain_window_end_utc"],
                "gold_alert_count": row["gold_alert_count"],
                "stage1_status": row["stage1_status"],
                "db_stage1_alert_row_count": row["db_stage1_alert_row_count"],
                "db_raw_window_alert_row_count": row["db_raw_window_alert_row_count"],
                "gold_sample_alert_ids": "; ".join(row["gold_sample_alert_ids"]),
                "stage1_allowed_fields": "; ".join(row["stage1_input"]["allowed_fields"]),
                "stage2_allowed_fields": "; ".join(row["stage2_input"]["allowed_fields"]),
                "stage3_allowed_fields": "; ".join(row["stage3_input"]["allowed_fields"]),
            }
            for row in input_rows
        ],
        [
            "chain_id",
            "episode_id",
            "chain_type",
            "host",
            "focus_processes",
            "chain_window_start_utc",
            "chain_window_end_utc",
            "gold_alert_count",
            "stage1_status",
            "db_stage1_alert_row_count",
            "db_raw_window_alert_row_count",
            "gold_sample_alert_ids",
            "stage1_allowed_fields",
            "stage2_allowed_fields",
            "stage3_allowed_fields",
        ],
    )
    write_csv(
        out / "chain_gold_db_validation_steps_2026-06-09.csv",
        step_rows,
        [
            "chain_id",
            "step_id",
            "order",
            "subject",
            "action",
            "object",
            "evidence_basis",
            "search_window_start_utc",
            "search_window_end_utc",
            "terms",
            "status",
            "best_table",
            "best_count",
            "cbc_alert_hits",
            "cbc_event_hits",
            "sysmon_hits",
            "stage3_status",
            "stage3_best_table",
            "stage3_best_count",
            "sample",
            "stage3_sample",
        ],
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
