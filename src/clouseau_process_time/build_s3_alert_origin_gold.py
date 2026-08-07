"""Build deduplicated, alert-origin / alert-content-hidden S3 gold cases.

The normalizer is deliberately mechanical: a seed alert supplies only its
process path and PID; the earliest matching process-creation row in the prior
ten minutes supplies the five-minute investigation window.  Alert text never
becomes model-visible input.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from build_s3_attack_behavior_gold import canonical_record, sample_log, score_template


ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db"
BASE_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s3_attack_behavior_chain_gold"
OUT = ROOT / "data/current_experiment/gold/atlasv2_s3_alert_origin_behavior_chain_gold"


SPECS = [
    {
        "base_chain": "s3_attack_02_word_temp_rtf_context",
        "chain_id": "s3_alert_origin_01_word_document_context",
        "case_group": "alert_origin_context",
        "seed_alert_id": 29,
        "cluster_member_alert_ids": [29],
        "expected_creation_id": 9807,
        "title": "Alert-origin Word document-processing context",
        "interpretation": "Alert-origin / alert-content-hidden context case. The observed Word file handling is not asserted malicious.",
    },
    {
        "base_chain": "s3_attack_03_eqnedt32_regsvr32_remote_sct",
        "chain_id": "s3_alert_origin_02_regsvr32_remote_sct",
        "case_group": "alert_origin_attack_associated",
        "seed_alert_id": 21,
        "cluster_member_alert_ids": [21, 28, 17, 11],
        "expected_creation_id": 7829,
        "title": "Alert-origin regsvr32 remote SCT",
        "interpretation": "Alert-origin / alert-content-hidden attack-associated reconstruction point. It is not an independent attack sample.",
    },
    {
        "base_chain": "s3_attack_04_regsvr32_hidden_powershell",
        "chain_id": "s3_alert_origin_03_regsvr32_powershell",
        "case_group": "alert_origin_attack_associated",
        "seed_alert_id": 4,
        "cluster_member_alert_ids": [4, 19, 18, 7, 6, 5, 20],
        "expected_creation_id": 17797,
        "title": "Alert-origin regsvr32 to hidden PowerShell",
        "interpretation": "Alert-origin / alert-content-hidden attack-associated reconstruction point. It is not an independent attack sample.",
    },
    {
        "base_chain": "s3_attack_05_powershell_cmd_payload",
        "chain_id": "s3_alert_origin_04_powershell_descendant_execution",
        "case_group": "alert_origin_nested_attack_associated",
        "seed_alert_id": 7,
        "cluster_member_alert_ids": [7, 6, 5, 20],
        "expected_creation_id": 17863,
        "window_policy": "lineage_lifetime",
        "root_edge_id": 17863,
        "end_event_id": 18728,
        "customization": "powershell_descendant",
        "title": "Alert-origin PowerShell descendant execution",
        "interpretation": "Nested alternate-anchor investigation within the AO03 incident episode. It is alert-selected but not an independent attack sample.",
    },
    {
        "base_chain": "s3_attack_02_word_temp_rtf_context",
        "chain_id": "s3_alert_origin_05_embedded_word_context",
        "case_group": "alert_origin_nested_context",
        "seed_alert_id": 8,
        "cluster_member_alert_ids": [8],
        "expected_creation_id": 8727,
        "window_policy": "lineage_lifetime",
        "root_edge_id": 8727,
        "end_event_id": 8039,
        "customization": "embedded_word",
        "title": "Alert-origin embedded Word document processing",
        "interpretation": "Nested Office-context investigation. The observed embedded Word processing is not asserted malicious.",
    },
    {
        "base_chain": "s3_attack_05_powershell_cmd_payload",
        "chain_id": "s3_alert_origin_06_payload_lineage_pivot",
        "case_group": "alert_origin_lineage_pivot",
        "seed_alert_id": 7,
        "cluster_member_alert_ids": [7, 6, 5, 20],
        "expected_creation_id": 17863,
        "window_policy": "lineage_lifetime",
        "root_edge_id": 18358,
        "end_event_id": 18663,
        "customization": "payload_lineage_pivot",
        "model_focus": "payload.exe",
        "title": "PowerShell-alert-derived payload lineage pivot",
        "interpretation": "An analyst-selected descendant-process pivot from the PowerShell alert origin. It covers the local payload execution interval and is not a direct-alert or independent attack sample.",
    },
]


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def z(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def select_process_creation(con: sqlite3.Connection, alert: sqlite3.Row) -> sqlite3.Row:
    start = z(parse_time(alert["create_time_utc"]) - timedelta(minutes=10))
    row = con.execute(
        """
        SELECT * FROM cbc_events
        WHERE timestamp_utc BETWEEN ? AND ?
          AND action LIKE '%ACTION_CREATE_PROCESS%'
          AND (
              (process_pid = ? AND lower(coalesce(process_path, '')) = lower(?))
              OR (childproc_pid = ? AND lower(coalesce(childproc_name, '')) = lower(?))
          )
        ORDER BY timestamp_utc, id
        LIMIT 1
        """,
        (start, alert["create_time_utc"], alert["process_pid"], alert["process_path"], alert["process_pid"], alert["process_path"]),
    ).fetchone()
    if row is None:
        raise ValueError(f"No process-creation row for seed alert {alert['id']}")
    return row


def record(row: sqlite3.Row, table: str, stream: str) -> dict:
    return {
        "source_table": table,
        "source_row_id": row["id"],
        "source_stream": stream,
        "timestamp_utc": row["create_time_utc"] if table == "cbc_alerts" else row["timestamp_utc"],
        "process_path": row["process_path"],
        "process_pid": row["process_pid"],
    }


def custom_step(con: sqlite3.Connection, step_id: str, order: int, focus: str, subject: str, action: str, object_: str, evidence_id: int, one_line_ja: str) -> dict:
    evidence = canonical_record(con, evidence_id)
    return {
        "step_id": step_id,
        "order": order,
        "focus_process": focus,
        "subject": subject,
        "action": action,
        "object": object_,
        "evidence_basis": "Canonical CBC EDR event row",
        "confidence": "observed",
        "one_line_ja": one_line_ja,
        "process_code_object": object_,
        "scoring_template": score_template(),
        "canonical_evidence": [evidence],
        "supporting_evidence": {"source_types": ["CBC event"], "sample_logs": [sample_log(evidence)]},
    }


def sync_chain_fields(gold: dict) -> None:
    steps = gold["gold_steps"]
    gold["behavior_timeline"] = steps
    gold["timeline_ja"] = [step["one_line_ja"] for step in steps]
    gold["natural_language_summary_ja"] = " ".join(gold["timeline_ja"])
    gold["gold_order_pairs"] = [[steps[i]["step_id"], steps[i + 1]["step_id"]] for i in range(len(steps) - 1)]
    times = [step["canonical_evidence"][0]["timestamp_utc"] for step in steps]
    gold["evidence_span_utc"] = {"start": min(times), "end": max(times)}
    gold["case_scoring"]["step_score_max"] = len(steps) * 4
    gold["case_scoring"]["case_score_max"] = len(steps) * 4 + gold["case_scoring"]["sequence_score_max"]


def customize_gold(con: sqlite3.Connection, gold: dict, mode: str) -> None:
    if mode == "powershell_descendant":
        early_steps = [
            custom_step(con, "S3-AO04-S01", 1, "powershell.exe", "regsvr32.exe (PID 3992)", "started", "powershell.exe (PID 2340)", 17863, "regsvr32.exe が PowerShell (PID 2340) を起動した。"),
            custom_step(con, "S3-AO04-S02", 2, "powershell.exe", "powershell.exe (PID 2340)", "initiated connection", "10.193.66.115:8080", 18136, "PowerShell が 10.193.66.115:8080 への接続開始を記録した。"),
            custom_step(con, "S3-AO04-S03", 3, "powershell.exe", "powershell.exe (PID 2340)", "initiated connection", "10.193.66.115:8443", 18152, "PowerShell が 10.193.66.115:8443 への接続開始を記録した。"),
        ]
        later_steps = gold["gold_steps"]
        for index, item in enumerate(later_steps, start=4):
            item["step_id"] = f"S3-AO04-S{index:02d}"
            item["order"] = index
            item["focus_process"] = "powershell.exe"
        later_steps.append(custom_step(
            con, "S3-AO04-S07", 7, "powershell.exe", "payload.exe (PID 4964)", "initiated connection",
            "ortrta.net / 10.193.66.115:9999", 18558,
            "子payload.exe (PID 4964) が 10.193.66.115:9999 への接続開始を記録した。",
        ))
        gold["gold_steps"] = [*early_steps, *later_steps]
        gold["observed_behavior"] = "regsvr32 starts PowerShell; PowerShell records connections to ports 8080 and 8443, then starts cmd. The descendant cmd/payload processes start a child payload process, which records connection creation to port 9999."
        gold["chain_description"] = gold["observed_behavior"]
        gold["limitations"].append("The network connection is not labelled C2 or exfiltration by the local evidence alone.")
    elif mode == "embedded_word":
        gold["gold_steps"] = [
            custom_step(con, "S3-AO05-S01", 1, "winword.exe", "WINWORD.EXE (PID 5592)", "started embedded child", "WINWORD.EXE (PID 3368), /Embedding", 8727, "WINWORD.EXE (PID 5592) が /Embedding の子WINWORD.EXE (PID 3368) を起動した。"),
            custom_step(con, "S3-AO05-S02", 2, "winword.exe", "WINWORD.EXE (PID 3368)", "created", r"C:\Users\aalsahee\AppData\Local\Temp\oice_ce7908a8-1b1c-41bb-9778-64a530acad65.0\63fe2fcd.wmf", 8775, "子WINWORD.EXE が一時WMFファイルを作成した。"),
            custom_step(con, "S3-AO05-S03", 3, "winword.exe", "WINWORD.EXE (PID 3368)", "deleted", r"C:\Users\aalsahee\AppData\Local\Temp\oice_ce7908a8-1b1c-41bb-9778-64a530acad65.0\63fe2fcd.wmf", 8009, "子WINWORD.EXE が同じ一時WMFファイルを削除した。"),
            custom_step(con, "S3-AO05-S04", 4, "winword.exe", "WINWORD.EXE (PID 3368)", "terminated", "WINWORD.EXE (PID 3368)", 8039, "子WINWORD.EXE (PID 3368) の終了が記録された。"),
        ]
        gold["chain_type"] = "embedded_word_document_processing"
        gold["observed_behavior"] = "A parent Word process starts an embedded child Word process; the child creates and deletes a temporary WMF file before terminating."
        gold["chain_description"] = gold["observed_behavior"]
        gold["limitations"] = ["These observed Office file operations do not establish exploitation or malicious intent."]
    elif mode == "payload_lineage_pivot":
        gold["gold_steps"] = [
            custom_step(con, "S3-AO06-S01", 1, "payload.exe", "cmd.exe (PID 1880)", "started", "payload.exe (PID 3208)", 18358, "cmd.exe (PID 1880) が payload.exe (PID 3208) を起動した。"),
            custom_step(con, "S3-AO06-S02", 2, "payload.exe", "payload.exe (PID 3208)", "created", r"C:\Users\aalsahee\AppData\Local\Temp\_MEI32082", 18367, "payload.exe (PID 3208) による一時パス _MEI32082 の作成が記録された。"),
            custom_step(con, "S3-AO06-S03", 3, "payload.exe", "payload.exe (PID 3208)", "started child", "payload.exe (PID 4964)", 18470, "payload.exe (PID 3208) が子 payload.exe (PID 4964) を起動した。"),
            custom_step(con, "S3-AO06-S04", 4, "payload.exe", "payload.exe (PID 4964)", "initiated connection", "ortrta.net / 10.193.66.115:9999", 18558, "子 payload.exe (PID 4964) が 10.193.66.115:9999 への接続開始を記録した。"),
            custom_step(con, "S3-AO06-S05", 5, "payload.exe", "payload.exe (PID 4964)", "terminated", "payload.exe (PID 4964)", 18559, "子 payload.exe (PID 4964) の終了が記録された。"),
            custom_step(con, "S3-AO06-S06", 6, "payload.exe", "payload.exe (PID 3208)", "terminated", "payload.exe (PID 3208)", 18663, "親 payload.exe (PID 3208) の終了が記録された。"),
        ]
        gold["chain_type"] = "alert_lineage_payload_execution"
        gold["observed_behavior"] = "A cmd descendant of the alert-origin PowerShell starts payload.exe. The payload records creation of a temporary path, starts a child payload process, which records a connection initiation, then both payload processes terminate."
        gold["chain_description"] = gold["observed_behavior"]
        gold["limitations"] = [
            "This is an alert-lineage pivot from the PowerShell alert, not a process directly named by a separate alert.",
            "The local evidence is an ACTION_CONNECTION_CREATE record only; it does not establish connection success, C2, exfiltration, or its contents.",
            "Stage 3 exposes timestamps at second precision; no strict temporal order is scored among the first three events, which all appear in 14:37:20.",
        ]
    else:
        return
    sync_chain_fields(gold)
    if mode == "payload_lineage_pivot":
        # The Stage 3 adapter exposes timestamps at second precision.  The
        # first three canonical events all appear as 14:37:20 there, so their
        # sub-second order is retained as reference metadata but not scored.
        gold["gold_order_pairs"] = [
            ["S3-AO06-S03", "S3-AO06-S04"],
            ["S3-AO06-S04", "S3-AO06-S05"],
            ["S3-AO06-S05", "S3-AO06-S06"],
        ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DB)
    parser.add_argument("--base-gold", type=Path, default=BASE_GOLD)
    parser.add_argument("--out-dir", type=Path, default=OUT)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    index = []
    for spec in SPECS:
        alert = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (spec["seed_alert_id"],)).fetchone()
        if alert is None:
            raise ValueError(f"Missing seed alert {spec['seed_alert_id']}")
        creation = select_process_creation(con, alert)
        if creation["id"] != spec["expected_creation_id"]:
            raise ValueError(f"Unexpected normalizer result for {spec['chain_id']}: {creation['id']}")
        if spec.get("window_policy") == "lineage_lifetime":
            root_edge = con.execute("SELECT * FROM cbc_events WHERE id = ?", (spec["root_edge_id"],)).fetchone()
            end_event = con.execute("SELECT * FROM cbc_events WHERE id = ?", (spec["end_event_id"],)).fetchone()
            if root_edge is None or end_event is None:
                raise ValueError(f"Missing lineage boundary for {spec['chain_id']}")
            start, end = root_edge["timestamp_utc"], end_event["timestamp_utc"]
            window_rule = "lineage_lifetime: root descendant edge through selected seed/child process termination"
        else:
            start_dt = parse_time(creation["timestamp_utc"]).replace(second=0, microsecond=0)
            end_dt = start_dt + timedelta(minutes=5)
            start, end = z(start_dt), z(end_dt)
            root_edge = creation
            end_event = None
            window_rule = "fixed_5min: floor normalized process-creation time to minute, then +5 min"
        members = [con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (alert_id,)).fetchone() for alert_id in spec["cluster_member_alert_ids"]]
        base_path = args.base_gold / "by_chain" / spec["base_chain"] / "chain_gold.json"
        gold = deepcopy(json.loads(base_path.read_text(encoding="utf-8")))
        if spec.get("customization"):
            customize_gold(con, gold, spec["customization"])
        for step in gold["gold_steps"]:
            evidence_time = step["canonical_evidence"][0]["timestamp_utc"]
            within_window = start <= evidence_time <= end if spec.get("window_policy") == "lineage_lifetime" else start <= evidence_time < end
            if not within_window:
                raise ValueError(f"{spec['chain_id']} gold evidence outside fixed alert-origin window: {evidence_time}")
        gold["chain_id"] = spec["chain_id"]
        gold["chain_title"] = spec["title"]
        gold["case_group"] = spec["case_group"]
        gold["chain_description"] = gold["observed_behavior"]
        gold["scenario_interpretation"] = spec["interpretation"]
        if spec["case_group"].startswith("alert_origin_nested"):
            gold["independence_note"] = "Nested, non-independent alert-anchor branch within one of the three primary S3 episodes; report separately from primary episode-level results."
        elif spec["case_group"] == "alert_origin_lineage_pivot":
            gold["independence_note"] = "Nested, non-independent downstream lineage pivot within the PowerShell alert-origin episode; payload.exe is not directly named by a separate alert."
        else:
            gold["independence_note"] = "One of three primary, deduplicated alert-origin investigation episodes from the same S3 incident; do not treat as an independent attack sample."
        gold["input_scope"]["focus_processes"] = [spec.get("model_focus", Path(alert["process_path"]).name.lower())]
        gold["input_scope"]["chain_window_start_utc"] = start
        gold["input_scope"]["chain_window_end_utc"] = end
        if spec.get("window_policy") == "lineage_lifetime":
            gold["input_scope"].pop("window_minutes", None)
            gold["input_scope"]["window_duration_seconds"] = (parse_time(end) - parse_time(start)).total_seconds()
            gold["input_scope"]["window_selection_policy"] = "incident_bounded_lineage"
        else:
            gold["input_scope"]["window_selection_policy"] = "fixed_5min_event_anchored"
        if spec["case_group"] == "alert_origin_lineage_pivot":
            gold["input_scope"]["input_policy"] = "Stage 3 receives only host, an analyst-selected descendant executable, and its incident-bounded lineage window. Alert report/reason/tags/command line/PID and ground truth are excluded."
        else:
            gold["input_scope"]["input_policy"] = "Stage 3 receives only host, alerted executable name, and a mechanically normalized incident-bounded lineage window. Alert report/reason/tags/command line/PID and ground truth are excluded." if spec.get("window_policy") == "lineage_lifetime" else "Stage 3 receives only host, alerted executable name, and a mechanically normalized five-minute window. Alert report/reason/tags/command line/PID and ground truth are excluded."
        gold["stages_present"] = ["stage3"]
        gold["alert_origin_provenance"] = {
            "condition": "alert_lineage_pivot_alert_content_hidden" if spec["case_group"] == "alert_origin_lineage_pivot" else "alert_origin_alert_content_hidden",
            "normalizer": {
                "version": "seed_alert_pid_path_to_earliest_create_v1",
                "rule": "Search cbc_events for matching seed PID/path and ACTION_CREATE_PROCESS in [seed alert create_time - 10 min, seed alert create_time]; choose earliest row. " + window_rule,
            },
            "seed_alert": record(alert, "cbc_alerts", alert["stream_name"]),
            "cluster_member_alerts": [record(member, "cbc_alerts", member["stream_name"]) for member in members],
            "normalized_process_creation": {
                **record(creation, "cbc_events", creation["stream_name"]),
                "matched_event_role": "childproc",
                "matched_process_path": creation["childproc_name"],
                "matched_process_pid": creation["childproc_pid"],
            },
            "analysis_window_boundary": {
                "start_event": record(root_edge, "cbc_events", root_edge["stream_name"]),
                "end_event": record(end_event, "cbc_events", end_event["stream_name"]) if end_event else None,
            },
            "model_visible_projection": {"host": "WIN-32-H1", "focus_processes": gold["input_scope"]["focus_processes"], "chain_window_start_utc": start, "chain_window_end_utc": end},
        }
        if spec["case_group"] == "alert_origin_lineage_pivot":
            gold["alert_origin_provenance"]["lineage_pivot"] = {
                "rule": "Analyst-selected reference subcase: starting from the normalized PowerShell alert process, follow observed direct child-process edges PowerShell -> cmd.exe -> payload.exe and focus Stage 3 on the resulting payload execution interval.",
                "pivot_edge_ids": [18350, 18358],
                "selected_process_path": r"c:\users\aalsahee\payload.exe",
                "selected_process_pid": 3208,
                "scope_note": "The alert text is hidden from Stage 3. The lineage pivot is analyst/evaluation orchestration, not autonomous alert-to-payload discovery or a primary direct-alert case.",
            }
        target = args.out_dir / "by_chain" / spec["chain_id"]
        target.mkdir(parents=True, exist_ok=True)
        (target / "chain_gold.json").write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        index.append({"chain_id": spec["chain_id"], "seed_alert_row_id": alert["id"], "normalized_creation_row_id": creation["id"], "case_group": spec["case_group"]})
    (args.out_dir / "chain_gold_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(index)} alert-origin S3 gold cases to {args.out_dir}")


if __name__ == "__main__":
    main()
