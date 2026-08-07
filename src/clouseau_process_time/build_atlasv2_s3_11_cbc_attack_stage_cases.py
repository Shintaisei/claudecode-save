"""Build the preflight assets for the 11 S3 CBC-alert attack inputs.

Each selected CBC alert target becomes one input in Stage 1, Stage 2, and
Stage 3.  The 11 inputs deliberately overlap: they are alert-level probes of
three observed S3 behavior clusters, not 11 independent attacks.

Gold uses only canonical ``cbc_events`` rows.  In particular, the Word
boundary case ends at observed Word file processing and never asserts a
Word-to-Equation-Editor edge.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from build_s3_attack_behavior_gold import canonical_record, sample_log, score_template


ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db"
OUT_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s3_11_cbc_attack_gold_20260723"
OUT_PROCESS_TIME_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s3_4_process_time_gold_20260723"
OUT_CASES = ROOT / "data/current_experiment/cases"
OUT_VALIDATION = ROOT / "docs/current_experiment/atlasv2_s3_11_cbc_attack_preflight_validation_20260723.json"

ALERT_FIELDS = (
    "create_time_utc", "stream_name", "alert_id", "type", "severity", "category", "reason", "reason_code",
    "process_name", "threat_cause_actor_name", "created_by_event_id", "device_name", "process_path", "process_pid",
    "process_cmdline", "parent_path", "parent_pid", "parent_cmdline", "report_name", "report_tags",
)
EVENT_FIELDS = (
    "timestamp_utc", "action", "process_path", "process_pid", "parent_path", "parent_pid", "process_cmdline",
    "object_name", "remote_ip", "remote_port", "netconn_domain", "childproc_name", "childproc_pid",
)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def window_for(alert_time: str) -> tuple[str, str]:
    """The fixed, experiment-wide hard investigation scope: alert time ±15 min."""
    moment = parse_time(alert_time)
    return iso(moment - timedelta(minutes=15)), iso(moment + timedelta(minutes=15))


def alert_visible(row: sqlite3.Row) -> dict:
    return {
        "source_row_id": row["id"], "time": row["create_time_utc"], "alert_id": row["alert_id"],
        "alert_name": row["report_name"], "alert_reason": row["reason"], "process": row["process_path"],
        "pid": row["process_pid"], "source_stream": row["stream_name"], "severity": row["severity"],
    }


def alert_canonical(row: sqlite3.Row) -> dict:
    return {"source_table": "cbc_alerts", "source_row_id": row["id"], **{key: row[key] for key in ALERT_FIELDS}}


def evidence_step(con: sqlite3.Connection, step_id: str, order: int, subject: str, action: str, object_: str,
                  evidence_id: int, evidence_kind: str, note_ja: str) -> dict:
    event = canonical_record(con, evidence_id)
    return {
        "step_id": step_id,
        "order": order,
        "subject": subject,
        "action": action,
        "object": object_,
        "evidence_kind": evidence_kind,
        "evidence_basis": "Canonical CBC EDR telemetry event row (Stage 3-visible)",
        "confidence": "observed",
        "one_line_ja": note_ja,
        "process_code_object": object_,
        "scoring_template": score_template(),
        "canonical_evidence": [event],
        "supporting_evidence": {"source_types": ["CBC event"], "sample_logs": [sample_log(event)]},
    }


WORD_STEPS = (
    ("WINWORD.EXE (PID 5592)", "opened/read", r"C:\Users\aalsahee\Downloads\s3take2\msf.rtf", 8705, "file", "Word が msf.rtf を開いた。"),
    ("WINWORD.EXE (PID 5592)", "created", r"C:\Users\aalsahee\AppData\Local\Temp\oice_ce7908a8-1b1c-41bb-9778-64a530acad65.0\c586a0f0.rtf", 8767, "file", "Word が一時 RTF ファイルを作成した。"),
    ("WINWORD.EXE (PID 5592)", "deleted", r"C:\Users\aalsahee\AppData\Local\Temp\oice_ce7908a8-1b1c-41bb-9778-64a530acad65.0\c586a0f0.rtf", 8041, "file", "Word が一時 RTF ファイルを削除した。"),
)
SHORT_REGSVR32_STEPS = (
    ("svchost.exe / DcomLaunch (PID 648)", "started", "EQNEDT32.EXE (PID 6032)", 7814, "parent_child", "DcomLaunch の svchost が Equation Editor を起動した。"),
    ("EQNEDT32.EXE (PID 6032)", "started", "regsvr32.exe (PID 6124)", 7829, "parent_child", "Equation Editor が regsvr32 を起動した。"),
    ("regsvr32.exe (PID 6124)", "initiated connection using remote SCT command", "ortrta.net / 10.193.66.115:8080", 7889, "command_network", "regsvr32 が remote SCT を示すコマンドで 10.193.66.115:8080 への接続作成を記録した。"),
)
LONG_REGSVR32_STEPS = (
    ("EQNEDT32.EXE (PID 2244)", "started", "regsvr32.exe (PID 3992)", 17797, "parent_child", "Equation Editor が regsvr32 を起動した。"),
    ("regsvr32.exe (PID 3992)", "started", "powershell.exe (PID 2340)", 17863, "parent_child_command", "regsvr32 が hidden/IEX を含む PowerShell を起動した。"),
    ("powershell.exe (PID 2340)", "initiated connection", "ortrta.net / 10.193.66.115:8080", 18136, "network", "PowerShell が 10.193.66.115:8080 への接続作成を記録した。"),
    ("powershell.exe (PID 2340)", "initiated connection", "ortrta.net / 10.193.66.115:8443", 18152, "network", "PowerShell が 10.193.66.115:8443 への接続作成を記録した。"),
    ("powershell.exe (PID 2340)", "started", "cmd.exe (PID 1880)", 18350, "parent_child", "PowerShell が cmd.exe を起動した。"),
    ("cmd.exe (PID 1880)", "started", r"C:\Users\aalsahee\payload.exe (PID 3208)", 18358, "parent_child", "cmd.exe が payload.exe を起動した。"),
    ("payload.exe (PID 3208)", "started", "payload.exe (PID 4964)", 18470, "parent_child", "payload.exe が子 payload.exe を起動した。"),
    ("payload.exe (PID 4964)", "initiated connection", "ortrta.net / 10.193.66.115:9999", 18558, "network", "子 payload.exe が 10.193.66.115:9999 への接続作成を記録した。"),
)
POWERSHELL_STEPS = LONG_REGSVR32_STEPS[1:]


SPECS = (
    {"case_id": "s3_01_word_normal_dotm", "selection_id": "S3-01", "alert_row_id": 29, "focus": "winword.exe", "cluster": "S3-C1", "steps": WORD_STEPS, "case_kind": "boundary_entry", "description": "Word opens msf.rtf and performs temporary RTF processing. No observed edge in this gold connects Word to the later Equation Editor/regsvr32 sequence.", "limitations": ["This is a boundary case: the local evidence establishes document processing, not exploitation or malicious intent.", "Do not causally connect this Word activity to Equation Editor, regsvr32, PowerShell, payload, or external connections without an observed edge."]},
    *({"case_id": f"s3_{number:02d}_regsvr32_6124", "selection_id": f"S3-{number:02d}", "alert_row_id": alert_id, "focus": "regsvr32.exe", "cluster": "S3-C2", "steps": SHORT_REGSVR32_STEPS, "case_kind": "clear_short_chain", "description": "CBC telemetry records DcomLaunch svchost starting Equation Editor, Equation Editor starting regsvr32, and regsvr32 creating a connection whose command line names a remote SCT.", "limitations": ["The connection creation record does not establish remote SCT execution success or payload execution."]} for number, alert_id in ((2, 21), (3, 28), (4, 17))),
    *({"case_id": f"s3_{number:02d}_regsvr32_3992", "selection_id": f"S3-{number:02d}", "alert_row_id": alert_id, "focus": "regsvr32.exe", "cluster": "S3-C3", "steps": LONG_REGSVR32_STEPS, "case_kind": "clear_long_chain", "description": "CBC telemetry records Equation Editor to regsvr32, regsvr32 to hidden/IEX PowerShell, two PowerShell connection creations, and descendant cmd/payload process events ending in an external connection creation.", "limitations": ["Connection creation does not establish download completion, connection success, C2, exfiltration, or payload purpose."]} for number, alert_id in ((5, 4), (6, 18), (7, 19))),
    *({"case_id": f"s3_{number:02d}_powershell_2340", "selection_id": f"S3-{number:02d}", "alert_row_id": alert_id, "focus": "powershell.exe", "cluster": "S3-C3", "steps": POWERSHELL_STEPS, "case_kind": "mid_chain", "description": "CBC telemetry records regsvr32 starting hidden/IEX PowerShell, then PowerShell-to-cmd and descendant payload process events ending in an external connection creation.", "limitations": ["The case starts at the observed regsvr32-to-PowerShell edge; it does not claim an earlier Equation Editor edge as part of this PowerShell-centered gold.", "Connection creation does not establish C2, exfiltration, or payload purpose."]} for number, alert_id in ((8, 7), (9, 6), (10, 5), (11, 20))),
)

# Stage 2/3 do not receive an alert summary.  Alert variants that have the
# same process and effectively the same alert-centred scope must therefore not
# be scored repeatedly.  Each entry selects one representative alert only to
# mechanically define the common 30-minute window; it is not model-visible.
PROCESS_TIME_SPECS = (
    {"chain_id": "s3_pt_01_word_document_processing", "title": "S3-C1: Word document processing", "source_case": "s3_01_word_normal_dotm", "cluster": "S3-C1", "representative_alert_row": 29, "variant_selection_ids": ["S3-01"]},
    {"chain_id": "s3_pt_02_regsvr32_remote_sct", "title": "S3-C2: Equation Editor to regsvr32 remote SCT", "source_case": "s3_02_regsvr32_6124", "cluster": "S3-C2", "representative_alert_row": 21, "variant_selection_ids": ["S3-02", "S3-03", "S3-04"]},
    {"chain_id": "s3_pt_03_regsvr32_long_chain", "title": "S3-C3: regsvr32 to PowerShell/payload lineage", "source_case": "s3_05_regsvr32_3992", "cluster": "S3-C3", "representative_alert_row": 4, "variant_selection_ids": ["S3-05", "S3-06", "S3-07"]},
    {"chain_id": "s3_pt_04_powershell_mid_chain", "title": "S3-C3: PowerShell-centered descendant lineage", "source_case": "s3_08_powershell_2340", "cluster": "S3-C3", "representative_alert_row": 7, "variant_selection_ids": ["S3-08", "S3-09", "S3-10", "S3-11"]},
)


def build_gold(con: sqlite3.Connection, spec: dict) -> dict:
    alert_row = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (spec["alert_row_id"],)).fetchone()
    if alert_row is None:
        raise ValueError(f"Missing cbc_alerts row {spec['alert_row_id']}")
    start, end = window_for(alert_row["create_time_utc"])
    steps = []
    for order, (subject, action, object_, event_id, kind, note_ja) in enumerate(spec["steps"], start=1):
        steps.append(evidence_step(con, f"{spec['selection_id']}-S{order:02d}", order, subject, action, object_, event_id, kind, note_ja))
    for step in steps:
        event = step["canonical_evidence"][0]
        if not start <= event["timestamp_utc"] <= end:
            raise ValueError(f"{spec['selection_id']} has window-external evidence {event['source_row_id']}")
        if event["source_table"] != "cbc_events" or event["source_stream"] not in {"cbc-edr", "cbc-ngav"}:
            raise ValueError(f"{spec['selection_id']} has non-Stage-3 telemetry evidence")
    evidence_times = [step["canonical_evidence"][0]["timestamp_utc"] for step in steps]
    return {
        "chain_id": spec["case_id"], "selection_id": spec["selection_id"], "chain_title": f"{spec['selection_id']}: {alert_row['report_name']}",
        "case_group": "s3_cbc_attack_alert", "case_kind": spec["case_kind"], "alert_cluster_id": spec["cluster"],
        "independence_note": "One of 11 alert-target inputs from three overlapping S3 behavior clusters; do not treat this as an independent attack sample.",
        "source_database": str(DB.relative_to(ROOT)), "scenario": "atlasv2-attack-h1-s3", "chain_type": "cbc_alert_attack_behavior_reconstruction",
        "chain_description": spec["description"], "observed_behavior": spec["description"],
        "stage3_visibility_policy": "Gold steps use canonical cbc_events telemetry only. CBC alert summary fields, ATLAS scenario text, and process labels are not evidence for a Stage 3-scored claim.",
        "stages_present": ["stage1", "stage2", "stage3"],
        "input_scope": {"host": "WIN-32-H1", "focus_processes": [spec["focus"]], "chain_window_start_utc": start, "chain_window_end_utc": end, "window_minutes": 30, "window_selection_policy": "fixed_cbc_alert_create_time_plus_minus_15_minutes", "input_policy": "All stages receive host, focus process, and this fixed time range. Only Stage 1 additionally receives the selected CBC alert summary."},
        "input_alert_rows": [alert_visible(alert_row)], "canonical_input_alert": alert_canonical(alert_row),
        "alert_timing": {"alert_time_utc": alert_row["create_time_utc"], "investigation_window_start_utc": start, "investigation_window_end_utc": end, "telemetry_evidence_window_start_utc": min(evidence_times), "telemetry_evidence_window_end_utc": max(evidence_times), "note": "Fixed investigation window is [CBC alert create_time - 15 minutes, create_time + 15 minutes]."},
        "behavior_timeline": steps, "gold_steps": steps,
        "gold_order_pairs": [[steps[i]["step_id"], steps[i + 1]["step_id"]] for i in range(len(steps) - 1)],
        "evidence_span_utc": {"start": min(evidence_times), "end": max(evidence_times)},
        "limitations": spec["limitations"],
        "case_scoring": {"step_score_max": len(steps) * 4, "sequence_score_max": 3, "case_score_max": len(steps) * 4 + 3},
    }


def build_process_time_gold(con: sqlite3.Connection, source: dict, spec: dict) -> dict:
    """Materialize one non-duplicated Stage 2/3 scoring unit."""
    alert = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (spec["representative_alert_row"],)).fetchone()
    if alert is None:
        raise ValueError(f"Missing representative alert {spec['representative_alert_row']}")
    start, end = window_for(alert["create_time_utc"])
    gold = deepcopy(source)
    gold.update({
        "chain_id": spec["chain_id"], "chain_title": spec["title"], "selection_id": None,
        "case_group": "s3_unique_process_time", "case_kind": "unique_process_time_cluster",
        "alert_cluster_id": spec["cluster"], "evaluation_unit": "unique_process_time_cluster",
        "independence_note": "One unique process-time scoring input. Its listed alert variants are provenance only and are not separately scored in Stage 2/3.",
        "stages_present": ["stage2", "stage3"],
        "input_scope": {**gold["input_scope"], "chain_window_start_utc": start, "chain_window_end_utc": end, "input_policy": "Stage 2/3 receive only host, focus process, and the fixed time range. CBC alert summaries are not model input."},
        "process_time_provenance": {"representative_alert_row_id": alert["id"], "representative_alert_create_time_utc": alert["create_time_utc"], "variant_selection_ids": spec["variant_selection_ids"], "selection_note": "Representative alert fixes the shared time range only; its title, reason, command line, and PID are not Stage 2/3 model input."},
        "alert_timing": {"alert_time_utc": alert["create_time_utc"], "investigation_window_start_utc": start, "investigation_window_end_utc": end, "telemetry_evidence_window_start_utc": gold["evidence_span_utc"]["start"], "telemetry_evidence_window_end_utc": gold["evidence_span_utc"]["end"], "note": "Representative CBC alert create_time defines [−15 min, +15 min] for this unique process-time input."},
    })
    gold.pop("input_alert_rows", None)
    gold.pop("canonical_input_alert", None)
    for step in gold["gold_steps"]:
        event = step["canonical_evidence"][0]
        if not start <= event["timestamp_utc"] <= end:
            raise ValueError(f"{spec['chain_id']} has window-external evidence {event['source_row_id']}")
    return gold


def model_input(gold: dict, stage: str, number: int) -> dict:
    scope = gold["input_scope"]
    base = {"host": scope["host"], "focus_processes": scope["focus_processes"], "chain_window_start_utc": scope["chain_window_start_utc"], "chain_window_end_utc": scope["chain_window_end_utc"]}
    if stage == "stage1":
        base["cbc_alert"] = gold["input_alert_rows"][0]
    return {"input_id": f"atlasv2_s3_11_attack_{stage}_{number:03d}", "stage": stage, "input": base}


def case_row(gold: dict, gold_path: Path, stage: str, number: int, gold_root: Path) -> dict:
    scope = gold["input_scope"]
    anchor = gold["gold_steps"][0]["canonical_evidence"][0]
    ready = model_input(gold, stage, number)
    row = {
        "instance_id": f"{gold['chain_id']}_{stage}", "case_id": f"{gold['chain_id']}_{stage}", "input_id": ready["input_id"], "stage": stage,
        "scenario": gold["scenario"], "database": gold["source_database"], "host": scope["host"], "process_name": "; ".join(scope["focus_processes"]), "actor": "; ".join(scope["focus_processes"]),
        "expected_behavior": gold["observed_behavior"], "expected_behavior_category": gold["chain_type"], "context_label": gold["case_kind"], "suite_group": "s3_cbc_attack_alert", "difficulty": "alert_input" if stage == "stage1" else "process_time",
        "time_window_utc": {"episode_start": scope["chain_window_start_utc"], "episode_end": scope["chain_window_end_utc"], "analysis_scope": "Hard scope: CBC alert create_time ±15 minutes; runner enforces this range in SQL."},
        "enforce_time_scope": True,
        "investigation_time_anchor_utc": gold["alert_timing"]["alert_time_utc"],
        "investigation_time_anchor_policy": "Selected CBC alert create_time. This is an input time hint, not a Gold telemetry event.",
        "anchor_event": {"source_stream": anchor["source_stream"], "source_table": anchor["source_table"], "source_row_id": anchor["source_row_id"], "timestamp_utc": anchor["timestamp_utc"], "process_name": anchor["process_path"], "process_path": anchor["process_path"], "process_cmdline": anchor["process_cmdline"], "parent_path": anchor["parent_path"], "action": anchor["action"]},
        "input_alert_rows": gold.get("input_alert_rows", []) if stage == "stage1" else [], "model_ready_input": ready,
        "gold_chain_file": str(gold_path.relative_to(gold_root)), "chain_id": gold["chain_id"], "chain_type": gold["chain_type"], "formal_gold_root": str(gold_root.relative_to(ROOT)),
        "stage_input_policy": {"stage1": "Selected CBC alert summary is visible as the initial clue.", "stage2": "Only host/process/time are provided; CBC alert summary rows remain searchable in the full database.", "stage3": "Only host/process/time are provided; runner must hide CBC alert summary rows while retaining CBC telemetry."}[stage],
    }
    if stage == "stage1":
        row["stage1_answerable_policy"] = "The selected CBC alert is visible. Ground truth, scenario narrative, and gold behavior are excluded from model input."
    else:
        row["stage23_answerable_policy"] = "CBC alert fields are excluded from the model input. Gold is based only on canonical CBC telemetry events."
    return row


def audit_cases(gold_paths: list[Path], case_paths: dict[str, Path], out: Path) -> dict:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    rows: list[dict] = []
    prohibited_stage3 = ("alert_id", "alert_name", "alert_reason", "report_name", "ground_truth", "atlasv2_labels", "s-3.txt")
    for path in gold_paths:
        gold = json.loads(path.read_text(encoding="utf-8"))
        start, end = gold["input_scope"]["chain_window_start_utc"], gold["input_scope"]["chain_window_end_utc"]
        if gold.get("canonical_input_alert"):
            alert = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (gold["canonical_input_alert"]["source_row_id"],)).fetchone()
            alert_ok = alert is not None and all(gold["canonical_input_alert"].get(field) == alert[field] for field in ALERT_FIELDS)
            rows.append({"case_id": gold["chain_id"], "check": "canonical_alert_identity", "status": "pass" if alert_ok else "fail", "detail": str(gold["canonical_input_alert"]["source_row_id"])})
        else:
            provenance = gold["process_time_provenance"]
            alert = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (provenance["representative_alert_row_id"],)).fetchone()
            rows.append({"case_id": gold["chain_id"], "check": "representative_alert_identity", "status": "pass" if alert is not None and alert["create_time_utc"] == provenance["representative_alert_create_time_utc"] else "fail", "detail": str(provenance["representative_alert_row_id"])})
        rows.append({"case_id": gold["chain_id"], "check": "fixed_30_min_window", "status": "pass" if (end == iso(parse_time(alert["create_time_utc"]) + timedelta(minutes=15)) and start == iso(parse_time(alert["create_time_utc"]) - timedelta(minutes=15))) else "fail", "detail": f"{start} .. {end}"})
        seen: set[int] = set()
        last_time = ""
        for step in gold["gold_steps"]:
            event = step["canonical_evidence"][0]
            db_event = con.execute("SELECT * FROM cbc_events WHERE id = ?", (event["source_row_id"],)).fetchone()
            ok = db_event is not None and event["source_table"] == "cbc_events" and start <= event["timestamp_utc"] <= end and event["source_row_id"] not in seen and all(event.get(field) == db_event[field] for field in EVENT_FIELDS) and (not last_time or event["timestamp_utc"] >= last_time)
            rows.append({"case_id": gold["chain_id"], "check": "gold_event", "status": "pass" if ok else "fail", "detail": f"{step['step_id']} row={event['source_row_id']} kind={step['evidence_kind']}"})
            seen.add(event["source_row_id"]); last_time = event["timestamp_utc"]
        if gold["selection_id"] == "S3-01":
            word_ok = all("eqnedt" not in json.dumps(step, ensure_ascii=False).lower() and "regsvr32" not in json.dumps(step, ensure_ascii=False).lower() for step in gold["gold_steps"])
            rows.append({"case_id": gold["chain_id"], "check": "word_boundary_no_unobserved_downstream_edge", "status": "pass" if word_ok else "fail", "detail": "Word gold contains no Equation Editor/regsvr32 claim."})
    for stage, path in case_paths.items():
        inputs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        expected_input_count = 11 if stage == "stage1" else 4
        rows.append({"case_id": stage, "check": "input_count", "status": "pass" if len(inputs) == expected_input_count else "fail", "detail": str(len(inputs))})
        for item in inputs:
            visible = json.dumps(item["model_ready_input"], ensure_ascii=False).lower()
            expected_time = next(g["alert_timing"]["alert_time_utc"] for g in (json.loads(p.read_text(encoding="utf-8")) for p in gold_paths) if g["chain_id"] == item["chain_id"])
            time_anchor_ok = item.get("investigation_time_anchor_utc") == expected_time
            rows.append({"case_id": item["case_id"], "check": "selected_alert_time_anchor", "status": "pass" if time_anchor_ok else "fail", "detail": str(item.get("investigation_time_anchor_utc"))})
            if stage == "stage3":
                bad = [term for term in prohibited_stage3 if term in visible]
                ok = not bad and item["input_alert_rows"] == [] and set(item["model_ready_input"]["input"]) == {"host", "focus_processes", "chain_window_start_utc", "chain_window_end_utc"}
                rows.append({"case_id": item["case_id"], "check": "stage3_no_alert_summary_input", "status": "pass" if ok else "fail", "detail": ", ".join(bad) or "clean"})
            elif stage == "stage2":
                ok = item["input_alert_rows"] == [] and "cbc_alert" not in item["model_ready_input"]["input"]
                rows.append({"case_id": item["case_id"], "check": "stage2_no_alert_summary_input", "status": "pass" if ok else "fail", "detail": "no visible alert"})
            else:
                ok = len(item["input_alert_rows"]) == 1 and "cbc_alert" in item["model_ready_input"]["input"]
                rows.append({"case_id": item["case_id"], "check": "stage1_visible_selected_alert", "status": "pass" if ok else "fail", "detail": "one visible alert"})
    con.close()
    failed = [row for row in rows if row["status"] != "pass"]
    result = {"status": "passed" if not failed else "failed", "gold_case_count": len(gold_paths), "stage_input_count": {stage: len([json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]) for stage, path in case_paths.items()}, "checks": len(rows), "passed_checks": len(rows) - len(failed), "failed_checks": len(failed), "rows": rows, "notes": ["This preflight validates asset identity and input visibility. It does not run a model.", "The execution runner must enforce the declared 30-minute scope in SQL/adapter data and hide CBC alert summaries for Stage 3."]}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DB)
    parser.add_argument("--gold-root", type=Path, default=OUT_GOLD)
    parser.add_argument("--cases-dir", type=Path, default=OUT_CASES)
    parser.add_argument("--validation", type=Path, default=OUT_VALIDATION)
    args = parser.parse_args()
    if args.db.resolve() != DB.resolve():
        raise ValueError("This builder is intentionally fixed to the selected ATLASv2 H1/S3 database.")
    args.gold_root.mkdir(parents=True, exist_ok=True)
    (args.gold_root / "by_chain").mkdir(exist_ok=True)
    process_time_gold_root = OUT_PROCESS_TIME_GOLD
    process_time_gold_root.mkdir(parents=True, exist_ok=True)
    (process_time_gold_root / "by_chain").mkdir(exist_ok=True)
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
    gold_paths: list[Path] = []
    index = []
    for spec in SPECS:
        gold = build_gold(con, spec)
        target = args.gold_root / "by_chain" / gold["chain_id"]
        target.mkdir(parents=True, exist_ok=True)
        path = target / "chain_gold.json"
        path.write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        gold_paths.append(path)
        index.append({"selection_id": gold["selection_id"], "chain_id": gold["chain_id"], "alert_row_id": gold["canonical_input_alert"]["source_row_id"], "alert_cluster_id": gold["alert_cluster_id"], "case_kind": gold["case_kind"], "gold_chain_file": str(path.relative_to(args.gold_root))})
    stage1_gold_by_id = {json.loads(path.read_text(encoding="utf-8"))["chain_id"]: path for path in gold_paths}
    process_time_paths: list[Path] = []
    process_time_index = []
    for spec in PROCESS_TIME_SPECS:
        source = json.loads(stage1_gold_by_id[spec["source_case"]].read_text(encoding="utf-8"))
        gold = build_process_time_gold(con, source, spec)
        target = process_time_gold_root / "by_chain" / gold["chain_id"]
        target.mkdir(parents=True, exist_ok=True)
        path = target / "chain_gold.json"
        path.write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        process_time_paths.append(path)
        process_time_index.append({"chain_id": gold["chain_id"], "alert_cluster_id": gold["alert_cluster_id"], "representative_alert_row_id": gold["process_time_provenance"]["representative_alert_row_id"], "alert_variant_selection_ids": gold["process_time_provenance"]["variant_selection_ids"], "gold_chain_file": str(path.relative_to(process_time_gold_root))})
    con.close()
    (args.gold_root / "chain_gold_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (process_time_gold_root / "chain_gold_index.json").write_text(json.dumps(process_time_index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.gold_root / "README.md").write_text("# ATLASv2 S3: 11 CBC-alert attack inputs\n\nEach alert target is a separate input, but the 11 inputs cover only three overlapping S3 behavior clusters. All Gold claims are linked to one canonical `cbc_events` telemetry row per step. The fixed scope is `[CBC alert create_time - 15 min, +15 min]`. The Word boundary case deliberately does not connect Word to the later Equation Editor/regsvr32 sequence.\n", encoding="utf-8")
    (process_time_gold_root / "README.md").write_text("# ATLASv2 S3: four unique process-time Gold units\n\nStage 2/3 contain four unique process-time inputs. Alert variants that share a process-time scope are retained only as provenance and are not separately scored.\n", encoding="utf-8")
    args.cases_dir.mkdir(parents=True, exist_ok=True)
    case_paths: dict[str, Path] = {}
    for stage in ("stage1", "stage2", "stage3"):
        selected_paths, selected_gold_root = (gold_paths, args.gold_root) if stage == "stage1" else (process_time_paths, process_time_gold_root)
        rows = [case_row(json.loads(path.read_text(encoding="utf-8")), path, stage, number, selected_gold_root) for number, path in enumerate(selected_paths, start=1)]
        output = args.cases_dir / f"atlasv2_s3_{'11_cbc_alert' if stage == 'stage1' else '4_process_time'}_{stage}_cases_20260723.jsonl"
        output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
        case_paths[stage] = output
    validation = audit_cases([*gold_paths, *process_time_paths], case_paths, args.validation)
    manifest = {"suite": "ATLASv2 H1/S3 CBC-alert attack reconstruction", "gold_case_count": {"stage1_alert_target": len(gold_paths), "stage2_stage3_unique_process_time": len(process_time_paths)}, "input_count_by_stage": {"stage1": 11, "stage2": 4, "stage3": 4}, "total_model_inputs": 19, "fixed_investigation_window_policy": "[CBC alert create_time - 15 minutes, create_time + 15 minutes] for every case; SQL access is hard-scoped by the runner.", "independence_note": "Stage 1 measures 11 alert-target inputs. Stage 2/3 measure four unique process-time inputs: alert variants with the same process-time scope are provenance only and are not separately scored.", "stage_conditions": {"stage1": "visible selected alert summary + host/process/time", "stage2": "host/process/time only; full DB alert summaries remain in the hard-scoped range", "stage3": "host/process/time only; runner must hard-scope time and hide CBC alert summaries while retaining CBC event telemetry"}, "validation": str(args.validation.relative_to(ROOT))}
    manifest_path = args.cases_dir / "atlasv2_s3_11_cbc_attack_stage_cases_20260723_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stage1_gold_cases": len(gold_paths), "process_time_gold_cases": len(process_time_paths), "stage_files": {key: str(value.relative_to(ROOT)) for key, value in case_paths.items()}, "validation": validation["status"], "checks": validation["checks"]}, ensure_ascii=False))
    if validation["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
