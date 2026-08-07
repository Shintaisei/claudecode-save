"""Build a strict ground-truth-labelled CBC-alert 10-input suite.

Five inputs start from alerts whose target process is labelled attack in the
ATLASv2 process ground truth.  Five start from alerts whose target process is
labelled benign.  The latter retain the same-host, later attack evidence as a
separate sequence: alert disposition and host disposition must not be merged.
"""

from __future__ import annotations

import copy
import csv
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from build_s3_attack_behavior_gold import canonical_record, sample_log, score_template


ROOT = Path(__file__).resolve().parents[2]
S3_DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db"
S4_DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s4/incident.db"
S3_ALERT_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s3_alert_origin_behavior_chain_gold/by_chain"
OUT_GOLD = ROOT / "data/current_experiment/gold/atlasv2_tp5_fp5_cbc_alert_gold"
OUT_CASES = ROOT / "data/current_experiment/cases/atlasv2_tp5_fp5_cbc_alert_stage1_cases_20260720.jsonl"
OUT_MANIFEST = ROOT / "data/current_experiment/cases/atlasv2_tp5_fp5_cbc_alert_stage1_cases_20260720_manifest.json"
OUT_VALIDATION = ROOT / "docs/current_experiment/atlasv2_tp5_fp5_cbc_alert_validation_20260720.json"
LABELS_CSV = ROOT / "external/reapr-ground-truth/atlasv2/atlasv2_labels.csv"

IMMUTABLE_FIELDS = (
    "timestamp_utc", "action", "process_path", "process_pid", "parent_path", "parent_pid",
    "process_cmdline", "object_name", "remote_ip", "remote_port", "netconn_domain",
    "childproc_name", "childproc_pid",
)
ALERT_IMMUTABLE_FIELDS = (
    "create_time_utc", "stream_name", "alert_id", "type", "severity", "category", "reason", "reason_code",
    "process_name", "threat_cause_actor_name", "created_by_event_id", "device_name", "process_path", "process_pid",
    "process_cmdline", "parent_path", "parent_pid", "parent_cmdline", "report_name", "report_tags",
)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def alert_scope(alert_time: str) -> tuple[str, str]:
    """Use one fixed policy for both TP and FP alert inputs."""
    moment = parse_time(alert_time)
    return iso(moment - timedelta(minutes=6)), iso(moment + timedelta(minutes=10))


def evidence_span(steps: list[dict]) -> tuple[str, str]:
    times = [step["canonical_evidence"][0]["timestamp_utc"] for step in steps]
    return min(times), max(times)


def alert_payload(con: sqlite3.Connection, alert_id: int) -> dict:
    row = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise ValueError(f"Missing cbc_alerts row {alert_id}")
    return {
        "source_row_id": row["id"],
        "time": row["create_time_utc"],
        "alert_id": row["alert_id"],
        "alert_name": row["report_name"],
        "alert_reason": row["reason"],
        "process": row["process_path"],
        "pid": row["process_pid"],
        "source_stream": row["stream_name"],
        "severity": row["severity"],
    }


def canonical_alert(con: sqlite3.Connection, alert_id: int) -> dict:
    row = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise ValueError(f"Missing cbc_alerts row {alert_id}")
    return {"source_table": "cbc_alerts", "source_row_id": row["id"], **{field: row[field] for field in ALERT_IMMUTABLE_FIELDS}}


def ground_truth_labels() -> dict[tuple[str, int, str], str]:
    labels: dict[tuple[str, int, str], str] = {}
    with LABELS_CSV.open(encoding="utf-8-sig", newline="") as handle:
        for raw in csv.DictReader(handle):
            row = {key.strip(): value.strip() for key, value in raw.items() if key is not None and value is not None}
            labels[(row["attack"], int(row["process_id"]), row["process_name"].lower())] = row["label"]
    return labels


def scenario_label_key(scenario: str) -> str:
    suffix = scenario.removeprefix("atlasv2-attack-")
    return f"atlasv2/{suffix}"


def evidence_step(con: sqlite3.Connection, step_id: str, order: int, subject: str, action: str, object_: str, row_id: int, segment: str) -> dict:
    evidence = canonical_record(con, row_id)
    return {
        "step_id": step_id,
        "order": order,
        "subject": subject,
        "action": action,
        "object": object_,
        "segment": segment,
        "evidence_basis": "Canonical CBC EDR event row",
        "confidence": "observed",
        "process_code_object": object_,
        "scoring_template": score_template(),
        "canonical_evidence": [evidence],
        "supporting_evidence": {"source_types": ["CBC event"], "sample_logs": [sample_log(evidence)]},
    }


def base_gold(chain_id: str, title: str, db: Path, scenario: str, group: str, verdict: str, alert: dict, canonical: dict, host: str, focus: str, start: str, end: str, steps: list[dict], cluster: str, episode: str, nested: bool, description: str) -> dict:
    pairs = [
        [steps[i]["step_id"], steps[i + 1]["step_id"]]
        for i in range(len(steps) - 1)
        if steps[i]["segment"] == steps[i + 1]["segment"]
    ]
    alert_disposition = "escalate_alert" if verdict == "true_positive" else "close_alert"
    host_disposition = "escalate_host_investigation"
    decision_scoring = {
        "required_output_path": "triage_decision",
        "alert_disposition": {"expected": alert_disposition, "score_max": 1},
        "host_disposition": {"expected": host_disposition, "score_max": 1},
    }
    return {
        "chain_id": chain_id,
        "chain_title": title,
        "case_group": group,
        "suite_group": group,
        "source_database": str(db.relative_to(ROOT)),
        "scenario": scenario,
        "chain_type": "cbc_alert_triage_with_behavior_reconstruction",
        "chain_description": description,
        "observed_behavior": description,
        "stages_present": ["stage1"],
        "input_scope": {
            "host": host,
            "focus_processes": [focus],
            "chain_window_start_utc": start,
            "chain_window_end_utc": end,
            "input_policy": "Stage 1 receives one visible CBC alert and the declared host/time scope. Ground-truth labels and gold behavior are excluded.",
        },
        "evaluation_mode": "false_positive_alert_near_attack" if verdict == "false_positive" else "standard_reconstruction",
        "alert_ground_truth": {
            "verdict": verdict,
            "label_scope": "ATLASv2 process-level ground truth for the alert target process",
            "required_alert_disposition": alert_disposition,
            "required_host_disposition": host_disposition,
            "rationale": "The alert target process is labelled attack." if verdict == "true_positive" else "The alert target process is labelled benign; the alert's claimed technique is not an attack action in this scenario.",
        },
        "input_alert_rows": [alert],
        "canonical_input_alert": canonical,
        "alert_timing": {
            "alert_time_utc": alert["time"],
            "investigation_window_start_utc": start,
            "investigation_window_end_utc": end,
            "telemetry_evidence_window_start_utc": evidence_span(steps)[0],
            "telemetry_evidence_window_end_utc": evidence_span(steps)[1],
            "alert_created_after_telemetry_evidence": alert["time"] > evidence_span(steps)[1],
            "note": "All inputs use [alert time - 6 min, alert time + 10 min]. CBC alert creation time and telemetry evidence span are recorded separately because alert generation can lag telemetry.",
        },
        "alert_cluster_id": cluster,
        "incident_episode_id": episode,
        "is_nested_anchor": nested,
        "behavior_timeline": steps,
        "gold_steps": steps,
        "gold_order_pairs": pairs,
        "limitations": [
            "Alert-level verdict and host-level disposition are scored separately.",
            "A separate attack sequence in the same host/time scope is not a causal continuation unless an observed edge connects it.",
        ],
        "decision_scoring": decision_scoring,
        "case_scoring": {"step_score_max": len(steps) * 4, "sequence_score_max": 3, "decision_score_max": 2, "case_score_max": len(steps) * 4 + 5},
    }


def copy_s3_tp(source_id: str, chain_id: str, alert_id: int, cluster: str, nested: bool) -> dict:
    source = S3_ALERT_GOLD / source_id / "chain_gold.json"
    gold = copy.deepcopy(json.loads(source.read_text(encoding="utf-8")))
    con = sqlite3.connect(S3_DB)
    con.row_factory = sqlite3.Row
    alert = alert_payload(con, alert_id)
    canonical = canonical_alert(con, alert_id)
    con.close()
    gold["chain_id"] = chain_id
    gold["chain_title"] = f"True-positive CBC alert {alert_id}: {alert['alert_name']}"
    gold["case_group"] = "true_positive_alert"
    gold["suite_group"] = "true_positive_alert"
    gold["source_database"] = str(S3_DB.relative_to(ROOT))
    gold["scenario"] = "atlasv2-attack-h1-s3"
    gold["stages_present"] = ["stage1"]
    start, end = alert_scope(alert["time"])
    gold["input_scope"]["chain_window_start_utc"] = start
    gold["input_scope"]["chain_window_end_utc"] = end
    gold["input_scope"]["window_minutes"] = 16
    gold["input_scope"]["window_selection_policy"] = "fixed_alert_time_minus6_plus10"
    gold["input_scope"]["input_policy"] = "Stage 1 receives the visible seed CBC alert, host, alerted executable, and the mechanically normalized evidence window. Ground truth and gold behavior are excluded."
    gold["input_alert_rows"] = [alert]
    gold["canonical_input_alert"] = canonical
    gold["evaluation_mode"] = "standard_reconstruction"
    gold["alert_ground_truth"] = {
        "verdict": "true_positive",
        "label_scope": "ATLASv2 process-level ground truth for the alert target process",
        "required_alert_disposition": "escalate_alert",
        "required_host_disposition": "escalate_host_investigation",
        "rationale": "The alert target process is labelled attack and the gold sequence contains direct attack evidence.",
    }
    gold["decision_scoring"] = {
        "required_output_path": "triage_decision",
        "alert_disposition": {"expected": "escalate_alert", "score_max": 1},
        "host_disposition": {"expected": "escalate_host_investigation", "score_max": 1},
    }
    gold["case_scoring"]["decision_score_max"] = 2
    gold["case_scoring"]["case_score_max"] = gold["case_scoring"]["step_score_max"] + gold["case_scoring"].get("sequence_score_max", 0) + 2
    gold["alert_timing"] = {
        "alert_time_utc": alert["time"],
        "investigation_window_start_utc": start,
        "investigation_window_end_utc": end,
        "telemetry_evidence_window_start_utc": evidence_span(gold["gold_steps"])[0],
        "telemetry_evidence_window_end_utc": evidence_span(gold["gold_steps"])[1],
        "alert_created_after_telemetry_evidence": alert["time"] > evidence_span(gold["gold_steps"])[1],
        "note": "All inputs use [alert time - 6 min, alert time + 10 min]. CBC alert creation time and telemetry evidence span are recorded separately because alert generation can lag telemetry.",
    }
    gold["alert_cluster_id"] = cluster
    gold["incident_episode_id"] = "s3_malicious_document_compromise"
    gold["is_nested_anchor"] = nested
    return gold


def s4_tp_cases() -> list[dict]:
    con = sqlite3.connect(S4_DB)
    con.row_factory = sqlite3.Row
    common = [
        ("mshta.exe (PID 4724)", "started", "powershell.exe (PID 2976)", 3640),
        ("powershell.exe (PID 2976)", "started", "powershell.exe (PID 3820)", 3793),
        ("powershell.exe (PID 3820)", "initiated connection", "10.193.66.115:8443", 12843),
        ("powershell.exe (PID 3820)", "started", "cmd.exe (PID 2168)", 13141),
    ]
    specs = [
        ("tp_04_s4_mshta_script_interpreter", 18, "mshta.exe", common, "s4_mshta_powershell", False),
        ("tp_05_s4_powershell_hidden_encoded", 16, "powershell.exe", common[0:], "s4_mshta_powershell", True),
    ]
    result = []
    for chain_id, alert_id, focus, rows, cluster, nested in specs:
        steps = [evidence_step(con, f"{chain_id}-S{i:02d}", i, *row, "alert_chain") for i, row in enumerate(rows, 1)]
        alert = alert_payload(con, alert_id)
        canonical = canonical_alert(con, alert_id)
        start, end = alert_scope(alert["time"])
        result.append(base_gold(
            chain_id, f"True-positive CBC alert {alert_id}: {alert['alert_name']}", S4_DB,
            "atlasv2-attack-h1-s4", "true_positive_alert", "true_positive", alert, canonical,
            "WIN-32-H1", focus, start, end, steps, cluster, "s4_word_hta_compromise", nested,
            "CBC telemetry shows the mshta-to-PowerShell execution chain, a connection, and command-shell execution.",
        ))
    con.close()
    return result


def s3_fp_cases() -> list[dict]:
    con = sqlite3.connect(S3_DB)
    con.row_factory = sqlite3.Row
    attack_rows = [
        ("svchost.exe (PID 648)", "started", "EQNEDT32.EXE (PID 6032)", 7814),
        ("EQNEDT32.EXE (PID 6032)", "started", "regsvr32.exe (PID 6124)", 7829),
        ("regsvr32.exe (PID 6124)", "initiated connection", "ortrta.net / 10.193.66.115:8080", 7889),
    ]
    specs = [
        ("fp_01_s3_llmnr_svchost", 2, "svchost.exe", [("svchost.exe (PID 1212)", "initiated multicast connection", "224.0.0.252:5355", 11138)], "s3_benign_llmnr", False),
        ("fp_02_s3_cmd_dns_logging", 3, "cmd.exe", [("explorer.exe (PID 1604)", "started", "cmd.exe (PID 960)", 10952), ("start_dns_logs.bat (PID 960)", "started", "tshark.exe (PID 1388)", 21259)], "s3_dns_capture_startup", False),
        ("fp_03_s3_dumpcap_capture", 10, "dumpcap.exe", [("tshark.exe (PID 1388)", "started", "dumpcap.exe (PID 1300)", 21320)], "s3_dns_capture_startup", True),
        ("fp_04_s3_tshark_capture", 13, "tshark.exe", [("start_dns_logs.bat (PID 960)", "started", "tshark.exe (PID 1388)", 21259), ("tshark.exe (PID 1388)", "started", "dumpcap.exe (PID 1300)", 21320)], "s3_dns_capture_startup", True),
        ("fp_05_s3_dumpcap_interface_list", 14, "dumpcap.exe", [("tshark.exe (PID 1388)", "started", "dumpcap.exe (PID 2868)", 11150)], "s3_dns_capture_startup", True),
    ]
    result = []
    for chain_id, alert_id, focus, local_rows, cluster, nested in specs:
        rows = [(row, "alert_local") for row in local_rows] + [(row, "separate_attack") for row in attack_rows]
        steps = [evidence_step(con, f"{chain_id}-S{i:02d}", i, *row, segment) for i, (row, segment) in enumerate(rows, 1)]
        alert = alert_payload(con, alert_id)
        canonical = canonical_alert(con, alert_id)
        start, end = alert_scope(alert["time"])
        result.append(base_gold(
            chain_id, f"False-positive CBC alert {alert_id}: {alert['alert_name']}", S3_DB,
            "atlasv2-attack-h1-s3", "false_positive_alert", "false_positive", alert, canonical,
            "WIN-32-H1", focus, start, end, steps, cluster, "s3_benign_alert_then_compromise", nested,
            "The alerted process is benign and its local CBC evidence explains the alert. Later in the same host scope, a separate Equation Editor-to-regsvr32 sequence is observed.",
        ))
    con.close()
    return result


def validate(gold_paths: list[Path]) -> dict:
    outcomes = []
    labels = ground_truth_labels()
    for path in gold_paths:
        gold = json.loads(path.read_text(encoding="utf-8"))
        con = sqlite3.connect(ROOT / gold["source_database"])
        con.row_factory = sqlite3.Row
        start = gold["input_scope"]["chain_window_start_utc"]
        end = gold["input_scope"]["chain_window_end_utc"]
        alert = gold["input_alert_rows"][0]
        arow = con.execute("SELECT * FROM cbc_alerts WHERE id = ?", (alert["source_row_id"],)).fetchone()
        canonical = gold["canonical_input_alert"]
        alert_ok = (
            arow is not None
            and canonical["source_table"] == "cbc_alerts"
            and canonical["source_row_id"] == arow["id"]
            and all(canonical.get(field) == arow[field] for field in ALERT_IMMUTABLE_FIELDS)
        )
        outcomes.append({"chain_id": gold["chain_id"], "kind": "alert", "row_id": alert["source_row_id"], "status": "pass" if alert_ok else "fail"})
        scenario = scenario_label_key(gold["scenario"])
        gt_key = (scenario, int(arow["process_pid"]), str(arow["process_path"]).lower()) if arow is not None else None
        gt_label = labels.get(gt_key) if gt_key else None
        expected_label = "attack" if gold["alert_ground_truth"]["verdict"] == "true_positive" else "benign"
        gt_ok = gt_label == expected_label
        outcomes.append({
            "chain_id": gold["chain_id"], "kind": "ground_truth_label", "row_id": alert["source_row_id"],
            "ground_truth_source": str(LABELS_CSV.relative_to(ROOT)),
            "matched_scenario": gt_key[0] if gt_key else None,
            "matched_pid": gt_key[1] if gt_key else None,
            "matched_process_path": gt_key[2] if gt_key else None,
            "expected": expected_label, "actual": gt_label, "status": "pass" if gt_ok else "fail",
        })
        decision = gold.get("decision_scoring", {})
        decision_ok = (
            decision.get("required_output_path") == "triage_decision"
            and decision.get("alert_disposition", {}).get("expected") == gold["alert_ground_truth"]["required_alert_disposition"]
            and decision.get("host_disposition", {}).get("expected") == gold["alert_ground_truth"]["required_host_disposition"]
            and gold.get("case_scoring", {}).get("decision_score_max") == 2
        )
        outcomes.append({"chain_id": gold["chain_id"], "kind": "decision_scoring", "row_id": alert["source_row_id"], "status": "pass" if decision_ok else "fail"})
        timing = gold.get("alert_timing", {})
        expected_start, expected_end = alert_scope(alert["time"])
        observed_start, observed_end = evidence_span(gold["gold_steps"])
        timing_ok = (
            timing.get("alert_time_utc") == alert["time"]
            and start == expected_start and end == expected_end
            and timing.get("investigation_window_start_utc") == expected_start
            and timing.get("investigation_window_end_utc") == expected_end
            and timing.get("telemetry_evidence_window_start_utc") == observed_start
            and timing.get("telemetry_evidence_window_end_utc") == observed_end
        )
        outcomes.append({"chain_id": gold["chain_id"], "kind": "alert_timing", "row_id": alert["source_row_id"], "status": "pass" if timing_ok else "fail"})
        for item in gold["gold_steps"]:
            evidence = item["canonical_evidence"][0]
            row = con.execute("SELECT * FROM cbc_events WHERE id = ?", (evidence["source_row_id"],)).fetchone()
            ok = row is not None and evidence["source_table"] == "cbc_events" and start <= row["timestamp_utc"] <= end
            if row is not None:
                ok = ok and all(evidence.get(field) == row[field] for field in IMMUTABLE_FIELDS)
            outcomes.append({"chain_id": gold["chain_id"], "kind": "evidence", "row_id": evidence["source_row_id"], "status": "pass" if ok else "fail"})
        con.close()
    return {"status": "passed" if all(item["status"] == "pass" for item in outcomes) else "failed", "chain_count": len(gold_paths), "checked_items": len(outcomes), "passed_items": sum(item["status"] == "pass" for item in outcomes), "rows": outcomes}


def case_row(number: int, gold: dict, path: Path) -> dict:
    scope = gold["input_scope"]
    alert = gold["input_alert_rows"][0]
    anchor = gold["gold_steps"][0]["canonical_evidence"][0]
    return {
        "instance_id": f"{gold['chain_id']}_stage1",
        "case_id": f"{gold['chain_id']}_stage1",
        "input_id": f"atlasv2_tp_fp_alert10_input_{number:03d}",
        "stage": "stage1",
        "scenario": gold["scenario"],
        "database": gold["source_database"],
        "host": scope["host"],
        "process_name": "; ".join(scope["focus_processes"]),
        "actor": "; ".join(scope["focus_processes"]),
        "expected_behavior": gold["observed_behavior"],
        "expected_behavior_category": gold["chain_type"],
        "context_label": gold["case_group"],
        "suite_group": gold["suite_group"],
        "evaluation_mode": gold["evaluation_mode"],
        "difficulty": "alert_input",
        "time_window_utc": {"episode_start": scope["chain_window_start_utc"], "episode_end": scope["chain_window_end_utc"], "analysis_scope": "CBC alert centred investigation window"},
        "anchor_event": {
            "source_stream": anchor["source_stream"], "source_table": anchor["source_table"], "source_row_id": anchor["source_row_id"],
            "timestamp_utc": anchor["timestamp_utc"], "process_name": anchor["process_path"], "process_path": anchor["process_path"],
            "process_cmdline": anchor["process_cmdline"], "parent_path": anchor["parent_path"], "action": anchor["action"],
        },
        "input_alert_rows": gold["input_alert_rows"],
        "model_ready_input": {"input_id": f"atlasv2_tp_fp_alert10_input_{number:03d}", "stage": "stage1", "input": {"host": scope["host"], "focus_processes": scope["focus_processes"], "chain_window_start_utc": scope["chain_window_start_utc"], "chain_window_end_utc": scope["chain_window_end_utc"], "cbc_alert": alert}},
        "gold_chain_file": str(path.relative_to(OUT_GOLD)),
        "chain_id": gold["chain_id"],
        "chain_type": gold["chain_type"],
        "formal_gold_root": str(OUT_GOLD.relative_to(ROOT)),
        "alert_ground_truth": gold["alert_ground_truth"],
        "decision_scoring": gold["decision_scoring"],
        "alert_timing": gold["alert_timing"],
        "alert_cluster_id": gold["alert_cluster_id"],
        "incident_episode_id": gold["incident_episode_id"],
        "is_nested_anchor": gold["is_nested_anchor"],
        "stage1_answerable_policy": "The input CBC alert is visible. Ground-truth labels, gold behavior, and ATLAS scenario descriptions are excluded from model input.",
    }


def main() -> None:
    if OUT_GOLD.exists():
        shutil.rmtree(OUT_GOLD)
    (OUT_GOLD / "by_chain").mkdir(parents=True)
    golds = [
        copy_s3_tp("s3_alert_origin_02_regsvr32_remote_sct", "tp_01_s3_regsvr32_remote_sct", 21, "s3_regsvr32_6124", False),
        copy_s3_tp("s3_alert_origin_03_regsvr32_powershell", "tp_02_s3_regsvr32_powershell", 4, "s3_regsvr32_3992_powershell", False),
        copy_s3_tp("s3_alert_origin_04_powershell_descendant_execution", "tp_03_s3_powershell_iex", 7, "s3_regsvr32_3992_powershell", True),
        *s4_tp_cases(),
        *s3_fp_cases(),
    ]
    paths = []
    for gold in golds:
        target = OUT_GOLD / "by_chain" / gold["chain_id"]
        target.mkdir()
        path = target / "chain_gold.json"
        path.write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    validation = validate(paths)
    OUT_VALIDATION.parent.mkdir(parents=True, exist_ok=True)
    OUT_VALIDATION.write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if validation["status"] != "passed":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
    cases = [case_row(i, json.loads(path.read_text(encoding="utf-8")), path) for i, path in enumerate(paths, 1)]
    OUT_CASES.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in cases), encoding="utf-8")
    fp_cases = [row for row in cases if row["alert_ground_truth"]["verdict"] == "false_positive"]
    fp_unique_alert_ids = {row["input_alert_rows"][0]["alert_id"] for row in fp_cases}
    manifest = {
        "stage": "stage1",
        "true_positive_alert_input_count": 5,
        "false_positive_alert_input_count": 5,
        "suite_input_count": 10,
        "truth_label_scope": "ATLASv2 process-level ground truth for the CBC alert target process",
        "independence_note": "The suite has 10 alert-target-row inputs, not 10 independent incidents. TP02/TP03 and TP04/TP05 are nested alert anchors; FP02-FP05 share the DNS-capture startup cluster.",
        "false_positive_input_count": len(fp_cases),
        "false_positive_unique_cbc_alert_id_count": len(fp_unique_alert_ids),
        "false_positive_alert_identity_note": "FP01 and FP02 have distinct CBC alert identities; FP03-FP05 are three target-process rows under one packet-capture CBC alert identity. Thus five FP inputs represent three unique CBC alert identities.",
        "fixed_investigation_window_policy": "All TP and FP inputs use [CBC alert create_time - 6 minutes, create_time + 10 minutes] (16 minutes). Do not compare this suite's time/cost directly with prior five-minute Stage 3 results.",
        "false_positive_scope_note": "FP inputs are benign-target alerts. After the fixed 16-minute host scan, the alert technique can be closed while a later, separately scored attack sequence requires host escalation; this does not establish causality.",
        "validation": str(OUT_VALIDATION.relative_to(ROOT)),
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"gold_cases": len(paths), "validation": validation["status"], "checked_items": validation["passed_items"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
