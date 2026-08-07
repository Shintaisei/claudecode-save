"""Build model-ready Stage 1--3 assets for the 13 selected S4 CBC alerts.

The selection document is the authority for the 13 input alert rows.  Gold
steps are deliberately limited to raw ``cbc_events`` evidence so that Stage 3
(where CBC alert summaries are hidden) remains answerable.  In particular,
the three Word clusters are not joined to the later mshta cluster: no direct
Word -> mshta edge is observed in the selected telemetry.
"""

from __future__ import annotations

import csv
import copy
import json
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from build_s3_attack_behavior_gold import canonical_record, sample_log, score_template


ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s4/incident.db"
OUT_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s4_13_cbc_attack_gold_20260723"
OUT_CASES = ROOT / "data/current_experiment/cases/atlasv2_s4_13_cbc_attack_stage_cases_20260723.jsonl"
OUT_MANIFEST = ROOT / "data/current_experiment/cases/atlasv2_s4_13_cbc_attack_stage_cases_20260723_manifest.json"
OUT_VALIDATION = ROOT / "docs/current_experiment/atlasv2_s4_13_cbc_attack_assets_validation_20260723.json"
OUT_ANSWERABILITY = ROOT / "docs/current_experiment/atlasv2_s4_13_cbc_attack_stage3_answerability_20260723.json"
LABELS = ROOT / "external/reapr-ground-truth/atlasv2/atlasv2_labels.csv"

HOST = "WIN-32-H1"
SCENARIO = "atlasv2-attack-h1-s4"
WINDOW_MINUTES = 15
EVENT_FIELDS = (
    "timestamp_utc", "action", "process_path", "process_pid", "parent_path", "parent_pid",
    "process_cmdline", "object_name", "remote_ip", "remote_port", "netconn_domain",
    "childproc_name", "childproc_pid",
)
ALERT_FIELDS = (
    "create_time_utc", "stream_name", "alert_id", "type", "severity", "category", "reason", "reason_code",
    "process_name", "threat_cause_actor_name", "created_by_event_id", "device_name", "process_path", "process_pid",
    "process_cmdline", "parent_path", "parent_pid", "parent_cmdline", "report_name", "report_tags",
)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def window(alert_time: str) -> tuple[str, str]:
    moment = parse_time(alert_time)
    return iso(moment - timedelta(minutes=WINDOW_MINUTES)), iso(moment + timedelta(minutes=WINDOW_MINUTES))


def alert_row(conn: sqlite3.Connection, row_id: int) -> tuple[dict, dict]:
    row = conn.execute("SELECT * FROM cbc_alerts WHERE id = ?", (row_id,)).fetchone()
    if row is None:
        raise ValueError(f"missing cbc_alerts row {row_id}")
    public = {
        "source_row_id": row["id"], "time": row["create_time_utc"], "alert_id": row["alert_id"],
        "alert_name": row["report_name"], "alert_reason": row["reason"], "process": row["process_path"],
        "pid": row["process_pid"], "source_stream": row["stream_name"], "severity": row["severity"],
    }
    canonical = {"source_table": "cbc_alerts", "source_row_id": row["id"], **{key: row[key] for key in ALERT_FIELDS}}
    return public, canonical


def step(conn: sqlite3.Connection, chain_id: str, order: int, subject: str, action: str, object_: str, row_id: int) -> dict:
    evidence = canonical_record(conn, row_id)
    return {
        "step_id": f"{chain_id}-S{order:02d}", "order": order, "subject": subject,
        "action": action, "object": object_, "segment": "observed_attack_cluster",
        "evidence_basis": "Canonical CBC EDR event row", "confidence": "observed",
        "process_code_object": object_, "scoring_template": score_template(),
        "canonical_evidence": [evidence],
        "supporting_evidence": {"source_types": ["CBC event"], "sample_logs": [sample_log(evidence)]},
    }


# (alert row, id, focus process, cluster, case role, Gold rows).
# Gold row tuples are subject, action, object, cbc_events.id.  The Word cases
# intentionally terminate at their own parent/child/network evidence.
SPECS = [
    (5, "s4_01_word3236_normal_dotm", "winword.exe", "s4_w1_word3236", "boundary_word_broad", [
        ("explorer.exe (PID 1592)", "started", "winword.exe (PID 3236)", 7566),
        ("winword.exe (PID 3236)", "started", "winword.exe (PID 4572)", 7986),
        ("winword.exe (PID 3236)", "initiated connection", "10.193.66.115:8080", 8124),
    ]),
    (25, "s4_02_word4572_suspicious_vbl", "winword.exe", "s4_w1_word3236", "boundary_word_specific", [
        ("explorer.exe (PID 1592)", "started", "winword.exe (PID 3236)", 7566),
        ("winword.exe (PID 3236)", "started", "winword.exe (PID 4572)", 7986),
        ("winword.exe (PID 3236)", "initiated connection", "10.193.66.115:8080", 8124),
    ]),
    (32, "s4_03_word5980_normal_dotm", "winword.exe", "s4_w2_word5980", "boundary_word_broad", [
        ("werfault.exe (PID 528)", "started", "winword.exe (PID 5980)", 4543),
        ("winword.exe (PID 5980)", "started", "winword.exe (PID 3784)", 4636),
        ("winword.exe (PID 5980)", "initiated connection", "10.193.66.115:8080", 516),
    ]),
    (6, "s4_04_word3784_suspicious_vbl", "winword.exe", "s4_w2_word5980", "boundary_word_specific", [
        ("werfault.exe (PID 528)", "started", "winword.exe (PID 5980)", 4543),
        ("winword.exe (PID 5980)", "started", "winword.exe (PID 3784)", 4636),
        ("winword.exe (PID 5980)", "initiated connection", "10.193.66.115:8080", 516),
    ]),
    (14, "s4_05_word2608_normal_dotm", "winword.exe", "s4_w3_word2608", "boundary_word_broad", [
        ("winword.exe (PID 2608)", "started", "winword.exe (PID 3060)", 2378),
        ("winword.exe (PID 2608)", "initiated connection", "10.193.66.115:8080", 3493),
    ]),
    (19, "s4_06_word3060_suspicious_vbl", "winword.exe", "s4_w3_word2608", "boundary_word_specific", [
        ("winword.exe (PID 2608)", "started", "winword.exe (PID 3060)", 2378),
        ("winword.exe (PID 2608)", "initiated connection", "10.193.66.115:8080", 3493),
    ]),
]

MAIN_CHAIN = [
    ("svchost.exe (PID 644)", "started", "mshta.exe (PID 4724)", 3500),
    ("mshta.exe (PID 4724)", "initiated connection", "10.193.66.115:8080", 3623),
    ("mshta.exe (PID 4724)", "started", "powershell.exe (PID 2976)", 3640),
    ("powershell.exe (PID 2976)", "started", "powershell.exe (PID 3820)", 3793),
    ("powershell.exe (PID 3820)", "initiated connection", "ortrta.net / 10.193.66.115:8443", 12843),
    ("powershell.exe (PID 3820)", "started", "cmd.exe (PID 2168)", 13141),
    ("cmd.exe (PID 2168)", "started", "payload.exe (PID 4184)", 13187),
    ("payload.exe (PID 4184)", "started", "payload.exe (PID 3652)", 13300),
    ("payload.exe (PID 3652)", "initiated connection", "ortrta.net / 10.193.66.115:9999", 11453),
]
SPECS += [
    (31, "s4_07_mshta_svchost_hta", "mshta.exe", "s4_c1_mshta_payload", "loader_specific", MAIN_CHAIN),
    (18, "s4_08_mshta_script_interpreter", "mshta.exe", "s4_c1_mshta_payload", "loader_specific", MAIN_CHAIN),
    (9, "s4_09_ps2976_hidden_parent", "powershell.exe", "s4_c1_mshta_payload", "midchain_specific", MAIN_CHAIN[2:]),
    (16, "s4_10_ps2976_hidden_encoded", "powershell.exe", "s4_c1_mshta_payload", "midchain_specific", MAIN_CHAIN[2:]),
    (15, "s4_11_ps2976_interpreter", "powershell.exe", "s4_c1_mshta_payload", "midchain_broad", MAIN_CHAIN[2:]),
    (30, "s4_12_ps2976_encoded", "powershell.exe", "s4_c1_mshta_payload", "midchain_specific", MAIN_CHAIN[2:]),
    (10, "s4_13_ps3820_encoded", "powershell.exe", "s4_c1_mshta_payload", "late_midchain_specific", MAIN_CHAIN[3:]),
]


def labels() -> dict[tuple[int, str], str]:
    result = {}
    with LABELS.open(encoding="utf-8-sig", newline="") as handle:
        for raw in csv.DictReader(handle):
            row = {key.strip(): value.strip() for key, value in raw.items() if key and value is not None}
            if row["attack"] == "atlasv2/h1-s4":
                result[(int(row["process_id"]), row["process_name"].lower())] = row["label"]
    return result


def gold_case(conn: sqlite3.Connection, spec: tuple, gt: dict) -> dict:
    alert_id, chain_id, focus, cluster, role, rows = spec
    alert, canonical_alert = alert_row(conn, alert_id)
    start, end = window(alert["time"])
    steps = [step(conn, chain_id, index, *row) for index, row in enumerate(rows, 1)]
    target_key = (int(alert["pid"]), str(alert["process"]).lower())
    target_label = gt.get(target_key, "not_labelled")
    return {
        "chain_id": chain_id,
        "chain_title": f"S4 CBC attack-related alert {alert_id}: {alert['alert_name']}",
        "case_group": "attack_related_cbc_alert", "suite_group": "s4_attack_reconstruction",
        "source_database": str(DB.relative_to(ROOT)), "scenario": SCENARIO,
        "chain_type": "cbc_alert_attack_behavior_reconstruction",
        "chain_description": "Observed, evidence-backed behavior sequence in the selected S4 attack-related cluster.",
        "observed_behavior": "Observed, evidence-backed behavior sequence in the selected S4 attack-related cluster.",
        "stages_present": ["stage1"],
        "input_scope": {"host": HOST, "focus_processes": [focus], "chain_window_start_utc": start, "chain_window_end_utc": end,
                        "window_minutes": 30, "window_selection_policy": "fixed_cbc_alert_create_time_plus_minus_15_minutes",
                        "input_policy": "Stage 1 supplies one CBC alert summary; Stages 2 and 3 supply only host, process, and timestamp/time scope."},
        "input_alert_rows": [alert], "canonical_input_alert": canonical_alert,
        "alert_target_ground_truth": {"source": str(LABELS.relative_to(ROOT)), "scenario_key": "atlasv2/h1-s4", "target_process_label": target_label,
                                        "note": "This label is evaluation metadata, never model input. Selection is attack-related telemetry, not a claim that every target has the same process-level GT label."},
        "alert_timing": {"alert_time_utc": alert["time"], "investigation_window_start_utc": start, "investigation_window_end_utc": end,
                         "note": "All 24 attack cases use CBC alert create_time ±15 minutes (30 minutes total)."},
        "alert_cluster_id": cluster, "case_role": role, "is_boundary_case": cluster.startswith("s4_w"),
        "behavior_timeline": steps, "gold_steps": steps,
        "gold_order_pairs": [[steps[i]["step_id"], steps[i + 1]["step_id"]] for i in range(len(steps) - 1)],
        "limitations": (["The Word cluster is not causally joined to the later mshta cluster: no direct Word-to-mshta edge is required by this Gold."] if cluster.startswith("s4_w") else []),
        "case_scoring": {"step_score_max": len(steps) * 4, "sequence_score_max": 3, "case_score_max": len(steps) * 4 + 3},
    }


def process_time_gold(source: dict, chain_id: str, title: str, source_alert_rows: list[int]) -> dict:
    """Make one canonical Stage 2/3 Gold for one unique process-time input.

    Several Stage 1 alerts can name the same behavior cluster.  Once alert
    summary content is removed, they must not become separately scored copies
    of an indistinguishable host/process/time input.
    """
    result = copy.deepcopy(source)
    selected_alert = result.pop("input_alert_rows")[0]
    result.pop("canonical_input_alert", None)
    result["chain_id"] = chain_id
    result["chain_title"] = title
    result["case_group"] = "attack_related_process_time"
    result["suite_group"] = "s4_attack_reconstruction_process_time"
    result["stages_present"] = ["stage2", "stage3"]
    result["investigation_time_anchor_utc"] = selected_alert["time"]
    result["selection_anchor"] = {
        "source_alert_row": selected_alert["source_row_id"],
        "time": selected_alert["time"],
        "focus_process": result["input_scope"]["focus_processes"][0],
        "withheld_related_alert_rows": source_alert_rows,
        "note": "Evaluation provenance only. No CBC alert summary field is supplied to Stage 2/3.",
    }
    result["input_policy_note"] = "Stage 2/3 use one canonical process-time input for this cluster; the listed alert rows are withheld provenance, not independent model inputs."
    return result


def combined_word_process_time_gold(first: dict, second: dict) -> dict:
    """Build one input/Gold where runner-visible process-time is identical.

    W2 and W3 both reduce to ``winword.exe`` in the same runner-second.  Their
    local relations remain separate Gold segments, rather than being joined
    across clusters.
    """
    result = process_time_gold(
        first, "s4_pt_02_word_w2_w3", "S4 process-time W2+W3: two separate Word local clusters", [32, 6, 14, 19]
    )
    first_steps = copy.deepcopy(first["gold_steps"])
    second_steps = copy.deepcopy(second["gold_steps"])
    merged = []
    for segment, steps in (("s4_w2_word5980", first_steps), ("s4_w3_word2608", second_steps)):
        for item in steps:
            item["order"] = len(merged) + 1
            item["step_id"] = f"{result['chain_id']}-{segment}-S{len(merged) + 1:02d}"
            item["segment"] = segment
            merged.append(item)
    result["behavior_timeline"] = merged
    result["gold_steps"] = merged
    result["gold_order_pairs"] = [
        [merged[index]["step_id"], merged[index + 1]["step_id"]]
        for index in range(len(merged) - 1)
        if merged[index]["segment"] == merged[index + 1]["segment"]
    ]
    result["chain_description"] = "Two separately observed Word parent/child-and-network clusters share the same reduced host/process/time input. Gold keeps them separate because no cross-cluster edge is asserted."
    result["observed_behavior"] = result["chain_description"]
    result["limitations"] = [
        "S4-W2 and S4-W3 are separate observed Word local clusters. They share a reduced process-time input but Gold does not connect them causally.",
        "The Word clusters are not causally joined to the later mshta cluster: no direct Word-to-mshta edge is required by this Gold.",
    ]
    result["case_scoring"] = {"step_score_max": len(merged) * 4, "sequence_score_max": 3, "case_score_max": len(merged) * 4 + 3}
    return result


def alert_anchor(gold: dict) -> dict:
    if not gold.get("input_alert_rows"):
        selection = gold["selection_anchor"]
        return {"source_stream": None, "source_table": "cbc_alerts", "source_row_id": selection["source_alert_row"],
                "timestamp_utc": selection["time"], "process_name": selection["focus_process"], "process_path": selection["focus_process"],
                "process_cmdline": None, "parent_path": None, "action": "WITHHELD_CBC_ALERT_TIME_ANCHOR"}
    alert = gold["input_alert_rows"][0]
    return {"source_stream": alert["source_stream"], "source_table": "cbc_alerts", "source_row_id": alert["source_row_id"],
            "timestamp_utc": alert["time"], "process_name": alert["process"], "process_path": alert["process"],
            "process_cmdline": None, "parent_path": None, "action": "CBC_ALERT_SUMMARY"}


def case_row(number: int, gold: dict, stage: str) -> dict:
    scope = gold["input_scope"]
    alert = gold["input_alert_rows"][0] if gold.get("input_alert_rows") else gold["selection_anchor"]
    stage1 = stage == "stage1"
    record = {
        "instance_id": f"{gold['chain_id']}_{stage}", "case_id": f"{gold['chain_id']}_{stage}",
        "input_id": f"atlasv2_s4_13_attack_input_{number:03d}", "stage": stage,
        "scenario": SCENARIO, "database": gold["source_database"], "host": HOST,
        "process_name": scope["focus_processes"][0], "actor": scope["focus_processes"][0],
        "expected_behavior": gold["observed_behavior"], "expected_behavior_category": gold["chain_type"],
        "context_label": gold["case_group"], "suite_group": gold["suite_group"], "difficulty": "alert_input" if stage1 else "process_time",
        "time_window_utc": {"episode_start": scope["chain_window_start_utc"], "episode_end": scope["chain_window_end_utc"],
                            "analysis_scope": "Hard-scoped CBC alert create_time ±15 minute investigation window"},
        "anchor_event": alert_anchor(gold), "input_alert_rows": [alert] if stage1 else [],
        "investigation_time_anchor_utc": gold.get("investigation_time_anchor_utc", alert["time"]),
        "model_ready_input": {"input_id": f"atlasv2_s4_13_attack_input_{number:03d}", "stage": stage,
            "input": {"host": HOST, "focus_processes": scope["focus_processes"],
                      "chain_window_start_utc": scope["chain_window_start_utc"], "chain_window_end_utc": scope["chain_window_end_utc"],
                      **({"cbc_alert": alert} if stage1 else {})}},
        "gold_chain_file": f"by_chain/{gold['chain_id']}/chain_gold.json", "chain_id": gold["chain_id"],
        "chain_type": gold["chain_type"], "formal_gold_root": str(OUT_GOLD.relative_to(ROOT)),
        "stage3_answerable_policy": "All Gold steps use cbc_events telemetry; no Gold step depends on cbc_alerts summary fields.",
        "input_provenance": {"selected_cbc_alert_row": alert.get("source_row_id", alert.get("source_alert_row")), "stage1_visible": stage1,
                              "stage2_stage3_withheld_fields": [] if stage1 else ["CBC alert summary", "GT label", "scenario description"]},
        "enforce_time_scope": True,
    }
    if stage == "stage3":
        record["model_ready_input"]["db_filter"] = "hide cbc_alerts summary rows; retain cbc_events telemetry; enforce the declared ±15 minute window"
    return record


def validate(golds: list[dict], cases: list[dict]) -> dict:
    checks, conn = [], sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    for gold in golds:
        alert = gold["input_alert_rows"][0] if gold.get("input_alert_rows") else gold["selection_anchor"]
        alert_row_id = alert.get("source_row_id", alert.get("source_alert_row"))
        row = conn.execute("SELECT * FROM cbc_alerts WHERE id = ?", (alert_row_id,)).fetchone()
        alert_ok = row is not None and (not gold.get("input_alert_rows") or row["alert_id"] == alert["alert_id"])
        checks.append({"chain_id": gold["chain_id"], "kind": "alert_identity", "status": "pass" if alert_ok else "fail"})
        start, end = gold["input_scope"]["chain_window_start_utc"], gold["input_scope"]["chain_window_end_utc"]
        checks.append({"chain_id": gold["chain_id"], "kind": "fixed_30_minute_window", "status": "pass" if window(alert["time"]) == (start, end) else "fail"})
        word_case = gold["is_boundary_case"]
        for item in gold["gold_steps"]:
            ev = item["canonical_evidence"][0]
            event = conn.execute("SELECT * FROM cbc_events WHERE id = ?", (ev["source_row_id"],)).fetchone()
            immutable_ok = event is not None and all(ev.get(key) == event[key] for key in EVENT_FIELDS)
            within = event is not None and start <= event["timestamp_utc"] <= end
            checks.append({"chain_id": gold["chain_id"], "kind": "stage3_raw_event_and_window", "row_id": ev["source_row_id"], "status": "pass" if immutable_ok and within else "fail"})
            subject_pid = re.search(r"PID (\d+)", item["subject"])
            object_pid = re.search(r"PID (\d+)", item["object"])
            if item["action"] == "started":
                semantic_ok = event is not None and subject_pid is not None and object_pid is not None and event["process_pid"] == int(subject_pid.group(1)) and event["childproc_pid"] == int(object_pid.group(1))
            elif item["action"] == "initiated connection":
                host_port = item["object"].split("/")[-1].strip().split(":")
                semantic_ok = event is not None and subject_pid is not None and event["process_pid"] == int(subject_pid.group(1)) and len(host_port) == 2 and str(event["remote_ip"]) == host_port[0] and int(event["remote_port"]) == int(host_port[1])
            else:
                semantic_ok = False
            checks.append({"chain_id": gold["chain_id"], "kind": "pid_path_action_semantics", "row_id": ev["source_row_id"], "status": "pass" if semantic_ok else "fail"})
            if word_case:
                no_main_chain = event is not None and event["process_pid"] not in {644, 4724, 2976, 3820, 2168, 4184, 3652}
                checks.append({"chain_id": gold["chain_id"], "kind": "word_boundary_no_mshta_chain", "row_id": ev["source_row_id"], "status": "pass" if no_main_chain else "fail"})
    for row in cases:
        stage = row["stage"]
        has_alert = bool(row["input_alert_rows"])
        status = (stage == "stage1") == has_alert
        checks.append({"chain_id": row["chain_id"], "kind": f"{stage}_input_visibility", "status": "pass" if status else "fail"})
        checks.append({"chain_id": row["chain_id"], "kind": f"{stage}_time_scope_enforced", "status": "pass" if row.get("enforce_time_scope") is True else "fail"})
    conn.close()
    return {"status": "passed" if all(c["status"] == "pass" for c in checks) else "failed", "gold_case_count": len(golds),
            "stage_input_count": len(cases), "checked_items": len(checks), "passed_items": sum(c["status"] == "pass" for c in checks), "checks": checks}


def main() -> None:
    if OUT_GOLD.exists():
        shutil.rmtree(OUT_GOLD)
    (OUT_GOLD / "by_chain").mkdir(parents=True)
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    alert_golds = [gold_case(conn, spec, labels()) for spec in SPECS]
    by_id = {gold["chain_id"]: gold for gold in alert_golds}
    process_time_golds = [
        process_time_gold(by_id["s4_01_word3236_normal_dotm"], "s4_pt_01_word_w1", "S4 process-time W1: Word parent/child and :8080", [5, 25]),
        combined_word_process_time_gold(by_id["s4_04_word3784_suspicious_vbl"], by_id["s4_05_word2608_normal_dotm"]),
        process_time_gold(by_id["s4_08_mshta_script_interpreter"], "s4_pt_03_mshta_c1", "S4 process-time C1: mshta to payload and C2", [31, 18, 9, 16, 15, 30, 10]),
        process_time_gold(by_id["s4_09_ps2976_hidden_parent"], "s4_pt_04_powershell_c1", "S4 process-time C1: PowerShell to payload and C2", [9, 16, 15, 30, 10]),
    ]
    golds = [*alert_golds, *process_time_golds]
    conn.close()
    for gold in golds:
        target = OUT_GOLD / "by_chain" / gold["chain_id"]
        target.mkdir()
        (target / "chain_gold.json").write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT_GOLD / "chain_gold_index.json").write_text(json.dumps({"suite": "atlasv2_s4_13_cbc_attack", "chain_ids": [g["chain_id"] for g in golds]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cases = [
        *[case_row(index, gold, "stage1") for index, gold in enumerate(alert_golds, 1)],
        *[case_row(index, gold, "stage2") for index, gold in enumerate(process_time_golds, len(alert_golds) + 1)],
        *[case_row(index, gold, "stage3") for index, gold in enumerate(process_time_golds, len(alert_golds) + len(process_time_golds) + 1)],
    ]
    OUT_CASES.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in cases), encoding="utf-8")
    validation = validate(golds, cases)
    OUT_VALIDATION.write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if validation["status"] != "passed":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
    answerability = {"suite": "atlasv2_s4_13_cbc_attack", "stage3_policy": "Each Gold canonical evidence source_table is cbc_events, never cbc_alerts.",
                     "stage1_alert_target_case_count": len(alert_golds), "stage2_stage3_unique_process_time_case_count": len(process_time_golds),
                     "gold_step_count": sum(len(g["gold_steps"]) for g in golds),
                     "boundary_cases": [g["chain_id"] for g in golds if g["is_boundary_case"]],
                     "boundary_rule": "Word Golds exclude the later mshta/PowerShell/payload cluster because no direct Word-to-mshta edge is asserted."}
    OUT_ANSWERABILITY.write_text(json.dumps(answerability, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    unique_alert_ids = {g["input_alert_rows"][0]["alert_id"] for g in alert_golds}
    manifest = {"suite": "atlasv2_s4_13_cbc_attack", "gold_case_count": len(golds), "stage1_alert_target_case_count": len(alert_golds),
                "stage1_unique_alert_id_count": len(unique_alert_ids), "stage2_unique_process_time_case_count": len(process_time_golds), "stage3_unique_process_time_case_count": len(process_time_golds),
                "model_ready_input_count": len(cases), "time_window_policy": "CBC alert create_time ±15 minutes (30 minutes total)",
                "selection_document": "docs/current_experiment/atlasv2_s4_13_cbc_attack_alert_selection_20260723.md", "validation": str(OUT_VALIDATION.relative_to(ROOT)),
                "stage3_answerability": str(OUT_ANSWERABILITY.relative_to(ROOT)), "execution_status": "not_run"}
    OUT_MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"gold_cases": len(golds), "stage_inputs": len(cases), "validation": validation["status"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
