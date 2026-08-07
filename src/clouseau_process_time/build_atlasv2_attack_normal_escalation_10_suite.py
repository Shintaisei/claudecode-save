"""Build the primary 10-case ATLASv2 suite: 5 attack + 5 normal-to-escalation.

The normal-to-escalation cases start from a normal-looking Office/Windows
observation.  They do not assert that the initial process caused every later
event: they test whether a local explanation is insufficient once temporally
nearby, evidence-backed escalation signals are reconstructed.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from build_s3_attack_behavior_gold import canonical_record, sample_log, score_template


ROOT = Path(__file__).resolve().parents[2]
S3_DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db"
S4_DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s4/incident.db"
ATTACK5_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s3_alert_origin_behavior_chain_gold"
OUT_GOLD = ROOT / "data/current_experiment/gold/atlasv2_attack5_normal_escalation5_gold"
OUT_CASES = ROOT / "data/current_experiment/cases/atlasv2_attack5_normal_escalation5_stage3_cases_20260720.jsonl"
OUT_COMBINED = ROOT / "data/current_experiment/cases/cbc_23_plus_atlasv2_attack5_normal_escalation5_stage3_cases_20260720.jsonl"
OUT_MANIFEST = ROOT / "data/current_experiment/cases/atlasv2_attack5_normal_escalation5_stage3_cases_20260720_manifest.json"
OUT_VALIDATION = ROOT / "docs/current_experiment/atlasv2_attack5_normal_escalation5_validation_20260720.json"
EXISTING_23 = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
IMMUTABLE_FIELDS = ("timestamp_utc", "action", "process_path", "process_pid", "parent_path", "parent_pid", "process_cmdline", "object_name", "remote_ip", "remote_port", "netconn_domain", "childproc_name", "childproc_pid")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def step(con: sqlite3.Connection, step_id: str, order: int, subject: str, action: str, object_: str, row_id: int) -> dict:
    evidence = canonical_record(con, row_id)
    return {
        "step_id": step_id,
        "order": order,
        "focus_process": "normal-context expansion",
        "subject": subject,
        "action": action,
        "object": object_,
        "evidence_basis": "Canonical CBC EDR event row",
        "confidence": "observed",
        "process_code_object": object_,
        "scoring_template": score_template(),
        "canonical_evidence": [evidence],
        "supporting_evidence": {"source_types": ["CBC event"], "sample_logs": [sample_log(evidence)]},
    }


def escalation_gold(spec: dict) -> dict:
    con = sqlite3.connect(spec["db"])
    con.row_factory = sqlite3.Row
    start = spec["anchor_time"]
    end = iso(parse_time(start) + timedelta(minutes=5))
    rows = [*spec["prefix_steps"]]
    central = spec.get("central_steps", [])
    for entry in central:
        timestamp = con.execute("SELECT timestamp_utc FROM cbc_events WHERE id = ?", (entry[-1],)).fetchone()[0]
        if start <= timestamp <= end:
            rows.append(entry)
    gold_steps = [step(con, f"{spec['chain_id']}-S{i:02d}", i, *entry) for i, entry in enumerate(rows, start=1)]
    normal_count = spec.get("normal_prefix_count", {"n2a_01_s3_word_to_regsvr32": 1, "n2a_02_s4_word_initial_to_mshta": 3, "n2a_03_s4_word_restart_to_payload": 3, "n2a_04_s4_werfault_to_mshta": 2, "n2a_05_s4_word_late_to_payload": 3}[spec["chain_id"]])
    for index, item in enumerate(gold_steps):
        item["segment"] = "normal_context" if index < normal_count else "co_observed_escalation"
    for item in gold_steps:
        item["one_line_ja"] = f"{item['subject']} が {item['object']} に対して {item['action']} を記録した。"
    return {
        "chain_id": spec["chain_id"],
        "chain_title": spec["title"],
        "case_group": "normal_to_escalation",
        "suite_group": "normal_to_escalation",
        "source_database": str(spec["db"].relative_to(ROOT)),
        "scenario": spec["scenario"],
        "chain_type": "normal_context_escalation",
        "chain_description": spec["observed_behavior"],
        "observed_behavior": spec["observed_behavior"],
        "scenario_interpretation": "A normal-looking local context is the investigation start. Later events are reported as co-observed, temporally nearby escalation evidence; this gold does not assert an unobserved causal edge from the initial Office/Windows process to every later event.",
        "stage3_visibility_policy": "Stage 3 receives only host, focus executable, and time range. Alert summaries, labels, and scenario descriptions are excluded.",
        "stages_present": ["stage3"],
        "input_scope": {"host": spec["host"], "focus_processes": [spec["focus"]], "chain_window_start_utc": start, "chain_window_end_utc": end, "window_minutes": 5, "window_selection_policy": "fixed_5min_normal_context_anchored", "input_policy": "Stage 3 receives only host, normal-context executable name, and a five-minute evidence-anchored window. Alert report/reason/tags/PID and ground truth are excluded."},
        "evaluation_mode": "normal_context_escalation",
        "overlap_cluster_id": spec.get("overlap_cluster_id", "s3_word_regsvr32" if spec["scenario"].endswith("s3") else "s4_word_mshta_payload"),
        "behavior_timeline": gold_steps,
        "gold_steps": gold_steps,
        "normal_context_steps": gold_steps[:normal_count],
        "co_observed_escalation_steps": gold_steps[normal_count:],
        "gold_order_pairs": [[gold_steps[i]["step_id"], gold_steps[i + 1]["step_id"]] for i in range(len(gold_steps) - 1) if gold_steps[i]["segment"] == gold_steps[i + 1]["segment"]],
        "timeline_ja": [item["one_line_ja"] for item in gold_steps],
        "natural_language_summary_ja": " ".join(item["one_line_ja"] for item in gold_steps),
        "evidence_span_utc": {"start": gold_steps[0]["canonical_evidence"][0]["timestamp_utc"], "end": gold_steps[-1]["canonical_evidence"][0]["timestamp_utc"]},
        "limitations": ["The normal-context steps and escalation-evidence steps are separate sequences. Their temporal co-observation is not a causal process edge.", "Connection-create records do not establish C2, exfiltration, or transfer success.", "This is an escalation-support condition, not autonomous attack discovery or an alert-classification result."],
        "case_scoring": {"step_score_max": len(gold_steps) * 4, "sequence_score_max": 3, "case_score_max": len(gold_steps) * 4 + 3, "step_score": None, "sequence_score": None, "case_score": None},
        "independence_note": spec["independence_note"],
        "normal_context_provenance": {"condition": "normal_context_to_escalation_alert_content_hidden", "normal_context_anchor": {"source_table": "cbc_events", "source_row_id": spec["anchor_row_id"], "timestamp_utc": start, "focus_process": spec["focus"]}, "related_alert_rows_withheld": spec["alert_rows"], "scope_note": "The initial normal-looking context and the expansion window are supplied by evaluation orchestration; the model is not told that this is an attack scenario."},
    }


S4_CENTRAL = [
    ("svchost.exe (PID 644)", "started", "mshta.exe (PID 4724)", 3500),
    ("mshta.exe (PID 4724)", "initiated connection", "10.193.66.115:8080", 3623),
    ("mshta.exe (PID 4724)", "started", "powershell.exe (PID 2976)", 3640),
    ("powershell.exe (PID 2976)", "started", "powershell.exe (PID 3820)", 3793),
    ("powershell.exe (PID 3820)", "initiated connection", "10.193.66.115:8443", 12843),
    ("powershell.exe (PID 3820)", "started", "cmd.exe (PID 2168)", 13141),
    ("cmd.exe (PID 2168)", "started", "payload.exe (PID 4184)", 13187),
    ("payload.exe (PID 4184)", "started child", "payload.exe (PID 3652)", 13300),
    ("payload.exe (PID 3652)", "initiated connection", "ortrta.net / 10.193.66.115:9999", 11453),
]


SPECS = [
    {"chain_id": "n2a_01_s3_word_to_regsvr32", "title": "Normal-context Word investigation escalates to regsvr32 evidence", "db": S3_DB, "scenario": "atlasv2-attack-h1-s3", "host": "WIN-32-H1", "focus": "winword.exe", "anchor_row_id": 8705, "anchor_time": "2022-07-19T14:33:20.0350217Z", "alert_rows": [29], "prefix_steps": [("WINWORD.EXE (PID 5592)", "opened/read", "msf.rtf", 8705), ("svchost.exe (PID 648)", "started", "EQNEDT32.EXE (PID 6032)", 7814), ("EQNEDT32.EXE (PID 6032)", "started", "regsvr32.exe (PID 6124)", 7829), ("regsvr32.exe (PID 6124)", "initiated connection", "ortrta.net / 10.193.66.115:8080", 7889)], "observed_behavior": "Word document handling is observed, followed in the same five-minute host window by EqnEdt32 starting regsvr32 and regsvr32 initiating a remote connection. The latter evidence means a Word-only normal explanation is insufficient.", "independence_note": "One normal-to-escalation input for the S3 incident. It overlaps the S3 attack reconstruction cases and is not an independent attack sample."},
    {"chain_id": "n2a_02_s4_word_initial_to_mshta", "title": "Normal-context initial Word handling escalates to mshta", "db": S4_DB, "scenario": "atlasv2-attack-h1-s4", "host": "WIN-32-H1", "focus": "winword.exe", "anchor_row_id": 7618, "anchor_time": "2022-07-20T00:48:58.8232054Z", "alert_rows": [5], "prefix_steps": [("WINWORD.EXE (PID 3236)", "opened/read", "normal.dotm", 7618), ("WINWORD.EXE (PID 3236)", "opened/read", "msf.doc", 7971), ("WINWORD.EXE (PID 3236)", "initiated connection", "10.193.66.115:8080", 8124)], "central_steps": S4_CENTRAL, "observed_behavior": "Word opens normal.dotm and msf.doc, then records a remote connection. The same five-minute host window also records mshta and descendant PowerShell activity, so the local Office explanation should be escalated.", "independence_note": "One of four overlapping normal-to-escalation inputs for the single S4 incident episode; do not count it as an independent attack."},
    {"chain_id": "n2a_03_s4_word_restart_to_payload", "title": "Normal-context Word restart escalates to payload lineage", "db": S4_DB, "scenario": "atlasv2-attack-h1-s4", "host": "WIN-32-H1", "focus": "winword.exe", "anchor_row_id": 4592, "anchor_time": "2022-07-20T00:50:38.069882Z", "alert_rows": [32], "prefix_steps": [("WINWORD.EXE (PID 5980)", "opened/read", "normal.dotm", 4592), ("WINWORD.EXE (PID 5980)", "opened/read", "msf.doc", 4616), ("WINWORD.EXE (PID 5980)", "initiated connection", "10.193.66.115:8080", 516)], "central_steps": S4_CENTRAL, "observed_behavior": "A restarted Word process opens normal.dotm and msf.doc and initiates a remote connection. The same five-minute host window contains an mshta-to-PowerShell-to-payload lineage, so the initial normal explanation is insufficient.", "independence_note": "One of four overlapping normal-to-escalation inputs for the single S4 incident episode; do not count it as an independent attack."},
    {"chain_id": "n2a_04_s4_werfault_to_mshta", "title": "Normal-context Windows error-reporting path escalates to mshta", "db": S4_DB, "scenario": "atlasv2-attack-h1-s4", "host": "WIN-32-H1", "focus": "werfault.exe", "anchor_row_id": 1004, "anchor_time": "2022-07-20T00:52:16.065487Z", "alert_rows": [8], "prefix_steps": [("WerFault.exe (PID 1704)", "started", "WINWORD.EXE (PID 3284)", 1004), ("WINWORD.EXE (PID 3284)", "opened/read", "normal.dotm", 1057)], "central_steps": S4_CENTRAL, "observed_behavior": "A Windows error-reporting path starts Word, which opens normal.dotm. Within the same five-minute host window, mshta and descendant PowerShell/payload activity are recorded; the initial context should be escalated rather than closed in isolation.", "independence_note": "One of four overlapping normal-to-escalation inputs for the single S4 incident episode; do not count it as an independent attack."},
    {"chain_id": "n2a_05_s4_word_late_to_payload", "title": "Normal-context later Word handling escalates to payload lineage", "db": S4_DB, "scenario": "atlasv2-attack-h1-s4", "host": "WIN-32-H1", "focus": "winword.exe", "anchor_row_id": 1203, "anchor_time": "2022-07-20T00:52:44.1410929Z", "alert_rows": [14], "prefix_steps": [("WINWORD.EXE (PID 2608)", "opened/read", "normal.dotm", 1203), ("WINWORD.EXE (PID 2608)", "opened/read", "msf.doc", 2358), ("WINWORD.EXE (PID 2608)", "initiated connection", "10.193.66.115:8080", 3493)], "central_steps": S4_CENTRAL, "observed_behavior": "A later Word process opens normal.dotm and msf.doc and initiates a remote connection. The same five-minute host window contains mshta, PowerShell, and payload lineage evidence, so the initial normal explanation is insufficient.", "independence_note": "One of four overlapping normal-to-escalation inputs for the single S4 incident episode; do not count it as an independent attack."},
]


def validate(gold_paths: list[Path]) -> dict:
    results = []
    for path in gold_paths:
        gold = json.loads(path.read_text(encoding="utf-8"))
        con = sqlite3.connect(ROOT / gold["source_database"])
        con.row_factory = sqlite3.Row
        start, end = gold["input_scope"]["chain_window_start_utc"], gold["input_scope"]["chain_window_end_utc"]
        for item in gold["gold_steps"]:
            evidence = item["canonical_evidence"][0]
            row = con.execute("SELECT * FROM cbc_events WHERE id = ?", (evidence["source_row_id"],)).fetchone()
            ok = row is not None and evidence["source_table"] == "cbc_events" and start <= row["timestamp_utc"] <= end
            if row is not None:
                ok = ok and all(evidence.get(field) == row[field] for field in IMMUTABLE_FIELDS)
            results.append({"chain_id": gold["chain_id"], "step_id": item["step_id"], "row_id": evidence["source_row_id"], "status": "pass" if ok else "fail"})
    return {"status": "passed" if all(row["status"] == "pass" for row in results) else "failed", "chain_count": len(gold_paths), "step_count": len(results), "passed_step_count": sum(row["status"] == "pass" for row in results), "rows": results}


def main() -> None:
    if OUT_GOLD.exists():
        shutil.rmtree(OUT_GOLD)
    (OUT_GOLD / "by_chain").mkdir(parents=True)
    attack_ids = [f"s3_alert_origin_0{i}_" for i in range(1, 6)]
    for source in sorted(ATTACK5_GOLD.glob("by_chain/*/chain_gold.json")):
        gold = json.loads(source.read_text(encoding="utf-8"))
        if not any(gold["chain_id"].startswith(prefix) for prefix in attack_ids):
            continue
        gold["suite_group"] = "attack_reconstruction"
        gold["evaluation_mode"] = "standard_reconstruction"
        gold["source_database"] = str(S3_DB.relative_to(ROOT))
        target = OUT_GOLD / "by_chain" / gold["chain_id"]
        target.mkdir()
        (target / "chain_gold.json").write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for spec in SPECS:
        gold = escalation_gold(spec)
        target = OUT_GOLD / "by_chain" / gold["chain_id"]
        target.mkdir()
        (target / "chain_gold.json").write_text(json.dumps(gold, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    paths = sorted(OUT_GOLD.glob("by_chain/*/chain_gold.json"))
    validation = validate(paths)
    OUT_VALIDATION.parent.mkdir(parents=True, exist_ok=True)
    OUT_VALIDATION.write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if validation["status"] != "passed":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
    cases = []
    for number, path in enumerate(paths, start=1):
        gold = json.loads(path.read_text(encoding="utf-8"))
        scope = gold["input_scope"]
        model_input = {"input_id": f"atlasv2_10_input_{number:03d}", "stage": "stage3", "input": {"host": scope["host"], "focus_processes": scope["focus_processes"], "chain_window_start_utc": scope["chain_window_start_utc"], "chain_window_end_utc": scope["chain_window_end_utc"]}, "db_filter": "remove cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; retain cbc_events telemetry"}
        anchor = gold["gold_steps"][0]["canonical_evidence"][0]
        cases.append({"instance_id": f"{gold['chain_id']}_stage3", "case_id": f"{gold['chain_id']}_stage3", "input_id": model_input["input_id"], "stage": "stage3", "scenario": gold.get("scenario", "atlasv2-attack-h1-s3"), "database": gold["source_database"], "host": scope["host"], "process_name": "; ".join(scope["focus_processes"]), "actor": "; ".join(scope["focus_processes"]), "expected_behavior": gold["observed_behavior"], "expected_behavior_category": gold["chain_type"], "context_label": gold["case_group"], "suite_group": gold["suite_group"], "evaluation_mode": gold.get("evaluation_mode", "standard_reconstruction"), "overlap_cluster_id": gold.get("overlap_cluster_id"), "quality": "canonical_evidence_finalized_20260720", "difficulty": "process_time", "time_window_utc": {"episode_start": scope["chain_window_start_utc"], "episode_end": scope["chain_window_end_utc"], "analysis_scope": "Five-minute local investigation window"}, "anchor_event": {"source_stream": anchor["source_stream"], "source_table": anchor["source_table"], "source_row_id": anchor["source_row_id"], "timestamp_utc": anchor["timestamp_utc"], "process_name": anchor["process_path"], "process_path": anchor["process_path"], "process_cmdline": anchor["process_cmdline"], "parent_path": anchor["parent_path"], "action": anchor["action"]}, "input_alert_rows": [], "model_ready_input": model_input, "gold_chain_file": str(path.relative_to(OUT_GOLD)), "chain_id": gold["chain_id"], "chain_type": gold["chain_type"], "formal_gold_root": str(OUT_GOLD.relative_to(ROOT)), "stage3_answerable_policy": "All gold steps have canonical cbc_events evidence and are Stage 3-visible; alert summaries, labels, and scenario descriptions are excluded from model input.", "independence_note": gold["independence_note"], "input_provenance": gold.get("alert_origin_provenance", gold.get("normal_context_provenance", {}))})
    OUT_CASES.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases), encoding="utf-8")
    existing = [json.loads(line) for line in EXISTING_23.read_text(encoding="utf-8").splitlines() if json.loads(line)["stage"] == "stage3"]
    OUT_COMBINED.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in [*existing, *cases]), encoding="utf-8")
    OUT_MANIFEST.write_text(json.dumps({"stage": "stage3", "attack_reconstruction_case_count": 5, "normal_to_escalation_case_count": 5, "suite_case_count": 10, "existing_benign_case_count": len(existing), "combined_case_count": len(existing) + 10, "attack_case_selection_note": "AO06 is excluded because it is an analyst-selected payload-lineage pivot, not one of the five direct alert-origin investigation inputs.", "normal_to_escalation_condition_note": "All five are alert-selected, alert-content-hidden, normal-looking-context inputs. The escalation evidence is a separately reported co-observed sequence, not a causal continuation of the focus process unless an observed process edge exists.", "independent_episode_note": "The 10 inputs cover three primary S3 attack episodes plus one S4 incident episode; cases overlap and are not independent attacks. N2A02-N2A05 share overlap_cluster_id=s4_word_mshta_payload.", "validation": str(OUT_VALIDATION.relative_to(ROOT))}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"gold_cases": len(paths), "validation": validation["status"], "validated_steps": validation["passed_step_count"], "combined_cases": len(existing) + len(cases)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
