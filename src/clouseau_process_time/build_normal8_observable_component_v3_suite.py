#!/usr/bin/env python3
"""Build a normal-behavior suite directly comparable with attack v3.

The historical normal suite cannot be used as the formal attack comparison:
some Gold evidence lies outside the supplied five-minute window, process
identity is not fixed by PID, module-load rows are sometimes used as proxies
for a claimed action, and the historical run imposed experiment-side Agent
call ceilings.

This builder does not modify those historical assets.  It creates eight new
normal observable components with the same contract used by attack v3:

* one neutral primary-telemetry anchor and one five-minute window per case;
* identical anchor, window, component rule, and Gold across all three stages;
* Stage 1 adds exactly one representative alert; Stage 2/3 expose no alert;
* hidden alert identity or alert-to-Gold correspondence is never scored;
* one canonical cbc_events fingerprint per semantic Gold action;
* subject/action/object scoring, with critical evidence kept diagnostic;
* module loads, duplicate sensor rows, and nearby unconnected activity are
  excluded from the Gold behavior component.
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
VERSION = "20260726"
SUITE = "normal8_observable_component_v3"
CONTRACT_VERSION = "observable_component_normal_parity_v3"
STAGES = ("stage1", "stage2", "stage3")
WINDOW_MINUTES = 5
EXPECTED_STEP_TOTAL = 23

SOURCE_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "cbc_23_chain_stage_cases_2026-06-12.jsonl"
)
OUT_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / f"{SUITE}_stage_cases_{VERSION}.jsonl"
)
OUT_GOLD_ROOT = (
    ROOT / "data/current_experiment/gold" / f"{SUITE}_gold_{VERSION}"
)
OUT_MANIFEST = (
    ROOT / "data/current_experiment/cases" / f"{SUITE}_manifest_{VERSION}.json"
)
OUT_VALIDATION = (
    ROOT / "docs/current_experiment" / f"{SUITE}_build_validation_{VERSION}.json"
)

SOURCE_DATABASE = (
    "Clouseau/artifact/scenarios/atlasv2/benign/h1/benign-1/incident.db"
)

TARGET_COMPONENT_RULE = (
    "Starting from the observed primary-telemetry row at the supplied neutral "
    "anchor, reconstruct the complete evidence-backed semantic component. "
    "Traverse observed parent/child, command-target, network-target, and "
    "materialized-object edges in either direction. Include explicit process "
    "creation, central document/script input, network connection, and a file "
    "materialized for later use. Collapse duplicate sensor rows and repeated "
    "raw lifecycle rows for the same semantic action. Exclude module loads, "
    "MRU/registry/cache housekeeping, and nearby components that are connected "
    "only by time or a shared process name."
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
    "object_type": "object_type",
    "object_name": "object_name",
    "remote_ip": "remote_ip",
    "remote_port": "remote_port",
    "local_ip": "local_ip",
    "local_port": "local_port",
    "netconn_domain": "netconn_domain",
    "childproc_name": "childproc_name",
    "childproc_pid": "childproc_pid",
    "filemod_name": "filemod_name",
    "regmod_name": "regmod_name",
}


# These components were selected before the new model run.  Each primary row
# was checked against the raw benign incident database.  A supporting row is
# provenance for a duplicate/lifecycle record and is not an additional Gold
# action.
CASE_SPECS: list[dict[str, Any]] = [
    {
        "chain_id": "chain_02_e01_python_simplehttpserver_network_chain",
        "focus_process": "cmd.exe",
        "title": "E01: HTTP server batch launch component",
        "category": "http_server_batch_launch",
        "representative_alert_pid": None,
        "steps": [
            {
                "row_id": 45539,
                "subject": "explorer.exe (PID 1612)",
                "action": "started",
                "object": "cmd.exe (PID 336)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 45553,
                "subject": "cmd.exe (PID 336)",
                "action": "executed batch script",
                "object": r"C:\Users\aalsahee\Desktop\run_http_server.bat",
                "evidence_kind": "command_script",
            },
            {
                "row_id": 45554,
                "subject": "cmd.exe (PID 336)",
                "action": "started",
                "object": "python.exe (PID 720)",
                "evidence_kind": "parent_child",
            },
        ],
        "limitations": [
            "No listener or connection row from Python PID 720 is present in this component.",
        ],
    },
    {
        "chain_id": "chain_04_e03_dns_packet_capture_batch_chain",
        "focus_process": "cmd.exe",
        "title": "E03: DNS packet-capture launch component",
        "category": "dns_packet_capture",
        "representative_alert_pid": 3652,
        "steps": [
            {
                "row_id": 996890,
                "supporting_row_ids": [1007854],
                "subject": "explorer.exe (PID 1612)",
                "action": "started",
                "object": "cmd.exe (PID 3652)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 996904,
                "subject": "cmd.exe (PID 3652)",
                "action": "executed batch script",
                "object": r"C:\Users\aalsahee\Desktop\start_dns_logs.bat",
                "evidence_kind": "command_script",
            },
            {
                "row_id": 996905,
                "subject": "cmd.exe (PID 3652)",
                "action": "created directory",
                "object": r"C:\Users\aalsahee\Desktop\logs\dns",
                "evidence_kind": "file",
            },
            {
                "row_id": 996906,
                "supporting_row_ids": [1003480],
                "subject": "cmd.exe (PID 3652)",
                "action": "started",
                "object": "tshark.exe (PID 2496)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 996989,
                "supporting_row_ids": [997034, 997045],
                "subject": "tshark.exe (PID 2496)",
                "action": "started interface-discovery probes",
                "object": "dumpcap.exe (PID 3288; repeated probe PID 2164)",
                "evidence_kind": "parent_child_command",
            },
            {
                "row_id": 997089,
                "supporting_row_ids": [997094, 1010444],
                "subject": "tshark.exe (PID 2496)",
                "action": "started DNS capture worker",
                "object": "dumpcap.exe (PID 2384; UDP port 53)",
                "evidence_kind": "parent_child_command",
            },
            {
                "row_id": 997132,
                "subject": "dumpcap.exe (PID 2384)",
                "action": "created packet-capture file",
                "object": (
                    r"C:\Users\aalsahee\AppData\Local\Temp"
                    r"\wireshark_de145f66-537b-427d-820a-707cc694da57_"
                    r"20220715155212_a02384.pcapng"
                ),
                "evidence_kind": "file",
            },
        ],
        "limitations": [
            "Two short dumpcap -D launches are collapsed into one interface-discovery action.",
        ],
    },
    {
        "chain_id": "chain_05_e03_python_simplehttpserver_network_chain",
        "focus_process": "python.exe",
        "title": "E03: Python SimpleHTTPServer listener component",
        "category": "python_http_listener",
        "representative_alert_pid": None,
        "steps": [
            {
                "row_id": 996752,
                "supporting_row_ids": [998522],
                "subject": "cmd.exe (PID 2032)",
                "action": "started",
                "object": "python.exe (PID 2760)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 996889,
                "supporting_row_ids": [1000413],
                "subject": "python.exe (PID 2760)",
                "action": "listened",
                "object": "0.0.0.0:8000",
                "evidence_kind": "network",
            },
        ],
        "limitations": [
            "Repeated ACTION_LOAD_SCRIPT rows are attributes of the Python action and are not separate Gold actions.",
        ],
    },
    {
        "chain_id": "chain_06_e04_python_simplehttpserver_network_chain",
        "focus_process": "python.exe",
        "title": "E04: Persisting Python HTTP connection component",
        "category": "python_http_connection",
        "representative_alert_pid": None,
        "steps": [
            {
                "row_id": 791951,
                "supporting_row_ids": [1008022],
                "subject": "python.exe (PID 2760)",
                "action": "created network connection",
                "object": "10.193.66.115:58199 from local port 8000",
                "evidence_kind": "network",
            },
        ],
        "limitations": [
            "The server process began on a previous day and is outside this scoped component.",
            "EDR create and NGAV established rows for the same tuple are collapsed.",
        ],
    },
    {
        "chain_id": "chain_09_e07_cmdexe_other_chain",
        "focus_process": "cmd.exe",
        "title": "E07: Discord renderer command launch component",
        "category": "discord_cmd_launch",
        "representative_alert_pid": 4872,
        "steps": [
            {
                "row_id": 428334,
                "supporting_row_ids": [1002384],
                "subject": "Discord.exe (PID 4424)",
                "action": "started",
                "object": "cmd.exe (PID 4872)",
                "evidence_kind": "parent_child",
            },
        ],
        "limitations": [
            "The nvidia-smi text appears only in cmd.exe attributes; no primary child-process row proves nvidia-smi execution.",
            "Discord startup housekeeping and sibling processes are outside this component.",
        ],
    },
    {
        "chain_id": "chain_10_e07_discord_run_key_registry_chain",
        "focus_process": "reg.exe",
        "title": "E07: Discord Run-key registration component",
        "category": "discord_run_key",
        "representative_alert_pid": 2360,
        "steps": [
            {
                "row_id": 410470,
                "supporting_row_ids": [1003635],
                "subject": "Discord.exe (PID 3768)",
                "action": "started",
                "object": "reg.exe (PID 2360)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 997599,
                "supporting_row_ids": [410482],
                "subject": "reg.exe (PID 2360)",
                "action": "wrote registry value",
                "object": (
                    r"HKU\S-1-5-21-450080267-1945256726-3465656282-1000"
                    r"\Software\Microsoft\Windows\CurrentVersion\Run\Discord"
                ),
                "evidence_kind": "registry",
            },
        ],
        "limitations": [
            "The historical Gold query-registry claim is removed because no primary row supports it for PID 2360.",
            "Sibling reg.exe invocations are separate nearby components.",
        ],
    },
    {
        "chain_id": "chain_11_e07_sublime_python_script_execution_chain",
        "focus_process": "cmd.exe",
        "title": "E07: Sublime Text Python script component",
        "category": "sublime_python_script",
        "representative_alert_pid": 4020,
        "steps": [
            {
                "row_id": 1007113,
                "subject": "plugin_host.exe (PID 2676)",
                "action": "started",
                "object": "cmd.exe (PID 4020)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 658321,
                "supporting_row_ids": [1009364],
                "subject": "cmd.exe (PID 4020)",
                "action": "started",
                "object": "python.exe (PID 3984)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 1005805,
                "subject": "cmd.exe (PID 4020)",
                "action": "invoked script",
                "object": r"C:\Users\aalsahee\Documents\hello.py",
                "evidence_kind": "command_script",
            },
        ],
        "limitations": [
            "A second hello.py run with different PIDs is a sibling component and is not joined by time alone.",
        ],
    },
    {
        "chain_id": "chain_24_e18_cmdexe_other_chain",
        "focus_process": "cmd.exe",
        "title": "E18: HTTP batch launch and listener component",
        "category": "http_server_batch_listener",
        "representative_alert_pid": 5576,
        "steps": [
            {
                "row_id": 197602,
                "supporting_row_ids": [998562],
                "subject": "explorer.exe (PID 1612)",
                "action": "started",
                "object": "cmd.exe (PID 5576)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 197616,
                "subject": "cmd.exe (PID 5576)",
                "action": "executed batch script",
                "object": r"C:\Users\aalsahee\Desktop\run_http_server.bat",
                "evidence_kind": "command_script",
            },
            {
                "row_id": 197617,
                "supporting_row_ids": [1003356],
                "subject": "cmd.exe (PID 5576)",
                "action": "started",
                "object": "python.exe (PID 3384)",
                "evidence_kind": "parent_child",
            },
            {
                "row_id": 197753,
                "supporting_row_ids": [998342],
                "subject": "python.exe (PID 3384)",
                "action": "listened",
                "object": "0.0.0.0:8000",
                "evidence_kind": "network",
            },
        ],
        "limitations": [],
    },
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def compact_db_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def normalize_process(value: Any) -> str:
    return str(value or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def db_path() -> Path:
    return ROOT / Path(SOURCE_DATABASE)


def fetch_full_row(connection: sqlite3.Connection, row_id: int) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM cbc_events WHERE id = ?", (row_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"cbc_events row {row_id} is missing")
    result = {
        gold_field: row[db_field]
        for gold_field, db_field in CANONICAL_DB_FIELDS.items()
    }
    result.update({"source_table": "cbc_events", "source_row_id": row_id})
    return result


def row_touches_focus(row: dict[str, Any], focus_process: str) -> bool:
    wanted = normalize_process(focus_process)
    return wanted in {
        normalize_process(row.get("process_path")),
        normalize_process(row.get("parent_path")),
        normalize_process(row.get("childproc_name")),
        normalize_process(row.get("object_name"))
        if row.get("object_type") == "Process"
        else "",
    }


def evidence_target(row: dict[str, Any]) -> Any:
    action = str(row.get("action") or "")
    if "CREATE_PROCESS" in action:
        return row.get("childproc_pid") or row.get("object_name")
    if "CONNECTION" in action:
        if row.get("remote_ip"):
            return f"{row.get('remote_ip')}:{row.get('remote_port')}"
        return f"{row.get('local_ip')}:{row.get('local_port')}"
    if row.get("filemod_name"):
        return row["filemod_name"]
    if row.get("regmod_name"):
        return row["regmod_name"]
    if "LOAD_SCRIPT" in action:
        return row.get("process_cmdline")
    return row.get("object_name")


def evidence_basis(row: dict[str, Any]) -> str:
    return (
        f"cbc_events row {row['source_row_id']} at {row['timestamp_utc']}; "
        f"process_pid={row.get('process_pid')}; action={row.get('action')}; "
        f"target={evidence_target(row)}"
    )


def evidence_signature(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_table": "cbc_events",
        "source_row_id": row["source_row_id"],
        "timestamp_utc": row["timestamp_utc"],
        "action_family": row["action"],
        "process_pid": row.get("process_pid"),
        "target_key": evidence_target(row),
    }


def sample_log(row: dict[str, Any]) -> str:
    return (
        f"cbc_events row_id={row['source_row_id']} time={row['timestamp_utc']} "
        f"stream={row['source_stream']} action={row['action']} "
        f"process={row.get('process_path')} pid={row.get('process_pid')} "
        f"object={row.get('object_name')} child_pid={row.get('childproc_pid')} "
        f"remote={row.get('remote_ip')}:{row.get('remote_port')} "
        f"local={row.get('local_ip')}:{row.get('local_port')}"
    )


def scoring_template() -> dict[str, Any]:
    return {
        "subject": {"max": 1, "score": None, "note": ""},
        "action": {"max": 1, "score": None, "note": ""},
        "object": {"max": 1, "score": None, "note": ""},
        "action_component_total": {"max": 3, "score": None},
        "critical_evidence_diagnostic": {
            "max": 1,
            "score": None,
            "included_in_action_total": False,
        },
    }


def select_representative_alert(
    source_case: dict[str, Any], expected_pid: int | None
) -> dict[str, Any]:
    alerts = copy.deepcopy(source_case.get("input_alert_rows") or [])
    if not alerts:
        raise ValueError(f"{source_case['chain_id']}: no representative alert")
    if expected_pid is None:
        return alerts[0]
    matching = [alert for alert in alerts if alert.get("pid") == expected_pid]
    if not matching:
        raise ValueError(
            f"{source_case['chain_id']}: alert PID {expected_pid} is missing"
        )
    return matching[0]


def build_gold_and_scope(
    spec: dict[str, Any],
    chain_number: int,
    representative_alert: dict[str, Any],
    connection: sqlite3.Connection,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    rows_by_id: dict[int, dict[str, Any]] = {}
    supporting_ids: set[int] = set()
    for step_spec in spec["steps"]:
        row_id = int(step_spec["row_id"])
        rows_by_id[row_id] = fetch_full_row(connection, row_id)
        for value in step_spec.get("supporting_row_ids", []):
            supporting_id = int(value)
            supporting_ids.add(supporting_id)
            fetch_full_row(connection, supporting_id)

    steps: list[dict[str, Any]] = []
    for order, step_spec in enumerate(spec["steps"], 1):
        row = rows_by_id[int(step_spec["row_id"])]
        step_id = f"N8V3-{chain_number:02d}-S{order:02d}"
        steps.append(
            {
                "step_id": step_id,
                "order": order,
                "subject": step_spec["subject"],
                "action": step_spec["action"],
                "object": step_spec["object"],
                "evidence_kind": step_spec["evidence_kind"],
                "evidence_basis": evidence_basis(row),
                "confidence": "observed",
                "one_line_ja": (
                    f"{step_spec['subject']} が {step_spec['action']} "
                    f"{step_spec['object']}。"
                ),
                "process_code_object": step_spec["object"],
                "scoring_template": scoring_template(),
                "canonical_evidence": [row],
                "supporting_evidence": {
                    "source_types": ["CBC primary telemetry"],
                    "sample_logs": [sample_log(row)],
                    "supporting_source_row_ids": [
                        int(value)
                        for value in step_spec.get("supporting_row_ids", [])
                    ],
                },
                "critical_evidence_signature": evidence_signature(row),
            }
        )

    canonical_rows = [
        row for step in steps for row in step["canonical_evidence"]
    ]
    focus_rows = [
        row
        for row in canonical_rows
        if row_touches_focus(row, str(spec["focus_process"]))
    ]
    if not focus_rows:
        raise ValueError(
            f"{spec['chain_id']}: no canonical row touches {spec['focus_process']}"
        )
    component_start = min(
        parse_time(str(row["timestamp_utc"])) for row in canonical_rows
    )
    anchor_row = min(
        focus_rows, key=lambda row: parse_time(str(row["timestamp_utc"]))
    )
    window_start = iso_time(component_start)
    window_end = iso_time(component_start + timedelta(minutes=WINDOW_MINUTES))
    anchor = {
        "timestamp_utc": anchor_row["timestamp_utc"],
        "database_time": compact_db_time(str(anchor_row["timestamp_utc"])),
        "source_stream": anchor_row["source_stream"],
        "source_table": "cbc_events",
        "source_row_id": anchor_row["source_row_id"],
        "process_name": spec["focus_process"],
        "selection_policy": (
            "earliest canonical primary-telemetry row that actually touches "
            "the declared focus process"
        ),
        "touches_declared_focus_process": True,
    }
    audit_primary_ids = [int(item["row_id"]) for item in spec["steps"]]
    gold = {
        "chain_id": spec["chain_id"],
        "chain_title": spec["title"],
        "case_group": "normal_behavior_observable_component",
        "case_kind": "unique_process_time_cluster",
        "source_database": SOURCE_DATABASE,
        "scenario": "atlasv2-benign-h1",
        "chain_type": spec["category"],
        "chain_description": spec["title"],
        "observed_behavior": spec["title"],
        "stage3_visibility_policy": (
            "Gold steps use canonical cbc_events telemetry only. CBC alert "
            "summary fields are not evidence for a Stage 3-scored claim."
        ),
        "stages_present": list(STAGES),
        "input_scope": {
            "host": "WIN-32-H1",
            "focus_processes": [spec["focus_process"]],
            "chain_window_start_utc": window_start,
            "chain_window_end_utc": window_end,
            "window_minutes": WINDOW_MINUTES,
            "window_selection_policy": (
                "five-minute component-complete window starting at the first "
                "canonical component row"
            ),
            "input_policy": (
                "All stages use identical host, focus process, neutral anchor, "
                "five-minute window, component rule, and Gold. Stage 1 alone "
                "adds one observed alert clue. Hidden alert correspondence is not scored."
            ),
            "neutral_anchor_utc": anchor["timestamp_utc"],
            "neutral_anchor_policy": anchor["selection_policy"],
            "target_component_rule": TARGET_COMPONENT_RULE,
        },
        "alert_timing": {
            "representative_alert_time_utc": representative_alert.get("time"),
            "neutral_anchor_utc": anchor["timestamp_utc"],
            "chain_window_start_utc": window_start,
            "chain_window_end_utc": window_end,
            "note": (
                "Alert time may lag primary telemetry and is a Stage-1 clue "
                "only. Alert-to-component correspondence is outside the score."
            ),
        },
        "behavior_timeline": copy.deepcopy(steps),
        "gold_steps": copy.deepcopy(steps),
        "gold_order_pairs": [
            [steps[index]["step_id"], steps[index + 1]["step_id"]]
            for index in range(len(steps) - 1)
        ],
        "evidence_span_utc": {
            "start": min(row["timestamp_utc"] for row in canonical_rows),
            "end": max(row["timestamp_utc"] for row in canonical_rows),
        },
        "limitations": copy.deepcopy(spec["limitations"]),
        "case_scoring": {
            "action_component_denominator": len(steps) * 3,
            "action_components": ["subject", "action", "object"],
            "critical_evidence_diagnostic_denominator": len(steps),
            "critical_evidence_in_action_denominator": False,
            "order_pair_denominator": max(0, len(steps) - 1),
            "candidate_precision_policy": (
                "literal included candidate action slots; command_line is "
                "an action attribute and is not a separate candidate slot"
            ),
        },
        "evaluation_unit": "observable semantic component",
        "suite_group": SUITE,
        "paired_stage_contract": {
            "contract_version": CONTRACT_VERSION,
            "evaluation_unit": "observable semantic component",
            "same_gold_all_stages": True,
            "same_neutral_anchor_all_stages": True,
            "same_five_minute_window_all_stages": True,
            "target_component_rule": TARGET_COMPONENT_RULE,
            "alert_mapping_scored": False,
            "hard_time_scope": False,
            "critical_evidence_separate_diagnostic": True,
        },
        "scoring_exclusions": [
            "inferring which unavailable CBC alert corresponds to the Gold chain",
            "predicting a hidden alert id, alert title, alert reason, or alert-to-chain mapping",
            "using alert-summary text as a substitute for primary behavior evidence",
            "scoring command_line as an independent candidate action slot",
        ],
        "gold_exhaustiveness_audit": {
            "status": "pass",
            "auditor_role": "row-level primary-telemetry audit before model run",
            "policy": (
                "Audit central script inputs, explicit process edges, network "
                "edges, registry/file effects, and materialized objects; "
                "exclude module loads, duplicate lifecycle rows, housekeeping, "
                "and nearby PID-disconnected components."
            ),
            "expected_primary_row_ids": audit_primary_ids,
            "supporting_duplicate_or_lifecycle_row_ids": sorted(supporting_ids),
        },
    }
    return gold, anchor, window_start, window_end


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


def build_case(
    source: dict[str, Any],
    spec: dict[str, Any],
    gold: dict[str, Any],
    gold_file: str,
    representative_alert: dict[str, Any],
    anchor: dict[str, Any],
    window_start: str,
    window_end: str,
    stage: str,
    chain_number: int,
) -> dict[str, Any]:
    case = copy.deepcopy(source)
    chain_id = str(spec["chain_id"])
    instance_id = f"{chain_id}_{stage}"
    alerts = [copy.deepcopy(representative_alert)] if stage == "stage1" else []
    model_input: dict[str, Any] = {
        "host": "WIN-32-H1",
        "focus_processes": [spec["focus_process"]],
        "neutral_anchor_utc": anchor["timestamp_utc"],
        "chain_window_start_utc": window_start,
        "chain_window_end_utc": window_end,
        "target_component_rule": TARGET_COMPONENT_RULE,
        "alert_mapping_scored": False,
    }
    if stage == "stage1":
        model_input["alerts"] = copy.deepcopy(alerts)
    case.update(
        {
            "chain_id": chain_id,
            "chain_type": spec["category"],
            "instance_id": instance_id,
            "case_id": instance_id,
            "input_id": f"normal8_observable_v3_{chain_number:02d}_{stage}",
            "stage": stage,
            "scenario": "atlasv2-benign-h1",
            "database": SOURCE_DATABASE,
            "host": "WIN-32-H1",
            "process_name": spec["focus_process"],
            "actor": spec["focus_process"],
            "difficulty": "alert_input" if stage == "stage1" else "process_time",
            "context_label": "normal_behavior_observable_component",
            "suite_group": SUITE,
            "quality": "observable_component_normal_parity_v3_20260726",
            "expected_behavior": spec["title"],
            "expected_behavior_category": spec["category"],
            "time_window_utc": {
                "episode_start": window_start,
                "episode_end": window_end,
                "analysis_scope": (
                    "Reference/exploration scope for the complete observable "
                    "semantic component; not an exhaustive audit-row checklist."
                ),
            },
            "anchor_event": neutral_anchor_event(anchor),
            "investigation_time_anchor_utc": anchor["timestamp_utc"],
            "investigation_time_anchor_policy": anchor["selection_policy"],
            "neutral_anchor_all_stages": True,
            "neutral_anchor_provenance": copy.deepcopy(anchor),
            "input_alert_rows": alerts,
            "model_ready_input": {
                "input_id": f"normal8_observable_v3_{chain_number:02d}",
                "stage": stage,
                "input": model_input,
            },
            "gold_chain_file": gold_file,
            "formal_gold_root": str(OUT_GOLD_ROOT.relative_to(ROOT)),
            "stage_input_policy": (
                "Stage 1: common neutral process/time scope plus one observed "
                "alert clue; hidden alert mapping is not scored."
                if stage == "stage1"
                else (
                    "Stage 2: common neutral process/time scope; alert summaries "
                    "may be discovered but their mapping is not scored."
                    if stage == "stage2"
                    else (
                        "Stage 3: common neutral process/time scope; alert summaries "
                        "are unavailable and their mapping is not scored."
                    )
                )
            ),
            "stage3_answerable_policy": (
                "Every scored item is supported by primary cbc_events telemetry "
                "and the target boundary is observable without alert summaries."
            ),
            "paired_stage_contract": copy.deepcopy(gold["paired_stage_contract"])
            | {"chain_index": chain_number},
        }
    )
    case.pop("enforce_time_scope", None)
    case.pop("input_provenance", None)
    if stage == "stage3":
        case["model_ready_input"]["db_filter"] = (
            "hide cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; "
            "retain primary cbc_events telemetry"
        )
    else:
        case["model_ready_input"].pop("db_filter", None)
    return case


def values_equal(gold_value: Any, db_value: Any) -> bool:
    if gold_value is None or db_value is None:
        return gold_value is None and db_value is None
    return gold_value == db_value or str(gold_value) == str(db_value)


def validate(
    cases: list[dict[str, Any]],
    gold_by_chain: dict[str, dict[str, Any]],
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    comparisons = 0
    stage_counts = Counter(case["stage"] for case in cases)
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        failures.append({"check": "stage_counts", "actual": dict(stage_counts)})
    if len(cases) != 24 or len({case["instance_id"] for case in cases}) != 24:
        failures.append({"check": "case_identity", "case_count": len(cases)})
    if len(gold_by_chain) != 8:
        failures.append({"check": "chain_count", "actual": len(gold_by_chain)})

    total_steps = 0
    chain_reports: list[dict[str, Any]] = []
    for chain_id, gold in gold_by_chain.items():
        steps = gold["gold_steps"]
        total_steps += len(steps)
        canonical_rows = [
            row for step in steps for row in step.get("canonical_evidence") or []
        ]
        expected_ids = {
            int(value)
            for value in gold["gold_exhaustiveness_audit"][
                "expected_primary_row_ids"
            ]
        }
        actual_ids = {int(row["source_row_id"]) for row in canonical_rows}
        if actual_ids != expected_ids or len(canonical_rows) != len(steps):
            failures.append(
                {
                    "check": "one_canonical_row_per_step",
                    "chain_id": chain_id,
                    "expected": sorted(expected_ids),
                    "actual": sorted(actual_ids),
                    "row_count": len(canonical_rows),
                    "step_count": len(steps),
                }
            )
        paired = [case for case in cases if case["chain_id"] == chain_id]
        signatures = {
            (
                case["host"],
                case["process_name"],
                case["investigation_time_anchor_utc"],
                case["time_window_utc"]["episode_start"],
                case["time_window_utc"]["episode_end"],
                case["gold_chain_file"],
                json.dumps(case["paired_stage_contract"], sort_keys=True),
            )
            for case in paired
        }
        if len(paired) != 3 or len(signatures) != 1:
            failures.append(
                {"check": "same_contract_all_stages", "chain_id": chain_id}
            )
            continue
        stage_visibility = {
            case["stage"]: len(case.get("input_alert_rows") or [])
            for case in paired
        }
        if stage_visibility != {"stage1": 1, "stage2": 0, "stage3": 0}:
            failures.append(
                {
                    "check": "stage_alert_visibility",
                    "chain_id": chain_id,
                    "actual": stage_visibility,
                }
            )
        start = parse_time(paired[0]["time_window_utc"]["episode_start"])
        end = parse_time(paired[0]["time_window_utc"]["episode_end"])
        coverage = all(
            start <= parse_time(str(row["timestamp_utc"])) <= end
            for row in canonical_rows
        )
        alert_time = parse_time(
            str(
                next(
                    case
                    for case in paired
                    if case["stage"] == "stage1"
                )["input_alert_rows"][0]["time"]
            )
        )
        alert_inside = start <= alert_time <= end
        if end - start != timedelta(minutes=5) or not coverage or not alert_inside:
            failures.append(
                {
                    "check": "five_minute_scope",
                    "chain_id": chain_id,
                    "gold_inside": coverage,
                    "representative_alert_inside": alert_inside,
                }
            )
        anchor = paired[0]["neutral_anchor_provenance"]
        anchor_rows = [
            row
            for row in canonical_rows
            if int(row["source_row_id"]) == int(anchor["source_row_id"])
        ]
        anchor_touches = (
            len(anchor_rows) == 1
            and row_touches_focus(anchor_rows[0], paired[0]["process_name"])
        )
        if not anchor_touches:
            failures.append(
                {"check": "anchor_touches_focus", "chain_id": chain_id}
            )
        expected_pairs = [
            [steps[index]["step_id"], steps[index + 1]["step_id"]]
            for index in range(len(steps) - 1)
        ]
        if gold["gold_order_pairs"] != expected_pairs:
            failures.append(
                {"check": "adjacent_order_pairs", "chain_id": chain_id}
            )
        for row in canonical_rows:
            db_row = connection.execute(
                "SELECT * FROM cbc_events WHERE id = ?",
                (int(row["source_row_id"]),),
            ).fetchone()
            if db_row is None:
                mismatches.append(
                    {
                        "chain_id": chain_id,
                        "source_row_id": row["source_row_id"],
                        "field": "row",
                    }
                )
                continue
            for gold_field, db_field in CANONICAL_DB_FIELDS.items():
                comparisons += 1
                if not values_equal(row.get(gold_field), db_row[db_field]):
                    mismatches.append(
                        {
                            "chain_id": chain_id,
                            "source_row_id": row["source_row_id"],
                            "field": gold_field,
                            "gold": row.get(gold_field),
                            "database": db_row[db_field],
                        }
                    )
        chain_reports.append(
            {
                "chain_id": chain_id,
                "step_count": len(steps),
                "canonical_primary_row_ids": sorted(actual_ids),
                "neutral_anchor_row_id": anchor["source_row_id"],
                "anchor_touches_focus": anchor_touches,
                "five_minute_window_covers_gold": coverage,
                "representative_stage1_alert_inside_window": alert_inside,
                "stage3_identifiable_without_alert_mapping": True,
                "gold_exhaustiveness_audit": "pass",
            }
        )

    if total_steps != EXPECTED_STEP_TOTAL:
        failures.append(
            {
                "check": "gold_step_total",
                "expected": EXPECTED_STEP_TOTAL,
                "actual": total_steps,
            }
        )
    if mismatches:
        failures.append(
            {
                "check": "canonical_database_equality",
                "mismatch_count": len(mismatches),
            }
        )
    return {
        "status": "pass" if not failures else "fail",
        "suite": SUITE,
        "contract_version": CONTRACT_VERSION,
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "chain_count": len(gold_by_chain),
        "gold_step_count_unique": total_steps,
        "gold_step_count_across_stages": total_steps * len(STAGES),
        "canonical_primary_row_count_unique": sum(
            len(gold["gold_steps"]) for gold in gold_by_chain.values()
        ),
        "source_database_field_comparisons": comparisons,
        "source_database_mismatch_count": len(mismatches),
        "source_database_mismatches": mismatches,
        "alert_mapping_scored": False,
        "critical_evidence_separate_diagnostic": True,
        "command_line_independent_candidate_slot": False,
        "stage3_identifiable_chain_count": sum(
            report["stage3_identifiable_without_alert_mapping"]
            for report in chain_reports
        ),
        "gold_exhaustiveness_pass_chain_count": sum(
            report["gold_exhaustiveness_audit"] == "pass"
            for report in chain_reports
        ),
        "chain_reports": chain_reports,
        "failures": failures,
    }


def ensure_fresh(paths: list[Path]) -> None:
    existing = [str(path) for path in paths if path.exists()]
    if existing:
        raise FileExistsError(
            "Refusing to overwrite versioned normal-v3 artifacts: "
            + ", ".join(existing)
        )


def main() -> None:
    global OUT_GOLD_ROOT

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cases", type=Path, default=SOURCE_CASES)
    parser.add_argument("--out-cases", type=Path, default=OUT_CASES)
    parser.add_argument("--out-gold-root", type=Path, default=OUT_GOLD_ROOT)
    parser.add_argument("--manifest", type=Path, default=OUT_MANIFEST)
    parser.add_argument("--validation", type=Path, default=OUT_VALIDATION)
    args = parser.parse_args()
    OUT_GOLD_ROOT = args.out_gold_root

    source_cases = read_jsonl(args.source_cases)
    source_stage1 = {
        case["chain_id"]: case
        for case in source_cases
        if case.get("stage") == "stage1"
    }
    missing_sources = [
        spec["chain_id"]
        for spec in CASE_SPECS
        if spec["chain_id"] not in source_stage1
    ]
    if missing_sources:
        raise ValueError(f"source Stage-1 cases are missing: {missing_sources}")

    connection = sqlite3.connect(db_path())
    connection.row_factory = sqlite3.Row
    try:
        cases: list[dict[str, Any]] = []
        gold_by_chain: dict[str, dict[str, Any]] = {}
        gold_index: list[dict[str, Any]] = []
        for chain_number, spec in enumerate(CASE_SPECS, 1):
            source_case = source_stage1[spec["chain_id"]]
            alert = select_representative_alert(
                source_case, spec["representative_alert_pid"]
            )
            gold, anchor, window_start, window_end = build_gold_and_scope(
                spec, chain_number, alert, connection
            )
            gold_by_chain[spec["chain_id"]] = gold
            gold_file = f"by_chain/{spec['chain_id']}/chain_gold.json"
            gold_index.append(
                {
                    "chain_id": spec["chain_id"],
                    "gold_chain_file": gold_file,
                    "source_historical_case": source_case["instance_id"],
                    "neutral_anchor_utc": anchor["timestamp_utc"],
                    "neutral_anchor_source_row_id": anchor["source_row_id"],
                    "neutral_anchor_touches_focus_process": True,
                    "window_start_utc": window_start,
                    "window_end_utc": window_end,
                    "representative_stage1_alert_time_utc": alert["time"],
                    "gold_step_count": len(gold["gold_steps"]),
                    "alert_mapping_scored": False,
                    "gold_sha256": sha256_value(gold),
                }
            )
            for stage in STAGES:
                cases.append(
                    build_case(
                        source_case,
                        spec,
                        gold,
                        gold_file,
                        alert,
                        anchor,
                        window_start,
                        window_end,
                        stage,
                        chain_number,
                    )
                )
        validation = validate(cases, gold_by_chain, connection)
    finally:
        connection.close()

    if validation["status"] != "pass":
        raise SystemExit(
            json.dumps(
                {"status": "fail", "failures": validation["failures"]},
                ensure_ascii=False,
                indent=2,
            )
        )

    ensure_fresh(
        [args.out_cases, args.out_gold_root, args.manifest, args.validation]
    )
    for item in gold_index:
        gold_path = args.out_gold_root / item["gold_chain_file"]
        write_json(gold_path, gold_by_chain[item["chain_id"]])
    write_json(args.out_gold_root / "chain_gold_index.json", gold_index)
    args.out_cases.parent.mkdir(parents=True, exist_ok=True)
    args.out_cases.write_text(
        "".join(
            json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n"
            for case in cases
        ),
        encoding="utf-8",
    )
    write_json(args.validation, validation)
    write_json(
        args.manifest,
        {
            "suite": SUITE,
            "contract_version": CONTRACT_VERSION,
            "purpose": (
                "Evaluate normal behavior reconstruction under the same "
                "observable action/component meaning and scoring used by attack v3."
            ),
            "source_historical_case_file": str(args.source_cases.relative_to(ROOT)),
            "source_database": SOURCE_DATABASE,
            "case_file": str(args.out_cases.relative_to(ROOT)),
            "gold_root": str(args.out_gold_root.relative_to(ROOT)),
            "stage_counts": {stage: 8 for stage in STAGES},
            "total_model_inputs": len(cases),
            "evaluation_unit": "eight observable semantic components",
            "window_policy": (
                "five-minute component-complete reference/exploration scope; "
                "identical across stages"
            ),
            "neutral_anchor_policy": (
                "earliest canonical primary row touching the declared focus process"
            ),
            "metric_contract": {
                "action_components": ["subject", "action", "object"],
                "critical_evidence": "separate diagnostic",
                "order": "adjacent Gold-pair recall",
                "candidate_precision": (
                    "literal included candidate action-slot precision with "
                    "duplicate TP rate reported separately"
                ),
                "command_line": "action attribute, not an independent candidate slot",
                "hidden_alert_mapping": "excluded",
            },
            "agent_call_limit_policy": "unbounded_by_experiment",
            "gold_step_count_unique": EXPECTED_STEP_TOTAL,
            "gold_index": gold_index,
            "validation": str(args.validation.relative_to(ROOT)),
            "historical_artifacts_modified": False,
        },
    )
    print(
        json.dumps(
            {
                "status": "pass",
                "cases": str(args.out_cases),
                "case_count": len(cases),
                "stage_counts": dict(Counter(case["stage"] for case in cases)),
                "gold_step_count_unique": validation["gold_step_count_unique"],
                "stage3_identifiable_chain_count": validation[
                    "stage3_identifiable_chain_count"
                ],
                "gold_exhaustiveness_pass_chain_count": validation[
                    "gold_exhaustiveness_pass_chain_count"
                ],
                "source_database_field_comparisons": validation[
                    "source_database_field_comparisons"
                ],
                "alert_mapping_scored": False,
                "validation": str(args.validation),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
