#!/usr/bin/env python3
"""Build the observable-component v3 ATLASv2 attack reconstruction suite.

The legacy 45-step Gold was accurate for the rows that it cited, but it was
not exhaustive under the neutral-anchor semantic-component contract.  It also
merged two unconnected S4 Word clusters and selected one neutral anchor from a
row that did not touch the declared focus process.

This builder preserves v1/v2 artifacts and creates a new version in which:

* the scored target is determined only from visible primary telemetry;
* hidden CBC alert identity/title/reason/mapping is never scored;
* a neutral anchor must actually touch the declared focus process;
* the five-minute scope covers the whole observable component;
* different anchors into the same component use identical Gold;
* duplicate sensor/lifecycle rows collapse into one semantic action;
* every Gold step has one concrete canonical CBC row fingerprint.
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
SOURCE_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_neutral5_parity_v2_stage_cases_20260726.jsonl"
)
SOURCE_GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "atlasv2_s3_s4_attack8_neutral5_parity_v2_gold_20260726"
)
SUITE = "atlasv2_s3_s4_attack8_observable_component_v3"
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
    ROOT
    / "docs/current_experiment"
    / f"{SUITE}_build_validation_{VERSION}.json"
)

STAGES = ("stage1", "stage2", "stage3")
WINDOW_MINUTES = 5
CONTRACT_VERSION = "observable_component_normal_parity_v3"
EXPECTED_STEP_TOTAL = 59

TARGET_COMPONENT_RULE = (
    "Starting from the observed primary-telemetry row at the supplied neutral "
    "anchor, reconstruct the complete evidence-backed semantic component. "
    "Traverse observed parent/child, command-target, network-target, and "
    "materialized-object edges in either direction. Include explicit process "
    "creation, central document/script input, network connection, and a file "
    "materialized for later execution. Collapse duplicate sensor rows and "
    "consecutive raw lifecycle rows for the same semantic action. Exclude "
    "module loads, MRU/registry/cache housekeeping, and nearby components that "
    "are connected only by time or a shared process name."
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
    "object_name": "object_name",
    "remote_ip": "remote_ip",
    "remote_port": "remote_port",
    "netconn_domain": "netconn_domain",
    "childproc_name": "childproc_name",
    "childproc_pid": "childproc_pid",
}

RENAMED_CHAIN = {
    "s4_pt_02_word_w2_w3": "s4_pt_02_word_w2",
}

# New semantic steps established by the independent database exhaustiveness
# audit.  Only the first row is the canonical scoring fingerprint.  Additional
# row ids are retained as supporting duplicate/lifecycle provenance.
ADDITIONS: dict[str, list[dict[str, Any]]] = {
    "s3_pt_01_word_document_processing": [
        {
            "row_id": 8727,
            "supporting_row_ids": [21159],
            "subject": "WINWORD.EXE (PID 5592)",
            "action": "started",
            "object": "WINWORD.EXE (PID 3368)",
            "evidence_kind": "parent_child",
            "one_line_ja": "Word PID 5592 が文書処理用の子 Word PID 3368 を起動した。",
        }
    ],
    "s3_pt_03_regsvr32_long_chain": [
        {
            "row_id": 17849,
            "subject": "regsvr32.exe (PID 3992)",
            "action": "initiated connection",
            "object": "ortrta.net / 10.193.66.115:8080",
            "evidence_kind": "network",
            "one_line_ja": "regsvr32 が remote SCT 取得先へ接続した。",
        },
        {
            "row_id": 17855,
            "subject": "regsvr32.exe (PID 3992)",
            "action": "materialized remote SCT",
            "object": (
                r"C:\Users\aalsahee\AppData\Local\Microsoft\Windows\Temporary "
                r"Internet Files\Content.IE5\CKKIICUI\sF5riGj4K26DK[1].sct"
            ),
            "evidence_kind": "file",
            "one_line_ja": "regsvr32 が取得したSCTをローカルキャッシュへ生成した。",
        },
        {
            "row_id": 18346,
            "supporting_row_ids": [18347, 21284],
            "subject": "powershell.exe (PID 2340)",
            "action": "materialized",
            "object": r"C:\Users\aalsahee\payload.exe",
            "evidence_kind": "file",
            "one_line_ja": "PowerShell が後続実行される payload.exe を生成した。",
        },
    ],
    "s3_pt_04_powershell_mid_chain": [
        {
            "row_id": 17849,
            "subject": "regsvr32.exe (PID 3992)",
            "action": "initiated connection",
            "object": "ortrta.net / 10.193.66.115:8080",
            "evidence_kind": "network",
            "one_line_ja": "regsvr32 が remote SCT 取得先へ接続した。",
        },
        {
            "row_id": 17855,
            "subject": "regsvr32.exe (PID 3992)",
            "action": "materialized remote SCT",
            "object": (
                r"C:\Users\aalsahee\AppData\Local\Microsoft\Windows\Temporary "
                r"Internet Files\Content.IE5\CKKIICUI\sF5riGj4K26DK[1].sct"
            ),
            "evidence_kind": "file",
            "one_line_ja": "regsvr32 が取得したSCTをローカルキャッシュへ生成した。",
        },
        {
            "row_id": 18346,
            "supporting_row_ids": [18347, 21284],
            "subject": "powershell.exe (PID 2340)",
            "action": "materialized",
            "object": r"C:\Users\aalsahee\payload.exe",
            "evidence_kind": "file",
            "one_line_ja": "PowerShell が後続実行される payload.exe を生成した。",
        },
    ],
    "s4_pt_01_word_w1": [
        {
            "row_id": 7971,
            "subject": "winword.exe (PID 3236)",
            "action": "opened/read",
            "object": r"C:\Users\aalsahee\Downloads\s4-at-night\msf.doc",
            "evidence_kind": "file",
            "one_line_ja": "Word が対象文書 msf.doc を開いた。",
        }
    ],
    "s4_pt_02_word_w2": [
        {
            "row_id": 4616,
            "subject": "winword.exe (PID 5980)",
            "action": "opened/read",
            "object": r"C:\Users\aalsahee\Downloads\s4-at-night\msf.doc",
            "evidence_kind": "file",
            "one_line_ja": "Word PID 5980 が対象文書 msf.doc を開いた。",
        }
    ],
    "s4_pt_03_mshta_c1": [
        {
            "row_id": 3633,
            "supporting_row_ids": [15824],
            "subject": "mshta.exe (PID 4724)",
            "action": "materialized HTA",
            "object": (
                r"C:\Users\aalsahee\AppData\Local\Microsoft\Windows\Temporary "
                r"Internet Files\Content.IE5\CKKIICUI\default[1].hta"
            ),
            "evidence_kind": "file",
            "one_line_ja": "mshta が取得したHTAをローカルキャッシュへ生成した。",
        },
        {
            "row_id": 13107,
            "supporting_row_ids": [13138, 15754],
            "subject": "powershell.exe (PID 3820)",
            "action": "materialized",
            "object": r"C:\Users\aalsahee\payload.exe",
            "evidence_kind": "file",
            "one_line_ja": "PowerShell が後続実行される payload.exe を生成した。",
        },
    ],
    "s4_pt_04_powershell_c1": [
        {
            "row_id": 3633,
            "supporting_row_ids": [15824],
            "subject": "mshta.exe (PID 4724)",
            "action": "materialized HTA",
            "object": (
                r"C:\Users\aalsahee\AppData\Local\Microsoft\Windows\Temporary "
                r"Internet Files\Content.IE5\CKKIICUI\default[1].hta"
            ),
            "evidence_kind": "file",
            "one_line_ja": "mshta が取得したHTAをローカルキャッシュへ生成した。",
        },
        {
            "row_id": 13107,
            "supporting_row_ids": [13138, 15754],
            "subject": "powershell.exe (PID 3820)",
            "action": "materialized",
            "object": r"C:\Users\aalsahee\payload.exe",
            "evidence_kind": "file",
            "one_line_ja": "PowerShell が後続実行される payload.exe を生成した。",
        },
    ],
}

EXPECTED_PRIMARY_ROWS = {
    "s3_pt_01_word_document_processing": {8705, 8727, 8767, 8041},
    "s3_pt_02_regsvr32_remote_sct": {7814, 7829, 7889},
    "s3_pt_03_regsvr32_long_chain": {
        17797,
        17849,
        17855,
        17863,
        18136,
        18152,
        18346,
        18350,
        18358,
        18470,
        18558,
    },
    "s3_pt_04_powershell_mid_chain": {
        17797,
        17849,
        17855,
        17863,
        18136,
        18152,
        18346,
        18350,
        18358,
        18470,
        18558,
    },
    "s4_pt_01_word_w1": {7566, 7971, 7986, 8124},
    "s4_pt_02_word_w2": {4543, 4616, 4636, 516},
    "s4_pt_03_mshta_c1": {
        3500,
        3623,
        3633,
        3640,
        3793,
        12843,
        13107,
        13141,
        13187,
        13300,
        11453,
    },
    "s4_pt_04_powershell_c1": {
        3500,
        3623,
        3633,
        3640,
        3793,
        12843,
        13107,
        13141,
        13187,
        13300,
        11453,
    },
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def compact_db_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def normalize_process(value: Any) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def db_path(gold: dict[str, Any]) -> Path:
    return ROOT / Path(str(gold["source_database"]).replace("\\", "/"))


def fetch_row(gold: dict[str, Any], row_id: int) -> dict[str, Any]:
    connection = sqlite3.connect(db_path(gold))
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM cbc_events WHERE id = ?", (row_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError(f"{gold['chain_id']}: cbc_events row {row_id} missing")
    return {
        gold_field: row[db_field]
        for gold_field, db_field in CANONICAL_DB_FIELDS.items()
    } | {
        "source_table": "cbc_events",
        "source_row_id": row_id,
    }


def process_touches(evidence: dict[str, Any], process_name: str) -> bool:
    wanted = normalize_process(process_name)
    return any(
        normalize_process(evidence.get(field)) == wanted
        for field in ("process_path", "parent_path", "childproc_name", "object_name")
        if evidence.get(field)
    )


def evidence_kind(evidence: dict[str, Any]) -> str:
    action = str(evidence.get("action") or "")
    if "CONNECTION" in action:
        return "network"
    if "CREATE_PROCESS" in action:
        return "parent_child"
    if "FILE" in action:
        return "file"
    return "telemetry"


def evidence_signature(evidence: dict[str, Any]) -> dict[str, Any]:
    target_key = (
        evidence.get("childproc_pid")
        or evidence.get("object_name")
        or (
            f"{evidence.get('remote_ip')}:{evidence.get('remote_port')}"
            if evidence.get("remote_ip")
            else None
        )
    )
    return {
        "source_table": evidence["source_table"],
        "source_row_id": evidence["source_row_id"],
        "timestamp_utc": evidence["timestamp_utc"],
        "action_family": evidence["action"],
        "process_pid": evidence["process_pid"],
        "target_key": target_key,
    }


def evidence_basis(evidence: dict[str, Any]) -> str:
    signature = evidence_signature(evidence)
    return (
        f"cbc_events row {signature['source_row_id']} at "
        f"{signature['timestamp_utc']}; process_pid={signature['process_pid']}; "
        f"action={signature['action_family']}; target={signature['target_key']}"
    )


def sample_log(evidence: dict[str, Any]) -> str:
    fields = [
        f"cbc_events row_id={evidence['source_row_id']}",
        f"time={evidence['timestamp_utc']}",
        f"stream={evidence['source_stream']}",
        f"action={evidence['action']}",
        f"process={evidence['process_path']}",
        f"pid={evidence['process_pid']}",
        f"object={evidence['object_name']}",
    ]
    if evidence.get("childproc_pid") is not None:
        fields.append(f"child_pid={evidence['childproc_pid']}")
    if evidence.get("remote_ip"):
        fields.append(
            f"remote={evidence['remote_ip']}:{evidence.get('remote_port')}"
        )
    return " ".join(fields)


def normalized_step(
    step: dict[str, Any],
    chain_number: int,
    order: int,
) -> dict[str, Any]:
    result = copy.deepcopy(step)
    prior_id = str(result.get("step_id") or "")
    evidence = copy.deepcopy((result.get("canonical_evidence") or [])[0])
    if not evidence:
        raise ValueError(f"step {prior_id}: canonical evidence missing")
    result.update(
        {
            "step_id": f"A8V3-{chain_number:02d}-S{order:02d}",
            "legacy_step_id": prior_id or None,
            "order": order,
            "evidence_kind": result.get("evidence_kind") or evidence_kind(evidence),
            "evidence_basis": evidence_basis(evidence),
            "critical_evidence_signature": evidence_signature(evidence),
            "canonical_evidence": [evidence],
            "scoring_template": {
                "subject": {"max": 1, "score": None, "note": ""},
                "action": {"max": 1, "score": None, "note": ""},
                "object": {"max": 1, "score": None, "note": ""},
                "action_component_total": {"max": 3, "score": None},
                "critical_evidence_diagnostic": {
                    "max": 1,
                    "score": None,
                    "included_in_action_total": False,
                },
            },
        }
    )
    result["supporting_evidence"] = {
        "source_types": ["CBC primary telemetry"],
        "sample_logs": [sample_log(evidence)],
        "supporting_source_row_ids": list(
            (result.get("supporting_evidence") or {}).get(
                "supporting_source_row_ids", []
            )
        ),
    }
    return result


def addition_step(
    gold: dict[str, Any],
    specification: dict[str, Any],
) -> dict[str, Any]:
    evidence = fetch_row(gold, int(specification["row_id"]))
    supporting_ids = [int(value) for value in specification.get("supporting_row_ids", [])]
    return {
        "step_id": "",
        "order": 0,
        "subject": specification["subject"],
        "action": specification["action"],
        "object": specification["object"],
        "evidence_kind": specification["evidence_kind"],
        "evidence_basis": evidence_basis(evidence),
        "critical_evidence_signature": evidence_signature(evidence),
        "confidence": "observed",
        "one_line_ja": specification["one_line_ja"],
        "process_code_object": specification["object"],
        "canonical_evidence": [evidence],
        "supporting_evidence": {
            "source_types": ["CBC primary telemetry"],
            "sample_logs": [sample_log(evidence)],
            "supporting_source_row_ids": supporting_ids,
        },
    }


def prepare_source_gold(
    source_by_chain: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    result = copy.deepcopy(source_by_chain)

    # Different investigation anchors into the same observed attack component
    # must not imply a hidden, anchor-specific endpoint boundary.
    result["s3_pt_04_powershell_mid_chain"]["behavior_timeline"] = copy.deepcopy(
        result["s3_pt_03_regsvr32_long_chain"]["behavior_timeline"]
    )
    result["s4_pt_04_powershell_c1"]["behavior_timeline"] = copy.deepcopy(
        result["s4_pt_03_mshta_c1"]["behavior_timeline"]
    )

    # The v2 case merged two independent Word clusters.  Retain only W2, the
    # component actually selected by the observable neutral anchor.
    w2 = result.pop("s4_pt_02_word_w2_w3")
    w2["chain_id"] = "s4_pt_02_word_w2"
    w2["chain_title"] = "S4-W2: WerFault-launched Word component"
    w2["chain_description"] = (
        "The observable W2 component: WerFault launches Word PID 5980, which "
        "opens msf.doc, launches child Word PID 3784, and connects externally."
    )
    w2["observed_behavior"] = w2["chain_description"]
    w2["behavior_timeline"] = [
        step
        for step in w2["behavior_timeline"]
        if int((step.get("canonical_evidence") or [{}])[0].get("source_row_id", -1))
        in {4543, 4636, 516}
    ]
    w2["limitations"] = [
        "The later Word PID 2608 cluster is a separate nearby component and is not scored.",
        "No hidden alert grouping is used to connect W2 to W3 or to the mshta component.",
    ]
    result["s4_pt_02_word_w2"] = w2
    return result


def build_gold(
    source: dict[str, Any],
    chain_number: int,
    focus_process: str,
    representative_alert: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    gold = copy.deepcopy(source)
    chain_id = str(gold["chain_id"])
    steps = copy.deepcopy(gold.get("behavior_timeline") or [])
    steps.extend(addition_step(gold, item) for item in ADDITIONS.get(chain_id, []))
    steps.sort(
        key=lambda item: parse_time(
            str((item.get("canonical_evidence") or [{}])[0]["timestamp_utc"])
        )
    )
    steps = [
        normalized_step(step, chain_number=chain_number, order=order)
        for order, step in enumerate(steps, 1)
    ]
    evidence = [
        item
        for step in steps
        for item in (step.get("canonical_evidence") or [])
    ]
    touching = [item for item in evidence if process_touches(item, focus_process)]
    if not touching:
        raise ValueError(f"{chain_id}: no canonical row touches {focus_process}")
    anchor_evidence = min(touching, key=lambda item: parse_time(item["timestamp_utc"]))
    component_start = min(parse_time(item["timestamp_utc"]) for item in evidence)
    window_start = iso_time(component_start)
    window_end = iso_time(component_start + timedelta(minutes=WINDOW_MINUTES))
    anchor = {
        "timestamp_utc": anchor_evidence["timestamp_utc"],
        "database_time": compact_db_time(anchor_evidence["timestamp_utc"]),
        "source_stream": anchor_evidence["source_stream"],
        "source_table": anchor_evidence["source_table"],
        "source_row_id": anchor_evidence["source_row_id"],
        "process_name": focus_process,
        "selection_policy": (
            "earliest canonical primary-telemetry row that actually touches "
            "the declared focus process"
        ),
        "touches_declared_focus_process": True,
    }

    gold.update(
        {
            "case_group": "attack_behavior_observable_component",
            "suite_group": SUITE,
            "stages_present": list(STAGES),
            "behavior_timeline": steps,
            "gold_steps": copy.deepcopy(steps),
            "gold_order_pairs": [
                [steps[index]["step_id"], steps[index + 1]["step_id"]]
                for index in range(len(steps) - 1)
            ],
            "evidence_span_utc": {
                "start": min(item["timestamp_utc"] for item in evidence),
                "end": max(item["timestamp_utc"] for item in evidence),
            },
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
                "policy": (
                    "Independent row-level audit of central document/script "
                    "inputs, explicit process edges, network edges, and files "
                    "materialized for later execution; routine ancillary rows excluded"
                ),
                "expected_primary_row_ids": sorted(EXPECTED_PRIMARY_ROWS[chain_id]),
            },
        }
    )
    scope = gold.setdefault("input_scope", {})
    scope.update(
        {
            "host": scope.get("host") or "WIN-32-H1",
            "focus_processes": [focus_process],
            "chain_window_start_utc": window_start,
            "chain_window_end_utc": window_end,
            "window_minutes": WINDOW_MINUTES,
            "window_selection_policy": (
                "five-minute component-complete window starting at the first "
                "canonical component row"
            ),
            "neutral_anchor_utc": anchor["timestamp_utc"],
            "neutral_anchor_policy": anchor["selection_policy"],
            "target_component_rule": TARGET_COMPONENT_RULE,
            "input_policy": (
                "All stages use identical host, focus process, neutral anchor, "
                "five-minute window, component rule, and Gold. Stage 1 alone "
                "adds an observed alert clue. Hidden alert correspondence is not scored."
            ),
        }
    )
    gold["alert_timing"] = {
        "representative_alert_time_utc": representative_alert.get("time"),
        "neutral_anchor_utc": anchor["timestamp_utc"],
        "chain_window_start_utc": window_start,
        "chain_window_end_utc": window_end,
        "note": (
            "Alert time may lag primary telemetry and is a Stage-1 clue only. "
            "Alert-to-component correspondence is outside the score."
        ),
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
    gold: dict[str, Any],
    gold_file: str,
    anchor: dict[str, Any],
    window_start: str,
    window_end: str,
    stage: str,
    chain_number: int,
) -> dict[str, Any]:
    case = copy.deepcopy(source)
    old_chain_id = str(case["chain_id"])
    chain_id = RENAMED_CHAIN.get(old_chain_id, old_chain_id)
    instance_id = f"{chain_id}_{stage}"
    alerts = (
        copy.deepcopy(source.get("input_alert_rows") or [])
        if stage == "stage1"
        else []
    )
    if stage == "stage1" and len(alerts) != 1:
        raise ValueError(f"{chain_id}: Stage 1 requires one alert clue")
    model_input: dict[str, Any] = {
        "host": case["host"],
        "focus_processes": [case["process_name"]],
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
            "instance_id": instance_id,
            "case_id": instance_id,
            "input_id": f"atlasv2_attack8_observable_v3_{chain_number:02d}_{stage}",
            "stage": stage,
            "difficulty": "alert_input" if stage == "stage1" else "process_time",
            "context_label": "attack_behavior_observable_component",
            "suite_group": SUITE,
            "quality": "observable_component_normal_parity_v3_20260726",
            "expected_behavior": gold.get("chain_title") or chain_id,
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
                "input_id": f"atlasv2_attack8_observable_v3_{chain_number:02d}",
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
) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    stage_counts = Counter(case["stage"] for case in cases)
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        failures.append({"check": "stage_counts", "actual": dict(stage_counts)})
    if len({case["instance_id"] for case in cases}) != 24:
        failures.append({"check": "unique_instance_ids"})
    if len(gold_by_chain) != 8:
        failures.append({"check": "chain_count", "actual": len(gold_by_chain)})

    comparisons = 0
    mismatches: list[dict[str, Any]] = []
    chain_reports: list[dict[str, Any]] = []
    total_steps = 0
    total_rows = 0
    for chain_id, gold in sorted(gold_by_chain.items()):
        steps = gold["gold_steps"]
        total_steps += len(steps)
        rows = [
            evidence
            for step in steps
            for evidence in step.get("canonical_evidence") or []
        ]
        total_rows += len(rows)
        actual_primary = {int(row["source_row_id"]) for row in rows}
        expected_primary = EXPECTED_PRIMARY_ROWS[chain_id]
        if actual_primary != expected_primary:
            failures.append(
                {
                    "check": "audited_primary_row_set",
                    "chain_id": chain_id,
                    "missing": sorted(expected_primary - actual_primary),
                    "unexpected": sorted(actual_primary - expected_primary),
                }
            )
        expected_pairs = [
            [steps[index]["step_id"], steps[index + 1]["step_id"]]
            for index in range(len(steps) - 1)
        ]
        if gold["gold_order_pairs"] != expected_pairs:
            failures.append({"check": "adjacent_order_pairs", "chain_id": chain_id})

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
            failures.append({"check": "same_contract_all_stages", "chain_id": chain_id})
            continue
        anchor = paired[0]["neutral_anchor_provenance"]
        anchor_rows = [
            row for row in rows if int(row["source_row_id"]) == int(anchor["source_row_id"])
        ]
        anchor_touches = (
            len(anchor_rows) == 1
            and process_touches(anchor_rows[0], paired[0]["process_name"])
        )
        if not anchor_touches:
            failures.append({"check": "anchor_touches_focus", "chain_id": chain_id})
        start = parse_time(paired[0]["time_window_utc"]["episode_start"])
        end = parse_time(paired[0]["time_window_utc"]["episode_end"])
        coverage = all(start <= parse_time(row["timestamp_utc"]) <= end for row in rows)
        if end - start != timedelta(minutes=5) or not coverage:
            failures.append({"check": "five_minute_coverage", "chain_id": chain_id})
        visibility = all(
            (
                len(case.get("input_alert_rows") or []) == 1
                and len(case["model_ready_input"]["input"].get("alerts") or []) == 1
            )
            if case["stage"] == "stage1"
            else not (case.get("input_alert_rows") or [])
            and "alerts" not in case["model_ready_input"]["input"]
            for case in paired
        )
        if not visibility:
            failures.append({"check": "stage_alert_visibility", "chain_id": chain_id})
        if any(
            case["paired_stage_contract"].get("alert_mapping_scored") is not False
            for case in paired
        ):
            failures.append({"check": "alert_mapping_excluded", "chain_id": chain_id})

        connection = sqlite3.connect(db_path(gold))
        connection.row_factory = sqlite3.Row
        try:
            for evidence in rows:
                db_row = connection.execute(
                    "SELECT * FROM cbc_events WHERE id = ?",
                    (int(evidence["source_row_id"]),),
                ).fetchone()
                if db_row is None:
                    mismatches.append(
                        {
                            "chain_id": chain_id,
                            "source_row_id": evidence["source_row_id"],
                            "field": "row",
                        }
                    )
                    continue
                for gold_field, db_field in CANONICAL_DB_FIELDS.items():
                    comparisons += 1
                    if not values_equal(evidence.get(gold_field), db_row[db_field]):
                        mismatches.append(
                            {
                                "chain_id": chain_id,
                                "source_row_id": evidence["source_row_id"],
                                "field": gold_field,
                                "gold": evidence.get(gold_field),
                                "database": db_row[db_field],
                            }
                        )
        finally:
            connection.close()
        chain_reports.append(
            {
                "chain_id": chain_id,
                "step_count": len(steps),
                "primary_row_ids": sorted(actual_primary),
                "anchor_row_id": anchor["source_row_id"],
                "anchor_touches_focus": anchor_touches,
                "five_minute_window_covers_gold": coverage,
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
    if total_rows != EXPECTED_STEP_TOTAL:
        failures.append(
            {
                "check": "one_primary_row_per_step",
                "expected": EXPECTED_STEP_TOTAL,
                "actual": total_rows,
            }
        )
    if mismatches:
        failures.append(
            {"check": "canonical_database_equality", "mismatch_count": len(mismatches)}
        )

    pair_checks = {}
    for left, right in (
        ("s3_pt_03_regsvr32_long_chain", "s3_pt_04_powershell_mid_chain"),
        ("s4_pt_03_mshta_c1", "s4_pt_04_powershell_c1"),
    ):
        left_rows = [
            row["source_row_id"]
            for step in gold_by_chain[left]["gold_steps"]
            for row in step["canonical_evidence"]
        ]
        right_rows = [
            row["source_row_id"]
            for step in gold_by_chain[right]["gold_steps"]
            for row in step["canonical_evidence"]
        ]
        equal = left_rows == right_rows
        pair_checks[f"{left}__{right}"] = equal
        if not equal:
            failures.append(
                {"check": "same_component_gold_for_different_anchor", "pair": [left, right]}
            )

    return {
        "status": "pass" if not failures else "fail",
        "suite": SUITE,
        "contract_version": CONTRACT_VERSION,
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "chain_count": len(gold_by_chain),
        "gold_step_count_unique": total_steps,
        "gold_step_count_across_stages": total_steps * 3,
        "canonical_primary_row_count_unique": total_rows,
        "source_database_field_comparisons": comparisons,
        "source_database_mismatch_count": len(mismatches),
        "source_database_mismatches": mismatches,
        "alert_mapping_scored": False,
        "critical_evidence_separate_diagnostic": True,
        "command_line_independent_candidate_slot": False,
        "different_anchor_same_component_gold_checks": pair_checks,
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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    global OUT_GOLD_ROOT

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cases", type=Path, default=SOURCE_CASES)
    parser.add_argument("--source-gold-root", type=Path, default=SOURCE_GOLD_ROOT)
    parser.add_argument("--out-cases", type=Path, default=OUT_CASES)
    parser.add_argument("--out-gold-root", type=Path, default=OUT_GOLD_ROOT)
    parser.add_argument("--manifest", type=Path, default=OUT_MANIFEST)
    parser.add_argument("--validation", type=Path, default=OUT_VALIDATION)
    args = parser.parse_args()

    OUT_GOLD_ROOT = args.out_gold_root

    source_cases = read_jsonl(args.source_cases)
    source_stage1 = [case for case in source_cases if case["stage"] == "stage1"]
    source_gold_by_chain = {}
    for case in source_stage1:
        chain_id = str(case["chain_id"])
        path = args.source_gold_root / str(case["gold_chain_file"])
        source_gold_by_chain[chain_id] = json.loads(path.read_text(encoding="utf-8"))
    prepared = prepare_source_gold(source_gold_by_chain)

    cases: list[dict[str, Any]] = []
    gold_by_chain: dict[str, dict[str, Any]] = {}
    gold_index: list[dict[str, Any]] = []
    for chain_number, source_case in enumerate(source_stage1, 1):
        old_chain_id = str(source_case["chain_id"])
        chain_id = RENAMED_CHAIN.get(old_chain_id, old_chain_id)
        source_gold = prepared[chain_id]
        representative_alert = copy.deepcopy(source_case["input_alert_rows"][0])
        gold, anchor, window_start, window_end = build_gold(
            source_gold,
            chain_number,
            str(source_case["process_name"]),
            representative_alert,
        )
        gold_file = f"by_chain/{chain_id}/chain_gold.json"
        gold_path = args.out_gold_root / gold_file
        write_json(gold_path, gold)
        gold_by_chain[chain_id] = gold
        gold_index.append(
            {
                "chain_id": chain_id,
                "gold_chain_file": gold_file,
                "source_suite": str(args.source_gold_root.relative_to(ROOT)),
                "source_chain_id": old_chain_id,
                "neutral_anchor_utc": anchor["timestamp_utc"],
                "neutral_anchor_source_row_id": anchor["source_row_id"],
                "neutral_anchor_touches_focus_process": True,
                "window_start_utc": window_start,
                "window_end_utc": window_end,
                "gold_step_count": len(gold["gold_steps"]),
                "alert_mapping_scored": False,
                "gold_sha256": sha256(gold_path),
            }
        )
        for stage in STAGES:
            cases.append(
                build_case(
                    source_case,
                    gold,
                    gold_file,
                    anchor,
                    window_start,
                    window_end,
                    stage,
                    chain_number,
                )
            )

    validation = validate(cases, gold_by_chain)
    write_json(args.validation, validation)
    if validation["status"] != "pass":
        raise SystemExit(
            json.dumps(
                {"status": "fail", "failures": validation["failures"]},
                ensure_ascii=False,
                indent=2,
            )
        )

    args.out_cases.parent.mkdir(parents=True, exist_ok=True)
    args.out_cases.write_text(
        "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases),
        encoding="utf-8",
    )
    write_json(args.out_gold_root / "chain_gold_index.json", gold_index)
    write_json(
        args.manifest,
        {
            "suite": SUITE,
            "contract_version": CONTRACT_VERSION,
            "purpose": (
                "Evaluate attack behavior reconstruction under the same "
                "observable action/component meaning used for normal behavior."
            ),
            "source_case_file": str(args.source_cases.relative_to(ROOT)),
            "source_gold_root": str(args.source_gold_root.relative_to(ROOT)),
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
                "earliest canonical primary-telemetry row that actually "
                "touches the declared focus process"
            ),
            "target_component_rule": TARGET_COMPONENT_RULE,
            "alert_mapping_scored": False,
            "scoring_policy": {
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
