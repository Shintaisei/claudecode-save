#!/usr/bin/env python3
"""Build the normal-23-parity process-chain v4 attack reconstruction suite.

The observable-component v3 suite treated each independently observable file,
network, and process edge as a scored action.  That granularity is stricter
than the original 23 normal-use-case experiment, whose Gold unit is a compact
causal behavior chain expressed as process subject / semantic action / object.

This builder preserves all earlier artifacts and creates a v4 suite in which:

* every scored step is a major process-attributed behavior;
* PID identity is evidence provenance, not a required subject/object token;
* central document input, process creation, and behavior-defining network
  activity are scored;
* temporary/cache lifecycle rows and download materialization duplicates are
  supporting evidence rather than independent Gold steps;
* Stage 1/2/3 model-ready inputs have the same shape as the normal 23-case
  experiment: alert+process+five-minute window, process+window, and the same
  process+window with alert summaries hidden, respectively;
* hidden alert correspondence, attack labels, and analyst intent are excluded.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sqlite3
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

import build_atlasv2_s3_s4_attack8_observable_component_v3_suite as v3


ROOT = Path(__file__).resolve().parents[2]
VERSION = "20260727"
SOURCE_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_observable_component_v3_stage_cases_20260726.jsonl"
)
SOURCE_GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "atlasv2_s3_s4_attack8_observable_component_v3_gold_20260726"
)
SUITE = "atlasv2_s3_s4_attack8_process_chain_v4"
OUT_CASES = (
    ROOT / "data/current_experiment/cases" / f"{SUITE}_stage_cases_{VERSION}.jsonl"
)
OUT_GOLD_ROOT = ROOT / "data/current_experiment/gold" / f"{SUITE}_gold_{VERSION}"
OUT_MANIFEST = (
    ROOT / "data/current_experiment/cases" / f"{SUITE}_manifest_{VERSION}.json"
)
OUT_VALIDATION = (
    ROOT / "docs/current_experiment" / f"{SUITE}_build_validation_{VERSION}.json"
)

STAGES = ("stage1", "stage2", "stage3")
WINDOW_MINUTES = 5
CONTRACT_VERSION = "process_behavior_chain_normal23_parity_v4"
EXPECTED_STEP_TOTAL = 44
STEP_ID_PREFIX = "A8V4"
ID_NAMESPACE = "atlasv2_attack8_process_chain_v4"
QUALITY_LABEL = "normal23_process_chain_parity_v4_20260727"
RENAMED_CHAINS: dict[str, str] = {}
REPRESENTATIVE_ALERT_ROW_OVERRIDES: dict[str, int] = {}
WINDOW_OVERRIDES: dict[str, tuple[str, str]] = {}
CHAIN_METADATA_OVERRIDES: dict[str, dict[str, Any]] = {}

TARGET_CHAIN_RULE = (
    "Reconstruct the compact causal behavior chain around the supplied focus "
    "process and five-minute scope. Express each major behavior as process "
    "subject, semantic action, and object. Include central document/script "
    "input, explicit process creation or execution, and behavior-defining "
    "external communication. Treat PID values, duplicate sensor rows, temporary "
    "or cache lifecycle operations, and file materialization that merely "
    "duplicates the same download/execution behavior as supporting evidence, "
    "not additional actions. Do not connect nearby activity by time or shared "
    "process name alone."
)


def spec(
    row_id: int,
    subject: str,
    action: str,
    object_: str,
    evidence_kind: str,
    one_line_ja: str,
    supporting_row_ids: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "row_id": row_id,
        "subject": subject,
        "action": action,
        "object": object_,
        "evidence_kind": evidence_kind,
        "one_line_ja": one_line_ja,
        "supporting_row_ids": supporting_row_ids or [],
    }


# One row is the primary fingerprint for each semantic behavior.  Rows in
# supporting_row_ids substantiate the same behavior but are not extra actions.
STEP_SPECS: dict[str, list[dict[str, Any]]] = {
    "s3_pt_01_word_document_processing": [
        spec(
            8705,
            "WINWORD.EXE",
            "文書を開いて処理した",
            r"C:\Users\aalsahee\Downloads\s3take2\msf.rtf",
            "document_input",
            "WINWORD.EXE が msf.rtf を開いて処理した。",
        ),
        spec(
            8727,
            "WINWORD.EXE",
            "文書処理用の子プロセスを起動した",
            "WINWORD.EXE",
            "process_creation",
            "WINWORD.EXE が文書処理用の子 WINWORD.EXE を起動した。",
        ),
    ],
    "s3_pt_02_regsvr32_remote_sct": [
        spec(
            7814,
            "svchost.exe",
            "Equation Editorを子プロセスとして起動した",
            "EQNEDT32.EXE",
            "process_creation",
            "svchost.exe が EQNEDT32.EXE を起動した。",
        ),
        spec(
            7829,
            "EQNEDT32.EXE",
            "regsvr32.exeを子プロセスとして起動した",
            "regsvr32.exe",
            "process_creation",
            "EQNEDT32.EXE が regsvr32.exe を起動した。",
        ),
        spec(
            7889,
            "regsvr32.exe",
            "remote SCTを指定したコマンドで外部へ接続した",
            "ortrta.net / 10.193.66.115:8080",
            "command_network",
            "regsvr32.exe が remote SCT を指定して ortrta.net:8080 へ接続した。",
        ),
    ],
    "s3_pt_03_regsvr32_long_chain": [
        spec(
            17797,
            "EQNEDT32.EXE",
            "regsvr32.exeを子プロセスとして起動した",
            "regsvr32.exe",
            "process_creation",
            "EQNEDT32.EXE が regsvr32.exe を起動した。",
        ),
        spec(
            17863,
            "regsvr32.exe",
            "remote SCTを実行してPowerShellを起動した",
            "powershell.exe",
            "command_process_creation",
            "regsvr32.exe が remote SCT を実行して powershell.exe を起動した。",
            [17849, 17855],
        ),
        spec(
            18136,
            "powershell.exe",
            "外部スクリプト取得先へ接続した",
            "ortrta.net / 10.193.66.115:8080",
            "network",
            "powershell.exe が外部スクリプト取得先の 8080/tcp へ接続した。",
        ),
        spec(
            18152,
            "powershell.exe",
            "後続payload取得先へ接続した",
            "ortrta.net / 10.193.66.115:8443",
            "network",
            "powershell.exe が後続 payload 取得先の 8443/tcp へ接続した。",
        ),
        spec(
            18350,
            "powershell.exe",
            "cmd.exeを子プロセスとして起動した",
            "cmd.exe",
            "process_creation",
            "powershell.exe が cmd.exe を起動した。",
            [18346],
        ),
        spec(
            18358,
            "cmd.exe",
            "payload.exeを起動した",
            "payload.exe",
            "process_creation",
            "cmd.exe が payload.exe を起動した。",
        ),
        spec(
            18470,
            "payload.exe",
            "別のpayload.exeプロセスを起動した",
            "payload.exe",
            "process_creation",
            "payload.exe が別の payload.exe プロセスを起動した。",
        ),
        spec(
            18558,
            "payload.exe",
            "C2候補へ接続した",
            "ortrta.net / 10.193.66.115:9999",
            "network",
            "payload.exe が C2 候補の 9999/tcp へ接続した。",
        ),
    ],
    "s3_pt_04_powershell_mid_chain": [
        spec(
            17863,
            "regsvr32.exe",
            "remote SCTを実行してPowerShellを起動した",
            "powershell.exe",
            "command_process_creation",
            "regsvr32.exe が remote SCT を実行して powershell.exe を起動した。",
            [17849, 17855],
        ),
        spec(
            18136,
            "powershell.exe",
            "外部スクリプト取得先へ接続した",
            "ortrta.net / 10.193.66.115:8080",
            "network",
            "powershell.exe が外部スクリプト取得先の 8080/tcp へ接続した。",
        ),
        spec(
            18152,
            "powershell.exe",
            "後続payload取得先へ接続した",
            "ortrta.net / 10.193.66.115:8443",
            "network",
            "powershell.exe が後続 payload 取得先の 8443/tcp へ接続した。",
        ),
        spec(
            18350,
            "powershell.exe",
            "cmd.exeを子プロセスとして起動した",
            "cmd.exe",
            "process_creation",
            "powershell.exe が cmd.exe を起動した。",
            [18346],
        ),
        spec(
            18358,
            "cmd.exe",
            "payload.exeを起動した",
            "payload.exe",
            "process_creation",
            "cmd.exe が payload.exe を起動した。",
        ),
        spec(
            18470,
            "payload.exe",
            "別のpayload.exeプロセスを起動した",
            "payload.exe",
            "process_creation",
            "payload.exe が別の payload.exe プロセスを起動した。",
        ),
        spec(
            18558,
            "payload.exe",
            "C2候補へ接続した",
            "ortrta.net / 10.193.66.115:9999",
            "network",
            "payload.exe が C2 候補の 9999/tcp へ接続した。",
        ),
    ],
    "s4_pt_01_word_w1": [
        spec(
            7566,
            "explorer.exe",
            "Wordを子プロセスとして起動した",
            "WINWORD.EXE",
            "process_creation",
            "explorer.exe が WINWORD.EXE を起動した。",
        ),
        spec(
            7971,
            "WINWORD.EXE",
            "文書を開いて処理した",
            r"C:\Users\aalsahee\Downloads\s4-at-night\msf.doc",
            "document_input",
            "WINWORD.EXE が msf.doc を開いて処理した。",
        ),
        spec(
            7986,
            "WINWORD.EXE",
            "文書処理用の子プロセスを起動した",
            "WINWORD.EXE",
            "process_creation",
            "WINWORD.EXE が文書処理用の子 WINWORD.EXE を起動した。",
        ),
        spec(
            8124,
            "WINWORD.EXE",
            "外部ホストへ接続した",
            "10.193.66.115:8080",
            "network",
            "WINWORD.EXE が 10.193.66.115:8080 へ接続した。",
        ),
    ],
    "s4_pt_02_word_w2": [
        spec(
            4543,
            "werfault.exe",
            "Wordを子プロセスとして起動した",
            "WINWORD.EXE",
            "process_creation",
            "werfault.exe が WINWORD.EXE を起動した。",
        ),
        spec(
            4616,
            "WINWORD.EXE",
            "文書を開いて処理した",
            r"C:\Users\aalsahee\Downloads\s4-at-night\msf.doc",
            "document_input",
            "WINWORD.EXE が msf.doc を開いて処理した。",
        ),
        spec(
            4636,
            "WINWORD.EXE",
            "文書処理用の子プロセスを起動した",
            "WINWORD.EXE",
            "process_creation",
            "WINWORD.EXE が文書処理用の子 WINWORD.EXE を起動した。",
        ),
        spec(
            516,
            "WINWORD.EXE",
            "外部ホストへ接続した",
            "10.193.66.115:8080",
            "network",
            "WINWORD.EXE が 10.193.66.115:8080 へ接続した。",
        ),
    ],
    "s4_pt_03_mshta_c1": [
        spec(
            3500,
            "svchost.exe",
            "mshta.exeを子プロセスとして起動した",
            "mshta.exe",
            "process_creation",
            "svchost.exe が mshta.exe を起動した。",
        ),
        spec(
            3623,
            "mshta.exe",
            "外部コンテンツ取得先へ接続した",
            "10.193.66.115:8080",
            "network",
            "mshta.exe が外部コンテンツ取得先の 8080/tcp へ接続した。",
        ),
        spec(
            3640,
            "mshta.exe",
            "PowerShellを子プロセスとして起動した",
            "powershell.exe",
            "process_creation",
            "mshta.exe が powershell.exe を起動した。",
            [3633],
        ),
        spec(
            3793,
            "powershell.exe",
            "別のPowerShellプロセスを起動した",
            "powershell.exe",
            "process_creation",
            "powershell.exe が別の powershell.exe プロセスを起動した。",
        ),
        spec(
            12843,
            "powershell.exe",
            "後続payload取得先へ接続した",
            "ortrta.net / 10.193.66.115:8443",
            "network",
            "powershell.exe が後続 payload 取得先の 8443/tcp へ接続した。",
        ),
        spec(
            13141,
            "powershell.exe",
            "cmd.exeを子プロセスとして起動した",
            "cmd.exe",
            "process_creation",
            "powershell.exe が cmd.exe を起動した。",
            [13107],
        ),
        spec(
            13187,
            "cmd.exe",
            "payload.exeを起動した",
            "payload.exe",
            "process_creation",
            "cmd.exe が payload.exe を起動した。",
        ),
        spec(
            13300,
            "payload.exe",
            "別のpayload.exeプロセスを起動した",
            "payload.exe",
            "process_creation",
            "payload.exe が別の payload.exe プロセスを起動した。",
        ),
        spec(
            11453,
            "payload.exe",
            "C2候補へ接続した",
            "ortrta.net / 10.193.66.115:9999",
            "network",
            "payload.exe が C2 候補の 9999/tcp へ接続した。",
        ),
    ],
    "s4_pt_04_powershell_c1": [
        spec(
            3640,
            "mshta.exe",
            "PowerShellを子プロセスとして起動した",
            "powershell.exe",
            "process_creation",
            "mshta.exe が powershell.exe を起動した。",
            [3633],
        ),
        spec(
            3793,
            "powershell.exe",
            "別のPowerShellプロセスを起動した",
            "powershell.exe",
            "process_creation",
            "powershell.exe が別の powershell.exe プロセスを起動した。",
        ),
        spec(
            12843,
            "powershell.exe",
            "後続payload取得先へ接続した",
            "ortrta.net / 10.193.66.115:8443",
            "network",
            "powershell.exe が後続 payload 取得先の 8443/tcp へ接続した。",
        ),
        spec(
            13141,
            "powershell.exe",
            "cmd.exeを子プロセスとして起動した",
            "cmd.exe",
            "process_creation",
            "powershell.exe が cmd.exe を起動した。",
            [13107],
        ),
        spec(
            13187,
            "cmd.exe",
            "payload.exeを起動した",
            "payload.exe",
            "process_creation",
            "cmd.exe が payload.exe を起動した。",
        ),
        spec(
            13300,
            "payload.exe",
            "別のpayload.exeプロセスを起動した",
            "payload.exe",
            "process_creation",
            "payload.exe が別の payload.exe プロセスを起動した。",
        ),
        spec(
            11453,
            "payload.exe",
            "C2候補へ接続した",
            "ortrta.net / 10.193.66.115:9999",
            "network",
            "payload.exe が C2 候補の 9999/tcp へ接続した。",
        ),
    ],
}

EXPECTED_STEPS_BY_CHAIN = {
    chain_id: len(items) for chain_id, items in STEP_SPECS.items()
}
PID_TOKEN = re.compile(r"\(\s*PID\s+\d+\s*\)", re.IGNORECASE)


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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_identity(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_name": v3.normalize_process(evidence.get("process_path")),
        "process_pid": evidence.get("process_pid"),
        "parent_name": v3.normalize_process(evidence.get("parent_path")),
        "parent_pid": evidence.get("parent_pid"),
        "child_name": v3.normalize_process(evidence.get("childproc_name")),
        "child_pid": evidence.get("childproc_pid"),
        "pid_scored": False,
    }


def build_step(
    source_gold: dict[str, Any],
    item: dict[str, Any],
    chain_number: int,
    order: int,
) -> dict[str, Any]:
    primary = v3.fetch_row(source_gold, int(item["row_id"]))
    supporting = [
        v3.fetch_row(source_gold, int(row_id))
        for row_id in item.get("supporting_row_ids", [])
    ]
    return {
        "step_id": f"{STEP_ID_PREFIX}-{chain_number:02d}-S{order:02d}",
        "order": order,
        "focus_process": None,
        "subject": item["subject"],
        "action": item["action"],
        "object": item["object"],
        "evidence_kind": item["evidence_kind"],
        "evidence_basis": v3.evidence_basis(primary),
        "confidence": "observed",
        "one_line_ja": item["one_line_ja"],
        "process_code_object": item["object"],
        "canonical_evidence": [primary],
        "critical_evidence_signature": v3.evidence_signature(primary),
        "process_identity_provenance": evidence_identity(primary),
        "supporting_evidence": {
            "source_types": ["CBC primary telemetry"],
            "sample_logs": [
                v3.sample_log(evidence) for evidence in [primary, *supporting]
            ],
            "supporting_source_row_ids": [
                int(evidence["source_row_id"]) for evidence in supporting
            ],
            "supporting_canonical_rows": supporting,
            "note": (
                "Supporting rows substantiate the same semantic process action "
                "and do not add candidate or Gold action slots."
            ),
        },
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


def source_row_map(source_gold: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for step in source_gold.get("gold_steps") or source_gold.get("behavior_timeline") or []:
        for evidence in step.get("canonical_evidence") or []:
            result[int(evidence["source_row_id"])] = step
    return result


def granularity_audit(
    source_gold: dict[str, Any],
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    source_rows = source_row_map(source_gold)
    primary_rows = {
        int(evidence["source_row_id"])
        for step in steps
        for evidence in step.get("canonical_evidence") or []
    }
    supporting_rows = {
        int(row_id)
        for step in steps
        for row_id in (step.get("supporting_evidence") or {}).get(
            "supporting_source_row_ids", []
        )
    }
    outside = sorted(set(source_rows) - primary_rows - supporting_rows)
    excluded = []
    for row_id in outside:
        source_step = source_rows[row_id]
        kind = str(source_step.get("evidence_kind") or "")
        reason = (
            "temporary_or_cache_file_lifecycle_not_a_major_process_behavior"
            if kind == "file"
            else "outside_the_focus_process_causal_subchain"
        )
        excluded.append(
            {
                "source_row_id": row_id,
                "source_step_id": source_step.get("step_id"),
                "subject": source_step.get("subject"),
                "action": source_step.get("action"),
                "object": source_step.get("object"),
                "reason": reason,
            }
        )
    return {
        "status": "pass",
        "reference_normal_gold_root": (
            "data/current_experiment/gold/cbc_alert_behavior_chain_gold"
        ),
        "policy": TARGET_CHAIN_RULE,
        "primary_scored_row_ids": sorted(primary_rows),
        "supporting_not_independently_scored_row_ids": sorted(supporting_rows),
        "excluded_v3_rows": excluded,
        "pid_identity_scored": False,
        "raw_lifecycle_row_scored_as_independent_action": False,
    }


def build_gold(
    source_gold: dict[str, Any],
    chain_number: int,
    focus_process: str,
    representative_alert: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    chain_id = str(source_gold["chain_id"])
    steps = [
        build_step(source_gold, item, chain_number, order)
        for order, item in enumerate(STEP_SPECS[chain_id], 1)
    ]
    all_evidence = [
        evidence
        for step in steps
        for evidence in [
            *(step.get("canonical_evidence") or []),
            *((step.get("supporting_evidence") or {}).get(
                "supporting_canonical_rows", []
            )),
        ]
    ]
    start = min(v3.parse_time(str(item["timestamp_utc"])) for item in all_evidence)
    if chain_id in WINDOW_OVERRIDES:
        window_start, window_end = WINDOW_OVERRIDES[chain_id]
    else:
        window_start = v3.iso_time(start)
        window_end = v3.iso_time(start + timedelta(minutes=WINDOW_MINUTES))
    gold = copy.deepcopy(source_gold)
    gold.update(copy.deepcopy(CHAIN_METADATA_OVERRIDES.get(chain_id, {})))
    gold.update(
        {
            "evaluation_unit": "process-attributed causal behavior chain",
            "case_group": "attack_process_behavior_chain",
            "suite_group": SUITE,
            "stages_present": list(STAGES),
            "chain_description": (
                "Compact causal process behavior chain built at the same semantic "
                "granularity as the original 23 normal-use-case Gold."
            ),
            "behavior_timeline": steps,
            "gold_steps": copy.deepcopy(steps),
            "gold_order_pairs": [
                [steps[index]["step_id"], steps[index + 1]["step_id"]]
                for index in range(len(steps) - 1)
            ],
            "timeline_ja": [step["one_line_ja"] for step in steps],
            "evidence_span_utc": {
                "start": min(item["timestamp_utc"] for item in all_evidence),
                "end": max(item["timestamp_utc"] for item in all_evidence),
            },
            "case_scoring": {
                "action_component_denominator": len(steps) * 3,
                "action_components": ["subject", "action", "object"],
                "critical_evidence_diagnostic_denominator": len(steps),
                "critical_evidence_in_action_denominator": False,
                "order_pair_denominator": max(0, len(steps) - 1),
                "candidate_precision_policy": (
                    "literal included candidate action slots; PID and command_line "
                    "are action/evidence attributes, not independent slots"
                ),
                "pid_identity_required_for_match": False,
            },
            "paired_stage_contract": {
                "contract_version": CONTRACT_VERSION,
                "evaluation_unit": "process-attributed causal behavior chain",
                "same_gold_all_stages": True,
                "same_process_and_five_minute_scope_all_stages": True,
                "target_component_rule": TARGET_CHAIN_RULE,
                "target_rule_exposed_to_model": False,
                "neutral_anchor_exposed_to_model": False,
                "alert_mapping_scored": False,
                "hard_time_scope": False,
                "critical_evidence_separate_diagnostic": True,
                "pid_identity_scored": False,
            },
            "scoring_exclusions": [
                "exact PID reproduction or PID-based process-instance identity",
                "inferring an unavailable CBC alert-to-chain correspondence",
                "predicting alert id, alert title, alert reason, ATT&CK technique, or intent",
                "temporary/cache file lifecycle rows as independent behavior actions",
                "file materialization as another action when it supports the same download/execution behavior",
                "command_line as an independent candidate action slot",
            ],
            "gold_granularity_audit": granularity_audit(source_gold, steps),
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
                "five-minute finalized chain scope containing all scored and "
                "supporting primary telemetry"
            ),
            "target_component_rule": TARGET_CHAIN_RULE,
            "input_policy": (
                "Stage 1 receives host, focus process, five-minute scope, and one "
                "representative alert clue. Stage 2 receives host, focus process, "
                "and the same scope. Stage 3 receives the Stage 2 input with CBC "
                "alert summaries unavailable. No neutral event anchor or Gold "
                "boundary rule is exposed to the model."
            ),
        }
    )
    gold["alert_timing"] = {
        "representative_alert_time_utc": representative_alert.get("time"),
        "chain_window_start_utc": window_start,
        "chain_window_end_utc": window_end,
        "note": "The alert is a Stage-1 clue only; alert correspondence is not scored.",
    }
    return gold, window_start, window_end


def alert_anchor(alert: dict[str, Any], process_name: str) -> dict[str, Any]:
    return {
        "source_stream": alert.get("source_stream"),
        "timestamp_utc": alert.get("time"),
        "database_time": v3.compact_db_time(str(alert.get("time"))),
        "alert_id": alert.get("alert_id"),
        "alert_name": alert.get("alert_name"),
        "process_name": process_name,
        "process_path": None,
        "process_cmdline": None,
        "parent_path": None,
        "parent_cmdline": None,
        "severity": alert.get("severity"),
        "reason": alert.get("alert_reason"),
        "event_record_id": alert.get("alert_id"),
        "action": "cbc_alert",
    }


def fetch_alert_row(source_gold: dict[str, Any], row_id: int) -> dict[str, Any]:
    connection = sqlite3.connect(v3.db_path(source_gold))
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM cbc_alerts WHERE id = ?",
            (row_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError(f"cbc_alerts row {row_id} not found")
    return {
        "source_row_id": int(row["id"]),
        "time": row["create_time_utc"],
        "alert_id": row["alert_id"],
        "alert_name": row["report_name"] or row["reason"],
        "alert_reason": row["reason"],
        "process": row["process_path"],
        "pid": row["process_pid"],
        "source_stream": row["stream_name"],
        "severity": row["severity"],
    }


def scope_anchor(window_start: str, process_name: str) -> dict[str, Any]:
    return {
        "source_stream": "scope",
        "timestamp_utc": window_start,
        "database_time": v3.compact_db_time(window_start),
        "alert_id": None,
        "alert_name": None,
        "process_name": process_name,
        "process_path": None,
        "process_cmdline": None,
        "parent_path": None,
        "parent_cmdline": None,
        "severity": None,
        "reason": None,
        "event_record_id": None,
        "action": "scope",
    }


def build_case(
    source: dict[str, Any],
    gold: dict[str, Any],
    gold_file: str,
    window_start: str,
    window_end: str,
    stage: str,
    chain_number: int,
) -> dict[str, Any]:
    case = copy.deepcopy(source)
    chain_id = str(gold["chain_id"])
    process_name = str(case["process_name"])
    source_alerts = copy.deepcopy(source.get("input_alert_rows") or [])
    if len(source_alerts) != 1:
        raise ValueError(f"{chain_id}: exactly one representative alert is required")
    alerts = source_alerts if stage == "stage1" else []
    model_input: dict[str, Any] = {
        "host": case["host"],
        "focus_processes": [process_name],
        "chain_window_start_utc": window_start,
        "chain_window_end_utc": window_end,
    }
    if stage == "stage1":
        model_input["alerts"] = copy.deepcopy(alerts)
    instance_id = f"{chain_id}_{stage}"
    case.update(
        {
            "chain_id": chain_id,
            "instance_id": instance_id,
            "case_id": instance_id,
            "input_id": f"{ID_NAMESPACE}_{chain_number:02d}_{stage}",
            "stage": stage,
            "difficulty": "alert_input" if stage == "stage1" else "process_time",
            "context_label": "attack_process_behavior_chain",
            "suite_group": SUITE,
            "quality": QUALITY_LABEL,
            "expected_behavior": gold.get("chain_title") or chain_id,
            "time_window_utc": {
                "episode_start": window_start,
                "episode_end": window_end,
                "analysis_scope": (
                    "finalized process behavior-chain window; surrounding DB "
                    "evidence may be inspected but unrelated activity is not Gold"
                ),
            },
            "anchor_event": (
                alert_anchor(source_alerts[0], process_name)
                if stage == "stage1"
                else scope_anchor(window_start, process_name)
            ),
            "investigation_time_anchor_utc": window_start,
            "investigation_time_anchor_policy": (
                "five-minute chain scope start; not an exposed event-level pivot"
            ),
            "input_alert_rows": alerts,
            "model_ready_input": {
                "input_id": f"{ID_NAMESPACE}_{chain_number:02d}",
                "stage": stage,
                "input": model_input,
            },
            "gold_chain_file": gold_file,
            "formal_gold_root": str(OUT_GOLD_ROOT.relative_to(ROOT)),
            "stage_input_policy": (
                "Stage 1: representative CBC alert plus host, focus process, and "
                "five-minute chain scope."
                if stage == "stage1"
                else (
                    "Stage 2: host, focus process, and five-minute chain scope; "
                    "alert summaries may be discovered during investigation."
                    if stage == "stage2"
                    else (
                        "Stage 3: same host, focus process, and five-minute scope; "
                        "CBC alert summaries are unavailable."
                    )
                )
            ),
            "stage3_answerable_policy": (
                "Every scored action is supported by primary CBC event telemetry; "
                "hidden alert correspondence is not required."
            ),
            "paired_stage_contract": copy.deepcopy(gold["paired_stage_contract"])
            | {"chain_index": chain_number},
        }
    )
    for key in (
        "neutral_anchor_all_stages",
        "neutral_anchor_provenance",
        "enforce_time_scope",
        "input_provenance",
    ):
        case.pop(key, None)
    if stage == "stage3":
        case["model_ready_input"]["db_filter"] = (
            "remove cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; "
            "retain primary cbc_events telemetry"
        )
    else:
        case["model_ready_input"].pop("db_filter", None)
    return case


def values_equal(gold_value: Any, db_value: Any) -> bool:
    return v3.values_equal(gold_value, db_value)


def validate(
    cases: list[dict[str, Any]],
    gold_by_chain: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    stage_counts = Counter(case["stage"] for case in cases)
    if stage_counts != Counter({stage: 8 for stage in STAGES}):
        failures.append({"check": "stage_counts", "actual": dict(stage_counts)})
    if len(cases) != 24 or len({case["instance_id"] for case in cases}) != 24:
        failures.append({"check": "case_identity", "actual": len(cases)})
    if set(gold_by_chain) != set(STEP_SPECS):
        failures.append({"check": "chain_set"})

    comparisons = 0
    mismatches: list[dict[str, Any]] = []
    total_steps = 0
    total_supporting_rows = 0
    chain_reports: list[dict[str, Any]] = []
    for chain_id, gold in sorted(gold_by_chain.items()):
        steps = gold["gold_steps"]
        total_steps += len(steps)
        expected_count = EXPECTED_STEPS_BY_CHAIN[chain_id]
        if len(steps) != expected_count:
            failures.append(
                {
                    "check": "step_count",
                    "chain_id": chain_id,
                    "expected": expected_count,
                    "actual": len(steps),
                }
            )
        expected_primary = {int(item["row_id"]) for item in STEP_SPECS[chain_id]}
        actual_primary = {
            int(evidence["source_row_id"])
            for step in steps
            for evidence in step.get("canonical_evidence") or []
        }
        if actual_primary != expected_primary:
            failures.append({"check": "primary_rows", "chain_id": chain_id})
        if any(
            PID_TOKEN.search(str(step.get(field) or ""))
            for step in steps
            for field in ("subject", "object")
        ):
            failures.append({"check": "pid_leaked_into_scored_component", "chain_id": chain_id})
        if any(
            step.get("evidence_kind") == "file"
            for step in steps
        ):
            failures.append({"check": "raw_file_step_remains", "chain_id": chain_id})

        all_rows = []
        for step in steps:
            all_rows.extend(step.get("canonical_evidence") or [])
            supporting = (step.get("supporting_evidence") or {}).get(
                "supporting_canonical_rows", []
            )
            total_supporting_rows += len(supporting)
            all_rows.extend(supporting)
        start = v3.parse_time(gold["input_scope"]["chain_window_start_utc"])
        end = v3.parse_time(gold["input_scope"]["chain_window_end_utc"])
        if end - start != timedelta(minutes=5):
            failures.append({"check": "five_minute_window", "chain_id": chain_id})
        if any(
            not start <= v3.parse_time(str(row["timestamp_utc"])) <= end
            for row in all_rows
        ):
            failures.append({"check": "evidence_outside_window", "chain_id": chain_id})

        connection = sqlite3.connect(v3.db_path(gold))
        connection.row_factory = sqlite3.Row
        try:
            for evidence in all_rows:
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
                for gold_field, db_field in v3.CANONICAL_DB_FIELDS.items():
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

        paired = [case for case in cases if case["chain_id"] == chain_id]
        scope_signatures = {
            (
                case["host"],
                case["process_name"],
                case["time_window_utc"]["episode_start"],
                case["time_window_utc"]["episode_end"],
                case["gold_chain_file"],
            )
            for case in paired
        }
        if len(paired) != 3 or len(scope_signatures) != 1:
            failures.append({"check": "paired_scope", "chain_id": chain_id})
        for case in paired:
            model_input = case["model_ready_input"]["input"]
            required = {
                "host",
                "focus_processes",
                "chain_window_start_utc",
                "chain_window_end_utc",
            }
            expected_keys = required | ({"alerts"} if case["stage"] == "stage1" else set())
            if set(model_input) != expected_keys:
                failures.append(
                    {
                        "check": "normal23_input_shape",
                        "instance_id": case["instance_id"],
                        "keys": sorted(model_input),
                    }
                )
            if case["stage"] == "stage1":
                if len(case.get("input_alert_rows") or []) != 1:
                    failures.append({"check": "stage1_alert", "instance_id": case["instance_id"]})
                if case["anchor_event"].get("action") != "cbc_alert":
                    failures.append({"check": "stage1_anchor", "instance_id": case["instance_id"]})
            else:
                if case.get("input_alert_rows"):
                    failures.append({"check": "stage23_alert_leak", "instance_id": case["instance_id"]})
                if case["anchor_event"].get("action") != "scope":
                    failures.append({"check": "stage23_anchor", "instance_id": case["instance_id"]})
        chain_reports.append(
            {
                "chain_id": chain_id,
                "step_count": len(steps),
                "primary_row_ids": sorted(actual_primary),
                "supporting_not_scored_row_ids": sorted(
                    {
                        int(row_id)
                        for step in steps
                        for row_id in (step.get("supporting_evidence") or {}).get(
                            "supporting_source_row_ids", []
                        )
                    }
                ),
                "pid_identity_scored": False,
                "raw_file_lifecycle_step_count": 0,
                "normal23_model_input_shape": True,
            }
        )

    if total_steps != EXPECTED_STEP_TOTAL:
        failures.append(
            {
                "check": "total_steps",
                "expected": EXPECTED_STEP_TOTAL,
                "actual": total_steps,
            }
        )
    if mismatches:
        failures.append(
            {"check": "canonical_database_equality", "count": len(mismatches)}
        )
    return {
        "status": "pass" if not failures else "fail",
        "suite": SUITE,
        "contract_version": CONTRACT_VERSION,
        "reference_normal_case_file": (
            "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
        ),
        "reference_normal_gold_root": (
            "data/current_experiment/gold/cbc_alert_behavior_chain_gold"
        ),
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "chain_count": len(gold_by_chain),
        "gold_step_count_unique": total_steps,
        "gold_step_count_across_stages": total_steps * 3,
        "supporting_not_scored_row_count_unique": total_supporting_rows,
        "source_database_field_comparisons": comparisons,
        "source_database_mismatch_count": len(mismatches),
        "source_database_mismatches": mismatches,
        "normal23_model_input_shape": True,
        "five_minute_window": True,
        "pid_identity_scored": False,
        "hidden_alert_mapping_scored": False,
        "critical_evidence_separate_diagnostic": True,
        "command_line_independent_candidate_slot": False,
        "raw_file_lifecycle_step_count": 0,
        "chain_reports": chain_reports,
        "failures": failures,
    }


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
    source_gold_by_chain = {
        str(case["chain_id"]): json.loads(
            (args.source_gold_root / str(case["gold_chain_file"])).read_text(
                encoding="utf-8"
            )
        )
        for case in source_stage1
    }
    output_chain_ids = {
        RENAMED_CHAINS.get(chain_id, chain_id)
        for chain_id in source_gold_by_chain
    }
    if output_chain_ids != set(STEP_SPECS):
        raise SystemExit(
            "source/output chain set mismatch: "
            f"source={sorted(source_gold_by_chain)} "
            f"output={sorted(output_chain_ids)} expected={sorted(STEP_SPECS)}"
        )

    cases: list[dict[str, Any]] = []
    gold_by_chain: dict[str, dict[str, Any]] = {}
    gold_index: list[dict[str, Any]] = []
    for chain_number, source_case in enumerate(source_stage1, 1):
        source_chain_id = str(source_case["chain_id"])
        chain_id = RENAMED_CHAINS.get(source_chain_id, source_chain_id)
        source_gold = copy.deepcopy(source_gold_by_chain[source_chain_id])
        source_gold["chain_id"] = chain_id
        if chain_id in REPRESENTATIVE_ALERT_ROW_OVERRIDES:
            representative_alert = fetch_alert_row(
                source_gold,
                REPRESENTATIVE_ALERT_ROW_OVERRIDES[chain_id],
            )
            source_case = copy.deepcopy(source_case)
            source_case["input_alert_rows"] = [copy.deepcopy(representative_alert)]
        else:
            representative_alert = copy.deepcopy(source_case["input_alert_rows"][0])
        gold, window_start, window_end = build_gold(
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
                "source_chain_id": source_chain_id,
                "window_start_utc": window_start,
                "window_end_utc": window_end,
                "gold_step_count": len(gold["gold_steps"]),
                "pid_identity_scored": False,
                "hidden_alert_mapping_scored": False,
                "gold_sha256": sha256(gold_path),
            }
        )
        for stage in STAGES:
            cases.append(
                build_case(
                    source_case,
                    gold,
                    gold_file,
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
                "Evaluate attack process-behavior reconstruction at the same "
                "semantic chain granularity and Stage input shape as the original "
                "23 normal-use-case experiment."
            ),
            "reference_normal_case_file": (
                "data/current_experiment/cases/"
                "cbc_23_chain_stage_cases_2026-06-12.jsonl"
            ),
            "reference_normal_gold_root": (
                "data/current_experiment/gold/cbc_alert_behavior_chain_gold"
            ),
            "source_case_file": str(args.source_cases.relative_to(ROOT)),
            "source_gold_root": str(args.source_gold_root.relative_to(ROOT)),
            "case_file": str(args.out_cases.relative_to(ROOT)),
            "gold_root": str(args.out_gold_root.relative_to(ROOT)),
            "stage_counts": {stage: 8 for stage in STAGES},
            "total_model_inputs": len(cases),
            "evaluation_unit": "eight process-attributed causal behavior chains",
            "window_policy": "same five-minute finalized chain scope in all stages",
            "model_input_policy": {
                "stage1": "host + focus process + five-minute scope + representative alert",
                "stage2": "host + focus process + five-minute scope",
                "stage3": "Stage 2 input with CBC alert summaries hidden",
                "neutral_event_anchor_exposed": False,
                "target_chain_rule_exposed": False,
            },
            "target_chain_rule": TARGET_CHAIN_RULE,
            "scoring_policy": {
                "action_components": ["subject", "action", "object"],
                "critical_evidence": "separate diagnostic",
                "order": "adjacent Gold-pair recall",
                "candidate_precision": "literal candidate action-slot precision",
                "pid_identity": "provenance only; not scored",
                "command_line": "action/evidence attribute; not an independent slot",
                "hidden_alert_mapping": "excluded",
                "attack_label_or_intent": "excluded",
            },
            "agent_call_limit_policy": "unbounded_by_experiment",
            "gold_step_count_unique": EXPECTED_STEP_TOTAL,
            "gold_step_counts_by_chain": EXPECTED_STEPS_BY_CHAIN,
            "gold_index": gold_index,
            "validation": str(args.validation.relative_to(ROOT)),
        },
    )
    print(
        json.dumps(
            {
                "status": "pass",
                "suite": SUITE,
                "cases": str(args.out_cases),
                "case_count": len(cases),
                "stage_counts": dict(Counter(case["stage"] for case in cases)),
                "gold_step_count_unique": validation["gold_step_count_unique"],
                "gold_step_counts_by_chain": EXPECTED_STEPS_BY_CHAIN,
                "pid_identity_scored": False,
                "normal23_model_input_shape": True,
                "validation": str(args.validation),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
