#!/usr/bin/env python3
"""Build the formally reviewed normal-23-parity attack process-chain Gold.

This version supersedes the v4 candidate without overwriting it.  It removes
purpose/intent wording not directly supported by primary telemetry, selects
non-overlapping five-minute scopes for repeated same-name process clusters, and
replaces the ambiguous S4 W2 case with the independently observable W3 Word
cluster and its matching CBC alert provenance.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import build_atlasv2_s3_s4_attack8_process_chain_v4_suite as base


ROOT = Path(__file__).resolve().parents[2]
VERSION = "20260727"
SUITE = "atlasv2_s3_s4_attack8_process_chain_v5_formal"
CONTRACT_VERSION = "process_behavior_chain_normal23_parity_v5_formal"


def evidence_neutral_specs() -> dict[str, list[dict[str, Any]]]:
    result = copy.deepcopy(base.STEP_SPECS)
    for items in result.values():
        for item in items:
            kind = str(item["evidence_kind"])
            subject = str(item["subject"])
            object_ = str(item["object"])
            if kind == "document_input":
                item["action"] = "文書を開いた"
            elif kind == "network":
                port = object_.rsplit(":", 1)[-1]
                item["action"] = f"外部ホストの{port}/tcpへ接続した"
            elif (
                kind == "process_creation"
                and subject.lower() == "winword.exe"
                and object_.lower() == "winword.exe"
            ):
                item["action"] = "WINWORD.EXEを子プロセスとして起動した"
            elif kind == "command_process_creation":
                item["action"] = (
                    "remote SCT URLを指定したregsvr32コマンドから"
                    "PowerShellを起動した"
                )
            item["one_line_ja"] = (
                f"{item['subject']} が {item['action']}。対象: {item['object']}。"
            )

    # W2 cannot be uniquely selected from process name + a five-minute scope:
    # W1, W2, and W3 are too close together.  W3 has its own document-open,
    # child-process, network rows and matching CBC alert rows (14/19).  A scope
    # starting at 00:51 excludes W1/W2 while retaining the complete W3 chain.
    result.pop("s4_pt_02_word_w2")
    result["s4_pt_02_word_w3"] = [
        base.spec(
            2358,
            "WINWORD.EXE",
            "文書を開いた",
            r"C:\Users\aalsahee\Downloads\s4-at-night\msf.doc",
            "document_input",
            "WINWORD.EXE が文書 msf.doc を開いた。",
        ),
        base.spec(
            2378,
            "WINWORD.EXE",
            "WINWORD.EXEを子プロセスとして起動した",
            "WINWORD.EXE",
            "process_creation",
            "WINWORD.EXE が子 WINWORD.EXE を起動した。",
        ),
        base.spec(
            3493,
            "WINWORD.EXE",
            "外部ホストの8080/tcpへ接続した",
            "10.193.66.115:8080",
            "network",
            "WINWORD.EXE が外部ホスト 10.193.66.115:8080 へ接続した。",
        ),
    ]
    return result


def configure() -> None:
    base.VERSION = VERSION
    base.SUITE = SUITE
    base.CONTRACT_VERSION = CONTRACT_VERSION
    base.STEP_ID_PREFIX = "A8V5"
    base.ID_NAMESPACE = "atlasv2_attack8_process_chain_v5_formal"
    base.QUALITY_LABEL = "normal23_process_chain_parity_v5_formal_20260727"
    base.STEP_SPECS = evidence_neutral_specs()
    base.EXPECTED_STEPS_BY_CHAIN = {
        chain_id: len(items) for chain_id, items in base.STEP_SPECS.items()
    }
    base.EXPECTED_STEP_TOTAL = sum(base.EXPECTED_STEPS_BY_CHAIN.values())
    base.RENAMED_CHAINS = {
        "s4_pt_02_word_w2": "s4_pt_02_word_w3",
    }
    base.REPRESENTATIVE_ALERT_ROW_OVERRIDES = {
        "s4_pt_02_word_w3": 19,
    }
    base.CHAIN_METADATA_OVERRIDES = {
        "s4_pt_02_word_w3": {
            "chain_title": "S4-W3: explorer-launched Word process chain",
            "chain_description": (
                "A single causally connected Word chain: WINWORD.EXE opens "
                "msf.doc, launches an embedded child WINWORD.EXE, and connects "
                "to the observed external endpoint."
            ),
            "observed_behavior": (
                "WINWORD.EXE opens msf.doc, launches child WINWORD.EXE, and "
                "connects to 10.193.66.115:8080."
            ),
        },
    }
    base.WINDOW_OVERRIDES = {
        "s3_pt_01_word_document_processing": (
            "2022-07-19T14:31:00Z",
            "2022-07-19T14:36:00Z",
        ),
        "s3_pt_02_regsvr32_remote_sct": (
            "2022-07-19T14:31:00Z",
            "2022-07-19T14:36:00Z",
        ),
        "s3_pt_03_regsvr32_long_chain": (
            "2022-07-19T14:36:00Z",
            "2022-07-19T14:41:00Z",
        ),
        "s3_pt_04_powershell_mid_chain": (
            "2022-07-19T14:36:00Z",
            "2022-07-19T14:41:00Z",
        ),
        "s4_pt_01_word_w1": (
            "2022-07-20T00:45:30Z",
            "2022-07-20T00:50:30Z",
        ),
        "s4_pt_02_word_w3": (
            "2022-07-20T00:51:00Z",
            "2022-07-20T00:56:00Z",
        ),
        "s4_pt_03_mshta_c1": (
            "2022-07-20T00:53:30Z",
            "2022-07-20T00:58:30Z",
        ),
        "s4_pt_04_powershell_c1": (
            "2022-07-20T00:53:30Z",
            "2022-07-20T00:58:30Z",
        ),
    }
    base.OUT_CASES = (
        ROOT
        / "data/current_experiment/cases"
        / f"{SUITE}_stage_cases_{VERSION}.jsonl"
    )
    base.OUT_GOLD_ROOT = (
        ROOT / "data/current_experiment/gold" / f"{SUITE}_gold_{VERSION}"
    )
    base.OUT_MANIFEST = (
        ROOT / "data/current_experiment/cases" / f"{SUITE}_manifest_{VERSION}.json"
    )
    base.OUT_VALIDATION = (
        ROOT
        / "docs/current_experiment"
        / f"{SUITE}_build_validation_{VERSION}.json"
    )


def main() -> None:
    configure()
    base.main()


if __name__ == "__main__":
    main()
