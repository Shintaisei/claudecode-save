#!/usr/bin/env python3
"""Rebuild the four-way failure analysis after the semantic re-audit.

This script does not overwrite the observable-semantic v2 scores.  It creates
an auditable v3 view with two corrections that were previously left only as
sensitivity/manual-review findings:

1. cmd -> script invocation and interpreter -> script read are accepted as
   equivalent representations for the Sublime/Python case.
2. The repeated tshark/dumpcap instance-alignment error is classified as a
   final adoption omission, not as a relation-construction error.  Each run
   still contributes one failed Gold relation; only the failure stage changes.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V2_ROWS = (
    ROOT
    / "docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2"
    / "observable_rescore_all_384.jsonl"
)
TRACE_ROWS = (
    ROOT
    / "docs/current_experiment/results_2026-08-14/three_model_pipeline_trace_errors_v1"
    / "gold_step_pipeline_trace.jsonl"
)
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-15/failure_analysis_semantic_v3"
)

MODELS = ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5")
LABELS = (
    "調査段階／調査論点の設定漏れ",
    "調査段階／証跡探索の失敗",
    "まとめ段階／調査結果の採用漏れ",
    "まとめ段階／関係整理の誤り",
)
STATUS_TO_LABEL = {
    "ISSUE_NOT_RAISED_FINAL_OMISSION": LABELS[0],
    "ISSUE_RAISED_EVIDENCE_NOT_FOUND_FINAL_OMISSION": LABELS[1],
    "EVIDENCE_FOUND_NOT_REFLECTED_IN_FINAL": LABELS[2],
    "EVIDENCE_FOUND_FINAL_RELATION_ERROR": LABELS[3],
}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def key(row: dict, step_id: str) -> tuple[str, str, str, str, str, str]:
    return (
        row["model"],
        row["phase"],
        row["replicate"],
        row["stage"],
        row["chain_id"],
        step_id,
    )


def exact_port_missing(trace: dict) -> bool:
    gold = str(trace.get("gold_object") or "")
    ports = re.findall(r"(?::|port\s+)(\d{2,5})", gold.lower())
    if not ports:
        return False
    tokens: list[str] = []
    semantic = trace.get("semantic_evidence_match") or {}
    tokens.extend(str(x).lower() for x in semantic.get("object_match_tokens") or [])
    tokens.extend(str(x).lower() for x in trace.get("matched_evidence_identifiers") or [])
    return not any(
        f"port:{port}" in token or f":{port}" in token
        for port in ports
        for token in tokens
    )


def is_launcher_interpreter_equivalent(row: dict, step: dict) -> bool:
    return bool(
        row["chain_id"].startswith("chain_11_")
        and step["step_id"] == "N8V3-07-S03"
        and step["launcher_interpreter_sensitivity_complete"]
        and not step["observable_complete"]
    )


def is_tshark_instance_alignment_case(row: dict, step: dict, label: str) -> bool:
    return bool(
        row["model"] == "gpt-5.5"
        and row["chain_id"].startswith("chain_04_")
        and step["step_id"] == "N8V3-02-S06"
        and label == LABELS[3]
    )


def main() -> None:
    rows = read_jsonl(V2_ROWS)
    traces = {key(row, row["step_id"]): row for row in read_jsonl(TRACE_ROWS)}
    records: list[dict] = []
    rescued: list[dict] = []
    summary: dict[str, dict] = {}

    for model in MODELS:
        counts: Counter[str] = Counter()
        untraceable = 0
        failed_steps = 0
        for row in rows:
            if row["model"] != model:
                continue
            for step in row["steps"]:
                if step["observable_complete"]:
                    continue

                base = {
                    "model": model,
                    "phase": row["phase"],
                    "replicate": row["replicate"],
                    "stage": row["stage"],
                    "chain_id": row["chain_id"],
                    "original_step_id": step["step_id"],
                    "gold_subject": step["gold_subject"],
                    "gold_action": step["gold_action"],
                    "gold_object": step["gold_object"],
                }

                if is_launcher_interpreter_equivalent(row, step):
                    rescued.append(
                        {
                            **base,
                            "decision": "semantic_equivalent_success",
                            "reason": (
                                "The interpreter-to-script read is accepted as an "
                                "evidence-backed representation of script execution."
                            ),
                        }
                    )
                    continue

                failed_steps += 1
                trace = traces.get(key(row, step["step_id"]))
                if trace is None:
                    untraceable += 1
                    records.append({**base, "classification": "調査過程を追跡できない"})
                    continue

                status = str(trace["pipeline_status"])
                if status == "EVIDENCE_FOUND_NOT_REFLECTED_IN_FINAL" and exact_port_missing(trace):
                    status = "ISSUE_NOT_RAISED_FINAL_OMISSION"

                if status in {
                    "FINAL_PARTIAL_WITHOUT_TRACEABLE_INVESTIGATION",
                    "FINAL_CORRECT_WITHOUT_TRACEABLE_INVESTIGATION",
                }:
                    untraceable += 1
                    records.append({**base, "classification": "調査過程を追跡できない"})
                    continue

                label = STATUS_TO_LABEL.get(status)
                if label is None and status == "EVIDENCE_FOUND_REFLECTED_CORRECTLY":
                    label = LABELS[3]
                if label is None:
                    raise AssertionError(f"Unmapped pipeline status: {status}")

                adjusted_step_id = step["step_id"]
                correction = ""
                if is_tshark_instance_alignment_case(row, step, label):
                    label = LABELS[2]
                    correction = "tshark_dumpcap_instance_alignment"
                    # In these two runs the single final claim represents the
                    # worker (PID 2384), so the actually omitted Gold relation
                    # is the discovery probe.  The other runs omit the worker.
                    if row["replicate"] == "replicate_02" and row["stage"] in {
                        "stage2",
                        "stage3",
                    }:
                        adjusted_step_id = "N8V3-02-S05"

                counts[label] += 1
                records.append(
                    {
                        **base,
                        "adjusted_failed_step_id": adjusted_step_id,
                        "classification": label,
                        "pipeline_status": status,
                        "correction": correction,
                    }
                )

        denominator = sum(counts.values())
        summary[model] = {
            "failed_gold_steps_after_semantic_equivalence": failed_steps,
            "traceable_failure_denominator": denominator,
            "untraceable_failure_steps": untraceable,
            "counts": {label: counts[label] for label in LABELS},
            "percentages": {
                label: (100.0 * counts[label] / denominator if denominator else None)
                for label in LABELS
            },
            "rescued_semantic_equivalent_steps": sum(
                1 for item in rescued if item["model"] == model
            ),
        }

    expected = {
        "gpt-4.1-mini": [165, 49, 93, 73],
        "gpt-5.4-mini": [278, 93, 67, 23],
        "gpt-5.5": [49, 24, 23, 12],
    }
    for model, expected_counts in expected.items():
        actual = [summary[model]["counts"][label] for label in LABELS]
        if actual != expected_counts:
            raise AssertionError(f"Unexpected {model} counts: {actual} != {expected_counts}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "failure_step_audit.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    with (OUT_DIR / "semantic_equivalent_rescues.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for record in rescued:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    (OUT_DIR / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": "failure_analysis_semantic_v3",
                "source_v2": str(V2_ROWS.relative_to(ROOT)).replace("\\", "/"),
                "source_trace": str(TRACE_ROWS.relative_to(ROOT)).replace("\\", "/"),
                "policy": {
                    "failure_percentage_denominator": "traceable failed Gold relations after adopted semantic equivalence",
                    "untraceable_excluded": True,
                    "launcher_interpreter_equivalence_adopted": True,
                    "tshark_dumpcap_instance_alignment_reclassified": True,
                },
                "by_model": summary,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with (OUT_DIR / "failure_analysis_by_model.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as f:
        writer = csv.writer(f)
        writer.writerow(["大分類", "小分類", *MODELS])
        for label in LABELS:
            major, minor = label.split("／", 1)
            writer.writerow(
                [major, minor]
                + [f'{summary[m]["percentages"][label]:.2f}%' for m in MODELS]
            )
        writer.writerow(["合計", "", "100.00%", "100.00%", "100.00%"])

    report_lines = [
        "# 失敗パターン再監査 v3",
        "",
        "割合の分母は、意味同値を正解へ戻した後の追跡可能な未復元Gold relationである。追跡不能は除外した。",
        "",
        "| 大分類 | 小分類 | GPT-4.1-mini | GPT-5.4-mini | GPT-5.5 |",
        "|---|---|---:|---:|---:|",
    ]
    for label in LABELS:
        major, minor = label.split("／", 1)
        report_lines.append(
            "| "
            + " | ".join(
                [major, minor]
                + [f'{summary[m]["percentages"][label]:.2f}%' for m in MODELS]
            )
            + " |"
        )
    report_lines.extend(
        [
            "| 合計 |  | 100.00% | 100.00% | 100.00% |",
            "",
            "## 分母",
            "",
            "| モデル | 追跡可能な失敗 | 追跡不能 | 意味同値として正解へ戻したstep |",
            "|---|---:|---:|---:|",
        ]
    )
    for model in MODELS:
        item = summary[model]
        report_lines.append(
            f'| {model} | {item["traceable_failure_denominator"]} | '
            f'{item["untraceable_failure_steps"]} | '
            f'{item["rescued_semantic_equivalent_steps"]} |'
        )
    report_lines.extend(
        [
            "",
            "GPT-5.5ではSublime/Pythonの6 stepを意味同値として正解へ戻し、"
            "tshark/dumpcapの6回を関係整理ミスから採用漏れへ移した。",
            "そのため関係整理の誤りは24/114（21.05%）から12/108（11.11%）へ下がる。",
        ]
    )
    (OUT_DIR / "report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
