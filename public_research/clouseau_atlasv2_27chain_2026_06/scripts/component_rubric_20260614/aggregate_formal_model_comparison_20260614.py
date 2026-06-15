from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs/current_experiment/results_2026-06-09/formal_model_comparison_20260614"
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
CHAIN_SUMMARY = ROOT / "data/current_experiment/gold/cbc_non_alert_behavior_chain_gold_2026-06-11/chain_summary.csv"

LEDGER_2REP = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612/codex_double_reviews.jsonl"
LEDGER_GPT55 = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_3rep_20260613/codex_double_reviews.jsonl"
LEDGER_ADDITIONAL = ROOT / "data/current_experiment/scores/additional_repeats_20260612/r1/codex_double_reviews.jsonl"


FRAMEWORK_LABELS = {
    "dns_packet_capture_batch_chain": "collection_or_tool_invocation",
    "python_simplehttpserver_network_chain": "network_service_behavior",
    "sublime_python_script_execution_chain": "script_execution_chain",
    "cmdexe_other_chain": "command_shell_execution",
    "discord_run_key_registry_chain": "persistence_registry_run_key",
}

STAGE_LABELS = {
    "stage1": "alert_clue",
    "stage2": "process_time_clue",
    "stage3": "non_alert_telemetry_only",
}


@dataclass(frozen=True)
class DatasetSpec:
    label: str
    ledger: Path
    models: tuple[str, ...]
    replicates: tuple[str, ...]
    include_gpt55_complete_first_round_only: bool = False


DATASETS = [
    DatasetSpec(
        label="gpt-4.1-mini_2complete_reps",
        ledger=LEDGER_2REP,
        models=("gpt-4.1-mini",),
        replicates=("replicate_01", "replicate_02"),
    ),
    DatasetSpec(
        label="gpt-5.4-mini_2complete_reps",
        ledger=LEDGER_2REP,
        models=("gpt-5.4-mini",),
        replicates=("replicate_01", "replicate_02"),
    ),
    DatasetSpec(
        label="gpt-5.5_low_1complete_rep",
        ledger=LEDGER_GPT55,
        models=("gpt-5.5",),
        replicates=("replicate_01",),
        include_gpt55_complete_first_round_only=True,
    ),
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_cases() -> dict[str, dict[str, Any]]:
    cases = read_jsonl(CASE_FILE)
    return {str(case["instance_id"]): case for case in cases}


def read_chain_summary() -> dict[str, dict[str, Any]]:
    with CHAIN_SUMMARY.open("r", encoding="utf-8", newline="") as f:
        return {row["chain_id"]: row for row in csv.DictReader(f)}


def pct(hit: int, total: int) -> str:
    if total == 0:
        return "NA"
    return f"{hit / total:.3f}"


def f1(precision_hit: int, precision_total: int, recall_hit: int, recall_total: int) -> str:
    if precision_total == 0 or recall_total == 0:
        return "NA"
    precision = precision_hit / precision_total
    recall = recall_hit / recall_total
    if precision + recall == 0:
        return "0.000"
    return f"{2 * precision * recall / (precision + recall):.3f}"


def row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("replicate") or ""),
        str(row.get("model") or ""),
        str(row.get("stage") or ""),
        str(row.get("instance_id") or ""),
    )


def expected_keys(cases: dict[str, dict[str, Any]], spec: DatasetSpec) -> set[tuple[str, str, str, str]]:
    return {
        (replicate, model, str(case["stage"]), instance_id)
        for replicate in spec.replicates
        for model in spec.models
        for instance_id, case in cases.items()
    }


def load_scored_rows(cases: dict[str, dict[str, Any]], chain_summary: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in DATASETS:
        expected = expected_keys(cases, spec)
        seen: set[tuple[str, str, str, str]] = set()
        for row in read_jsonl(spec.ledger):
            key = row_key(row)
            if key not in expected:
                continue
            if row.get("two_review_adoptable") is not True:
                continue
            case = cases.get(key[3], {})
            chain_id = str(row.get("chain_id") or case.get("chain_id") or "")
            chain_type = str(case.get("chain_type") or chain_summary.get(chain_id, {}).get("chain_type") or "")
            enriched = dict(row)
            enriched["dataset_label"] = spec.label
            enriched["stage_label"] = STAGE_LABELS.get(key[2], key[2])
            enriched["chain_type"] = chain_type
            enriched["framework_group"] = FRAMEWORK_LABELS.get(chain_type, chain_type or "unknown")
            enriched["expected_behavior_category"] = case.get("expected_behavior_category") or chain_type
            enriched["evaluable_chain"] = chain_summary.get(chain_id, {}).get("evaluable")
            rows.append(enriched)
            seen.add(key)
        missing = sorted(expected - seen)
        if missing:
            print(json.dumps({"dataset": spec.label, "missing_review_count": len(missing), "first_missing": missing[:5]}, ensure_ascii=False))
    return rows


def summarize_group(rows: list[dict[str, Any]], group_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[tuple(row.get(field) for field in group_fields)].append(row)

    out: list[dict[str, Any]] = []
    for key, bucket in sorted(buckets.items(), key=lambda item: tuple("" if v is None else str(v) for v in item[0])):
        recall_hits = sum(int(row.get("recall_hits") or 0) for row in bucket)
        recall_total = sum(int(row.get("recall_total") or 0) for row in bucket)
        precision_hits = sum(int(row.get("precision_hits") or 0) for row in bucket)
        precision_total = sum(int(row.get("precision_total") or 0) for row in bucket)
        order_hits = sum(int(row.get("behavior_sequence_order_hits") or 0) for row in bucket)
        order_total = sum(int(row.get("behavior_sequence_order_total") or 0) for row in bucket)
        gold_step_total = sum(int(row.get("gold_step_count") or 0) for row in bucket)
        candidate_step_total = sum(int(row.get("candidate_step_count") or 0) for row in bucket)
        chain_ids = {str(row.get("chain_id") or "") for row in bucket}
        evaluable_chain_ids = {str(row.get("chain_id") or "") for row in bucket if int(row.get("gold_step_count") or 0) > 0}
        summary = {field: key[i] for i, field in enumerate(group_fields)}
        summary.update(
            {
                "run_count": len(bucket),
                "chain_count": len(chain_ids),
                "evaluable_chain_count": len(evaluable_chain_ids),
                "gold_step_total": gold_step_total,
                "candidate_step_total": candidate_step_total,
                "recall_hits": recall_hits,
                "recall_total": recall_total,
                "recall": pct(recall_hits, recall_total),
                "precision_hits": precision_hits,
                "precision_total": precision_total,
                "precision": pct(precision_hits, precision_total),
                "f1": f1(precision_hits, precision_total, recall_hits, recall_total),
                "behavior_sequence_order_hits": order_hits,
                "behavior_sequence_order_total": order_total,
                "behavior_sequence_order": pct(order_hits, order_total),
            }
        )
        out.append(summary)
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(rows: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


def write_summary_md(tables: dict[str, list[dict[str, Any]]]) -> None:
    overall_fields = [
        "dataset_label",
        "run_count",
        "chain_count",
        "evaluable_chain_count",
        "gold_step_total",
        "candidate_step_total",
        "recall",
        "precision",
        "f1",
        "behavior_sequence_order",
    ]
    stage_fields = [
        "dataset_label",
        "stage",
        "stage_label",
        "run_count",
        "gold_step_total",
        "candidate_step_total",
        "recall",
        "precision",
        "f1",
        "behavior_sequence_order",
    ]
    framework_fields = [
        "dataset_label",
        "framework_group",
        "run_count",
        "chain_count",
        "gold_step_total",
        "candidate_step_total",
        "recall",
        "precision",
        "f1",
        "behavior_sequence_order",
    ]
    md = [
        "# Formal Model Comparison 2026-06-14",
        "",
        "Scope: complete comparable blocks only. gpt-4.1-mini and gpt-5.4-mini use two complete replicates; gpt-5.5 uses the first complete low-reasoning replicate. Partial gpt-5.5 replicate_02 rows are excluded from headline comparison.",
        "",
        "Metric unit: behavior_plus_evidence_step. Recall denominator is gold steps; precision denominator is candidate steps; sequence-order denominator is gold steps.",
        "",
        "## Overall",
        "",
        markdown_table(tables["overall"], overall_fields),
        "",
        "## By Stage",
        "",
        markdown_table(tables["by_stage"], stage_fields),
        "",
        "## By Security Framework Group",
        "",
        markdown_table(tables["by_framework"], framework_fields),
        "",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def audit_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for row in rows:
        row_issues: list[str] = []
        if row.get("evaluation_unit") != "behavior_plus_evidence_step":
            row_issues.append("unexpected_evaluation_unit")
        if row.get("review1_pass") is not True or row.get("review2_pass") is not True:
            row_issues.append("double_review_not_passed")
        if row.get("two_review_adoptable") is not True:
            row_issues.append("not_adoptable")
        if int(row.get("recall_hits") or 0) > int(row.get("recall_total") or 0):
            row_issues.append("recall_hits_exceed_total")
        if int(row.get("precision_hits") or 0) > int(row.get("precision_total") or 0):
            row_issues.append("precision_hits_exceed_total")
        if int(row.get("behavior_sequence_order_hits") or 0) > int(row.get("behavior_sequence_order_total") or 0):
            row_issues.append("order_hits_exceed_total")
        if int(row.get("candidate_step_count") or 0) != int(row.get("precision_total") or 0):
            row_issues.append("candidate_precision_denominator_mismatch")
        if int(row.get("gold_step_count") or 0) != int(row.get("recall_total") or 0):
            row_issues.append("gold_recall_denominator_mismatch")
        if int(row.get("gold_step_count") or 0) != int(row.get("behavior_sequence_order_total") or 0):
            row_issues.append("gold_order_denominator_mismatch")
        if row_issues:
            issues.append(
                {
                    "dataset_label": row.get("dataset_label"),
                    "replicate": row.get("replicate"),
                    "model": row.get("model"),
                    "stage": row.get("stage"),
                    "instance_id": row.get("instance_id"),
                    "issues": ";".join(row_issues),
                }
            )
    return issues


def main() -> None:
    cases = read_cases()
    chain_summary = read_chain_summary()
    rows = load_scored_rows(cases, chain_summary)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    per_run_rows = sorted(
        rows,
        key=lambda row: (
            str(row.get("dataset_label") or ""),
            str(row.get("replicate") or ""),
            str(row.get("stage") or ""),
            str(row.get("instance_id") or ""),
        ),
    )
    write_csv(OUT_DIR / "per_run_scores.csv", per_run_rows)

    tables = {
        "overall": summarize_group(rows, ("dataset_label",)),
        "by_stage": summarize_group(rows, ("dataset_label", "stage", "stage_label")),
        "by_framework": summarize_group(rows, ("dataset_label", "framework_group")),
        "by_chain_type": summarize_group(rows, ("dataset_label", "chain_type")),
        "by_stage_framework": summarize_group(rows, ("dataset_label", "stage", "stage_label", "framework_group")),
    }
    for name, table_rows in tables.items():
        write_csv(OUT_DIR / f"{name}.csv", table_rows)
    write_csv(OUT_DIR / "audit_issues.csv", audit_rows(rows))
    write_summary_md(tables)

    print(json.dumps({"out_dir": OUT_DIR.relative_to(ROOT).as_posix(), "row_count": len(rows), "audit_issue_count": len(audit_rows(rows))}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
