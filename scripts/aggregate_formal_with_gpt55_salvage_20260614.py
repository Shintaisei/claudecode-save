from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs/current_experiment/results_2026-06-09/formal_model_comparison_with_gpt55_salvage_20260614"
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
CHAIN_SUMMARY = ROOT / "data/current_experiment/gold/cbc_non_alert_behavior_chain_gold_2026-06-11/chain_summary.csv"

LEDGER_2REP = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612/codex_double_reviews.jsonl"
LEDGER_GPT55_STRICT = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_3rep_20260613/codex_double_reviews.jsonl"
LEDGER_GPT55_SALVAGE = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_salvage_20260614/codex_salvage_double_reviews.jsonl"


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
    scoring_mode: str
    comparison_scope: str


DATASETS = [
    DatasetSpec("gpt-4.1-mini_2rep_strict", LEDGER_2REP, ("gpt-4.1-mini",), ("replicate_01", "replicate_02"), "strict_json", "full_available"),
    DatasetSpec("gpt-5.4-mini_2rep_strict", LEDGER_2REP, ("gpt-5.4-mini",), ("replicate_01", "replicate_02"), "strict_json", "full_available"),
    DatasetSpec("gpt-5.5_low_103run_strict_json", LEDGER_GPT55_STRICT, ("gpt-5.5",), ("replicate_01", "replicate_02"), "strict_json_format_failed", "full_available"),
    DatasetSpec("gpt-5.5_low_103run_salvage", LEDGER_GPT55_SALVAGE, ("gpt-5.5",), ("replicate_01", "replicate_02"), "raw_text_salvage", "full_available"),
    DatasetSpec("gpt-4.1-mini_rep1_strict", LEDGER_2REP, ("gpt-4.1-mini",), ("replicate_01",), "strict_json", "rep1_comparable"),
    DatasetSpec("gpt-5.4-mini_rep1_strict", LEDGER_2REP, ("gpt-5.4-mini",), ("replicate_01",), "strict_json", "rep1_comparable"),
    DatasetSpec("gpt-5.5_low_rep1_salvage", LEDGER_GPT55_SALVAGE, ("gpt-5.5",), ("replicate_01",), "raw_text_salvage", "rep1_comparable"),
    DatasetSpec("gpt-5.5_low_rep1_strict_json", LEDGER_GPT55_STRICT, ("gpt-5.5",), ("replicate_01",), "strict_json_format_failed", "rep1_comparable"),
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_cases() -> dict[str, dict[str, Any]]:
    return {str(row["instance_id"]): row for row in read_jsonl(CASE_FILE)}


def read_chain_summary() -> dict[str, dict[str, Any]]:
    with CHAIN_SUMMARY.open("r", encoding="utf-8", newline="") as f:
        return {row["chain_id"]: row for row in csv.DictReader(f)}


def key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("replicate") or ""),
        str(row.get("model") or ""),
        str(row.get("stage") or ""),
        str(row.get("instance_id") or ""),
    )


def ratio(hit: int, total: int) -> float | None:
    if total == 0:
        return None
    return hit / total


def f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def expected_keys(cases: dict[str, dict[str, Any]], spec: DatasetSpec) -> set[tuple[str, str, str, str]]:
    return {
        (replicate, model, str(case["stage"]), instance_id)
        for replicate in spec.replicates
        for model in spec.models
        for instance_id, case in cases.items()
    }


def load_rows(cases: dict[str, dict[str, Any]], chain_summary: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    audit: list[dict[str, Any]] = []
    for spec in DATASETS:
        expected = expected_keys(cases, spec)
        seen: set[tuple[str, str, str, str]] = set()
        for row in read_jsonl(spec.ledger):
            row_key = key(row)
            if row_key not in expected:
                continue
            if row.get("two_review_adoptable") is not True:
                continue
            issues: list[str] = []
            if row.get("review1_pass") is not True or row.get("review2_pass") is not True:
                issues.append("review_pass_missing")
            if int(row.get("candidate_step_count") or 0) != int(row.get("precision_total") or 0):
                issues.append("candidate_precision_total_mismatch")
            if int(row.get("gold_step_count") or 0) != int(row.get("recall_total") or 0):
                issues.append("gold_recall_total_mismatch")
            if int(row.get("gold_step_count") or 0) != int(row.get("behavior_sequence_order_total") or 0):
                issues.append("gold_order_total_mismatch")
            if spec.scoring_mode == "raw_text_salvage" and row.get("adjudication_pass") is True:
                review_status = "two_review_plus_adjudication"
            else:
                review_status = "two_review_agreed"
            case = cases.get(row_key[3], {})
            chain_id = str(row.get("chain_id") or case.get("chain_id") or "")
            chain_type = str(case.get("chain_type") or chain_summary.get(chain_id, {}).get("chain_type") or "")
            enriched = dict(row)
            enriched.update(
                {
                    "dataset_label": spec.label,
                    "comparison_scope": spec.comparison_scope,
                    "scoring_mode": spec.scoring_mode,
                    "review_status": review_status,
                    "stage_label": STAGE_LABELS.get(row_key[2], row_key[2]),
                    "chain_type": chain_type,
                    "framework_group": FRAMEWORK_LABELS.get(chain_type, chain_type or "unknown"),
                    "evaluable_chain": chain_summary.get(chain_id, {}).get("evaluable"),
                }
            )
            rows.append(enriched)
            seen.add(row_key)
            if issues:
                audit.append({"dataset_label": spec.label, "key": "|".join(row_key), "issues": ";".join(issues)})
        missing = sorted(expected - seen)
        # GPT-5.5 replicate_02 was quota-stopped after 34 valid runs; record but do not treat as a scoring defect.
        if missing:
            audit.append({"dataset_label": spec.label, "key": "", "issues": f"missing_expected_rows={len(missing)}; first={missing[:3]}"})
    return rows, audit


def summarize(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[tuple(row.get(field) for field in fields)].append(row)
    out: list[dict[str, Any]] = []
    for bucket_key, bucket in sorted(buckets.items(), key=lambda item: tuple("" if v is None else str(v) for v in item[0])):
        rh = sum(int(row.get("recall_hits") or 0) for row in bucket)
        rt = sum(int(row.get("recall_total") or 0) for row in bucket)
        ph = sum(int(row.get("precision_hits") or 0) for row in bucket)
        pt = sum(int(row.get("precision_total") or 0) for row in bucket)
        oh = sum(int(row.get("behavior_sequence_order_hits") or 0) for row in bucket)
        ot = sum(int(row.get("behavior_sequence_order_total") or 0) for row in bucket)
        rec = ratio(rh, rt)
        prec = ratio(ph, pt)
        row = {field: bucket_key[i] for i, field in enumerate(fields)}
        row.update(
            {
                "run_count": len(bucket),
                "chain_count": len({str(item.get("chain_id") or "") for item in bucket}),
                "gold_step_total": rt,
                "candidate_step_total": pt,
                "recall_hits": rh,
                "recall_total": rt,
                "recall": rec,
                "precision_hits": ph,
                "precision_total": pt,
                "precision": prec,
                "f1": f1(prec, rec),
                "behavior_sequence_order_hits": oh,
                "behavior_sequence_order_total": ot,
                "behavior_sequence_order": ratio(oh, ot),
                "adjudicated_count": sum(1 for item in bucket if item.get("adjudication_pass") is True),
            }
        )
        out.append(row)
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for field in row.keys():
            if field not in fields:
                fields.append(field)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: Any) -> str:
    if value is None:
        return "NA"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def md_table(rows: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join(["---"] * len(fields)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(fmt(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


def main() -> None:
    cases = read_cases()
    chain_summary = read_chain_summary()
    rows, audit = load_rows(cases, chain_summary)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    tables = {
        "overall": summarize(rows, ("comparison_scope", "dataset_label", "scoring_mode")),
        "by_stage": summarize(rows, ("comparison_scope", "dataset_label", "scoring_mode", "stage", "stage_label")),
        "by_framework": summarize(rows, ("comparison_scope", "dataset_label", "scoring_mode", "framework_group")),
        "by_stage_framework": summarize(rows, ("comparison_scope", "dataset_label", "scoring_mode", "stage", "stage_label", "framework_group")),
    }
    write_csv(OUT_DIR / "per_run_scores.csv", rows)
    write_csv(OUT_DIR / "audit_issues.csv", audit)
    for name, table_rows in tables.items():
        write_csv(OUT_DIR / f"{name}.csv", table_rows)

    headline = [row for row in tables["overall"] if row["comparison_scope"] == "full_available"]
    comparable = [row for row in tables["overall"] if row["comparison_scope"] == "rep1_comparable"]
    stage_full = [row for row in tables["by_stage"] if row["comparison_scope"] == "full_available"]
    framework_full = [row for row in tables["by_framework"] if row["comparison_scope"] == "full_available"]

    fields_overall = ["dataset_label", "scoring_mode", "run_count", "chain_count", "gold_step_total", "candidate_step_total", "recall", "precision", "f1", "behavior_sequence_order", "adjudicated_count"]
    fields_stage = ["dataset_label", "stage", "stage_label", "run_count", "gold_step_total", "candidate_step_total", "recall", "precision", "f1", "behavior_sequence_order", "adjudicated_count"]
    fields_framework = ["dataset_label", "framework_group", "run_count", "chain_count", "gold_step_total", "candidate_step_total", "recall", "precision", "f1", "behavior_sequence_order", "adjudicated_count"]
    md = [
        "# Formal Model Comparison With GPT-5.5 Salvage 2026-06-14",
        "",
        "All score rows are Codex-reviewed. Strict-json rows use two accepted reviews. GPT-5.5 salvage rows use two independent Codex reviews; disagreements are accepted only after conservative adjudication using max(candidate_step_count) and min(hit counts).",
        "",
        "GPT-5.5 strict-json scoring remains a format-failure baseline because the runs did not emit formal JSON/code_steps. GPT-5.5 salvage is a separate raw-text evaluation and should be reported separately from strict-json scores.",
        "",
        "## Full Available Runs",
        "",
        md_table(headline, fields_overall),
        "",
        "## Replicate 1 Comparable Block",
        "",
        md_table(comparable, fields_overall),
        "",
        "## Full Available By Stage",
        "",
        md_table(stage_full, fields_stage),
        "",
        "## Full Available By Framework Group",
        "",
        md_table(framework_full, fields_framework),
        "",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"out_dir": OUT_DIR.relative_to(ROOT).as_posix(), "rows": len(rows), "audit_issue_rows": len(audit)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
