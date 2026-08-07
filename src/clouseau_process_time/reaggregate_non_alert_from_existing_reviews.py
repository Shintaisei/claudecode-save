#!/usr/bin/env python3
"""Re-aggregate accepted Codex review results for the non-alert gold policy.

This script does not call any model API. It reuses already accepted review
artifacts and removes chains whose gold is alert-only under the Stage3
non-alert policy.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RESULT_ROOT = ROOT / "docs" / "current_experiment" / "results_2026-06-09" / "formal_27_chain_experiment_20260609"
GPT41_ROOT = RESULT_ROOT / "scores_codex_manual_double_review"
GPT54_ROOT = RESULT_ROOT / "scores_codex_manual_double_review_gpt54"
OUT_ROOT = ROOT / "data" / "current_experiment" / "scores" / "non_alert_existing_review_reaggregate_20260611"
CASE_METADATA = ROOT / "public_research" / "clouseau_atlasv2_27chain_2026_06" / "experiment_metadata" / "case_metadata_81runs.json"
EXCLUDED_CHAINS = {
    "chain_03_e02_dns_packet_capture_batch_chain",
    "chain_08_e06_sublime_python_script_execution_chain",
    "chain_20_e14_dns_packet_capture_batch_chain",
    "chain_27_e19_dns_packet_capture_batch_chain",
}
METRIC_FIELDS = [
    "action_step_recall_hits",
    "action_step_recall_total",
    "critical_evidence_recall_hits",
    "critical_evidence_recall_total",
    "behavior_sequence_order_hits",
    "behavior_sequence_order_total",
    "candidate_claim_precision_hits",
    "candidate_claim_precision_total",
    "overclaim_slot_count",
]
ACTION_KINDS = {"subject", "operation", "object"}
ALERT_EVIDENCE_TOKENS = {
    "cbc-edr-alerts",
    "cbc-ngav-alerts",
    "cbc_alert",
    "cbc alerts",
    "alert_id",
    "alert_name",
    "report_name",
    "watchlist.hit",
    "report/reason",
}
SCENARIO_GROUP_LABELS = {
    "explicit_execution_chain": "明示的実行チェーン",
    "multi_step_tool_chain": "複数段ツールチェーン",
    "semantic_interpretation_chain": "意味解釈型チェーン",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def chain_id_from_instance(instance_id: str) -> str:
    for suffix in ("_stage1", "_stage2", "_stage3"):
        if instance_id.endswith(suffix):
            return instance_id[: -len(suffix)]
    return instance_id


def load_scenario_map() -> dict[str, dict[str, str]]:
    metadata = read_json(CASE_METADATA)
    mapping: dict[str, dict[str, str]] = {}
    for row in metadata:
        mapping[row["instance_id"]] = {
            "scenario_group": row["scenario_group"],
            "scenario_group_ja": SCENARIO_GROUP_LABELS.get(row["scenario_group"], row.get("scenario_group_ja", "")),
            "chain_type": row.get("chain_type", ""),
        }
    return mapping


def rate(hits: int, total: int) -> float | None:
    return hits / total if total else None


def add_rates(row: dict[str, Any]) -> dict[str, Any]:
    row = dict(row)
    row["action_step_recall"] = rate(row["action_step_recall_hits"], row["action_step_recall_total"])
    row["critical_evidence_recall"] = rate(
        row["critical_evidence_recall_hits"], row["critical_evidence_recall_total"]
    )
    row["behavior_sequence_order"] = rate(
        row["behavior_sequence_order_hits"], row["behavior_sequence_order_total"]
    )
    row["candidate_claim_precision"] = rate(
        row["candidate_claim_precision_hits"], row["candidate_claim_precision_total"]
    )
    return row


def evidence_score_for_non_alert(item: dict[str, Any]) -> int:
    score = int(item.get("score") or 0)
    if not score:
        return 0
    text = " ".join(
        str(item.get(key) or "")
        for key in ("matched_candidate_excerpt", "reason_ja", "reason", "candidate_slot_excerpt")
    ).lower()
    if any(token in text for token in ALERT_EVIDENCE_TOKENS):
        return 0
    return score


def parse_gpt41(scenario_map: dict[str, dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for path in sorted(GPT41_ROOT.glob("final_chain_*_stage*_codex_adjudicated_score.json")):
        data = read_json(path)
        instance_id = data["case"]
        chain_id = chain_id_from_instance(instance_id)
        stage = data["stage"]
        is_excluded = chain_id in EXCLUDED_CHAINS
        final_totals = data.get("final_totals") or {}
        item_scores = data.get("final_gold_required_item_scores") or []
        step_scores = data.get("final_gold_step_scores") or []
        old_action_hits = int(final_totals.get("action_step_recall_hits") or 0)
        old_action_total = int(final_totals.get("action_step_recall_total") or 0)
        old_critical_hits = int(final_totals.get("critical_evidence_recall_hits") or 0)
        old_critical_total = int(final_totals.get("critical_evidence_recall_total") or 0)
        action_hits = max(old_action_hits - old_critical_hits, 0)
        action_total = max(old_action_total - old_critical_total, 0)
        critical_hits = old_critical_hits
        critical_total = old_critical_total
        if item_scores:
            detail_critical_hits = 0
            detail_critical_total = 0
            for item in item_scores:
                kind = item.get("kind")
                if kind == "evidence":
                    kind = "critical_evidence"
                if kind == "operation":
                    kind = "action"
                if kind == "critical_evidence":
                    detail_critical_total += 1
                    detail_critical_hits += evidence_score_for_non_alert(item)
            if detail_critical_total:
                critical_hits = detail_critical_hits
                critical_total = detail_critical_total
        else:
            detail_critical_hits = 0
            detail_critical_total = 0
            for step in step_scores:
                scores = step.get("scores") or {}
                if "critical_evidence" in scores:
                    detail_critical_total += 1
                    pseudo_item = {
                        "score": scores.get("critical_evidence"),
                        "matched_candidate_excerpt": step.get("matched_candidate_excerpt"),
                        "reason_ja": step.get("reason"),
                    }
                    detail_critical_hits += evidence_score_for_non_alert(pseudo_item)
            if detail_critical_total:
                critical_hits = detail_critical_hits
                critical_total = detail_critical_total
        row = {
            "model": "gpt-4.1-mini",
            "stage": stage,
            "instance_id": instance_id,
            "chain_id": chain_id,
            **scenario_map.get(instance_id, {}),
            "excluded_non_alert_gold": is_excluded,
            "source_path": str(path.relative_to(ROOT)),
            "action_step_recall_hits": action_hits,
            "action_step_recall_total": action_total,
            "critical_evidence_recall_hits": critical_hits,
            "critical_evidence_recall_total": critical_total,
            "behavior_sequence_order_hits": int(final_totals.get("behavior_sequence_order_hits") or 0),
            "behavior_sequence_order_total": int(final_totals.get("behavior_sequence_order_total") or 0),
            "candidate_claim_precision_hits": int(final_totals.get("candidate_claim_precision_hits") or 0),
            "candidate_claim_precision_total": int(final_totals.get("candidate_claim_precision_total") or 0),
            "overclaim_slot_count": int(final_totals.get("overclaim_slot_count") or 0),
        }
        row = add_rates(row)
        if is_excluded:
            excluded.append(row)
        else:
            rows.append(row)
    return rows, excluded


def parse_gpt54(scenario_map: dict[str, dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    with (GPT54_ROOT / "codex_score_final_gpt54.csv").open("r", encoding="utf-8", newline="") as handle:
        for item in csv.DictReader(handle):
            instance_id = item["instance_id"]
            chain_id = chain_id_from_instance(instance_id)
            is_excluded = chain_id in EXCLUDED_CHAINS
            row = {
                "model": item["model"],
                "stage": item["stage"],
                "instance_id": instance_id,
                "chain_id": chain_id,
                **scenario_map.get(instance_id, {}),
                "excluded_non_alert_gold": is_excluded,
                "source_path": item.get("final_path") or "",
            }
            for field in METRIC_FIELDS:
                row[field] = int(float(item.get(field) or 0))
            row = add_rates(row)
            if is_excluded:
                excluded.append(row)
            else:
                rows.append(row)
    return rows, excluded


def aggregate(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_stage: dict[tuple[str, str], dict[str, Any]] = {}
    by_model: dict[str, dict[str, Any]] = {}

    def blank(model: str, stage: str | None = None) -> dict[str, Any]:
        row: dict[str, Any] = {"model": model, "case_count": 0}
        if stage is not None:
            row["stage"] = stage
        for field in METRIC_FIELDS:
            row[field] = 0
        return row

    for row in rows:
        key = (row["model"], row["stage"])
        stage_row = by_stage.setdefault(key, blank(row["model"], row["stage"]))
        model_row = by_model.setdefault(row["model"], blank(row["model"]))
        for target in (stage_row, model_row):
            target["case_count"] += 1
            for field in METRIC_FIELDS:
                target[field] += int(row[field])

    stage_rows = [add_rates(row) for _, row in sorted(by_stage.items())]
    model_rows = [add_rates(row) for _, row in sorted(by_model.items())]
    payload = {
        "policy": "non_alert_existing_review_reaggregate_20260611",
        "api_calls": 0,
        "source": "accepted Codex manual review outputs only",
        "excluded_chains": sorted(EXCLUDED_CHAINS),
        "models": model_rows,
        "by_stage": stage_rows,
    }
    return stage_rows, model_rows, payload


def aggregate_grouped(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_group: dict[tuple[str, str], dict[str, Any]] = {}
    by_stage_group: dict[tuple[str, str, str], dict[str, Any]] = {}

    def blank(model: str, group: str, stage: str | None = None) -> dict[str, Any]:
        row: dict[str, Any] = {
            "model": model,
            "scenario_group": group,
            "scenario_group_ja": SCENARIO_GROUP_LABELS.get(group, ""),
            "case_count": 0,
        }
        if stage is not None:
            row["stage"] = stage
        for field in METRIC_FIELDS:
            row[field] = 0
        return row

    for row in rows:
        group = row.get("scenario_group") or "unknown"
        group_row = by_group.setdefault((row["model"], group), blank(row["model"], group))
        stage_group_row = by_stage_group.setdefault(
            (row["model"], row["stage"], group), blank(row["model"], group, row["stage"])
        )
        for target in (group_row, stage_group_row):
            target["case_count"] += 1
            for field in METRIC_FIELDS:
                target[field] += int(row[field])

    group_rows = [add_rates(row) for _, row in sorted(by_group.items())]
    stage_group_rows = [add_rates(row) for _, row in sorted(by_stage_group.items())]
    return group_rows, stage_group_rows


def main() -> None:
    scenario_map = load_scenario_map()
    gpt41_rows, gpt41_excluded = parse_gpt41(scenario_map)
    gpt54_rows, gpt54_excluded = parse_gpt54(scenario_map)
    rows = gpt41_rows + gpt54_rows
    excluded = gpt41_excluded + gpt54_excluded
    stage_rows, model_rows, payload = aggregate(rows)
    group_rows, stage_group_rows = aggregate_grouped(rows)
    payload["by_scenario_group"] = group_rows
    payload["by_stage_and_scenario_group"] = stage_group_rows

    per_case_fields = [
        "model",
        "stage",
        "instance_id",
        "chain_id",
        "chain_type",
        "scenario_group",
        "scenario_group_ja",
        "excluded_non_alert_gold",
        *METRIC_FIELDS,
        "action_step_recall",
        "critical_evidence_recall",
        "behavior_sequence_order",
        "candidate_claim_precision",
        "source_path",
    ]
    aggregate_fields = [
        "model",
        "stage",
        "case_count",
        *METRIC_FIELDS,
        "action_step_recall",
        "critical_evidence_recall",
        "behavior_sequence_order",
        "candidate_claim_precision",
    ]
    model_fields = [field for field in aggregate_fields if field != "stage"]
    group_fields = [
        "model",
        "scenario_group",
        "scenario_group_ja",
        "case_count",
        *METRIC_FIELDS,
        "action_step_recall",
        "critical_evidence_recall",
        "behavior_sequence_order",
        "candidate_claim_precision",
    ]
    stage_group_fields = [
        "model",
        "stage",
        "scenario_group",
        "scenario_group_ja",
        "case_count",
        *METRIC_FIELDS,
        "action_step_recall",
        "critical_evidence_recall",
        "behavior_sequence_order",
        "candidate_claim_precision",
    ]

    write_csv(OUT_ROOT / "non_alert_per_case_scores.csv", rows, per_case_fields)
    write_csv(OUT_ROOT / "non_alert_excluded_cases.csv", excluded, per_case_fields)
    write_csv(OUT_ROOT / "non_alert_summary_by_stage.csv", stage_rows, aggregate_fields)
    write_csv(OUT_ROOT / "non_alert_summary_overall.csv", model_rows, model_fields)
    write_csv(OUT_ROOT / "non_alert_summary_by_scenario_group.csv", group_rows, group_fields)
    write_csv(OUT_ROOT / "non_alert_summary_by_stage_and_scenario_group.csv", stage_group_rows, stage_group_fields)
    write_json(OUT_ROOT / "non_alert_summary_all.json", payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
