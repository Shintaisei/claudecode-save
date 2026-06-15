from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/component_rubric_20260614"
LEDGER = SCORE_ROOT / "codex_component_double_reviews.jsonl"
QUEUE_STATUS = SCORE_ROOT / "review_queue_status.json"
OLD_BASELINE = ROOT / "data/current_experiment/scores/non_alert_existing_review_reaggregate_20260611/non_alert_per_case_scores.csv"
OUT_DIR = ROOT / "docs/current_experiment/results_2026-06-09/component_rubric_model_comparison_20260614"

FRAMEWORK_LABELS = {
    "dns_packet_capture_batch_chain": "collection_or_tool_invocation",
    "python_simplehttpserver_network_chain": "network_service_behavior",
    "sublime_python_script_execution_chain": "script_execution_chain",
    "cmdexe_other_chain": "command_shell_execution",
    "discord_run_key_registry_chain": "persistence_registry_run_key",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_old_baseline() -> list[dict[str, Any]]:
    if not OLD_BASELINE.exists():
        return []
    rows: list[dict[str, Any]] = []
    with OLD_BASELINE.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            out = dict(row)
            out["dataset_label"] = f"{row['model']}_old_1run_component"
            out["replicate"] = "old_20260609"
            out["evaluation_unit"] = "component_rubric_subject_action_object_evidence"
            out["contract"] = "legacy_formal27_component_review"
            rows.append(out)
    return rows


def ratio(hit: int, total: int) -> str:
    if total == 0:
        return "NA"
    return f"{hit / total:.3f}"


def as_int(row: dict[str, Any], field: str) -> int:
    return int(float(row.get(field) or 0))


def enrich(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    chain_type = str(out.get("chain_type") or "")
    out["framework_group"] = FRAMEWORK_LABELS.get(chain_type, chain_type or "unknown")
    return out


def summarize(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[tuple(row.get(field) for field in fields)].append(row)
    out: list[dict[str, Any]] = []
    for key, bucket in sorted(buckets.items(), key=lambda item: tuple("" if v is None else str(v) for v in item[0])):
        ah = sum(as_int(row, "action_step_recall_hits") for row in bucket)
        at = sum(as_int(row, "action_step_recall_total") for row in bucket)
        eh = sum(as_int(row, "critical_evidence_recall_hits") for row in bucket)
        et = sum(as_int(row, "critical_evidence_recall_total") for row in bucket)
        oh = sum(as_int(row, "behavior_sequence_order_hits") for row in bucket)
        ot = sum(as_int(row, "behavior_sequence_order_total") for row in bucket)
        ph = sum(as_int(row, "candidate_claim_precision_hits") for row in bucket)
        pt = sum(as_int(row, "candidate_claim_precision_total") for row in bucket)
        summary = {field: key[i] for i, field in enumerate(fields)}
        summary.update(
            {
                "run_count": len(bucket),
                "chain_count": len({str(row.get("chain_id") or "") for row in bucket}),
                "action_step_recall_hits": ah,
                "action_step_recall_total": at,
                "action_step_recall": ratio(ah, at),
                "critical_evidence_recall_hits": eh,
                "critical_evidence_recall_total": et,
                "critical_evidence_recall": ratio(eh, et),
                "behavior_sequence_order_hits": oh,
                "behavior_sequence_order_total": ot,
                "behavior_sequence_order": ratio(oh, ot),
                "candidate_claim_precision_hits": ph,
                "candidate_claim_precision_total": pt,
                "candidate_claim_precision": ratio(ph, pt),
                "overclaim_slot_count": sum(as_int(row, "overclaim_slot_count") for row in bucket),
            }
        )
        out.append(summary)
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def md_table(rows: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


def main() -> None:
    reviewed_rows = [enrich(row) for row in read_jsonl(LEDGER) if row.get("two_review_adoptable") is True]
    old_rows = [enrich(row) for row in read_old_baseline()]
    rows = old_rows + reviewed_rows
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    write_csv(OUT_DIR / "per_run_component_scores.csv", rows)
    overall = summarize(rows, ("dataset_label", "contract"))
    by_stage = summarize(rows, ("dataset_label", "contract", "stage"))
    by_framework = summarize(rows, ("dataset_label", "contract", "framework_group"))
    write_csv(OUT_DIR / "overall.csv", overall)
    write_csv(OUT_DIR / "by_stage.csv", by_stage)
    write_csv(OUT_DIR / "by_framework.csv", by_framework)

    status = json.loads(QUEUE_STATUS.read_text(encoding="utf-8")) if QUEUE_STATUS.exists() else {}
    queue_summary = {
        "available_run_count": status.get("available_run_count"),
        "adopted_review_count": len(reviewed_rows),
        "valid_unreviewed_count_at_last_queue_build": status.get("valid_unreviewed_count"),
        "invalid_run_count": status.get("invalid_run_count"),
        "missing_run_count": status.get("missing_run_count"),
    }
    fields = ["dataset_label", "contract", "run_count", "chain_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    md = [
        "# Component-Rubric Model Comparison 2026-06-14",
        "",
        "Primary metric definition: component rubric from the earlier Codex review flow. This is intentionally separate from the stricter behavior-plus-evidence step metric.",
        "",
        "GPT-5.5 rows must be reported as raw-text salvage when contract=raw_text_contract_failed, because the run violated the formal JSON/code_steps output contract.",
        "",
        f"Queue status: `{json.dumps(queue_summary, ensure_ascii=False)}`",
        "",
        "## Overall",
        "",
        md_table(overall, fields),
        "",
        "## By Stage",
        "",
        md_table(by_stage, ["dataset_label", "contract", "stage", "run_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]),
        "",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"out_dir": OUT_DIR.relative_to(ROOT).as_posix(), "old_baseline_rows": len(old_rows), "reviewed_component_rows": len(reviewed_rows), "overall_rows": len(overall)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
