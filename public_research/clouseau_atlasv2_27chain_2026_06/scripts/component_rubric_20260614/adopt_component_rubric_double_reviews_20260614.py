from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/component_rubric_20260614"
LEDGER = SCORE_ROOT / "codex_component_double_reviews.jsonl"
CONFLICTS = SCORE_ROOT / "review_conflicts.jsonl"

KEY_FIELDS = ["replicate", "model", "stage", "instance_id"]
MATCH_FIELDS = [
    "chain_id",
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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in KEY_FIELDS)  # type: ignore[return-value]


def ratio(hit: int, total: int) -> float | None:
    if total == 0:
        return None
    return hit / total


def as_int(row: dict[str, Any], field: str) -> int:
    return int(row.get(field) or 0)


def validate_row(row: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    for field in MATCH_FIELDS:
        if field not in row:
            issues.append(f"missing_{field}")
    checks = [
        ("action_step_recall_hits", "action_step_recall_total"),
        ("critical_evidence_recall_hits", "critical_evidence_recall_total"),
        ("behavior_sequence_order_hits", "behavior_sequence_order_total"),
        ("candidate_claim_precision_hits", "candidate_claim_precision_total"),
    ]
    for hit_field, total_field in checks:
        if hit_field in row and total_field in row and as_int(row, hit_field) > as_int(row, total_field):
            issues.append(f"{hit_field}_exceeds_{total_field}")
    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Adopt matching A/B component-rubric Codex review rows.")
    parser.add_argument("--review-a", required=True, type=Path)
    parser.add_argument("--review-b", required=True, type=Path)
    parser.add_argument("--allow-conservative-conflict-resolution", action="store_true")
    args = parser.parse_args()

    rows_a = {key(row): row for row in read_jsonl(args.review_a)}
    rows_b = {key(row): row for row in read_jsonl(args.review_b)}
    existing = {key(row) for row in read_jsonl(LEDGER) if row.get("two_review_adoptable") is True}

    adopted: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for review_key in sorted(set(rows_a) | set(rows_b)):
        if review_key in existing:
            continue
        a = rows_a.get(review_key)
        b = rows_b.get(review_key)
        if not a or not b:
            conflicts.append({"created_at_utc": datetime.now(timezone.utc).isoformat(), "key": review_key, "reason": "missing reviewer row", "has_review_a": bool(a), "has_review_b": bool(b)})
            continue

        pass_a = a.get("review_pass") is True
        pass_b = b.get("review_pass") is True
        issues_a = validate_row(a)
        issues_b = validate_row(b)
        mismatches = [field for field in MATCH_FIELDS if a.get(field) != b.get(field)]
        if (mismatches or issues_a or issues_b or not pass_a or not pass_b) and not args.allow_conservative_conflict_resolution:
            conflicts.append(
                {
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "key": review_key,
                    "reason": "mismatch_or_failed_review",
                    "mismatches": mismatches,
                    "review_a_pass": pass_a,
                    "review_b_pass": pass_b,
                    "review_a_issues": issues_a,
                    "review_b_issues": issues_b,
                    "review_a": a,
                    "review_b": b,
                }
            )
            continue

        source = dict(a)
        adjudication_note = "two independent reviews matched"
        if mismatches or issues_a or issues_b or not pass_a or not pass_b:
            if issues_a or issues_b or not pass_a or not pass_b:
                conflicts.append(
                    {
                        "created_at_utc": datetime.now(timezone.utc).isoformat(),
                        "key": review_key,
                        "reason": "cannot conservative-resolve invalid review",
                        "mismatches": mismatches,
                        "review_a_pass": pass_a,
                        "review_b_pass": pass_b,
                        "review_a_issues": issues_a,
                        "review_b_issues": issues_b,
                        "review_a": a,
                        "review_b": b,
                    }
                )
                continue
            source = dict(a)
            for field in [
                "action_step_recall_hits",
                "critical_evidence_recall_hits",
                "behavior_sequence_order_hits",
                "candidate_claim_precision_hits",
            ]:
                source[field] = min(as_int(a, field), as_int(b, field))
            for field in [
                "action_step_recall_total",
                "critical_evidence_recall_total",
                "behavior_sequence_order_total",
                "candidate_claim_precision_total",
                "overclaim_slot_count",
            ]:
                source[field] = max(as_int(a, field), as_int(b, field))
            adjudication_note = "conservative conflict resolution: min hits, max totals/overclaims"

        action_hits = as_int(source, "action_step_recall_hits")
        action_total = as_int(source, "action_step_recall_total")
        evidence_hits = as_int(source, "critical_evidence_recall_hits")
        evidence_total = as_int(source, "critical_evidence_recall_total")
        order_hits = as_int(source, "behavior_sequence_order_hits")
        order_total = as_int(source, "behavior_sequence_order_total")
        precision_hits = as_int(source, "candidate_claim_precision_hits")
        precision_total = as_int(source, "candidate_claim_precision_total")

        adopted.append(
            {
                "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
                "dataset_label": source.get("dataset_label"),
                "replicate": review_key[0],
                "model": review_key[1],
                "stage": review_key[2],
                "instance_id": review_key[3],
                "chain_id": source.get("chain_id"),
                "chain_type": source.get("chain_type"),
                "run_json": source.get("run_json"),
                "gold_file": source.get("gold_file") or source.get("gold_steps_jsonl"),
                "evaluation_unit": "component_rubric_subject_action_object_evidence",
                "contract": source.get("contract"),
                "format_failure_note": source.get("format_failure_note"),
                "review1_pass": True,
                "review2_pass": True,
                "two_review_adoptable": True,
                "adjudication_note": adjudication_note,
                "action_step_recall_hits": action_hits,
                "action_step_recall_total": action_total,
                "action_step_recall": ratio(action_hits, action_total),
                "critical_evidence_recall_hits": evidence_hits,
                "critical_evidence_recall_total": evidence_total,
                "critical_evidence_recall": ratio(evidence_hits, evidence_total),
                "behavior_sequence_order_hits": order_hits,
                "behavior_sequence_order_total": order_total,
                "behavior_sequence_order": ratio(order_hits, order_total),
                "candidate_claim_precision_hits": precision_hits,
                "candidate_claim_precision_total": precision_total,
                "candidate_claim_precision": ratio(precision_hits, precision_total),
                "overclaim_slot_count": as_int(source, "overclaim_slot_count"),
                "candidate_step_count": source.get("candidate_step_count"),
                "normalized_candidate_step_count": source.get("normalized_candidate_step_count"),
                "reviewer_a_source": args.review_a.relative_to(ROOT).as_posix() if args.review_a.is_absolute() else args.review_a.as_posix(),
                "reviewer_b_source": args.review_b.relative_to(ROOT).as_posix() if args.review_b.is_absolute() else args.review_b.as_posix(),
                "review_summary": source.get("review_summary") or source.get("review_summary_ja") or b.get("review_summary") or b.get("review_summary_ja"),
            }
        )

    append_jsonl(LEDGER, adopted)
    append_jsonl(CONFLICTS, conflicts)
    print(json.dumps({"adopted_count": len(adopted), "conflict_count": len(conflicts), "ledger": LEDGER.relative_to(ROOT).as_posix(), "conflicts": CONFLICTS.relative_to(ROOT).as_posix()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
