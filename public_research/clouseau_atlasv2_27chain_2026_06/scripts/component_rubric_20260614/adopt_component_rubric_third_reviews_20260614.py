from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/component_rubric_20260614"
LEDGER = SCORE_ROOT / "codex_component_double_reviews.jsonl"
THIRD_LEDGER = SCORE_ROOT / "codex_component_third_review_adoptions.jsonl"


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
    return (
        str(row.get("replicate") or ""),
        str(row.get("model") or ""),
        str(row.get("stage") or ""),
        str(row.get("instance_id") or ""),
    )


def as_int(row: dict[str, Any], field: str) -> int:
    return int(row.get(field) or 0)


def ratio(hit: int, total: int) -> float | None:
    if total == 0:
        return None
    return hit / total


def main() -> None:
    parser = argparse.ArgumentParser(description="Adopt third-review component-rubric adjudications for conflicted rows.")
    parser.add_argument("--third-review", required=True, type=Path)
    args = parser.parse_args()

    existing = {key(row) for row in read_jsonl(LEDGER) if row.get("two_review_adoptable") is True}
    adopted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in read_jsonl(args.third_review):
        review_key = key(row)
        if review_key in existing:
            skipped.append({"key": review_key, "reason": "already_adopted"})
            continue
        if row.get("review_pass") is not True:
            skipped.append({"key": review_key, "reason": "third_review_not_passed"})
            continue
        action_hits = as_int(row, "action_step_recall_hits")
        action_total = as_int(row, "action_step_recall_total")
        evidence_hits = as_int(row, "critical_evidence_recall_hits")
        evidence_total = as_int(row, "critical_evidence_recall_total")
        order_hits = as_int(row, "behavior_sequence_order_hits")
        order_total = as_int(row, "behavior_sequence_order_total")
        precision_hits = as_int(row, "candidate_claim_precision_hits")
        precision_total = as_int(row, "candidate_claim_precision_total")
        adopted.append(
            {
                "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
                "dataset_label": row.get("dataset_label"),
                "replicate": review_key[0],
                "model": review_key[1],
                "stage": review_key[2],
                "instance_id": review_key[3],
                "chain_id": row.get("chain_id"),
                "chain_type": row.get("chain_type"),
                "run_json": row.get("run_json"),
                "gold_file": row.get("gold_file") or row.get("gold_steps_jsonl"),
                "evaluation_unit": "component_rubric_subject_action_object_evidence",
                "contract": row.get("contract"),
                "format_failure_note": row.get("format_failure_note"),
                "review1_pass": True,
                "review2_pass": True,
                "two_review_adoptable": True,
                "adjudication_note": "third-review adjudication after A/B conflict",
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
                "overclaim_slot_count": as_int(row, "overclaim_slot_count"),
                "candidate_step_count": row.get("candidate_step_count"),
                "normalized_candidate_step_count": row.get("normalized_candidate_step_count"),
                "reviewer_a_source": None,
                "reviewer_b_source": args.third_review.relative_to(ROOT).as_posix() if args.third_review.is_absolute() else args.third_review.as_posix(),
                "review_summary": row.get("review_summary") or row.get("review_summary_ja"),
            }
        )

    append_jsonl(LEDGER, adopted)
    append_jsonl(THIRD_LEDGER, adopted)
    print(json.dumps({"adopted_count": len(adopted), "skipped_count": len(skipped), "skipped": skipped[:10], "ledger": LEDGER.relative_to(ROOT).as_posix()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
