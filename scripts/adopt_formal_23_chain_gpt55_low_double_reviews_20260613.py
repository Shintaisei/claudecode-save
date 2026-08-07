from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_3rep_20260613"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"
CONFLICTS = SCORE_ROOT / "review_conflicts.jsonl"

KEY_FIELDS = ["replicate", "model", "stage", "instance_id"]
MATCH_FIELDS = [
    "chain_id",
    "gold_step_count",
    "candidate_step_count",
    "recall_hits",
    "recall_total",
    "precision_hits",
    "precision_total",
    "behavior_sequence_order_hits",
    "behavior_sequence_order_total",
]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def key(row: dict) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in KEY_FIELDS)  # type: ignore[return-value]


def ratio(hit: int | None, total: int | None) -> float | None:
    if total is None or total == 0 or hit is None:
        return None
    return hit / total


def main() -> None:
    parser = argparse.ArgumentParser(description="Adopt only matching A/B Codex double-review rows for GPT-5.5 low.")
    parser.add_argument("--review-a", required=True, type=Path)
    parser.add_argument("--review-b", required=True, type=Path)
    args = parser.parse_args()

    rows_a = {key(row): row for row in read_jsonl(args.review_a)}
    rows_b = {key(row): row for row in read_jsonl(args.review_b)}
    existing = {key(row) for row in read_jsonl(LEDGER) if row.get("two_review_adoptable") is True}

    adopted: list[dict] = []
    conflicts: list[dict] = []
    for review_key in sorted(set(rows_a) | set(rows_b)):
        if review_key in existing:
            continue
        a = rows_a.get(review_key)
        b = rows_b.get(review_key)
        if not a or not b:
            conflicts.append({"created_at_utc": datetime.now(timezone.utc).isoformat(), "key": review_key, "reason": "missing reviewer row", "has_review_a": bool(a), "has_review_b": bool(b)})
            continue
        mismatches = [field for field in MATCH_FIELDS if a.get(field) != b.get(field)]
        pass_a = a.get("review_pass") is True or a.get("review1_pass") is True
        pass_b = b.get("review_pass") is True or b.get("review2_pass") is True
        if mismatches or not pass_a or not pass_b:
            conflicts.append({"created_at_utc": datetime.now(timezone.utc).isoformat(), "key": review_key, "reason": "mismatch_or_failed_review", "mismatches": mismatches, "review_a_pass": pass_a, "review_b_pass": pass_b, "review_a": a, "review_b": b})
            continue

        recall_hits = int(a["recall_hits"])
        recall_total = int(a["recall_total"])
        precision_hits = int(a["precision_hits"])
        precision_total = int(a["precision_total"])
        order_hits = int(a["behavior_sequence_order_hits"])
        order_total = int(a["behavior_sequence_order_total"])
        adopted.append(
            {
                "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
                "replicate": review_key[0],
                "model": review_key[1],
                "stage": review_key[2],
                "instance_id": review_key[3],
                "chain_id": a.get("chain_id"),
                "run_json": a.get("run_json"),
                "gold_file": a.get("gold_file") or a.get("gold_steps_jsonl"),
                "evaluation_unit": "behavior_plus_evidence_step",
                "review1_pass": True,
                "review2_pass": True,
                "two_review_adoptable": True,
                "gold_step_count": int(a["gold_step_count"]),
                "candidate_step_count": int(a["candidate_step_count"]),
                "recall_hits": recall_hits,
                "recall_total": recall_total,
                "recall": ratio(recall_hits, recall_total),
                "precision_hits": precision_hits,
                "precision_total": precision_total,
                "precision": ratio(precision_hits, precision_total),
                "behavior_sequence_order_hits": order_hits,
                "behavior_sequence_order_total": order_total,
                "behavior_sequence_order": ratio(order_hits, order_total),
                "reviewer_a_source": args.review_a.relative_to(ROOT).as_posix() if args.review_a.is_absolute() else args.review_a.as_posix(),
                "reviewer_b_source": args.review_b.relative_to(ROOT).as_posix() if args.review_b.is_absolute() else args.review_b.as_posix(),
                "review_summary": a.get("review_summary") or a.get("review_summary_ja") or b.get("review_summary") or b.get("review_summary_ja"),
            }
        )

    append_jsonl(LEDGER, adopted)
    append_jsonl(CONFLICTS, conflicts)
    print(json.dumps({"adopted_count": len(adopted), "conflict_count": len(conflicts), "ledger": LEDGER.relative_to(ROOT).as_posix(), "conflicts": CONFLICTS.relative_to(ROOT).as_posix()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
