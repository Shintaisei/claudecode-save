from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_3rep_20260613"
CONFLICTS = SCORE_ROOT / "review_conflicts.jsonl"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def key(row: dict) -> tuple[str, str, str, str]:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Conservatively resolve GPT-5.5 low 3rep Codex review conflicts.")
    parser.add_argument("--conflicts", type=Path, default=CONFLICTS)
    parser.add_argument("--ledger", type=Path, default=LEDGER)
    parser.add_argument("--reviewer-a-source", default="")
    parser.add_argument("--reviewer-b-source", default="")
    args = parser.parse_args()

    existing = {key(row) for row in read_jsonl(args.ledger) if row.get("two_review_adoptable") is True}
    resolved: list[dict] = []
    for conflict in read_jsonl(args.conflicts):
        a = conflict.get("review_a") or {}
        b = conflict.get("review_b") or {}
        if not a or not b:
            continue
        review_key = key(a)
        if review_key in existing:
            continue

        gold_step_count = min(int(a.get("gold_step_count") or 0), int(b.get("gold_step_count") or 0))
        candidate_step_count = max(int(a.get("candidate_step_count") or 0), int(b.get("candidate_step_count") or 0))
        recall_hits = min(int(a.get("recall_hits") or 0), int(b.get("recall_hits") or 0))
        recall_total = min(int(a.get("recall_total") or 0), int(b.get("recall_total") or 0))
        precision_hits = min(int(a.get("precision_hits") or 0), int(b.get("precision_hits") or 0))
        precision_total = candidate_step_count
        order_hits = min(int(a.get("behavior_sequence_order_hits") or 0), int(b.get("behavior_sequence_order_hits") or 0))
        order_total = min(int(a.get("behavior_sequence_order_total") or 0), int(b.get("behavior_sequence_order_total") or 0))

        resolved.append(
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
                "adjudication_pass": True,
                "adjudication_rule": "conservative: max(candidate_step_count), min(hit counts)",
                "two_review_adoptable": True,
                "gold_step_count": gold_step_count,
                "candidate_step_count": candidate_step_count,
                "recall_hits": recall_hits,
                "recall_total": recall_total,
                "recall": ratio(recall_hits, recall_total),
                "precision_hits": precision_hits,
                "precision_total": precision_total,
                "precision": ratio(precision_hits, precision_total),
                "behavior_sequence_order_hits": order_hits,
                "behavior_sequence_order_total": order_total,
                "behavior_sequence_order": ratio(order_hits, order_total),
                "reviewer_a_source": args.reviewer_a_source,
                "reviewer_b_source": args.reviewer_b_source,
                "review_summary": "A/B conflict resolved conservatively by Codex: max candidate total, min hit counts.",
            }
        )

    if resolved:
        args.ledger.parent.mkdir(parents=True, exist_ok=True)
        with args.ledger.open("a", encoding="utf-8", newline="") as handle:
            for row in resolved:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({"resolved_count": len(resolved), "ledger": args.ledger.relative_to(ROOT).as_posix()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
