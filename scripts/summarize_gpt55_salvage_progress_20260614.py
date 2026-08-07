from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QUEUE_STATUS = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_salvage_20260614/review_queue_status.json"
LEDGER = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_salvage_20260614/codex_salvage_double_reviews.jsonl"
PROGRESS = ROOT / "data/current_experiment/scores/formal_23_chain_gpt55_low_salvage_20260614/progress.json"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def pct(hit: int, total: int) -> float | None:
    if total == 0:
        return None
    return hit / total


def main() -> None:
    rows = [row for row in read_jsonl(LEDGER) if row.get("two_review_adoptable") is True]
    stage_counts = Counter(row.get("stage") for row in rows)
    by_stage: dict[str, dict] = {}
    for stage in sorted(stage_counts):
        bucket = [row for row in rows if row.get("stage") == stage]
        rh = sum(int(row.get("recall_hits") or 0) for row in bucket)
        rt = sum(int(row.get("recall_total") or 0) for row in bucket)
        ph = sum(int(row.get("precision_hits") or 0) for row in bucket)
        pt = sum(int(row.get("precision_total") or 0) for row in bucket)
        oh = sum(int(row.get("behavior_sequence_order_hits") or 0) for row in bucket)
        ot = sum(int(row.get("behavior_sequence_order_total") or 0) for row in bucket)
        by_stage[str(stage)] = {"run_count": len(bucket), "recall": pct(rh, rt), "precision": pct(ph, pt), "behavior_sequence_order": pct(oh, ot), "gold_step_total": rt, "candidate_step_total": pt}
    rh = sum(int(row.get("recall_hits") or 0) for row in rows)
    rt = sum(int(row.get("recall_total") or 0) for row in rows)
    ph = sum(int(row.get("precision_hits") or 0) for row in rows)
    pt = sum(int(row.get("precision_total") or 0) for row in rows)
    oh = sum(int(row.get("behavior_sequence_order_hits") or 0) for row in rows)
    ot = sum(int(row.get("behavior_sequence_order_total") or 0) for row in rows)
    status = json.loads(QUEUE_STATUS.read_text(encoding="utf-8")) if QUEUE_STATUS.exists() else {}
    progress = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_valid_reviewable_count": status.get("valid_unreviewed_count", 0) + len(rows),
        "adopted_review_count": len(rows),
        "remaining_review_count_from_last_queue": status.get("valid_unreviewed_count"),
        "overall": {"run_count": len(rows), "recall": pct(rh, rt), "precision": pct(ph, pt), "behavior_sequence_order": pct(oh, ot), "gold_step_total": rt, "candidate_step_total": pt},
        "by_stage": by_stage,
    }
    PROGRESS.parent.mkdir(parents=True, exist_ok=True)
    PROGRESS.write_text(json.dumps(progress, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(progress, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
