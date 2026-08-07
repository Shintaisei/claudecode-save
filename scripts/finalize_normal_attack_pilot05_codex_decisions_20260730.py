from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(
    "docs/current_experiment/results_2026-07-30/"
    "normal_attack_full_ledger_pilot_05/analysis_codex_single_review_v1"
)
QUEUE = ROOT / "review_queue_v1.jsonl"
PARTIAL = ROOT / "_working_decisions_partial_v1.jsonl"
OUTPUT = ROOT / "codex_decisions_v1.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"create-only output already exists: {OUTPUT}")
    if not QUEUE.exists():
        raise FileNotFoundError(f"review queue is not ready: {QUEUE}")

    queue_rows = read_jsonl(QUEUE)
    decisions = read_jsonl(PARTIAL)
    for path in sorted(ROOT.glob("_working_decision_*.json")):
        decisions.append(json.loads(path.read_text(encoding="utf-8")))

    by_id: dict[str, dict] = {}
    for decision in decisions:
        queue_id = decision["queue_id"]
        if queue_id in by_id:
            raise ValueError(f"duplicate decision: {queue_id}")
        by_id[queue_id] = decision

    queue_ids = [row["queue_id"] for row in queue_rows]
    missing = sorted(set(queue_ids) - set(by_id))
    extra = sorted(set(by_id) - set(queue_ids))
    if missing or extra:
        raise ValueError(f"decision coverage mismatch: missing={missing}, extra={extra}")

    payload = "".join(
        json.dumps(by_id[queue_id], ensure_ascii=False, sort_keys=True) + "\n"
        for queue_id in queue_ids
    )
    OUTPUT.write_text(payload, encoding="utf-8", newline="\n")
    print(
        json.dumps(
            {
                "status": "PASS",
                "queue_count": len(queue_rows),
                "decision_count": len(by_id),
                "output": str(OUTPUT),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
