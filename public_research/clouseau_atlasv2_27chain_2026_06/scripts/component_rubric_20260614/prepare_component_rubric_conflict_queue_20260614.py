from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/component_rubric_20260614"
CONFLICTS = SCORE_ROOT / "review_conflicts.jsonl"
LEDGER = SCORE_ROOT / "codex_component_double_reviews.jsonl"
OUT = SCORE_ROOT / "review_queue_conflicts_for_third_review.jsonl"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    adopted = {
        (
            str(row.get("replicate") or ""),
            str(row.get("model") or ""),
            str(row.get("stage") or ""),
            str(row.get("instance_id") or ""),
        )
        for row in read_jsonl(LEDGER)
        if row.get("two_review_adoptable") is True
    }
    for conflict in read_jsonl(CONFLICTS):
        review_a = conflict.get("review_a")
        if not isinstance(review_a, dict):
            continue
        key = (
            str(review_a.get("replicate") or ""),
            str(review_a.get("model") or ""),
            str(review_a.get("stage") or ""),
            str(review_a.get("instance_id") or ""),
        )
        if key in seen or key in adopted:
            continue
        seen.add(key)
        row = {
            field: review_a.get(field)
            for field in [
                "dataset_label",
                "replicate",
                "model",
                "stage",
                "instance_id",
                "chain_id",
                "chain_type",
                "run_json",
                "gold_steps_jsonl",
                "contract",
            ]
        }
        row["evaluation_unit"] = "component_rubric_subject_action_object_evidence"
        row["conflict_reason"] = conflict.get("reason")
        row["conflict_mismatches"] = conflict.get("mismatches")
        row["third_review_instruction"] = "Score independently from run_json and gold_steps_jsonl. Do not copy reviewer A/B values."
        rows.append(row)
    OUT.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    print(json.dumps({"conflict_queue": OUT.relative_to(ROOT).as_posix(), "row_count": len(rows)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
