#!/usr/bin/env python3
"""Materialize the independent Codex review-1 decisions for attack8 v3.

This is deliberately a decision ledger, not an automatic semantic scorer.
The mappings below are the reviewer's item-by-item judgments after reading the
frozen queue.  The script only expands those judgments into the validated
schema and refuses to overwrite an existing raw review.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCORE_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-26"
    / "atlasv2_s3_s4_attack8_observable_component_v3"
    / "gpt54mini_replicate_01_v3/scores_codex_manual_double_review_v2"
)
QUEUE = SCORE_ROOT / "review_queue.jsonl"
TEMPLATE = SCORE_ROOT / "review_template.jsonl"
# The first materialization exposed that aligned_gold_step_id requires the
# chain-qualified identifier.  Preserve that failed artifact and emit this
# corrected, versioned raw review instead of overwriting it.
OUTPUT = SCORE_ROOT / "raw_reviews/review1_raw_corrected_01.jsonl"
REVIEWER_ID = "/root/v3_codex_review1"


# queue row (1-based) -> candidate claim -> (Gold step, TP slot kinds)
ALIGNMENTS: dict[int, dict[str, tuple[str, set[str]]]] = {
    1: {"C1": ("A8V3-01-S01", {"operation", "object"})},
    2: {"C1": ("A8V3-02-S02", {"operation"})},
    3: {
        "C1": ("A8V3-03-S01", {"subject", "operation"}),
        "C2": ("A8V3-03-S02", {"subject", "object"}),
    },
    4: {"C1": ("A8V3-04-S04", {"operation"})},
    5: {},
    6: {"C1": ("A8V3-06-S03", {"operation"})},
    7: {
        "C1": ("A8V3-07-S01", {"operation"}),
        "C2": ("A8V3-07-S03", {"subject", "operation", "object"}),
        "C3": ("A8V3-07-S02", {"subject", "operation", "object"}),
        "C4": ("A8V3-07-S04", {"operation"}),
    },
    8: {
        "C1": ("A8V3-08-S04", {"operation"}),
        "C2": ("A8V3-08-S05", {"operation"}),
        "C3": ("A8V3-08-S08", {"operation"}),
        "C4": ("A8V3-08-S09", {"operation"}),
    },
    9: {
        "C1": ("A8V3-01-S01", {"operation", "object"}),
        "C3": ("A8V3-01-S03", {"operation", "object"}),
    },
    10: {
        "C1": ("A8V3-02-S02", {"subject", "operation"}),
        "C2": ("A8V3-02-S03", {"subject", "operation", "object"}),
    },
    11: {
        "C1": ("A8V3-03-S01", {"operation"}),
        "C2": ("A8V3-03-S02", {"subject", "operation", "object"}),
    },
    12: {"C1": ("A8V3-04-S04", {"operation"})},
    13: {
        "C1": ("A8V3-05-S01", {"operation"}),
        "C2": ("A8V3-05-S03", {"operation"}),
        "C3": ("A8V3-05-S04", {"operation", "object"}),
    },
    14: {},
    15: {
        "C1": ("A8V3-07-S01", {"operation"}),
        "C2": ("A8V3-07-S02", {"subject", "operation", "object"}),
        "C3": ("A8V3-07-S04", {"operation"}),
        "C4": ("A8V3-07-S03", {"operation", "object"}),
    },
    16: {},
    17: {},
    18: {
        "C1": ("A8V3-02-S02", {"operation"}),
        "C2": ("A8V3-02-S03", {"subject", "operation", "object"}),
    },
    19: {
        "C2": ("A8V3-03-S02", {"object"}),
        "C3": ("A8V3-03-S05", {"object"}),
    },
    20: {
        "C1": ("A8V3-04-S08", {"subject", "operation"}),
        "C2": ("A8V3-04-S09", {"subject", "operation"}),
        "C3": ("A8V3-04-S09", {"operation"}),
    },
    21: {},
    22: {},
    23: {
        "C1": ("A8V3-07-S01", {"operation"}),
        "C2": ("A8V3-07-S03", {"subject", "operation", "object"}),
        "C3": ("A8V3-07-S04", {"operation"}),
    },
    24: {"C1": ("A8V3-08-S04", {"operation"})},
}


# queue row (1-based) -> Gold steps whose essential non-alert evidence content
# was recovered. Alert-only evidence is intentionally absent.
CRITICAL_HITS: dict[int, set[str]] = {
    1: set(),
    2: set(),
    3: set(),
    4: set(),
    5: set(),
    6: set(),
    7: {"A8V3-07-S01", "A8V3-07-S02", "A8V3-07-S03", "A8V3-07-S04"},
    8: set(),
    9: {"A8V3-01-S01", "A8V3-01-S03"},
    10: {"A8V3-02-S02", "A8V3-02-S03"},
    11: {"A8V3-03-S01", "A8V3-03-S02"},
    12: {"A8V3-04-S04"},
    13: {"A8V3-05-S01", "A8V3-05-S04"},
    14: set(),
    15: {"A8V3-07-S01", "A8V3-07-S02", "A8V3-07-S04"},
    16: set(),
    17: set(),
    18: {"A8V3-02-S02", "A8V3-02-S03"},
    19: set(),
    20: {"A8V3-04-S04", "A8V3-04-S08", "A8V3-04-S09"},
    21: set(),
    22: set(),
    23: {"A8V3-07-S01", "A8V3-07-S03", "A8V3-07-S04"},
    24: set(),
}


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def step_from_item(item_id: str) -> str:
    return item_id.rsplit(":", 2)[-2]


def candidate_order(queue: dict) -> dict[str, int]:
    result: dict[str, int] = {}
    for index, step in enumerate(queue["candidate_output"].get("code_steps", []), 1):
        result[f"C{index}"] = int(step.get("order") or index)
    return result


def main() -> None:
    queues = read_jsonl(QUEUE)
    templates = read_jsonl(TEMPLATE)
    if len(queues) != 24 or len(templates) != 24:
        raise SystemExit("frozen queue/template must both contain 24 rows")
    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite {OUTPUT}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    rendered: list[dict] = []
    for row_number, (queue, row) in enumerate(zip(queues, templates), 1):
        if queue["queue_id"] != row["queue_id"]:
            raise SystemExit(f"queue/template mismatch at row {row_number}")
        alignments = ALIGNMENTS[row_number]
        critical_hits = CRITICAL_HITS[row_number]
        order_by_claim = candidate_order(queue)

        row["reviewer_id"] = REVIEWER_ID
        gold_hit_excerpts: dict[str, str] = {}

        for slot in row["candidate_slots"]:
            claim_id = slot["candidate_claim_id"]
            kind = slot["kind"]
            decision = alignments.get(claim_id)
            slot["include_in_denominator"] = 1
            if decision is None:
                slot["aligned_gold_step_id"] = None
                slot["matched_gold_item_id"] = None
                slot["is_true_positive"] = 0
                slot["false_positive_type"] = "wrong_component"
                slot["reason_ja"] = (
                    "凍結Goldのいずれのactor-action-target関係にも整合しない周辺行動。"
                )
                continue

            gold_step, tp_kinds = decision
            full_gold_step = next(
                item["item_id"].rsplit(":", 1)[0]
                for item in queue["gold_items"]
                if item["step_id"] == gold_step
            )
            slot["aligned_gold_step_id"] = full_gold_step
            if kind in tp_kinds:
                gold_item_id = next(
                    item["item_id"]
                    for item in queue["gold_items"]
                    if item["step_id"] == gold_step and item["kind"] == kind
                )
                slot["matched_gold_item_id"] = gold_item_id
                slot["is_true_positive"] = 1
                slot["false_positive_type"] = ""
                slot["reason_ja"] = (
                    f"{gold_step}の{kind}と観測主張が意味的に一致する。"
                )
                gold_hit_excerpts[gold_item_id] = slot["candidate_slot_excerpt"]
            else:
                slot["matched_gold_item_id"] = None
                slot["is_true_positive"] = 0
                slot["false_positive_type"] = (
                    "wrong_relation" if kind == "operation" else "wrong_value"
                )
                slot["reason_ja"] = (
                    f"候補claimは{gold_step}へ対応するが、{kind}はPID・役割・値の"
                    "いずれかがGoldと一致しない。他slotやevidenceによる補完はしない。"
                )

        for item in row["gold_items"]:
            item_id = item["item_id"]
            step_id = step_from_item(item_id)
            if item["kind"] == "critical_evidence":
                hit = step_id in critical_hits
                item["score"] = int(hit)
                item["matched_candidate_excerpt"] = (
                    f"{step_id}を裏付ける非alert一次証跡のprocess/parent/target/time内容"
                    if hit
                    else None
                )
                item["reason_ja"] = (
                    "必須の非alert一次証跡内容を復元しており、全raw fieldの再掲は要求しない。"
                    if hit
                    else "必須の非alert一次証跡内容が不足、別instance、またはalert-onlyである。"
                )
            else:
                hit = item_id in gold_hit_excerpts
                item["score"] = int(hit)
                item["matched_candidate_excerpt"] = (
                    gold_hit_excerpts[item_id] if hit else None
                )
                item["reason_ja"] = (
                    "同一Gold stepへalignした候補slotが意味的に一致する。"
                    if hit
                    else "同一Gold stepへalignできる一致slotが提示されていない。"
                )

        step_claims: dict[str, list[str]] = {}
        for claim_id, (step_id, _tp_kinds) in alignments.items():
            step_claims.setdefault(step_id, []).append(claim_id)
        for pair in row["order_pairs"]:
            pair_body = pair["pair_id"].split(":", 1)[1]
            before, after = pair_body.split("->", 1)
            hit = any(
                left != right and order_by_claim[left] < order_by_claim[right]
                for left in step_claims.get(before, [])
                for right in step_claims.get(after, [])
            )
            pair["score"] = int(hit)
            pair["reason_ja"] = (
                "異なる2候補claimが両Gold stepへalignし、候補順も正順である。"
                if hit
                else "両Gold stepに対応する異なる候補claimの正順ペアが存在しない。"
            )

        row["review_summary_ja"] = (
            "未提示CBC alertとの対応推測を採点せず、PID付きGoldはname-onlyで"
            "補完せず、critical evidenceを行動要素と分離して独立採点した。"
        )
        rendered.append(row)

    with OUTPUT.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rendered:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"wrote {len(rendered)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
