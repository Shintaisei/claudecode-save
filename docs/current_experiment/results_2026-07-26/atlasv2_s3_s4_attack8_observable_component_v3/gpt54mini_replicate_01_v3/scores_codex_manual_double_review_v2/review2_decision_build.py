#!/usr/bin/env python3
"""Materialize the independent Codex review2 decisions for the frozen v3 queue."""

from __future__ import annotations

import json
from pathlib import Path


SCORE_ROOT = Path(__file__).resolve().parent
QUEUE = SCORE_ROOT / "review_queue.jsonl"
OUTPUT = SCORE_ROOT / "raw_reviews" / "review2_raw.jsonl"
REVIEWER_ID = "/root/v3_codex_review2"
ALL_KINDS = frozenset({"subject", "operation", "object"})


# Manual claim alignment.  Each value is:
# candidate claim -> (Gold step number, TP component kinds).
CLAIM_DECISIONS = {
    2: {
        "C1": (1, {"subject", "operation"}),
        "C2": (2, {"subject", "object"}),
    },
    3: {"C1": (5, {"subject", "operation"})},
    6: {
        "C1": (4, {"subject", "operation"}),
        "C2": (3, set(ALL_KINDS)),
        "C3": (2, set(ALL_KINDS)),
    },
    9: {
        "C1": (2, set(ALL_KINDS)),
        "C2": (3, set(ALL_KINDS)),
    },
    10: {
        "C1": (3, {"subject"}),
        "C2": (2, set(ALL_KINDS)),
    },
    11: {
        "C1": (5, {"subject", "operation"}),
        "C2": (7, {"subject", "operation"}),
    },
    14: {
        "C1": (4, {"subject", "operation"}),
        "C2": (2, set(ALL_KINDS)),
        "C3": (5, {"subject", "operation"}),
        "C4": (3, {"operation", "object"}),
    },
    17: {"C2": (3, set(ALL_KINDS))},
    19: {
        "C1": (8, {"subject", "operation"}),
        "C2": (9, {"subject", "operation"}),
        "C3": (10, {"subject", "operation"}),
    },
    22: {"C2": (3, set(ALL_KINDS))},
}


# Critical evidence is scored independently from action components.
# Gold step number -> candidate claim containing the direct observed evidence.
CRITICAL_EVIDENCE_DECISIONS = {
    6: {1: "C1", 2: "C3", 3: "C2", 4: "C4"},
    9: {2: "C1", 3: "C2"},
    10: {1: "C1", 2: "C2"},
    11: {4: "C1"},
    14: {1: "C1", 2: "C2", 4: "C3"},
    17: {2: "C1", 3: "C2"},
    19: {4: "C1", 8: "C2", 9: "C3"},
    22: {1: "C1", 3: "C2", 4: "C3"},
}


# Diagnostic FP categories for claims that cannot be aligned at all.
UNALIGNED_FP_TYPES = {
    0: {
        "C1": "unsupported",
        "C2": "wrong_component",
        "C3": "wrong_component",
        "C4": "wrong_component",
        "C5": "wrong_component",
        "C6": "wrong_component",
        "C7": "wrong_component",
    },
    1: {"C1": "unsupported", "C2": "unsupported"},
    4: {
        "C1": "unsupported",
        "C2": "unsupported",
        "C3": "wrong_component",
        "C4": "wrong_component",
        "C5": "wrong_component",
        "C6": "wrong_component",
        "C7": "wrong_component",
    },
    5: {"C1": "unsupported", "C2": "unsupported"},
    6: {"C4": "wrong_relation"},
    7: {
        "C1": "unsupported",
        "C2": "unsupported",
        "C3": "unsupported",
        "C4": "unsupported",
    },
    8: {
        "C1": "unsupported",
        "C2": "unsupported",
        "C3": "unsupported",
        "C4": "wrong_component",
        "C5": "wrong_component",
        "C6": "wrong_component",
        "C7": "wrong_component",
    },
    9: {"C3": "wrong_component"},
    12: {
        "C1": "unsupported",
        "C2": "unsupported",
        "C3": "unsupported",
        "C4": "wrong_component",
        "C5": "wrong_component",
        "C6": "wrong_component",
    },
    13: {"C1": "wrong_component"},
    17: {"C1": "wrong_relation", "C3": "wrong_component"},
    18: {"C1": "unsupported", "C2": "unsupported", "C3": "unsupported"},
    21: {
        "C1": "wrong_component",
        "C2": "wrong_component",
        "C3": "wrong_component",
        "C4": "wrong_component",
    },
    22: {"C1": "wrong_relation", "C3": "wrong_relation"},
    23: {
        "C1": "unsupported",
        "C2": "wrong_component",
        "C3": "wrong_component",
        "C4": "wrong_component",
    },
}


PARTIAL_FP_TYPES = {
    (2, "C1", "object"): "wrong_relation",
    (2, "C2", "operation"): "wrong_relation",
    (3, "C1", "object"): "wrong_value",
    (6, "C1", "object"): "wrong_relation",
    (10, "C1", "operation"): "wrong_relation",
    (10, "C1", "object"): "wrong_value",
    (11, "C1", "object"): "wrong_value",
    (11, "C2", "object"): "wrong_value",
    (14, "C1", "object"): "wrong_relation",
    (14, "C3", "object"): "wrong_value",
    (14, "C4", "subject"): "wrong_component",
    (19, "C1", "object"): "wrong_relation",
    (19, "C2", "object"): "wrong_relation",
    (19, "C3", "object"): "wrong_relation",
}


def full_step_id(queue_row: dict, step_number: int) -> str:
    suffix = f"-S{step_number:02d}"
    matches = {
        item["item_id"].rsplit(":", 1)[0]
        for item in queue_row["gold_items"]
        if item["step_id"].endswith(suffix)
    }
    if len(matches) != 1:
        raise RuntimeError(
            f"cannot resolve Gold step {step_number} for {queue_row['queue_id']}"
        )
    return next(iter(matches))


def candidate_steps(queue_row: dict) -> dict[str, dict]:
    return {
        f"C{number}": step
        for number, step in enumerate(
            queue_row["candidate_output"].get("code_steps", []), start=1
        )
    }


def evidence_excerpt(step: dict) -> str:
    evidence = step.get("evidence") or []
    compact = [
        {
            key: event.get(key)
            for key in ("source_stream", "timestamp", "field", "value", "pid", "ppid")
        }
        for event in evidence[:3]
    ]
    return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))


def build_review(index: int, queue_row: dict) -> dict:
    decisions = CLAIM_DECISIONS.get(index, {})
    aligned = {
        claim_id: (full_step_id(queue_row, step_number), tp_kinds)
        for claim_id, (step_number, tp_kinds) in decisions.items()
    }
    steps = candidate_steps(queue_row)
    expected_slots = {
        slot["slot_id"]: slot for slot in queue_row["candidate_slots"]
    }

    candidate_slots = []
    for slot in queue_row["candidate_slots"]:
        claim_id = slot["candidate_claim_id"]
        kind = slot["kind"]
        aligned_decision = aligned.get(claim_id)
        if aligned_decision is None:
            is_tp = 0
            aligned_step = None
            matched_item = None
            fp_type = UNALIGNED_FP_TYPES.get(index, {}).get(
                claim_id, "wrong_component"
            )
            reason = (
                "Goldで指定されたactor PID・関係・対象を同時に満たすclaimではない。"
            )
        else:
            aligned_step, tp_kinds = aligned_decision
            is_tp = int(kind in tp_kinds)
            if is_tp:
                matched_item = f"{aligned_step}:{kind}"
                fp_type = ""
                reason = (
                    f"{claim_id}は{aligned_step}に整合し、この{kind}要素を明示する。"
                )
            else:
                matched_item = None
                fp_type = PARTIAL_FP_TYPES.get(
                    (index, claim_id, kind), "wrong_value"
                )
                reason = (
                    f"{claim_id}は{aligned_step}に部分整合するが、この{kind}要素は"
                    "Goldの値または関係を満たさない。"
                )
        candidate_slots.append(
            {
                **slot,
                "include_in_denominator": 1,
                "aligned_gold_step_id": aligned_step,
                "matched_gold_item_id": matched_item,
                "is_true_positive": is_tp,
                "false_positive_type": fp_type,
                "reason_ja": reason,
            }
        )

    slot_by_gold_item = {}
    for slot in candidate_slots:
        if slot["is_true_positive"] == 1:
            slot_by_gold_item.setdefault(slot["matched_gold_item_id"], slot)

    critical_map = {
        full_step_id(queue_row, step_number): claim_id
        for step_number, claim_id in CRITICAL_EVIDENCE_DECISIONS.get(
            index, {}
        ).items()
    }
    gold_items = []
    for item in queue_row["gold_items"]:
        item_id = item["item_id"]
        kind = item["kind"]
        if kind == "critical_evidence":
            claim_id = critical_map.get(item_id.rsplit(":", 1)[0])
            if claim_id is not None:
                score = 1
                excerpt = evidence_excerpt(steps[claim_id])
                reason = (
                    f"{claim_id}の直接観測証拠がPID・対象/親子関係・時刻で"
                    "当該Gold stepを裏付ける。"
                )
            else:
                score = 0
                excerpt = None
                reason = (
                    "当該Gold stepを具体的に裏付けるPID・対象・時刻付きの"
                    "直接証拠が提示されていない。"
                )
        else:
            matched_slot = slot_by_gold_item.get(item_id)
            if matched_slot is not None:
                score = 1
                excerpt = matched_slot["candidate_slot_excerpt"]
                reason = (
                    f"{matched_slot['candidate_claim_id']}が同一Gold stepの"
                    f"{kind}要素を明示する。"
                )
            else:
                score = 0
                excerpt = None
                reason = (
                    "同一Gold stepへ整合したcandidate claimに、この要素の"
                    "一致はない。"
                )
        gold_items.append(
            {
                "item_id": item_id,
                "kind": kind,
                "score": score,
                "matched_candidate_excerpt": excerpt,
                "reason_ja": reason,
            }
        )

    claim_order = {
        f"C{number}": number
        for number, _ in enumerate(
            queue_row["candidate_output"].get("code_steps", []), start=1
        )
    }
    step_to_claims: dict[str, list[str]] = {}
    for claim_id, (step_id, _) in aligned.items():
        step_to_claims.setdefault(step_id, []).append(claim_id)

    order_pairs = []
    for pair in queue_row["order_pairs"]:
        before_ref = f"{pair['chain_id']}:{pair['before_step_id']}"
        after_ref = f"{pair['chain_id']}:{pair['after_step_id']}"
        before_claims = step_to_claims.get(before_ref, [])
        after_claims = step_to_claims.get(after_ref, [])
        witnesses = [
            (before, after)
            for before in before_claims
            for after in after_claims
            if before != after and claim_order[before] < claim_order[after]
        ]
        if witnesses:
            score = 1
            before, after = witnesses[0]
            reason = (
                f"別claim {before}→{after}が両Gold stepへ整合し、正順で現れる。"
            )
        else:
            score = 0
            reason = (
                "両Gold stepへ整合する別々のcandidate claimが正順では揃わない。"
            )
        order_pairs.append(
            {
                "pair_id": pair["pair_id"],
                "score": score,
                "reason_ja": reason,
            }
        )

    gold_hits = sum(item["score"] for item in gold_items)
    slot_hits = sum(slot["is_true_positive"] for slot in candidate_slots)
    order_hits = sum(pair["score"] for pair in order_pairs)
    return {
        "schema_version": queue_row["schema_version"],
        "queue_id": queue_row["queue_id"],
        "contract_sha256": queue_row["contract_sha256"],
        "reviewer_id": REVIEWER_ID,
        "gold_items": gold_items,
        "order_pairs": order_pairs,
        "candidate_slots": candidate_slots,
        "review_summary_ja": (
            f"独立review2。Gold item {gold_hits}/{len(gold_items)}、"
            f"order {order_hits}/{len(order_pairs)}、candidate slot "
            f"{slot_hits}/{len(candidate_slots)}。未提示CBC alert対応は採点外。"
        ),
    }


def main() -> None:
    queue_rows = [
        json.loads(line)
        for line in QUEUE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(queue_rows) != 24:
        raise RuntimeError(f"expected 24 queue rows, got {len(queue_rows)}")
    if OUTPUT.exists():
        raise FileExistsError(f"refusing to overwrite {OUTPUT}")

    reviews = [build_review(index, row) for index, row in enumerate(queue_rows)]
    with OUTPUT.open("x", encoding="utf-8", newline="\n") as handle:
        for review in reviews:
            handle.write(json.dumps(review, ensure_ascii=False) + "\n")
    print(f"wrote {len(reviews)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
