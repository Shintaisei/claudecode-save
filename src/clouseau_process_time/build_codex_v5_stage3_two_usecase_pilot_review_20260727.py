#!/usr/bin/env python3
"""Materialize the item-level Codex review for the v5 Stage-3 pilot.

This script contains only the explicit decisions made by Codex after reading
the four frozen queue items.  It does not call a model or a judge API.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REVIEWER_ID = "/root/codex_v5_stage3_two_usecase_pilot_single_review"

# candidate claim -> (Gold step id, true-positive component kinds)
ALIGNMENTS: dict[tuple[str, str], dict[str, tuple[str, set[str]]]] = {
    (
        "gpt-4.1-mini",
        "s3_pt_01_word_document_processing_stage3",
    ): {},
    (
        "gpt-4.1-mini",
        "s4_pt_03_mshta_c1_stage3",
    ): {
        "C3": ("A8V5-07-S03", {"operation", "object"}),
    },
    (
        "gpt-5.4-mini",
        "s3_pt_01_word_document_processing_stage3",
    ): {
        "C2": ("A8V5-01-S01", {"subject", "operation", "object"}),
    },
    (
        "gpt-5.4-mini",
        "s4_pt_03_mshta_c1_stage3",
    ): {
        "C1": ("A8V5-07-S02", {"subject", "operation"}),
        "C2": ("A8V5-07-S03", {"operation", "object"}),
        "C3": ("A8V5-07-S04", {"subject", "operation", "object"}),
    },
}

# Critical evidence uses content inclusion under the normal-23 rubric.  These
# steps include substantive non-alert process/file/network evidence in output.
CRITICAL_EVIDENCE_HITS: dict[tuple[str, str], set[str]] = {
    (
        "gpt-4.1-mini",
        "s3_pt_01_word_document_processing_stage3",
    ): set(),
    (
        "gpt-4.1-mini",
        "s4_pt_03_mshta_c1_stage3",
    ): {"A8V5-07-S03"},
    (
        "gpt-5.4-mini",
        "s3_pt_01_word_document_processing_stage3",
    ): {"A8V5-01-S01"},
    (
        "gpt-5.4-mini",
        "s4_pt_03_mshta_c1_stage3",
    ): {"A8V5-07-S02", "A8V5-07-S03", "A8V5-07-S04"},
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl_new(path: Path, rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def chain_id(queue: dict[str, Any]) -> str:
    return str(queue["gold_items"][0]["chain_id"])


def full_step_id(queue: dict[str, Any], step_id: str) -> str:
    return f"{chain_id(queue)}:{step_id}"


def build_review(queue: dict[str, Any]) -> dict[str, Any]:
    key = (str(queue["model"]), str(queue["instance_id"]))
    alignments = ALIGNMENTS[key]
    evidence_hits = CRITICAL_EVIDENCE_HITS[key]
    matched_gold_items: dict[str, str] = {}
    claim_order = {
        str(step["step_id"]): int(step.get("order") or index + 1)
        for index, step in enumerate(queue["candidate_output"]["code_steps"])
    }

    candidate_slots: list[dict[str, Any]] = []
    aligned_claims: dict[str, str] = {}
    for source in queue["candidate_slots"]:
        claim_id = str(source["candidate_claim_id"])
        kind = str(source["kind"])
        decision = alignments.get(claim_id)
        if decision is None:
            aligned = None
            matched = None
            is_tp = 0
            fp_type = "wrong_component"
            reason = (
                "凍結Goldのactor-action-target関係へalignできない周辺行動、"
                "別系列、または未確認の追加行動である。"
            )
        else:
            step_id, true_kinds = decision
            aligned = full_step_id(queue, step_id)
            aligned_claims[claim_id] = step_id
            if kind in true_kinds:
                matched = f"{aligned}:{kind}"
                matched_gold_items[matched] = str(source["candidate_slot_excerpt"])
                is_tp = 1
                fp_type = ""
                reason = (
                    f"{step_id}へalignしたclaim内で、{kind}がGoldと意味的に一致する。"
                )
            else:
                matched = None
                is_tp = 0
                fp_type = "wrong_value"
                reason = (
                    f"claimは{step_id}へalignするが、{kind}の値または役割が"
                    "同一Gold stepと一致しない。別slotでは補完しない。"
                )
        candidate_slots.append(
            {
                **source,
                "include_in_denominator": 1,
                "aligned_gold_step_id": aligned,
                "matched_gold_item_id": matched,
                "is_true_positive": is_tp,
                "false_positive_type": fp_type,
                "reason_ja": reason,
            }
        )

    gold_items: list[dict[str, Any]] = []
    for item in queue["gold_items"]:
        item_id = str(item["item_id"])
        step_id = str(item["step_id"])
        kind = str(item["kind"])
        if kind == "critical_evidence":
            score = int(step_id in evidence_hits)
            excerpt = (
                "candidate output内の非alert一次証拠内容"
                if score
                else None
            )
            reason = (
                "process/file/networkの主要な非alert証拠内容を回収している。"
                if score
                else "Gold stepを支える主要な非alert証拠内容を回収していない。"
            )
        else:
            score = int(item_id in matched_gold_items)
            excerpt = matched_gold_items.get(item_id)
            reason = (
                "同一Gold stepへalignした候補slotが意味的に一致する。"
                if score
                else "同一Gold stepへalignできる一致slotが提示されていない。"
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

    order_pairs: list[dict[str, Any]] = []
    claims_by_step: dict[str, list[str]] = {}
    for claim_id, step_id in aligned_claims.items():
        claims_by_step.setdefault(step_id, []).append(claim_id)
    for pair in queue["order_pairs"]:
        before = str(pair["before_step_id"])
        after = str(pair["after_step_id"])
        valid = any(
            before_claim != after_claim
            and claim_order[before_claim.replace("C", "S", 1)]
            < claim_order[after_claim.replace("C", "S", 1)]
            for before_claim in claims_by_step.get(before, [])
            for after_claim in claims_by_step.get(after, [])
        )
        order_pairs.append(
            {
                "pair_id": pair["pair_id"],
                "score": int(valid),
                "reason_ja": (
                    "異なるcandidate claimが両Gold stepへalignし、正順である。"
                    if valid
                    else "両Gold stepへalignする異なるcandidate claimの正順ペアがない。"
                ),
            }
        )

    return {
        "schema_version": queue["schema_version"],
        "queue_id": queue["queue_id"],
        "contract_sha256": queue["contract_sha256"],
        "reviewer_id": REVIEWER_ID,
        "gold_items": gold_items,
        "order_pairs": order_pairs,
        "candidate_slots": candidate_slots,
        "review_summary_ja": (
            "正常23と同じprocess-chain component rubricによるCodex単独pilotレビュー。"
            "PIDとhidden alert mappingは非採点。"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = read_jsonl(args.queue)
    keys = {(str(row["model"]), str(row["instance_id"])) for row in rows}
    if keys != set(ALIGNMENTS):
        raise ValueError(
            f"queue/decision key mismatch: missing={set(ALIGNMENTS) - keys}, "
            f"extra={keys - set(ALIGNMENTS)}"
        )
    reviews = [build_review(row) for row in rows]
    write_jsonl_new(args.output, reviews)
    print(f"Wrote {len(reviews)} Codex review rows: {args.output}")


if __name__ == "__main__":
    main()
