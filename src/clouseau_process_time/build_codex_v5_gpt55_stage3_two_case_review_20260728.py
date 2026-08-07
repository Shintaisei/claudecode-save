#!/usr/bin/env python3
"""Materialize the manual Codex review for the GPT-5.5 two-case pilot.

The decisions below were made by Codex after reading the frozen Gold,
candidate output, and evidence.  This script does not call a judge API.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REVIEWER_ID = "/root/codex_gpt55_stage3_two_case_single_review_20260728"

# Candidate claim -> (Gold step, true-positive atomic component kinds).
ALIGNMENTS: dict[str, dict[str, tuple[str, set[str]]]] = {
    "s3_pt_01_word_document_processing_stage3": {
        # The command line names msf.rtf, but the claim itself is process
        # creation with a process object; only its subject matches the
        # document-open Gold step.
        "C1": ("A8V5-01-S01", {"subject"}),
        "C2": ("A8V5-01-S02", {"subject", "operation", "object"}),
    },
    "s4_pt_03_mshta_c1_stage3": {
        # C1 reverses/omits the causal actor but does identify creation of
        # mshta.exe; operation and object therefore match, subject does not.
        "C1": ("A8V5-07-S01", {"operation", "object"}),
        "C2": ("A8V5-07-S02", {"subject", "operation", "object"}),
        "C4": ("A8V5-07-S03", {"subject", "operation", "object"}),
    },
}

# Evidence is a separate diagnostic.  Equivalent primary telemetry is
# accepted even when the exact Gold row identifier was not copied.
CRITICAL_EVIDENCE_HITS: dict[str, set[str]] = {
    "s3_pt_01_word_document_processing_stage3": {"A8V5-01-S02"},
    "s4_pt_03_mshta_c1_stage3": {
        "A8V5-07-S01",
        "A8V5-07-S02",
        "A8V5-07-S03",
    },
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
    instance_id = str(queue["instance_id"])
    alignments = ALIGNMENTS[instance_id]
    evidence_hits = CRITICAL_EVIDENCE_HITS[instance_id]
    matched_gold_items: dict[str, str] = {}
    aligned_claims: dict[str, str] = {}
    claim_order = {
        f"C{index}": int(step.get("order") or index)
        for index, step in enumerate(
            queue["candidate_output"]["code_steps"], start=1
        )
    }

    candidate_slots: list[dict[str, Any]] = []
    for source in queue["candidate_slots"]:
        claim_id = str(source["candidate_claim_id"])
        kind = str(source["kind"])
        decision = alignments.get(claim_id)
        if decision is None:
            aligned = None
            matched = None
            is_tp = 0
            fp_type = "unsupported"
            reason = "このcandidate行動はGoldの主要process-chain stepに対応しない。"
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
                    f"{step_id}へ対応し、{kind}がGoldの同一atomic componentと"
                    "意味的に一致する。"
                )
            else:
                matched = None
                is_tp = 0
                fp_type = "wrong_component"
                reason = (
                    f"claim全体は{step_id}に近いが、{kind}の値または因果上の"
                    "役割がGoldと一致しない。"
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
                "candidate output内の同時刻・同process edgeの一次テレメトリ"
                if score
                else None
            )
            reason = (
                "同じ行動を裏付けるprocess/file/networkの一次証拠を提示した。"
                if score
                else "Gold行動を直接裏付ける一次証拠を提示していない。"
            )
        else:
            score = int(item_id in matched_gold_items)
            excerpt = matched_gold_items.get(item_id)
            reason = (
                "対応candidate slotが同一Gold componentと一致する。"
                if score
                else "対応する一致candidate slotがない。"
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

    claims_by_step: dict[str, list[str]] = {}
    for claim_id, step_id in aligned_claims.items():
        claims_by_step.setdefault(step_id, []).append(claim_id)

    order_pairs: list[dict[str, Any]] = []
    for pair in queue["order_pairs"]:
        before = str(pair["before_step_id"])
        after = str(pair["after_step_id"])
        valid = any(
            before_claim != after_claim
            and claim_order[before_claim] < claim_order[after_claim]
            for before_claim in claims_by_step.get(before, [])
            for after_claim in claims_by_step.get(after, [])
        )
        order_pairs.append(
            {
                "pair_id": pair["pair_id"],
                "score": int(valid),
                "reason_ja": (
                    "異なるcandidate claimが両Gold stepへ対応し、順序も正しい。"
                    if valid
                    else "両Gold stepへ対応する異なるcandidate claimの正順序がない。"
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
            "正常23と同じprocess-chain component rubricによる単一Codex pilot review。"
            "subject/operation/objectはcandidate TP slotとのatomic alignmentから決定し、"
            "critical evidenceとorderは別診断、PIDとhidden alert mappingは非採点。"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = read_jsonl(args.queue)
    found = {str(row["instance_id"]) for row in rows}
    if found != set(ALIGNMENTS):
        raise ValueError(
            f"queue/decision mismatch: missing={set(ALIGNMENTS) - found}, "
            f"extra={found - set(ALIGNMENTS)}"
        )
    for row in rows:
        if str(row["model"]) != "gpt-5.5" or str(row["stage"]) != "stage3":
            raise ValueError("unexpected model/stage in frozen queue")

    write_jsonl_new(args.output, [build_review(row) for row in rows])
    print(f"Wrote {len(rows)} Codex review rows: {args.output}")


if __name__ == "__main__":
    main()
