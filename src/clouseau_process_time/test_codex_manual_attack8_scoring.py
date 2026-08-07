#!/usr/bin/env python3
"""Synthetic offline tests for codex_manual_attack8_scoring.py."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import codex_manual_attack8_scoring as scoring


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def make_review(
    queue: dict[str, object],
    reviewer_id: str,
    *,
    gold_score: int = 1,
    slot_score: int = 1,
) -> dict[str, object]:
    row = scoring.review_template(queue)
    row["reviewer_id"] = reviewer_id
    for item in row["gold_items"]:
        item["score"] = gold_score
        item["reason_ja"] = "synthetic"
    for pair in row["order_pairs"]:
        pair["score"] = gold_score
        pair["reason_ja"] = "synthetic"
    for slot in row["candidate_slots"]:
        slot["include_in_denominator"] = 1
        slot["is_true_positive"] = slot_score
        matched = next(
            (
                item["item_id"]
                for item in queue["gold_items"]
                if item["kind"] == slot["kind"]
            ),
            None,
        )
        slot["matched_gold_item_id"] = (
            matched if slot_score else None
        )
        slot["aligned_gold_step_id"] = (
            matched.rsplit(":", 1)[0] if slot_score and matched else None
        )
        slot["false_positive_type"] = "" if slot_score else "unsupported"
        slot["reason_ja"] = "synthetic"
    return row


def make_run(instance_id: str) -> dict[str, object]:
    return {
        "model": "gpt-5.4-mini",
        "experiment_stage": "stage1",
        "instance_id": instance_id,
        "error": None,
        "configs": {
            "max_investigations": None,
            "max_questions": None,
            "max_queries": None,
            "agent_call_limit_policy": "unbounded_by_experiment",
        },
        "output_text": json.dumps(
            {
                "code_steps": [
                    {
                        "step_id": "S1",
                        "subject_process": {"name": "proc.exe"},
                        "operation": "read",
                        "object": {"type": "file", "path": "C:\\test.txt"},
                        "command_line": None,
                        "evidence": [],
                    }
                ]
            }
        ),
    }


def test_v2_deterministic_contract() -> None:
    output = json.loads(make_run("case")["output_text"])
    output["code_steps"][0]["command_line"] = "proc.exe --test"
    output["code_steps"][0]["evidence"] = [{"source_row_id": 1}]
    slots = scoring.candidate_slots(output)
    assert [slot["kind"] for slot in slots] == [
        "subject",
        "operation",
        "object",
    ]

    queue = {
        "schema_version": scoring.SCHEMA_VERSION,
        "model": "gpt-5.4-mini",
        "stage": "stage1",
        "instance_id": "case_stage1",
        "run_sha256": "a" * 64,
        "gold_sha256": "b" * 64,
        "validation_steps_sha256": "c" * 64,
        "maxima": {
            "gold_required_item_count": 4,
            "gold_action_required_item_count": 3,
            "gold_step_count": 1,
            "gold_order_pair_count": 0,
        },
        "gold_items": [
            {
                "chain_id": "chain",
                "step_id": "G1",
                "item_id": f"chain:G1:{kind}",
                "kind": kind,
                "gold_value": kind,
                "acceptable_terms": [],
            }
            for kind in ("subject", "operation", "object", "critical_evidence")
        ],
        "order_pairs": [],
        "candidate_slots": slots,
    }
    contract = {key: queue[key] for key in scoring.CONTRACT_KEYS}
    queue["contract_sha256"] = scoring.canonical_hash(contract)
    queue["queue_id"] = (
        "gpt-5.4-mini/stage1/case_stage1/"
        f"{queue['contract_sha256'][:16]}"
    )
    first = make_review(queue, "reviewer-a")
    second = copy.deepcopy(first)
    second["reviewer_id"] = "reviewer-b"
    second["candidate_slots"][0]["false_positive_type"] = "other"
    assert scoring.decision_fingerprint(first) == scoring.decision_fingerprint(second)

    normalized, errors = scoring.validate_review_row(first, queue)
    assert normalized is not None and not errors
    totals = scoring.totals_from_review(normalized, queue)
    assert totals["candidate_claim_precision_hits"] == 3
    assert totals["candidate_claim_precision_total"] == 3
    assert totals["action_step_precision"] == 1.0


def test_prepare_batching(root: Path) -> None:
    result_root = root / "experiment"
    cases_path = root / "cases.jsonl"
    validation_path = root / "validation.csv"
    gold_root = root / "gold"
    gold_path = gold_root / "chain_gold.json"
    write_json(
        gold_path,
        {
            "chain_id": "chain",
            "behavior_timeline": [
                {
                    "step_id": "G1",
                    "order": 1,
                    "subject": "proc.exe",
                    "action": "read",
                    "object": "C:\\test.txt",
                    "evidence_basis": "row",
                }
            ],
            "gold_order_pairs": [],
        },
    )
    instances = ["case_a_stage1", "case_b_stage1", "case_c_stage1"]
    write_jsonl(
        cases_path,
        [
            {
                "instance_id": instance,
                "formal_gold_root": str(gold_root),
                "gold_chain_file": gold_path.name,
            }
            for instance in instances
        ],
    )
    validation_path.write_text(
        "chain_id,step_id,stage3_status\n", encoding="utf-8"
    )
    for instance in instances[:2]:
        write_json(
            result_root
            / "runs"
            / "gpt-5.4-mini"
            / "stage1"
            / f"{instance}_run.json",
            make_run(instance),
        )

    batch1 = root / "batch_01"
    scoring.prepare(
        SimpleNamespace(
            result_root=result_root,
            score_root=batch1,
            cases=cases_path,
            validation_steps=validation_path,
            expected_count=2,
            exclude_queue=[],
        )
    )
    batch1_queue = batch1 / "review_queue.jsonl"
    first_rows = scoring.read_jsonl(batch1_queue)
    exclusions, sources = scoring.load_exclusion_queues([batch1_queue])
    assert len(exclusions) == 2
    assert sources[0]["case_count"] == 2
    assert scoring.matches_verified_exclusion(
        exclusions,
        model=first_rows[0]["model"],
        stage=first_rows[0]["stage"],
        instance_id=first_rows[0]["instance_id"],
        run_sha256=first_rows[0]["run_sha256"],
    )
    assert not scoring.matches_verified_exclusion(
        exclusions,
        model="gpt-5.4-mini",
        stage="stage1",
        instance_id="not_queued",
        run_sha256="f" * 64,
    )
    try:
        scoring.matches_verified_exclusion(
            exclusions,
            model=first_rows[0]["model"],
            stage=first_rows[0]["stage"],
            instance_id=first_rows[0]["instance_id"],
            run_sha256="f" * 64,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("changed run SHA-256 was incorrectly excluded")

    changed = copy.deepcopy(first_rows[0])
    changed["run_sha256"] = "d" * 64
    contract = {key: changed[key] for key in scoring.CONTRACT_KEYS}
    changed["contract_sha256"] = scoring.canonical_hash(contract)
    changed["queue_id"] = (
        f"{changed['model']}/{changed['stage']}/{changed['instance_id']}/"
        f"{changed['contract_sha256'][:16]}"
    )
    changed_queue = root / "changed_queue.jsonl"
    write_jsonl(changed_queue, [changed])
    try:
        scoring.load_exclusion_queues([batch1_queue, changed_queue])
    except ValueError:
        pass
    else:
        raise AssertionError("conflicting exclusion queues were accepted")

    third = instances[2]
    write_json(
        result_root
        / "runs"
        / "gpt-5.4-mini"
        / "stage1"
        / f"{third}_run.json",
        make_run(third),
    )
    batch2 = root / "batch_02"
    scoring.prepare(
        SimpleNamespace(
            result_root=result_root,
            score_root=batch2,
            cases=cases_path,
            validation_steps=validation_path,
            expected_count=1,
            exclude_queue=[batch1_queue],
        )
    )
    batch2_rows = scoring.read_jsonl(batch2 / "review_queue.jsonl")
    assert [row["instance_id"] for row in batch2_rows] == [third]
    manifest = scoring.read_json(batch2 / "queue_manifest.json")
    assert manifest["completed_eligible_before_exclusion"] == 3
    assert manifest["excluded_count"] == 2
    assert manifest["eligible_count"] == 1


def run_test() -> None:
    test_v2_deterministic_contract()
    with tempfile.TemporaryDirectory(prefix="codex_manual_scoring_") as temporary:
        root = Path(temporary)
        test_prepare_batching(root / "batching")
        queue_rows: list[dict[str, object]] = []
        for stage in ("stage1", "stage2", "stage3"):
            body = {
                "schema_version": scoring.SCHEMA_VERSION,
                "model": "gpt-5.4-mini",
                "stage": stage,
                "instance_id": f"case_{stage}",
                "run_sha256": "a" * 64,
                "gold_sha256": "b" * 64,
                "validation_steps_sha256": "c" * 64,
                "maxima": {
                    "gold_required_item_count": 2,
                    "gold_action_required_item_count": 1,
                    "gold_step_count": 1,
                    "gold_order_pair_count": 0,
                },
                "gold_items": [
                    {
                        "chain_id": "chain",
                        "step_id": "G1",
                        "item_id": f"chain:G1:subject",
                        "kind": "subject",
                        "gold_value": "proc.exe",
                        "acceptable_terms": ["proc.exe"],
                    },
                    {
                        "chain_id": "chain",
                        "step_id": "G1",
                        "item_id": f"chain:G1:critical_evidence",
                        "kind": "critical_evidence",
                        "gold_value": "row",
                        "acceptable_terms": ["row"],
                    },
                ],
                "order_pairs": [],
                "candidate_slots": [
                    {
                        "candidate_claim_id": "C1",
                        "candidate_step_id": "S1",
                        "slot_id": "C1:subject",
                        "kind": "subject",
                        "candidate_slot_excerpt": '{"name":"proc.exe"}',
                    }
                ],
            }
            body["contract_sha256"] = scoring.canonical_hash(body)
            body["queue_id"] = (
                f"gpt-5.4-mini/{stage}/case_{stage}/"
                f"{body['contract_sha256'][:16]}"
            )
            body["candidate_output"] = {
                "code_steps": [
                    {
                        "step_id": "S1",
                        "subject_process": {"name": "proc.exe"},
                        "operation": None,
                        "object": None,
                        "command_line": None,
                        "evidence": [],
                    }
                ]
            }
            body["run_json"] = f"{stage}_run.json"
            body["gold_json"] = "gold.json"
            queue_rows.append(body)

        queue_path = root / "review_queue.jsonl"
        write_jsonl(queue_path, queue_rows)
        review1 = [make_review(row, "codex-reviewer-a") for row in queue_rows]
        review2 = [make_review(row, "codex-reviewer-b") for row in queue_rows]
        review2[1]["gold_items"][0]["score"] = 0
        raw1, raw2 = root / "raw_review1.jsonl", root / "raw_review2.jsonl"
        write_jsonl(raw1, review1)
        write_jsonl(raw2, review2)

        score_root = root / scoring.DEFAULT_SCORE_ROOT_NAME
        for name, path in (("review1", raw1), ("review2", raw2)):
            scoring.validate_reviews(
                SimpleNamespace(
                    queue=queue_path,
                    reviewer_jsonl=path,
                    review_name=name,
                    score_root=score_root,
                )
            )
        validated1 = score_root / "validated_reviews" / "review1.jsonl"
        validated2 = score_root / "validated_reviews" / "review2.jsonl"

        first_finalize_root = root / "without_third"
        scoring.finalize(
            SimpleNamespace(
                queue=queue_path,
                review1=validated1,
                review2=validated2,
                review3=None,
                score_root=first_finalize_root,
            )
        )
        aggregate1 = scoring.read_json(
            first_finalize_root
            / "formal_outputs"
            / "formal_aggregate_adopted_only.json"
        )
        assert aggregate1["adopted_run_count"] == 2
        assert aggregate1["excluded_conflict_count"] == 1
        assert aggregate1["complete"] is False

        review3 = [make_review(queue_rows[1], "codex-reviewer-c", gold_score=0)]
        raw3 = root / "raw_review3.jsonl"
        write_jsonl(raw3, review3)
        # Review3 is intentionally a conflict-only subset; validate it directly
        # against a matching conflict queue.
        conflict_queue = root / "conflict_queue.jsonl"
        write_jsonl(conflict_queue, [queue_rows[1]])
        scoring.validate_reviews(
            SimpleNamespace(
                queue=conflict_queue,
                reviewer_jsonl=raw3,
                review_name="review3",
                score_root=score_root,
            )
        )
        validated3 = score_root / "validated_reviews" / "review3.jsonl"
        final_root = root / "with_third"
        scoring.finalize(
            SimpleNamespace(
                queue=queue_path,
                review1=validated1,
                review2=validated2,
                review3=validated3,
                score_root=final_root,
            )
        )
        aggregate2 = scoring.read_json(
            final_root / "formal_outputs" / "formal_aggregate_adopted_only.json"
        )
        assert aggregate2["adopted_run_count"] == 3
        assert aggregate2["third_review_adjudicated_count"] == 1
        assert aggregate2["excluded_conflict_count"] == 0
        assert aggregate2["complete"] is True
        assert aggregate2["by_stage"]["stage2"]["metrics"][
            "behavior_step_recall"
        ]["hits"] == 0

        adopted_rows = scoring.read_jsonl(
            final_root / "formal_outputs" / "adopted_reviews.jsonl"
        )
        ledger1 = root / "batch_adopted_01.jsonl"
        ledger2 = root / "batch_adopted_02.jsonl"
        write_jsonl(ledger1, adopted_rows[:2])
        write_jsonl(ledger2, adopted_rows[2:])
        merged_root = root / "merged_final"
        scoring.merge_batches(
            SimpleNamespace(
                adopted_ledger=[ledger1, ledger2],
                score_root=merged_root,
                expected_count=3,
                expected_stage_count=1,
            )
        )
        merged_aggregate = scoring.read_json(
            merged_root
            / "formal_outputs"
            / "formal_aggregate_adopted_only.json"
        )
        assert merged_aggregate["adopted_run_count"] == 3
        assert merged_aggregate["stage_counts"] == {
            "stage1": 1,
            "stage2": 1,
            "stage3": 1,
        }
        assert merged_aggregate["complete"] is True
        merged_rows = scoring.read_jsonl(
            merged_root / "formal_outputs" / "adopted_reviews.jsonl"
        )
        assert all(
            row["merge_verification_level"]
            == "full_contract_decision_and_totals"
            for row in merged_rows
        )

        try:
            scoring.merge_batches(
                SimpleNamespace(
                    adopted_ledger=[ledger1, ledger1, ledger2],
                    score_root=root / "duplicate_merge",
                    expected_count=3,
                    expected_stage_count=1,
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate adopted rows were merged")

        tampered_rows = copy.deepcopy(adopted_rows[:1])
        tampered_rows[0]["adopted_decisions"]["gold_items"][0]["score"] = (
            1 - tampered_rows[0]["adopted_decisions"]["gold_items"][0]["score"]
        )
        tampered_ledger = root / "tampered_adopted.jsonl"
        write_jsonl(tampered_ledger, tampered_rows)
        try:
            scoring.merge_batches(
                SimpleNamespace(
                    adopted_ledger=[tampered_ledger],
                    score_root=root / "tampered_merge",
                    expected_count=1,
                    expected_stage_count=1,
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError("tampered adopted decision was merged")

        invalid = make_review(queue_rows[0], "bad-reviewer")
        invalid["candidate_slots"][0]["slot_id"] = "unknown"
        normalized, errors = scoring.validate_review_row(invalid, queue_rows[0])
        assert normalized is None
        assert any("unknown candidate slot" in error for error in errors)

        duplicate_target = root / "immutable.json"
        write_json(duplicate_target, {"existing": True})
        try:
            scoring.write_json_new(duplicate_target, {"replacement": True})
        except FileExistsError:
            pass
        else:
            raise AssertionError("non-overwrite policy was not enforced")

    print("synthetic Codex manual scoring tests: PASS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    run_test()


if __name__ == "__main__":
    main()
