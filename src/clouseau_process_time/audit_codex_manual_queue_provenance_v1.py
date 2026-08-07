#!/usr/bin/env python3
"""Read-only provenance/schema audit for a Codex manual review queue.

The audit deliberately reads only the queue, its manifest, source runs, cases,
Gold files, and Stage-3 validation contract.  It does not read reviewer
templates, reviewer decisions, conflicts, or adopted ledgers, and it makes no
external API calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import codex_manual_attack8_scoring as scoring


EXPECTED_MODELS = ("gpt-4.1-mini", "gpt-5.4-mini")
EXPECTED_STAGES = ("stage1", "stage2", "stage3")
EXPECTED_QUEUE_ROWS = 48
EXPECTED_PER_MODEL = 24
EXPECTED_PER_STAGE = 16
EXPECTED_PER_MODEL_STAGE = 8
REQUIRED_CANDIDATE_KINDS = frozenset({"subject", "action", "object"})
REQUIRED_ROW_FIELDS = frozenset(
    {
        *scoring.CONTRACT_KEYS,
        "queue_id",
        "contract_sha256",
        "run_json",
        "gold_json",
        "candidate_output",
        "review_policy",
    }
)
PID_TOKEN = re.compile(
    r"(?i)(?:process_pid|childproc_pid|\bpid\b\s*[:=]|\bppid\b\s*[:=])"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def counter_json(counter: Counter[Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, value in sorted(counter.items(), key=lambda item: str(item[0])):
        if isinstance(key, tuple):
            label = "/".join(str(part) for part in key)
        else:
            label = str(key)
        result[label] = value
    return result


def item_match_count(
    queued: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    id_key: str,
) -> tuple[int, list[str]]:
    queued_by_id = {
        str(row.get(id_key) or ""): row for row in queued if isinstance(row, dict)
    }
    expected_by_id = {
        str(row.get(id_key) or ""): row for row in expected if isinstance(row, dict)
    }
    ids = set(queued_by_id) | set(expected_by_id)
    matched = sum(
        queued_by_id.get(identity) == expected_by_id.get(identity) for identity in ids
    )
    failed_ids = sorted(
        identity
        for identity in ids
        if queued_by_id.get(identity) != expected_by_id.get(identity)
    )
    duplicate_count = (len(queued) - len(queued_by_id)) + (
        len(expected) - len(expected_by_id)
    )
    if duplicate_count:
        failed_ids.append(f"<duplicate_count:{duplicate_count}>")
    return matched, failed_ids


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--score-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    score_root = args.score_root.resolve()
    queue_path = score_root / "review_queue.jsonl"
    manifest_path = score_root / "queue_manifest.json"
    output_path = (args.output or score_root / "queue_provenance_audit_v1.json").resolve()
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {output_path}")

    manifest = scoring.read_json(manifest_path)
    rows = scoring.read_jsonl(queue_path)
    cases_path = Path(str(manifest["cases"]))
    validation_path = Path(str(manifest["validation_steps"]))
    result_root = Path(str(manifest["result_root"]))
    cases = scoring.case_index(cases_path)
    queue_sha256 = sha256_file(queue_path)

    checks: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []

    def add_check(
        name: str,
        checked_count: int,
        passed_count: int,
        *,
        expected_count: int | None = None,
        details: dict[str, Any] | None = None,
        failed_examples: list[Any] | None = None,
    ) -> None:
        failed_count = checked_count - passed_count
        status = "pass" if failed_count == 0 else "fail"
        check: dict[str, Any] = {
            "status": status,
            "checked_count": checked_count,
            "passed_count": passed_count,
            "failed_count": failed_count,
        }
        if expected_count is not None:
            check["expected_count"] = expected_count
        if details:
            check["details"] = details
        if failed_examples:
            check["failed_examples"] = failed_examples[:20]
        checks[name] = check
        if status == "fail":
            failures.append(
                {
                    "check": name,
                    "failed_count": failed_count,
                    "failed_examples": (failed_examples or [])[:20],
                }
            )

    add_check(
        "queue_row_count",
        EXPECTED_QUEUE_ROWS,
        min(len(rows), EXPECTED_QUEUE_ROWS) if len(rows) == EXPECTED_QUEUE_ROWS else 0,
        expected_count=EXPECTED_QUEUE_ROWS,
        details={"actual_count": len(rows)},
        failed_examples=[] if len(rows) == EXPECTED_QUEUE_ROWS else [len(rows)],
    )

    model_counts = Counter(str(row.get("model")) for row in rows)
    model_passed = sum(
        model_counts.get(model, 0) == EXPECTED_PER_MODEL for model in EXPECTED_MODELS
    )
    model_exact = set(model_counts) == set(EXPECTED_MODELS)
    add_check(
        "model_distribution",
        len(EXPECTED_MODELS),
        model_passed if model_exact else 0,
        expected_count=len(EXPECTED_MODELS),
        details={
            "expected_each": EXPECTED_PER_MODEL,
            "observed": counter_json(model_counts),
        },
        failed_examples=(
            []
            if model_passed == len(EXPECTED_MODELS) and model_exact
            else [counter_json(model_counts)]
        ),
    )

    stage_counts = Counter(str(row.get("stage")) for row in rows)
    stage_passed = sum(
        stage_counts.get(stage, 0) == EXPECTED_PER_STAGE for stage in EXPECTED_STAGES
    )
    stage_exact = set(stage_counts) == set(EXPECTED_STAGES)
    add_check(
        "stage_distribution",
        len(EXPECTED_STAGES),
        stage_passed if stage_exact else 0,
        expected_count=len(EXPECTED_STAGES),
        details={
            "expected_each": EXPECTED_PER_STAGE,
            "observed": counter_json(stage_counts),
        },
        failed_examples=(
            []
            if stage_passed == len(EXPECTED_STAGES) and stage_exact
            else [counter_json(stage_counts)]
        ),
    )

    model_stage_counts = Counter(
        (str(row.get("model")), str(row.get("stage"))) for row in rows
    )
    expected_model_stages = {
        (model, stage) for model in EXPECTED_MODELS for stage in EXPECTED_STAGES
    }
    model_stage_passed = sum(
        model_stage_counts.get(key, 0) == EXPECTED_PER_MODEL_STAGE
        for key in expected_model_stages
    )
    model_stage_exact = set(model_stage_counts) == expected_model_stages
    add_check(
        "model_stage_distribution",
        len(expected_model_stages),
        model_stage_passed if model_stage_exact else 0,
        expected_count=len(expected_model_stages),
        details={
            "expected_each": EXPECTED_PER_MODEL_STAGE,
            "observed": counter_json(model_stage_counts),
        },
        failed_examples=(
            []
            if model_stage_passed == len(expected_model_stages) and model_stage_exact
            else [counter_json(model_stage_counts)]
        ),
    )

    manifest_ok = (
        manifest.get("queue_sha256") == queue_sha256
        and manifest.get("eligible_count") == EXPECTED_QUEUE_ROWS
        and manifest.get("stage_counts") == {
            stage: EXPECTED_PER_STAGE for stage in EXPECTED_STAGES
        }
        and set(manifest.get("models") or []) == set(EXPECTED_MODELS)
        and same_path(Path(str(manifest["queue"])), queue_path)
        and same_path(Path(str(manifest["score_root"])), score_root)
        and cases_path.is_file()
        and validation_path.is_file()
    )
    add_check(
        "queue_manifest_integrity",
        1,
        int(manifest_ok),
        expected_count=1,
        details={
            "manifest_queue_sha256": manifest.get("queue_sha256"),
            "actual_queue_sha256": queue_sha256,
            "eligible_count": manifest.get("eligible_count"),
        },
        failed_examples=[] if manifest_ok else ["manifest/path/count/hash mismatch"],
    )

    schema_failed: list[str] = []
    contract_failed: list[str] = []
    queue_id_failed: list[str] = []
    triple_counter: Counter[tuple[str, str, str]] = Counter()
    queue_id_counter: Counter[str] = Counter()
    for index, row in enumerate(rows, 1):
        label = str(row.get("queue_id") or f"row:{index}")
        if (
            row.get("schema_version") != scoring.SCHEMA_VERSION
            or not REQUIRED_ROW_FIELDS.issubset(row)
        ):
            schema_failed.append(label)
        triple_counter[
            (
                str(row.get("model")),
                str(row.get("stage")),
                str(row.get("instance_id")),
            )
        ] += 1
        queue_id_counter[str(row.get("queue_id"))] += 1
        if all(key in row for key in scoring.CONTRACT_KEYS):
            body = {key: row[key] for key in scoring.CONTRACT_KEYS}
            expected_contract_hash = scoring.canonical_hash(body)
        else:
            expected_contract_hash = ""
        if row.get("contract_sha256") != expected_contract_hash:
            contract_failed.append(label)
        expected_queue_id = (
            f"{row.get('model')}/{row.get('stage')}/{row.get('instance_id')}/"
            f"{expected_contract_hash[:16]}"
        )
        if row.get("queue_id") != expected_queue_id:
            queue_id_failed.append(label)

    add_check(
        "row_schema",
        len(rows),
        len(rows) - len(schema_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        details={"schema_version": scoring.SCHEMA_VERSION},
        failed_examples=schema_failed,
    )
    add_check(
        "canonical_contract_sha256",
        len(rows),
        len(rows) - len(contract_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        failed_examples=contract_failed,
    )
    add_check(
        "queue_id_contract_binding",
        len(rows),
        len(rows) - len(queue_id_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        failed_examples=queue_id_failed,
    )

    duplicate_triples = [
        "/".join(key) for key, count in triple_counter.items() if count != 1
    ]
    add_check(
        "instance_model_stage_uniqueness",
        len(rows),
        len(rows) if not duplicate_triples and len(triple_counter) == len(rows) else 0,
        expected_count=EXPECTED_QUEUE_ROWS,
        details={"unique_count": len(triple_counter)},
        failed_examples=duplicate_triples,
    )
    duplicate_queue_ids = [
        key for key, count in queue_id_counter.items() if count != 1
    ]
    add_check(
        "queue_id_uniqueness",
        len(rows),
        len(rows) if not duplicate_queue_ids and len(queue_id_counter) == len(rows) else 0,
        expected_count=EXPECTED_QUEUE_ROWS,
        details={"unique_count": len(queue_id_counter)},
        failed_examples=duplicate_queue_ids,
    )

    run_path_failed: list[str] = []
    run_hash_failed: list[str] = []
    run_identity_failed: list[str] = []
    gold_path_failed: list[str] = []
    gold_hash_failed: list[str] = []
    validation_hash_failed: list[str] = []
    candidate_output_failed: list[str] = []
    gold_contract_cache: dict[tuple[str, str], dict[str, Any]] = {}
    gold_items_checked = 0
    gold_items_matched = 0
    gold_item_failed: list[str] = []
    order_pairs_checked = 0
    order_pairs_matched = 0
    order_pair_failed: list[str] = []
    adjacent_checked = 0
    adjacent_passed = 0
    adjacent_failed: list[str] = []
    candidate_slots_checked = 0
    candidate_slots_matched = 0
    candidate_slot_failed: list[str] = []
    maxima_failed: list[str] = []
    fixed_candidate_policy_failed: list[str] = []
    critical_policy_failed: list[str] = []
    pid_gold_contract_failed: list[str] = []
    pid_review_policy_failed: list[str] = []
    hidden_alert_policy_failed: list[str] = []
    candidate_kind_counter: Counter[str] = Counter()
    candidate_kind_failures: list[str] = []
    policy_kind_failed: list[str] = []

    for row in rows:
        label = str(row.get("queue_id"))
        model = str(row.get("model"))
        stage = str(row.get("stage"))
        instance_id = str(row.get("instance_id"))
        expected_run_path = (
            result_root / "runs" / model / stage / f"{instance_id}_run.json"
        )
        stored_run_path = Path(str(row.get("run_json")))
        if (
            not stored_run_path.is_file()
            or not expected_run_path.is_file()
            or not same_path(stored_run_path, expected_run_path)
        ):
            run_path_failed.append(label)
            run_payload: dict[str, Any] = {}
            run_output: dict[str, Any] | None = None
        else:
            run_payload = scoring.read_json(stored_run_path)
            try:
                parsed_output = json.loads(str(run_payload.get("output_text") or ""))
                run_output = parsed_output if isinstance(parsed_output, dict) else None
            except json.JSONDecodeError:
                run_output = None
        if (
            not stored_run_path.is_file()
            or sha256_file(stored_run_path) != row.get("run_sha256")
        ):
            run_hash_failed.append(label)
        if (
            run_payload.get("model") != model
            or run_payload.get("experiment_stage") != stage
            or run_payload.get("instance_id") != instance_id
        ):
            run_identity_failed.append(label)
        if run_output != row.get("candidate_output"):
            candidate_output_failed.append(label)

        case = cases.get(instance_id)
        if case is None:
            gold_path_failed.append(label)
            gold_hash_failed.append(label)
            maxima_failed.append(label)
            gold_item_failed.append(label)
            order_pair_failed.append(label)
            adjacent_failed.append(label)
            pid_gold_contract_failed.append(label)
            continue
        expected_gold_path = scoring.resolve_gold(case)
        stored_gold_path = Path(str(row.get("gold_json")))
        if (
            not stored_gold_path.is_file()
            or not same_path(stored_gold_path, expected_gold_path)
        ):
            gold_path_failed.append(label)
        if (
            not stored_gold_path.is_file()
            or sha256_file(stored_gold_path) != row.get("gold_sha256")
        ):
            gold_hash_failed.append(label)
        if row.get("validation_steps_sha256") != sha256_file(validation_path):
            validation_hash_failed.append(label)

        cache_key = (str(expected_gold_path), stage)
        if cache_key not in gold_contract_cache:
            gold_contract_cache[cache_key] = scoring.gold_contract(
                expected_gold_path, stage, validation_path
            )
        expected_gold_contract = gold_contract_cache[cache_key]
        if row.get("maxima") != expected_gold_contract["maxima"]:
            maxima_failed.append(label)

        queued_gold_items = row.get("gold_items") or []
        expected_gold_items = expected_gold_contract["gold_items"]
        matched, failed_ids = item_match_count(
            queued_gold_items, expected_gold_items, "item_id"
        )
        gold_items_checked += len(set(
            [str(item.get("item_id") or "") for item in queued_gold_items]
            + [str(item.get("item_id") or "") for item in expected_gold_items]
        ))
        gold_items_matched += matched
        gold_item_failed.extend(f"{label}:{identity}" for identity in failed_ids)

        queued_pairs = row.get("order_pairs") or []
        expected_pairs = expected_gold_contract["order_pairs"]
        matched, failed_ids = item_match_count(queued_pairs, expected_pairs, "pair_id")
        order_pairs_checked += len(set(
            [str(pair.get("pair_id") or "") for pair in queued_pairs]
            + [str(pair.get("pair_id") or "") for pair in expected_pairs]
        ))
        order_pairs_matched += matched
        order_pair_failed.extend(f"{label}:{identity}" for identity in failed_ids)

        raw_gold = scoring.read_json(expected_gold_path)
        step_ids = [
            str(step.get("step_id") or "") for step in raw_gold.get("gold_steps") or []
        ]
        adjacent_ids = {
            f"{raw_gold.get('chain_id')}:{before}->{after}"
            for before, after in zip(step_ids, step_ids[1:])
        }
        for pair in queued_pairs:
            adjacent_checked += 1
            if pair.get("pair_id") in adjacent_ids:
                adjacent_passed += 1
            else:
                adjacent_failed.append(f"{label}:{pair.get('pair_id')}")

        expected_slots = scoring.candidate_slots(run_output or {})
        queued_slots = row.get("candidate_slots") or []
        matched, failed_ids = item_match_count(queued_slots, expected_slots, "slot_id")
        candidate_slots_checked += len(set(
            [str(slot.get("slot_id") or "") for slot in queued_slots]
            + [str(slot.get("slot_id") or "") for slot in expected_slots]
        ))
        candidate_slots_matched += matched
        candidate_slot_failed.extend(f"{label}:{identity}" for identity in failed_ids)

        policy = row.get("review_policy") or {}
        if not (
            policy.get("candidate_slots_are_fixed") is True
            and policy.get("candidate_denominator_is_fixed") is True
        ):
            fixed_candidate_policy_failed.append(label)
        if not (
            policy.get("action_denominator_excludes_critical_evidence") is True
            and policy.get("critical_evidence_is_separate_gold_diagnostic") is True
            and row["maxima"].get("gold_required_item_count")
            == len(queued_gold_items)
            and row["maxima"].get("gold_action_required_item_count")
            == sum(
                item.get("kind") in {"subject", "operation", "action", "object"}
                for item in queued_gold_items
            )
            and (
                row["maxima"].get("gold_required_item_count")
                - row["maxima"].get("gold_action_required_item_count")
                == sum(
                    item.get("kind") == "critical_evidence"
                    for item in queued_gold_items
                )
            )
        ):
            critical_policy_failed.append(label)

        noncritical_gold_text = canonical_json(
            [
                {
                    "gold_value": item.get("gold_value"),
                    "acceptable_terms": item.get("acceptable_terms"),
                }
                for item in queued_gold_items
                if item.get("kind") != "critical_evidence"
            ]
        )
        gold_payload = scoring.read_json(expected_gold_path)
        case_contract = case.get("paired_stage_contract") or {}
        gold_contract = gold_payload.get("paired_stage_contract") or {}
        if not (
            case_contract.get("pid_identity_scored") is False
            and gold_contract.get("pid_identity_scored") is False
            and PID_TOKEN.search(noncritical_gold_text) is None
        ):
            pid_gold_contract_failed.append(label)
        match_semantics = str(policy.get("match_semantics") or "")
        if not (
            policy.get("pid_identity_scored") is False
            and "If Gold specifies a PID" not in match_semantics
        ):
            pid_review_policy_failed.append(label)
        excluded_text = canonical_json(policy.get("excluded_from_scoring") or [])
        if not (
            policy.get("alert_mapping_scored") is False
            and case_contract.get("alert_mapping_scored") is False
            and gold_contract.get("alert_mapping_scored") is False
            and all(
                token in excluded_text
                for token in ("hidden alert id", "alert title", "alert reason")
            )
        ):
            hidden_alert_policy_failed.append(label)

        policy_kinds = policy.get("candidate_slot_kinds")
        if policy_kinds != ["subject", "action", "object"]:
            policy_kind_failed.append(label)
        for slot in queued_slots:
            kind = str(slot.get("kind"))
            candidate_kind_counter[kind] += 1
            if kind not in REQUIRED_CANDIDATE_KINDS:
                candidate_kind_failures.append(f"{label}:{slot.get('slot_id')}:{kind}")

    for name, failed_rows in (
        ("run_path_binding", run_path_failed),
        ("run_sha256_binding", run_hash_failed),
        ("run_identity_binding", run_identity_failed),
        ("gold_path_binding", gold_path_failed),
        ("gold_sha256_binding", gold_hash_failed),
        ("validation_steps_sha256_binding", validation_hash_failed),
        ("candidate_output_run_binding", candidate_output_failed),
        ("gold_maxima_recomputed", maxima_failed),
    ):
        add_check(
            name,
            len(rows),
            len(rows) - len(failed_rows),
            expected_count=EXPECTED_QUEUE_ROWS,
            failed_examples=failed_rows,
        )

    add_check(
        "all_gold_items_recomputed",
        gold_items_checked,
        gold_items_matched,
        expected_count=1032,
        details={"queued_total": sum(len(row.get("gold_items") or []) for row in rows)},
        failed_examples=gold_item_failed,
    )
    add_check(
        "all_order_pairs_recomputed",
        order_pairs_checked,
        order_pairs_matched,
        expected_count=210,
        details={"queued_total": sum(len(row.get("order_pairs") or []) for row in rows)},
        failed_examples=order_pair_failed,
    )
    add_check(
        "all_order_pairs_are_adjacent",
        adjacent_checked,
        adjacent_passed,
        expected_count=210,
        failed_examples=adjacent_failed,
    )
    add_check(
        "all_candidate_slots_recomputed",
        candidate_slots_checked,
        candidate_slots_matched,
        expected_count=414,
        details={
            "queued_total": sum(len(row.get("candidate_slots") or []) for row in rows)
        },
        failed_examples=candidate_slot_failed,
    )
    add_check(
        "candidate_denominator_fixed",
        len(rows),
        len(rows) - len(fixed_candidate_policy_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        details={
            "candidate_slot_denominator_overall": sum(
                len(row.get("candidate_slots") or []) for row in rows
            ),
            "candidate_slot_denominator_by_stage": {
                stage: sum(
                    len(row.get("candidate_slots") or [])
                    for row in rows
                    if row.get("stage") == stage
                )
                for stage in EXPECTED_STAGES
            },
        },
        failed_examples=fixed_candidate_policy_failed,
    )
    add_check(
        "critical_evidence_separate_denominator",
        len(rows),
        len(rows) - len(critical_policy_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        details={
            "action_component_denominator_overall": sum(
                row["maxima"]["gold_action_required_item_count"] for row in rows
            ),
            "critical_evidence_denominator_overall": sum(
                row["maxima"]["gold_required_item_count"]
                - row["maxima"]["gold_action_required_item_count"]
                for row in rows
            ),
            "order_pair_denominator_overall": sum(
                row["maxima"]["gold_order_pair_count"] for row in rows
            ),
            "per_model_stage_expected": {
                "action_components": 129,
                "critical_evidence": 43,
                "order_pairs": 35,
            },
            "per_stage_two_models_expected": {
                "action_components": 258,
                "critical_evidence": 86,
                "order_pairs": 70,
            },
        },
        failed_examples=critical_policy_failed,
    )
    add_check(
        "pid_identity_not_scored_in_gold_contract",
        len(rows),
        len(rows) - len(pid_gold_contract_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        failed_examples=pid_gold_contract_failed,
    )
    add_check(
        "pid_identity_not_scored_in_queue_review_policy",
        len(rows),
        len(rows) - len(pid_review_policy_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        details={
            "required": (
                "review_policy.pid_identity_scored=false and no PID-dependent "
                "matching instruction"
            )
        },
        failed_examples=pid_review_policy_failed,
    )
    add_check(
        "hidden_alert_mapping_not_scored",
        len(rows),
        len(rows) - len(hidden_alert_policy_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        failed_examples=hidden_alert_policy_failed,
    )
    add_check(
        "candidate_slot_kind_allowlist_subject_action_object",
        sum(candidate_kind_counter.values()),
        sum(
            count
            for kind, count in candidate_kind_counter.items()
            if kind in REQUIRED_CANDIDATE_KINDS
        ),
        expected_count=414,
        details={
            "required_kinds": sorted(REQUIRED_CANDIDATE_KINDS),
            "observed_counts": counter_json(candidate_kind_counter),
        },
        failed_examples=candidate_kind_failures,
    )
    add_check(
        "candidate_slot_kind_policy_subject_action_object",
        len(rows),
        len(rows) - len(policy_kind_failed),
        expected_count=EXPECTED_QUEUE_ROWS,
        details={"required_policy": ["subject", "action", "object"]},
        failed_examples=policy_kind_failed,
    )

    important_issues: list[dict[str, Any]] = []
    if pid_review_policy_failed:
        important_issues.append(
            {
                "severity": "critical",
                "issue": "PID non-scoring is not bound in the queue review policy",
                "affected_queue_rows": len(pid_review_policy_failed),
                "evidence": (
                    "review_policy.pid_identity_scored is absent, and every row's "
                    "match_semantics says a name-only candidate does not match when "
                    "Gold specifies a PID. Source case/Gold contracts do set "
                    "pid_identity_scored=false and non-critical Gold items contain "
                    "no PID tokens."
                ),
            }
        )
    if candidate_kind_failures or policy_kind_failed:
        important_issues.append(
            {
                "severity": "critical",
                "issue": (
                    "Candidate slot vocabulary is operation rather than the required "
                    "action"
                ),
                "affected_candidate_slots": len(candidate_kind_failures),
                "affected_queue_policies": len(policy_kind_failed),
                "observed_counts": counter_json(candidate_kind_counter),
                "required_kinds": sorted(REQUIRED_CANDIDATE_KINDS),
            }
        )

    report = {
        "schema_version": "queue_provenance_audit_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pass" if not failures else "fail",
        "audit_scope": {
            "score_root": str(score_root),
            "queue": str(queue_path),
            "queue_manifest": str(manifest_path),
            "cases": str(cases_path),
            "validation_steps": str(validation_path),
            "review_decision_files_read": False,
            "review_template_read": False,
            "external_api_calls": False,
            "read_only_inputs": True,
            "output_created_without_overwrite": True,
        },
        "queue_sha256": queue_sha256,
        "queue_row_count": len(rows),
        "checks": checks,
        "check_count": len(checks),
        "passed_check_count": sum(
            check["status"] == "pass" for check in checks.values()
        ),
        "failed_check_count": sum(
            check["status"] == "fail" for check in checks.values()
        ),
        "failure_count": len(failures),
        "failures": failures,
        "important_issues": important_issues,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "status": report["status"],
        "output": str(output_path),
        "queue_sha256": queue_sha256,
        "passed_check_count": report["passed_check_count"],
        "failed_check_count": report["failed_check_count"],
        "important_issue_count": len(important_issues),
    }, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
