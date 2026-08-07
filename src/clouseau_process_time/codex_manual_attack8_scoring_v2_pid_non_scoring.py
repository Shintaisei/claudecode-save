#!/usr/bin/env python3
"""Overlay-bound PID-non-scoring extension for manual attack8 scoring.

This versioned wrapper leaves ``codex_manual_attack8_scoring.py`` unchanged.
It binds an authoritative review-policy overlay into every queue contract,
validates the resulting queue bundle and replacement reviews, and finalizes
only reviews carrying the same overlay SHA-256.

No command in this module calls a model API.  Every output is create-only.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from . import codex_manual_attack8_scoring as base
except ImportError:  # Direct script execution.
    import codex_manual_attack8_scoring as base


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "codex_manual_action_claim_review_v2_pid_non_scoring_overlay_v1"
BINDING_SCHEMA_VERSION = "formal_review_policy_overlay_binding_v2"
MANIFEST_SCHEMA_VERSION = "codex_manual_queue_manifest_v2_pid_non_scoring_overlay_v1"
STRICT_PID_TEXT = (
    "If Gold specifies a PID, a name-only candidate does not match; "
    "evidence or another slot cannot backfill it."
)
CONTRACT_KEYS = (
    *base.CONTRACT_KEYS,
    "review_policy_overlay_path",
    "review_policy_overlay_sha256",
    "effective_review_policy_sha256",
)
FROZEN_KEYS = tuple(key for key in base.CONTRACT_KEYS if key != "schema_version")
EXPECTED_SLOT_KINDS = frozenset({"subject", "operation", "object"})


def repo_relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise ValueError(f"Policy overlay must be inside repository root: {path}") from exc


def validate_overlay(path: Path) -> tuple[dict[str, Any], str, str]:
    resolved = path.resolve()
    overlay = base.read_json(resolved)
    if not isinstance(overlay, dict):
        raise ValueError("Policy overlay is not a JSON object")
    errors: list[str] = []
    if overlay.get("schema_version") != "formal_review_policy_overlay_v1":
        errors.append("unexpected overlay schema_version")
    pid = overlay.get("pid_resolution")
    if not isinstance(pid, dict) or pid.get("pid_identity_scored") is not False:
        errors.append("overlay does not set pid_identity_scored=false")
    if not isinstance(pid, dict) or pid.get("superseded_queue_text") != STRICT_PID_TEXT:
        errors.append("overlay does not identify the queue-local strict PID sentence")
    terminology = overlay.get("terminology_resolution")
    aliases = terminology.get("semantic_aliases") if isinstance(terminology, dict) else None
    if not isinstance(aliases, dict) or aliases.get("action") != "operation":
        errors.append("overlay does not bind action=operation")
    if errors:
        raise ValueError(f"Invalid formal review policy overlay: {errors}")
    return overlay, repo_relative(resolved), base.sha256_file(resolved)


def effective_review_policy(
    overlay_path: str,
    overlay_sha256: str,
) -> dict[str, Any]:
    return {
        "binding_schema_version": BINDING_SCHEMA_VERSION,
        "authoritative_overlay_path": overlay_path,
        "authoritative_overlay_sha256": overlay_sha256,
        "authority": "overlay_supersedes_queue_local_default_matching_prose",
        "canonical_slot_kinds": ["subject", "operation", "object"],
        "semantic_aliases": {"action": "operation"},
        "action_denominator_excludes_critical_evidence": True,
        "candidate_slots_are_fixed": True,
        "candidate_denominator_is_fixed": True,
        "command_line_is_action_attribute": True,
        "critical_evidence_is_separate_gold_diagnostic": True,
        "pid_identity_scored": False,
        "pid_rule": (
            "PID tokens and PID equality are non-scoring provenance. A missing, "
            "different, or absent PID must not by itself turn an otherwise "
            "semantically matching item, claim alignment, or order pair into a miss."
        ),
        "semantic_edge_rule": (
            "When process names and the observed semantic parent-child, actor, "
            "operation, and object edge agree, PID difference or name-only process "
            "description is not a mismatch. A genuinely different process or "
            "different observed parent-child/actor/object edge meaning may be "
            "marked as a semantic mismatch."
        ),
        "critical_evidence_pid_rule": (
            "Score substantive observable process, operation, target/path/endpoint, "
            "timing, and causal support. Exact PID identity is not an additional "
            "critical-evidence requirement."
        ),
        "alert_mapping_scored": False,
        "hidden_alert_mapping_rule": (
            "Do not score inference of a hidden alert id, title, reason, or "
            "alert-to-Gold mapping."
        ),
        "superseded_queue_text": STRICT_PID_TEXT,
        "superseded_queue_text_status": "explicitly_superseded_and_not_effective",
        "match_semantics": (
            "Judge semantic equivalence from observed claims only; do not infer "
            "missing subject, operation, object, evidence, or causal edges. Align "
            "each candidate claim to at most one Gold step using process names, "
            "operation family, target/path/endpoint, observed semantic edge, and "
            "order. Every TP slot in one candidate claim must reference the same "
            "aligned Gold step. PID identity and PID equality are not scoring axes."
        ),
        "order_semantics": (
            "An order pair is correct only when two distinct candidate claims align "
            "to its two Gold steps and appear in that order; PID identity is not an "
            "additional ordering condition."
        ),
    }


def contract_body(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in CONTRACT_KEYS}


def validate_queue_rows(
    rows: list[dict[str, Any]],
    *,
    overlay_path: str,
    overlay_sha256: str,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    expected_policy = effective_review_policy(overlay_path, overlay_sha256)
    expected_policy_sha256 = base.canonical_hash(expected_policy)
    for index, row in enumerate(rows, 1):
        missing = [
            key
            for key in (*CONTRACT_KEYS, "queue_id", "contract_sha256", "review_policy")
            if key not in row
        ]
        if missing:
            raise ValueError(f"Queue row {index} is missing fields: {missing}")
        if row["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"Queue schema mismatch at row {index}")
        if row["review_policy_overlay_path"] != overlay_path:
            raise ValueError(f"Overlay path mismatch at row {index}")
        if row["review_policy_overlay_sha256"] != overlay_sha256:
            raise ValueError(f"Overlay SHA-256 mismatch at row {index}")
        if row["effective_review_policy_sha256"] != expected_policy_sha256:
            raise ValueError(f"Effective policy SHA-256 mismatch at row {index}")
        if row["review_policy"] != expected_policy:
            raise ValueError(f"Effective review policy mismatch at row {index}")
        if STRICT_PID_TEXT in str(row["review_policy"].get("match_semantics") or ""):
            raise ValueError(f"Strict PID text remains effective at row {index}")
        if row["review_policy"].get("pid_identity_scored") is not False:
            raise ValueError(f"PID is not explicitly non-scoring at row {index}")
        if row["review_policy"].get("semantic_aliases") != {"action": "operation"}:
            raise ValueError(f"Action/operation alias mismatch at row {index}")
        contract = contract_body(row)
        expected_hash = base.canonical_hash(contract)
        if row["contract_sha256"] != expected_hash:
            raise ValueError(f"Queue contract hash mismatch at row {index}")
        expected_id = (
            f"{row['model']}/{row['stage']}/{row['instance_id']}/"
            f"{expected_hash[:16]}"
        )
        if row["queue_id"] != expected_id:
            raise ValueError(f"Queue ID mismatch at row {index}")
        if row.get("candidate_output") is not None:
            if base.candidate_slots(row["candidate_output"]) != row["candidate_slots"]:
                raise ValueError(f"Candidate slot extraction mismatch at row {index}")
        gold_item_ids = [item["item_id"] for item in row["gold_items"]]
        if len(gold_item_ids) != len(set(gold_item_ids)):
            raise ValueError(f"Duplicate Gold item ID at row {index}")
        if len(gold_item_ids) != row["maxima"]["gold_required_item_count"]:
            raise ValueError(f"Gold item denominator mismatch at row {index}")
        order_pair_ids = [pair["pair_id"] for pair in row["order_pairs"]]
        if len(order_pair_ids) != len(set(order_pair_ids)):
            raise ValueError(f"Duplicate order-pair ID at row {index}")
        if len(order_pair_ids) != row["maxima"]["gold_order_pair_count"]:
            raise ValueError(f"Order-pair denominator mismatch at row {index}")
        slot_ids = [slot["slot_id"] for slot in row["candidate_slots"]]
        if len(slot_ids) != len(set(slot_ids)):
            raise ValueError(f"Duplicate candidate-slot ID at row {index}")
        slot_kinds = {slot["kind"] for slot in row["candidate_slots"]}
        if not slot_kinds <= EXPECTED_SLOT_KINDS:
            raise ValueError(f"Non-canonical candidate slot kind at row {index}")
        if row["queue_id"] in result:
            raise ValueError(f"Duplicate queue ID: {row['queue_id']}")
        result[row["queue_id"]] = row
    return result


def review_template(row: dict[str, Any]) -> dict[str, Any]:
    template = base.review_template(row)
    template["schema_version"] = SCHEMA_VERSION
    template["review_policy_overlay_path"] = row["review_policy_overlay_path"]
    template["review_policy_overlay_sha256"] = row["review_policy_overlay_sha256"]
    template["review_policy_acknowledgement"] = {
        "pid_identity_scored": False,
        "action_aliases_operation": True,
        "strict_pid_sentence_effective": False,
    }
    return template


def bind_overlay(args: argparse.Namespace) -> None:
    source_queue_path = args.source_queue.resolve()
    source_manifest_path = args.source_manifest.resolve()
    score_root = args.score_root.resolve()
    source_rows = base.read_jsonl(source_queue_path)
    base.validate_queue_rows(source_rows)
    source_manifest = base.read_json(source_manifest_path)
    if source_manifest.get("queue_sha256") != base.sha256_file(source_queue_path):
        raise ValueError("Source manifest queue SHA-256 does not match source queue")
    if source_manifest.get("eligible_count") != len(source_rows):
        raise ValueError("Source manifest eligible_count does not match source queue")
    if len(source_rows) != args.expected_count:
        raise ValueError(
            f"Source queue has {len(source_rows)} rows, expected {args.expected_count}"
        )

    _, overlay_path, overlay_sha256 = validate_overlay(args.overlay)
    policy = effective_review_policy(overlay_path, overlay_sha256)
    policy_sha256 = base.canonical_hash(policy)
    source_queue_sha256 = base.sha256_file(source_queue_path)
    bound_rows: list[dict[str, Any]] = []
    for source in source_rows:
        contract = {
            **{key: source[key] for key in base.CONTRACT_KEYS},
            "schema_version": SCHEMA_VERSION,
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "effective_review_policy_sha256": policy_sha256,
        }
        contract_sha256 = base.canonical_hash(contract)
        bound_rows.append(
            {
                **source,
                **contract,
                "queue_id": (
                    f"{source['model']}/{source['stage']}/{source['instance_id']}/"
                    f"{contract_sha256[:16]}"
                ),
                "contract_sha256": contract_sha256,
                "source_queue_id": source["queue_id"],
                "source_contract_sha256": source["contract_sha256"],
                "source_queue_sha256": source_queue_sha256,
                "review_policy": policy,
            }
        )

    queue_path = score_root / args.queue_name
    template_path = score_root / args.template_name
    manifest_path = score_root / args.manifest_name
    base.write_jsonl_new(queue_path, bound_rows)
    base.write_jsonl_new(template_path, (review_template(row) for row in bound_rows))
    queue_sha256 = base.sha256_file(queue_path)
    template_sha256 = base.sha256_file(template_path)
    maxima = denominator_summary(bound_rows)
    base.write_json_new(
        manifest_path,
        {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "created_at_utc": base.utc_now(),
            "score_root": str(score_root),
            "source_prepare_manifest": str(source_manifest_path),
            "source_prepare_manifest_sha256": base.sha256_file(source_manifest_path),
            "source_queue": str(source_queue_path),
            "source_queue_sha256": source_queue_sha256,
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "effective_review_policy_sha256": policy_sha256,
            "queue": str(queue_path),
            "queue_sha256": queue_sha256,
            "review_template": str(template_path),
            "review_template_sha256": template_sha256,
            "eligible_count": len(bound_rows),
            "models": sorted({row["model"] for row in bound_rows}),
            "stage_counts": dict(Counter(row["stage"] for row in bound_rows)),
            "denominators": maxima,
            "canonical_slot_kinds": ["subject", "operation", "object"],
            "semantic_aliases": {"action": "operation"},
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "strict_pid_sentence_effective": False,
            "source_artifacts_modified": False,
            "external_api_calls": False,
            "non_overwrite_policy": True,
        },
    )
    verify_bundle_paths(
        queue_path,
        manifest_path,
        args.overlay.resolve(),
        expected_count=args.expected_count,
    )
    print(
        f"Bound {len(bound_rows)} queue rows to overlay {overlay_sha256}; "
        f"queue={queue_path}"
    )


def denominator_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_model_stage: dict[str, dict[str, int]] = {}
    overall = Counter()
    for row in rows:
        maxima = row["maxima"]
        values = {
            "case_count": 1,
            "gold_action_required_item_count": int(
                maxima["gold_action_required_item_count"]
            ),
            "critical_evidence_count": int(
                maxima["gold_required_item_count"]
                - maxima["gold_action_required_item_count"]
            ),
            "gold_order_pair_count": int(maxima["gold_order_pair_count"]),
            "candidate_slot_count": len(row["candidate_slots"]),
        }
        key = f"{row['model']}/{row['stage']}"
        target = by_model_stage.setdefault(key, dict.fromkeys(values, 0))
        for name, value in values.items():
            target[name] += value
            overall[name] += value
    return {"by_model_stage": by_model_stage, "overall": dict(overall)}


def verify_bundle_paths(
    queue_path: Path,
    manifest_path: Path,
    overlay_file: Path,
    *,
    expected_count: int,
) -> dict[str, Any]:
    _, overlay_path, overlay_sha256 = validate_overlay(overlay_file)
    rows = base.read_jsonl(queue_path)
    queue = validate_queue_rows(
        rows,
        overlay_path=overlay_path,
        overlay_sha256=overlay_sha256,
    )
    manifest = base.read_json(manifest_path)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("Bound manifest schema mismatch")
    if manifest.get("eligible_count") != expected_count or len(queue) != expected_count:
        raise ValueError(
            f"Bound queue count mismatch: queue={len(queue)}, "
            f"manifest={manifest.get('eligible_count')}, expected={expected_count}"
        )
    if Path(str(manifest.get("queue"))).resolve() != queue_path.resolve():
        raise ValueError("Manifest queue path mismatch")
    if manifest.get("queue_sha256") != base.sha256_file(queue_path):
        raise ValueError("Manifest queue SHA-256 mismatch")
    if manifest.get("review_policy_overlay_path") != overlay_path:
        raise ValueError("Manifest overlay path mismatch")
    if manifest.get("review_policy_overlay_sha256") != overlay_sha256:
        raise ValueError("Manifest overlay SHA-256 mismatch")
    if manifest.get("effective_review_policy_sha256") != base.canonical_hash(
        effective_review_policy(overlay_path, overlay_sha256)
    ):
        raise ValueError("Manifest effective policy SHA-256 mismatch")
    if manifest.get("canonical_slot_kinds") != ["subject", "operation", "object"]:
        raise ValueError("Manifest canonical slot kinds mismatch")
    if manifest.get("semantic_aliases") != {"action": "operation"}:
        raise ValueError("Manifest action/operation alias mismatch")
    if manifest.get("pid_identity_scored") is not False:
        raise ValueError("Manifest does not make PID non-scoring")
    if manifest.get("hidden_alert_mapping_scored") is not False:
        raise ValueError("Manifest does not make hidden alert mapping non-scoring")
    if manifest.get("strict_pid_sentence_effective") is not False:
        raise ValueError("Manifest does not invalidate the old strict PID sentence")

    source_queue = Path(str(manifest.get("source_queue"))).resolve()
    source_rows = base.read_jsonl(source_queue)
    base.validate_queue_rows(source_rows)
    if manifest.get("source_queue_sha256") != base.sha256_file(source_queue):
        raise ValueError("Manifest source queue SHA-256 mismatch")
    if len(source_rows) != len(rows):
        raise ValueError("Source and bound queue row counts differ")
    source_manifest_path = Path(str(manifest.get("source_prepare_manifest"))).resolve()
    if manifest.get("source_prepare_manifest_sha256") != base.sha256_file(
        source_manifest_path
    ):
        raise ValueError("Source prepare manifest SHA-256 mismatch")
    source_manifest = base.read_json(source_manifest_path)
    if Path(str(source_manifest.get("queue"))).resolve() != source_queue:
        raise ValueError("Source prepare manifest queue path mismatch")
    if source_manifest.get("queue_sha256") != base.sha256_file(source_queue):
        raise ValueError("Source prepare manifest queue SHA-256 mismatch")
    validation_steps = Path(str(source_manifest.get("validation_steps"))).resolve()
    validation_steps_sha256 = base.sha256_file(validation_steps)
    for index, (source, bound) in enumerate(zip(source_rows, rows), 1):
        if (source["model"], source["stage"], source["instance_id"]) != (
            bound["model"],
            bound["stage"],
            bound["instance_id"],
        ):
            raise ValueError(f"Source/bound order or identity mismatch at row {index}")
        for key in FROZEN_KEYS:
            if source[key] != bound[key]:
                raise ValueError(f"Frozen field changed at row {index}: {key}")
        if bound.get("source_queue_id") != source["queue_id"]:
            raise ValueError(f"Source queue ID provenance mismatch at row {index}")
        if bound.get("source_contract_sha256") != source["contract_sha256"]:
            raise ValueError(f"Source contract provenance mismatch at row {index}")
        if bound.get("source_queue_sha256") != base.sha256_file(source_queue):
            raise ValueError(f"Source queue provenance mismatch at row {index}")
        run_path = Path(str(bound.get("run_json"))).resolve()
        gold_path = Path(str(bound.get("gold_json"))).resolve()
        if base.sha256_file(run_path) != bound["run_sha256"]:
            raise ValueError(f"Run file SHA-256 mismatch at row {index}")
        if base.sha256_file(gold_path) != bound["gold_sha256"]:
            raise ValueError(f"Gold file SHA-256 mismatch at row {index}")
        if validation_steps_sha256 != bound["validation_steps_sha256"]:
            raise ValueError(f"Validation-steps SHA-256 mismatch at row {index}")

    summary = denominator_summary(rows)
    if manifest.get("denominators") != summary:
        raise ValueError("Manifest denominator summary mismatch")
    expected_per_model_stage = {
        "case_count": 8,
        "gold_action_required_item_count": 129,
        "critical_evidence_count": 43,
        "gold_order_pair_count": 35,
    }
    if expected_count == 48:
        if set(summary["by_model_stage"]) != {
            f"{model}/{stage}"
            for model in ("gpt-4.1-mini", "gpt-5.4-mini")
            for stage in base.STAGES
        }:
            raise ValueError("Unexpected model/stage denominator groups")
        for key, values in summary["by_model_stage"].items():
            for name, expected in expected_per_model_stage.items():
                if values[name] != expected:
                    raise ValueError(
                        f"Formal denominator mismatch for {key}/{name}: "
                        f"{values[name]} != {expected}"
                    )

    gold_kind_counts = Counter(
        item["kind"] for row in rows for item in row["gold_items"]
    )
    candidate_kind_counts = Counter(
        slot["kind"] for row in rows for slot in row["candidate_slots"]
    )
    content_counts = {
        "gold_items": sum(len(row["gold_items"]) for row in rows),
        "order_pairs": sum(len(row["order_pairs"]) for row in rows),
        "candidate_slots": sum(len(row["candidate_slots"]) for row in rows),
        "gold_item_kinds": dict(gold_kind_counts),
        "candidate_slot_kinds": dict(candidate_kind_counts),
    }
    return {
        "status": "pass",
        "queue_row_count": len(rows),
        "queue_sha256": base.sha256_file(queue_path),
        "manifest_sha256": base.sha256_file(manifest_path),
        "overlay_path": overlay_path,
        "overlay_sha256": overlay_sha256,
        "effective_review_policy_sha256": manifest[
            "effective_review_policy_sha256"
        ],
        "source_queue_sha256": base.sha256_file(source_queue),
        "validation_steps_path": str(validation_steps),
        "validation_steps_sha256": validation_steps_sha256,
        "run_file_hashes_verified": len(rows),
        "gold_file_hashes_verified": len(rows),
        "denominators": summary,
        "content_counts": content_counts,
        "frozen_item_order_slot_content": "pass",
        "queue_order_preserved": "pass",
        "canonical_slot_kinds": ["subject", "operation", "object"],
        "action_aliases_operation": True,
        "pid_identity_scored": False,
        "hidden_alert_mapping_scored": False,
        "old_strict_pid_sentence_effective": False,
        "external_api_calls": False,
    }


def verify_queue(args: argparse.Namespace) -> None:
    report = verify_bundle_paths(
        args.queue.resolve(),
        args.manifest.resolve(),
        args.overlay.resolve(),
        expected_count=args.expected_count,
    )
    if args.report:
        base.write_json_new(args.report.resolve(), report)
    print(
        f"PASS: {report['queue_row_count']} overlay-bound rows; "
        f"queue_sha256={report['queue_sha256']}; "
        f"overlay_sha256={report['overlay_sha256']}"
    )


def validate_review_row(
    row: dict[str, Any],
    queue_row: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    for key in (
        "review_policy_overlay_path",
        "review_policy_overlay_sha256",
        "review_policy_acknowledgement",
    ):
        if key not in row:
            errors.append(f"{key} is missing")
    if row.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if row.get("review_policy_overlay_path") != queue_row[
        "review_policy_overlay_path"
    ]:
        errors.append("review policy overlay path mismatch")
    if row.get("review_policy_overlay_sha256") != queue_row[
        "review_policy_overlay_sha256"
    ]:
        errors.append("review policy overlay SHA-256 mismatch")
    acknowledgement = row.get("review_policy_acknowledgement")
    expected_acknowledgement = {
        "pid_identity_scored": False,
        "action_aliases_operation": True,
        "strict_pid_sentence_effective": False,
    }
    if acknowledgement != expected_acknowledgement:
        errors.append("review policy acknowledgement mismatch")

    adapted = dict(row)
    adapted["schema_version"] = base.SCHEMA_VERSION
    normalized, base_errors = base.validate_review_row(adapted, queue_row)
    errors.extend(base_errors)
    if normalized is None or errors:
        return None, errors
    normalized["schema_version"] = SCHEMA_VERSION
    normalized["review_policy_overlay_path"] = queue_row[
        "review_policy_overlay_path"
    ]
    normalized["review_policy_overlay_sha256"] = queue_row[
        "review_policy_overlay_sha256"
    ]
    normalized["review_policy_acknowledgement"] = expected_acknowledgement
    normalized["decision_sha256"] = base.canonical_hash(
        base.decision_fingerprint(normalized)
    )
    return normalized, []


def validated_review_map(
    path: Path,
    queue: dict[str, dict[str, Any]],
    *,
    allow_subset: bool,
) -> dict[str, dict[str, Any]]:
    rows = base.read_jsonl(path)
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        queue_id = str(row.get("queue_id") or "")
        if queue_id in result:
            raise ValueError(f"Duplicate queue_id in {path}: {queue_id}")
        queue_row = queue.get(queue_id)
        if queue_row is None:
            raise ValueError(f"Unknown queue_id in {path}: {queue_id}")
        normalized, errors = validate_review_row(row, queue_row)
        if normalized is None:
            raise ValueError(f"{path} is invalid for {queue_id}: {errors}")
        expected_hash = base.canonical_hash(base.decision_fingerprint(normalized))
        if row.get("decision_sha256") != expected_hash:
            raise ValueError(f"decision_sha256 mismatch in {path}: {queue_id}")
        result[queue_id] = normalized
    if not allow_subset and set(result) != set(queue):
        raise ValueError(f"{path} queue ID set does not match the full queue")
    return result


def validate_reviews(args: argparse.Namespace) -> None:
    verify_bundle_paths(
        args.queue.resolve(),
        args.manifest.resolve(),
        args.overlay.resolve(),
        expected_count=args.expected_count,
    )
    _, overlay_path, overlay_sha256 = validate_overlay(args.overlay)
    queue_rows = base.read_jsonl(args.queue)
    queue = validate_queue_rows(
        queue_rows,
        overlay_path=overlay_path,
        overlay_sha256=overlay_sha256,
    )
    input_rows = base.read_jsonl(args.reviewer_jsonl)
    by_id: dict[str, dict[str, Any]] = {}
    duplicate_ids: list[str] = []
    for row in input_rows:
        queue_id = str(row.get("queue_id") or "")
        if queue_id in by_id:
            duplicate_ids.append(queue_id)
        by_id[queue_id] = row
    reports: list[dict[str, Any]] = []
    valid_rows: list[dict[str, Any]] = []
    for queue_id, queue_row in queue.items():
        row = by_id.get(queue_id)
        if row is None:
            reports.append(
                {"queue_id": queue_id, "valid": False, "errors": ["missing row"]}
            )
            continue
        normalized, errors = validate_review_row(row, queue_row)
        reports.append({"queue_id": queue_id, "valid": not errors, "errors": errors})
        if normalized is not None:
            valid_rows.append(normalized)
    unknown = sorted(set(by_id) - set(queue))
    if duplicate_ids or unknown:
        reports.append(
            {
                "queue_id": None,
                "valid": False,
                "errors": [
                    *(f"duplicate row: {item}" for item in sorted(set(duplicate_ids))),
                    *(f"unknown queue_id: {item}" for item in unknown),
                ],
            }
        )
    all_valid = len(valid_rows) == len(queue) and all(row["valid"] for row in reports)
    output = (
        args.score_root
        / "validated_reviews_v2_pid_non_scoring"
        / f"{args.review_name}.jsonl"
    )
    report = (
        args.score_root
        / "validation_reports_v2_pid_non_scoring"
        / f"{args.review_name}.json"
    )
    if not all_valid:
        failed_report = base.next_versioned_path(
            args.score_root / "validation_reports_v2_pid_non_scoring",
            f"{args.review_name}_failed",
            ".json",
        )
        base.write_json_new(
            failed_report,
            {
                "review_name": args.review_name,
                "reviewer_jsonl": str(args.reviewer_jsonl),
                "valid": False,
                "valid_count": len(valid_rows),
                "expected_count": len(queue),
                "review_policy_overlay_path": overlay_path,
                "review_policy_overlay_sha256": overlay_sha256,
                "rows": reports,
            },
        )
        raise ValueError(f"Review validation failed; see {failed_report}")
    reviewer_ids = sorted({row["reviewer_id"] for row in valid_rows})
    if len(reviewer_ids) != 1:
        raise ValueError(
            f"One review file must have exactly one reviewer_id, got {reviewer_ids}"
        )
    base.write_jsonl_new(output, valid_rows)
    base.write_json_new(
        report,
        {
            "review_name": args.review_name,
            "reviewer_jsonl": str(args.reviewer_jsonl),
            "reviewer_id": reviewer_ids[0],
            "valid": True,
            "valid_count": len(valid_rows),
            "expected_count": len(queue),
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "validated_output": str(output),
            "validated_output_sha256": base.sha256_file(output),
            "rows": reports,
        },
    )
    print(f"Validated {len(valid_rows)} overlay-bound rows: {output}")


def finalize(args: argparse.Namespace) -> None:
    verify_bundle_paths(
        args.queue.resolve(),
        args.manifest.resolve(),
        args.overlay.resolve(),
        expected_count=args.expected_count,
    )
    _, overlay_path, overlay_sha256 = validate_overlay(args.overlay)
    queue_rows = base.read_jsonl(args.queue)
    queue = validate_queue_rows(
        queue_rows,
        overlay_path=overlay_path,
        overlay_sha256=overlay_sha256,
    )
    reviews = [
        validated_review_map(path, queue, allow_subset=False)
        for path in (args.review1, args.review2)
    ]
    third = (
        validated_review_map(args.review3, queue, allow_subset=True)
        if args.review3
        else {}
    )
    reviewer_ids = [{row["reviewer_id"] for row in review.values()} for review in reviews]
    if any(len(ids) != 1 for ids in reviewer_ids):
        raise ValueError("Each validated base review must have one reviewer_id")
    if next(iter(reviewer_ids[0])) == next(iter(reviewer_ids[1])):
        raise ValueError("review1 and review2 must have different reviewer_id values")

    comparisons: list[dict[str, Any]] = []
    adopted: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    adjudicated: list[dict[str, Any]] = []
    for queue_id, queue_row in queue.items():
        first, second = reviews[0][queue_id], reviews[1][queue_id]
        exact = (
            base.decision_fingerprint(first) == base.decision_fingerprint(second)
        )
        comparison = {
            "queue_id": queue_id,
            "model": queue_row["model"],
            "stage": queue_row["stage"],
            "instance_id": queue_row["instance_id"],
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "review1_reviewer_id": first["reviewer_id"],
            "review2_reviewer_id": second["reviewer_id"],
            "review1_decision_sha256": first["decision_sha256"],
            "review2_decision_sha256": second["decision_sha256"],
            "item_level_exact_match": exact,
            "adopted": False,
            "adoption_route": None,
        }
        selected: dict[str, Any] | None = first if exact else None
        conservative_count = 0
        if exact:
            comparison["adopted"] = True
            comparison["adoption_route"] = "exact_two_review_match"
        elif queue_id in third:
            third_row = third[queue_id]
            if third_row["reviewer_id"] in {
                first["reviewer_id"],
                second["reviewer_id"],
            }:
                raise ValueError(f"Third reviewer is not independent for {queue_id}")
            selected, conservative_count = base.adjudicate_reviews(
                first, second, third_row
            )
            selected["schema_version"] = SCHEMA_VERSION
            selected["review_policy_overlay_path"] = overlay_path
            selected["review_policy_overlay_sha256"] = overlay_sha256
            comparison["adopted"] = True
            comparison["adoption_route"] = "third_review_2_of_3"
            comparison["review3_reviewer_id"] = third_row["reviewer_id"]
            comparison["review3_decision_sha256"] = third_row["decision_sha256"]
            comparison["conservative_fallback_item_count"] = conservative_count
        if selected is None:
            conflicts.append(
                {
                    **comparison,
                    "reason": "item_level_mismatch_requires_independent_review3",
                }
            )
        else:
            decisions = base.decision_fingerprint(selected)
            adopted_row = {
                **comparison,
                "totals": base.totals_from_review(selected, queue_row),
                "adopted_decisions": decisions,
                "adopted_decision_sha256": base.canonical_hash(decisions),
                "contract_sha256": queue_row["contract_sha256"],
                "run_sha256": queue_row["run_sha256"],
                "gold_sha256": queue_row["gold_sha256"],
                "queue_contract": contract_body(queue_row),
            }
            adopted.append(adopted_row)
            if comparison["adoption_route"] == "third_review_2_of_3":
                adjudicated.append(adopted_row)
        comparisons.append(comparison)

    output_root = args.score_root / "formal_outputs_v2_pid_non_scoring"
    base.write_jsonl_new(output_root / "comparisons.jsonl", comparisons)
    base.write_jsonl_new(output_root / "adopted_reviews.jsonl", adopted)
    base.write_jsonl_new(output_root / "review_conflicts.jsonl", conflicts)
    base.write_jsonl_new(
        output_root / "resolved_by_third_review.jsonl", adjudicated
    )
    conflict_ids = {row["queue_id"] for row in conflicts}
    conflict_queue = [row for row in queue_rows if row["queue_id"] in conflict_ids]
    base.write_jsonl_new(
        output_root / "review3_conflict_queue.jsonl", conflict_queue
    )
    base.write_jsonl_new(
        output_root / "review3_template.jsonl",
        (review_template(row) for row in conflict_queue),
    )
    aggregate = base.aggregate(adopted)
    aggregate.update(
        {
            "schema_version": SCHEMA_VERSION,
            "review_policy_overlay_path": overlay_path,
            "review_policy_overlay_sha256": overlay_sha256,
            "pid_identity_scored": False,
            "excluded_conflict_count": len(conflicts),
            "expected_queue_count": len(queue),
            "complete": len(adopted) == len(queue) and not conflicts,
        }
    )
    base.write_json_new(
        output_root / "formal_aggregate_adopted_only.json", aggregate
    )
    if conflicts:
        print(
            f"Adopted {len(adopted)}/{len(queue)}; "
            f"{len(conflicts)} conflicts require overlay-bound review3"
        )
        return
    print(
        f"Formal overlay-bound scoring complete: {len(adopted)}/{len(queue)} "
        f"adopted; {len(adjudicated)} used review3"
    )


def add_bundle_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=48)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)

    bind = sub.add_parser(
        "bind-overlay",
        help="Create a versioned queue and manifest bound to the policy overlay",
    )
    bind.add_argument("--source-queue", type=Path, required=True)
    bind.add_argument("--source-manifest", type=Path, required=True)
    bind.add_argument("--overlay", type=Path, required=True)
    bind.add_argument("--score-root", type=Path, required=True)
    bind.add_argument("--expected-count", type=int, default=48)
    bind.add_argument(
        "--queue-name",
        default="review_queue_v2_pid_non_scoring_overlay_bound.jsonl",
    )
    bind.add_argument(
        "--template-name",
        default="review_template_v2_pid_non_scoring_overlay_bound.jsonl",
    )
    bind.add_argument(
        "--manifest-name",
        default="queue_manifest_v2_pid_non_scoring_overlay_bound.json",
    )
    bind.set_defaults(func=bind_overlay)

    verify = sub.add_parser("verify-queue", help="Verify the full bound queue bundle")
    add_bundle_arguments(verify)
    verify.add_argument("--report", type=Path, default=None)
    verify.set_defaults(func=verify_queue)

    validate = sub.add_parser(
        "validate-review",
        help="Validate one independent review and its overlay acknowledgement",
    )
    add_bundle_arguments(validate)
    validate.add_argument("--reviewer-jsonl", type=Path, required=True)
    validate.add_argument(
        "--review-name",
        choices=("review1", "review2", "review3"),
        required=True,
    )
    validate.add_argument("--score-root", type=Path, required=True)
    validate.set_defaults(func=validate_reviews)

    finish = sub.add_parser(
        "finalize",
        help="Finalize only reviews bound to the same queue and overlay hash",
    )
    add_bundle_arguments(finish)
    finish.add_argument("--review1", type=Path, required=True)
    finish.add_argument("--review2", type=Path, required=True)
    finish.add_argument("--review3", type=Path, default=None)
    finish.add_argument("--score-root", type=Path, required=True)
    finish.set_defaults(func=finalize)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        args.func(args)
    except (
        ValueError,
        FileNotFoundError,
        FileExistsError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
