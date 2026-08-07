#!/usr/bin/env python3
"""Offline, Codex-only double-review scoring for attack8 paired runs.

This module never calls a model API.  It prepares a provenance-bound JSONL
review queue from completed run JSONs, validates independently produced Codex
review JSONL, adopts exact two-review matches, adjudicates conflicts with a
third review, and aggregates the same formal action-claim metrics used by the
normal reconstruction scorer.

Artifacts are immutable: every command refuses to overwrite an existing file.
Use the dedicated ``scores_codex_manual_double_review`` score root or a new
score root for a fresh scoring pass.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ROOT
    / "data"
    / "current_experiment"
    / "cases"
    / "atlasv2_s3_s4_attack8_paired_stage_cases_20260724.jsonl"
)
VALIDATION_STEPS = (
    ROOT
    / "docs"
    / "current_experiment"
    / "atlasv2_s3_s4_attack8_paired_stage3_validation_steps_20260724.csv"
)
SCORER = ROOT / "src" / "clouseau_process_time" / "score_element_order_with_gpt.py"
DEFAULT_SCORE_ROOT_NAME = "scores_codex_manual_double_review_v2"
STAGES = ("stage1", "stage2", "stage3")
ACTION_KINDS = frozenset({"subject", "operation", "object"})
METRICS = (
    "behavior_step_recall",
    "action_step_recall",
    "action_step_precision",
    "behavior_sequence_order",
    "critical_evidence_recall",
    "candidate_claim_precision",
)
SCHEMA_VERSION = "codex_manual_action_claim_review_v2"
FALSE_POSITIVE_TYPES = frozenset(
    {
        "",
        "unsupported",
        "wrong_value",
        "wrong_relation",
        "wrong_component",
        "duplicate",
        "alert_only",
        "other",
    }
)
CONTRACT_KEYS = (
    "schema_version",
    "model",
    "stage",
    "instance_id",
    "run_sha256",
    "gold_sha256",
    "validation_steps_sha256",
    "maxima",
    "gold_items",
    "order_pairs",
    "candidate_slots",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def filesystem_path(path: Path) -> Path:
    text = str(path)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        return Path("\\\\?\\" + str(path.resolve()))
    return path


def read_json(path: Path) -> Any:
    return json.loads(filesystem_path(path).read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        filesystem_path(path).read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: JSONL row is not an object")
        rows.append(value)
    return rows


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with filesystem_path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_new(path: Path) -> Path:
    target = filesystem_path(path)
    if target.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing artifact: {path}. "
            "Use a new score root or output filename."
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def write_json_new(path: Path, value: Any) -> None:
    ensure_new(path).write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def write_jsonl_new(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    ensure_new(path).write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def next_versioned_path(directory: Path, stem: str, suffix: str) -> Path:
    for index in range(1, 10_000):
        candidate = directory / f"{stem}_{index:02d}{suffix}"
        if not filesystem_path(candidate).exists():
            return candidate
    raise RuntimeError(f"No free versioned artifact name under {directory}")


def load_scorer() -> Any:
    spec = importlib.util.spec_from_file_location("attack8_manual_scorer_base", SCORER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load scorer: {SCORER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def case_index(path: Path) -> dict[str, dict[str, Any]]:
    return {str(row["instance_id"]): row for row in read_jsonl(path)}


def discover_runs(result_root: Path) -> list[Path]:
    return sorted((result_root / "runs").glob("*/*/*_run.json"))


def run_identity(run_path: Path, result_root: Path) -> tuple[str, str, str]:
    relative = run_path.relative_to(result_root / "runs")
    return relative.parts[0], relative.parts[1], run_path.stem.removesuffix("_run")


def completed_run(
    run_path: Path, model: str, stage: str, instance_id: str
) -> tuple[bool, str | None, dict[str, Any] | None, dict[str, Any] | None]:
    try:
        payload = read_json(run_path)
    except Exception as exc:
        return False, f"invalid run JSON: {exc}", None, None
    mismatches = {
        key: (payload.get(key), expected)
        for key, expected in (
            ("model", model),
            ("experiment_stage", stage),
            ("instance_id", instance_id),
        )
        if payload.get(key) != expected
    }
    if mismatches:
        return False, f"run identity mismatch: {mismatches}", payload, None
    if payload.get("error"):
        return False, f"run error: {payload.get('error')}", payload, None
    configs = payload.get("configs")
    if not isinstance(configs, dict):
        return False, "configs is missing or not an object", payload, None
    limited = {
        key: configs.get(key)
        for key in ("max_investigations", "max_questions", "max_queries")
        if configs.get(key) is not None
    }
    if limited:
        return False, f"agent call limits are not null: {limited}", payload, None
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        return False, "agent_call_limit_policy is not unbounded_by_experiment", payload, None
    output_text = payload.get("output_text")
    if not isinstance(output_text, str) or not output_text.strip():
        return False, "output_text is empty", payload, None
    try:
        output = json.loads(output_text)
    except Exception as exc:
        return False, f"output_text is invalid JSON: {exc}", payload, None
    if not isinstance(output, dict) or not isinstance(output.get("code_steps"), list):
        return False, "output_text JSON has no code_steps list", payload, None
    return True, None, payload, output


def resolve_gold(case: dict[str, Any]) -> Path:
    root = Path(str(case["formal_gold_root"]))
    if not root.is_absolute():
        root = ROOT / root
    path = root / str(case["gold_chain_file"])
    if not filesystem_path(path).is_file():
        raise FileNotFoundError(f"Gold not found for {case['instance_id']}: {path}")
    return path


def normalized_kind(value: Any) -> str:
    text = str(value or "")
    return "critical_evidence" if text == "evidence" else text


def gold_contract(
    gold_path: Path, stage: str, validation_steps: Path
) -> dict[str, Any]:
    scorer = load_scorer()
    chains = scorer.normalize_gold(read_json(gold_path), gold_path)
    chains = scorer.filter_chains_for_stage(chains, stage, validation_steps)
    maxima = scorer.gold_maxima(chains)
    items = scorer.gold_required_items(chains)
    gold_items = [
        {
            "chain_id": str(item.get("chain_id") or ""),
            "step_id": str(item.get("step_id") or ""),
            "item_id": str(item.get("item_id") or ""),
            "kind": normalized_kind(item.get("kind")),
            "gold_value": item.get("gold_value"),
            "acceptable_terms": item.get("acceptable_terms") or [],
        }
        for item in items
    ]
    order_pairs: list[dict[str, str]] = []
    for chain in chains:
        chain_id = str(chain.get("chain_id") or "")
        pairs = chain.get("gold_order_pairs") or []
        if not pairs:
            step_ids = [
                str(step.get("step_id") or "") for step in chain.get("gold_steps") or []
            ]
            pairs = list(zip(step_ids, step_ids[1:]))
        for pair in pairs:
            if isinstance(pair, dict):
                before, after = pair.get("before_step_id"), pair.get("after_step_id")
            elif isinstance(pair, (list, tuple)) and len(pair) == 2:
                before, after = pair
            else:
                raise ValueError(f"Invalid gold order pair for {chain_id}: {pair!r}")
            pair_id = f"{chain_id}:{before}->{after}"
            order_pairs.append(
                {
                    "chain_id": chain_id,
                    "before_step_id": str(before),
                    "after_step_id": str(after),
                    "pair_id": pair_id,
                }
            )
    if len(order_pairs) != maxima["gold_order_pair_count"]:
        raise ValueError(
            f"Order-pair contract mismatch for {gold_path}: "
            f"{len(order_pairs)} != {maxima['gold_order_pair_count']}"
        )
    if len({row["item_id"] for row in gold_items}) != len(gold_items):
        raise ValueError(f"Duplicate gold item IDs in {gold_path}")
    if len({row["pair_id"] for row in order_pairs}) != len(order_pairs):
        raise ValueError(f"Duplicate order-pair IDs in {gold_path}")
    return {"maxima": maxima, "gold_items": gold_items, "order_pairs": order_pairs}


def meaningful(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, dict):
        return any(meaningful(child) for child in value.values())
    if isinstance(value, list):
        return any(meaningful(child) for child in value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {
            "",
            "...",
            "…",
            "{...}",
            "未提示",
            "不明",
            "unknown",
            "null",
            "none",
            "n/a",
        }:
            return False
    return True


def meaningful_object(value: Any) -> bool:
    if not isinstance(value, dict):
        return meaningful(value)
    # A bare object type ("file", "process", etc.) is a schema placeholder, not
    # a substantive candidate object value under the normal scorer's rules.
    return any(
        meaningful(value.get(key)) for key in ("name", "path", "value", "data")
    )


def compact_excerpt(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return canonical_json(value)
    return str(value)


def candidate_slots(output: dict[str, Any]) -> list[dict[str, Any]]:
    """Freeze subject/action/object slots before any reviewer sees the case.

    Command lines are attributes of an action claim, not independent actions.
    Critical evidence is evaluated only against the separate Gold-side
    diagnostic.  This keeps recall and precision on the same three action
    components.
    """
    slots: list[dict[str, Any]] = []
    for index, step in enumerate(output.get("code_steps") or [], 1):
        if not isinstance(step, dict):
            raise ValueError(f"code_steps[{index - 1}] is not an object")
        claim_id = f"C{index}"
        step_id = str(step.get("step_id") or f"step_{index}")
        values = (
            ("subject", step.get("subject_process")),
            ("operation", step.get("operation")),
            ("object", step.get("object")),
        )
        for kind, value in values:
            is_meaningful = (
                meaningful_object(value) if kind == "object" else meaningful(value)
            )
            if not is_meaningful:
                continue
            slot_id = f"{claim_id}:{kind}"
            slots.append(
                {
                    "candidate_claim_id": claim_id,
                    "candidate_step_id": step_id,
                    "slot_id": slot_id,
                    "kind": kind,
                    "candidate_slot_excerpt": compact_excerpt(value),
                }
            )
    identities = [row["slot_id"] for row in slots]
    if len(identities) != len(set(identities)):
        raise ValueError("Candidate slot IDs are not unique")
    return slots


def validate_queue_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows, 1):
        missing = [key for key in (*CONTRACT_KEYS, "queue_id", "contract_sha256") if key not in row]
        if missing:
            raise ValueError(f"Queue row {index} is missing fields: {missing}")
        contract = {key: row[key] for key in CONTRACT_KEYS}
        expected_hash = canonical_hash(contract)
        if row["contract_sha256"] != expected_hash:
            raise ValueError(f"Queue contract hash mismatch at row {index}")
        expected_id = (
            f"{row['model']}/{row['stage']}/{row['instance_id']}/"
            f"{expected_hash[:16]}"
        )
        if row["queue_id"] != expected_id:
            raise ValueError(f"Queue ID mismatch at row {index}")
        if row.get("candidate_output") is not None:
            if candidate_slots(row["candidate_output"]) != row["candidate_slots"]:
                raise ValueError(f"Candidate slot extraction mismatch at row {index}")
        if row["queue_id"] in result:
            raise ValueError(f"Duplicate queue ID: {row['queue_id']}")
        result[row["queue_id"]] = row
    return result


def queue_case_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row["model"]),
        str(row["stage"]),
        str(row["instance_id"]),
    )


def load_exclusion_queues(
    paths: list[Path],
) -> tuple[dict[tuple[str, str, str], dict[str, Any]], list[dict[str, Any]]]:
    exclusions: dict[tuple[str, str, str], dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []
    for path in paths:
        resolved = path.resolve()
        rows = read_jsonl(resolved)
        validated = validate_queue_rows(rows)
        sources.append(
            {
                "queue": str(resolved),
                "queue_sha256": sha256_file(resolved),
                "case_count": len(validated),
            }
        )
        for row in validated.values():
            key = queue_case_key(row)
            previous = exclusions.get(key)
            if previous is not None and previous["run_sha256"] != row["run_sha256"]:
                raise ValueError(
                    "Exclusion queues disagree on run SHA-256 for "
                    f"{key}: {previous['run_sha256']} != {row['run_sha256']}"
                )
            exclusions[key] = row
    return exclusions, sources


def matches_verified_exclusion(
    exclusions: dict[tuple[str, str, str], dict[str, Any]],
    *,
    model: str,
    stage: str,
    instance_id: str,
    run_sha256: str,
) -> bool:
    key = (model, stage, instance_id)
    previous = exclusions.get(key)
    if previous is None:
        return False
    if previous["run_sha256"] != run_sha256:
        raise ValueError(
            "Refusing to exclude a changed run for "
            f"{model}/{stage}/{instance_id}: queued SHA-256 "
            f"{previous['run_sha256']} != current {run_sha256}"
        )
    return True


def review_template(queue_row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "queue_id": queue_row["queue_id"],
        "contract_sha256": queue_row["contract_sha256"],
        "reviewer_id": "REPLACE_WITH_CODEX_TASK_OR_THREAD_ID",
        "gold_items": [
            {
                "item_id": item["item_id"],
                "kind": item["kind"],
                "score": None,
                "matched_candidate_excerpt": None,
                "reason_ja": "",
            }
            for item in queue_row["gold_items"]
        ],
        "order_pairs": [
            {
                "pair_id": pair["pair_id"],
                "score": None,
                "reason_ja": "",
            }
            for pair in queue_row["order_pairs"]
        ],
        "candidate_slots": [
            {
                **slot,
                "include_in_denominator": 1,
                "aligned_gold_step_id": None,
                "matched_gold_item_id": None,
                "is_true_positive": None,
                "false_positive_type": "",
                "reason_ja": "",
            }
            for slot in queue_row["candidate_slots"]
        ],
        "review_summary_ja": "",
    }


def prepare(args: argparse.Namespace) -> None:
    result_root = args.result_root.resolve()
    score_root = (args.score_root or result_root / DEFAULT_SCORE_ROOT_NAME).resolve()
    cases = case_index(args.cases)
    exclusions, exclusion_sources = load_exclusion_queues(args.exclude_queue)
    queue: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    completed_eligible_count = 0
    selected_stages = set(getattr(args, "stage", None) or ())
    instance_prefixes = tuple(getattr(args, "instance_prefix", None) or ())
    for run_path in discover_runs(result_root):
        model, stage, instance_id = run_identity(run_path, result_root)
        if selected_stages and stage not in selected_stages:
            continue
        if instance_prefixes and not instance_id.startswith(instance_prefixes):
            continue
        valid, reason, run, output = completed_run(
            run_path, model, stage, instance_id
        )
        case = cases.get(instance_id)
        if case is None:
            valid, reason = False, "instance_id not found in cases"
        case_contract = (case or {}).get("paired_stage_contract") or {}
        contract_version = str(case_contract.get("contract_version") or "")
        if (
            (
                contract_version.startswith("neutral_anchor_")
                or contract_version.startswith("observable_component_")
            )
            and case_contract.get("alert_mapping_scored") is not False
        ):
            valid, reason = (
                False,
                "neutral-anchor contract must explicitly set alert_mapping_scored=false",
            )
        if not valid or run is None or output is None or case is None:
            rejected.append({"run_json": str(run_path), "reason": str(reason)})
            continue
        completed_eligible_count += 1
        run_sha256 = sha256_file(run_path)
        if matches_verified_exclusion(
            exclusions,
            model=model,
            stage=stage,
            instance_id=instance_id,
            run_sha256=run_sha256,
        ):
            excluded.append(
                {
                    "model": model,
                    "stage": stage,
                    "instance_id": instance_id,
                    "run_json": str(run_path),
                    "run_sha256": run_sha256,
                }
            )
            continue
        gold_path = resolve_gold(case)
        contract = gold_contract(gold_path, stage, args.validation_steps)
        slots = candidate_slots(output)
        contract_body = {
            "schema_version": SCHEMA_VERSION,
            "model": model,
            "stage": stage,
            "instance_id": instance_id,
            "run_sha256": run_sha256,
            "gold_sha256": sha256_file(gold_path),
            "validation_steps_sha256": sha256_file(args.validation_steps),
            "maxima": contract["maxima"],
            "gold_items": contract["gold_items"],
            "order_pairs": contract["order_pairs"],
            "candidate_slots": slots,
        }
        contract_sha256 = canonical_hash(contract_body)
        queue_id = f"{model}/{stage}/{instance_id}/{contract_sha256[:16]}"
        queue.append(
            {
                **contract_body,
                "queue_id": queue_id,
                "contract_sha256": contract_sha256,
                "run_json": str(run_path),
                "gold_json": str(gold_path),
                "candidate_output": output,
                "review_policy": {
                    "action_denominator_excludes_critical_evidence": True,
                    "candidate_slots_are_fixed": True,
                    "candidate_denominator_is_fixed": True,
                    "candidate_slot_kinds": ["subject", "operation", "object"],
                    "command_line_is_action_attribute": True,
                    "critical_evidence_is_separate_gold_diagnostic": True,
                    "alert_mapping_scored": False,
                    "excluded_from_scoring": [
                        "inferring which unavailable CBC alert corresponds to the Gold chain",
                        "predicting a hidden alert id, alert title, alert reason, or alert-to-chain mapping",
                    ],
                    "alert_candidate_rule": (
                        "Do not create or judge a Gold item for alert correspondence. "
                        "If the submitted code_steps themselves treat an alert title "
                        "or alert row as a behavior action, evaluate that candidate "
                        "slot under the ordinary normal-reconstruction precision rule."
                    ),
                    "match_semantics": (
                        "Judge semantic equivalence from observed claims only; "
                        "do not infer missing subject, operation, object, evidence, "
                        "or causal edges. First align each candidate claim to at "
                        "most one Gold step using actor instance, operation family, "
                        "target instance/path/endpoint, and order. Every TP slot in "
                        "one candidate claim must reference that same aligned Gold "
                        "step. If Gold specifies a PID, a name-only candidate does "
                        "not match; evidence or another slot cannot backfill it."
                    ),
                    "order_semantics": (
                        "An order pair is correct only when two distinct candidate "
                        "claims align to its two Gold steps and appear in that order."
                    ),
                },
            }
        )
    if len(queue) != args.expected_count:
        raise ValueError(
            f"Eligible completed run count is {len(queue)}, expected "
            f"{args.expected_count}; excluded={len(excluded)}, "
            f"rejected={len(rejected)}"
        )
    if len({row["queue_id"] for row in queue}) != len(queue):
        raise ValueError("Duplicate queue IDs")
    queue_path = score_root / "review_queue.jsonl"
    template_path = score_root / "review_template.jsonl"
    write_jsonl_new(queue_path, queue)
    write_jsonl_new(template_path, (review_template(row) for row in queue))
    write_json_new(
        score_root / "queue_manifest.json",
        {
            "schema_version": SCHEMA_VERSION,
            "created_at_utc": utc_now(),
            "result_root": str(result_root),
            "score_root": str(score_root),
            "cases": str(args.cases.resolve()),
            "validation_steps": str(args.validation_steps.resolve()),
            "queue": str(queue_path),
            "queue_sha256": sha256_file(queue_path),
            "eligible_count": len(queue),
            "completed_eligible_before_exclusion": completed_eligible_count,
            "excluded_count": len(excluded),
            "excluded": excluded,
            "exclusion_sources": exclusion_sources,
            "rejected_count": len(rejected),
            "rejected": rejected,
            "models": sorted({row["model"] for row in queue}),
            "stage_counts": dict(Counter(row["stage"] for row in queue)),
            "selected_stages": sorted(selected_stages) if selected_stages else list(STAGES),
            "review_route": "Codex-only; no API calls made by this script",
            "base_reviews_per_run": 2,
            "third_review_only_for_conflicts": True,
            "adjudication_rule": (
                "exact two-review decision match; otherwise third-review "
                "2-of-3 per item, with conservative fallback"
            ),
            "non_overwrite_policy": True,
        },
    )
    print(f"Prepared {len(queue)} review cases at {queue_path}")


def binary(value: Any) -> int | None:
    if value in (0, "0", False):
        return 0
    if value in (1, "1", True):
        return 1
    return None


def decision_fingerprint(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "gold_items": sorted(
            (
                {"item_id": row["item_id"], "kind": row["kind"], "score": row["score"]}
                for row in review["gold_items"]
            ),
            key=lambda row: row["item_id"],
        ),
        "order_pairs": sorted(
            (
                {"pair_id": row["pair_id"], "score": row["score"]}
                for row in review["order_pairs"]
            ),
            key=lambda row: row["pair_id"],
        ),
        "candidate_slots": sorted(
            (
                {
                    "slot_id": row["slot_id"],
                    "kind": row["kind"],
                    "include_in_denominator": row["include_in_denominator"],
                    "aligned_gold_step_id": row["aligned_gold_step_id"],
                    "matched_gold_item_id": row["matched_gold_item_id"],
                    "is_true_positive": row["is_true_positive"],
                }
                for row in review["candidate_slots"]
            ),
            key=lambda row: row["slot_id"],
        ),
    }


def validate_review_row(
    row: dict[str, Any], queue: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    for key in ("schema_version", "queue_id", "contract_sha256", "reviewer_id"):
        if not isinstance(row.get(key), str) or not row.get(key):
            errors.append(f"{key} is missing or empty")
    if row.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if row.get("queue_id") != queue["queue_id"]:
        errors.append("queue_id mismatch")
    if row.get("contract_sha256") != queue["contract_sha256"]:
        errors.append("contract_sha256 mismatch")

    expected_gold = {item["item_id"]: item for item in queue["gold_items"]}
    actual_gold: dict[str, dict[str, Any]] = {}
    if not isinstance(row.get("gold_items"), list):
        errors.append("gold_items is not a list")
    else:
        for item in row["gold_items"]:
            if not isinstance(item, dict):
                errors.append("gold_items contains a non-object")
                continue
            item_id = str(item.get("item_id") or "")
            if item_id in actual_gold:
                errors.append(f"duplicate gold item: {item_id}")
            actual_gold[item_id] = item
            expected = expected_gold.get(item_id)
            if expected is None:
                errors.append(f"unknown gold item: {item_id}")
                continue
            if normalized_kind(item.get("kind")) != expected["kind"]:
                errors.append(f"gold item kind mismatch: {item_id}")
            if binary(item.get("score")) is None:
                errors.append(f"gold item score is not binary: {item_id}")
    if set(actual_gold) != set(expected_gold):
        errors.append("gold item ID set is incomplete or contains extras")

    expected_pairs = {pair["pair_id"]: pair for pair in queue["order_pairs"]}
    actual_pairs: dict[str, dict[str, Any]] = {}
    if not isinstance(row.get("order_pairs"), list):
        errors.append("order_pairs is not a list")
    else:
        for pair in row["order_pairs"]:
            if not isinstance(pair, dict):
                errors.append("order_pairs contains a non-object")
                continue
            pair_id = str(pair.get("pair_id") or "")
            if pair_id in actual_pairs:
                errors.append(f"duplicate order pair: {pair_id}")
            actual_pairs[pair_id] = pair
            if pair_id not in expected_pairs:
                errors.append(f"unknown order pair: {pair_id}")
            if binary(pair.get("score")) is None:
                errors.append(f"order score is not binary: {pair_id}")
    if set(actual_pairs) != set(expected_pairs):
        errors.append("order-pair ID set is incomplete or contains extras")

    expected_slots = {slot["slot_id"]: slot for slot in queue["candidate_slots"]}
    expected_step_ids = {
        item_id.rsplit(":", 1)[0] for item_id in expected_gold
    }
    actual_slots: dict[str, dict[str, Any]] = {}
    if not isinstance(row.get("candidate_slots"), list):
        errors.append("candidate_slots is not a list")
    else:
        for slot in row["candidate_slots"]:
            if not isinstance(slot, dict):
                errors.append("candidate_slots contains a non-object")
                continue
            slot_id = str(slot.get("slot_id") or "")
            if slot_id in actual_slots:
                errors.append(f"duplicate candidate slot: {slot_id}")
            actual_slots[slot_id] = slot
            expected = expected_slots.get(slot_id)
            if expected is None:
                errors.append(f"unknown candidate slot: {slot_id}")
                continue
            for key in (
                "candidate_claim_id",
                "candidate_step_id",
                "kind",
                "candidate_slot_excerpt",
            ):
                actual = (
                    normalized_kind(slot.get(key))
                    if key == "kind"
                    else slot.get(key)
                )
                if actual != expected[key]:
                    errors.append(f"candidate slot immutable field mismatch: {slot_id}/{key}")
            true_positive = binary(slot.get("is_true_positive"))
            included = binary(slot.get("include_in_denominator"))
            if included != 1:
                errors.append(f"fixed candidate slot must be included: {slot_id}")
            if true_positive is None:
                errors.append(f"candidate slot score is not binary: {slot_id}")
                continue
            aligned = slot.get("aligned_gold_step_id")
            aligned_id = str(aligned) if aligned not in (None, "") else None
            if aligned_id is not None and aligned_id not in expected_step_ids:
                errors.append(f"candidate slot has unknown aligned Gold step: {slot_id}")
            matched = slot.get("matched_gold_item_id")
            matched_id = str(matched) if matched not in (None, "") else None
            if true_positive == 1:
                if matched_id is None:
                    errors.append(f"true-positive slot has no gold reference: {slot_id}")
                elif matched_id not in expected_gold:
                    errors.append(f"slot references unknown gold item: {slot_id}")
                elif expected_gold[matched_id]["kind"] != expected["kind"]:
                    errors.append(f"candidate/gold kind mismatch: {slot_id} -> {matched_id}")
                elif aligned_id != matched_id.rsplit(":", 1)[0]:
                    errors.append(
                        f"TP slot alignment does not match referenced Gold step: {slot_id}"
                    )
            elif matched_id is not None:
                errors.append(f"false-positive slot must not reference gold: {slot_id}")
            fp_type = slot.get("false_positive_type")
            if not isinstance(fp_type, str) or fp_type not in FALSE_POSITIVE_TYPES:
                errors.append(f"invalid false_positive_type: {slot_id}")
            if true_positive == 1 and fp_type:
                errors.append(f"true-positive slot must have empty FP type: {slot_id}")
            if true_positive == 0 and not fp_type:
                errors.append(f"false-positive slot must have an FP type: {slot_id}")
    if set(actual_slots) != set(expected_slots):
        errors.append("candidate slot ID set is incomplete or contains extras")
    claims: dict[str, set[str]] = {}
    for slot_id, slot in actual_slots.items():
        if slot_id not in expected_slots:
            continue
        aligned = slot.get("aligned_gold_step_id")
        if aligned not in (None, ""):
            claims.setdefault(expected_slots[slot_id]["candidate_claim_id"], set()).add(
                str(aligned)
            )
    for claim_id, aligned_steps in claims.items():
        if len(aligned_steps) > 1:
            errors.append(
                f"candidate claim aligns to more than one Gold step: "
                f"{claim_id} -> {sorted(aligned_steps)}"
            )
    if errors:
        return None, errors

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "queue_id": queue["queue_id"],
        "contract_sha256": queue["contract_sha256"],
        "reviewer_id": row["reviewer_id"],
        "gold_items": [
            {
                "item_id": item_id,
                "kind": expected_gold[item_id]["kind"],
                "score": binary(actual_gold[item_id]["score"]),
                "matched_candidate_excerpt": actual_gold[item_id].get(
                    "matched_candidate_excerpt"
                ),
                "reason_ja": str(actual_gold[item_id].get("reason_ja") or ""),
            }
            for item_id in sorted(expected_gold)
        ],
        "order_pairs": [
            {
                "pair_id": pair_id,
                "score": binary(actual_pairs[pair_id]["score"]),
                "reason_ja": str(actual_pairs[pair_id].get("reason_ja") or ""),
            }
            for pair_id in sorted(expected_pairs)
        ],
        "candidate_slots": [
            {
                **expected_slots[slot_id],
                "include_in_denominator": binary(
                    actual_slots[slot_id]["include_in_denominator"]
                ),
                "aligned_gold_step_id": (
                    str(actual_slots[slot_id].get("aligned_gold_step_id"))
                    if actual_slots[slot_id].get("aligned_gold_step_id")
                    not in (None, "")
                    else None
                ),
                "matched_gold_item_id": (
                    str(actual_slots[slot_id].get("matched_gold_item_id"))
                    if actual_slots[slot_id].get("matched_gold_item_id")
                    not in (None, "")
                    else None
                ),
                "is_true_positive": binary(actual_slots[slot_id]["is_true_positive"]),
                "false_positive_type": actual_slots[slot_id]["false_positive_type"],
                "reason_ja": str(actual_slots[slot_id].get("reason_ja") or ""),
            }
            for slot_id in sorted(expected_slots)
        ],
        "review_summary_ja": str(row.get("review_summary_ja") or ""),
    }
    normalized["decision_sha256"] = canonical_hash(decision_fingerprint(normalized))
    return normalized, []


def validate_reviews(args: argparse.Namespace) -> None:
    queue_rows = read_jsonl(args.queue)
    queue = validate_queue_rows(queue_rows)
    input_rows = read_jsonl(args.reviewer_jsonl)
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
            reports.append({"queue_id": queue_id, "valid": False, "errors": ["missing row"]})
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
    output = args.score_root / "validated_reviews" / f"{args.review_name}.jsonl"
    report = args.score_root / "validation_reports" / f"{args.review_name}.json"
    if not all_valid:
        failed_report = next_versioned_path(
            args.score_root / "validation_reports",
            f"{args.review_name}_failed",
            ".json",
        )
        write_json_new(
            failed_report,
            {
                "review_name": args.review_name,
                "reviewer_jsonl": str(args.reviewer_jsonl),
                "valid": False,
                "valid_count": len(valid_rows),
                "expected_count": len(queue),
                "rows": reports,
            },
        )
        raise ValueError(f"Review validation failed; see {failed_report}")
    reviewer_ids = sorted({row["reviewer_id"] for row in valid_rows})
    if len(reviewer_ids) != 1:
        raise ValueError(
            f"One review file must have exactly one reviewer_id, got {reviewer_ids}"
        )
    write_jsonl_new(output, valid_rows)
    write_json_new(
        report,
        {
            "review_name": args.review_name,
            "reviewer_jsonl": str(args.reviewer_jsonl),
            "reviewer_id": reviewer_ids[0],
            "valid": True,
            "valid_count": len(valid_rows),
            "expected_count": len(queue),
            "validated_output": str(output),
            "validated_output_sha256": sha256_file(output),
            "rows": reports,
        },
    )
    print(f"Validated {len(valid_rows)} rows as {args.review_name}: {output}")


def majority_value(values: list[Any]) -> tuple[Any, bool]:
    counts = Counter(canonical_json(value) for value in values)
    encoded, count = counts.most_common(1)[0]
    return json.loads(encoded), count >= 2


def conservative_candidate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    template = rows[0]
    decision, majority = majority_value(
        [
            {
                "include_in_denominator": row["include_in_denominator"],
                "aligned_gold_step_id": row["aligned_gold_step_id"],
                "matched_gold_item_id": row["matched_gold_item_id"],
                "is_true_positive": row["is_true_positive"],
            }
            for row in rows
        ]
    )
    if not majority:
        decision = {
            # A no-majority extraction disagreement uses the larger candidate
            # denominator and zero hits, which is the conservative formal rule.
            "include_in_denominator": 1,
            "aligned_gold_step_id": None,
            "matched_gold_item_id": None,
            "is_true_positive": 0,
        }
    fp_type, fp_majority = majority_value(
        [row["false_positive_type"] for row in rows]
    )
    if decision["is_true_positive"] == 1:
        fp_type = ""
    elif not fp_majority or not fp_type:
        fp_type = "other"
    return {
        **{key: template[key] for key in (
            "candidate_claim_id",
            "candidate_step_id",
            "slot_id",
            "kind",
            "candidate_slot_excerpt",
        )},
        **decision,
        "false_positive_type": fp_type,
        "reason_ja": "third-review 2-of-3; conservative fallback when no tuple majority",
        "conservative_fallback": not majority,
    }


def adjudicate_reviews(
    first: dict[str, Any], second: dict[str, Any], third: dict[str, Any]
) -> tuple[dict[str, Any], int]:
    resolved: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "queue_id": first["queue_id"],
        "contract_sha256": first["contract_sha256"],
        "reviewer_id": "formal_2_of_3_adjudication",
    }
    conservative_count = 0
    for category, identity in (
        ("gold_items", "item_id"),
        ("order_pairs", "pair_id"),
    ):
        maps = [{row[identity]: row for row in review[category]} for review in (first, second, third)]
        rows: list[dict[str, Any]] = []
        for item_id in sorted(maps[0]):
            values = [mapping[item_id]["score"] for mapping in maps]
            score, majority = majority_value(values)
            if not majority:
                score = min(values)
                conservative_count += 1
            template = maps[0][item_id]
            rows.append(
                {
                    **{key: template[key] for key in template if key not in {"score", "reason_ja"}},
                    "score": score,
                    "reason_ja": "third-review 2-of-3 item-level majority",
                    "conservative_fallback": not majority,
                }
            )
        resolved[category] = rows
    slot_maps = [
        {row["slot_id"]: row for row in review["candidate_slots"]}
        for review in (first, second, third)
    ]
    resolved["candidate_slots"] = []
    for slot_id in sorted(slot_maps[0]):
        row = conservative_candidate([mapping[slot_id] for mapping in slot_maps])
        conservative_count += int(row["conservative_fallback"])
        resolved["candidate_slots"].append(row)
    resolved["review_summary_ja"] = "2-of-3 item-level adjudication"
    resolved["decision_sha256"] = canonical_hash(decision_fingerprint(resolved))
    return resolved, conservative_count


def totals_from_review(review: dict[str, Any], queue: dict[str, Any]) -> dict[str, Any]:
    maxima = queue["maxima"]
    gold_items = review["gold_items"]
    slots = review["candidate_slots"]
    included_slots = [
        slot for slot in slots if slot["include_in_denominator"] == 1
    ]
    covered_steps = {
        row["item_id"].rsplit(":", 1)[0]
        for row in gold_items
        if row["score"] == 1 and row["kind"] in ACTION_KINDS
    }
    action_recall_hits = sum(
        row["score"] == 1 and row["kind"] in ACTION_KINDS for row in gold_items
    )
    critical_hits = sum(
        row["score"] == 1 and row["kind"] == "critical_evidence"
        for row in gold_items
    )
    matched_action: set[str] = set()
    literal_true_positive_slots = 0
    for slot in included_slots:
        matched = slot["matched_gold_item_id"]
        if slot["is_true_positive"] != 1 or matched is None:
            continue
        literal_true_positive_slots += 1
        matched_action.add(matched)
    hits_totals = {
        "behavior_step_recall": (len(covered_steps), maxima["gold_step_count"]),
        "action_step_recall": (
            int(action_recall_hits),
            maxima["gold_action_required_item_count"],
        ),
        "action_step_precision": (
            literal_true_positive_slots,
            len(included_slots),
        ),
        "behavior_sequence_order": (
            sum(row["score"] == 1 for row in review["order_pairs"]),
            maxima["gold_order_pair_count"],
        ),
        "critical_evidence_recall": (
            int(critical_hits),
            maxima["gold_required_item_count"]
            - maxima["gold_action_required_item_count"],
        ),
        "candidate_claim_precision": (
            literal_true_positive_slots,
            len(included_slots),
        ),
    }
    totals: dict[str, Any] = {
        "gold_required_item_count": maxima["gold_required_item_count"],
        "gold_action_required_item_count": maxima["gold_action_required_item_count"],
        "action_denominator_excludes_critical_evidence": True,
        "candidate_action_claim_slot_count": len(included_slots),
        "candidate_action_claim_true_positive_slot_count": (
            literal_true_positive_slots
        ),
        "candidate_action_claim_unique_gold_item_count": len(matched_action),
        "candidate_action_claim_duplicate_true_positive_slot_count": (
            literal_true_positive_slots - len(matched_action)
        ),
        "candidate_action_claim_duplicate_true_positive_rate": (
            (literal_true_positive_slots - len(matched_action))
            / literal_true_positive_slots
            if literal_true_positive_slots
            else 0.0
        ),
        "unique_gold_coverage_per_candidate_slot": (
            len(matched_action) / len(included_slots) if included_slots else None
        ),
        "candidate_slot_kinds": sorted(ACTION_KINDS),
        "command_line_is_action_attribute": True,
        "critical_evidence_is_separate_gold_diagnostic": True,
    }
    for metric, (hits, total) in hits_totals.items():
        totals[f"{metric}_hits"] = hits
        totals[f"{metric}_total"] = total
        totals[metric] = hits / total if total else None
    return totals


def aggregate(adopted: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "policy": (
            "Codex-only independent double review; exact matches adopted. "
            "Conflicts require a third Codex review and item-level 2-of-3 "
            "adjudication with conservative fallback."
        ),
        "adopted_run_count": len(adopted),
        "third_review_adjudicated_count": sum(
            row["adoption_route"] == "third_review_2_of_3" for row in adopted
        ),
        "by_stage": {},
        "overall": {},
    }
    for stage in ("stage1", "stage2", "stage3"):
        rows = [row for row in adopted if row["stage"] == stage]
        metrics: dict[str, Any] = {}
        for metric in METRICS:
            hits = sum(row["totals"][f"{metric}_hits"] for row in rows)
            total = sum(row["totals"][f"{metric}_total"] for row in rows)
            metrics[metric] = {
                "hits": hits,
                "total": total,
                "value": hits / total if total else None,
            }
        result["by_stage"][stage] = {
            "adopted_run_count": len(rows),
            "metrics": metrics,
            "candidate_diagnostics": {
                "literal_true_positive_slots": sum(
                    row["totals"][
                        "candidate_action_claim_true_positive_slot_count"
                    ]
                    for row in rows
                ),
                "unique_matched_gold_items": sum(
                    row["totals"]["candidate_action_claim_unique_gold_item_count"]
                    for row in rows
                ),
                "duplicate_true_positive_slots": sum(
                    row["totals"][
                        "candidate_action_claim_duplicate_true_positive_slot_count"
                    ]
                    for row in rows
                ),
            },
        }
    for metric in METRICS:
        hits = sum(row["totals"][f"{metric}_hits"] for row in adopted)
        total = sum(row["totals"][f"{metric}_total"] for row in adopted)
        result["overall"][metric] = {
            "hits": hits,
            "total": total,
            "value": hits / total if total else None,
        }
    literal_tp = sum(
        row["totals"]["candidate_action_claim_true_positive_slot_count"]
        for row in adopted
    )
    unique_matches = sum(
        row["totals"]["candidate_action_claim_unique_gold_item_count"]
        for row in adopted
    )
    duplicate_tp = sum(
        row["totals"]["candidate_action_claim_duplicate_true_positive_slot_count"]
        for row in adopted
    )
    result["overall_candidate_diagnostics"] = {
        "literal_true_positive_slots": literal_tp,
        "unique_matched_gold_items": unique_matches,
        "duplicate_true_positive_slots": duplicate_tp,
        "duplicate_true_positive_rate": (
            duplicate_tp / literal_tp if literal_tp else 0.0
        ),
    }
    return result


def validated_review_map(
    path: Path,
    queue: dict[str, dict[str, Any]],
    *,
    allow_subset: bool,
) -> dict[str, dict[str, Any]]:
    rows = read_jsonl(path)
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
            raise ValueError(
                f"{path} is not a valid normalized review for {queue_id}: {errors}"
            )
        expected_hash = canonical_hash(decision_fingerprint(normalized))
        if row.get("decision_sha256") != expected_hash:
            raise ValueError(f"decision_sha256 mismatch in {path}: {queue_id}")
        result[queue_id] = normalized
    if not allow_subset and set(result) != set(queue):
        raise ValueError(f"{path} queue ID set does not match the full queue")
    return result


def finalize(args: argparse.Namespace) -> None:
    queue_rows = read_jsonl(args.queue)
    queue = validate_queue_rows(queue_rows)
    reviews = [
        validated_review_map(path, queue, allow_subset=False)
        for path in (args.review1, args.review2)
    ]
    third = (
        validated_review_map(args.review3, queue, allow_subset=True)
        if args.review3
        else {}
    )
    reviewer_ids = [
        {row["reviewer_id"] for row in review.values()} for review in reviews
    ]
    if any(len(ids) != 1 for ids in reviewer_ids):
        raise ValueError("Each validated base review must have exactly one reviewer_id")
    if next(iter(reviewer_ids[0])) == next(iter(reviewer_ids[1])):
        raise ValueError("review1 and review2 must have different reviewer_id values")

    comparisons: list[dict[str, Any]] = []
    adopted: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    adjudicated: list[dict[str, Any]] = []
    for queue_id, queue_row in queue.items():
        first, second = reviews[0][queue_id], reviews[1][queue_id]
        first_fp, second_fp = decision_fingerprint(first), decision_fingerprint(second)
        exact = first_fp == second_fp
        comparison = {
            "queue_id": queue_id,
            "model": queue_row["model"],
            "stage": queue_row["stage"],
            "instance_id": queue_row["instance_id"],
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
            selected, conservative_count = adjudicate_reviews(
                first, second, third_row
            )
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
            adopted_row = {
                **comparison,
                "totals": totals_from_review(selected, queue_row),
                "adopted_decisions": decision_fingerprint(selected),
                "adopted_decision_sha256": canonical_hash(
                    decision_fingerprint(selected)
                ),
                "contract_sha256": queue_row["contract_sha256"],
                "run_sha256": queue_row["run_sha256"],
                "gold_sha256": queue_row["gold_sha256"],
                "queue_contract": {
                    key: queue_row[key] for key in CONTRACT_KEYS
                },
            }
            adopted.append(adopted_row)
            if comparison["adoption_route"] == "third_review_2_of_3":
                adjudicated.append(adopted_row)
        comparisons.append(comparison)

    output_root = args.score_root / "formal_outputs"
    write_jsonl_new(output_root / "comparisons.jsonl", comparisons)
    write_jsonl_new(output_root / "adopted_reviews.jsonl", adopted)
    write_jsonl_new(output_root / "review_conflicts.jsonl", conflicts)
    write_jsonl_new(output_root / "resolved_by_third_review.jsonl", adjudicated)
    conflict_ids = {row["queue_id"] for row in conflicts}
    conflict_queue = [row for row in queue_rows if row["queue_id"] in conflict_ids]
    write_jsonl_new(output_root / "review3_conflict_queue.jsonl", conflict_queue)
    write_jsonl_new(
        output_root / "review3_template.jsonl",
        (review_template(row) for row in conflict_queue),
    )
    formal_aggregate = aggregate(adopted)
    formal_aggregate["excluded_conflict_count"] = len(conflicts)
    formal_aggregate["expected_queue_count"] = len(queue)
    formal_aggregate["complete"] = len(adopted) == len(queue) and not conflicts
    write_json_new(output_root / "formal_aggregate_adopted_only.json", formal_aggregate)
    if conflicts:
        print(
            f"Adopted {len(adopted)}/{len(queue)}; "
            f"{len(conflicts)} conflicts require review3"
        )
        return
    print(
        f"Formal scoring complete: {len(adopted)}/{len(queue)} adopted; "
        f"{len(adjudicated)} used review3"
    )


def verify_adopted_row(row: dict[str, Any], source: Path) -> dict[str, Any]:
    required = (
        "queue_id",
        "model",
        "stage",
        "instance_id",
        "adopted",
        "adoption_route",
        "totals",
        "adopted_decisions",
    )
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError(f"{source}: adopted row is missing fields: {missing}")
    if row["adopted"] is not True:
        raise ValueError(f"{source}: non-adopted row found in adopted ledger")
    if row["adoption_route"] not in {
        "exact_two_review_match",
        "third_review_2_of_3",
    }:
        raise ValueError(
            f"{source}: unsupported adoption route {row['adoption_route']!r}"
        )
    queue_prefix = (
        f"{row['model']}/{row['stage']}/{row['instance_id']}/"
    )
    if not str(row["queue_id"]).startswith(queue_prefix):
        raise ValueError(f"{source}: queue ID does not match row identity")

    decisions = row["adopted_decisions"]
    if not isinstance(decisions, dict):
        raise ValueError(f"{source}: adopted_decisions is not an object")
    decision_sha256 = canonical_hash(decisions)
    claimed_decision_sha256 = row.get("adopted_decision_sha256")
    if (
        claimed_decision_sha256 is not None
        and claimed_decision_sha256 != decision_sha256
    ):
        raise ValueError(f"{source}: adopted decision SHA-256 mismatch")
    if row["adoption_route"] == "exact_two_review_match":
        for key in ("review1_decision_sha256", "review2_decision_sha256"):
            if row.get(key) != decision_sha256:
                raise ValueError(
                    f"{source}: exact-match {key} does not match adopted decision"
                )

    queue_contract = row.get("queue_contract")
    verification_level = "decision_and_metric_shape"
    recomputed_totals: dict[str, Any] | None = None
    if queue_contract is not None:
        if not isinstance(queue_contract, dict):
            raise ValueError(f"{source}: queue_contract is not an object")
        missing_contract = [key for key in CONTRACT_KEYS if key not in queue_contract]
        if missing_contract:
            raise ValueError(
                f"{source}: queue_contract is missing fields: {missing_contract}"
            )
        normalized_contract = {key: queue_contract[key] for key in CONTRACT_KEYS}
        contract_sha256 = canonical_hash(normalized_contract)
        if row.get("contract_sha256") != contract_sha256:
            raise ValueError(f"{source}: queue contract SHA-256 mismatch")
        if not str(row["queue_id"]).endswith(f"/{contract_sha256[:16]}"):
            raise ValueError(f"{source}: queue ID contract prefix mismatch")
        if row.get("run_sha256") != normalized_contract["run_sha256"]:
            raise ValueError(f"{source}: run SHA-256 provenance mismatch")
        if row.get("gold_sha256") != normalized_contract["gold_sha256"]:
            raise ValueError(f"{source}: gold SHA-256 provenance mismatch")
        for key in ("model", "stage", "instance_id"):
            if row[key] != normalized_contract[key]:
                raise ValueError(f"{source}: contract identity mismatch for {key}")
        recomputed_totals = totals_from_review(decisions, normalized_contract)
        verification_level = "full_contract_decision_and_totals"

    totals = row["totals"]
    if not isinstance(totals, dict):
        raise ValueError(f"{source}: totals is not an object")
    if totals.get("action_denominator_excludes_critical_evidence") is not True:
        raise ValueError(f"{source}: action denominator policy mismatch")
    for metric in METRICS:
        hits = totals.get(f"{metric}_hits")
        total = totals.get(f"{metric}_total")
        value = totals.get(metric)
        if (
            not isinstance(hits, int)
            or isinstance(hits, bool)
            or not isinstance(total, int)
            or isinstance(total, bool)
            or hits < 0
            or total < 0
            or hits > total
        ):
            raise ValueError(f"{source}: invalid hits/total for {metric}")
        expected_value = hits / total if total else None
        if value != expected_value:
            raise ValueError(f"{source}: invalid metric value for {metric}")
    if recomputed_totals is not None:
        mismatches = {
            key: {
                "actual": totals.get(key),
                "recomputed": value,
            }
            for key, value in recomputed_totals.items()
            if totals.get(key) != value
        }
        if mismatches:
            raise ValueError(f"{source}: recomputed totals mismatch: {mismatches}")

    normalized = dict(row)
    normalized["adopted_decision_sha256"] = decision_sha256
    normalized["merge_verification_level"] = verification_level
    return normalized


def merge_batches(args: argparse.Namespace) -> None:
    if args.expected_count <= 0 or args.expected_stage_count <= 0:
        raise ValueError("Expected counts must be positive")
    merged: list[dict[str, Any]] = []
    ledger_sources: list[dict[str, Any]] = []
    seen_queue_ids: set[str] = set()
    seen_case_keys: set[tuple[str, str, str]] = set()
    for path in args.adopted_ledger:
        resolved = path.resolve()
        rows = read_jsonl(resolved)
        ledger_sources.append(
            {
                "adopted_ledger": str(resolved),
                "sha256": sha256_file(resolved),
                "row_count": len(rows),
            }
        )
        for row in rows:
            verified = verify_adopted_row(row, resolved)
            queue_id = str(verified["queue_id"])
            case_key = queue_case_key(verified)
            if queue_id in seen_queue_ids:
                raise ValueError(f"Duplicate queue ID across batches: {queue_id}")
            if case_key in seen_case_keys:
                raise ValueError(
                    "Duplicate model/stage/instance across batches: "
                    f"{case_key}"
                )
            seen_queue_ids.add(queue_id)
            seen_case_keys.add(case_key)
            verified["merged_from_adopted_ledger"] = str(resolved)
            merged.append(verified)
    if len(merged) != args.expected_count:
        raise ValueError(
            f"Merged adopted count is {len(merged)}, expected {args.expected_count}"
        )
    stage_counts = Counter(str(row["stage"]) for row in merged)
    expected_stages = {
        "stage1": args.expected_stage_count,
        "stage2": args.expected_stage_count,
        "stage3": args.expected_stage_count,
    }
    if dict(stage_counts) != expected_stages:
        raise ValueError(
            f"Merged Stage counts are {dict(stage_counts)}, "
            f"expected {expected_stages}"
        )
    merged.sort(
        key=lambda row: (
            row["model"],
            row["stage"],
            row["instance_id"],
            row["queue_id"],
        )
    )
    formal_aggregate = aggregate(merged)
    formal_aggregate.update(
        {
            "complete": True,
            "expected_queue_count": args.expected_count,
            "excluded_conflict_count": 0,
            "merge_policy": (
                "Immutable offline merge of formally adopted batch ledgers; "
                "duplicate case keys and queue IDs prohibited."
            ),
            "metric_definitions": {
                "behavior_step_recall": "covered gold steps / gold steps",
                "action_step_recall": (
                    "matched non-critical gold required items / "
                    "non-critical gold required items"
                ),
                "action_step_precision": (
                    "literal true-positive subject/action/object candidate "
                    "slots / included subject/action/object candidate slots"
                ),
                "behavior_sequence_order": (
                    "correct gold order pairs / gold order pairs"
                ),
                "critical_evidence_recall": (
                    "matched critical-evidence gold items / "
                    "critical-evidence gold items"
                ),
                "candidate_claim_precision": (
                    "literal true-positive subject/action/object candidate "
                    "slots / included subject/action/object candidate slots"
                ),
                "duplicate_true_positive_rate": (
                    "duplicate TP subject/action/object slots / literal TP "
                    "subject/action/object slots"
                ),
                "action_denominator_excludes_critical_evidence": True,
                "command_line_is_action_attribute": True,
            },
            "stage_counts": dict(stage_counts),
            "input_ledgers": ledger_sources,
            "merged_at_utc": utc_now(),
        }
    )
    output_root = args.score_root.resolve() / "formal_outputs"
    write_jsonl_new(output_root / "adopted_reviews.jsonl", merged)
    write_json_new(
        output_root / "formal_aggregate_adopted_only.json",
        formal_aggregate,
    )
    print(
        f"Merged formal scoring complete: {len(merged)} adopted cases; "
        f"Stages {dict(stage_counts)}"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)

    prepare_parser = sub.add_parser("prepare", help="Build a validated review queue")
    prepare_parser.add_argument("--result-root", type=Path, required=True)
    prepare_parser.add_argument("--score-root", type=Path, default=None)
    prepare_parser.add_argument("--cases", type=Path, default=CASES)
    prepare_parser.add_argument("--validation-steps", type=Path, default=VALIDATION_STEPS)
    prepare_parser.add_argument("--expected-count", type=int, default=24)
    prepare_parser.add_argument(
        "--stage",
        action="append",
        choices=STAGES,
        help=(
            "Optionally prepare only selected stages. Repeat for multiple stages. "
            "This is intended for immutable, independently reviewed batches."
        ),
    )
    prepare_parser.add_argument(
        "--instance-prefix",
        action="append",
        help=(
            "Optionally prepare only instance IDs beginning with this prefix. "
            "Repeat for multiple prefixes; useful for immutable scenario batches."
        ),
    )
    prepare_parser.add_argument(
        "--exclude-queue",
        type=Path,
        action="append",
        default=[],
        help=(
            "Repeatable prior review_queue.jsonl to exclude. A case is "
            "excluded only when model, stage, instance_id, and run SHA-256 "
            "match the current completed run."
        ),
    )
    prepare_parser.set_defaults(func=prepare)

    validate_parser = sub.add_parser(
        "validate-review", help="Validate one independent Codex review JSONL"
    )
    validate_parser.add_argument("--queue", type=Path, required=True)
    validate_parser.add_argument("--reviewer-jsonl", type=Path, required=True)
    validate_parser.add_argument("--review-name", choices=("review1", "review2", "review3"), required=True)
    validate_parser.add_argument("--score-root", type=Path, required=True)
    validate_parser.set_defaults(func=validate_reviews)

    finalize_parser = sub.add_parser(
        "finalize", help="Adopt exact matches, adjudicate review3, and aggregate"
    )
    finalize_parser.add_argument("--queue", type=Path, required=True)
    finalize_parser.add_argument("--review1", type=Path, required=True)
    finalize_parser.add_argument("--review2", type=Path, required=True)
    finalize_parser.add_argument("--review3", type=Path, default=None)
    finalize_parser.add_argument("--score-root", type=Path, required=True)
    finalize_parser.set_defaults(func=finalize)

    merge_parser = sub.add_parser(
        "merge-batches",
        help="Verify and merge immutable adopted ledgers into one formal aggregate",
    )
    merge_parser.add_argument(
        "--adopted-ledger",
        type=Path,
        action="append",
        required=True,
        help=(
            "Repeatable batch formal_outputs/adopted_reviews.jsonl path"
        ),
    )
    merge_parser.add_argument("--score-root", type=Path, required=True)
    merge_parser.add_argument("--expected-count", type=int, default=24)
    merge_parser.add_argument("--expected-stage-count", type=int, default=8)
    merge_parser.set_defaults(func=merge_batches)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        args.func(args)
    except (ValueError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
