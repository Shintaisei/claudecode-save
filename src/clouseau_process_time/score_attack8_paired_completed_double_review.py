#!/usr/bin/env python3
"""Double-review completed attack8 paired runs with the formal normal scorer.

Only valid, completed ``*_run.json`` files are eligible.  Each eligible run is
scored twice by independent invocations of ``score_element_order_with_gpt.py``.
Existing score results are never overwritten.  To rescore, use a new
``--score-root``.  The ledger files are rebuilt from the score tree, so ordinary
reruns are idempotent and can pick up newly completed experiment runs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ROOT
    / "data"
    / "current_experiment"
    / "cases"
    / "atlasv2_s3_s4_attack8_paired_stage_cases_20260724.jsonl"
)
RESULT_ROOT = (
    ROOT
    / "docs"
    / "current_experiment"
    / "results_2026-07-24"
    / "atlasv2_s3_s4_attack8_paired"
    / "replicate_01"
)
VALIDATION_STEPS = (
    ROOT
    / "docs"
    / "current_experiment"
    / "atlasv2_s3_s4_attack8_paired_stage3_validation_steps_20260724.csv"
)
SCORER = ROOT / "src" / "clouseau_process_time" / "score_element_order_with_gpt.py"
DEFAULT_SCORE_ROOT = RESULT_ROOT / "scores_normal_parity_double_review"
ACTION_TOTAL_KEYS = (
    "behavior_step_recall",
    "behavior_step_recall_hits",
    "behavior_step_recall_total",
    "action_step_recall",
    "action_step_recall_hits",
    "action_step_recall_total",
    "action_step_precision",
    "action_step_precision_hits",
    "action_step_precision_total",
    "behavior_sequence_order",
    "behavior_sequence_order_hits",
    "behavior_sequence_order_total",
    "critical_evidence_recall",
    "critical_evidence_recall_hits",
    "critical_evidence_recall_total",
    "action_denominator_excludes_critical_evidence",
    "candidate_claim_precision",
    "candidate_claim_precision_hits",
    "candidate_claim_precision_total",
)
FORMAL_REVIEW_QUALITY_KEYS = (
    "schema_valid",
    "denominator_match",
    "gold_item_set_complete",
    "order_pair_set_complete",
    "candidate_slot_complete",
    "reference_valid",
    "totals_recompute_match",
    "provenance_match",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def filesystem_path(path: Path) -> Path:
    return (
        Path("\\\\?\\" + str(path.resolve()))
        if os.name == "nt" and not str(path).startswith("\\\\?\\")
        else path
    )


def path_exists(path: Path) -> bool:
    return filesystem_path(path).exists()


def read_json(path: Path) -> Any:
    target = filesystem_path(path)
    return json.loads(target.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, payload: Any) -> None:
    target = filesystem_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def case_index(path: Path) -> dict[str, dict[str, Any]]:
    return {str(case["instance_id"]): case for case in read_jsonl(path)}


def discover_runs(result_root: Path) -> list[Path]:
    return sorted((result_root / "runs").glob("*/*/*_run.json"))


def run_identity(run_json: Path, result_root: Path) -> tuple[str, str, str]:
    relative = run_json.relative_to(result_root / "runs")
    return (
        relative.parts[0],
        relative.parts[1],
        run_json.stem.removesuffix("_run"),
    )


def completed_run(
    run_json: Path,
    expected_model: str,
    expected_stage: str,
    expected_instance_id: str,
) -> tuple[bool, str | None]:
    try:
        payload = read_json(run_json)
    except Exception as exc:
        return False, f"invalid run JSON: {exc}"
    if payload.get("error"):
        return False, f"run error: {payload['error']}"
    identity_mismatches = {
        "instance_id": {
            "actual": payload.get("instance_id"),
            "expected": expected_instance_id,
        },
        "model": {"actual": payload.get("model"), "expected": expected_model},
        "experiment_stage": {
            "actual": payload.get("experiment_stage"),
            "expected": expected_stage,
        },
    }
    identity_mismatches = {
        key: value
        for key, value in identity_mismatches.items()
        if value["actual"] != value["expected"]
    }
    if identity_mismatches:
        return False, f"run identity mismatch: {identity_mismatches}"
    configs = payload.get("configs")
    if not isinstance(configs, dict):
        return False, "run configs is missing or not an object"
    limit_mismatches = {
        key: configs.get(key)
        for key in ("max_investigations", "max_questions", "max_queries")
        if configs.get(key) is not None
    }
    if limit_mismatches:
        return False, f"agent call limits are not null: {limit_mismatches}"
    if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
        return False, (
            "agent_call_limit_policy is not unbounded_by_experiment: "
            f"{configs.get('agent_call_limit_policy')!r}"
        )
    output_text = payload.get("output_text")
    if not isinstance(output_text, str) or not output_text.strip():
        return False, "output_text is empty"
    try:
        output = json.loads(output_text)
    except Exception as exc:
        return False, f"output_text is not valid JSON: {exc}"
    if not isinstance(output, dict):
        return False, "output_text JSON is not an object"
    if not isinstance(output.get("code_steps"), list):
        return False, "output_text has no code_steps list"
    return True, None


def resolve_gold(case: dict[str, Any]) -> Path:
    gold_root = Path(str(case["formal_gold_root"]))
    if not gold_root.is_absolute():
        gold_root = ROOT / gold_root
    gold = gold_root / str(case["gold_chain_file"])
    if not gold.is_file():
        raise FileNotFoundError(f"Gold not found for {case['instance_id']}: {gold}")
    return gold


def score_dir(
    score_root: Path,
    review: str,
    model: str,
    stage: str,
    instance_id: str,
) -> Path:
    return score_root / review / model / stage / instance_id


def score_path(
    score_root: Path,
    review: str,
    model: str,
    stage: str,
    instance_id: str,
) -> Path:
    return score_dir(score_root, review, model, stage, instance_id) / "score_result.json"


def review_score_candidates(
    score_root: Path,
    review: str,
    model: str,
    stage: str,
    instance_id: str,
) -> list[Path]:
    candidates = [score_path(score_root, review, model, stage, instance_id)]
    for retry_root in sorted(score_root.glob(f"{review}_retry_[0-9][0-9]")):
        candidates.append(
            retry_root / model / stage / instance_id / "score_result.json"
        )
    return candidates


def next_retry_review_name(
    score_root: Path,
    review: str,
    model: str,
    stage: str,
    instance_id: str,
) -> str:
    index = 1
    while path_exists(
        score_path(
            score_root,
            f"{review}_retry_{index:02d}",
            model,
            stage,
            instance_id,
        )
    ):
        index += 1
    return f"{review}_retry_{index:02d}"


def score_totals(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    totals = ((payload.get("score") or {}).get("totals") or {})
    if not isinstance(totals, dict) or not totals:
        raise ValueError(f"score totals missing: {path}")
    if totals.get("action_denominator_excludes_critical_evidence") is not True:
        raise ValueError(
            f"formal denominator policy missing or false in score result: {path}"
        )
    return totals


def valid_score_payload(path: Path) -> bool:
    try:
        score_totals(path)
        return True
    except Exception:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with filesystem_path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def provenance_payload(
    run_json: Path,
    gold: Path,
    validation_steps: Path,
    judge_model: str,
    reasoning_effort: str,
) -> dict[str, Any]:
    inputs = {
        "run_json_sha256": sha256_file(run_json),
        "gold_sha256": sha256_file(gold),
        "validation_steps_sha256": sha256_file(validation_steps),
        "scorer_sha256": sha256_file(SCORER),
        "judge_model": judge_model,
        "reasoning_effort": reasoning_effort,
        "reviews_per_run": 2,
        "scoring_definition": "formal_normal_action_claim_metrics",
        "action_denominator_excludes_critical_evidence": True,
    }
    return {**inputs, "provenance_sha256": canonical_hash(inputs)}


def provenance_path(score_result: Path) -> Path:
    return score_result.with_name("score_result.provenance.json")


def write_provenance(score_result: Path, expected: dict[str, Any]) -> None:
    write_json(provenance_path(score_result), expected)


def reusable_score(score_result: Path, expected: dict[str, Any]) -> bool:
    if not valid_score_payload(score_result):
        return False
    try:
        actual = read_json(provenance_path(score_result))
    except Exception:
        return False
    return all(actual.get(key) == value for key, value in expected.items())


def effective_score_path(
    score_root: Path,
    review: str,
    model: str,
    stage: str,
    instance_id: str,
    expected_provenance: dict[str, Any],
) -> Path | None:
    for candidate in reversed(
        review_score_candidates(
            score_root, review, model, stage, instance_id
        )
    ):
        if reusable_score(candidate, expected_provenance):
            return candidate
    return None


def run_scorer(
    run_json: Path,
    out_dir: Path,
    gold: Path,
    stage: str,
    validation_steps: Path,
    judge_model: str,
    reasoning_effort: str,
    expected_provenance: dict[str, Any],
) -> None:
    command = [
        sys.executable,
        str(SCORER),
        "--gold",
        str(gold),
        "--run-json",
        str(run_json),
        "--out-dir",
        str(out_dir),
        "--stage",
        stage,
        "--validation-steps",
        str(validation_steps),
        "--model",
        judge_model,
        "--reasoning-effort",
        reasoning_effort,
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"scorer failed for {run_json} (exit {completed.returncode})\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    result_path = out_dir / "score_result.json"
    score_totals(result_path)
    write_provenance(result_path, expected_provenance)


def normalized(value: Any) -> Any:
    return round(value, 12) if isinstance(value, float) else value


def load_scorer_module() -> Any:
    spec = importlib.util.spec_from_file_location("attack8_formal_scorer", SCORER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scorer: {SCORER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_contract(
    gold: Path,
    stage: str,
    validation_steps: Path,
) -> dict[str, Any]:
    scorer = load_scorer_module()
    chains = scorer.normalize_gold(read_json(gold), gold)
    chains = scorer.filter_chains_for_stage(chains, stage, validation_steps)
    maxima = scorer.gold_maxima(chains)
    items = scorer.gold_required_items(chains)
    item_kinds = {
        str(item["item_id"]): (
            "critical_evidence"
            if item.get("kind") == "evidence"
            else str(item.get("kind"))
        )
        for item in items
    }
    order_pairs: set[str] = set()
    for chain in chains:
        chain_id = str(chain.get("chain_id") or "")
        for pair in chain.get("gold_order_pairs") or []:
            if isinstance(pair, dict):
                before = pair.get("before_step_id")
                after = pair.get("after_step_id")
            elif isinstance(pair, (list, tuple)) and len(pair) == 2:
                before, after = pair
            else:
                continue
            if before not in (None, "") and after not in (None, ""):
                order_pairs.add(f"{chain_id}:{before}->{after}")
    return {
        "maxima": maxima,
        "gold_item_kinds": item_kinds,
        "gold_item_ids": sorted(item_kinds),
        "order_pair_ids": sorted(order_pairs),
    }


def binary(value: Any) -> int | None:
    if value in (1, "1", True):
        return 1
    if value in (0, "0", False):
        return 0
    return None


def review_quality(
    score_result: Path,
    expected: dict[str, Any],
    expected_provenance: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    errors: list[str] = []
    reference_errors: list[str] = []
    payload = read_json(score_result)
    score = payload.get("score")
    chains = score.get("chains") if isinstance(score, dict) else None
    totals = score.get("totals") if isinstance(score, dict) else None
    schema_valid = isinstance(chains, list) and isinstance(totals, dict)
    if not schema_valid:
        return (
            {
                "schema_valid": False,
                "denominator_match": False,
                "gold_item_set_complete": False,
                "order_pair_set_complete": False,
                "candidate_slot_complete": False,
                "reference_valid": False,
                "totals_recompute_match": False,
                "provenance_match": False,
                "errors": ["score.chains or score.totals has invalid schema"],
            },
            {"gold_items": [], "order_pairs": [], "candidate_slots": []},
        )

    gold_items: list[dict[str, Any]] = []
    order_pairs: list[dict[str, Any]] = []
    candidate_slots: list[dict[str, Any]] = []
    seen_items: set[str] = set()
    seen_pairs: set[str] = set()
    seen_slots: set[str] = set()
    expected_kinds = expected["gold_item_kinds"]

    for chain in chains:
        if not isinstance(chain, dict):
            errors.append("chain entry is not an object")
            continue
        chain_id = str(chain.get("chain_id") or "")
        for item in chain.get("gold_required_item_scores") or []:
            if not isinstance(item, dict):
                errors.append(f"{chain_id}: gold item is not an object")
                continue
            item_id = str(item.get("item_id") or "")
            kind = (
                "critical_evidence"
                if item.get("kind") == "evidence"
                else str(item.get("kind") or "")
            )
            item_score = binary(item.get("score"))
            if not item_id or item_score is None:
                errors.append(f"{chain_id}: invalid gold item id/score")
            if item_id in seen_items:
                errors.append(f"duplicate gold item: {item_id}")
            seen_items.add(item_id)
            if expected_kinds.get(item_id) != kind:
                reference_errors.append(f"gold item kind mismatch: {item_id}")
            gold_items.append(
                {"item_id": item_id, "kind": kind, "score": item_score}
            )

        for pair in chain.get("order_pairs") or []:
            if not isinstance(pair, dict):
                errors.append(f"{chain_id}: order pair is not an object")
                continue
            pair_id = (
                f"{chain_id}:{pair.get('before_step_id')}"
                f"->{pair.get('after_step_id')}"
            )
            pair_score = binary(pair.get("score"))
            if pair_id in seen_pairs:
                errors.append(f"duplicate order pair: {pair_id}")
            seen_pairs.add(pair_id)
            if pair_score is None:
                errors.append(f"invalid order score: {pair_id}")
            order_pairs.append({"pair_id": pair_id, "score": pair_score})

        claims = (
            chain.get("candidate_action_claim_scores")
            or chain.get("candidate_claim_scores")
            or []
        )
        for claim in claims:
            if not isinstance(claim, dict):
                errors.append(f"{chain_id}: candidate claim is not an object")
                continue
            claim_id = str(
                claim.get("candidate_claim_id") or claim.get("claim_id") or ""
            )
            candidate_step_id = str(claim.get("candidate_step_id") or "")
            slots = claim.get("slot_scores") or claim.get("required_item_scores") or []
            for slot in slots:
                if not isinstance(slot, dict):
                    errors.append(f"{chain_id}/{claim_id}: slot is not an object")
                    continue
                slot_id = str(slot.get("slot_id") or "")
                identity = f"{chain_id}:{claim_id}:{slot_id}"
                kind = (
                    "critical_evidence"
                    if slot.get("kind") == "evidence"
                    else str(slot.get("kind") or "")
                )
                matched = slot.get("matched_gold_item_id") or slot.get(
                    "matched_gold_element_id"
                )
                matched_id = str(matched) if matched not in (None, "") else None
                true_positive = binary(slot.get("is_true_positive"))
                if identity in seen_slots:
                    errors.append(f"duplicate candidate slot: {identity}")
                seen_slots.add(identity)
                if not slot_id or true_positive is None:
                    errors.append(f"invalid candidate slot id/score: {identity}")
                if matched_id is not None:
                    if matched_id not in expected_kinds:
                        reference_errors.append(
                            f"true-positive slot references unknown gold item: {identity}"
                        )
                    elif expected_kinds[matched_id] != kind:
                        reference_errors.append(
                            f"candidate/gold kind mismatch: {identity} -> {matched_id}"
                        )
                candidate_slots.append(
                    {
                        "chain_id": chain_id,
                        "candidate_claim_id": claim_id,
                        "candidate_step_id": candidate_step_id,
                        "slot_id": slot_id,
                        "kind": kind,
                        "candidate_slot_excerpt": slot.get(
                            "candidate_slot_excerpt"
                        ),
                        "matched_gold_item_id": matched_id,
                        "is_true_positive": true_positive,
                        "false_positive_type": slot.get("false_positive_type"),
                    }
                )

    gold_item_set_complete = seen_items == set(expected["gold_item_ids"])
    order_pair_set_complete = seen_pairs == set(expected["order_pair_ids"])
    if not gold_item_set_complete:
        errors.append("gold item ID set is incomplete or contains extras")
    if not order_pair_set_complete:
        errors.append("order-pair set is incomplete or contains extras")

    maxima = expected["maxima"]
    expected_denominators = {
        "behavior_step_recall_total": maxima["gold_step_count"],
        "action_step_recall_total": maxima["gold_action_required_item_count"],
        "action_step_precision_total": maxima["gold_action_required_item_count"],
        "gold_required_item_count": maxima["gold_required_item_count"],
        "gold_action_required_item_count": maxima[
            "gold_action_required_item_count"
        ],
        "behavior_sequence_order_total": maxima["gold_order_pair_count"],
        "critical_evidence_recall_total": (
            maxima["gold_required_item_count"]
            - maxima["gold_action_required_item_count"]
        ),
        "action_denominator_excludes_critical_evidence": True,
    }
    denominator_mismatches = {
        key: {"actual": totals.get(key), "expected": value}
        for key, value in expected_denominators.items()
        if totals.get(key) != value
    }
    denominator_match = not denominator_mismatches
    if denominator_mismatches:
        errors.append(f"denominator mismatch: {denominator_mismatches}")

    candidate_count = len(candidate_slots)
    candidate_count_fields = (
        "candidate_action_claim_slot_count",
        "candidate_action_claim_raw_slot_count",
    )
    candidate_slot_complete = all(
        int(score.get(key, -1)) == candidate_count for key in candidate_count_fields
    ) and totals.get("candidate_claim_precision_total") == candidate_count
    if not candidate_slot_complete:
        errors.append(
            f"candidate slot count mismatch: actual={candidate_count}, "
            f"score={score.get('candidate_action_claim_slot_count')}, "
            f"raw={score.get('candidate_action_claim_raw_slot_count')}, "
            f"totals={totals.get('candidate_claim_precision_total')}"
        )

    action_kinds = {"subject", "operation", "object", "command_line"}
    action_gold_hits = sum(
        row["score"] == 1 and row["kind"] in action_kinds
        for row in gold_items
    )
    critical_gold_hits = sum(
        row["score"] == 1 and row["kind"] == "critical_evidence"
        for row in gold_items
    )
    covered_steps = {
        row["item_id"].rsplit(":", 1)[0]
        for row in gold_items
        if row["score"] == 1 and row["kind"] in action_kinds
    }
    matched_ids: set[str] = set()
    matched_action_ids: set[str] = set()
    for row in candidate_slots:
        matched_id = row["matched_gold_item_id"]
        if row["is_true_positive"] != 1 or matched_id is None:
            continue
        if matched_id in expected_kinds:
            matched_ids.add(matched_id)
            if expected_kinds[matched_id] in action_kinds:
                matched_action_ids.add(matched_id)
    recomputed = {
        "behavior_step_recall_hits": len(covered_steps),
        "action_step_recall_hits": int(action_gold_hits),
        "action_step_precision_hits": len(matched_action_ids),
        "behavior_sequence_order_hits": sum(
            row["score"] == 1 for row in order_pairs
        ),
        "critical_evidence_recall_hits": int(critical_gold_hits),
        "candidate_claim_precision_hits": len(matched_ids),
        "candidate_claim_precision_total": candidate_count,
        "candidate_action_claim_true_positive_slot_count": len(matched_ids),
        "candidate_action_claim_slot_count": candidate_count,
        "candidate_action_claim_raw_slot_count": candidate_count,
    }
    totals_recompute_mismatches = {
        key: {"actual": totals.get(key), "recomputed": value}
        for key, value in recomputed.items()
        if (
            totals.get(key)
            if key in totals
            else score.get(key)
        )
        != value
    }
    totals_recompute_match = not totals_recompute_mismatches
    if totals_recompute_mismatches:
        errors.append(
            f"item-level totals mismatch: {totals_recompute_mismatches}"
        )

    reference_valid = not reference_errors
    errors.extend(reference_errors)
    provenance_match = False
    try:
        actual_provenance = read_json(provenance_path(score_result))
        provenance_match = all(
            actual_provenance.get(key) == value
            for key, value in expected_provenance.items()
        )
    except Exception:
        pass
    if not provenance_match:
        errors.append("score provenance is missing or stale")

    fingerprints = {
        "gold_items": sorted(
            gold_items, key=lambda row: (row["item_id"], row["kind"])
        ),
        "order_pairs": sorted(order_pairs, key=lambda row: row["pair_id"]),
        "candidate_slots": sorted(
            candidate_slots,
            key=lambda row: (
                row["chain_id"],
                row["candidate_claim_id"],
                row["slot_id"],
            ),
        ),
    }
    return (
        {
            "schema_valid": schema_valid and not any(
                error.startswith(("chain entry", "duplicate", "invalid"))
                for error in errors
            ),
            "denominator_match": denominator_match,
            "gold_item_set_complete": gold_item_set_complete,
            "order_pair_set_complete": order_pair_set_complete,
            "candidate_slot_complete": candidate_slot_complete,
            "reference_valid": reference_valid,
            "totals_recompute_match": totals_recompute_match,
            "provenance_match": provenance_match,
            "expected_maxima": maxima,
            "denominator_mismatches": denominator_mismatches,
            "totals_recompute_mismatches": totals_recompute_mismatches,
            "reference_errors": reference_errors,
            "errors": errors,
        },
        fingerprints,
    )


def comparison_payload(
    score_root: Path,
    result_root: Path,
    run_json: Path,
    case: dict[str, Any],
    model: str,
    stage: str,
    instance_id: str,
    validation_steps: Path,
    judge_model: str,
    reasoning_effort: str,
) -> dict[str, Any]:
    gold = resolve_gold(case)
    contract = expected_contract(gold, stage, validation_steps)
    expected_provenance = provenance_payload(
        run_json,
        gold,
        validation_steps,
        judge_model,
        reasoning_effort,
    )
    first = effective_score_path(
        score_root,
        "review1",
        model,
        stage,
        instance_id,
        expected_provenance,
    )
    second = effective_score_path(
        score_root,
        "review2",
        model,
        stage,
        instance_id,
        expected_provenance,
    )
    if first is None or second is None:
        raise ValueError(
            f"no effective review pair for {model}/{stage}/{instance_id}"
        )
    totals1 = score_totals(first)
    totals2 = score_totals(second)
    differences = {
        key: {"review1": totals1.get(key), "review2": totals2.get(key)}
        for key in sorted(set(totals1) | set(totals2))
        if normalized(totals1.get(key)) != normalized(totals2.get(key))
    }
    quality1, fingerprint1 = review_quality(
        first, contract, expected_provenance
    )
    quality2, fingerprint2 = review_quality(
        second, contract, expected_provenance
    )
    item_differences = {
        key: {"review1": fingerprint1[key], "review2": fingerprint2[key]}
        for key in ("gold_items", "order_pairs", "candidate_slots")
        if fingerprint1[key] != fingerprint2[key]
    }
    item_level_match = not item_differences
    totals_match = not differences
    schema_valid = quality1["schema_valid"] and quality2["schema_valid"]
    denominator_match = (
        quality1["denominator_match"] and quality2["denominator_match"]
    )
    completeness_valid = all(
        quality[f"{key}_complete"]
        for quality in (quality1, quality2)
        for key in ("gold_item_set", "order_pair_set", "candidate_slot")
    )
    provenance_match = (
        quality1["provenance_match"] and quality2["provenance_match"]
    )
    reference_valid = (
        quality1["reference_valid"] and quality2["reference_valid"]
    )
    totals_recompute_match = (
        quality1["totals_recompute_match"]
        and quality2["totals_recompute_match"]
    )
    quality_valid = (
        schema_valid
        and denominator_match
        and completeness_valid
        and reference_valid
        and totals_recompute_match
    )
    two_review_adoptable = (
        quality_valid
        and provenance_match
        and totals_match
        and item_level_match
    )
    return {
        "model": model,
        "stage": stage,
        "instance_id": instance_id,
        "run_json": str(run_json.relative_to(result_root)),
        "gold": str(gold.relative_to(ROOT)),
        "review1": str(first.relative_to(score_root)),
        "review2": str(second.relative_to(score_root)),
        "review1_selected_source": str(first.relative_to(score_root)),
        "review2_selected_source": str(second.relative_to(score_root)),
        "review1_quality": quality1,
        "review2_quality": quality2,
        "schema_valid": schema_valid,
        "denominator_match": denominator_match,
        "completeness_valid": completeness_valid,
        "reference_valid": reference_valid,
        "totals_recompute_match": totals_recompute_match,
        "quality_valid": quality_valid,
        "provenance_match": provenance_match,
        "totals_match": totals_match,
        "item_level_match": item_level_match,
        "two_review_adoptable": two_review_adoptable,
        "total_differences": differences,
        "item_level_differences": item_differences,
        "provenance_sha256": expected_provenance["provenance_sha256"],
        "formal_action_totals_review1": {
            key: totals1.get(key) for key in ACTION_TOTAL_KEYS
        },
        "formal_action_totals_review2": {
            key: totals2.get(key) for key in ACTION_TOTAL_KEYS
        },
    }


def adjudication_identity(category: str, row: dict[str, Any]) -> str:
    if category == "gold_items":
        return f"{row.get('item_id')}|{row.get('kind')}"
    if category == "order_pairs":
        return str(row.get("pair_id"))
    return canonical_hash(
        {
            "chain_id": row.get("chain_id"),
            "candidate_step_id": row.get("candidate_step_id"),
            "kind": row.get("kind"),
            "candidate_slot_excerpt": row.get("candidate_slot_excerpt"),
        }
    )


def adjudication_decision(category: str, row: dict[str, Any]) -> dict[str, Any]:
    if category in {"gold_items", "order_pairs"}:
        return {"score": row.get("score")}
    return {
        "matched_gold_item_id": row.get("matched_gold_item_id"),
        "is_true_positive": row.get("is_true_positive"),
        "false_positive_type": row.get("false_positive_type"),
    }


def totals_from_adjudicated_items(
    fingerprint: dict[str, list[dict[str, Any]]],
    contract: dict[str, Any],
) -> dict[str, Any]:
    action_kinds = {"subject", "operation", "object", "command_line"}
    expected_kinds = contract["gold_item_kinds"]
    gold_items = fingerprint["gold_items"]
    order_pairs = fingerprint["order_pairs"]
    candidate_slots = fingerprint["candidate_slots"]
    covered_steps = {
        row["item_id"].rsplit(":", 1)[0]
        for row in gold_items
        if row["score"] == 1 and row["kind"] in action_kinds
    }
    action_recall_hits = sum(
        row["score"] == 1 and row["kind"] in action_kinds
        for row in gold_items
    )
    critical_hits = sum(
        row["score"] == 1 and row["kind"] == "critical_evidence"
        for row in gold_items
    )
    matched_ids = {
        row["matched_gold_item_id"]
        for row in candidate_slots
        if row["is_true_positive"] == 1
        and row["matched_gold_item_id"] in expected_kinds
    }
    action_matched_ids = {
        item_id
        for item_id in matched_ids
        if expected_kinds[item_id] in action_kinds
    }
    maxima = contract["maxima"]
    candidate_total = len(candidate_slots)
    totals = {
        "behavior_step_recall_hits": len(covered_steps),
        "behavior_step_recall_total": maxima["gold_step_count"],
        "action_step_recall_hits": int(action_recall_hits),
        "action_step_recall_total": maxima["gold_action_required_item_count"],
        "action_step_precision_hits": len(action_matched_ids),
        "action_step_precision_total": maxima["gold_action_required_item_count"],
        "behavior_sequence_order_hits": sum(
            row["score"] == 1 for row in order_pairs
        ),
        "behavior_sequence_order_total": maxima["gold_order_pair_count"],
        "critical_evidence_recall_hits": int(critical_hits),
        "critical_evidence_recall_total": (
            maxima["gold_required_item_count"]
            - maxima["gold_action_required_item_count"]
        ),
        "candidate_claim_precision_hits": len(matched_ids),
        "candidate_claim_precision_total": candidate_total,
        "action_denominator_excludes_critical_evidence": True,
    }
    for metric in (
        "behavior_step_recall",
        "action_step_recall",
        "action_step_precision",
        "behavior_sequence_order",
        "critical_evidence_recall",
        "candidate_claim_precision",
    ):
        hits = totals[f"{metric}_hits"]
        total = totals[f"{metric}_total"]
        totals[metric] = hits / total if total else None
    return totals


def adjudicate_three_reviews(
    score_root: Path,
    run_json: Path,
    case: dict[str, Any],
    model: str,
    stage: str,
    instance_id: str,
    validation_steps: Path,
    judge_model: str,
    reasoning_effort: str,
) -> dict[str, Any]:
    gold = resolve_gold(case)
    contract = expected_contract(gold, stage, validation_steps)
    expected_provenance = provenance_payload(
        run_json,
        gold,
        validation_steps,
        judge_model,
        reasoning_effort,
    )
    paths = {
        review: effective_score_path(
            score_root,
            review,
            model,
            stage,
            instance_id,
            expected_provenance,
        )
        for review in ("review1", "review2", "review3")
    }
    if any(path is None for path in paths.values()):
        raise ValueError(
            f"no effective three-review set for {model}/{stage}/{instance_id}"
        )
    qualities: dict[str, dict[str, Any]] = {}
    fingerprints: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for review, path in paths.items():
        assert path is not None
        qualities[review], fingerprints[review] = review_quality(
            path, contract, expected_provenance
        )

    unresolved: list[dict[str, Any]] = []
    resolved: dict[str, list[dict[str, Any]]] = {
        "gold_items": [],
        "order_pairs": [],
        "candidate_slots": [],
    }
    sources: Counter[str] = Counter()
    for category in resolved:
        by_review = {
            review: {
                adjudication_identity(category, row): row
                for row in fingerprints[review][category]
            }
            for review in ("review1", "review2", "review3")
        }
        for identity in sorted(
            set().union(*(set(rows) for rows in by_review.values()))
        ):
            votes: dict[str, list[str]] = {}
            records: dict[str, dict[str, Any]] = {}
            for review, rows in by_review.items():
                row = rows.get(identity)
                if row is None:
                    continue
                decision = adjudication_decision(category, row)
                encoded = json.dumps(
                    decision,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                votes.setdefault(encoded, []).append(review)
                records[encoded] = row
            majority = [
                (encoded, reviewers)
                for encoded, reviewers in votes.items()
                if len(reviewers) >= 2
            ]
            if len(majority) != 1:
                unresolved.append(
                    {
                        "category": category,
                        "identity": identity,
                        "votes": votes,
                        "reason": "no_unique_two_of_three_majority",
                    }
                )
                continue
            encoded, reviewers = majority[0]
            source = "+".join(sorted(reviewers))
            sources[source] += 1
            resolved[category].append(
                {
                    **records[encoded],
                    "adjudication_source": source,
                    "adjudication_rule": "two_of_three_item_level_majority",
                }
            )

    quality_failures = {
        review: {
            key: quality.get(key)
            for key in FORMAL_REVIEW_QUALITY_KEYS
            if quality.get(key) is not True
        }
        for review, quality in qualities.items()
    }
    quality_failures = {
        review: failures
        for review, failures in quality_failures.items()
        if failures
    }
    all_review_totals = {}
    for review, path in paths.items():
        assert path is not None
        all_review_totals[review] = score_totals(path)
    adjudication_pass = not quality_failures
    totals: dict[str, Any] | None = None
    rule = (
        "two_of_three_item_level_majority_then_conservative_"
        "min_hits_max_candidate_denominator"
    )
    if adjudication_pass:
        majority_totals = totals_from_adjudicated_items(resolved, contract)
        maxima = contract["maxima"]
        gold_complete = (
            len(resolved["gold_items"]) == maxima["gold_required_item_count"]
        )
        order_complete = (
            len(resolved["order_pairs"]) == maxima["gold_order_pair_count"]
        )
        candidate_complete = len(unresolved) == 0
        totals = {}
        fixed_totals = {
            "behavior_step_recall": maxima["gold_step_count"],
            "action_step_recall": maxima["gold_action_required_item_count"],
            "action_step_precision": maxima["gold_action_required_item_count"],
            "behavior_sequence_order": maxima["gold_order_pair_count"],
            "critical_evidence_recall": (
                maxima["gold_required_item_count"]
                - maxima["gold_action_required_item_count"]
            ),
        }
        for metric, total in fixed_totals.items():
            category_complete = (
                gold_complete
                if metric
                in {
                    "behavior_step_recall",
                    "action_step_recall",
                    "critical_evidence_recall",
                }
                else order_complete
                if metric == "behavior_sequence_order"
                else candidate_complete
            )
            hits = (
                majority_totals[f"{metric}_hits"]
                if category_complete
                else min(
                    int(review_totals.get(f"{metric}_hits") or 0)
                    for review_totals in all_review_totals.values()
                )
            )
            totals[f"{metric}_hits"] = hits
            totals[f"{metric}_total"] = total
            totals[metric] = hits / total if total else None
        candidate_hits = (
            majority_totals["candidate_claim_precision_hits"]
            if candidate_complete
            else min(
                int(
                    review_totals.get("candidate_claim_precision_hits") or 0
                )
                for review_totals in all_review_totals.values()
            )
        )
        candidate_total = (
            majority_totals["candidate_claim_precision_total"]
            if candidate_complete
            else max(
                int(
                    review_totals.get("candidate_claim_precision_total") or 0
                )
                for review_totals in all_review_totals.values()
            )
        )
        totals.update(
            {
                "candidate_claim_precision_hits": candidate_hits,
                "candidate_claim_precision_total": candidate_total,
                "candidate_claim_precision": (
                    candidate_hits / candidate_total
                    if candidate_total
                    else None
                ),
                "action_denominator_excludes_critical_evidence": True,
            }
        )
    return {
        "model": model,
        "stage": stage,
        "instance_id": instance_id,
        "adjudication_pass": adjudication_pass,
        "adjudication_rule": rule,
        "adjudication_source_counts": dict(sources),
        "review_quality": qualities,
        "quality_failures": quality_failures,
        "conservatively_resolved_items": unresolved,
        "conservative_resolution_used": bool(unresolved),
        "resolved_item_counts": {
            category: len(rows) for category, rows in resolved.items()
        },
        "adjudicated_items": resolved if adjudication_pass else None,
        "adjudicated_totals": totals,
    }


def rebuild_ledgers(
    score_root: Path,
    result_root: Path,
    cases: dict[str, dict[str, Any]],
    validation_steps: Path,
    judge_model: str,
    reasoning_effort: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run_json in discover_runs(result_root):
        model, stage, instance_id = run_identity(run_json, result_root)
        case = cases.get(instance_id)
        if case is None:
            continue
        gold = resolve_gold(case)
        expected_provenance = provenance_payload(
            run_json,
            gold,
            validation_steps,
            judge_model,
            reasoning_effort,
        )
        first = effective_score_path(
            score_root,
            "review1",
            model,
            stage,
            instance_id,
            expected_provenance,
        )
        second = effective_score_path(
            score_root,
            "review2",
            model,
            stage,
            instance_id,
            expected_provenance,
        )
        if first is None or second is None:
            continue
        payload = comparison_payload(
            score_root,
            result_root,
            run_json,
            case,
            model,
            stage,
            instance_id,
            validation_steps,
            judge_model,
            reasoning_effort,
        )
        payload["adjudication_pass"] = False
        payload["adjudication_rule"] = None
        payload["adjudication_source"] = None
        review3 = effective_score_path(
            score_root,
            "review3",
            model,
            stage,
            instance_id,
            expected_provenance,
        )
        if not payload["two_review_adoptable"] and review3 is not None:
            adjudication = adjudicate_three_reviews(
                score_root,
                run_json,
                case,
                model,
                stage,
                instance_id,
                validation_steps,
                judge_model,
                reasoning_effort,
            )
            adjudication_path = (
                score_root
                / "adjudications"
                / model
                / stage
                / instance_id
                / "adjudication_summary.json"
            )
            write_json(adjudication_path, adjudication)
            payload["adjudication_pass"] = adjudication["adjudication_pass"]
            payload["adjudication_rule"] = adjudication["adjudication_rule"]
            payload["adjudication_source"] = str(
                adjudication_path.relative_to(score_root)
            )
            payload["adjudicated_totals"] = adjudication[
                "adjudicated_totals"
            ]
        comparison = (
            score_root
            / "comparisons"
            / model
            / stage
            / instance_id
            / "review_pair_summary.json"
        )
        write_json(comparison, payload)
        rows.append(payload)

    jsonl = score_root / "double_review_log.jsonl"
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    jsonl.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    fields = [
        "model",
        "stage",
        "instance_id",
        "review1",
        "review2",
        "totals_match",
        "item_level_match",
        "schema_valid",
        "denominator_match",
        "completeness_valid",
        "reference_valid",
        "totals_recompute_match",
        "quality_valid",
        "provenance_match",
        "two_review_adoptable",
        "adjudication_pass",
        "adjudication_rule",
        "adjudication_source",
        "different_total_keys",
    ]
    with (score_root / "double_review_summary.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **{key: row.get(key, "") for key in fields},
                    "different_total_keys": ",".join(row["total_differences"]),
                }
            )

    adopted = [
        row
        for row in rows
        if row["two_review_adoptable"] or row.get("adjudication_pass") is True
    ]
    conflicts = [
        {
            "model": row["model"],
            "stage": row["stage"],
            "instance_id": row["instance_id"],
            "reason": "two_review_gate_failed",
            "failed_gates": [
                gate
                for gate in (
                    "schema_valid",
                    "denominator_match",
                    "completeness_valid",
                    "reference_valid",
                    "totals_recompute_match",
                    "quality_valid",
                    "provenance_match",
                    "totals_match",
                    "item_level_match",
                )
                if not row[gate]
            ],
            "comparison": str(
                Path("comparisons")
                / row["model"]
                / row["stage"]
                / row["instance_id"]
                / "review_pair_summary.json"
            ),
        }
        for row in rows
        if not row["two_review_adoptable"]
        and row.get("adjudication_pass") is not True
    ]
    adjudicated = [
        row for row in rows if row.get("adjudication_pass") is True
    ]
    for name, ledger_rows in (
        ("adopted_double_reviews.jsonl", adopted),
        ("resolved_by_third_review.jsonl", adjudicated),
        ("review_conflicts.jsonl", conflicts),
    ):
        (score_root / name).write_text(
            "".join(
                json.dumps(row, ensure_ascii=False) + "\n"
                for row in ledger_rows
            ),
            encoding="utf-8",
        )

    invalid_artifacts: list[dict[str, Any]] = []
    for run_json in discover_runs(result_root):
        model, stage, instance_id = run_identity(run_json, result_root)
        case = cases.get(instance_id)
        if case is None:
            continue
        expected_provenance = provenance_payload(
            run_json,
            resolve_gold(case),
            validation_steps,
            judge_model,
            reasoning_effort,
        )
        for review in ("review1", "review2", "review3"):
            selected = effective_score_path(
                score_root,
                review,
                model,
                stage,
                instance_id,
                expected_provenance,
            )
            for candidate in review_score_candidates(
                score_root, review, model, stage, instance_id
            ):
                if not path_exists(candidate) or valid_score_payload(candidate):
                    continue
                invalid_artifacts.append(
                    {
                        "model": model,
                        "stage": stage,
                        "instance_id": instance_id,
                        "review": review,
                        "invalid_score_result": str(
                            candidate.relative_to(score_root)
                        ),
                        "invalid_score_sha256": sha256_file(candidate),
                        "superseded_by": (
                            str(selected.relative_to(score_root))
                            if selected is not None
                            else None
                        ),
                        "run_rejected": selected is None,
                    }
                )
    (score_root / "invalid_score_artifacts.jsonl").write_text(
        "".join(
            json.dumps(row, ensure_ascii=False) + "\n"
            for row in invalid_artifacts
        ),
        encoding="utf-8",
    )

    aggregate: dict[str, Any] = {
        "policy": (
            "Include only two_review_adoptable pairs or conflicts resolved by "
            "formal review3 adjudication. Unresolved conflicts and stale scores "
            "are excluded."
        ),
        "adopted_run_count": len(adopted),
        "third_review_adjudicated_count": len(adjudicated),
        "excluded_conflict_count": len(conflicts),
        "by_stage": {},
    }
    for stage in ("stage1", "stage2", "stage3"):
        stage_rows = [row for row in adopted if row["stage"] == stage]
        metrics: dict[str, Any] = {}
        for metric in (
            "behavior_step_recall",
            "action_step_recall",
            "action_step_precision",
            "behavior_sequence_order",
            "critical_evidence_recall",
            "candidate_claim_precision",
        ):
            hits = sum(
                int(
                    (
                        row.get("adjudicated_totals")
                        if row.get("adjudication_pass")
                        else row["formal_action_totals_review1"]
                    ).get(f"{metric}_hits")
                    or 0
                )
                for row in stage_rows
            )
            total = sum(
                int(
                    (
                        row.get("adjudicated_totals")
                        if row.get("adjudication_pass")
                        else row["formal_action_totals_review1"]
                    ).get(f"{metric}_total")
                    or 0
                )
                for row in stage_rows
            )
            metrics[metric] = {
                "hits": hits,
                "total": total,
                "value": hits / total if total else None,
            }
        aggregate["by_stage"][stage] = {
            "adopted_run_count": len(stage_rows),
            "metrics": metrics,
        }
    write_json(score_root / "formal_aggregate_adopted_only.json", aggregate)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--result-root", type=Path, default=RESULT_ROOT)
    parser.add_argument("--score-root", type=Path, default=DEFAULT_SCORE_ROOT)
    parser.add_argument("--validation-steps", type=Path, default=VALIDATION_STEPS)
    parser.add_argument("--judge-model", default="gpt-5")
    parser.add_argument("--reasoning-effort", default="high")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Deprecated and rejected: formal scoring never overwrites an existing "
            "score_result.json; use a new --score-root."
        ),
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Validate and list eligible runs without judge API calls.",
    )
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="Rebuild comparisons/ledgers without judge API calls.",
    )
    parser.add_argument(
        "--bootstrap-provenance",
        action="store_true",
        help=(
            "Attach current hashes to already-created valid score payloads. "
            "Use only for results known to have been generated by this exact command."
        ),
    )
    parser.add_argument(
        "--adjudicate-conflicts",
        action="store_true",
        help=(
            "Score only unresolved two-review conflicts with review3, then "
            "apply the documented 2-of-3/conservative formal rule."
        ),
    )
    parser.add_argument(
        "--retry-invalid-scores",
        action="store_true",
        help=(
            "Write one new versioned retry for each latest schema-invalid or "
            "formal-quality-failed review artifact. Originals are never "
            "overwritten."
        ),
    )
    args = parser.parse_args()

    if args.force:
        parser.error(
            "--force is prohibited by the formal non-overwrite contract; "
            "use a new --score-root"
        )

    cases = case_index(args.cases)
    discovered = discover_runs(args.result_root)
    eligible: list[tuple[Path, str, str, str]] = []
    rejected: list[dict[str, str]] = []
    for run_json in discovered:
        model, stage, instance_id = run_identity(run_json, args.result_root)
        valid, reason = completed_run(run_json, model, stage, instance_id)
        if instance_id not in cases:
            valid, reason = False, "instance_id not found in cases"
        if valid:
            eligible.append((run_json, model, stage, instance_id))
        else:
            rejected.append({"run_json": str(run_json), "reason": str(reason)})
    if args.limit is not None:
        eligible = eligible[: args.limit]

    args.score_root.mkdir(parents=True, exist_ok=True)
    manifest_path = args.score_root / "double_review_manifest.json"
    created_at = utc_now()
    if manifest_path.is_file():
        try:
            created_at = str(read_json(manifest_path).get("created_at_utc") or created_at)
        except Exception:
            pass
    write_json(
        manifest_path,
        {
            "created_at_utc": created_at,
            "updated_at_utc": utc_now(),
            "cases": str(args.cases),
            "result_root": str(args.result_root),
            "score_root": str(args.score_root),
            "validation_steps": str(args.validation_steps),
            "scorer": str(SCORER),
            "judge_model": args.judge_model,
            "reasoning_effort": args.reasoning_effort,
            "base_reviews_per_run": 2,
            "optional_adjudication_reviews_per_conflict": 1,
            "maximum_reviews_per_conflicted_run": 3,
            "target_count": 24,
            "scoring_definition": "formal_normal_action_claim_metrics",
            "action_denominator_excludes_critical_evidence": True,
            "invalid_score_retry_policy": (
                "Never overwrite. One new reviewN_retry_XX version per "
                "--retry-invalid-scores invocation for schema-invalid or "
                "formal-quality-failed artifacts; latest valid retry wins."
            ),
        },
    )

    score_api_calls = 0
    stale_scores: list[dict[str, str]] = []
    for run_json, model, stage, instance_id in eligible:
        case = cases[instance_id]
        gold = resolve_gold(case)
        expected_provenance = provenance_payload(
            run_json,
            gold,
            args.validation_steps,
            args.judge_model,
            args.reasoning_effort,
        )
        for review in ("review1", "review2"):
            candidates = review_score_candidates(
                args.score_root, review, model, stage, instance_id
            )
            for candidate in candidates:
                is_base_review = (
                    candidate.relative_to(args.score_root).parts[0] == review
                )
                if (
                    args.bootstrap_provenance
                    and is_base_review
                    and valid_score_payload(candidate)
                ):
                    write_provenance(candidate, expected_provenance)
            if effective_score_path(
                args.score_root,
                review,
                model,
                stage,
                instance_id,
                expected_provenance,
            ) is not None:
                continue
            existing = [candidate for candidate in candidates if path_exists(candidate)]
            if existing:
                latest = existing[-1]
                if (
                    args.retry_invalid_scores
                    and not valid_score_payload(latest)
                    and not (
                        args.list_only
                        or args.audit_only
                        or args.adjudicate_conflicts
                    )
                ):
                    retry_review = next_retry_review_name(
                        args.score_root,
                        review,
                        model,
                        stage,
                        instance_id,
                    )
                    destination = score_dir(
                        args.score_root,
                        retry_review,
                        model,
                        stage,
                        instance_id,
                    )
                    retry_provenance = {
                        **expected_provenance,
                        "supersedes_score_result": str(
                            latest.relative_to(args.score_root)
                        ),
                        "supersedes_score_sha256": sha256_file(latest),
                        "retry_reason": "json_parse_error",
                        "retry_review": retry_review,
                    }
                    retry_provenance["retry_provenance_sha256"] = canonical_hash(
                        retry_provenance
                    )
                    run_scorer(
                        run_json,
                        destination,
                        gold,
                        stage,
                        args.validation_steps,
                        args.judge_model,
                        args.reasoning_effort,
                        retry_provenance,
                    )
                    score_api_calls += 1
                    print(
                        json.dumps(
                            {
                                "scored": instance_id,
                                "model": model,
                                "stage": stage,
                                "review": review,
                                "retry_review": retry_review,
                                "supersedes": str(
                                    latest.relative_to(args.score_root)
                                ),
                            },
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                    continue
                stale_scores.append(
                    {
                        "review": review,
                        "instance_id": instance_id,
                        "score_result": str(latest),
                        "reason": (
                            "missing_or_stale_provenance"
                            if valid_score_payload(latest)
                            else "existing_invalid_score_not_overwritten"
                        ),
                    }
                )
                continue
            if args.list_only or args.audit_only or args.adjudicate_conflicts:
                continue
            destination = score_dir(
                args.score_root, review, model, stage, instance_id
            )
            run_scorer(
                run_json,
                destination,
                gold,
                stage,
                args.validation_steps,
                args.judge_model,
                args.reasoning_effort,
                expected_provenance,
            )
            score_api_calls += 1
            print(
                json.dumps(
                    {
                        "scored": instance_id,
                        "model": model,
                        "stage": stage,
                        "review": review,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

    rows = rebuild_ledgers(
        args.score_root,
        args.result_root,
        cases,
        args.validation_steps,
        args.judge_model,
        args.reasoning_effort,
    )
    if args.adjudicate_conflicts:
        unresolved_keys = {
            (row["model"], row["stage"], row["instance_id"])
            for row in rows
            if not row["two_review_adoptable"]
            and row.get("adjudication_pass") is not True
        }
        for run_json, model, stage, instance_id in eligible:
            if (model, stage, instance_id) not in unresolved_keys:
                continue
            case = cases[instance_id]
            gold = resolve_gold(case)
            expected_provenance = provenance_payload(
                run_json,
                gold,
                args.validation_steps,
                args.judge_model,
                args.reasoning_effort,
            )
            review = "review3"
            candidates = review_score_candidates(
                args.score_root, review, model, stage, instance_id
            )
            effective = effective_score_path(
                args.score_root,
                review,
                model,
                stage,
                instance_id,
                expected_provenance,
            )
            existing = [candidate for candidate in candidates if path_exists(candidate)]
            retry_source: Path | None = None
            retry_reason: str | None = None
            if effective is not None:
                if args.retry_invalid_scores:
                    contract = expected_contract(
                        gold, stage, args.validation_steps
                    )
                    quality, _ = review_quality(
                        effective, contract, expected_provenance
                    )
                    failed_quality_keys = [
                        key
                        for key in FORMAL_REVIEW_QUALITY_KEYS
                        if quality.get(key) is not True
                    ]
                    if failed_quality_keys:
                        retry_source = effective
                        retry_reason = (
                            "formal_quality_failure:"
                            + ",".join(failed_quality_keys)
                        )
                if retry_source is None:
                    continue
            elif existing:
                latest = existing[-1]
                if args.retry_invalid_scores and not valid_score_payload(latest):
                    retry_source = latest
                    retry_reason = "json_parse_error"
                else:
                    stale_scores.append(
                        {
                            "review": review,
                            "instance_id": instance_id,
                            "score_result": str(latest),
                            "reason": (
                                "missing_or_stale_provenance"
                                if valid_score_payload(latest)
                                else "existing_invalid_score_not_overwritten"
                            ),
                        }
                    )
                    continue
            if retry_source is not None:
                assert retry_reason is not None
                latest = retry_source
                if args.retry_invalid_scores:
                    retry_review = next_retry_review_name(
                        args.score_root,
                        review,
                        model,
                        stage,
                        instance_id,
                    )
                    destination = score_dir(
                        args.score_root,
                        retry_review,
                        model,
                        stage,
                        instance_id,
                    )
                    retry_provenance = {
                        **expected_provenance,
                        "supersedes_score_result": str(
                            latest.relative_to(args.score_root)
                        ),
                        "supersedes_score_sha256": sha256_file(latest),
                        "retry_reason": retry_reason,
                        "retry_review": retry_review,
                    }
                    retry_provenance["retry_provenance_sha256"] = canonical_hash(
                        retry_provenance
                    )
                    run_scorer(
                        run_json,
                        destination,
                        gold,
                        stage,
                        args.validation_steps,
                        args.judge_model,
                        args.reasoning_effort,
                        retry_provenance,
                    )
                    score_api_calls += 1
                    print(
                        json.dumps(
                            {
                                "scored": instance_id,
                                "model": model,
                                "stage": stage,
                                "review": review,
                                "retry_review": retry_review,
                                "supersedes": str(
                                    latest.relative_to(args.score_root)
                                ),
                            },
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                    continue
            destination = score_dir(
                args.score_root, review, model, stage, instance_id
            )
            run_scorer(
                run_json,
                destination,
                gold,
                stage,
                args.validation_steps,
                args.judge_model,
                args.reasoning_effort,
                expected_provenance,
            )
            score_api_calls += 1
            print(
                json.dumps(
                    {
                        "scored": instance_id,
                        "model": model,
                        "stage": stage,
                        "review": review,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        rows = rebuild_ledgers(
            args.score_root,
            args.result_root,
            cases,
            args.validation_steps,
            args.judge_model,
            args.reasoning_effort,
        )
    two_review_adoptable = [
        row for row in rows if row["two_review_adoptable"]
    ]
    third_review_adjudicated = [
        row for row in rows if row.get("adjudication_pass") is True
    ]
    formally_adopted = [
        row
        for row in rows
        if row["two_review_adoptable"]
        or row.get("adjudication_pass") is True
    ]
    status = {
        "updated_at_utc": utc_now(),
        "available_run_jsons": len(discovered),
        "eligible_completed_runs": len(eligible),
        "completed_double_review_pairs": len(rows),
        "two_review_adoptable_pairs": len(two_review_adoptable),
        "third_review_adjudicated_pairs": len(third_review_adjudicated),
        "formally_adopted_pairs": len(formally_adopted),
        "conflict_pairs": len(rows) - len(formally_adopted),
        "score_api_calls_this_call": score_api_calls,
        "stage_counts": dict(Counter(row["stage"] for row in rows)),
        "adopted_stage_counts": dict(
            Counter(row["stage"] for row in formally_adopted)
        ),
        "two_review_adopted_stage_counts": dict(
            Counter(row["stage"] for row in two_review_adoptable)
        ),
        "third_review_adjudicated_stage_counts": dict(
            Counter(row["stage"] for row in third_review_adjudicated)
        ),
        "review_pairs_with_total_differences": sum(
            not row["totals_match"] for row in rows
        ),
        "review_pairs_with_item_level_differences": sum(
            not row["item_level_match"] for row in rows
        ),
        "stale_scores_rejected": stale_scores,
        "rejected_runs": rejected,
        "list_only": args.list_only,
        "audit_only": args.audit_only,
        "bootstrap_provenance": args.bootstrap_provenance,
        "adjudicate_conflicts": args.adjudicate_conflicts,
        "retry_invalid_scores": args.retry_invalid_scores,
    }
    write_json(args.score_root / "double_review_status.json", status)
    print(json.dumps(status, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
