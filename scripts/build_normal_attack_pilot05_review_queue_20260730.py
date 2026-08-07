"""Build a create-only v5 atomic review queue for pilot05.

This script performs no semantic matching and calls no model API. It freezes
the completed run, Gold, validation, candidate action slots, and denominators
so that a later Codex review can make explicit item-level decisions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-30/"
    / "normal_attack_full_ledger_pilot_05"
)
MANIFEST = RESULT_ROOT / "pilot_selection_manifest.json"
OUTPUT_ROOT = RESULT_ROOT / "analysis_codex_single_review_v1"
QUEUE = OUTPUT_ROOT / "review_queue_v1.jsonl"
QUEUE_MANIFEST = OUTPUT_ROOT / "review_queue_manifest_v1.json"
NORMAL_GOLD = (
    ROOT
    / "data/current_experiment/gold/"
    / "normal8_observable_component_v3_gold_20260726/by_chain"
)
ATTACK_GOLD = (
    ROOT
    / "data/current_experiment/gold/"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727/by_chain"
)
RETRY_STAGE_ROOTS = {
    ("normal_chain10_gpt41", 3): (
        RESULT_ROOT
        / "executions"
        / "normal_chain10_gpt41"
        / "s3r2"
    ),
}
ACTION_KINDS = ("subject", "operation", "object")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def stage_root(pair: dict[str, Any], stage: int) -> Path:
    return RETRY_STAGE_ROOTS.get(
        (pair["pair_id"], stage),
        RESULT_ROOT / "executions" / pair["pair_id"] / f"stage{stage}",
    )


def run_path(pair: dict[str, Any], stage: int) -> Path:
    instance_id = f"{pair['chain_id']}_stage{stage}"
    return (
        stage_root(pair, stage)
        / "runs"
        / pair["model"]
        / f"stage{stage}"
        / f"{instance_id}_run.json"
    )


def gold_path(pair: dict[str, Any]) -> Path:
    root = NORMAL_GOLD if pair["scenario_group"] == "normal" else ATTACK_GOLD
    return root / pair["chain_id"] / "chain_gold.json"


def compact(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def expressed(value: Any) -> bool:
    if isinstance(value, dict):
        return any(expressed(item) for item in value.values())
    if isinstance(value, list):
        return any(expressed(item) for item in value)
    return value not in (None, "")


def candidate_slots(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    slots: list[dict[str, Any]] = []
    for index, step in enumerate(candidate.get("code_steps") or [], start=1):
        claim_id = f"C{index}"
        step_id = str(step.get("step_id") or f"S{index}")
        components = {
            "subject": step.get("subject_process"),
            "operation": step.get("operation"),
            "object": step.get("object"),
        }
        for kind in ACTION_KINDS:
            value = components[kind]
            if not expressed(value):
                continue
            slots.append(
                {
                    "candidate_claim_id": claim_id,
                    "candidate_step_id": step_id,
                    "candidate_order": step.get("order", index),
                    "slot_id": f"{claim_id}:{kind}",
                    "kind": kind,
                    "candidate_slot_excerpt": (
                        value if isinstance(value, str) else compact(value)
                    ),
                }
            )
    return slots


def gold_items(gold: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for step in gold["gold_steps"]:
        values = {
            "subject": step["subject"],
            "operation": step["action"],
            "object": step["object"],
            "critical_evidence": step["evidence_basis"],
        }
        for kind, value in values.items():
            items.append(
                {
                    "chain_id": gold["chain_id"],
                    "step_id": step["step_id"],
                    "step_order": step["order"],
                    "item_id": f"{gold['chain_id']}:{step['step_id']}:{kind}",
                    "kind": kind,
                    "gold_value": value,
                    "acceptable_terms": [value],
                }
            )
    return items


def order_pairs(gold: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "chain_id": gold["chain_id"],
            "before_step_id": before,
            "after_step_id": after,
            "pair_id": f"{gold['chain_id']}:{before}->{after}",
        }
        for before, after in gold["gold_order_pairs"]
    ]


def expected_specs() -> list[dict[str, Any]]:
    manifest = read_json(MANIFEST)
    specs: list[dict[str, Any]] = []
    for pair in manifest["pairs"]:
        for stage in (1, 2, 3):
            specs.append(
                {
                    "pair": pair,
                    "stage": stage,
                    "instance_id": f"{pair['chain_id']}_stage{stage}",
                    "run": run_path(pair, stage),
                    "gold": gold_path(pair),
                    "validation": ROOT / pair["validation"],
                }
            )
    return specs


def build_row(spec: dict[str, Any]) -> dict[str, Any]:
    pair = spec["pair"]
    run = read_json(spec["run"])
    gold = read_json(spec["gold"])
    candidate = json.loads(run["output_text"])
    items = gold_items(gold)
    pairs = order_pairs(gold)
    slots = candidate_slots(candidate)
    action_items = [item for item in items if item["kind"] in ACTION_KINDS]
    critical_items = [
        item for item in items if item["kind"] == "critical_evidence"
    ]
    row = {
        "schema_version": "normal_attack_pilot05_v5_atomic_review_queue_v1",
        "pair_id": pair["pair_id"],
        "scenario_group": pair["scenario_group"],
        "model": pair["model"],
        "stage": f"stage{spec['stage']}",
        "instance_id": spec["instance_id"],
        "run_json": str(spec["run"].relative_to(ROOT)),
        "gold_json": str(spec["gold"].relative_to(ROOT)),
        "validation_steps": str(spec["validation"].relative_to(ROOT)),
        "run_sha256": sha256(spec["run"]),
        "gold_sha256": sha256(spec["gold"]),
        "validation_steps_sha256": sha256(spec["validation"]),
        "maxima": {
            "gold_required_item_count": len(items),
            "gold_action_required_item_count": len(action_items),
            "gold_step_count": len(gold["gold_steps"]),
            "gold_critical_evidence_count": len(critical_items),
            "gold_order_pair_count": len(pairs),
            "candidate_slot_count": len(slots),
        },
        "gold_items": items,
        "order_pairs": pairs,
        "candidate_slots": slots,
        "candidate_output": candidate,
        "review_policy": {
            "action_components": list(ACTION_KINDS),
            "action_aliases_operation": True,
            "candidate_slots_are_fixed": True,
            "candidate_denominator_is_fixed": True,
            "critical_evidence_is_separate": True,
            "command_line_is_action_attribute": True,
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "candidate_claim_alignment": (
                "one candidate claim aligns to at most one Gold step; every "
                "TP slot in the claim must reference that same step"
            ),
            "action_hit_derivation": (
                "Gold action hit only from unique included TP candidate-slot "
                "coverage of matched_gold_item_id"
            ),
        },
    }
    contract = {
        key: row[key]
        for key in (
            "pair_id",
            "scenario_group",
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
            "review_policy",
        )
    }
    row["contract_sha256"] = canonical_hash(contract)
    row["queue_id"] = (
        f"{pair['model']}/{row['stage']}/{row['instance_id']}/"
        f"{row['contract_sha256'][:16]}"
    )
    return row


def main() -> None:
    specs = expected_specs()
    missing = [
        str(spec["run"].relative_to(ROOT))
        for spec in specs
        if not spec["run"].is_file()
    ]
    if missing:
        raise SystemExit(
            f"expected 12 completed runs; missing {len(missing)}: "
            + ", ".join(missing)
        )
    rows = [build_row(spec) for spec in specs]
    expected = {
        "row_count": 12,
        "gold_action_denominator": sum(
            row["maxima"]["gold_action_required_item_count"] for row in rows
        ),
        "behavior_step_denominator": sum(
            row["maxima"]["gold_step_count"] for row in rows
        ),
        "critical_evidence_denominator": sum(
            row["maxima"]["gold_critical_evidence_count"] for row in rows
        ),
        "order_pair_denominator": sum(
            row["maxima"]["gold_order_pair_count"] for row in rows
        ),
        "candidate_slot_denominator": sum(
            row["maxima"]["candidate_slot_count"] for row in rows
        ),
    }
    queue_text = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
        for row in rows
    )
    manifest = {
        "schema_version": "normal_attack_pilot05_review_queue_manifest_v1",
        "source_manifest": str(MANIFEST.relative_to(ROOT)),
        "source_manifest_sha256": sha256(MANIFEST),
        "review_queue_sha256": hashlib.sha256(
            queue_text.encode("utf-8")
        ).hexdigest(),
        "expected_denominators": expected,
        "run_hashes": {
            row["queue_id"]: row["run_sha256"] for row in rows
        },
        "gold_hashes": {
            row["queue_id"]: row["gold_sha256"] for row in rows
        },
        "external_judge_api_used": False,
        "status": "PASS",
    }
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    for path in (QUEUE, QUEUE_MANIFEST):
        if path.exists():
            raise FileExistsError(f"create-only target exists: {path}")
    QUEUE.write_text(queue_text, encoding="utf-8")
    QUEUE_MANIFEST.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(QUEUE)
    print(QUEUE_MANIFEST)


if __name__ == "__main__":
    main()
