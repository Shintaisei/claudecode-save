#!/usr/bin/env python3
"""Create-only v5 normalization of the v4 double-blind atomic reviews.

The only changed score source is action-element recall: subject, operation,
and object scores are derived from literal included TP candidate slots.  The
reviewers' candidate-slot, critical-evidence, and order judgments are copied
without interpretation.  No API calls are made.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/two_model_baseline_replicate_01"
SOURCE = BASE / "scores_codex_manual_double_review_v4_pid_non_scoring_hardened"
OUT = BASE / "scores_codex_manual_double_review_v5_atomic_alignment"
SOURCE_FILES = ("raw_review1_v4.jsonl", "raw_review2_v4.jsonl", "queue_self_validation_v4.json")
ACTION_KINDS = {"subject", "operation", "object"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canon(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def step_id(item_id: str) -> str:
    return item_id.rsplit(":", 1)[0]


def snapshot_old_trees() -> dict[str, str]:
    """Hash every readable regular file in v1--v4 trees; dangling OneDrive items are excluded."""
    snapshot: dict[str, str] = {}
    for tree in sorted(BASE.glob("scores_codex_manual_double_review_v[1-4]*")):
        for directory, _, names in os.walk(tree):
            for name in names:
                path = Path(directory) / name
                try:
                    if path.is_file():
                        snapshot[str(path.relative_to(BASE)).replace("\\", "/")] = sha256_file(path)
                except OSError:
                    pass
    return snapshot


def normalize(row: dict) -> dict:
    out = json.loads(json.dumps(row))  # preserve reviewer wording and all non-derived fields
    gold = {x["item_id"]: x for x in out["gold_items"]}
    action_ids = {item_id for item_id, item in gold.items() if item["kind"] in ACTION_KINDS}
    hits: set[str] = set()
    errors: list[str] = []
    for slot in out["candidate_slots"]:
        included_tp = slot.get("include_in_denominator") == 1 and slot.get("is_true_positive") == 1
        if slot.get("is_true_positive") == 1 and slot.get("include_in_denominator") != 1:
            errors.append(f"TP_NOT_INCLUDED:{slot.get('slot_id')}")
        if not included_tp:
            continue
        target = slot.get("matched_gold_item_id")
        target_item = gold.get(target)
        if target_item is None:
            errors.append(f"TP_UNKNOWN_GOLD:{slot.get('slot_id')}:{target}")
            continue
        if target_item["kind"] not in ACTION_KINDS:
            errors.append(f"TP_NON_ACTION_GOLD:{slot.get('slot_id')}:{target}")
        if slot.get("kind") != target_item["kind"]:
            errors.append(f"TP_KIND_MISMATCH:{slot.get('slot_id')}:{slot.get('kind')}:{target_item['kind']}")
        if slot.get("aligned_gold_step_id") != step_id(target):
            errors.append(f"TP_STEP_MISMATCH:{slot.get('slot_id')}:{slot.get('aligned_gold_step_id')}:{step_id(target)}")
        hits.add(target)
    if errors:
        raise ValueError(f"{out['queue_id']}: " + "; ".join(errors))
    for item in out["gold_items"]:
        if item["kind"] in ACTION_KINDS:
            item["score"] = int(item["item_id"] in hits)
            item["score_source"] = "derived_from_included_tp_matched_gold_item_id"
    out["schema_version"] = "codex_manual_action_claim_review_v5_atomic_alignment"
    out["source_schema_version"] = row["schema_version"]
    out["source_decision_sha256"] = row.get("decision_sha256")
    out["action_score_derivation"] = {
        "rule": "gold action item hit iff an included candidate slot is literal TP and matched_gold_item_id equals the item",
        "matched_action_gold_item_ids": sorted(hits),
        "gold_action_denominator": len(action_ids),
        "gold_action_hit_count": len(hits),
    }
    out["decision_sha256"] = sha256_bytes(canon({k: v for k, v in out.items() if k != "decision_sha256"}))
    return out


def validate(rows: list[dict]) -> dict:
    failures: list[str] = []
    totals = defaultdict(lambda: defaultdict(int))
    for row in rows:
        gold = {x["item_id"]: x for x in row["gold_items"]}
        action = [x for x in row["gold_items"] if x["kind"] in ACTION_KINDS]
        tp_ids = {
            s["matched_gold_item_id"] for s in row["candidate_slots"]
            if s.get("include_in_denominator") == 1 and s.get("is_true_positive") == 1
        }
        for item in action:
            if item["score"] != int(item["item_id"] in tp_ids):
                failures.append(f"GOLD_TP_INCONSISTENT:{row['queue_id']}:{item['item_id']}")
        for target in tp_ids:
            if target not in gold or gold[target]["score"] != 1:
                failures.append(f"TP_GOLD0:{row['queue_id']}:{target}")
        steps = defaultdict(dict)
        for item in action:
            steps[step_id(item["item_id"])][item["kind"]] = item["score"]
        all_three = sum(all(parts.get(k) == 1 for k in ACTION_KINDS) for parts in steps.values())
        key = f"{row['queue_id'].split('/')[0]}/{row['queue_id'].split('/')[1]}"
        t = totals[key]
        t["case_count"] += 1
        t["gold_action_denominator"] += len(action)
        t["gold_action_hits"] += sum(x["score"] for x in action)
        t["candidate_slot_denominator"] += sum(s.get("include_in_denominator") == 1 for s in row["candidate_slots"])
        t["candidate_slot_tp"] += sum(s.get("include_in_denominator") == 1 and s.get("is_true_positive") == 1 for s in row["candidate_slots"])
        critical = [x for x in row["gold_items"] if x["kind"] == "critical_evidence"]
        t["critical_evidence_denominator"] += len(critical)
        t["critical_evidence_hits"] += sum(x["score"] for x in critical)
        t["order_pair_denominator"] += len(row["order_pairs"])
        t["order_pair_hits"] += sum(x["score"] for x in row["order_pairs"])
        t["behavior_step_denominator"] += len(steps)
        t["behavior_step_hits"] += all_three
    for t in totals.values():
        t["action_recall"] = t["gold_action_hits"] / t["gold_action_denominator"]
        t["candidate_precision"] = t["candidate_slot_tp"] / t["candidate_slot_denominator"]
        t["behavior_step_recall"] = t["behavior_step_hits"] / t["behavior_step_denominator"]
        t["critical_evidence_recall"] = t["critical_evidence_hits"] / t["critical_evidence_denominator"]
        t["order_recall"] = t["order_pair_hits"] / t["order_pair_denominator"]
    overall = defaultdict(int)
    for t in totals.values():
        for k, v in t.items():
            if k.endswith(("_recall", "_precision")):
                continue
            overall[k] += v
    for metric, num, den in (
        ("action_recall", "gold_action_hits", "gold_action_denominator"),
        ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"),
        ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"),
        ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"),
        ("order_recall", "order_pair_hits", "order_pair_denominator"),
    ):
        overall[metric] = overall[num] / overall[den]
    return {"status": "pass" if not failures else "fail", "row_count": len(rows), "negative_checks": {"gold1_without_tp": 0 if not failures else None, "tp_gold0": 0 if not failures else None, "all_three_behavior_step": "computed_from_all_subject_operation_object_hits"}, "failures": failures, "by_model_stage": dict(totals), "overall": dict(overall)}


def conflicts(left: list[dict], right: list[dict]) -> dict:
    l_by_q = {r["queue_id"]: r for r in left}
    r_by_q = {r["queue_id"]: r for r in right}
    result = {"candidate_slot_tuple_disagreements": [], "critical_evidence_score_disagreements": [], "order_pair_disagreements": []}
    for queue_id in sorted(l_by_q):
        a, b = l_by_q[queue_id], r_by_q[queue_id]
        slots_a, slots_b = {x["slot_id"]: x for x in a["candidate_slots"]}, {x["slot_id"]: x for x in b["candidate_slots"]}
        for slot_id in sorted(set(slots_a) | set(slots_b)):
            fields = ("include_in_denominator", "is_true_positive", "aligned_gold_step_id", "matched_gold_item_id")
            va = tuple(slots_a.get(slot_id, {}).get(x) for x in fields)
            vb = tuple(slots_b.get(slot_id, {}).get(x) for x in fields)
            if va != vb:
                result["candidate_slot_tuple_disagreements"].append({"queue_id": queue_id, "slot_id": slot_id, "review1": dict(zip(fields, va)), "review2": dict(zip(fields, vb))})
        ce_a = {x["item_id"]: x["score"] for x in a["gold_items"] if x["kind"] == "critical_evidence"}
        ce_b = {x["item_id"]: x["score"] for x in b["gold_items"] if x["kind"] == "critical_evidence"}
        for item_id in sorted(set(ce_a) | set(ce_b)):
            if ce_a.get(item_id) != ce_b.get(item_id):
                result["critical_evidence_score_disagreements"].append({"queue_id": queue_id, "item_id": item_id, "review1_score": ce_a.get(item_id), "review2_score": ce_b.get(item_id)})
        op_a = {x["pair_id"]: x["score"] for x in a["order_pairs"]}
        op_b = {x["pair_id"]: x["score"] for x in b["order_pairs"]}
        for pair_id in sorted(set(op_a) | set(op_b)):
            if op_a.get(pair_id) != op_b.get(pair_id):
                result["order_pair_disagreements"].append({"queue_id": queue_id, "pair_id": pair_id, "review1_score": op_a.get(pair_id), "review2_score": op_b.get(pair_id)})
    result["counts"] = {k: len(v) for k, v in result.items() if isinstance(v, list)}
    result["total_remaining_conflict_items"] = sum(result["counts"].values())
    return result


def main() -> None:
    # A prior interrupted run may have created only the empty directory.  It is
    # safe to resume that state; any material output still causes refusal.
    if OUT.exists() and any(OUT.iterdir()):
        raise SystemExit(f"create-only refusal: output already exists: {OUT}")
    missing = [name for name in SOURCE_FILES if not (SOURCE / name).is_file()]
    if missing:
        raise SystemExit("missing required v4 source files: " + ", ".join(missing))
    old_before = snapshot_old_trees()
    source_hashes = {str((SOURCE / n).relative_to(ROOT)).replace("\\", "/"): sha256_file(SOURCE / n) for n in SOURCE_FILES}
    raw1, raw2 = load_jsonl(SOURCE / SOURCE_FILES[0]), load_jsonl(SOURCE / SOURCE_FILES[1])
    if len(raw1) != 48 or len(raw2) != 48 or {r["queue_id"] for r in raw1} != {r["queue_id"] for r in raw2}:
        raise SystemExit("v4 source reviews do not form the expected identical 48-row queue")
    normalized1, normalized2 = [normalize(r) for r in raw1], [normalize(r) for r in raw2]
    validation1, validation2 = validate(normalized1), validate(normalized2)
    if validation1["status"] != "pass" or validation2["status"] != "pass":
        raise SystemExit("atomic alignment validation failed")
    source_self_validation = json.loads((SOURCE / "queue_self_validation_v4.json").read_text(encoding="utf-8"))
    conflict = conflicts(normalized1, normalized2)
    OUT.mkdir(parents=False, exist_ok=True)
    # The required sibling root is itself long; short child names retain
    # compatibility with Windows' legacy 260-character path limit.
    write_jsonl(OUT / "review1.jsonl", normalized1)
    write_jsonl(OUT / "review2.jsonl", normalized2)
    write_json(OUT / "validation_review1.json", validation1)
    write_json(OUT / "validation_review2.json", validation2)
    write_json(OUT / "conflicts.json", conflict)
    old_after = snapshot_old_trees()
    integrity = {"status": "pass" if old_before == old_after else "fail", "readable_file_count": len(old_before), "before_sha256": sha256_bytes(canon(old_before)), "after_sha256": sha256_bytes(canon(old_after)), "changed_paths": sorted(set(old_before) ^ set(old_after) | {p for p in old_before if old_before[p] != old_after.get(p)})}
    if integrity["status"] != "pass":
        raise SystemExit("old tree integrity check failed")
    write_json(OUT / "integrity.json", integrity)
    binding = {
        "schema_version": "v5_atomic_alignment_source_binding_v1",
        "method": "create-only normalization; action element scores derive solely from included TP matched_gold_item_id coverage",
        "source_root": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "source_file_sha256": source_hashes,
        "v4_queue_manifest_binding": {k: source_self_validation[k] for k in ("queue_sha256", "manifest_sha256", "source_queue_sha256", "review_template_sha256", "overlay_sha256", "run_file_paths_and_hashes_verified", "gold_file_paths_and_hashes_verified", "denominators")},
        "normalized_file_sha256": {p.name: sha256_file(p) for p in (OUT / "review1.jsonl", OUT / "review2.jsonl")},
        "reviewer_provisional_totals": {"review1": validation1, "review2": validation2},
        "conflict_manifest_sha256": sha256_file(OUT / "conflicts.json"),
        "external_api_calls": False,
    }
    write_json(OUT / "manifest.json", binding)
    print(json.dumps({"output": str(OUT), "conflicts": conflict["counts"], "total": conflict["total_remaining_conflict_items"], "output_hashes": binding["normalized_file_sha256"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
