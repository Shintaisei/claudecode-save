#!/usr/bin/env python3
"""Create the formal v5 atomic-alignment 2-of-3 adjudication and aggregate.

This program is deliberately local-only.  It reads the two normalized blind
reviews and the targeted blind third review, then creates a separate set of
formal artefacts.  Action-element scores are never voted: they are derived
from adopted literal candidate-slot TP matches.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/two_model_baseline_replicate_01"
SRC = BASE / "scores_codex_manual_double_review_v5_atomic_alignment"
# Windows legacy path limits apply in this OneDrive workspace.  The required
# create-only formal artefacts therefore live directly under the v5 root.
OUT = SRC
ACTION = {"subject", "operation", "object"}
TUPLE_FIELDS = ("include_in_denominator", "is_true_positive", "aligned_gold_step_id", "matched_gold_item_id")


def canon(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def load_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def dump_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def dump_jsonl(path, rows):
    path.write_text("".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in rows), encoding="utf-8")


def step_id(item_id):
    return item_id.rsplit(":", 1)[0]


def qmeta(queue_id):
    model, stage, case_stage, _ = queue_id.split("/", 3)
    return model, stage, case_stage.rsplit("_", 1)[0]


def slot_tuple(slot):
    return tuple(slot.get(k) for k in TUPLE_FIELDS)


def r3_candidate_tuple(decision):
    # review3's stored order was fixed as include, aligned step, matched item, TP.
    value = decision["decision"]
    return (value[0], value[3], value[1], value[2])


def mode_or_none(values):
    if not values:
        return None
    counts = Counter(values)
    value, n = counts.most_common(1)[0]
    return value if n >= 2 else None


def choose_candidate(a, b, c, gold_by_id):
    """Return an adopted tuple and the prescribed formal adjudication record."""
    votes = [slot_tuple(a), slot_tuple(b), r3_candidate_tuple(c)]
    exact = mode_or_none(votes)
    fallback = False
    if exact is None:
        fallback = True
        include = min(int(v[0] or 0) for v in votes)
        tp = min(int(v[1] or 0) for v in votes)
        # A conservative TP cannot be retained without an unambiguous valid target.
        candidate_targets = [v[3] for v in votes if v[1] == 1 and v[3] in gold_by_id]
        target = candidate_targets[0] if tp and candidate_targets and len(set(candidate_targets)) == 1 else None
        if target is not None:
            aligned = step_id(target)
        else:
            tp, target = 0, None
            alignment_candidates = [v[2] for v in votes if v[2] is not None]
            aligned = alignment_candidates[0] if alignment_candidates and len(set(alignment_candidates)) == 1 else None
        exact = (include, tp, aligned, target)
    include, tp, aligned, target = exact
    valid = (include in (0, 1) and tp in (0, 1))
    if tp:
        item = gold_by_id.get(target)
        valid = valid and include == 1 and item is not None and item["kind"] == a["kind"] and aligned == step_id(target)
    if not valid:
        raise ValueError(f"invalid adjudicated candidate tuple {a['slot_id']}: {exact}")
    # FP classification is selected only among classifications consistent with final TP/FP.
    provenance = [(slot_tuple(a), a.get("false_positive_type"), "review1"),
                  (slot_tuple(b), b.get("false_positive_type"), "review2"),
                  (r3_candidate_tuple(c), c.get("false_positive_type"), "review3")]
    fp_values = [fp for tup, fp, _ in provenance if tup[1] == tp and fp]
    fp = mode_or_none(fp_values) or (None if tp else next((x for x in fp_values), None))
    selected_reason = next((a.get("reason_ja") for tup, _, _ in provenance if tup == exact), a.get("reason_ja"))
    return exact, {"method": "exact_tuple_2_of_3" if not fallback else "conservative_fallback",
                   "votes": [dict(zip(TUPLE_FIELDS, v)) for v in votes],
                   "adopted": dict(zip(TUPLE_FIELDS, exact)), "false_positive_type": fp,
                   "reason_ja": selected_reason, "fallback_used": fallback}


def binary_vote(a, b, c):
    votes = [int(a), int(b), int(c)]
    return int(sum(votes) >= 2), votes


def derive_actions(row):
    gold = {x["item_id"]: x for x in row["gold_items"]}
    hits = set()
    for slot in row["candidate_slots"]:
        if slot.get("include_in_denominator") == 1 and slot.get("is_true_positive") == 1:
            target = slot.get("matched_gold_item_id")
            item = gold.get(target)
            if not item or item["kind"] not in ACTION or item["kind"] != slot["kind"] or slot.get("aligned_gold_step_id") != step_id(target):
                raise ValueError(f"invalid TP match: {row['queue_id']} {slot['slot_id']}")
            hits.add(target)
    for item in row["gold_items"]:
        if item["kind"] in ACTION:
            item["score"] = int(item["item_id"] in hits)
            item["score_source"] = "derived_from_adopted_included_tp_matched_gold_item_id"
    row["action_score_derivation"] = {"rule": "Gold subject/operation/object hit iff adopted included TP slot matches exactly", "matched_action_gold_item_ids": sorted(hits), "gold_action_hit_count": len(hits)}
    return hits


def metric_block(rows):
    t = defaultdict(int)
    fp_types = Counter()
    duplicate = 0
    for row in rows:
        action = [x for x in row["gold_items"] if x["kind"] in ACTION]
        critical = [x for x in row["gold_items"] if x["kind"] == "critical_evidence"]
        pairs = row["order_pairs"]
        targets = [s["matched_gold_item_id"] for s in row["candidate_slots"] if s.get("include_in_denominator") == 1 and s.get("is_true_positive") == 1]
        duplicate += len(targets) - len(set(targets))
        for slot in row["candidate_slots"]:
            if slot.get("include_in_denominator") == 1:
                t["candidate_slot_denominator"] += 1
                if slot.get("is_true_positive") == 1:
                    t["candidate_slot_tp"] += 1
                else:
                    t["candidate_slot_fp"] += 1
                    fp_types[slot.get("false_positive_type") or "unclassified"] += 1
        t["case_count"] += 1
        t["gold_action_denominator"] += len(action)
        t["gold_action_hits"] += sum(x["score"] for x in action)
        t["critical_evidence_denominator"] += len(critical)
        t["critical_evidence_hits"] += sum(x["score"] for x in critical)
        t["order_pair_denominator"] += len(pairs)
        t["order_pair_hits"] += sum(x["score"] for x in pairs)
        steps = defaultdict(dict)
        for x in action:
            steps[step_id(x["item_id"])][x["kind"]] = x["score"]
        t["behavior_step_denominator"] += len(steps)
        t["behavior_step_hits"] += sum(all(p.get(k) == 1 for k in ACTION) for p in steps.values())
    t["duplicate_tp_slot_count"] = duplicate
    t["false_positive_types"] = dict(sorted(fp_types.items()))
    for name, num, den in (("action_recall", "gold_action_hits", "gold_action_denominator"),
                           ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"),
                           ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"),
                           ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"),
                           ("order_recall", "order_pair_hits", "order_pair_denominator")):
        t[name] = t[num] / t[den] if t[den] else None
    return dict(t)


def markdown(by_model, by_stage, by_case, overall):
    cols = ("action_recall", "candidate_precision", "behavior_step_recall", "critical_evidence_recall", "order_recall")
    def table(title, values):
        lines = [f"## {title}", "", "| Group | Cases | Action recall | Precision | Behavior-step recall | Critical evidence | Order |", "|---|---:|---:|---:|---:|---:|---:|"]
        for key in sorted(values):
            m = values[key]
            lines.append("| " + key + " | " + str(m["case_count"]) + " | " + " | ".join(f"{m[x]*100:.2f}%" for x in cols) + " |")
        return "\n".join(lines)
    return "# ATLAS v2 attack8 process-chain v5 formal metrics\n\n" + table("By model", by_model) + "\n\n" + table("By stage", by_stage) + "\n\n" + table("By use case", by_case) + "\n\n" + table("Overall", {"all models/stages": overall}) + "\n"


def main():
    p1, p2, p3, pm = (SRC / "review1.jsonl", SRC / "review2.jsonl", SRC / "review3_targeted_v5.json", SRC / "manifest.json")
    for p in (p1, p2, p3, pm):
        if not p.is_file():
            raise SystemExit(f"missing input: {p}")
    output_names = ("formal_adopted_reviews_v5.jsonl", "adjudication_manifest_v5.json", "formal_aggregate_v5.json", "metrics_by_model_stage_case_v5.json", "metrics_by_model_stage_case_v5.md", "merge_validation_v5.json")
    existing = [name for name in output_names if (OUT / name).exists()]
    if existing:
        raise SystemExit("create-only refusal; output(s) already exist: " + ", ".join(existing))
    r1, r2, review3 = load_jsonl(p1), load_jsonl(p2), json.loads(p3.read_text(encoding="utf-8"))
    if len(r1) != 48 or len(r2) != 48 or {x["queue_id"] for x in r1} != {x["queue_id"] for x in r2}:
        raise SystemExit("expected identical 48-row review queues")
    if review3.get("validation", {}).get("status") != "PASS":
        raise SystemExit("review3 validation is not PASS")
    c3 = {(x["queue_id"], x["target_id"]): x for x in review3["candidate_slot_decisions"]}
    e3 = {(x["queue_id"], x["target_id"]): x for x in review3["critical_evidence_decisions"]}
    o3 = {(x["queue_id"], x["target_id"]): x for x in review3["order_pair_decisions"]}
    if (len(c3), len(e3), len(o3)) != (29, 12, 6):
        raise SystemExit("third review must contain exactly 29/12/6 unique decisions")
    left, right = {x["queue_id"]: x for x in r1}, {x["queue_id"]: x for x in r2}
    adopted, log = [], {"candidate": [], "critical_evidence": [], "order": [], "nonconflicting_counts": defaultdict(int), "fallback_count": 0}
    for qid in sorted(left):
        a, b = left[qid], right[qid]
        row = json.loads(json.dumps(a))
        gold = {x["item_id"]: x for x in row["gold_items"]}
        slots_a, slots_b = {x["slot_id"]: x for x in a["candidate_slots"]}, {x["slot_id"]: x for x in b["candidate_slots"]}
        new_slots = []
        for sid in sorted(slots_a):
            sa, sb = slots_a[sid], slots_b[sid]
            if slot_tuple(sa) == slot_tuple(sb):
                ns = json.loads(json.dumps(sa)); log["nonconflicting_counts"]["candidate"] += 1
            else:
                target = c3.get((qid, sid))
                if target is None: raise ValueError(f"unresolved candidate conflict: {qid} {sid}")
                tup, detail = choose_candidate(sa, sb, target, gold)
                ns = json.loads(json.dumps(sa))
                for field, value in zip(TUPLE_FIELDS, tup): ns[field] = value
                ns["false_positive_type"] = detail["false_positive_type"]
                ns["reason_ja"] = detail["reason_ja"]
                log["candidate"].append({"queue_id": qid, "slot_id": sid, **detail})
                log["fallback_count"] += int(detail["fallback_used"])
            new_slots.append(ns)
        row["candidate_slots"] = new_slots
        ga, gb = {x["item_id"]: x for x in a["gold_items"]}, {x["item_id"]: x for x in b["gold_items"]}
        for item in row["gold_items"]:
            if item["kind"] != "critical_evidence": continue
            if ga[item["item_id"]]["score"] == gb[item["item_id"]]["score"]:
                item["score"] = ga[item["item_id"]]["score"]; log["nonconflicting_counts"]["critical_evidence"] += 1
            else:
                d = e3.get((qid, item["item_id"]))
                if d is None: raise ValueError(f"unresolved critical conflict: {qid} {item['item_id']}")
                score, votes = binary_vote(ga[item["item_id"]]["score"], gb[item["item_id"]]["score"], d["decision"])
                item["score"] = score; item["reason_ja"] = d["reason_ja"]
                log["critical_evidence"].append({"queue_id": qid, "item_id": item["item_id"], "votes": votes, "adopted_score": score})
        oa, ob = {x["pair_id"]: x for x in a["order_pairs"]}, {x["pair_id"]: x for x in b["order_pairs"]}
        for pair in row["order_pairs"]:
            if oa[pair["pair_id"]]["score"] == ob[pair["pair_id"]]["score"]:
                pair["score"] = oa[pair["pair_id"]]["score"]; log["nonconflicting_counts"]["order"] += 1
            else:
                d = o3.get((qid, pair["pair_id"]))
                if d is None: raise ValueError(f"unresolved order conflict: {qid} {pair['pair_id']}")
                score, votes = binary_vote(oa[pair["pair_id"]]["score"], ob[pair["pair_id"]]["score"], d["decision"])
                pair["score"] = score; pair["reason_ja"] = d["reason_ja"]
                log["order"].append({"queue_id": qid, "pair_id": pair["pair_id"], "votes": votes, "adopted_score": score})
        derive_actions(row)
        row["schema_version"] = "codex_manual_action_claim_review_v5_atomic_alignment_formal_2of3"
        row["reviewer_id"] = "formal_2of3_adjudication_v5_atomic_alignment"
        row["formal_adjudication"] = {"method": "two-review exact agreement, targeted conflicts resolved by 2-of-3; action scores deterministically derived", "reviewers": [a["reviewer_id"], b["reviewer_id"], review3["reviewer_id"]]}
        row.pop("decision_sha256", None)
        row["decision_sha256"] = hashlib.sha256(canon(row)).hexdigest()
        adopted.append(row)
    used = {"candidate": {(x["queue_id"], x["slot_id"]) for x in log["candidate"]}, "critical": {(x["queue_id"], x["item_id"]) for x in log["critical_evidence"]}, "order": {(x["queue_id"], x["pair_id"]) for x in log["order"]}}
    if used["candidate"] != set(c3) or used["critical"] != set(e3) or used["order"] != set(o3):
        raise SystemExit("stale or unused review3 decision found")
    by_model = {m: metric_block([x for x in adopted if qmeta(x["queue_id"])[0] == m]) for m in sorted({qmeta(x["queue_id"])[0] for x in adopted})}
    by_stage = {s: metric_block([x for x in adopted if qmeta(x["queue_id"])[1] == s]) for s in sorted({qmeta(x["queue_id"])[1] for x in adopted})}
    by_case = {case: metric_block([x for x in adopted if qmeta(x["queue_id"])[2] == case]) for case in sorted({qmeta(x["queue_id"])[2] for x in adopted})}
    by_model_stage = {f"{m}/{s}": metric_block([x for x in adopted if qmeta(x["queue_id"])[0] == m and qmeta(x["queue_id"])[1] == s]) for m in by_model for s in by_stage}
    by_model_case = {f"{m}/{c}": metric_block([x for x in adopted if qmeta(x["queue_id"])[0] == m and qmeta(x["queue_id"])[2] == c]) for m in by_model for c in by_case}
    overall = metric_block(adopted)
    source_manifest = json.loads(pm.read_text(encoding="utf-8"))
    failures = []
    expected_denoms = source_manifest["v4_queue_manifest_binding"]["denominators"]
    for key, expected in expected_denoms["by_model_stage"].items():
        got = by_model_stage.get(key, {})
        for name in ("case_count", "gold_action_required_item_count", "critical_evidence_count", "gold_order_pair_count", "candidate_slot_count"):
            mapped = {"gold_action_required_item_count": "gold_action_denominator", "critical_evidence_count": "critical_evidence_denominator", "gold_order_pair_count": "order_pair_denominator", "candidate_slot_count": "candidate_slot_denominator"}.get(name, name)
            if got.get(mapped) != expected[name]: failures.append(f"denominator mismatch {key} {name}: {got.get(mapped)} != {expected[name]}")
    # Explicit atomic cross-field checks, including duplicate target diagnostics.
    gold1_without_tp = tp_gold0 = 0
    for row in adopted:
        hits = {s["matched_gold_item_id"] for s in row["candidate_slots"] if s.get("include_in_denominator") == 1 and s.get("is_true_positive") == 1}
        for item in row["gold_items"]:
            if item["kind"] in ACTION:
                gold1_without_tp += int(item["score"] == 1 and item["item_id"] not in hits)
                tp_gold0 += int(item["score"] == 0 and item["item_id"] in hits)
    if gold1_without_tp or tp_gold0: failures.append("atomic action/TP cross-field inconsistency")
    validation = {"schema_version": "v5_atomic_alignment_formal_merge_validation_v1", "status": "PASS" if not failures else "FAIL", "row_count": len(adopted), "model_stage_case_counts": {"models": len(by_model), "stages": len(by_stage), "use_cases": len(by_case), "model_stage_cells": len(by_model_stage)}, "targeted_conflicts": {"candidate": len(log["candidate"]), "critical_evidence": len(log["critical_evidence"]), "order": len(log["order"]), "total": sum(len(log[x]) for x in ("candidate", "critical_evidence", "order")), "unresolved": 0, "stale": 0, "rejected": 0, "conservative_fallback_count": log["fallback_count"]}, "atomic_consistency": {"gold1_without_tp": gold1_without_tp, "tp_gold0": tp_gold0, "duplicate_tp_slot_count": overall["duplicate_tp_slot_count"]}, "source_hashes": {"review1.jsonl": sha_file(p1), "review2.jsonl": sha_file(p2), "review3_targeted_v5.json": sha_file(p3), "v5_manifest.json": sha_file(pm), "bound_v4_queue_sha256": source_manifest["v4_queue_manifest_binding"]["queue_sha256"], "bound_v4_manifest_sha256": source_manifest["v4_queue_manifest_binding"]["manifest_sha256"], "bound_overlay_sha256": source_manifest["v4_queue_manifest_binding"]["overlay_sha256"]}, "reviewer_provenance": {"review1": r1[0]["reviewer_id"], "review2": r2[0]["reviewer_id"], "review3": review3["reviewer_id"], "external_api_calls": False}, "failures": failures}
    dump_jsonl(OUT / "formal_adopted_reviews_v5.jsonl", adopted)
    manifest = {"schema_version": "v5_atomic_alignment_adjudication_manifest_v1", "method": "2-of-3 at targeted conflicts, exact agreement elsewhere; action scores derived from adopted TP matches", "inputs": validation["source_hashes"], "reviewer_provenance": validation["reviewer_provenance"], "adjudication_log": log, "formal_adopted_reviews_sha256": sha_file(OUT / "formal_adopted_reviews_v5.jsonl"), "external_api_calls": False}
    dump_json(OUT / "adjudication_manifest_v5.json", manifest)
    aggregate = {"schema_version": "v5_atomic_alignment_formal_aggregate_v1", "overall": overall, "by_model": by_model, "by_stage": by_stage, "by_model_stage": by_model_stage, "notes": {"action_recall": "unique matched Gold action items / fixed Gold action denominator", "candidate_precision": "literal included TP slots / fixed candidate slots", "behavior_step_recall": "step has subject, operation, object all hit", "critical_evidence_recall": "separate binary Gold critical evidence scores", "order_recall": "separate binary adjacent Gold order pair scores"}}
    dump_json(OUT / "formal_aggregate_v5.json", aggregate)
    details = {"schema_version": "v5_atomic_alignment_metrics_by_model_stage_case_v1", "overall": overall, "by_model": by_model, "by_stage": by_stage, "by_use_case": by_case, "by_model_stage": by_model_stage, "by_model_use_case": by_model_case}
    dump_json(OUT / "metrics_by_model_stage_case_v5.json", details)
    (OUT / "metrics_by_model_stage_case_v5.md").write_text(markdown(by_model, by_stage, by_case, overall), encoding="utf-8")
    dump_json(OUT / "merge_validation_v5.json", validation)
    if failures: raise SystemExit("formal merge validation failed: " + "; ".join(failures))
    print(json.dumps({"status": validation["status"], "output": str(OUT), "overall": overall, "hashes": {p.name: sha_file(p) for p in OUT.iterdir() if p.is_file()}}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
