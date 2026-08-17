#!/usr/bin/env python3
"""Create-only provisional v5 atomic scoring for the 96 GPT-5.5 PASS runs.

This scorer is deliberately missingness-aware: the 48 non-PASS first-pass
cells are inventoried but excluded from accuracy.  Exact-hash matches reuse the
independent 2026-08-03 Codex gpt-5.6-sol decisions; new normal8 runs use the
same deterministic normal8 atomic scorer; new attack8 runs use frozen semantic
alignments reviewed against the same Gold.  No judge API or model API is used.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/current_experiment/results_2026-08-06/gpt55_normal_attack8_three_replicates_cost20_formal_01"
OUT = ROOT / "docs/current_experiment/results_2026-08-07/gpt55_three_replicate_96pass_scores_codex_sol_provisional_v2"
REPORT_JSON = ROOT / "docs/current_experiment/gpt55_three_replicate_96pass_codex_sol_provisional_results_20260807_v2.json"
REPORT_MD = ROOT / "docs/current_experiment/gpt55_three_replicate_96pass_codex_sol_provisional_results_20260807_v2.md"
BASE_SCORER = ROOT / "scripts/score_normal8_formal19_codex_sol_v1_20260802.py"
OLD_NORMAL = ROOT / "docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01/normal8/scores_codex_gpt56sol_v1/formal_scores.jsonl"
OLD_ATTACK = ROOT / "docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01/attack8_scores_codex_gpt56sol_v5_atomic_v1_20260803/per_run_scores.jsonl"
ATTACK_CASES = ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
KINDS = ("subject", "operation", "object")


# candidate ordinal -> (Gold ordinal, literal TP kinds).  s=subject,
# p=operation, o=object.  Omitted claims remain fixed-denominator false
# positives.  These 20 alignments cover only new attack PASS outputs.
ATTACK_ALIGNMENTS: dict[str, dict[int, tuple[int, str]]] = {
    "replicate_01/stage1/s4_pt_04_powershell_c1": {2: (1, "sop"), 3: (2, "sop"), 4: (4, "sop"), 5: (5, "sop")},
    "replicate_02/stage2/s4_pt_01_word_w1": {1: (1, "sop"), 3: (3, "sop"), 5: (4, "sop")},
    "replicate_02/stage1/s4_pt_04_powershell_c1": {2: (1, "sop"), 3: (2, "sop")},
    "replicate_02/stage2/s4_pt_04_powershell_c1": {2: (1, "sop"), 3: (2, "sop"), 4: (3, "sop"), 6: (4, "sop"), 7: (5, "sop"), 8: (6, "sop"), 9: (7, "sop")},
    "replicate_02/stage2/s4_pt_02_word_w3": {4: (2, "sop"), 6: (3, "sop")},
    "replicate_02/stage2/s3_pt_04_powershell_mid_chain": {3: (2, "po"), 4: (1, "sop"), 5: (2, "sop"), 6: (4, "sop"), 7: (5, "sop"), 8: (6, "sop"), 9: (7, "sop")},
    "replicate_02/stage1/s4_pt_02_word_w3": {2: (2, "sop")},
    "replicate_02/stage1/s3_pt_03_regsvr32_long_chain": {2: (1, "sop"), 4: (3, "po")},
    "replicate_02/stage2/s4_pt_03_mshta_c1": {1: (1, "sop")},
    "replicate_02/stage3/s3_pt_01_word_document_processing": {2: (1, "sop"), 3: (2, "sop")},
    "replicate_02/stage2/s3_pt_02_regsvr32_remote_sct": {1: (1, "sop"), 2: (2, "sop"), 3: (3, "sop")},
    "replicate_02/stage2/s3_pt_03_regsvr32_long_chain": {1: (1, "sop"), 3: (3, "po"), 4: (2, "sop"), 5: (3, "sop"), 6: (5, "sop"), 7: (6, "sop"), 8: (7, "sop"), 9: (8, "sop")},
    "replicate_02/stage1/s3_pt_01_word_document_processing": {1: (2, "sop")},
    "replicate_02/stage1/s3_pt_04_powershell_mid_chain": {4: (2, "po"), 5: (1, "sop"), 6: (2, "sop"), 7: (3, "sop")},
    "replicate_02/stage3/s4_pt_04_powershell_c1": {5: (1, "sop"), 6: (2, "sop"), 7: (3, "sop"), 9: (4, "sop"), 10: (5, "sop"), 11: (6, "sop"), 12: (7, "sop")},
    "replicate_02/stage1/s4_pt_03_mshta_c1": {1: (1, "sop"), 3: (2, "sop"), 4: (3, "sop"), 5: (4, "sop"), 8: (5, "sop"), 10: (6, "sop"), 11: (7, "sop"), 13: (8, "sop"), 14: (9, "sop")},
    "replicate_02/stage3/s4_pt_02_word_w3": {3: (2, "sop")},
    "replicate_02/stage1/s3_pt_02_regsvr32_remote_sct": {1: (1, "sop"), 2: (2, "sop"), 4: (3, "sop")},
    "replicate_02/stage3/s3_pt_03_regsvr32_long_chain": {2: (1, "sop"), 5: (3, "po")},
    "replicate_02/stage3/s3_pt_04_powershell_mid_chain": {3: (2, "po"), 4: (1, "sop"), 5: (2, "sop"), 6: (4, "sop"), 7: (5, "sop"), 8: (6, "sop"), 9: (7, "sop")},
}


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BASE = load_module(BASE_SCORER, "normal_atomic_base")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def write_json(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in rows), encoding="utf-8")


def old_scores() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in (OLD_NORMAL, OLD_ATTACK):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                out[row["run_sha256"]] = row
    return out


def audit_rows() -> list[tuple[str, Path, dict[str, Any]]]:
    rows = []
    for rep in sorted(SOURCE.glob("replicate_*")):
        for path in sorted(rep.glob("audits/**/*.json")):
            audit = read_json(path)
            if audit.get("schema_version") == "gpt55_normal_attack8_three_replicate_run_audit_v1":
                rows.append((rep.name, path, audit))
    return rows


def investigation(audit: dict[str, Any]) -> dict[str, Any]:
    activity = audit.get("activity") or {}
    usage = audit.get("usage") or {}
    guard = audit.get("run_budget_guard") or {}
    return {
        "api_calls": int(audit.get("api_call_count") or guard.get("api_calls") or 0),
        "chief_leads": int(activity.get("chief_leads") or 0),
        "unique_chief_leads": int(activity.get("unique_chief_leads") or 0),
        "investigator_questions": int(activity.get("investigator_questions") or 0),
        "unique_investigator_questions": int(activity.get("unique_investigator_questions") or 0),
        "sql_queries": int(activity.get("sql_queries") or 0),
        "unique_sql_queries": int(activity.get("unique_sql_queries") or 0),
        "input_tokens": int(usage.get("input_tokens") or 0),
        "output_tokens": int(usage.get("output_tokens") or 0),
        "cached_input_tokens": int(usage.get("cached_input_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or 0),
        "cost_usd": float(audit.get("cost_usd") or guard.get("estimated_cost_usd") or 0),
        "elapsed_seconds": float(audit.get("elapsed_seconds") or 0),
    }


def normal_audit_adapter(audit: dict[str, Any]) -> dict[str, Any]:
    inv = investigation(audit)
    return {
        "chief_lead_event_count": inv["chief_leads"],
        "unique_chief_lead_count": inv["unique_chief_leads"],
        "repeated_chief_lead_count": max(0, inv["chief_leads"] - inv["unique_chief_leads"]),
        "unique_chief_behavior_key_count": inv["unique_chief_leads"],
        "accepted_behavior_fingerprint_count": inv["unique_chief_leads"],
        "behavior_guard_status_counts": {},
        "investigator_question_count": inv["investigator_questions"],
        "unique_investigator_question_count": inv["unique_investigator_questions"],
        "sql_query_count": inv["sql_queries"],
        "unique_sql_query_count": inv["unique_sql_queries"],
        "activity_event_count": 0,
        "api_call_count": inv["api_calls"],
        "total_tokens": inv["total_tokens"],
        "cost_usd": inv["cost_usd"],
        "elapsed_seconds": inv["elapsed_seconds"],
        "sha256": audit["sha256"],
        "gold_sha256": audit.get("gold_sha256"),
        "case_file_sha256": audit.get("case_file_sha256"),
        "validation_sha256": audit.get("validation_sha256"),
    }


def step_num(step_id: str) -> int:
    return int(step_id.rsplit("S", 1)[1])


def compact_obj(value: Any) -> str:
    if not isinstance(value, dict):
        return str(value)
    return " | ".join(str(value.get(k)) for k in ("name", "path", "value", "data") if value.get(k) not in (None, ""))


def manual_attack_score(replicate: str, audit_path: Path, audit: dict[str, Any]) -> dict[str, Any]:
    run_path = Path(audit["path"])
    run = read_json(run_path)
    output = json.loads(run["output_text"])
    steps = output.get("code_steps") or []
    gold_path = Path(run["atlasv2_s3_s4_attack8_paired_experiment"]["gold"])
    gold = read_json(gold_path)
    stage, chain, instance = audit["stage"], audit["chain_id"], audit["instance_id"]
    key = f"{replicate}/{stage}/{chain}"
    decision = ATTACK_ALIGNMENTS[key]
    gsteps = {step_num(x["step_id"]): x for x in gold["gold_steps"]}
    slots: list[dict[str, Any]] = []
    hit_ids: set[str] = set()
    aligned: dict[int, int] = {}
    fp = Counter()
    for ci, step in enumerate(steps, 1):
        spec = decision.get(ci)
        if spec:
            aligned[ci] = spec[0]
        subject = step.get("subject_process") or {}
        values = {
            "subject": subject.get("name") if isinstance(subject, dict) else str(subject),
            "operation": step.get("operation"),
            "object": compact_obj(step.get("object") or {}),
        }
        for kind, letter in (("subject", "s"), ("operation", "p"), ("object", "o")):
            raw_tp = bool(spec and letter in spec[1])
            target = f"{gsteps[spec[0]]['step_id']}:{kind}" if raw_tp else None
            is_tp = int(bool(target and target not in hit_ids))
            if is_tp:
                hit_ids.add(target)
            fp_type = "" if is_tp else ("duplicate" if raw_tp else ("wrong_component" if spec else "unsupported_or_nearby"))
            if fp_type:
                fp[fp_type] += 1
            slots.append({
                "slot_id": f"C{ci}:{kind}", "candidate_claim_id": f"C{ci}",
                "source_step_id": step.get("step_id"), "source_order": step.get("order"),
                "kind": kind, "candidate_slot_excerpt": values[kind], "include_in_denominator": 1,
                "is_true_positive": is_tp,
                "aligned_gold_step_id": gsteps[spec[0]]["step_id"] if spec else None,
                "matched_gold_item_id": target if is_tp else None,
                "false_positive_type": fp_type,
            })
    evidence_hits: set[int] = set()
    for ci, gn in aligned.items():
        signature = gsteps[gn].get("critical_evidence_signature") or {}
        evidence = json.dumps(steps[ci - 1].get("evidence") or [], ensure_ascii=False).lower()
        anchors = (signature.get("source_row_id"), signature.get("timestamp_utc"), signature.get("target_key"))
        if any(x not in (None, "") and str(x).lower() in evidence for x in anchors):
            evidence_hits.add(gn)
    gold_items = []
    for gn, step in gsteps.items():
        for kind in KINDS:
            item_id = f"{step['step_id']}:{kind}"
            value = step["subject"] if kind == "subject" else step["action"] if kind == "operation" else step["object"]
            gold_items.append({"item_id": item_id, "step_id": step["step_id"], "kind": kind, "gold_value": value, "score": int(item_id in hit_ids), "score_source": "derived_from_unique_literal_tp_matched_gold_item_id"})
        gold_items.append({"item_id": f"{step['step_id']}:critical_evidence", "step_id": step["step_id"], "kind": "critical_evidence", "gold_value": step.get("critical_evidence_signature"), "score": int(gn in evidence_hits), "score_source": "separate_exact_canonical_evidence_anchor_review"})
    operation_positions = {gn: ci for ci, gn in aligned.items() if "p" in decision[ci][1]}
    order_pairs = []
    for left, right in gold.get("gold_order_pairs") or []:
        lnum, rnum = step_num(left), step_num(right)
        order_pairs.append({"pair_id": f"{left}->{right}", "left_step_id": left, "right_step_id": right, "score": int(lnum in operation_positions and rnum in operation_positions and operation_positions[lnum] < operation_positions[rnum])})
    behavior_hits = sum(all(f"{step['step_id']}:{kind}" in hit_ids for kind in KINDS) for step in gold["gold_steps"])
    totals = {
        "gold_action_denominator": 3 * len(gsteps), "gold_action_hits": len(hit_ids),
        "candidate_slot_denominator": len(slots), "candidate_slot_tp": sum(x["is_true_positive"] for x in slots),
        "behavior_step_denominator": len(gsteps), "behavior_step_hits": behavior_hits,
        "critical_evidence_denominator": len(gsteps), "critical_evidence_hits": len(evidence_hits),
        "order_pair_denominator": len(order_pairs), "order_pair_hits": sum(x["score"] for x in order_pairs),
        "false_positive_types": dict(fp),
    }
    inv = investigation(audit)
    row = {
        "schema_version": "gpt55_provisional_v5_atomic_score_row_v1",
        "queue_id": f"{replicate}/attack8/gpt-5.5/{stage}/{instance}",
        "reviewer": "Codex gpt-5.6-sol", "replicate": replicate, "phase": "attack8",
        "model": "gpt-5.5", "stage": stage, "instance_id": instance, "chain_id": chain,
        "run_path": rel(run_path), "run_sha256": sha(run_path),
        "audit_path": rel(audit_path), "audit_sha256": sha(audit_path),
        "case_file_sha256": audit.get("case_file_sha256"),
        "gold_path": rel(gold_path), "gold_sha256": sha(gold_path),
        "budget_censored": False, "budget_limited": False,
        "gold_items": gold_items, "candidate_slots": slots, "order_pairs": order_pairs,
        "fixed_denominators": {"gold_action": 3 * len(gsteps), "candidate_slots": len(slots), "behavior_steps": len(gsteps), "critical_evidence": len(gsteps), "order_pairs": len(order_pairs)},
        "totals": totals, "investigation": inv,
        "failure_diagnostics": {
            "gold_steps_without_aligned_claim": len(gsteps) - len(set(aligned.values())),
            "incomplete_behavior_steps": len(gsteps) - behavior_hits,
            "missing_adjacent_causal_edges": len(order_pairs) - sum(x["score"] for x in order_pairs),
            "unsupported_or_nearby_slots": fp["unsupported_or_nearby"],
            "wrong_component_slots": fp["wrong_component"],
            "duplicate_slots": fp["duplicate"],
        },
        "score_provenance": "new_manual_semantic_alignment_same_v5_rubric",
    }
    row["decision_sha256"] = hashlib.sha256(canonical(row)).hexdigest()
    return row


def bind_reused(row: dict[str, Any], replicate: str, phase: str, audit_path: Path, audit: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(row)
    run_path = Path(audit["path"])
    out["schema_version"] = "gpt55_provisional_v5_atomic_score_row_v1"
    out["replicate"] = replicate
    out["phase"] = phase
    out["queue_id"] = f"{replicate}/{phase}/gpt-5.5/{audit['stage']}/{audit['instance_id']}"
    if "run_json" in out:
        out["run_json"] = rel(run_path)
        out["source_audit"] = rel(audit_path)
        out["source_audit_sha256"] = sha(audit_path)
    else:
        out["run_path"] = rel(run_path)
        out["audit_path"] = rel(audit_path)
        out["audit_sha256"] = sha(audit_path)
    out["run_sha256"] = sha(run_path)
    out["score_provenance"] = "exact_run_sha256_reuse_from_independent_20260803_codex_review"
    out["investigation_rebound"] = investigation(audit)
    return out


def score_normal(replicate: str, audit_path: Path, audit: dict[str, Any]) -> dict[str, Any]:
    run_path = Path(audit["path"])
    run = read_json(run_path)
    row = BASE.score_run(run_path, {}, normal_audit_adapter(audit))
    row["schema_version"] = "gpt55_provisional_v5_atomic_score_row_v1"
    row["replicate"] = replicate
    row["phase"] = "normal8"
    row["queue_id"] = f"{replicate}/normal8/gpt-5.5/{audit['stage']}/{audit['instance_id']}"
    row["reviewer"] = {"identity": "Codex gpt-5.6-sol", "independent_from_candidate_model": True, "external_judge_api_calls": 0, "api_scorer_calls": 0}
    row["source_audit"] = rel(audit_path)
    row["source_audit_sha256"] = sha(audit_path)
    row["score_provenance"] = "deterministic_normal8_atomic_scorer_same_v5_rubric"
    return row


def row_numbers(row: dict[str, Any]) -> dict[str, float]:
    source = row.get("metrics") or row.get("totals") or {}
    return {
        "gold_action_hits": int(source.get("gold_action_hits") or 0),
        "gold_action_denominator": int(source.get("gold_action_denominator") or 0),
        "candidate_slot_tp": int(source.get("candidate_slot_tp") or 0),
        "candidate_slot_denominator": int(source.get("candidate_slot_denominator") or 0),
        "behavior_step_hits": int(source.get("behavior_step_hits") or 0),
        "behavior_step_denominator": int(source.get("behavior_step_denominator") or 0),
        "critical_evidence_hits": int(source.get("critical_evidence_hits") or 0),
        "critical_evidence_denominator": int(source.get("critical_evidence_denominator") or 0),
        "order_pair_hits": int(source.get("order_pair_hits") or 0),
        "order_pair_denominator": int(source.get("order_pair_denominator") or 0),
    }


def row_investigation(row: dict[str, Any]) -> dict[str, float]:
    if row.get("investigation_rebound"):
        return row["investigation_rebound"]
    inv = row.get("investigation") or {}
    return {
        "api_calls": int(inv.get("api_calls") or 0),
        "chief_leads": int(inv.get("chief_leads") or inv.get("lead_call_count") or 0),
        "unique_chief_leads": int(inv.get("unique_chief_leads") or inv.get("unique_lead_count") or 0),
        "investigator_questions": int(inv.get("investigator_questions") or inv.get("investigator_question_count") or 0),
        "unique_investigator_questions": int(inv.get("unique_investigator_questions") or inv.get("unique_investigator_question_count") or 0),
        "sql_queries": int(inv.get("sql_queries") or inv.get("sql_query_count") or 0),
        "unique_sql_queries": int(inv.get("unique_sql_queries") or inv.get("unique_sql_query_count") or 0),
        "input_tokens": int(inv.get("input_tokens") or 0), "output_tokens": int(inv.get("output_tokens") or 0),
        "cached_input_tokens": int(inv.get("cached_input_tokens") or 0),
        "total_tokens": int(inv.get("total_tokens") or inv.get("tokens") or 0),
        "cost_usd": float(inv.get("cost_usd") or 0), "elapsed_seconds": float(inv.get("elapsed_seconds") or 0),
    }


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metric = Counter()
    resource = Counter()
    for row in rows:
        metric.update(row_numbers(row))
        resource.update(row_investigation(row))
    out: dict[str, Any] = {k: int(v) for k, v in metric.items()}
    for name, num, den in (
        ("action_recall", "gold_action_hits", "gold_action_denominator"),
        ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"),
        ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"),
        ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"),
        ("order_recall", "order_pair_hits", "order_pair_denominator"),
    ):
        out[name] = out.get(num, 0) / out.get(den, 1) if out.get(den, 0) else None
    out["run_count"] = len(rows)
    out["resources"] = dict(resource)
    out["resources"]["mean_cost_usd_per_run"] = resource["cost_usd"] / len(rows) if rows else None
    out["resources"]["mean_elapsed_seconds_per_run"] = resource["elapsed_seconds"] / len(rows) if rows else None
    out["resources"]["mean_total_tokens_per_run"] = resource["total_tokens"] / len(rows) if rows else None
    return out


def grouped(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups["/".join(str(row[f]) for f in fields)].append(row)
    return {key: aggregate(value) for key, value in sorted(groups.items())}


def validate(rows: list[dict[str, Any]], pass_audits: dict[tuple[str, str, str, str], tuple[Path, dict[str, Any]]]) -> dict[str, Any]:
    failures = []
    seen = set()
    for row in rows:
        key = (row["replicate"], row["phase"], row["stage"], row["chain_id"])
        if key in seen:
            failures.append(f"DUPLICATE_CELL:{key}")
        seen.add(key)
        source = pass_audits.get(key)
        if source is None:
            failures.append(f"MISSING_PASS_AUDIT:{key}")
            continue
        audit_path, audit = source
        run_path = Path(audit["path"])
        if sha(run_path) != row["run_sha256"] or row["run_sha256"] != audit["sha256"]:
            failures.append(f"RUN_HASH:{key}")
        if sha(audit_path) not in {row.get("audit_sha256"), row.get("source_audit_sha256")}:
            failures.append(f"AUDIT_HASH:{key}")
        gold_path_text = row.get("gold_json") or row.get("gold_path")
        if not gold_path_text or sha(ROOT / gold_path_text) != row["gold_sha256"]:
            failures.append(f"GOLD_HASH:{key}")
        den = row["fixed_denominators"]
        expected = {
            "gold_action": sum(x["kind"] in KINDS for x in row["gold_items"]),
            "candidate_slots": len(row["candidate_slots"]),
            "behavior_steps": sum(x["kind"] == "critical_evidence" for x in row["gold_items"]),
            "critical_evidence": sum(x["kind"] == "critical_evidence" for x in row["gold_items"]),
            "order_pairs": len(row["order_pairs"]),
        }
        if den != expected:
            failures.append(f"DENOMINATOR:{key}:{den}!={expected}")
        tp = [x["matched_gold_item_id"] for x in row["candidate_slots"] if x.get("include_in_denominator") == 1 and x.get("is_true_positive") == 1]
        if len(tp) != len(set(tp)):
            failures.append(f"DUPLICATE_TP:{key}")
        action_scores = {x["item_id"]: x["score"] for x in row["gold_items"] if x["kind"] in KINDS}
        for item, score in action_scores.items():
            if score != int(item in tp):
                failures.append(f"GOLD_TP:{key}:{item}")
    if len(rows) != 96:
        failures.append(f"ROW_COUNT:{len(rows)}!=96")
    return {
        "status": "PASS" if not failures else "FAIL", "scored_rows": len(rows), "unique_cells": len(seen),
        "run_hashes_checked": len(rows), "audit_hashes_checked": len(rows), "gold_hashes_checked": len(rows),
        "gold_action_items_checked": sum(row["fixed_denominators"]["gold_action"] for row in rows),
        "candidate_slots_checked": sum(row["fixed_denominators"]["candidate_slots"] for row in rows),
        "behavior_steps_checked": sum(row["fixed_denominators"]["behavior_steps"] for row in rows),
        "critical_evidence_items_checked": sum(row["fixed_denominators"]["critical_evidence"] for row in rows),
        "order_pairs_checked": sum(row["fixed_denominators"]["order_pairs"] for row in rows),
        "failure_count": len(failures), "failures": failures,
        "external_judge_api_calls": 0, "api_scorer_calls": 0,
    }


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def table(title: str, groups: dict[str, Any]) -> str:
    lines = [f"## {title}", "", "| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for key, block in groups.items():
        res = block["resources"]
        lines.append(f"| {key} | {block['run_count']} | {pct(block['action_recall'])} | {pct(block['candidate_precision'])} | {pct(block['behavior_step_recall'])} | {pct(block['critical_evidence_recall'])} | {pct(block['order_recall'])} | ${res['cost_usd']:.6f} | {res['elapsed_seconds']/60:.2f} min |")
    return "\n".join(lines)


def main() -> None:
    for path in (OUT, REPORT_JSON, REPORT_MD):
        if path.exists():
            raise SystemExit(f"create-only refusal: {path}")
    old = old_scores()
    audits = audit_rows()
    pass_index: dict[tuple[str, str, str, str], tuple[Path, dict[str, Any]]] = {}
    missing = []
    rows = []
    provenance_counts = Counter()
    for replicate, audit_path, audit in audits:
        key = (replicate, audit["phase"], audit["stage"], audit["chain_id"])
        if audit["status"] != "PASS":
            run_error = None
            if audit.get("path") and Path(audit["path"]).is_file():
                failed_run = read_json(Path(audit["path"]))
                run_error = failed_run.get("error")
            missing.append({
                "replicate": replicate, "phase": audit["phase"], "stage": audit["stage"],
                "chain_id": audit["chain_id"], "instance_id": audit["instance_id"],
                "status": audit["status"], "issues": audit.get("issues") or [],
                "error": audit.get("error") or audit.get("runner_exception") or run_error,
                "audit_path": rel(audit_path), "audit_sha256": sha(audit_path),
            })
            continue
        pass_index[key] = (audit_path, audit)
        if audit["sha256"] in old:
            row = bind_reused(old[audit["sha256"]], replicate, audit["phase"], audit_path, audit)
        elif audit["phase"] == "normal8":
            row = score_normal(replicate, audit_path, audit)
        else:
            row = manual_attack_score(replicate, audit_path, audit)
        provenance_counts[row["score_provenance"]] += 1
        rows.append(row)
    rows.sort(key=lambda x: (x["replicate"], x["phase"], x["stage"], x["chain_id"]))
    validation = validate(rows, pass_index)
    if validation["status"] != "PASS":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
    result = {
        "schema_version": "gpt55_three_replicate_96pass_codex_sol_provisional_v1",
        "status": "PASS_PROVISIONAL_MISSINGNESS_AWARE",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewer": "Codex gpt-5.6-sol",
        "external_judge_api_used": False, "api_scorer_used": False,
        "scope": {
            "logical_grid": 144, "scored_pass_runs": len(rows), "excluded_nonpass_runs": len(missing),
            "headline_policy": "Only deterministic-audit PASS runs are scored. Non-PASS cells are missing, not zero.",
            "provisional_reason": "48 retry cells remain pending API quota recovery; selection is highly unbalanced by replicate and phase.",
            "pass_by_replicate": dict(Counter(x["replicate"] for x in rows)),
            "pass_by_domain": dict(Counter(x["phase"] for x in rows)),
            "missing_by_reason": dict(Counter(
                "quota" if "insufficient_quota" in str(x.get("error")) or "credit_balance_exhausted" in str(x.get("error"))
                else "api_timeout" if "APITimeoutError" in str(x.get("error")) or "Request timed out" in str(x.get("error"))
                else "run_hard_wall_or_runner"
                for x in missing
            )),
        },
        "scoring_policy": {
            "rubric": "v5 atomic process chain", "action_components": list(KINDS),
            "gold_hit_derivation": "unique included literal-TP candidate slot matched_gold_item_id",
            "behavior_step_rule": "all subject+operation+object", "critical_evidence_separate": True,
            "order_unit": "adjacent Gold pair", "pid_scored": False, "hidden_alert_mapping_scored": False,
            "candidate_denominator": "3 fixed slots per emitted code_step",
        },
        "score_provenance_counts": dict(provenance_counts),
        "headline_observed_pass_only": aggregate(rows),
        "by_replicate": grouped(rows, ("replicate",)),
        "by_domain": grouped(rows, ("phase",)),
        "by_stage": grouped(rows, ("stage",)),
        "by_replicate_domain": grouped(rows, ("replicate", "phase")),
        "by_domain_stage": grouped(rows, ("phase", "stage")),
        "by_case": grouped(rows, ("phase", "chain_id")),
        "validation": validation,
        "missing_cells": missing,
        "source": {"root": rel(SOURCE), "contract_sha256": sha(SOURCE / "experiment_contract.json"), "summary_sha256": sha(SOURCE / "experiment_summary.json")},
        "formal_contract_status": "NOT_FINAL; provisional result only; supersede after 144 PASS",
    }
    OUT.mkdir(parents=True, exist_ok=False)
    write_jsonl(OUT / "formal_scores_96pass.jsonl", rows)
    write_json(OUT / "metrics_provisional.json", {k: result[k] for k in ("headline_observed_pass_only", "by_replicate", "by_domain", "by_stage", "by_replicate_domain", "by_domain_stage", "by_case")})
    write_json(OUT / "missing_cells_48.json", missing)
    write_json(OUT / "semantic_alignment_decisions_new_attack20.json", ATTACK_ALIGNMENTS)
    write_json(OUT / "deterministic_consistency_audit.json", validation)
    write_json(OUT / "provenance_manifest.json", {"source": result["source"], "score_provenance_counts": result["score_provenance_counts"], "bindings": [{"replicate": x["replicate"], "phase": x["phase"], "stage": x["stage"], "chain_id": x["chain_id"], "run_sha256": x["run_sha256"], "score_provenance": x["score_provenance"]} for x in rows]})
    write_json(REPORT_JSON, result)
    overall = result["headline_observed_pass_only"]
    md = "\n\n".join([
        "# GPT-5.5 96 PASS provisional Codex review (2026-08-07)",
        "**96/144 logical runs are scored.** The other 48 are excluded as missing, not scored as zero. This is a provisional, missingness-aware view and must not be presented as a balanced three-replicate estimate.",
        table("Observed PASS headline", {"gpt-5.5 observed PASS": overall}),
        table("By replicate", result["by_replicate"]),
        table("By normal / attack", result["by_domain"]),
        table("By Stage", result["by_stage"]),
        table("By replicate and domain", result["by_replicate_domain"]),
        table("By domain and Stage", result["by_domain_stage"]),
        table("By use case", result["by_case"]),
        "## Missingness warning\n\n" + f"PASS distribution: `{json.dumps(result['scope']['pass_by_replicate'], ensure_ascii=False)}`; domain distribution: `{json.dumps(result['scope']['pass_by_domain'], ensure_ascii=False)}`. Replicate 03 contains only the early normal PASS cells before quota exhaustion. Do not compare replicate means causally or use the 96-run headline as the final GPT-5.5 number.",
        "## Integrity\n\n" + f"Deterministic consistency audit: **{validation['status']}**. Checked {validation['run_hashes_checked']} run/audit/Gold bindings, {validation['gold_action_items_checked']} Gold action items, {validation['candidate_slots_checked']} candidate slots, {validation['behavior_steps_checked']} behavior steps, {validation['critical_evidence_items_checked']} critical-evidence items, and {validation['order_pairs_checked']} order pairs. Judge/API scorer calls: 0.",
        "## Provenance\n\n" + f"Exact-hash reused decisions: {provenance_counts['exact_run_sha256_reuse_from_independent_20260803_codex_review']}; deterministic new normal scores: {provenance_counts['deterministic_normal8_atomic_scorer_same_v5_rubric']}; new manual attack semantic reviews: {provenance_counts['new_manual_semantic_alignment_same_v5_rubric']}. Existing artifacts were not overwritten.",
    ]) + "\n"
    if REPORT_MD.exists():
        raise FileExistsError(f"create-only refusal: {REPORT_MD}")
    REPORT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"status": result["status"], "scored": len(rows), "missing": len(missing), "report_json": str(REPORT_JSON), "report_md": str(REPORT_MD), "score_root": str(OUT), "headline": overall, "validation": validation}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
