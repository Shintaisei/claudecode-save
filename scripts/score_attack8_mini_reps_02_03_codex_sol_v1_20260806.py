#!/usr/bin/env python3
"""Create-only Codex review of attack8 replicate_02 and replicate_03.

No OpenAI judge/API scorer is used.  ALIGNMENTS is the frozen independent
Codex semantic review.  Every atomic item, candidate slot, adjacent Gold
order pair, hash, total, and aggregate is derived deterministically from it.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/current_experiment/results_2026-08-06/mini_reps_02_03_v5_failure_retry_01"
CASES = ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
GOLD_ROOT = ROOT / "data/current_experiment/gold/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727/by_chain"
OUT = ROOT / "docs/current_experiment/results_2026-08-06/mini_reps_02_03_v5_scores_attack_codex_sol_v1"
REPORT_JSON = ROOT / "docs/current_experiment/attack8_mini_reps_02_03_codex_sol_results_20260806.json"
REPORT_MD = ROOT / "docs/current_experiment/attack8_mini_reps_02_03_codex_sol_results_20260806.md"
KINDS = ("subject", "operation", "object")

# key: replicate/model/stage/chain
# value: candidate output ordinal -> (Gold ordinal, literal TP kinds)
# s=subject, p=operation, o=object.  Omitted claims are unsupported, nearby,
# duplicate, or over-connected, so their three candidate slots are FP.
ALIGNMENTS = {
    # s3_pt_01_word_document_processing
    "replicate_02/gpt-4.1-mini/stage1/s3_pt_01_word_document_processing": {2: (1, "sop")},
    "replicate_02/gpt-4.1-mini/stage2/s3_pt_01_word_document_processing": {1: (2, "sop")},
    "replicate_02/gpt-4.1-mini/stage3/s3_pt_01_word_document_processing": {},
    "replicate_02/gpt-5.4-mini/stage1/s3_pt_01_word_document_processing": {},
    "replicate_02/gpt-5.4-mini/stage2/s3_pt_01_word_document_processing": {1: (2, "sop"), 2: (1, "sop")},
    "replicate_02/gpt-5.4-mini/stage3/s3_pt_01_word_document_processing": {2: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage1/s3_pt_01_word_document_processing": {2: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s3_pt_01_word_document_processing": {},
    "replicate_03/gpt-4.1-mini/stage3/s3_pt_01_word_document_processing": {2: (2, "sop")},
    "replicate_03/gpt-5.4-mini/stage1/s3_pt_01_word_document_processing": {},
    "replicate_03/gpt-5.4-mini/stage2/s3_pt_01_word_document_processing": {1: (2, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s3_pt_01_word_document_processing": {},

    # s3_pt_02_regsvr32_remote_sct
    "replicate_02/gpt-4.1-mini/stage1/s3_pt_02_regsvr32_remote_sct": {1: (3, "so")},
    "replicate_02/gpt-4.1-mini/stage2/s3_pt_02_regsvr32_remote_sct": {1: (2, "sop")},
    "replicate_02/gpt-4.1-mini/stage3/s3_pt_02_regsvr32_remote_sct": {},
    "replicate_02/gpt-5.4-mini/stage1/s3_pt_02_regsvr32_remote_sct": {1: (1, "sop"), 2: (2, "sop"), 3: (3, "sop")},
    "replicate_02/gpt-5.4-mini/stage2/s3_pt_02_regsvr32_remote_sct": {2: (3, "sop")},
    "replicate_02/gpt-5.4-mini/stage3/s3_pt_02_regsvr32_remote_sct": {2: (3, "sop")},
    "replicate_03/gpt-4.1-mini/stage1/s3_pt_02_regsvr32_remote_sct": {1: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s3_pt_02_regsvr32_remote_sct": {1: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage3/s3_pt_02_regsvr32_remote_sct": {1: (2, "sop")},
    "replicate_03/gpt-5.4-mini/stage1/s3_pt_02_regsvr32_remote_sct": {},
    "replicate_03/gpt-5.4-mini/stage2/s3_pt_02_regsvr32_remote_sct": {1: (2, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s3_pt_02_regsvr32_remote_sct": {},

    # s3_pt_03_regsvr32_long_chain
    "replicate_02/gpt-4.1-mini/stage1/s3_pt_03_regsvr32_long_chain": {1: (1, "sop"), 2: (2, "sop"), 3: (5, "sop"), 4: (6, "sop"), 8: (3, "sp")},
    "replicate_02/gpt-4.1-mini/stage2/s3_pt_03_regsvr32_long_chain": {1: (1, "sop"), 3: (2, "sop"), 5: (5, "sop"), 6: (6, "sop")},
    "replicate_02/gpt-4.1-mini/stage3/s3_pt_03_regsvr32_long_chain": {1: (1, "sop"), 4: (3, "sp")},
    "replicate_02/gpt-5.4-mini/stage1/s3_pt_03_regsvr32_long_chain": {},
    "replicate_02/gpt-5.4-mini/stage2/s3_pt_03_regsvr32_long_chain": {},
    "replicate_02/gpt-5.4-mini/stage3/s3_pt_03_regsvr32_long_chain": {},
    "replicate_03/gpt-4.1-mini/stage1/s3_pt_03_regsvr32_long_chain": {1: (2, "sop"), 4: (8, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s3_pt_03_regsvr32_long_chain": {2: (2, "sop"), 3: (3, "sop")},
    "replicate_03/gpt-4.1-mini/stage3/s3_pt_03_regsvr32_long_chain": {5: (2, "sop"), 6: (3, "sop"), 8: (5, "sp"), 9: (8, "sop")},
    "replicate_03/gpt-5.4-mini/stage1/s3_pt_03_regsvr32_long_chain": {},
    "replicate_03/gpt-5.4-mini/stage2/s3_pt_03_regsvr32_long_chain": {},
    "replicate_03/gpt-5.4-mini/stage3/s3_pt_03_regsvr32_long_chain": {},

    # s3_pt_04_powershell_mid_chain
    "replicate_02/gpt-4.1-mini/stage1/s3_pt_04_powershell_mid_chain": {3: (2, "so"), 5: (6, "sop")},
    "replicate_02/gpt-4.1-mini/stage2/s3_pt_04_powershell_mid_chain": {1: (1, "sop"), 2: (4, "sop"), 3: (5, "sop")},
    "replicate_02/gpt-4.1-mini/stage3/s3_pt_04_powershell_mid_chain": {2: (1, "sop"), 3: (2, "sop"), 4: (4, "sop"), 5: (5, "sop")},
    "replicate_02/gpt-5.4-mini/stage1/s3_pt_04_powershell_mid_chain": {2: (1, "sop")},
    "replicate_02/gpt-5.4-mini/stage2/s3_pt_04_powershell_mid_chain": {},
    "replicate_02/gpt-5.4-mini/stage3/s3_pt_04_powershell_mid_chain": {2: (1, "sop"), 4: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage1/s3_pt_04_powershell_mid_chain": {2: (1, "sop"), 4: (2, "sop"), 7: (4, "sop"), 8: (5, "sop"), 9: (7, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s3_pt_04_powershell_mid_chain": {3: (1, "sop"), 4: (2, "so"), 5: (4, "sop"), 6: (5, "sop"), 9: (7, "sop")},
    "replicate_03/gpt-4.1-mini/stage3/s3_pt_04_powershell_mid_chain": {1: (1, "sop"), 2: (2, "so"), 4: (4, "sop"), 5: (5, "sop")},
    "replicate_03/gpt-5.4-mini/stage1/s3_pt_04_powershell_mid_chain": {1: (1, "sop"), 2: (2, "so")},
    "replicate_03/gpt-5.4-mini/stage2/s3_pt_04_powershell_mid_chain": {1: (4, "sop"), 2: (5, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s3_pt_04_powershell_mid_chain": {1: (1, "sop")},

    # s4_pt_01_word_w1
    "replicate_02/gpt-4.1-mini/stage1/s4_pt_01_word_w1": {1: (3, "sop")},
    "replicate_02/gpt-4.1-mini/stage2/s4_pt_01_word_w1": {1: (2, "sp"), 2: (3, "sop"), 3: (4, "sp")},
    "replicate_02/gpt-4.1-mini/stage3/s4_pt_01_word_w1": {1: (3, "sop"), 3: (4, "sop")},
    "replicate_02/gpt-5.4-mini/stage1/s4_pt_01_word_w1": {1: (3, "sop")},
    "replicate_02/gpt-5.4-mini/stage2/s4_pt_01_word_w1": {},
    "replicate_02/gpt-5.4-mini/stage3/s4_pt_01_word_w1": {1: (3, "sop"), 2: (4, "sop")},
    "replicate_03/gpt-4.1-mini/stage1/s4_pt_01_word_w1": {1: (3, "sp")},
    "replicate_03/gpt-4.1-mini/stage2/s4_pt_01_word_w1": {1: (1, "sop")},
    "replicate_03/gpt-4.1-mini/stage3/s4_pt_01_word_w1": {1: (1, "sop")},
    "replicate_03/gpt-5.4-mini/stage1/s4_pt_01_word_w1": {1: (3, "sop")},
    "replicate_03/gpt-5.4-mini/stage2/s4_pt_01_word_w1": {1: (3, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s4_pt_01_word_w1": {1: (3, "sp")},

    # s4_pt_02_word_w3
    "replicate_02/gpt-4.1-mini/stage1/s4_pt_02_word_w3": {1: (2, "sop"), 2: (1, "sop")},
    "replicate_02/gpt-4.1-mini/stage2/s4_pt_02_word_w3": {4: (2, "sop"), 5: (3, "sp")},
    "replicate_02/gpt-4.1-mini/stage3/s4_pt_02_word_w3": {4: (3, "sop"), 5: (2, "sop"), 6: (1, "sp")},
    "replicate_02/gpt-5.4-mini/stage1/s4_pt_02_word_w3": {},
    "replicate_02/gpt-5.4-mini/stage2/s4_pt_02_word_w3": {1: (2, "sop")},
    "replicate_02/gpt-5.4-mini/stage3/s4_pt_02_word_w3": {2: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage1/s4_pt_02_word_w3": {3: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s4_pt_02_word_w3": {},
    "replicate_03/gpt-4.1-mini/stage3/s4_pt_02_word_w3": {2: (1, "sp")},
    "replicate_03/gpt-5.4-mini/stage1/s4_pt_02_word_w3": {},
    "replicate_03/gpt-5.4-mini/stage2/s4_pt_02_word_w3": {1: (2, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s4_pt_02_word_w3": {},

    # s4_pt_03_mshta_c1
    "replicate_02/gpt-4.1-mini/stage1/s4_pt_03_mshta_c1": {1: (1, "sop"), 2: (3, "sop"), 3: (6, "sop"), 4: (7, "sop")},
    "replicate_02/gpt-4.1-mini/stage2/s4_pt_03_mshta_c1": {2: (1, "sop"), 3: (3, "sop"), 4: (4, "sop"), 5: (6, "sop")},
    "replicate_02/gpt-4.1-mini/stage3/s4_pt_03_mshta_c1": {1: (1, "sop")},
    "replicate_02/gpt-5.4-mini/stage1/s4_pt_03_mshta_c1": {2: (4, "sop")},
    "replicate_02/gpt-5.4-mini/stage2/s4_pt_03_mshta_c1": {1: (4, "sop")},
    "replicate_02/gpt-5.4-mini/stage3/s4_pt_03_mshta_c1": {},
    "replicate_03/gpt-4.1-mini/stage1/s4_pt_03_mshta_c1": {1: (1, "sop"), 2: (3, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s4_pt_03_mshta_c1": {1: (1, "sop"), 2: (3, "sop"), 3: (6, "sop"), 5: (2, "sp")},
    "replicate_03/gpt-4.1-mini/stage3/s4_pt_03_mshta_c1": {1: (3, "sop"), 2: (4, "sop"), 3: (7, "sop"), 4: (9, "sp")},
    "replicate_03/gpt-5.4-mini/stage1/s4_pt_03_mshta_c1": {1: (3, "sop")},
    "replicate_03/gpt-5.4-mini/stage2/s4_pt_03_mshta_c1": {2: (4, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s4_pt_03_mshta_c1": {},

    # s4_pt_04_powershell_c1
    "replicate_02/gpt-4.1-mini/stage1/s4_pt_04_powershell_c1": {1: (1, "sop"), 3: (4, "sop")},
    "replicate_02/gpt-4.1-mini/stage2/s4_pt_04_powershell_c1": {},
    "replicate_02/gpt-4.1-mini/stage3/s4_pt_04_powershell_c1": {1: (2, "sop")},
    "replicate_02/gpt-5.4-mini/stage1/s4_pt_04_powershell_c1": {1: (1, "sop"), 2: (2, "sop")},
    "replicate_02/gpt-5.4-mini/stage2/s4_pt_04_powershell_c1": {1: (1, "sop"), 2: (2, "sp")},
    "replicate_02/gpt-5.4-mini/stage3/s4_pt_04_powershell_c1": {1: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage1/s4_pt_04_powershell_c1": {2: (1, "sop"), 6: (4, "sop")},
    "replicate_03/gpt-4.1-mini/stage2/s4_pt_04_powershell_c1": {2: (1, "sop"), 4: (2, "sop")},
    "replicate_03/gpt-4.1-mini/stage3/s4_pt_04_powershell_c1": {2: (1, "sop"), 4: (2, "sop"), 5: (4, "sop"), 6: (5, "sop")},
    "replicate_03/gpt-5.4-mini/stage1/s4_pt_04_powershell_c1": {1: (2, "sop")},
    "replicate_03/gpt-5.4-mini/stage2/s4_pt_04_powershell_c1": {1: (4, "sop")},
    "replicate_03/gpt-5.4-mini/stage3/s4_pt_04_powershell_c1": {1: (4, "sop")},
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def step_number(step_id: str) -> int:
    return int(step_id.rsplit("S", 1)[1])


def chain_of(instance_id: str) -> str:
    return instance_id.rsplit("_stage", 1)[0]


def compact_object(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    return " | ".join(
        str(value.get(key))
        for key in ("type", "name", "path", "value", "data")
        if value.get(key) not in (None, "")
    )


def metric(rows: list[dict]) -> dict:
    totals = Counter()
    false_positives = Counter()
    numeric = (
        "gold_action_denominator",
        "gold_action_hits",
        "candidate_slot_denominator",
        "candidate_slot_tp",
        "behavior_step_denominator",
        "behavior_step_hits",
        "critical_evidence_denominator",
        "critical_evidence_hits",
        "order_pair_denominator",
        "order_pair_hits",
    )
    for row in rows:
        for key in numeric:
            totals[key] += row["totals"][key]
        false_positives.update(row["totals"]["false_positive_types"])
    result = dict(totals)
    result["run_count"] = len(rows)
    result["false_positive_types"] = dict(false_positives)
    for name, numerator, denominator in (
        ("action_recall", "gold_action_hits", "gold_action_denominator"),
        ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"),
        ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"),
        ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"),
        ("order_recall", "order_pair_hits", "order_pair_denominator"),
    ):
        n = result[numerator]
        d = result[denominator]
        result[name] = {"hits": n, "denominator": d, "value": n / d if d else None}
    return result


def aggregate(rows: list[dict], fields: tuple[str, ...]) -> dict:
    keys = sorted({"/".join(str(row[field]) for field in fields) for row in rows})
    return {
        key: metric(
            [
                row
                for row in rows
                if "/".join(str(row[field]) for field in fields) == key
            ]
        )
        for key in keys
    }


def activity_aggregate(rows: list[dict], fields: tuple[str, ...]) -> dict:
    keys = sorted({"/".join(str(row[field]) for field in fields) for row in rows})
    result = {}
    for key in keys:
        selected = [
            row
            for row in rows
            if "/".join(str(row[field]) for field in fields) == key
        ]
        names = tuple(selected[0]["investigation"])
        sums = {name: sum(float(row["investigation"].get(name, 0) or 0) for row in selected) for name in names}
        result[key] = {
            "run_count": len(selected),
            "totals": sums,
            "per_run_mean": {name: value / len(selected) for name, value in sums.items()},
        }
    return result


def main() -> None:
    for path in (OUT, REPORT_JSON, REPORT_MD):
        if path.exists():
            raise SystemExit(f"create-only refusal: {path}")

    case_rows = [json.loads(line) for line in CASES.read_text(encoding="utf-8").splitlines() if line.strip()]
    cases = {row["instance_id"]: row for row in case_rows}
    gold = {}
    for path in GOLD_ROOT.glob("*/chain_gold.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        gold[value["chain_id"]] = (value, path)

    audit_paths = sorted(SOURCE.glob("replicate_*/audits/attack8/*/*.json"))
    audits = {}
    source_failures = []
    for path in audit_paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        key = (value["replicate"], value["model"], value["stage"], value["instance_id"])
        if key in audits:
            source_failures.append("duplicate_audit:" + "/".join(key))
        audits[key] = (value, path)
        if value.get("status") != "PASS" or value.get("issues"):
            source_failures.append("audit_not_pass:" + "/".join(key))

    run_paths = sorted(SOURCE.glob("replicate_*/attack8/runs/*/*/*_run.json"))
    if len(run_paths) != 96 or len(audit_paths) != 96:
        source_failures.append(f"source_count:runs={len(run_paths)}:audits={len(audit_paths)}")
    if len(ALIGNMENTS) != 96:
        source_failures.append(f"alignment_key_count:{len(ALIGNMENTS)}")

    rows = []
    seen_alignment_keys = set()
    for path in run_paths:
        run = json.loads(path.read_text(encoding="utf-8"))
        replicate = path.parts[-6]
        model = "gpt-4.1-mini" if run["model"].startswith("gpt-4.1-mini") else "gpt-5.4-mini"
        instance = run["instance_id"]
        stage = run["experiment_stage"]
        chain = chain_of(instance)
        queue_id = f"{replicate}/{model}/{stage}/{instance}"
        audit_key = (replicate, model, stage, instance)
        if audit_key not in audits:
            source_failures.append("missing_audit:" + queue_id)
            continue
        source_audit, audit_path = audits[audit_key]
        run_hash = sha256_file(path)
        if source_audit.get("sha256") != run_hash:
            source_failures.append("audit_run_hash_mismatch:" + queue_id)
        if run.get("error") not in (None, ""):
            source_failures.append("run_error:" + queue_id)
        try:
            output = json.loads(run["output_text"])
        except Exception as exc:
            source_failures.append(f"invalid_output_json:{queue_id}:{type(exc).__name__}")
            continue
        if not isinstance(output, dict):
            source_failures.append("output_not_object:" + queue_id)
            continue

        alignment_key = f"{replicate}/{model}/{stage}/{chain}"
        if alignment_key not in ALIGNMENTS:
            source_failures.append("missing_alignment:" + alignment_key)
            continue
        seen_alignment_keys.add(alignment_key)
        decision = ALIGNMENTS[alignment_key]
        steps = output.get("code_steps", []) or []
        for ordinal, step in enumerate(steps, 1):
            emitted = int(re.sub(r"\D", "", str(step.get("step_id", ordinal))) or ordinal)
            if emitted != ordinal:
                source_failures.append(f"nonsequential_candidate_step:{queue_id}:{emitted}!={ordinal}")
        if any(ordinal < 1 or ordinal > len(steps) for ordinal in decision):
            source_failures.append("alignment_candidate_out_of_range:" + alignment_key)

        case = cases[instance]
        gold_value, gold_path = gold[chain]
        gold_steps = {step_number(item["step_id"]): item for item in gold_value["gold_steps"]}
        if any(number not in gold_steps for number, _ in decision.values()):
            source_failures.append("alignment_gold_out_of_range:" + alignment_key)

        gold_items = []
        hit_item_ids = set()
        aligned = {}
        candidate_slots = []
        false_positives = Counter()

        for ordinal, candidate in enumerate(steps, 1):
            specification = decision.get(ordinal)
            if specification:
                gold_number, letters = specification
                aligned[ordinal] = gold_number
            for kind, letter, excerpt in (
                ("subject", "s", (candidate.get("subject_process") or {}).get("name")),
                ("operation", "p", candidate.get("operation")),
                ("object", "o", compact_object(candidate.get("object") or {})),
            ):
                matched_item = None
                true_positive = 0
                if specification and letter in specification[1]:
                    matched_item = f"{gold_steps[specification[0]]['step_id']}:{kind}"
                    true_positive = 1
                    hit_item_ids.add(matched_item)
                false_positive_type = ""
                if not true_positive:
                    false_positive_type = "wrong_component" if specification else "unsupported_or_nearby"
                    false_positives[false_positive_type] += 1
                candidate_slots.append(
                    {
                        "slot_id": f"C{ordinal}:{kind}",
                        "candidate_claim_id": f"C{ordinal}",
                        "emitted_step_id": candidate.get("step_id"),
                        "kind": kind,
                        "candidate_slot_excerpt": excerpt,
                        "include_in_denominator": 1,
                        "is_true_positive": true_positive,
                        "aligned_gold_step_id": gold_steps[specification[0]]["step_id"] if specification else None,
                        "matched_gold_item_id": matched_item,
                        "false_positive_type": false_positive_type,
                    }
                )

        evidence_hits = set()
        for ordinal, gold_number in aligned.items():
            candidate = steps[ordinal - 1]
            signature = gold_steps[gold_number].get("critical_evidence_signature") or {}
            evidence_text = json.dumps(candidate.get("evidence", []), ensure_ascii=False).lower()
            anchors = (signature.get("source_row_id"), signature.get("timestamp_utc"), signature.get("target_key"))
            if any(anchor not in (None, "") and str(anchor).lower() in evidence_text for anchor in anchors):
                evidence_hits.add(gold_number)

        for gold_number, item in gold_steps.items():
            for kind in KINDS:
                item_id = f"{item['step_id']}:{kind}"
                gold_items.append(
                    {
                        "item_id": item_id,
                        "step_id": item["step_id"],
                        "kind": kind,
                        "gold_value": item["subject"] if kind == "subject" else item["action"] if kind == "operation" else item["object"],
                        "score": int(item_id in hit_item_ids),
                        "score_source": "derived_from_unique_literal_tp_matched_gold_item_id",
                    }
                )
            gold_items.append(
                {
                    "item_id": f"{item['step_id']}:critical_evidence",
                    "step_id": item["step_id"],
                    "kind": "critical_evidence",
                    "gold_value": item.get("critical_evidence_signature"),
                    "score": int(gold_number in evidence_hits),
                    "score_source": "separate_exact_canonical_evidence_anchor_review",
                }
            )

        operation_positions = {
            gold_number: ordinal
            for ordinal, gold_number in aligned.items()
            if "p" in decision[ordinal][1]
        }
        order_pairs = []
        for left, right in gold_value["gold_order_pairs"]:
            left_number = step_number(left)
            right_number = step_number(right)
            score = int(
                left_number in operation_positions
                and right_number in operation_positions
                and operation_positions[left_number] < operation_positions[right_number]
            )
            order_pairs.append(
                {
                    "pair_id": f"{left}->{right}",
                    "left_step_id": left,
                    "right_step_id": right,
                    "score": score,
                }
            )

        behavior_hits = sum(
            all(f"{item['step_id']}:{kind}" in hit_item_ids for kind in KINDS)
            for item in gold_value["gold_steps"]
        )
        totals = {
            "gold_action_denominator": len(gold_steps) * 3,
            "gold_action_hits": len(hit_item_ids),
            "candidate_slot_denominator": len(candidate_slots),
            "candidate_slot_tp": sum(item["is_true_positive"] for item in candidate_slots),
            "behavior_step_denominator": len(gold_steps),
            "behavior_step_hits": behavior_hits,
            "critical_evidence_denominator": len(gold_steps),
            "critical_evidence_hits": len(evidence_hits),
            "order_pair_denominator": len(order_pairs),
            "order_pair_hits": sum(item["score"] for item in order_pairs),
            "false_positive_types": dict(false_positives),
        }
        activity = (run.get("investigation_activity") or {}).get("summary") or {}
        usage = run.get("usage") or {}
        cost = run.get("cost_estimate") or {}
        row = {
            "queue_id": queue_id,
            "replicate": replicate,
            "model": model,
            "stage": stage,
            "instance_id": instance,
            "chain_id": chain,
            "run_path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "run_sha256": run_hash,
            "source_audit_path": str(audit_path.relative_to(ROOT)).replace("\\", "/"),
            "source_audit_sha256": sha256_file(audit_path),
            "case_sha256": hashlib.sha256(canonical_bytes(case)).hexdigest(),
            "case_file_sha256": sha256_file(CASES),
            "gold_path": str(gold_path.relative_to(ROOT)).replace("\\", "/"),
            "gold_sha256": sha256_file(gold_path),
            "gold_items": gold_items,
            "candidate_slots": candidate_slots,
            "order_pairs": order_pairs,
            "fixed_denominators": {
                "gold_action": len(gold_steps) * 3,
                "candidate_slots": len(candidate_slots),
                "behavior_steps": len(gold_steps),
                "critical_evidence": len(gold_steps),
                "order_pairs": len(order_pairs),
            },
            "totals": totals,
            "review_summary": {
                "aligned_candidate_claims": len(aligned),
                "unsupported_candidate_claims": len(steps) - len(aligned),
                "complete_gold_steps": behavior_hits,
                "missing_gold_steps": len(gold_steps) - len(set(aligned.values())),
                "causal_edge_missing_count": len(order_pairs) - sum(item["score"] for item in order_pairs),
                "nearby_or_unsupported_slot_count": false_positives["unsupported_or_nearby"],
                "wrong_component_slot_count": false_positives["wrong_component"],
                "hallucination_risk_claim_count": len(steps) - len(aligned),
            },
            "investigation": {
                **{
                    key: activity.get(key, 0)
                    for key in (
                        "lead_call_count",
                        "unique_lead_count",
                        "investigator_question_count",
                        "unique_investigator_question_count",
                        "sql_query_count",
                        "unique_sql_query_count",
                    )
                },
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "cached_input_tokens": usage.get("cached_input_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
                "cost_usd": cost.get("total_cost_usd", 0),
                "elapsed_seconds": run.get("elapsed_seconds", 0),
            },
        }
        row["decision_sha256"] = hashlib.sha256(canonical_bytes(row)).hexdigest()
        rows.append(row)

    source_failures.extend("unused_alignment:" + key for key in sorted(set(ALIGNMENTS) - seen_alignment_keys))
    if source_failures:
        raise AssertionError(json.dumps(source_failures, ensure_ascii=False, indent=2))
    if len(rows) != 96 or len({row["queue_id"] for row in rows}) != 96:
        raise AssertionError("expected 96 unique scored rows")

    consistency_failures = []
    duplicate_tp_count = 0
    gold_without_tp_count = 0
    tp_without_gold_count = 0
    for row in rows:
        gold_scores = {
            item["item_id"]: item["score"]
            for item in row["gold_items"]
            if item["kind"] in KINDS
        }
        tp_items = [
            item["matched_gold_item_id"]
            for item in row["candidate_slots"]
            if item["include_in_denominator"] == 1 and item["is_true_positive"] == 1
        ]
        duplicates = len(tp_items) - len(set(tp_items))
        duplicate_tp_count += duplicates
        if duplicates:
            consistency_failures.append(row["queue_id"] + ":duplicate_tp")
        for item_id, score in gold_scores.items():
            if score == 1 and item_id not in tp_items:
                gold_without_tp_count += 1
                consistency_failures.append(row["queue_id"] + ":gold1_without_tp:" + item_id)
            if score == 0 and item_id in tp_items:
                tp_without_gold_count += 1
                consistency_failures.append(row["queue_id"] + ":tp_without_gold1:" + item_id)
        if len(row["candidate_slots"]) != row["fixed_denominators"]["candidate_slots"]:
            consistency_failures.append(row["queue_id"] + ":candidate_denominator")
        if sum(item["score"] for item in row["gold_items"] if item["kind"] in KINDS) != row["totals"]["gold_action_hits"]:
            consistency_failures.append(row["queue_id"] + ":gold_action_total")

    validation = {
        "status": "pass" if not consistency_failures else "fail",
        "source_audit_status": "pass",
        "source_run_count": len(run_paths),
        "source_audit_count": len(audit_paths),
        "valid_output_json_count": len(rows),
        "row_count": len(rows),
        "run_hash_count": len({row["run_sha256"] for row in rows}),
        "case_hash_count": len({row["case_sha256"] for row in rows}),
        "gold_hash_count": len({row["gold_sha256"] for row in rows}),
        "gold_action_items_checked": sum(row["fixed_denominators"]["gold_action"] for row in rows),
        "candidate_slots_checked": sum(row["fixed_denominators"]["candidate_slots"] for row in rows),
        "behavior_steps_checked": sum(row["fixed_denominators"]["behavior_steps"] for row in rows),
        "critical_evidence_items_checked": sum(row["fixed_denominators"]["critical_evidence"] for row in rows),
        "order_pairs_checked": sum(row["fixed_denominators"]["order_pairs"] for row in rows),
        "gold1_without_tp": gold_without_tp_count,
        "tp_without_gold1": tp_without_gold_count,
        "duplicate_tp": duplicate_tp_count,
        "failures": consistency_failures,
        "external_judge_api_used": False,
    }
    if validation["status"] != "pass":
        raise AssertionError(json.dumps(validation, ensure_ascii=False, indent=2))

    overall = metric(rows)
    aggregates = {
        "by_replicate": aggregate(rows, ("replicate",)),
        "by_model": aggregate(rows, ("model",)),
        "by_stage": aggregate(rows, ("stage",)),
        "by_case": aggregate(rows, ("chain_id",)),
        "by_model_stage": aggregate(rows, ("model", "stage")),
        "by_model_case": aggregate(rows, ("model", "chain_id")),
        "by_replicate_model": aggregate(rows, ("replicate", "model")),
        "by_replicate_stage": aggregate(rows, ("replicate", "stage")),
        "by_replicate_case": aggregate(rows, ("replicate", "chain_id")),
        "by_replicate_model_stage": aggregate(rows, ("replicate", "model", "stage")),
        "by_replicate_model_case": aggregate(rows, ("replicate", "model", "chain_id")),
    }
    investigation = {
        "by_replicate": activity_aggregate(rows, ("replicate",)),
        "by_model": activity_aggregate(rows, ("model",)),
        "by_replicate_model": activity_aggregate(rows, ("replicate", "model")),
    }
    result = {
        "schema_version": "attack8_mini_reps_02_03_codex_sol_v5_atomic_v1",
        "reviewer": {
            "kind": "independent_experiment_nonparticipant_codex",
            "model": "gpt-5.6-sol",
            "external_judge_api_used": False,
        },
        "scoring_policy": {
            "action_components": ["subject", "operation", "object"],
            "action_alias": "operation",
            "gold_hit_derivation": "unique literal included TP candidate slot matched_gold_item_id",
            "behavior_step_rule": "all subject+operation+object hits",
            "critical_evidence_separate": True,
            "critical_evidence_rule": "canonical source_row_id, timestamp_utc, or target_key anchor appears in aligned candidate evidence",
            "order_unit": "adjacent Gold pair",
            "pid_scored": False,
            "hidden_alert_mapping_scored": False,
            "candidate_denominator": "3 fixed slots per emitted code_step",
            "fixed_gold_denominators": True,
            "external_judge_api_used": False,
        },
        "source": {
            "root": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
            "replicates": ["replicate_02", "replicate_03"],
            "phase": "attack8",
            "run_count": 96,
            "source_audits_all_pass": True,
            "case_file": str(CASES.relative_to(ROOT)).replace("\\", "/"),
            "case_file_sha256": sha256_file(CASES),
        },
        "validation": validation,
        "overall": overall,
        **aggregates,
        "investigation": investigation,
        "failure_analysis": {
            "unrecovered_gold_steps": sum(row["review_summary"]["missing_gold_steps"] for row in rows),
            "missing_adjacent_causal_edges": sum(row["review_summary"]["causal_edge_missing_count"] for row in rows),
            "nearby_or_unsupported_slots": sum(row["review_summary"]["nearby_or_unsupported_slot_count"] for row in rows),
            "wrong_component_slots": sum(row["review_summary"]["wrong_component_slot_count"] for row in rows),
            "hallucination_risk_claims": sum(row["review_summary"]["hallucination_risk_claim_count"] for row in rows),
            "interpretation": "Primary failures are truncated causal chains, nearby process/file activity substituted for the canonical chain, and over-connected pivots that skip an intermediate process. Partial subject/operation credit is retained only when the emitted claim itself identifies the corresponding Gold behavior; PID and hidden alert mapping are never scored.",
        },
        "rows": rows,
    }

    OUT.mkdir(parents=False)
    (OUT / "formal_scores.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "per_run_scores.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    (OUT / "cross_field_consistency_audit.json").write_text(
        json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT / "semantic_alignment_decisions.json").write_text(
        json.dumps(ALIGNMENTS, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    REPORT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def format_metric(value: dict) -> str:
        if value["value"] is None:
            return f"{value['hits']}/{value['denominator']} = n/a"
        return f"{value['hits']}/{value['denominator']} = {value['value']:.2%}"

    lines = [
        "# Attack8 replicate_02/03 Codex v5 atomic scoring (2026-08-06)",
        "",
        "OpenAI judge API/API scorer was not used. An experiment-nonparticipant Codex gpt-5.6-sol reviewer froze the semantic alignments, after which every score, fixed denominator, hash, and aggregate was derived deterministically.",
        "",
        "## Headline metrics",
        "",
        "| Slice | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    headline = [("Overall", overall)]
    headline.extend((key, value) for key, value in aggregates["by_replicate"].items())
    headline.extend((key, value) for key, value in aggregates["by_model"].items())
    headline.extend((key, value) for key, value in aggregates["by_stage"].items())
    for name, value in headline:
        lines.append(
            f"| {name} | {value['run_count']} | {format_metric(value['action_recall'])} | "
            f"{format_metric(value['candidate_precision'])} | {format_metric(value['behavior_step_recall'])} | "
            f"{format_metric(value['critical_evidence_recall'])} | {format_metric(value['order_recall'])} |"
        )

    lines.extend(
        [
            "",
            "## Model x Stage",
            "",
            "| Model / Stage | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, value in aggregates["by_model_stage"].items():
        lines.append(
            f"| {name} | {value['run_count']} | {format_metric(value['action_recall'])} | "
            f"{format_metric(value['candidate_precision'])} | {format_metric(value['behavior_step_recall'])} | "
            f"{format_metric(value['critical_evidence_recall'])} | {format_metric(value['order_recall'])} |"
        )

    lines.extend(
        [
            "",
            "## Deterministic audit",
            "",
            f"- Status: **{validation['status'].upper()}**",
            f"- Source runs/audits/output JSON: {validation['source_run_count']}/{validation['source_audit_count']}/{validation['valid_output_json_count']} (all source audits PASS)",
            f"- Checked: {validation['gold_action_items_checked']} Gold action items, {validation['candidate_slots_checked']} candidate slots, {validation['behavior_steps_checked']} behavior steps, {validation['critical_evidence_items_checked']} critical items, {validation['order_pairs_checked']} adjacent order pairs.",
            f"- Cross-field mismatches: Gold=1 without TP {validation['gold1_without_tp']}; TP without Gold=1 {validation['tp_without_gold1']}; duplicate TP {validation['duplicate_tp']}.",
            "- PID and hidden alert mapping are excluded from scoring. Critical evidence is diagnosed separately from action recall.",
            "",
            "## Failure pattern",
            "",
            f"- Unrecovered Gold steps across runs: {result['failure_analysis']['unrecovered_gold_steps']}",
            f"- Missing adjacent causal edges: {result['failure_analysis']['missing_adjacent_causal_edges']}",
            f"- Nearby/unsupported candidate slots: {result['failure_analysis']['nearby_or_unsupported_slots']}",
            f"- Wrong-component candidate slots: {result['failure_analysis']['wrong_component_slots']}",
            f"- {result['failure_analysis']['interpretation']}",
            "",
            "The score root contains every run/case/Gold hash, Gold item, candidate slot, order pair, fixed denominator, per-run total, semantic alignment decision, and cross-field consistency audit.",
        ]
    )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": "pass", "overall": overall, "validation": validation}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
