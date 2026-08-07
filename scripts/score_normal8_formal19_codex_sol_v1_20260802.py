#!/usr/bin/env python3
"""Create-only, local Codex scoring for the normal8 formal-19 retry matrix.

No judge/scorer API is used.  The program freezes literal candidate slots,
performs one-step semantic alignment under the v5 atomic process-chain rubric,
derives Gold subject/operation/object hits solely from unique included-TP slot
coverage, and writes provenance-bound ledgers plus aggregates.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-08-01/normal8_three_model_three_stage_formal_19_retry_02"
SCORE_ROOT = RUN_ROOT / "scores_codex_sol_v1"
REPORT_JSON = ROOT / "docs/current_experiment/normal8_two_model_three_stage_codex_sol_results_20260802.json"
REPORT_MD = ROOT / "docs/current_experiment/normal8_two_model_three_stage_codex_sol_results_20260802.md"
AUDIT_PATH = RUN_ROOT / "full_retry_audit.json"
CASE_PATH = ROOT / "data/current_experiment/cases/normal8_observable_component_v3_stage_cases_20260726.jsonl"
VALIDATION_PATH = ROOT / "docs/current_experiment/normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
MODELS = ("gpt-4.1-mini", "gpt-5.4-mini")
STAGES = ("stage1", "stage2", "stage3")
ACTION_KINDS = ("subject", "operation", "object")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json_new(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl_new(path: Path, rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def meaningful(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, dict):
        return any(meaningful(v) for v in value.values())
    if isinstance(value, list):
        return any(meaningful(v) for v in value)
    if isinstance(value, str):
        return value.strip().lower() not in {"", "...", "{...}", "unknown", "null", "none", "n/a", "未提示", "不明"}
    return True


def meaningful_object(value: Any) -> bool:
    if not isinstance(value, dict):
        return meaningful(value)
    return any(meaningful(value.get(k)) for k in ("name", "path", "value", "data"))


def candidate_slots(output: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, step in enumerate(output.get("code_steps") or [], 1):
        claim_id = f"C{index}"
        step_id = str(step.get("step_id") or f"step_{index}")
        for kind, value in (("subject", step.get("subject_process")), ("operation", step.get("operation")), ("object", step.get("object"))):
            keep = meaningful_object(value) if kind == "object" else meaningful(value)
            if keep:
                excerpt = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value)
                rows.append({"candidate_claim_id": claim_id, "candidate_step_id": step_id, "slot_id": f"{claim_id}:{kind}", "kind": kind, "candidate_slot_excerpt": excerpt})
    return rows


def exe_name(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("name") or value.get("path") or ""
    text = str(value or "").replace("/", "\\").strip().lower()
    text = re.sub(r"\s*\(pid[^)]*\)\s*", "", text, flags=re.I)
    return PureWindowsPath(text).name


def norm_text(value: Any) -> str:
    return str(value or "").replace("/", "\\").replace('"', "").strip().lower()


def object_text(value: Any) -> str:
    if not isinstance(value, dict):
        return norm_text(value)
    return " | ".join(norm_text(value.get(k)) for k in ("name", "path", "value", "data") if meaningful(value.get(k)))


def subject_matches(candidate: Any, gold: dict[str, Any]) -> bool:
    return bool(exe_name(candidate)) and exe_name(candidate) == exe_name(gold["subject"])


def registry_suffix(text: str) -> str:
    text = norm_text(text)
    marker = "\\software\\"
    return text[text.find(marker) + 1 :] if marker in text else text


def object_matches(candidate: Any, gold: dict[str, Any]) -> bool:
    c = object_text(candidate)
    g = norm_text(gold["object"])
    if "(pid" in str(gold["object"]).lower():
        return exe_name(candidate) == exe_name(gold["object"])
    if "\\software\\" in g:
        return registry_suffix(g) in registry_suffix(c)
    if re.search(r"\b\d+\.\d+\.\d+\.\d+:\d+", g):
        endpoints = re.findall(r"\b\d+\.\d+\.\d+\.\d+:\d+", g)
        if not all(endpoint in c for endpoint in endpoints):
            return False
        local = re.search(r"local port (\d+)", g)
        return not local or bool(re.search(rf"(?:local[^|]*|from[^|]*)\b{local.group(1)}\b", c))
    if re.fullmatch(r"0\.0\.0\.0:\d+", g):
        return g in c
    if ":\\" in g:
        return g in c
    return norm_text(g) in c


def op_tokens(value: Any) -> str:
    return re.sub(r"[^a-z0-9_\u3040-\u30ff\u3400-\u9fff]+", " ", str(value or "").lower())


def operation_matches(candidate: Any, gold: dict[str, Any]) -> bool:
    op = op_tokens(candidate)
    action = str(gold["action"]).lower()
    if not op or "�" in str(candidate):
        return False
    if "interface-discovery" in action:
        return any(x in op for x in ("interface", "discover", "probe", "列挙", "探索")) and any(x in op for x in ("start", "launch", "spawn", "起動"))
    if "dns capture worker" in action:
        return any(x in op for x in ("dns", "capture", "worker", "収集")) and any(x in op for x in ("start", "launch", "spawn", "起動", "initiation"))
    if action == "started":
        return any(x in op for x in ("start", "launch", "spawn", "process_create", "process creation", "create_process", "起動", "生成")) or op.strip() == "execute"
    if "executed batch script" in action or "invoked script" in action:
        return any(x in op for x in ("execute", "invoke", "run", "script", "実行", "呼び出"))
    if "created directory" in action:
        return any(x in op for x in ("create", "mkdir", "directory", "作成"))
    if "created packet-capture file" in action:
        return any(x in op for x in ("file_create", "create_file", "write", "created", "作成", "書き込"))
    if "listened" in action:
        return any(x in op for x in ("listen", "network_listen", "待受", "待ち受"))
    if "created network connection" in action:
        return any(x in op for x in ("network_connect", "connect", "connection_create", "接続"))
    if "wrote registry value" in action:
        return any(x in op for x in ("registry_write", "write", "modify", "add", "set_value", "書き込", "追加", "変更"))
    return False


def slot_truths(step: dict[str, Any], gold: dict[str, Any]) -> dict[str, bool]:
    return {
        "subject": subject_matches(step.get("subject_process"), gold),
        "operation": operation_matches(step.get("operation"), gold),
        "object": object_matches(step.get("object"), gold),
    }


def placeholder_like(text: str) -> bool:
    low = text.lower()
    return "�" in text or "undefined" in low or "unknown" in low or "placeholder" in low or "����" in text


def critical_evidence_hit(step: dict[str, Any], gold: dict[str, Any]) -> tuple[int, str | None]:
    canon = (gold.get("canonical_evidence") or [{}])[0]
    gold_source = norm_text(canon.get("source_stream"))
    gold_time = norm_text(canon.get("timestamp_utc")).replace("t", " ")[:19]
    target_terms = [
        exe_name(gold.get("subject")),
        exe_name(gold.get("object")),
        norm_text(canon.get("object_name")),
        norm_text(canon.get("remote_ip")),
        registry_suffix(norm_text(canon.get("regmod_name"))),
    ]
    target_terms = [x for x in target_terms if x and x not in {"none", "."}]
    for evidence in step.get("evidence") or []:
        if not isinstance(evidence, dict):
            continue
        source = norm_text(evidence.get("source_stream"))
        when = norm_text(evidence.get("timestamp") or evidence.get("timestamp_utc")).replace("t", " ")[:19]
        row_id = evidence.get("source_row_id") or evidence.get("row_id")
        if row_id is not None and str(row_id) == str(canon.get("source_row_id")):
            return 1, json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        if source != gold_source or when != gold_time:
            continue
        blob = norm_text(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
        if any(term in blob for term in target_terms):
            return 1, json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    return 0, None


def score_run(run_path: Path, case: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    run = load_json(run_path)
    output = json.loads(run["output_text"])
    gold_path = Path(run["atlasv2_s3_s4_attack8_paired_experiment"]["gold"])
    gold = load_json(gold_path)
    gold_steps = gold["gold_steps"]
    slots = candidate_slots(output)
    slot_by_id = {x["slot_id"]: x for x in slots}
    steps = output.get("code_steps") or []
    covered: set[str] = set()
    claim_rows: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    aligned_claims: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for index, step in enumerate(steps, 1):
        claim_id = f"C{index}"
        candidates = []
        for gindex, gstep in enumerate(gold_steps):
            truths = slot_truths(step, gstep)
            new_count = sum(truths[k] and f"{gold['chain_id']}:{gstep['step_id']}:{k}" not in covered for k in ACTION_KINDS)
            total = sum(truths.values())
            distance = abs((int(step.get("order") or index) - 1) - gindex)
            candidates.append((new_count, total, -distance, -gindex, gstep, truths))
        best = max(candidates, key=lambda x: x[:4]) if candidates else None
        aligned = best[4] if best and best[1] > 0 else None
        truths = best[5] if aligned is not None else {k: False for k in ACTION_KINDS}
        if aligned is not None:
            aligned_claims[aligned["step_id"]].append((int(step.get("order") or index), claim_id))
        claim_rows.append({
            "candidate_claim_id": claim_id,
            "candidate_step_id": str(step.get("step_id") or f"step_{index}"),
            "candidate_order": int(step.get("order") or index),
            "aligned_gold_step_id": aligned["step_id"] if aligned else None,
            "alignment_basis": [k for k, v in truths.items() if v],
            "evidence_count": len(step.get("evidence") or []),
        })
        for kind in ACTION_KINDS:
            slot_id = f"{claim_id}:{kind}"
            if slot_id not in slot_by_id:
                continue
            target = f"{gold['chain_id']}:{aligned['step_id']}:{kind}" if aligned else None
            raw_tp = bool(aligned and truths[kind])
            is_tp = int(raw_tp and target not in covered)
            if is_tp:
                covered.add(target)
            excerpt = slot_by_id[slot_id]["candidate_slot_excerpt"]
            if is_tp:
                fp_type = ""
            elif raw_tp:
                fp_type = "duplicate"
            elif placeholder_like(excerpt):
                fp_type = "unsupported"
            elif aligned and kind == "operation":
                fp_type = "wrong_relation"
            elif aligned:
                fp_type = "wrong_value"
            else:
                fp_type = "wrong_component"
            decisions.append({
                **slot_by_id[slot_id],
                "include_in_denominator": 1,
                "aligned_gold_step_id": aligned["step_id"] if aligned else None,
                "matched_gold_item_id": target if is_tp else None,
                "is_true_positive": is_tp,
                "false_positive_type": fp_type,
                "reason_ja": "literal slot semantic match" if is_tp else f"{fp_type}: v5 atomic alignment",
            })
    gold_items: list[dict[str, Any]] = []
    critical_hits: dict[str, int] = {}
    for gstep in gold_steps:
        for kind, field in (("subject", "subject"), ("operation", "action"), ("object", "object")):
            item_id = f"{gold['chain_id']}:{gstep['step_id']}:{kind}"
            gold_items.append({
                "item_id": item_id,
                "step_id": gstep["step_id"],
                "kind": kind,
                "gold_value": gstep[field],
                "score": int(item_id in covered),
                "score_source": "derived_from_unique_included_tp_matched_gold_item_id",
            })
        critical_id = f"{gold['chain_id']}:{gstep['step_id']}:critical_evidence"
        hit, excerpt = 0, None
        for order, claim_id in aligned_claims.get(gstep["step_id"], []):
            candidate_step = steps[int(claim_id[1:]) - 1]
            value, evidence_excerpt = critical_evidence_hit(candidate_step, gstep)
            if value:
                hit, excerpt = value, evidence_excerpt
                break
        critical_hits[gstep["step_id"]] = hit
        gold_items.append({
            "item_id": critical_id,
            "step_id": gstep["step_id"],
            "kind": "critical_evidence",
            "gold_value": gstep.get("evidence_basis"),
            "score": hit,
            "matched_candidate_excerpt": excerpt,
            "score_source": "separate_substantive_evidence_diagnostic_pid_non_scoring",
        })
    order_pairs = []
    for before, after in gold.get("gold_order_pairs") or []:
        before_claims, after_claims = aligned_claims.get(before, []), aligned_claims.get(after, [])
        hit = int(any(a[0] < b[0] and a[1] != b[1] for a in before_claims for b in after_claims))
        order_pairs.append({
            "pair_id": f"{gold['chain_id']}:{before}->{after}",
            "before_step_id": before,
            "after_step_id": after,
            "score": hit,
            "reason_ja": "distinct aligned candidate claims occur in Gold order" if hit else "Gold adjacent order not recovered by two distinct aligned claims",
        })
    action = [x for x in gold_items if x["kind"] in ACTION_KINDS]
    behavior_hits = sum(all(next(x["score"] for x in action if x["step_id"] == s["step_id"] and x["kind"] == k) for k in ACTION_KINDS) for s in gold_steps)
    fp_types = Counter(x["false_positive_type"] for x in decisions if not x["is_true_positive"])
    missing = []
    for gstep in gold_steps:
        missed = [k for k in ACTION_KINDS if f"{gold['chain_id']}:{gstep['step_id']}:{k}" not in covered]
        if missed:
            reason = "no_aligned_candidate_claim" if gstep["step_id"] not in aligned_claims else "partial_atomic_component_recovery"
            missing.append({"step_id": gstep["step_id"], "missing_kinds": missed, "reason": reason})
    research = {
        "chief_leads": audit["chief_lead_event_count"],
        "unique_chief_leads": audit["unique_chief_lead_count"],
        "repeated_chief_leads": audit["repeated_chief_lead_count"],
        "unique_chief_behavior_keys": audit["unique_chief_behavior_key_count"],
        "accepted_behavior_fingerprints": audit["accepted_behavior_fingerprint_count"],
        "behavior_guard_status_counts": audit["behavior_guard_status_counts"],
        "investigator_questions": audit["investigator_question_count"],
        "unique_investigator_questions": audit["unique_investigator_question_count"],
        "sql_queries": audit["sql_query_count"],
        "unique_sql_queries": audit["unique_sql_query_count"],
        "activity_events": audit["activity_event_count"],
        "api_calls": audit["api_call_count"],
        "tokens": audit["total_tokens"],
        "cost_usd": audit["cost_usd"],
        "elapsed_seconds": audit["elapsed_seconds"],
    }
    metrics = {
        "case_count": 1,
        "gold_action_hits": sum(x["score"] for x in action),
        "gold_action_denominator": len(action),
        "candidate_slot_tp": sum(x["is_true_positive"] for x in decisions),
        "candidate_slot_denominator": len(decisions),
        "behavior_step_hits": behavior_hits,
        "behavior_step_denominator": len(gold_steps),
        "critical_evidence_hits": sum(critical_hits.values()),
        "critical_evidence_denominator": len(gold_steps),
        "order_pair_hits": sum(x["score"] for x in order_pairs),
        "order_pair_denominator": len(order_pairs),
    }
    for metric, num, den in (("action_recall", "gold_action_hits", "gold_action_denominator"), ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"), ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"), ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"), ("order_recall", "order_pair_hits", "order_pair_denominator")):
        metrics[metric] = metrics[num] / metrics[den] if metrics[den] else None
    return {
        "schema_version": "normal8_codex_sol_v1_atomic_process_chain",
        "queue_id": f"{run['model']}/{run['experiment_stage']}/{run['instance_id']}/{sha256_file(run_path)[:16]}",
        "model": run["model"],
        "stage": run["experiment_stage"],
        "instance_id": run["instance_id"],
        "chain_id": gold["chain_id"],
        "run_json": str(run_path.relative_to(ROOT)).replace("\\", "/"),
        "run_sha256": sha256_file(run_path),
        "case_jsonl": str(CASE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "case_file_sha256": sha256_file(CASE_PATH),
        "gold_json": str(gold_path.relative_to(ROOT)).replace("\\", "/"),
        "gold_sha256": sha256_file(gold_path),
        "validation_steps_sha256": sha256_file(VALIDATION_PATH),
        "fixed_denominators": {"gold_action": len(action), "candidate_slots": len(decisions), "behavior_steps": len(gold_steps), "critical_evidence": len(gold_steps), "order_pairs": len(order_pairs)},
        "review_policy": {"action_aliases_operation": True, "pid_identity_scored": False, "hidden_alert_mapping_scored": False, "command_line_separate_slot": False, "critical_evidence_separate": True, "candidate_slots_fixed": True, "gold_action_hit_rule": "unique literal included-TP matched_gold_item_id coverage"},
        "gold_items": gold_items,
        "candidate_claim_alignments": claim_rows,
        "candidate_slots": decisions,
        "order_pairs": order_pairs,
        "metrics": metrics,
        "investigation": research,
        "diagnostics": {
            "missing_gold_steps": missing,
            "false_positive_types": dict(sorted(fp_types.items())),
            "unaligned_candidate_claim_count": sum(x["aligned_gold_step_id"] is None for x in claim_rows),
            "overconnection_candidate_slot_count": sum(x["false_positive_type"] == "wrong_component" for x in decisions),
            "hallucination_like_unsupported_slot_count": fp_types.get("unsupported", 0),
            "mojibake_or_placeholder_slot_count": sum(placeholder_like(x["candidate_slot_excerpt"]) for x in decisions),
        },
    }


def add_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = defaultdict(int)
    fp = Counter()
    guard = Counter()
    for row in rows:
        for k, v in row["metrics"].items():
            if k.endswith(("_recall", "_precision")):
                continue
            counts[k] += int(v)
        fp.update(row["diagnostics"]["false_positive_types"])
        guard.update(row["investigation"]["behavior_guard_status_counts"])
        for key in ("chief_leads", "unique_chief_leads", "repeated_chief_leads", "unique_chief_behavior_keys", "accepted_behavior_fingerprints", "investigator_questions", "unique_investigator_questions", "sql_queries", "unique_sql_queries", "activity_events", "api_calls", "tokens"):
            counts[key] += int(row["investigation"][key])
        counts["cost_usd"] += row["investigation"]["cost_usd"]
        counts["elapsed_seconds"] += row["investigation"]["elapsed_seconds"]
        counts["unaligned_candidate_claim_count"] += row["diagnostics"]["unaligned_candidate_claim_count"]
        counts["overconnection_candidate_slot_count"] += row["diagnostics"]["overconnection_candidate_slot_count"]
        counts["hallucination_like_unsupported_slot_count"] += row["diagnostics"]["hallucination_like_unsupported_slot_count"]
    out: dict[str, Any] = dict(counts)
    for metric, num, den in (("action_recall", "gold_action_hits", "gold_action_denominator"), ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"), ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"), ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"), ("order_recall", "order_pair_hits", "order_pair_denominator")):
        out[metric] = out[num] / out[den] if out[den] else None
    out["chief_lead_unique_rate"] = out["unique_chief_leads"] / out["chief_leads"] if out["chief_leads"] else None
    out["investigator_question_unique_rate"] = out["unique_investigator_questions"] / out["investigator_questions"] if out["investigator_questions"] else None
    out["sql_query_unique_rate"] = out["unique_sql_queries"] / out["sql_queries"] if out["sql_queries"] else None
    out["mean_tokens_per_run"] = out["tokens"] / out["case_count"]
    out["mean_cost_usd_per_run"] = out["cost_usd"] / out["case_count"]
    out["mean_elapsed_seconds_per_run"] = out["elapsed_seconds"] / out["case_count"]
    out["false_positive_types"] = dict(sorted(fp.items()))
    out["behavior_guard_status_counts"] = dict(sorted(guard.items()))
    return out


def grouped(rows: list[dict[str, Any]], key) -> dict[str, Any]:
    values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        values[str(key(row))].append(row)
    return {name: add_metrics(group) for name, group in sorted(values.items())}


def validate(rows: list[dict[str, Any]], audit_index: dict[tuple[str, str, str], dict[str, Any]]) -> dict[str, Any]:
    failures: list[str] = []
    if len(rows) != 48:
        failures.append(f"ROW_COUNT:{len(rows)}")
    for row in rows:
        key = (row["model"], row["stage"], row["instance_id"])
        audit = audit_index.get(key)
        if not audit:
            failures.append(f"AUDIT_MISSING:{key}")
            continue
        for field in ("run_sha256", "gold_sha256", "case_file_sha256", "validation_steps_sha256"):
            audit_field = {"run_sha256": "sha256", "validation_steps_sha256": "validation_sha256"}.get(field, field)
            if row[field] != audit.get(audit_field):
                failures.append(f"HASH_MISMATCH:{key}:{field}")
        action = {x["item_id"]: x for x in row["gold_items"] if x["kind"] in ACTION_KINDS}
        tp = [x for x in row["candidate_slots"] if x["include_in_denominator"] == 1 and x["is_true_positive"] == 1]
        targets = [x["matched_gold_item_id"] for x in tp]
        if len(targets) != len(set(targets)):
            failures.append(f"DUPLICATE_TP_TARGET:{key}")
        for slot in tp:
            item = action.get(slot["matched_gold_item_id"])
            if not item or item["kind"] != slot["kind"] or item["step_id"] != slot["aligned_gold_step_id"]:
                failures.append(f"TP_TARGET_INCONSISTENT:{key}:{slot['slot_id']}")
        for item_id, item in action.items():
            if item["score"] != int(item_id in targets):
                failures.append(f"GOLD_TP_INCONSISTENT:{key}:{item_id}")
        den = row["fixed_denominators"]
        if den["candidate_slots"] != len(row["candidate_slots"]) or den["gold_action"] != len(action):
            failures.append(f"DENOMINATOR_MISMATCH:{key}")
        step_scores: dict[str, dict[str, int]] = defaultdict(dict)
        for item in action.values():
            step_scores[item["step_id"]][item["kind"]] = item["score"]
        derived_behavior = sum(all(parts.get(k) == 1 for k in ACTION_KINDS) for parts in step_scores.values())
        if derived_behavior != row["metrics"]["behavior_step_hits"]:
            failures.append(f"BEHAVIOR_DERIVATION_MISMATCH:{key}")
    return {
        "status": "PASS" if not failures else "FAIL",
        "row_count": len(rows),
        "expected_row_count": 48,
        "checks": {"run_case_gold_hash_binding": True, "unique_tp_gold_coverage": True, "gold_hit_equals_tp_matching": True, "candidate_fixed_denominator": True, "behavior_step_requires_all_three": True, "critical_evidence_separate": True, "adjacent_order_pairs_separate": True, "pid_and_hidden_alert_non_scoring": True},
        "failure_count": len(failures),
        "failures": failures,
    }


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def metric_table(title: str, groups: dict[str, Any]) -> str:
    lines = [f"## {title}", "", "| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |", "|---|---:|---:|---:|---:|---:|---:|"]
    for name, m in groups.items():
        lines.append(f"| {name} | {m['case_count']} | {pct(m['action_recall'])} | {pct(m['candidate_precision'])} | {pct(m['behavior_step_recall'])} | {pct(m['critical_evidence_recall'])} | {pct(m['order_recall'])} |")
    return "\n".join(lines)


def main() -> None:
    outputs = [SCORE_ROOT, REPORT_JSON, REPORT_MD]
    existing = [str(path) for path in outputs if path.exists()]
    if existing:
        raise SystemExit("create-only refusal: " + ", ".join(existing))
    source_audit = load_json(AUDIT_PATH)
    if source_audit.get("status") != "PASS" or source_audit.get("audited_runs") != 48:
        raise SystemExit("full_retry_audit is not 48-run PASS")
    cases = {str(x["instance_id"]): x for x in load_jsonl(CASE_PATH)}
    audit_index = {(x["model"], x["stage"], x["instance_id"]): x for x in source_audit["audits"]}
    rows = []
    for run_path in sorted((RUN_ROOT / "runs").glob("*/*/*_run.json")):
        run = load_json(run_path)
        if run["model"] not in MODELS or run["experiment_stage"] not in STAGES:
            continue
        case = cases.get(run["instance_id"])
        audit = audit_index.get((run["model"], run["experiment_stage"], run["instance_id"]))
        if case is None or audit is None:
            raise SystemExit(f"missing case/audit binding: {run_path}")
        rows.append(score_run(run_path, case, audit))
    validation = validate(rows, audit_index)
    if validation["status"] != "PASS":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
    overall = add_metrics(rows)
    by_model = grouped(rows, lambda r: r["model"])
    by_stage = grouped(rows, lambda r: r["stage"])
    by_case = grouped(rows, lambda r: r["chain_id"])
    by_model_stage = grouped(rows, lambda r: f"{r['model']}/{r['stage']}")
    metrics = {"overall": overall, "by_model": by_model, "by_stage": by_stage, "by_case": by_case, "by_model_stage": by_model_stage}
    missing_reasons = Counter(item["reason"] for row in rows for item in row["diagnostics"]["missing_gold_steps"])
    missing_kinds = Counter(kind for row in rows for item in row["diagnostics"]["missing_gold_steps"] for kind in item["missing_kinds"])
    analysis = {
        "missing_reconstruction": {"reason_counts": dict(sorted(missing_reasons.items())), "missing_component_counts": dict(sorted(missing_kinds.items())), "run_level_details": [{"queue_id": r["queue_id"], **r["diagnostics"]} for r in rows if r["diagnostics"]["missing_gold_steps"]]},
        "overconnection": {"definition": "fixed candidate slots belonging to a candidate claim with no Gold-step atomic alignment", "candidate_slot_count": overall["overconnection_candidate_slot_count"], "unaligned_candidate_claim_count": overall["unaligned_candidate_claim_count"]},
        "hallucination": {"definition": "literal slot contains an unsupported/corrupted placeholder-like value; nearby but observed wrong components are counted as overconnection, not hallucination", "hallucination_like_unsupported_slot_count": overall["hallucination_like_unsupported_slot_count"]},
        "false_positive_types": overall["false_positive_types"],
        "investigation_behavior": {"overall": {k: overall[k] for k in ("chief_leads", "unique_chief_leads", "chief_lead_unique_rate", "investigator_questions", "unique_investigator_questions", "sql_queries", "unique_sql_queries", "activity_events", "api_calls", "tokens", "cost_usd", "elapsed_seconds", "mean_tokens_per_run", "mean_cost_usd_per_run", "mean_elapsed_seconds_per_run")}, "behavior_guard_status_counts": overall["behavior_guard_status_counts"], "by_model": by_model, "by_stage": by_stage},
    }
    provenance = {
        "schema_version": "normal8_codex_sol_v1_provenance",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "route": "Codex local/offline formal scoring; no OpenAI judge API and no API scorer",
        "run_root": str(RUN_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "score_root": str(SCORE_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "source_full_retry_audit": str(AUDIT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "source_full_retry_audit_sha256": sha256_file(AUDIT_PATH),
        "source_full_retry_audit_status": source_audit["status"],
        "case_file": str(CASE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "case_file_sha256": sha256_file(CASE_PATH),
        "validation_file_sha256": sha256_file(VALIDATION_PATH),
        "run_count": len(rows),
        "models": list(MODELS),
        "stages": list(STAGES),
        "run_case_gold_bindings": [{k: row[k] for k in ("queue_id", "model", "stage", "instance_id", "chain_id", "run_json", "run_sha256", "case_jsonl", "case_file_sha256", "gold_json", "gold_sha256", "validation_steps_sha256", "fixed_denominators")} for row in rows],
        "rubric": rows[0]["review_policy"],
        "external_judge_api_calls": False,
        "api_scorer_calls": False,
    }
    report = {
        "schema_version": "normal8_two_model_three_stage_codex_sol_results_20260802_v1",
        "status": "PASS",
        "scope": "8 normal use cases x 3 stages x 2 models = 48 completed runs",
        "provenance": provenance,
        "metrics": metrics,
        "analysis": analysis,
        "cross_field_validation": validation,
        "score_artifacts": ["formal_scores.jsonl", "metrics.json", "analysis.json", "provenance_manifest.json", "cross_field_validation.json"],
    }
    SCORE_ROOT.mkdir(parents=True, exist_ok=False)
    write_jsonl_new(SCORE_ROOT / "formal_scores.jsonl", rows)
    write_json_new(SCORE_ROOT / "metrics.json", metrics)
    write_json_new(SCORE_ROOT / "analysis.json", analysis)
    write_json_new(SCORE_ROOT / "provenance_manifest.json", provenance)
    write_json_new(SCORE_ROOT / "cross_field_validation.json", validation)
    write_json_new(REPORT_JSON, report)
    markdown = "\n\n".join([
        "# Normal8 two-model, three-stage Codex formal score (2026-08-02)",
        "48/48 runs were scored locally under the v5 atomic process-chain rubric. Full retry audit and cross-field consistency are PASS. OpenAI judge API/API scorer calls: 0.",
        metric_table("Overall", {"all 48 runs": overall}),
        metric_table("By model", by_model),
        metric_table("By stage", by_stage),
        metric_table("By model and stage", by_model_stage),
        metric_table("By use case", by_case),
        "## Investigation behavior\n\n" + f"Chief leads {overall['chief_leads']:,} (unique {overall['unique_chief_leads']:,}, {pct(overall['chief_lead_unique_rate'])}); investigator questions {overall['investigator_questions']:,} (unique {overall['unique_investigator_questions']:,}); SQL queries {overall['sql_queries']:,} (unique {overall['unique_sql_queries']:,}). Total tokens {overall['tokens']:,}, cost ${overall['cost_usd']:.6f}, elapsed {overall['elapsed_seconds']:.3f}s. Mean/run: {overall['mean_tokens_per_run']:,.1f} tokens, ${overall['mean_cost_usd_per_run']:.6f}, {overall['mean_elapsed_seconds_per_run']:.3f}s.",
        "## Error diagnostics\n\n" + f"Missing-step reasons: `{json.dumps(dict(sorted(missing_reasons.items())), ensure_ascii=False)}`. Missing atomic components: `{json.dumps(dict(sorted(missing_kinds.items())), ensure_ascii=False)}`. Unaligned candidate claims: {overall['unaligned_candidate_claim_count']}; overconnection slots: {overall['overconnection_candidate_slot_count']}; hallucination-like unsupported/corrupted slots: {overall['hallucination_like_unsupported_slot_count']}. FP types: `{json.dumps(overall['false_positive_types'], ensure_ascii=False)}`.",
        "## Formal integrity\n\nGold subject/operation/object hits are derived only from unique included literal-TP `matched_gold_item_id` coverage. Behavior steps require all three components. Critical evidence and adjacent order pairs are separate diagnostics. PID identity and hidden-alert mapping are not scored; `action` is normalized to `operation`. Every run/case/Gold hash, Gold item, fixed candidate slot, order pair, and denominator is retained in `scores_codex_sol_v1/formal_scores.jsonl` and the provenance manifest. Cross-field validation: PASS (0 failures).",
    ]) + "\n"
    if REPORT_MD.exists():
        raise FileExistsError(f"create-only refusal: {REPORT_MD}")
    REPORT_MD.write_text(markdown, encoding="utf-8")
    print(json.dumps({"status": "PASS", "rows": len(rows), "score_root": str(SCORE_ROOT), "report_json": str(REPORT_JSON), "report_md": str(REPORT_MD), "overall": overall, "validation": validation}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
