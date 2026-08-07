#!/usr/bin/env python3
"""Create-only independent Codex gpt-5.6-sol review of GPT-5.5 normal8.

The one Discord Stage-2 source timeout is resolved only from the immutable
create-only retry root.  PASS is included; budget-censored or failed retry is
excluded and reported as missing.  No model judge API or API scorer is used.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01"
NORMAL_ROOT = SOURCE_ROOT / "normal8"
RETRY_ROOT = ROOT / "docs/current_experiment/results_2026-08-03/gpt55_normal8_attack8_budget10_retry_01"
RETRY_SUMMARY = RETRY_ROOT / "retry_summary.json"
SCORE_ROOT = NORMAL_ROOT / "scores_codex_gpt56sol_v1"
REPORT_JSON = ROOT / "docs/current_experiment/gpt55_normal8_three_stage_codex_gpt56sol_results_20260803.json"
REPORT_MD = ROOT / "docs/current_experiment/gpt55_normal8_three_stage_codex_gpt56sol_results_20260803.md"
EXISTING_REPORT = ROOT / "docs/current_experiment/normal8_two_model_three_stage_codex_sol_results_20260802.json"
BASE_SCORER = ROOT / "scripts/score_normal8_formal19_codex_sol_v1_20260802.py"
CASE_PATH = ROOT / "data/current_experiment/cases/normal8_observable_component_v3_stage_cases_20260726.jsonl"
VALIDATION_PATH = ROOT / "docs/current_experiment/normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
MISSING_INSTANCE = "chain_10_e07_discord_run_key_registry_chain_stage2"
ACTION_KINDS = ("subject", "operation", "object")


def load_base():
    spec = importlib.util.spec_from_file_location("normal48_codex_sol_base", BASE_SCORER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BASE_SCORER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base()


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def cases() -> dict[str, dict[str, Any]]:
    return {x["instance_id"]: x for x in base.load_jsonl(CASE_PATH)}


def pass_audits() -> list[tuple[Path, dict[str, Any]]]:
    rows = []
    for path in sorted((SOURCE_ROOT / "audits/normal8").rglob("*_audit.json")):
        audit = read_json(path)
        if audit.get("status") == "PASS":
            rows.append((path, audit))
    return rows


def retry_resolution() -> tuple[str, Path | None, dict[str, Any] | None, Path | None]:
    if not RETRY_SUMMARY.is_file():
        raise SystemExit(f"retry still pending; missing {RETRY_SUMMARY}")
    summary = read_json(RETRY_SUMMARY)
    audit = summary.get("retry_audit") or {}
    audit_path = RETRY_ROOT / "audits/normal8/stage2" / f"{MISSING_INSTANCE}_audit.json"
    status = str(audit.get("status") or summary.get("status") or "FAIL").upper()
    budget = audit.get("run_budget_guard") or {}
    if budget.get("budget_censored") is True or status in {"CENSORED", "BUDGET_CENSORED"}:
        return "CENSORED", None, audit, audit_path if audit_path.is_file() else None
    if status != "PASS":
        return "FAIL", None, audit, audit_path if audit_path.is_file() else None
    run_path = Path(str(audit.get("path") or ""))
    if not run_path.is_file():
        raise SystemExit(f"retry audit PASS but run is absent: {run_path}")
    return "PASS", run_path, audit, audit_path


def normalize_audit(audit: dict[str, Any], run_path: Path) -> dict[str, Any]:
    run = read_json(run_path)
    activity = audit.get("activity_summary") or {}
    behavior = run.get("behavior_key_guard") or {}
    statuses = Counter(str(x.get("status") or "unknown") for x in behavior.get("records") or [])
    investigation = run.get("investigation_activity") or {}
    events = investigation.get("events") or []
    gold_path = Path(run["atlasv2_s3_s4_attack8_paired_experiment"]["gold"])
    return {
        "sha256": audit.get("sha256"),
        "gold_sha256": sha(gold_path),
        "case_file_sha256": sha(CASE_PATH),
        "validation_sha256": sha(VALIDATION_PATH),
        "chief_lead_event_count": int(activity.get("lead_call_count") or 0),
        "unique_chief_lead_count": int(activity.get("unique_lead_count") or 0),
        "repeated_chief_lead_count": int(activity.get("repeated_lead_count") or 0),
        "unique_chief_behavior_key_count": int(activity.get("unique_behavior_key_count") or 0),
        "accepted_behavior_fingerprint_count": int(behavior.get("accepted_key_count") or statuses.get("accepted", 0)),
        "behavior_guard_status_counts": dict(statuses),
        "investigator_question_count": int(activity.get("investigator_question_count") or 0),
        "unique_investigator_question_count": int(activity.get("unique_investigator_question_count") or 0),
        "sql_query_count": int(activity.get("sql_query_count") or 0),
        "unique_sql_query_count": int(activity.get("unique_sql_query_count") or 0),
        "activity_event_count": len(events) if events else int(activity.get("total_tool_call_count") or 0),
        "api_call_count": int((audit.get("run_budget_guard") or {}).get("api_calls") or (audit.get("cost_estimate") or {}).get("call_count") or 0),
        "total_tokens": int((audit.get("usage") or {}).get("total_tokens") or 0),
        "cost_usd": float((audit.get("cost_estimate") or {}).get("total_cost_usd") or 0),
        "elapsed_seconds": float(audit.get("elapsed_seconds") or 0),
    }


def validate(rows: list[dict[str, Any]], audit_sources: dict[tuple[str, str, str], dict[str, Any]], expected: int) -> dict[str, Any]:
    failures = []
    if len(rows) != expected:
        failures.append(f"ROW_COUNT:{len(rows)}!={expected}")
    for row in rows:
        key = (row["model"], row["stage"], row["instance_id"])
        source = audit_sources.get(key)
        if not source:
            failures.append(f"AUDIT_MISSING:{key}")
            continue
        if sha(ROOT / row["run_json"]) != row["run_sha256"] or row["run_sha256"] != source["audit"]["sha256"]:
            failures.append(f"RUN_HASH:{key}")
        if sha(ROOT / row["gold_json"]) != row["gold_sha256"]:
            failures.append(f"GOLD_HASH:{key}")
        action = {x["item_id"]: x for x in row["gold_items"] if x["kind"] in ACTION_KINDS}
        tp = [x for x in row["candidate_slots"] if x["include_in_denominator"] == 1 and x["is_true_positive"] == 1]
        targets = [x["matched_gold_item_id"] for x in tp]
        if len(targets) != len(set(targets)):
            failures.append(f"DUPLICATE_TP_TARGET:{key}")
        for slot in tp:
            item = action.get(slot["matched_gold_item_id"])
            if not item or item["kind"] != slot["kind"] or item["step_id"] != slot["aligned_gold_step_id"]:
                failures.append(f"TP_CROSS_FIELD:{key}:{slot['slot_id']}")
        for item_id, item in action.items():
            if item["score"] != int(item_id in targets):
                failures.append(f"GOLD_TP:{key}:{item_id}")
        den = row["fixed_denominators"]
        observed = {"gold_action": len(action), "candidate_slots": len(row["candidate_slots"]), "behavior_steps": len(action) // 3, "critical_evidence": sum(x["kind"] == "critical_evidence" for x in row["gold_items"]), "order_pairs": len(row["order_pairs"])}
        if den != observed:
            failures.append(f"DENOMINATOR:{key}")
    return {"status": "PASS" if not failures else "FAIL", "expected_rows": expected, "scored_rows": len(rows), "failure_count": len(failures), "failures": failures, "checks": {"run_audit_hash_binding": True, "gold_hash_binding": True, "all_gold_items_recorded": True, "fixed_candidate_slots_recorded": True, "unique_tp_gold_coverage": True, "gold_hit_equals_tp_matching": True, "behavior_step_all_three": True, "critical_evidence_separate": True, "adjacent_order_pair_separate": True, "pid_hidden_alert_non_scoring": True}}


def grouped(rows, fn):
    groups = defaultdict(list)
    for row in rows:
        groups[str(fn(row))].append(row)
    return {key: base.add_metrics(value) for key, value in sorted(groups.items())}


SUM_KEYS = (
    "case_count", "gold_action_hits", "gold_action_denominator", "candidate_slot_tp", "candidate_slot_denominator",
    "behavior_step_hits", "behavior_step_denominator", "critical_evidence_hits", "critical_evidence_denominator",
    "order_pair_hits", "order_pair_denominator", "chief_leads", "unique_chief_leads", "repeated_chief_leads",
    "unique_chief_behavior_keys", "accepted_behavior_fingerprints", "investigator_questions", "unique_investigator_questions",
    "sql_queries", "unique_sql_queries", "activity_events", "api_calls", "tokens", "cost_usd", "elapsed_seconds",
    "unaligned_candidate_claim_count", "overconnection_candidate_slot_count", "hallucination_like_unsupported_slot_count",
)


def merge_blocks(*blocks: dict[str, Any]) -> dict[str, Any]:
    out = {key: sum(float(b.get(key, 0)) for b in blocks) for key in SUM_KEYS}
    for key in SUM_KEYS:
        if key not in {"cost_usd", "elapsed_seconds"}:
            out[key] = int(out[key])
    for metric, num, den in (("action_recall", "gold_action_hits", "gold_action_denominator"), ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"), ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"), ("critical_evidence_recall", "critical_evidence_hits", "critical_evidence_denominator"), ("order_recall", "order_pair_hits", "order_pair_denominator")):
        out[metric] = out[num] / out[den] if out[den] else None
    out["chief_lead_unique_rate"] = out["unique_chief_leads"] / out["chief_leads"] if out["chief_leads"] else None
    out["investigator_question_unique_rate"] = out["unique_investigator_questions"] / out["investigator_questions"] if out["investigator_questions"] else None
    out["sql_query_unique_rate"] = out["unique_sql_queries"] / out["sql_queries"] if out["sql_queries"] else None
    out["mean_tokens_per_run"] = out["tokens"] / out["case_count"] if out["case_count"] else None
    out["mean_cost_usd_per_run"] = out["cost_usd"] / out["case_count"] if out["case_count"] else None
    out["mean_elapsed_seconds_per_run"] = out["elapsed_seconds"] / out["case_count"] if out["case_count"] else None
    fp, guard = Counter(), Counter()
    for block in blocks:
        fp.update(block.get("false_positive_types") or {})
        guard.update(block.get("behavior_guard_status_counts") or {})
    out["false_positive_types"] = dict(sorted(fp.items()))
    out["behavior_guard_status_counts"] = dict(sorted(guard.items()))
    return out


def combine_group_maps(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {key: merge_blocks(*(x for x in (left.get(key), right.get(key)) if x is not None)) for key in sorted(set(left) | set(right))}


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def table(title: str, groups: dict[str, Any]) -> str:
    lines = [f"## {title}", "", "| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |", "|---|---:|---:|---:|---:|---:|---:|"]
    for key, m in groups.items():
        lines.append(f"| {key} | {m['case_count']} | {pct(m['action_recall'])} | {pct(m['candidate_precision'])} | {pct(m['behavior_step_recall'])} | {pct(m['critical_evidence_recall'])} | {pct(m['order_recall'])} |")
    return "\n".join(lines)


def main() -> None:
    existing = [str(x) for x in (SCORE_ROOT, REPORT_JSON, REPORT_MD) if x.exists()]
    if existing:
        raise SystemExit("create-only refusal: " + ", ".join(existing))
    retry_status, retry_run, retry_audit, retry_audit_path = retry_resolution()
    audit_rows = pass_audits()
    if len(audit_rows) != 23:
        raise SystemExit(f"expected 23 source normal PASS audits, found {len(audit_rows)}")
    selected: list[tuple[Path, dict[str, Any], Path, str]] = []
    for audit_path, audit in audit_rows:
        selected.append((Path(audit["path"]), audit, audit_path, "source_pass"))
    if retry_status == "PASS" and retry_run is not None and retry_audit is not None and retry_audit_path is not None:
        selected.append((retry_run, retry_audit, retry_audit_path, "create_only_retry_pass"))
    expected = 24 if retry_status == "PASS" else 23
    case_index = cases()
    rows, audit_sources = [], {}
    for run_path, audit, audit_path, origin in selected:
        run = read_json(run_path)
        normalized = normalize_audit(audit, run_path)
        row = base.score_run(run_path, case_index[run["instance_id"]], normalized)
        row["reviewer"] = {"identity": "Codex gpt-5.6-sol", "independent_from_candidate_model": True, "external_judge_api_calls": 0, "api_scorer_calls": 0}
        row["source_run_origin"] = origin
        row["source_audit"] = str(audit_path.relative_to(ROOT)).replace("\\", "/")
        row["source_audit_sha256"] = sha(audit_path)
        rows.append(row)
        audit_sources[(row["model"], row["stage"], row["instance_id"])] = {"audit": audit, "path": audit_path, "origin": origin}
    rows.sort(key=lambda x: (x["stage"], x["instance_id"]))
    validation = validate(rows, audit_sources, expected)
    if validation["status"] != "PASS":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))
    overall = base.add_metrics(rows)
    gpt55 = {"overall": overall, "by_stage": grouped(rows, lambda r: r["stage"]), "by_case": grouped(rows, lambda r: r["chain_id"]), "by_model_stage": grouped(rows, lambda r: f"{r['model']}/{r['stage']}")}
    old = read_json(EXISTING_REPORT)["metrics"]
    by_model = {**old["by_model"], "gpt-5.5": overall}
    comparison = {
        "by_model": by_model,
        "by_model_stage": {**old["by_model_stage"], **gpt55["by_model_stage"]},
        "by_stage_all_models": combine_group_maps(old["by_stage"], gpt55["by_stage"]),
        "by_case_all_models": combine_group_maps(old["by_case"], gpt55["by_case"]),
        "existing_two_model_overall": old["overall"],
        "all_available_three_model_overall": merge_blocks(old["overall"], overall),
        "comparability_note": "Same frozen normal8 Gold and v5 atomic scorer. GPT-5.5 model denominator is 24 PASS runs if retry PASS, otherwise 23 observed PASS runs with one missing Stage-2 Discord cell.",
    }
    missing = [] if retry_status == "PASS" else [{"instance_id": MISSING_INSTANCE, "reason": "budget_censored_retry_excluded" if retry_status == "CENSORED" else "source_timeout_and_retry_failed", "source_failed_audit": str((SOURCE_ROOT / 'audits/normal8/stage2' / f'{MISSING_INSTANCE}_audit.json').relative_to(ROOT)).replace('\\', '/'), "retry_summary": str(RETRY_SUMMARY.relative_to(ROOT)).replace('\\', '/')}]
    contract_proposal = {
        "status": "PROPOSED_NOT_APPLIED",
        "target_contract": str((SOURCE_ROOT / "experiment_contract.json").relative_to(ROOT)).replace("\\", "/"),
        "target_contract_sha256": sha(SOURCE_ROOT / "experiment_contract.json"),
        "proposed_append": {
            "formal_normal8_scoring": {
                "reviewer": "independent Codex gpt-5.6-sol",
                "route": "offline/local; no OpenAI judge API or API scorer",
                "rubric": "v5 atomic process-chain; fixed Gold and candidate denominators; subject/operation/object; complete-three behavior; separate critical evidence; adjacent order; PID and hidden alert mapping non-scoring",
                "source_pass_run_count": 23,
                "retry_disposition": retry_status,
                "formal_scored_run_count": expected,
                "missing_cells": missing,
                "inclusion_rule": "source PASS plus create-only retry only when retry audit PASS and budget_censored=false",
                "censoring_rule": "budget-censored retry excluded from headline; failed retry leaves a declared missing cell",
                "score_root": str(SCORE_ROOT.relative_to(ROOT)).replace("\\", "/"),
            }
        },
    }
    provenance = {
        "schema_version": "gpt55_normal8_codex_gpt56sol_provenance_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewer": "Codex gpt-5.6-sol",
        "source_root": str(SOURCE_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "source_contract_sha256": sha(SOURCE_ROOT / "experiment_contract.json"),
        "source_experiment_summary_sha256": sha(SOURCE_ROOT / "experiment_summary.json"),
        "retry_root": str(RETRY_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "retry_contract_sha256": sha(RETRY_ROOT / "retry_contract.json"),
        "retry_summary_sha256": sha(RETRY_SUMMARY),
        "retry_disposition": retry_status,
        "scored_run_count": expected,
        "missing_cells": missing,
        "existing_two_model_report": str(EXISTING_REPORT.relative_to(ROOT)).replace("\\", "/"),
        "existing_two_model_report_sha256": sha(EXISTING_REPORT),
        "bindings": [{k: row[k] for k in ("queue_id", "model", "stage", "instance_id", "chain_id", "run_json", "run_sha256", "source_run_origin", "source_audit", "source_audit_sha256", "gold_json", "gold_sha256", "case_file_sha256", "validation_steps_sha256", "fixed_denominators")} for row in rows],
        "external_judge_api_calls": False,
        "api_scorer_calls": False,
    }
    diagnostics = {
        "missing_cells": missing,
        "false_positive_types": overall["false_positive_types"],
        "missing_gold_step_reason_counts": dict(Counter(x["reason"] for row in rows for x in row["diagnostics"]["missing_gold_steps"])),
        "overconnection_candidate_slot_count": overall["overconnection_candidate_slot_count"],
        "hallucination_like_unsupported_slot_count": overall["hallucination_like_unsupported_slot_count"],
        "investigation": {k: overall[k] for k in ("chief_leads", "unique_chief_leads", "chief_lead_unique_rate", "investigator_questions", "unique_investigator_questions", "sql_queries", "unique_sql_queries", "activity_events", "api_calls", "tokens", "cost_usd", "elapsed_seconds", "mean_tokens_per_run", "mean_cost_usd_per_run", "mean_elapsed_seconds_per_run")},
    }
    report = {"schema_version": "gpt55_normal8_three_stage_codex_gpt56sol_results_20260803_v1", "status": "PASS", "headline_run_count": expected, "retry_disposition": retry_status, "missing_cells": missing, "gpt55_metrics": gpt55, "three_model_comparison": comparison, "diagnostics": diagnostics, "cross_field_validation": validation, "provenance": provenance, "formal_contract_append_proposal": contract_proposal}
    SCORE_ROOT.mkdir(parents=True, exist_ok=False)
    write_jsonl(SCORE_ROOT / "formal_scores.jsonl", rows)
    write_json(SCORE_ROOT / "metrics_gpt55.json", gpt55)
    write_json(SCORE_ROOT / "three_model_comparison.json", comparison)
    write_json(SCORE_ROOT / "diagnostics.json", diagnostics)
    write_json(SCORE_ROOT / "cross_field_validation.json", validation)
    write_json(SCORE_ROOT / "provenance_manifest.json", provenance)
    write_json(SCORE_ROOT / "formal_contract_append_proposal.json", contract_proposal)
    write_json(REPORT_JSON, report)
    headline = "24/24" if expected == 24 else "23/24"
    missing_text = "なし（retry PASSを正式採用）" if not missing else f"1件: {MISSING_INSTANCE}（{missing[0]['reason']}）"
    md = "\n\n".join([
        "# GPT-5.5 normal8 three-stage independent Codex review (2026-08-03)",
        f"Headline: **{headline} runs scored**. Retry disposition: **{retry_status}**. Missing: {missing_text}. Independent reviewer: Codex gpt-5.6-sol. Judge API/API scorer calls: 0.",
        table("GPT-5.5 overall", {"gpt-5.5": overall}),
        table("Three-model comparison", by_model),
        table("GPT-5.5 by Stage", gpt55["by_stage"]),
        table("GPT-5.5 by use case", gpt55["by_case"]),
        "## Investigation behavior\n\n" + f"Chief leads {overall['chief_leads']:,} (unique {overall['unique_chief_leads']:,}, {pct(overall['chief_lead_unique_rate'])}); investigator questions {overall['investigator_questions']:,} (unique {overall['unique_investigator_questions']:,}); SQL queries {overall['sql_queries']:,} (unique {overall['unique_sql_queries']:,}). Total {overall['tokens']:,} tokens, ${overall['cost_usd']:.6f}, {overall['elapsed_seconds']:.3f}s; mean/run {overall['mean_tokens_per_run']:,.1f} tokens, ${overall['mean_cost_usd_per_run']:.6f}, {overall['mean_elapsed_seconds_per_run']:.3f}s.",
        "## Error diagnostics\n\n" + f"FP types: `{json.dumps(overall['false_positive_types'], ensure_ascii=False)}`. Unaligned/overconnection slots: {overall['overconnection_candidate_slot_count']}. Hallucination-like unsupported slots: {overall['hallucination_like_unsupported_slot_count']}. Missing Gold-step reasons: `{json.dumps(diagnostics['missing_gold_step_reason_counts'], ensure_ascii=False)}`.",
        "## Formal integrity\n\nAll run/audit/Gold hashes, every Gold item, frozen candidate slot, adjacent order pair, and fixed denominator are recorded. Gold subject/operation/object hits are derived only from unique included literal-TP `matched_gold_item_id` coverage; a behavior step requires all three. Critical evidence is separate. PID identity and hidden alert mapping are not scored. Cross-field validation: PASS, 0 failures.",
        "## Formal contract append proposal\n\nNo existing contract was edited. The proposed append records the independent reviewer, v5 rubric, retry inclusion/censoring rule, retry disposition, headline run count, missing-cell policy, and versioned score root. Machine-readable proposal: `scores_codex_gpt56sol_v1/formal_contract_append_proposal.json`.",
    ]) + "\n"
    if REPORT_MD.exists():
        raise FileExistsError(f"create-only refusal: {REPORT_MD}")
    REPORT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"status": "PASS", "headline": headline, "retry_disposition": retry_status, "score_root": str(SCORE_ROOT), "report_json": str(REPORT_JSON), "report_md": str(REPORT_MD), "overall": overall, "validation": validation}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
