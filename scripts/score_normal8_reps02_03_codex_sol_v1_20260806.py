#!/usr/bin/env python3
"""Create-only Codex scoring for normal8 replicate_02 and replicate_03.

This is a local/offline experiment-nonparticipant review.  It deliberately
imports the frozen replicate_01 v5 atomic matcher so that subject, operation,
object, critical-evidence, and adjacent-order decisions use exactly the same
rules.  No OpenAI judge API or API scorer is called.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import score_normal8_formal19_codex_sol_v1_20260802 as base


ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-08-06/mini_reps_02_03_v5_failure_retry_01"
SCORE_ROOT = ROOT / "docs/current_experiment/results_2026-08-06/mini_reps_02_03_v5_scores_normal_codex_sol_v1"
REPORT_JSON = ROOT / "docs/current_experiment/normal8_mini_reps_02_03_codex_sol_results_20260806.json"
REPORT_MD = ROOT / "docs/current_experiment/normal8_mini_reps_02_03_codex_sol_results_20260806.md"
CASE_PATH = ROOT / "data/current_experiment/cases/normal8_observable_component_v3_stage_cases_20260726.jsonl"
VALIDATION_PATH = ROOT / "docs/current_experiment/normal8_observable_component_v3_stage3_validation_steps_20260726.csv"
REPLICATES = ("replicate_02", "replicate_03")
MODELS = ("gpt-4.1-mini", "gpt-5.4-mini")
STAGES = ("stage1", "stage2", "stage3")
ACTION_KINDS = ("subject", "operation", "object")

# The imported scorer writes these paths into each provenance-bound score row.
base.CASE_PATH = CASE_PATH
base.VALIDATION_PATH = VALIDATION_PATH


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_hash(value: Any) -> str:
    blob = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


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
    data = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    path.write_text(data, encoding="utf-8")


def audit_index() -> tuple[dict[tuple[str, str, str, str], dict[str, Any]], list[dict[str, Any]]]:
    index: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []
    for replicate in REPLICATES:
        path = RUN_ROOT / replicate / "replicate_summary.json"
        summary = load_json(path)
        if summary.get("status") != "PASS" or summary.get("audited_runs") != 96:
            raise SystemExit(f"replicate summary is not 96-run PASS: {path}")
        normal = [row for row in summary["audits"] if row.get("phase") == "normal8"]
        if len(normal) != 48 or any(row.get("status") != "PASS" for row in normal):
            raise SystemExit(f"normal8 source audit is not 48/48 PASS: {path}")
        sources.append({
            "replicate": replicate,
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": sha256_file(path),
            "status": summary["status"],
            "audited_runs": summary["audited_runs"],
            "normal8_pass_count": len(normal),
        })
        for row in normal:
            key = (replicate, row["model"], row["stage"], row["instance_id"])
            if key in index:
                raise SystemExit(f"duplicate source audit binding: {key}")
            index[key] = row
    return index, sources


def normalized_audit(run: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    summary = run["investigation_activity"]["summary"]
    behavior = run["behavior_key_guard"]
    statuses = Counter(str(row.get("status") or "missing") for row in behavior.get("records") or [])
    return {
        **audit,
        "chief_lead_event_count": summary["lead_call_count"],
        "unique_chief_lead_count": summary["unique_lead_count"],
        "repeated_chief_lead_count": summary["repeated_lead_count"],
        "unique_chief_behavior_key_count": summary["unique_behavior_key_count"],
        "accepted_behavior_fingerprint_count": behavior["accepted_key_count"],
        "behavior_guard_status_counts": dict(sorted(statuses.items())),
        "investigator_question_count": summary["investigator_question_count"],
        "unique_investigator_question_count": summary["unique_investigator_question_count"],
        "sql_query_count": summary["sql_query_count"],
        "unique_sql_query_count": summary["unique_sql_query_count"],
        "activity_event_count": len(run["investigation_activity"]["events"]),
        "api_call_count": audit["api_call_count"],
        "total_tokens": audit["usage"]["total_tokens"],
        "cost_usd": audit["cost_usd"],
        "elapsed_seconds": audit["elapsed_seconds"],
    }


def source_checks(
    replicate: str,
    run_path: Path,
    run: dict[str, Any],
    audit: dict[str, Any],
) -> list[str]:
    key = f"{replicate}/{run.get('model')}/{run.get('experiment_stage')}/{run.get('instance_id')}"
    failures: list[str] = []
    if audit.get("status") != "PASS":
        failures.append(f"SOURCE_AUDIT_NOT_PASS:{key}")
    if run.get("error") not in (None, ""):
        failures.append(f"RUN_ERROR:{key}:{run.get('error')}")
    try:
        output = json.loads(run.get("output_text") or "")
        if not isinstance(output, dict) or not isinstance(output.get("code_steps"), list):
            failures.append(f"OUTPUT_SCHEMA:{key}")
    except Exception as exc:  # pragma: no cover - retained in formal ledger
        failures.append(f"OUTPUT_JSON:{key}:{type(exc).__name__}")
    if sha256_file(run_path) != audit.get("sha256"):
        failures.append(f"RUN_HASH:{key}")
    if sha256_file(CASE_PATH) != audit.get("case_file_sha256"):
        failures.append(f"CASE_HASH:{key}")
    if sha256_file(VALIDATION_PATH) != audit.get("validation_sha256"):
        failures.append(f"VALIDATION_HASH:{key}")
    gold_path = Path(run["atlasv2_s3_s4_attack8_paired_experiment"]["gold"])
    if not gold_path.is_file() or sha256_file(gold_path) != audit.get("gold_sha256"):
        failures.append(f"GOLD_HASH:{key}")
    if run.get("model") != audit.get("model") or run.get("experiment_stage") != audit.get("stage"):
        failures.append(f"MODEL_STAGE_BINDING:{key}")
    if run.get("instance_id") != audit.get("instance_id"):
        failures.append(f"INSTANCE_BINDING:{key}")
    if run.get("usage") != audit.get("usage"):
        failures.append(f"USAGE_BINDING:{key}")
    if abs(float(run.get("elapsed_seconds") or 0) - float(audit.get("elapsed_seconds") or 0)) > 1e-9:
        failures.append(f"ELAPSED_BINDING:{key}")
    if abs(float(run.get("cost_estimate", {}).get("total_cost_usd") or 0) - float(audit.get("cost_usd") or 0)) > 1e-9:
        failures.append(f"COST_BINDING:{key}")
    usage_audit = run.get("usage_audit") or {}
    for field in (
        "callback_aggregate_equals_call_ledger",
        "full_pipeline_equals_call_ledger",
        "full_pipeline_equals_role_total",
    ):
        if usage_audit.get(field) is not True:
            failures.append(f"USAGE_AUDIT:{key}:{field}")
    if usage_audit.get("full_pipeline_call_count") != usage_audit.get("role_call_count"):
        failures.append(f"USAGE_CALL_COUNT:{key}")
    if usage_audit.get("full_pipeline_call_count") != audit.get("api_call_count"):
        failures.append(f"AUDIT_CALL_COUNT:{key}")
    return failures


def score_consistency(rows: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    if len(rows) != 96:
        failures.append(f"ROW_COUNT:{len(rows)}")
    queue_ids = [row["queue_id"] for row in rows]
    if len(queue_ids) != len(set(queue_ids)):
        failures.append("DUPLICATE_QUEUE_ID")
    for row in rows:
        key = row["queue_id"]
        action = {item["item_id"]: item for item in row["gold_items"] if item["kind"] in ACTION_KINDS}
        critical = [item for item in row["gold_items"] if item["kind"] == "critical_evidence"]
        included = [slot for slot in row["candidate_slots"] if slot["include_in_denominator"] == 1]
        tp = [slot for slot in included if slot["is_true_positive"] == 1]
        targets = [slot["matched_gold_item_id"] for slot in tp]
        if len(targets) != len(set(targets)):
            failures.append(f"DUPLICATE_TP_TARGET:{key}")
        for slot in tp:
            item = action.get(slot["matched_gold_item_id"])
            if not item or item["kind"] != slot["kind"] or item["step_id"] != slot["aligned_gold_step_id"]:
                failures.append(f"TP_TARGET:{key}:{slot['slot_id']}")
        for item_id, item in action.items():
            if item["score"] != int(item_id in targets):
                failures.append(f"GOLD_TP:{key}:{item_id}")
        den = row["fixed_denominators"]
        expected = {
            "gold_action": len(action),
            "candidate_slots": len(included),
            "behavior_steps": len(action) // 3,
            "critical_evidence": len(critical),
            "order_pairs": len(row["order_pairs"]),
        }
        if den != expected:
            failures.append(f"DENOMINATOR:{key}:{den}!={expected}")
        step_scores: dict[str, dict[str, int]] = defaultdict(dict)
        for item in action.values():
            step_scores[item["step_id"]][item["kind"]] = item["score"]
        behavior = sum(all(parts.get(kind) == 1 for kind in ACTION_KINDS) for parts in step_scores.values())
        metrics = row["metrics"]
        derived = {
            "gold_action_hits": sum(item["score"] for item in action.values()),
            "gold_action_denominator": len(action),
            "candidate_slot_tp": len(tp),
            "candidate_slot_denominator": len(included),
            "behavior_step_hits": behavior,
            "behavior_step_denominator": len(action) // 3,
            "critical_evidence_hits": sum(item["score"] for item in critical),
            "critical_evidence_denominator": len(critical),
            "order_pair_hits": sum(pair["score"] for pair in row["order_pairs"]),
            "order_pair_denominator": len(row["order_pairs"]),
        }
        for field, value in derived.items():
            if metrics[field] != value:
                failures.append(f"METRIC_DERIVATION:{key}:{field}")
    return failures


def add_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out = base.add_metrics(rows)
    out["input_tokens"] = sum(int(row["investigation"]["input_tokens"]) for row in rows)
    out["output_tokens"] = sum(int(row["investigation"]["output_tokens"]) for row in rows)
    out["cached_input_tokens"] = sum(int(row["investigation"]["cached_input_tokens"]) for row in rows)
    out["max_llm_call_duration_seconds"] = max(float(row["investigation"]["max_llm_call_duration_seconds"]) for row in rows)
    out["mean_api_calls_per_run"] = out["api_calls"] / out["case_count"]
    return out


def grouped(rows: list[dict[str, Any]], key: Callable[[dict[str, Any]], str]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(key(row))].append(row)
    return {name: add_metrics(group) for name, group in sorted(groups.items())}


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def metric_table(title: str, groups: dict[str, Any]) -> str:
    lines = [
        f"## {title}",
        "",
        "| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, metrics in groups.items():
        lines.append(
            f"| {name} | {metrics['case_count']} | {pct(metrics['action_recall'])} | "
            f"{pct(metrics['candidate_precision'])} | {pct(metrics['behavior_step_recall'])} | "
            f"{pct(metrics['critical_evidence_recall'])} | {pct(metrics['order_recall'])} | "
            f"${metrics['cost_usd']:.6f} | {metrics['elapsed_seconds'] / 60:.2f} min |"
        )
    return "\n".join(lines)


def main() -> None:
    targets = (SCORE_ROOT, REPORT_JSON, REPORT_MD)
    existing = [str(path) for path in targets if path.exists()]
    if existing:
        raise SystemExit("create-only refusal: " + ", ".join(existing))

    audits, audit_sources = audit_index()
    cases = {str(row["instance_id"]): row for row in load_jsonl(CASE_PATH)}
    rows: list[dict[str, Any]] = []
    source_failures: list[str] = []
    source_bindings: list[dict[str, Any]] = []
    for replicate in REPLICATES:
        run_paths = sorted((RUN_ROOT / replicate / "normal8/runs").glob("*/*/*_run.json"))
        if len(run_paths) != 48:
            source_failures.append(f"SOURCE_RUN_COUNT:{replicate}:{len(run_paths)}")
        for run_path in run_paths:
            run = load_json(run_path)
            key = (replicate, run["model"], run["experiment_stage"], run["instance_id"])
            audit = audits.get(key)
            if audit is None:
                source_failures.append(f"AUDIT_MISSING:{key}")
                continue
            if run["instance_id"] not in cases:
                source_failures.append(f"CASE_MISSING:{key}")
                continue
            source_failures.extend(source_checks(replicate, run_path, run, audit))
            row = base.score_run(run_path, cases[run["instance_id"]], normalized_audit(run, audit))
            old_queue_id = row["queue_id"]
            row["schema_version"] = "normal8_reps02_03_codex_sol_v1_atomic_process_chain"
            row["replicate"] = replicate
            row["queue_id"] = f"{replicate}/{old_queue_id}"
            row["source_audit_entry_sha256"] = canonical_hash(audit)
            row["investigation"].update({
                "input_tokens": audit["usage"]["input_tokens"],
                "output_tokens": audit["usage"]["output_tokens"],
                "cached_input_tokens": audit["usage"]["cached_input_tokens"],
                "max_llm_call_duration_seconds": audit["max_llm_call_duration_seconds"],
            })
            rows.append(row)
            source_bindings.append({
                "queue_id": row["queue_id"],
                "replicate": replicate,
                "model": row["model"],
                "stage": row["stage"],
                "instance_id": row["instance_id"],
                "chain_id": row["chain_id"],
                "run_json": row["run_json"],
                "run_sha256": row["run_sha256"],
                "gold_json": row["gold_json"],
                "gold_sha256": row["gold_sha256"],
                "case_jsonl": row["case_jsonl"],
                "case_file_sha256": row["case_file_sha256"],
                "validation_steps_sha256": row["validation_steps_sha256"],
                "source_audit_entry_sha256": row["source_audit_entry_sha256"],
                "fixed_denominators": row["fixed_denominators"],
            })

    score_failures = score_consistency(rows)
    failures = source_failures + score_failures
    validation = {
        "status": "PASS" if not failures else "FAIL",
        "row_count": len(rows),
        "expected_row_count": 96,
        "source_normal8_audit_pass_count": len(audits),
        "checks": {
            "source_replicate_summaries_pass": not source_failures,
            "source_run_error_free_and_output_json_valid": not any(x.startswith(("RUN_ERROR", "OUTPUT_")) for x in source_failures),
            "run_case_gold_validation_hash_binding": not any("HASH" in x for x in source_failures),
            "full_pipeline_usage_ledger_consistent": not any("USAGE" in x or "CALL_COUNT" in x for x in source_failures),
            "unique_tp_gold_coverage": not any(x.startswith("DUPLICATE_TP") for x in score_failures),
            "gold_hit_equals_tp_matching": not any(x.startswith(("TP_TARGET", "GOLD_TP")) for x in score_failures),
            "candidate_fixed_denominator": not any(x.startswith("DENOMINATOR") for x in score_failures),
            "behavior_step_requires_all_three": not any(x.startswith("METRIC_DERIVATION") for x in score_failures),
            "critical_evidence_separate": True,
            "adjacent_order_pairs_separate": True,
            "pid_and_hidden_alert_non_scoring": True,
        },
        "failure_count": len(failures),
        "failures": failures,
    }
    if validation["status"] != "PASS":
        raise SystemExit(json.dumps(validation, ensure_ascii=False, indent=2))

    overall = add_metrics(rows)
    metrics = {
        "overall": overall,
        "by_replicate": grouped(rows, lambda row: row["replicate"]),
        "by_model": grouped(rows, lambda row: row["model"]),
        "by_stage": grouped(rows, lambda row: row["stage"]),
        "by_case": grouped(rows, lambda row: row["chain_id"]),
        "by_model_stage": grouped(rows, lambda row: f"{row['model']}/{row['stage']}"),
        "by_model_case": grouped(rows, lambda row: f"{row['model']}/{row['chain_id']}"),
        "by_replicate_model": grouped(rows, lambda row: f"{row['replicate']}/{row['model']}"),
        "by_replicate_stage": grouped(rows, lambda row: f"{row['replicate']}/{row['stage']}"),
        "by_replicate_case": grouped(rows, lambda row: f"{row['replicate']}/{row['chain_id']}"),
        "by_replicate_model_stage": grouped(rows, lambda row: f"{row['replicate']}/{row['model']}/{row['stage']}"),
        "by_replicate_model_case": grouped(rows, lambda row: f"{row['replicate']}/{row['model']}/{row['chain_id']}"),
    }
    missing_reasons = Counter(item["reason"] for row in rows for item in row["diagnostics"]["missing_gold_steps"])
    missing_kinds = Counter(kind for row in rows for item in row["diagnostics"]["missing_gold_steps"] for kind in item["missing_kinds"])
    analysis = {
        "missing_reconstruction": {
            "reason_counts": dict(sorted(missing_reasons.items())),
            "missing_component_counts": dict(sorted(missing_kinds.items())),
            "run_level_details": [
                {"queue_id": row["queue_id"], **row["diagnostics"]}
                for row in rows if row["diagnostics"]["missing_gold_steps"]
            ],
        },
        "overconnection": {
            "definition": "fixed candidate slots belonging to a candidate claim with no Gold-step atomic alignment",
            "candidate_slot_count": overall["overconnection_candidate_slot_count"],
            "unaligned_candidate_claim_count": overall["unaligned_candidate_claim_count"],
        },
        "hallucination": {
            "definition": "literal slot contains an unsupported/corrupted placeholder-like value; an observed nearby wrong component is overconnection, not hallucination",
            "hallucination_like_unsupported_slot_count": overall["hallucination_like_unsupported_slot_count"],
        },
        "false_positive_types": overall["false_positive_types"],
        "investigation_behavior": {
            "overall": {key: overall[key] for key in (
                "chief_leads", "unique_chief_leads", "chief_lead_unique_rate",
                "investigator_questions", "unique_investigator_questions",
                "sql_queries", "unique_sql_queries", "activity_events", "api_calls",
                "input_tokens", "output_tokens", "cached_input_tokens", "tokens",
                "cost_usd", "elapsed_seconds", "mean_tokens_per_run",
                "mean_cost_usd_per_run", "mean_elapsed_seconds_per_run",
                "mean_api_calls_per_run", "max_llm_call_duration_seconds",
            )},
            "behavior_guard_status_counts": overall["behavior_guard_status_counts"],
            "by_replicate": metrics["by_replicate"],
            "by_model": metrics["by_model"],
            "by_stage": metrics["by_stage"],
        },
    }

    provenance = {
        "schema_version": "normal8_reps02_03_codex_sol_v1_provenance",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewer": "independent experiment-nonparticipant Codex gpt-5.6-sol",
        "route": "Codex local/offline formal scoring; no OpenAI judge API and no API scorer",
        "frozen_replicate01_scorer": "scripts/score_normal8_formal19_codex_sol_v1_20260802.py",
        "frozen_replicate01_scorer_sha256": sha256_file(ROOT / "scripts/score_normal8_formal19_codex_sol_v1_20260802.py"),
        "scorer": str(Path(__file__).resolve().relative_to(ROOT)).replace("\\", "/"),
        "scorer_sha256": sha256_file(Path(__file__).resolve()),
        "run_root": str(RUN_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "score_root": str(SCORE_ROOT.relative_to(ROOT)).replace("\\", "/"),
        "source_replicate_summaries": audit_sources,
        "case_file": str(CASE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "case_file_sha256": sha256_file(CASE_PATH),
        "validation_file": str(VALIDATION_PATH.relative_to(ROOT)).replace("\\", "/"),
        "validation_file_sha256": sha256_file(VALIDATION_PATH),
        "run_count": len(rows),
        "replicates": list(REPLICATES),
        "models": list(MODELS),
        "stages": list(STAGES),
        "run_case_gold_bindings": source_bindings,
        "rubric": rows[0]["review_policy"],
        "external_judge_api_calls": False,
        "api_scorer_calls": False,
    }

    gold_ledger = [
        {"queue_id": row["queue_id"], "replicate": row["replicate"], "model": row["model"], "stage": row["stage"], "chain_id": row["chain_id"], **item}
        for row in rows for item in row["gold_items"]
    ]
    candidate_ledger = [
        {"queue_id": row["queue_id"], "replicate": row["replicate"], "model": row["model"], "stage": row["stage"], "chain_id": row["chain_id"], **slot}
        for row in rows for slot in row["candidate_slots"]
    ]
    order_ledger = [
        {"queue_id": row["queue_id"], "replicate": row["replicate"], "model": row["model"], "stage": row["stage"], "chain_id": row["chain_id"], **pair}
        for row in rows for pair in row["order_pairs"]
    ]
    report = {
        "schema_version": "normal8_mini_reps02_03_codex_sol_results_20260806_v1",
        "status": "PASS",
        "scope": "normal8 replicate_02 and replicate_03: 8 use cases x 3 stages x 2 models x 2 replicates = 96 completed runs",
        "provenance": provenance,
        "metrics": metrics,
        "analysis": analysis,
        "cross_field_validation": validation,
        "ledger_counts": {
            "runs": len(rows),
            "gold_items": len(gold_ledger),
            "candidate_slots": len(candidate_ledger),
            "order_pairs": len(order_ledger),
        },
        "score_artifacts": [
            "formal_scores.jsonl", "gold_items.jsonl", "candidate_slots.jsonl",
            "order_pairs.jsonl", "metrics.json", "analysis.json",
            "provenance_manifest.json", "cross_field_validation.json",
        ],
    }

    SCORE_ROOT.mkdir(parents=True, exist_ok=False)
    write_jsonl_new(SCORE_ROOT / "formal_scores.jsonl", rows)
    write_jsonl_new(SCORE_ROOT / "gold_items.jsonl", gold_ledger)
    write_jsonl_new(SCORE_ROOT / "candidate_slots.jsonl", candidate_ledger)
    write_jsonl_new(SCORE_ROOT / "order_pairs.jsonl", order_ledger)
    write_json_new(SCORE_ROOT / "metrics.json", metrics)
    write_json_new(SCORE_ROOT / "analysis.json", analysis)
    write_json_new(SCORE_ROOT / "provenance_manifest.json", provenance)
    write_json_new(SCORE_ROOT / "cross_field_validation.json", validation)
    write_json_new(REPORT_JSON, report)

    markdown = "\n\n".join([
        "# Normal8 mini-model replicate 02/03 Codex formal score (2026-08-06)",
        "96/96 normal runs were source-audit PASS and scored locally under the same v5 atomic process-chain rubric as replicate 01. OpenAI judge API/API scorer calls: 0. Cross-field deterministic audit: PASS.",
        metric_table("Overall", {"all 96 runs": overall}),
        metric_table("By replicate", metrics["by_replicate"]),
        metric_table("By model", metrics["by_model"]),
        metric_table("By stage", metrics["by_stage"]),
        metric_table("By model and stage", metrics["by_model_stage"]),
        metric_table("By use case", metrics["by_case"]),
        metric_table("By model and use case", metrics["by_model_case"]),
        "## Investigation behavior\n\n"
        f"Chief leads {overall['chief_leads']:,} (unique {overall['unique_chief_leads']:,}, {pct(overall['chief_lead_unique_rate'])}); "
        f"Investigator questions {overall['investigator_questions']:,} (unique {overall['unique_investigator_questions']:,}); "
        f"SQL queries {overall['sql_queries']:,} (unique {overall['unique_sql_queries']:,}). "
        f"API calls {overall['api_calls']:,}; input/output/cached/total tokens "
        f"{overall['input_tokens']:,}/{overall['output_tokens']:,}/{overall['cached_input_tokens']:,}/{overall['tokens']:,}; "
        f"cost ${overall['cost_usd']:.6f}; aggregate wall time {overall['elapsed_seconds'] / 60:.2f} min. "
        f"Mean/run: {overall['mean_api_calls_per_run']:.2f} calls, {overall['mean_tokens_per_run']:,.1f} tokens, "
        f"${overall['mean_cost_usd_per_run']:.6f}, {overall['mean_elapsed_seconds_per_run'] / 60:.2f} min.",
        "## Error diagnostics\n\n"
        f"Missing-step reasons: `{json.dumps(dict(sorted(missing_reasons.items())), ensure_ascii=False)}`. "
        f"Missing atomic components: `{json.dumps(dict(sorted(missing_kinds.items())), ensure_ascii=False)}`. "
        f"Unaligned candidate claims: {overall['unaligned_candidate_claim_count']}; "
        f"overconnection slots: {overall['overconnection_candidate_slot_count']}; "
        f"hallucination-like unsupported/corrupted slots: {overall['hallucination_like_unsupported_slot_count']}. "
        f"FP types: `{json.dumps(overall['false_positive_types'], ensure_ascii=False)}`.",
        "## Formal integrity\n\n"
        "Gold subject/operation/object hits are derived only from unique included literal-TP `matched_gold_item_id` coverage. "
        "Behavior steps require all three components. Critical evidence and adjacent Gold order pairs are separate diagnostics. "
        "PID identity and hidden-alert mapping are not scored; `action` is normalized to `operation`. Every run/Gold hash, "
        "Gold item, fixed candidate slot, adjacent order pair, denominator, and per-run total is retained in the score root. "
        f"Ledger counts: {len(rows)} runs, {len(gold_ledger)} Gold items, {len(candidate_ledger)} candidate slots, "
        f"{len(order_ledger)} order pairs. Cross-field validation: PASS (0 failures).",
    ]) + "\n"
    if REPORT_MD.exists():
        raise FileExistsError(f"create-only refusal: {REPORT_MD}")
    REPORT_MD.write_text(markdown, encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "rows": len(rows),
        "ledger_counts": report["ledger_counts"],
        "score_root": str(SCORE_ROOT),
        "report_json": str(REPORT_JSON),
        "report_md": str(REPORT_MD),
        "overall": overall,
        "validation": validation,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
