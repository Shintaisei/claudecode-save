from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612"
AUDIT_ROOT = SCORE_ROOT / "strict_reaudit_20260613"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"
CASES = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
GOLD = ROOT / "data/current_experiment/gold/cbc_non_alert_behavior_chain_gold_2026-06-11/all_chain_steps.jsonl"
RUN_ROOT = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_2rep_20260612"

MODELS = ["gpt-4.1-mini", "gpt-5.4-mini"]
REPLICATES = ["replicate_01", "replicate_02"]
KEY_FIELDS = ["replicate", "model", "stage", "instance_id"]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in KEY_FIELDS)  # type: ignore[return-value]


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def trunc(value: Any, limit: int = 300) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse_candidate_steps(run_path: Path) -> tuple[list[dict[str, Any]], str | None]:
    if not run_path.exists():
        return [], "missing_run_json"
    try:
        run = json.loads(run_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [], f"run_json_parse_error:{exc}"
    output_text = run.get("output_text")
    if not isinstance(output_text, str):
        return [], "missing_output_text"
    try:
        parsed = json.loads(output_text)
    except Exception as exc:  # noqa: BLE001
        return [], f"output_text_json_parse_error:{exc}"
    steps = parsed.get("code_steps")
    if not isinstance(steps, list):
        return [], "code_steps_not_list"
    return [step for step in steps if isinstance(step, dict)], None


def summarize_evidence(step: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = step.get("evidence")
    if not isinstance(evidence, list):
        return []
    out: list[dict[str, Any]] = []
    for item in evidence[:4]:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "source_stream": item.get("source_stream"),
                "timestamp": item.get("timestamp") or item.get("timestamp_utc"),
                "alert_id": item.get("alert_id"),
                "event_record_id": item.get("event_record_id"),
                "field": item.get("field"),
                "value": trunc(item.get("value"), 160),
                "pid": item.get("pid"),
                "ppid": item.get("ppid"),
            }
        )
    return out


def summarize_candidate(step: dict[str, Any]) -> dict[str, Any]:
    subject = step.get("subject_process") if isinstance(step.get("subject_process"), dict) else {}
    obj = step.get("object") if isinstance(step.get("object"), dict) else {}
    context = step.get("execution_context") if isinstance(step.get("execution_context"), dict) else {}
    return {
        "step_id": step.get("step_id"),
        "order": step.get("order"),
        "time": step.get("time"),
        "operation": step.get("operation") or step.get("action"),
        "subject": {
            "name": subject.get("name"),
            "pid": subject.get("pid"),
            "path": subject.get("path"),
        },
        "object": {
            "type": obj.get("type"),
            "name": obj.get("name"),
            "path": obj.get("path"),
            "value": trunc(obj.get("value"), 160),
            "data": trunc(obj.get("data"), 160),
        },
        "command_line": trunc(step.get("command_line"), 220),
        "execution_context": {
            "parent_process": context.get("parent_process"),
            "parent_pid": context.get("parent_pid"),
            "parent_command_line": trunc(context.get("parent_command_line"), 220),
            "child_process": context.get("child_process"),
            "child_pid": context.get("child_pid"),
        },
        "evidence": summarize_evidence(step),
        "confidence": step.get("confidence"),
        "limitations": step.get("limitations") if isinstance(step.get("limitations"), list) else None,
    }


def summarize_gold(step: dict[str, Any]) -> dict[str, Any]:
    supporting = step.get("supporting_evidence") if isinstance(step.get("supporting_evidence"), dict) else {}
    samples = supporting.get("sample_logs") if isinstance(supporting.get("sample_logs"), list) else []
    return {
        "step_id": step.get("step_id"),
        "order": step.get("order"),
        "subject": step.get("subject"),
        "action": trunc(step.get("action"), 180),
        "object": trunc(step.get("object"), 220),
        "source_types": step.get("source_types"),
        "evidence_basis": trunc(step.get("evidence_basis"), 450),
        "sample_logs": [trunc(sample, 450) for sample in samples[:2]],
    }


def main() -> None:
    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    cases = read_jsonl(CASES)
    ledger = read_jsonl(LEDGER)
    gold_rows = read_jsonl(GOLD)

    gold_by_chain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in gold_rows:
        gold_by_chain[str(row.get("chain_id"))].append(row)
    for rows in gold_by_chain.values():
        rows.sort(key=lambda r: int(r.get("order") or 0))

    case_by_instance = {str(case.get("instance_id")): case for case in cases}
    expected_keys = {
        (replicate, model, str(case["stage"]), str(case["instance_id"]))
        for replicate in REPLICATES
        for model in MODELS
        for case in cases
    }
    ledger_keys = [key(row) for row in ledger]
    ledger_key_counts = Counter(ledger_keys)

    issues: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []

    for row in ledger:
        row_key = key(row)
        replicate, model, stage, instance_id = row_key
        chain_id = str(row.get("chain_id") or "")
        run_json_raw = row.get("run_json")
        run_path = ROOT / str(run_json_raw) if run_json_raw else RUN_ROOT / replicate / "runs" / model / stage / f"{instance_id}_run.json"
        candidate_steps, parse_issue = parse_candidate_steps(run_path)
        gold_steps = gold_by_chain.get(chain_id, [])

        row_issues: list[str] = []
        if row_key not in expected_keys:
            row_issues.append("unexpected_ledger_key")
        if ledger_key_counts[row_key] > 1:
            row_issues.append("duplicate_ledger_key")
        if instance_id not in case_by_instance:
            row_issues.append("instance_not_in_cases")
        if not run_path.exists():
            row_issues.append("missing_run_json")
        if parse_issue:
            row_issues.append(parse_issue)
        if row.get("gold_step_count") != len(gold_steps):
            row_issues.append("gold_step_count_mismatch")
        if row.get("recall_total") != row.get("gold_step_count"):
            row_issues.append("recall_total_not_gold_count")
        if row.get("behavior_sequence_order_total") != row.get("gold_step_count"):
            row_issues.append("order_total_not_gold_count")
        if row.get("candidate_step_count") != len(candidate_steps):
            row_issues.append("candidate_step_count_mismatch")
        if row.get("precision_total") != row.get("candidate_step_count"):
            row_issues.append("precision_total_not_candidate_count")

        recall_hits = int(row.get("recall_hits") or 0)
        precision_hits = int(row.get("precision_hits") or 0)
        order_hits = int(row.get("behavior_sequence_order_hits") or 0)
        recall_total = int(row.get("recall_total") or 0)
        precision_total = int(row.get("precision_total") or 0)
        order_total = int(row.get("behavior_sequence_order_total") or 0)
        if recall_hits > recall_total:
            row_issues.append("recall_hits_exceed_total")
        if precision_hits > precision_total:
            row_issues.append("precision_hits_exceed_total")
        if order_hits > order_total:
            row_issues.append("order_hits_exceed_total")
        if order_hits > recall_hits:
            row_issues.append("order_hits_exceed_recall_hits")
        if recall_hits != precision_hits:
            row_issues.append("recall_precision_hits_differ_under_one_to_one")
        if precision_total == 0 and precision_hits != 0:
            row_issues.append("precision_hits_nonzero_with_zero_candidates")
        if recall_total == 0 or order_total == 0:
            row_issues.append("zero_gold_denominator")

        candidate_source_streams = sorted(
            {
                str(ev.get("source_stream"))
                for step in candidate_steps
                for ev in (step.get("evidence") if isinstance(step.get("evidence"), list) else [])
                if isinstance(ev, dict) and ev.get("source_stream") is not None
            }
        )
        all_sources_alert_like = bool(candidate_source_streams) and all("alert" in src.lower() for src in candidate_source_streams)
        if precision_hits > 0 and all_sources_alert_like:
            row_issues.append("positive_hit_with_only_alert_like_candidate_sources")

        if row_issues:
            issues.append(
                {
                    "key": {
                        "replicate": replicate,
                        "model": model,
                        "stage": stage,
                        "instance_id": instance_id,
                    },
                    "chain_id": chain_id,
                    "issues": row_issues,
                    "score": {
                        "gold_step_count": row.get("gold_step_count"),
                        "candidate_step_count": row.get("candidate_step_count"),
                        "recall_hits": row.get("recall_hits"),
                        "precision_hits": row.get("precision_hits"),
                        "behavior_sequence_order_hits": row.get("behavior_sequence_order_hits"),
                    },
                    "derived": {
                        "parsed_candidate_step_count": len(candidate_steps),
                        "gold_row_count": len(gold_steps),
                        "candidate_source_streams": candidate_source_streams,
                    },
                    "run_json": rel(run_path),
                }
            )

        manifest.append(
            {
                "key": {
                    "replicate": replicate,
                    "model": model,
                    "stage": stage,
                    "instance_id": instance_id,
                },
                "chain_id": chain_id,
                "run_json": rel(run_path),
                "score": {
                    "gold_step_count": row.get("gold_step_count"),
                    "candidate_step_count": row.get("candidate_step_count"),
                    "recall_hits": row.get("recall_hits"),
                    "recall_total": row.get("recall_total"),
                    "precision_hits": row.get("precision_hits"),
                    "precision_total": row.get("precision_total"),
                    "behavior_sequence_order_hits": row.get("behavior_sequence_order_hits"),
                    "behavior_sequence_order_total": row.get("behavior_sequence_order_total"),
                },
                "review_summary": row.get("review_summary"),
                "mechanical_issues": row_issues,
                "gold_steps": [summarize_gold(step) for step in gold_steps],
                "candidate_steps": [summarize_candidate(step) for step in candidate_steps],
            }
        )

    missing = sorted(expected_keys - set(ledger_keys))
    unexpected = sorted(set(ledger_keys) - expected_keys)

    manifest.sort(key=lambda r: (r["key"]["replicate"], r["key"]["model"], r["key"]["stage"], r["key"]["instance_id"]))
    half = (len(manifest) + 1) // 2
    write_jsonl(AUDIT_ROOT / "strict_reaudit_manifest.jsonl", manifest)
    write_jsonl(AUDIT_ROOT / "strict_reaudit_half_01.jsonl", manifest[:half])
    write_jsonl(AUDIT_ROOT / "strict_reaudit_half_02.jsonl", manifest[half:])
    write_jsonl(AUDIT_ROOT / "mechanical_issues.jsonl", issues)

    summary = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "ledger_rows": len(ledger),
        "expected_rows": len(expected_keys),
        "unique_ledger_keys": len(set(ledger_keys)),
        "missing_expected_rows": len(missing),
        "unexpected_rows": len(unexpected),
        "duplicate_keys": sum(1 for count in ledger_key_counts.values() if count > 1),
        "mechanical_issue_rows": len(issues),
        "issue_counts": Counter(issue for row in issues for issue in row["issues"]),
        "outputs": {
            "manifest": rel(AUDIT_ROOT / "strict_reaudit_manifest.jsonl"),
            "half_01": rel(AUDIT_ROOT / "strict_reaudit_half_01.jsonl"),
            "half_02": rel(AUDIT_ROOT / "strict_reaudit_half_02.jsonl"),
            "mechanical_issues": rel(AUDIT_ROOT / "mechanical_issues.jsonl"),
        },
        "missing_examples": [list(item) for item in missing[:10]],
        "unexpected_examples": [list(item) for item in unexpected[:10]],
    }
    (AUDIT_ROOT / "mechanical_audit_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=dict),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=dict))


if __name__ == "__main__":
    main()
