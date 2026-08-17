#!/usr/bin/env python3
"""Trace Gold steps through issue generation, evidence search, and final synthesis.

The classifier uses recorded investigate_lead calls, successful investigation
tool previews, exact Gold evidence identifiers, and the adopted final component
scores. Cases whose investigation trace cannot be established are kept outside
the stage-error categories instead of being forced into one of them.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import analyze_three_model_error_patterns_20260814 as patterns
import rescore_three_models_all_trials_action_order_semantic_v1_20260814 as base


ROOT = Path(__file__).resolve().parents[1]
PATTERN_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_error_patterns_v1"
)
SOURCE_GOLD_PATTERNS = PATTERN_DIR / "gold_step_patterns.jsonl"
SOURCE_CLAIM_PATTERNS = PATTERN_DIR / "candidate_claim_patterns.jsonl"
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_pipeline_trace_errors_v1"
)
OUT_STEPS = OUT_DIR / "gold_step_pipeline_trace.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REVIEW = OUT_DIR / "ambiguous_trace_review.jsonl"

MODELS = base.MODELS
PHASES = base.PHASES

ACTION_TERMS = {
    "PROCESS_CREATE": (
        "process_create", "create_process", "action_create_process",
        "process start", "process_start", "child_process", "child process",
        "childproc", "spawn", "ppid", "parent_process",
    ),
    "INPUT_USE": (
        "execution_input", "document", "script", "batch", ".bat", ".rtf",
        ".doc", "file_read", "read", "open", "command_line",
    ),
    "FILE_CREATE_WRITE": (
        "file_create", "file create", "file_write", "file write", "filemod",
        "action_file_create", "action_file_open_write", "directory", "write",
    ),
    "REGISTRY_WRITE": (
        "registry", "regmod", "write_value", "action_write_value",
        "currentversion\\run", "currentversion/run",
    ),
    "NETWORK_CONNECT": (
        "network_connect", "connection", "connect", "netconn", "remote_ip",
        "remote_port", "http://", "https://",
    ),
    "NETWORK_LISTEN": (
        "network_listen", "listen", "listener", "local_port", "0.0.0.0",
    ),
}

RAW_EVIDENCE_MARKERS = (
    "source_row_id", "event_record_id", "source_stream", "timestamp",
    "action_create_process", "process_create", "remote_ip", "remote_port",
    "childproc_name", "filemod_name", "regmod_name",
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def relative(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_normalized_rows() -> list[dict[str, Any]]:
    rows = []
    for spec in base.SOURCE_SPECS:
        rows.extend(
            base.normalize_row(source_row, spec)
            for source_row in base.read_jsonl(spec["path"])
        )
    return rows


def run_path(row: dict[str, Any]) -> Path:
    value = row.get("run_json") or row.get("run_path")
    if value:
        return ROOT / str(value).replace("\\", "/")
    parts = str(row["queue_id"]).split("/")
    if len(parts) != 4:
        raise ValueError(f"cannot resolve run path: {row['queue_id']}")
    model, stage, run_name, _ = parts
    return (
        ROOT
        / "docs/current_experiment/results_2026-07-27"
        / "atlasv2_s3_s4_attack8_process_chain_v5_formal"
        / "two_model_baseline_replicate_01/runs"
        / model
        / stage
        / f"{run_name}_run.json"
    )


def lower_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()


def port_tokens(value: Any) -> set[str]:
    text = str(value or "").lower()
    tokens = {"port:" + match for match in re.findall(r"(?::|port\D{0,8})(\d{2,5})\b", text)}
    return tokens


def identity_tokens(value: Any) -> set[str]:
    return patterns.entity_tokens(value) | port_tokens(value)


def step_identity_tokens(step: dict[str, Any]) -> tuple[set[str], set[str]]:
    subject = identity_tokens(step.get("subject"))
    obj = identity_tokens(step.get("object"))
    signature = step.get("critical_evidence_signature") or {}
    if signature.get("process_pid") is not None:
        subject.add("pid:" + str(signature["process_pid"]))
    target = signature.get("target_key")
    if target is not None:
        obj |= identity_tokens(target)
        if isinstance(target, int) or str(target).isdigit():
            obj.add("pid:" + str(target))
    return subject, obj


def evidence_ids(step: dict[str, Any]) -> list[str]:
    values = []
    signature = step.get("critical_evidence_signature") or {}
    values.extend((signature.get("source_row_id"), signature.get("event_record_id")))
    for evidence in step.get("canonical_evidence") or []:
        values.extend((evidence.get("source_row_id"), evidence.get("event_record_id")))
    return sorted({str(value) for value in values if value is not None and len(str(value)) >= 4})


def contains_identifier(text: str, identifier: str) -> bool:
    return bool(
        re.search(
            r"(?<![a-z0-9])" + re.escape(identifier.lower()) + r"(?![a-z0-9])",
            text,
        )
    )


def action_match(text: str, action_class: str) -> bool:
    return any(term in text for term in ACTION_TERMS[action_class])


def relation_match_details(
    text: str,
    step: dict[str, Any],
    action_class: str,
) -> dict[str, Any]:
    text_tokens = identity_tokens(text)
    subject_tokens, object_tokens = step_identity_tokens(step)
    distinct_subject = subject_tokens - object_tokens
    distinct_object = object_tokens - subject_tokens
    subject_match_tokens = text_tokens & (distinct_subject or subject_tokens)
    object_match_tokens = text_tokens & (distinct_object or object_tokens)
    action_matched = action_match(text.lower(), action_class)
    score = 2 * bool(subject_match_tokens) + 2 * bool(object_match_tokens) + bool(action_matched)
    return {
        "score": score,
        "subject_match_tokens": sorted(subject_match_tokens),
        "object_match_tokens": sorted(object_match_tokens),
        "action_match": action_matched,
        "strong": bool(subject_match_tokens and object_match_tokens and action_matched),
        "partial": bool(score >= 3),
    }


def extract_leads(run: dict[str, Any]) -> list[dict[str, Any]]:
    leads = []
    for message_index, message in enumerate(run.get("official_messages") or []):
        for tool_call in message.get("tool_calls") or []:
            if tool_call.get("name") != "investigate_lead":
                continue
            arguments = tool_call.get("args") or {}
            leads.append(
                {
                    "message_index": message_index,
                    "arguments": arguments,
                    "text": lower_json(arguments),
                }
            )
    return leads


def evidence_corpora(run: dict[str, Any]) -> tuple[str, str]:
    exact_texts = []
    semantic_texts = []
    for message in run.get("official_messages") or []:
        if message.get("type") == "ToolMessage":
            exact_texts.append(str(message.get("content") or "").lower())
    activity = (run.get("investigation_activity") or {}).get("events") or []
    for event in activity:
        outcome = str(event.get("outcome") or "")
        if outcome in {"sql_success", "success"}:
            preview = str(event.get("result_preview") or "").lower()
            if preview and "no results found" not in preview:
                semantic_texts.append(preview)
    return "\n".join(exact_texts), "\n".join(semantic_texts)


def trace_step(
    row: dict[str, Any],
    step: dict[str, Any],
    action_class: str,
    final_pattern: str,
    leads: list[dict[str, Any]],
    exact_corpus: str,
    semantic_corpus: str,
    claim_flags: list[str],
) -> dict[str, Any]:
    lead_matches = []
    for index, lead in enumerate(leads):
        details = relation_match_details(lead["text"], step, action_class)
        if details["partial"]:
            lead_matches.append({"lead_index": index, **details})
    strong_leads = [match for match in lead_matches if match["strong"]]

    matched_ids = [
        identifier
        for identifier in evidence_ids(step)
        if contains_identifier(exact_corpus, identifier)
        or contains_identifier(semantic_corpus, identifier)
    ]
    semantic_details = relation_match_details(semantic_corpus, step, action_class)
    raw_marker_count = sum(marker in semantic_corpus for marker in RAW_EVIDENCE_MARKERS)
    semantic_evidence = bool(semantic_details["strong"] and raw_marker_count >= 2)
    evidence_found = bool(matched_ids or semantic_evidence)

    if lead_matches or evidence_found:
        issue_status = "ISSUE_RAISED"
    else:
        issue_status = "NO_MATCHING_ISSUE_IN_RECORDED_LEADS"
    issue_match_confidence = (
        "strong"
        if strong_leads
        else (
            "partial"
            if lead_matches
            else ("implicit_from_evidence" if evidence_found else "none")
        )
    )

    final_complete = final_pattern == "COMPLETE_SAO"
    final_omitted = final_pattern == "STEP_OMISSION"
    if evidence_found and final_omitted:
        pipeline_status = "EVIDENCE_FOUND_NOT_REFLECTED_IN_FINAL"
    elif evidence_found and not final_complete:
        pipeline_status = "EVIDENCE_FOUND_FINAL_RELATION_ERROR"
    elif evidence_found and final_complete:
        pipeline_status = "EVIDENCE_FOUND_REFLECTED_CORRECTLY"
    elif final_complete:
        pipeline_status = "FINAL_CORRECT_WITHOUT_TRACEABLE_INVESTIGATION"
    elif not final_omitted:
        pipeline_status = "FINAL_PARTIAL_WITHOUT_TRACEABLE_INVESTIGATION"
    elif lead_matches:
        pipeline_status = "ISSUE_RAISED_EVIDENCE_NOT_FOUND_FINAL_OMISSION"
    else:
        pipeline_status = "ISSUE_NOT_RAISED_FINAL_OMISSION"

    return {
        "model": row["model"],
        "phase": row["phase"],
        "replicate": row["replicate"],
        "stage": row["stage"],
        "chain_id": row["chain_id"],
        "source_queue_id": row["queue_id"],
        "step_id": step["step_id"],
        "gold_subject": step.get("subject"),
        "gold_action": step.get("action"),
        "gold_object": step.get("object"),
        "gold_action_class": action_class,
        "final_recovery_pattern": final_pattern,
        "final_claim_error_flags": claim_flags,
        "recorded_lead_count": len(leads),
        "strong_matching_lead_count": len(strong_leads),
        "partial_matching_lead_count": len(lead_matches),
        "lead_match_details": lead_matches,
        "issue_status": issue_status,
        "issue_match_confidence": issue_match_confidence,
        "evidence_found_high_confidence": evidence_found,
        "evidence_match_method": (
            "exact_evidence_identifier"
            if matched_ids
            else ("semantic_successful_tool_result" if semantic_evidence else None)
        ),
        "matched_evidence_identifiers": matched_ids,
        "semantic_evidence_match": semantic_details,
        "successful_result_raw_marker_count": raw_marker_count,
        "pipeline_status": pipeline_status,
    }


def group_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {
        "overall": {
            "denominator": len(rows),
            "counts": dict(sorted(Counter(row["pipeline_status"] for row in rows).items())),
        },
        "by_model": {},
        "by_model_phase": {},
    }
    for model in MODELS:
        selected = [row for row in rows if row["model"] == model]
        result["by_model"][model] = {
            "denominator": len(selected),
            "counts": dict(sorted(Counter(row["pipeline_status"] for row in selected).items())),
        }
        for phase in PHASES:
            subset = [row for row in selected if row["phase"] == phase]
            result["by_model_phase"][f"{model}/{phase}"] = {
                "denominator": len(subset),
                "counts": dict(sorted(Counter(row["pipeline_status"] for row in subset).items())),
            }
    return result


def relation_error_breakdown(rows: list[dict[str, Any]]) -> dict[str, Any]:
    selected = [
        row
        for row in rows
        if row["pipeline_status"] == "EVIDENCE_FOUND_FINAL_RELATION_ERROR"
    ]

    def breakdown(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "denominator": len(items),
            "final_recovery_patterns": dict(
                sorted(Counter(row["final_recovery_pattern"] for row in items).items())
            ),
            "overlapping_claim_error_flags": dict(
                sorted(
                    Counter(
                        flag
                        for row in items
                        for flag in row["final_claim_error_flags"]
                    ).items()
                )
            ),
        }

    result = {"overall": breakdown(selected), "by_model": {}, "by_model_phase": {}}
    for model in MODELS:
        model_rows = [row for row in selected if row["model"] == model]
        result["by_model"][model] = breakdown(model_rows)
        for phase in PHASES:
            result["by_model_phase"][f"{model}/{phase}"] = breakdown(
                [row for row in model_rows if row["phase"] == phase]
            )
    return result


def main() -> None:
    replace_generated = "--replace-generated" in sys.argv[1:]
    for path in (OUT_STEPS, OUT_SUMMARY, OUT_REVIEW):
        if path.exists() and not replace_generated:
            raise FileExistsError(f"create-only refusal: {path}")

    normalized_rows = load_normalized_rows()
    gold_patterns = {
        (row["source_queue_id"], row["step_id"]): row
        for row in read_jsonl(SOURCE_GOLD_PATTERNS)
    }
    claim_patterns = read_jsonl(SOURCE_CLAIM_PATTERNS)
    claim_flags_by_step: dict[tuple[str, str], set[str]] = defaultdict(set)
    for claim in claim_patterns:
        step_id = claim.get("aligned_gold_step_id") or claim.get("reversal_gold_step_id")
        if step_id:
            claim_flags_by_step[(claim["source_queue_id"], step_id)].update(
                claim["error_flags"]
            )

    traced = []
    run_inventory = []
    for row in normalized_rows:
        path = run_path(row)
        if not path.exists():
            raise FileNotFoundError(path)
        run = read_json(path)
        leads = extract_leads(run)
        exact_corpus, semantic_corpus = evidence_corpora(run)
        gold = read_json(base.policy_v1.gold_path(row))
        for step in gold["gold_steps"]:
            key = (row["queue_id"], step["step_id"])
            pattern = gold_patterns[key]
            traced.append(
                trace_step(
                    row=row,
                    step=step,
                    action_class=pattern["gold_action_class"],
                    final_pattern=pattern["recovery_pattern"],
                    leads=leads,
                    exact_corpus=exact_corpus,
                    semantic_corpus=semantic_corpus,
                    claim_flags=sorted(claim_flags_by_step.get(key, set())),
                )
            )
        run_inventory.append(
            {
                "source_queue_id": row["queue_id"],
                "run_path": relative(path),
                "run_sha256": sha256(path),
                "lead_count": len(leads),
            }
        )

    if len(traced) != 1571:
        raise AssertionError(f"expected 1571 traced steps, got {len(traced)}")
    review_statuses = {
        "FINAL_CORRECT_WITHOUT_TRACEABLE_INVESTIGATION",
        "FINAL_PARTIAL_WITHOUT_TRACEABLE_INVESTIGATION",
    }
    review_rows = [row for row in traced if row["pipeline_status"] in review_statuses]
    summary = {
        "schema_version": "three_model_pipeline_trace_errors_v1",
        "created_date": "2026-08-14",
        "method": {
            "issue_raised": "a recorded investigate_lead has a semantic partial or strong match to the Gold subject/object/action; evidence discovery itself also implies the issue was investigated",
            "evidence_found": "exact Gold evidence identifier in investigation output, or subject/object/action match in a successful tool result with raw-evidence markers",
            "final_reflection": "adopted semantic subject/action/object Gold-step pattern",
            "internal_reasoning_observed": False,
            "uncertain_matches_forced": False,
            "model_or_judge_calls": 0,
        },
        "counts": {
            "runs": len(normalized_rows),
            "gold_steps": len(traced),
            "untraceable_investigation_steps": len(review_rows),
        },
        "pipeline_status": group_counts(traced),
        "evidence_found_final_relation_error_breakdown": relation_error_breakdown(traced),
        "evidence_match_methods": dict(
            sorted(Counter(str(row["evidence_match_method"]) for row in traced).items())
        ),
        "run_inventory": run_inventory,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_STEPS, traced)
    write_jsonl(OUT_REVIEW, review_rows)
    OUT_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary["pipeline_status"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
