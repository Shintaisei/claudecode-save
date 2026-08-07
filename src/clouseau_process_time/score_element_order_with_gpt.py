#!/usr/bin/env python3
"""Score CLOUSEAU behavior-chain outputs with action-claim recall, precision, and order metrics."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - only relevant in Anthropic-only environments.
    OpenAI = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = ROOT / ".env.clouseau"
DEFAULT_OUT = ROOT / "data" / "current_experiment" / "scores" / "element_order_scores"
ACTION_REQUIRED_ITEM_KINDS = {"subject", "operation", "object", "command_line", "critical_evidence"}
ACTION_DENOMINATOR_ITEM_KINDS = ACTION_REQUIRED_ITEM_KINDS - {"critical_evidence"}


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def infer_judge_provider(model: str, env: dict[str, str], explicit_provider: str | None = None) -> str:
    provider = (
        explicit_provider
        or env.get("CLOUSEAU_JUDGE_PROVIDER")
        or env.get("CLOUSEAU_LLM_PROVIDER")
        or env.get("CLOUSEAU_PROVIDER")
        or os.getenv("CLOUSEAU_JUDGE_PROVIDER")
        or os.getenv("CLOUSEAU_LLM_PROVIDER")
        or os.getenv("CLOUSEAU_PROVIDER")
        or ""
    ).strip().lower()
    if provider:
        if provider not in {"openai", "anthropic"}:
            raise ValueError(f"Unsupported judge provider: {provider!r}")
        return provider
    if model.startswith("claude-"):
        return "anthropic"
    return "openai"


def select_judge_model(args: argparse.Namespace, env: dict[str, str]) -> str:
    provider_hint = (
        args.provider
        or env.get("CLOUSEAU_JUDGE_PROVIDER")
        or env.get("CLOUSEAU_LLM_PROVIDER")
        or env.get("CLOUSEAU_PROVIDER")
        or ""
    ).strip().lower()
    if args.model:
        return args.model
    if provider_hint == "anthropic":
        return env.get("ANTHROPIC_JUDGE_MODEL") or env.get("ANTHROPIC_MODEL") or env.get("CLAUDE_MODEL") or "claude-sonnet-4-6"
    return env.get("OPENAI_JUDGE_MODEL") or env.get("OPENAI_MODEL") or "gpt-5-mini"


def api_key_for_provider(provider: str, env: dict[str, str]) -> str | None:
    if provider == "anthropic":
        return (
            env.get("ANTHROPIC_API_KEY")
            or env.get("CLAUDE_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("CLAUDE_API_KEY")
        )
    return env.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")


def anthropic_output_text(response: Any) -> str:
    parts: list[str] = []
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
    return "\n".join(part for part in parts if part)


def call_judge_model(
    provider: str,
    model: str,
    api_key: str,
    prompt: str,
    reasoning_effort: str | None,
    max_output_tokens: int | None,
) -> tuple[str, str | None, dict[str, Any] | None]:
    if provider == "anthropic":
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise RuntimeError("Claude judging requires anthropic. Install it in the active Python environment.") from exc
        client = Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=max_output_tokens or 8192,
            messages=[{"role": "user", "content": prompt}],
        )
        usage = getattr(response, "usage", None)
        return (
            anthropic_output_text(response),
            getattr(response, "id", None),
            usage.model_dump() if hasattr(usage, "model_dump") else dict(usage) if usage else None,
        )

    if OpenAI is None:
        raise RuntimeError("OpenAI judging requires openai in the active Python environment.")
    client = OpenAI(api_key=api_key)
    request: dict[str, Any] = {"model": model, "input": prompt}
    if max_output_tokens:
        request["max_output_tokens"] = max_output_tokens
    if reasoning_effort and str(reasoning_effort).lower() not in {"none", "false", "0"}:
        request["reasoning"] = {"effort": reasoning_effort}
    response = client.responses.create(**request)
    usage = getattr(response, "usage", None)
    return (
        response.output_text,
        getattr(response, "id", None),
        usage.model_dump() if usage else None,
    )


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def writable_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    resolved = str(path.resolve())
    if resolved.startswith("\\\\?\\"):
        return Path(resolved)
    if resolved.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + resolved.lstrip("\\"))
    return Path("\\\\?\\" + resolved)


def write_text(path: Path, text: str) -> None:
    writable_path(path.parent).mkdir(parents=True, exist_ok=True)
    writable_path(path).write_text(text, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def extract_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return json.loads(fenced.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("judge output did not contain a JSON object")


def normalize_gold(gold: dict[str, Any], gold_path: Path | None = None) -> list[dict[str, Any]]:
    if "behavior_nodes" in gold:
        chains = []
        for node in gold["behavior_nodes"]:
            steps = node.get("gold_behavior_steps") or []
            chains.append(
                {
                    "chain_id": node.get("behavior_id"),
                    "chain_title": node.get("title"),
                    "time_range_utc": node.get("time_range_utc"),
                    "host": node.get("host"),
                    "user": node.get("user"),
                    "process_relation": node.get("process_relation"),
                    "subject": node.get("subject"),
                    "action": node.get("action"),
                    "object": node.get("object"),
                    "alerts": node.get("alerts"),
                    "required_evidence_fields": node.get("required_evidence_fields"),
                    "process_code_sequence": node.get("process_code_sequence"),
                    "gold_steps": sorted(steps, key=lambda s: s.get("order", 0)),
                    "gold_order_pairs": node.get("gold_order_pairs") or [],
                    "policy_note": node.get("gold_policy_note"),
                    "critical_evidence_policy": node.get("critical_evidence_policy"),
                }
            )
        return chains
    if "chains" in gold:
        chains = []
        for chain in gold["chains"]:
            steps = chain.get("gold_steps") or chain.get("behavior_timeline") or []
            if not steps and chain.get("chain_gold_file") and gold_path is not None:
                child_path = gold_path.parent / chain["chain_gold_file"]
                chains.extend(normalize_gold(read_json(child_path), child_path))
                continue
            chains.append(
                {
                    "chain_id": chain.get("chain_id"),
                    "chain_title": chain.get("chain_title"),
                    "gold_steps": sorted(steps, key=lambda s: s.get("order", 0)),
                    "gold_order_pairs": chain.get("gold_order_pairs") or [],
                }
            )
        return chains
    steps = gold.get("gold_steps") or gold.get("behavior_timeline") or []
    return [
        {
            "chain_id": gold.get("chain_id"),
            "chain_title": gold.get("chain_title"),
            "gold_steps": sorted(steps, key=lambda s: s.get("order", 0)),
            "gold_order_pairs": gold.get("gold_order_pairs") or [],
        }
    ]


def required_items_from_step(chain_id: str | None, step: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive action-claim required items from chain gold that lacks explicit slots."""
    step_id = step.get("step_id")
    derived: list[dict[str, Any]] = []
    template = step.get("scoring_template") or {}
    mapping = [
        ("subject", step.get("subject")),
        ("operation", step.get("action") or step.get("operation")),
        ("object", step.get("object") or step.get("process_code_object")),
        ("critical_evidence", step.get("evidence_basis")),
    ]
    for kind, value in mapping:
        template_key = "action" if kind == "operation" else "evidence" if kind == "critical_evidence" else kind
        template_slot = template.get(template_key)
        if isinstance(template_slot, dict) and int(template_slot.get("max") or 0) <= 0:
            continue
        if value in (None, ""):
            continue
        derived.append(
            {
                "chain_id": chain_id,
                "step_id": step_id,
                "item_id": f"{chain_id}:{step_id}:{kind}",
                "kind": kind,
                "gold_value": value,
                "acceptable_terms": [value],
            }
        )
    return derived


def candidate_output_from_run(run_json: Path) -> dict[str, Any]:
    run = read_json(run_json)
    return {
        "source_run_json": str(run_json),
        "run_id": run.get("run_id"),
        "model": run.get("model"),
        "instance_id": run.get("instance_id"),
        "difficulty": run.get("difficulty"),
        "experiment_stage": run.get("experiment_stage"),
        "expected_input_fields": run.get("expected_input_fields"),
        "clue": run.get("clue"),
        "output_text": run.get("output_text", ""),
        "usage": run.get("usage"),
    }


def gold_required_items(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for chain in chains:
        chain_id = chain.get("chain_id")
        for step in chain.get("gold_steps", []):
            step_id = step.get("step_id")
            required = step.get("required_items") or step.get("required_elements") or []
            if not required:
                items.extend(required_items_from_step(chain_id, step))
                continue
            for item in required:
                kind = item.get("kind")
                if kind == "evidence":
                    kind = "critical_evidence"
                if kind not in ACTION_REQUIRED_ITEM_KINDS:
                    continue
                items.append(
                    {
                        "chain_id": chain_id,
                        "step_id": step_id,
                        "item_id": item.get("item_id") or item.get("element_id"),
                        "kind": kind,
                        "gold_value": item.get("gold_value"),
                        "acceptable_terms": item.get("acceptable_terms") or [],
                    }
                )
    return items


def gold_maxima(chains: list[dict[str, Any]]) -> dict[str, int]:
    order_count = 0
    required_items = gold_required_items(chains)
    for chain in chains:
        explicit_pairs = chain.get("gold_order_pairs") or []
        order_count += len(explicit_pairs) if explicit_pairs else max(len(chain.get("gold_steps", [])) - 1, 0)
    return {
        "gold_required_item_count": len(required_items),
        "gold_action_required_item_count": sum(
            1 for item in required_items if item.get("kind") in ACTION_DENOMINATOR_ITEM_KINDS
        ),
        "gold_step_count": sum(len(chain.get("gold_steps", [])) for chain in chains),
        "gold_order_pair_count": order_count,
    }


def load_stage3_supported_step_keys(path: Path | None) -> set[tuple[str, str]]:
    if not path:
        return set()
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows.extend(reader)
    return {(row["chain_id"], row["step_id"]) for row in rows if row.get("stage3_status") == "pass"}


def filter_chains_for_stage(chains: list[dict[str, Any]], stage: str | None, validation_csv: Path | None) -> list[dict[str, Any]]:
    if stage != "stage3":
        return chains
    supported = load_stage3_supported_step_keys(validation_csv)
    if not supported:
        raise ValueError("--stage stage3 requires --validation-steps with stage3_status=pass rows")
    filtered: list[dict[str, Any]] = []
    for chain in chains:
        chain_id = chain.get("chain_id")
        kept_steps = [step for step in chain.get("gold_steps", []) if (chain_id, step.get("step_id")) in supported]
        if not kept_steps:
            continue
        item = dict(chain)
        item["gold_steps"] = kept_steps
        explicit_pairs = chain.get("gold_order_pairs") or []
        if explicit_pairs:
            # Older single-chain gold files encode order pairs as two-element
            # arrays, while newer composite gold uses mapping objects.  Stage 3
            # filtering must support both representations before dereferencing
            # pair keys; otherwise valid legacy gold fails before scoring.
            normalized_pairs: list[dict[str, Any]] = []
            for pair in explicit_pairs:
                if isinstance(pair, dict):
                    normalized_pairs.append(pair)
                elif isinstance(pair, (list, tuple)) and len(pair) == 2:
                    normalized_pairs.append(
                        {"before_step_id": pair[0], "after_step_id": pair[1]}
                    )
                else:
                    raise ValueError(
                        f"Unsupported gold_order_pairs entry for chain {chain_id!r}: {pair!r}"
                    )
            item["gold_order_pairs"] = [
                pair
                for pair in normalized_pairs
                if (chain_id, pair.get("before_step_id")) in supported
                and (chain_id, pair.get("after_step_id")) in supported
            ]
        filtered.append(item)
    return filtered


def force_binary(value: Any) -> int:
    try:
        return 1 if int(value) == 1 else 0
    except Exception:
        return 0


def normalize_match_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "n/a", "na"}:
        return None
    return text


def candidate_slot_scores(chain: dict[str, Any]) -> Iterable[dict[str, Any]]:
    claims = chain.get("candidate_action_claim_scores") or chain.get("candidate_claim_scores") or []
    for claim in claims:
        claim_id = claim.get("candidate_claim_id") or claim.get("claim_id")
        slots = claim.get("slot_scores") or claim.get("required_item_scores") or []
        for slot in slots:
            slot = dict(slot)
            slot.setdefault("candidate_claim_id", claim_id)
            yield slot


def recompute_totals(score: dict[str, Any], maxima: dict[str, int]) -> dict[str, Any]:
    recall_hits = 0
    order_hits = 0
    candidate_true_positive = 0
    action_candidate_true_positive = 0
    duplicate_true_positive = 0
    raw_candidate_total = 0
    candidate_total = 0
    critical_evidence_hits = 0
    critical_evidence_total = 0
    covered_step_ids: set[str] = set()
    matched_gold_item_ids: set[str] = set()
    diagnostics_by_kind: dict[str, dict[str, int]] = {
        kind: {"recall_hits": 0, "recall_total": 0, "precision_hits": 0, "precision_total": 0}
        for kind in sorted(ACTION_REQUIRED_ITEM_KINDS)
    }

    for chain in score.get("chains", []):
        gold_scores = chain.get("gold_required_item_scores") or chain.get("gold_atomic_element_scores") or []
        for item in gold_scores:
            kind = item.get("kind")
            if kind == "evidence":
                kind = "critical_evidence"
            item_score = force_binary(item.get("score"))
            if kind in ACTION_DENOMINATOR_ITEM_KINDS:
                recall_hits += item_score
            if kind in diagnostics_by_kind:
                diagnostics_by_kind[kind]["recall_total"] += 1
                diagnostics_by_kind[kind]["recall_hits"] += item_score
            if kind == "critical_evidence":
                critical_evidence_total += 1
                critical_evidence_hits += item_score
            if item_score and kind in ACTION_DENOMINATOR_ITEM_KINDS:
                step_id = item.get("step_id")
                if step_id:
                    covered_step_ids.add(str(step_id))

        for slot in candidate_slot_scores(chain):
            raw_candidate_total += 1
            kind = slot.get("kind")
            if kind == "evidence":
                kind = "critical_evidence"
            candidate_total += 1
            if kind in diagnostics_by_kind:
                diagnostics_by_kind[kind]["precision_total"] += 1
            if not force_binary(slot.get("is_true_positive")):
                continue
            matched_id = normalize_match_id(slot.get("matched_gold_item_id") or slot.get("matched_gold_element_id"))
            if matched_id is None:
                continue
            if matched_id in matched_gold_item_ids:
                duplicate_true_positive += 1
                continue
            matched_gold_item_ids.add(matched_id)
            candidate_true_positive += 1
            if kind in ACTION_DENOMINATOR_ITEM_KINDS:
                action_candidate_true_positive += 1
            if kind in diagnostics_by_kind:
                diagnostics_by_kind[kind]["precision_hits"] += 1

        for pair in chain.get("order_pairs", []):
            order_hits += force_binary(pair.get("score"))

    if not candidate_total:
        candidate_total = int(score.get("candidate_action_claim_slot_count") or score.get("candidate_atomic_element_count") or 0)
        candidate_true_positive = int(
            score.get("candidate_action_claim_true_positive_slot_count")
            or score.get("candidate_atomic_true_positive_count")
            or 0
        )
    flags = score.get("error_flags") or {}
    hallucinated_claim_count = int(score.get("hallucinated_claim_count") or len(flags.get("hallucinated_claims") or []))
    unsupported_evidence_count = int(score.get("unsupported_evidence_count") or len(flags.get("unsupported_evidence") or []))
    contradicted_evidence_count = int(score.get("contradicted_evidence_count") or len(flags.get("contradicted_evidence") or []))
    nearby_action_fp_count = int(score.get("nearby_action_fp_count") or len(flags.get("nearby_action_false_positives") or []))

    gold_required_item_count = maxima["gold_required_item_count"]
    gold_action_required_item_count = maxima["gold_action_required_item_count"]
    gold_order_pair_count = maxima["gold_order_pair_count"]
    gold_step_count = maxima["gold_step_count"]
    score["candidate_action_claim_true_positive_slot_count"] = candidate_true_positive
    score["candidate_action_claim_slot_count"] = candidate_total
    score["candidate_action_claim_raw_slot_count"] = raw_candidate_total
    score["candidate_action_claim_duplicate_true_positive_slot_count"] = duplicate_true_positive
    false_positive_slot_count = max(candidate_total - candidate_true_positive, 0)
    score["totals"] = {
        "behavior_step_recall": len(covered_step_ids) / gold_step_count if gold_step_count else None,
        "behavior_step_recall_hits": len(covered_step_ids),
        "behavior_step_recall_total": gold_step_count,
        "action_step_recall": recall_hits / gold_action_required_item_count if gold_action_required_item_count else None,
        "action_step_recall_hits": recall_hits,
        "action_step_recall_total": gold_action_required_item_count,
        "action_step_precision": (
            action_candidate_true_positive / gold_action_required_item_count
            if gold_action_required_item_count
            else None
        ),
        "action_step_precision_hits": action_candidate_true_positive,
        "action_step_precision_total": gold_action_required_item_count,
        "gold_required_item_count": gold_required_item_count,
        "gold_action_required_item_count": gold_action_required_item_count,
        "action_denominator_excludes_critical_evidence": True,
        "candidate_claim_precision": candidate_true_positive / candidate_total if candidate_total else None,
        "candidate_claim_precision_hits": candidate_true_positive,
        "candidate_claim_precision_total": candidate_total,
        "overclaim_slot_count": false_positive_slot_count,
        "candidate_action_claim_true_positive_slot_count": candidate_true_positive,
        "candidate_action_claim_slot_count": candidate_total,
        "candidate_action_claim_raw_slot_count": raw_candidate_total,
        "candidate_action_claim_duplicate_true_positive_slot_count": duplicate_true_positive,
        "behavior_sequence_order": order_hits / gold_order_pair_count if gold_order_pair_count else None,
        "behavior_sequence_order_hits": order_hits,
        "behavior_sequence_order_total": gold_order_pair_count,
        "critical_evidence_recall": critical_evidence_hits / critical_evidence_total if critical_evidence_total else None,
        "critical_evidence_recall_hits": critical_evidence_hits,
        "critical_evidence_recall_total": critical_evidence_total,
        "coarse_action_step_coverage": len(covered_step_ids) / gold_step_count if gold_step_count else None,
        "coarse_action_step_coverage_hits": len(covered_step_ids),
        "coarse_action_step_coverage_total": gold_step_count,
        "hallucinated_claim_count": hallucinated_claim_count,
        "unsupported_evidence_count": unsupported_evidence_count,
        "contradicted_evidence_count": contradicted_evidence_count,
        "nearby_action_fp_count": nearby_action_fp_count,
        "behavior_element_diagnostics": diagnostics_by_kind,
    }
    return score


def write_summary_csv(path: Path, result: dict[str, Any], candidate: dict[str, Any]) -> None:
    score = result.get("score") or {}
    totals = score.get("totals") or {}
    flags = score.get("error_flags") or {}
    condition = candidate.get("experiment_stage") or candidate.get("difficulty") or ""
    row = {
        "condition": condition,
        "model": candidate.get("model") or "",
        "action_step_recall": totals.get("action_step_recall"),
        "action_step_recall_hits": totals.get("action_step_recall_hits"),
        "action_step_recall_total": totals.get("action_step_recall_total"),
        "behavior_step_recall": totals.get("behavior_step_recall"),
        "behavior_step_recall_hits": totals.get("behavior_step_recall_hits"),
        "behavior_step_recall_total": totals.get("behavior_step_recall_total"),
        "action_step_precision": totals.get("action_step_precision"),
        "action_step_precision_hits": totals.get("action_step_precision_hits"),
        "action_step_precision_total": totals.get("action_step_precision_total"),
        "candidate_claim_precision": totals.get("candidate_claim_precision"),
        "candidate_claim_precision_hits": totals.get("candidate_claim_precision_hits"),
        "candidate_claim_precision_total": totals.get("candidate_claim_precision_total"),
        "overclaim_slot_count": totals.get("overclaim_slot_count"),
        "behavior_sequence_order": totals.get("behavior_sequence_order"),
        "critical_evidence_recall": totals.get("critical_evidence_recall"),
        "coarse_action_step_coverage": totals.get("coarse_action_step_coverage"),
        "hallucinated_claim_count": totals.get("hallucinated_claim_count"),
        "unsupported_evidence_count": totals.get("unsupported_evidence_count"),
        "contradicted_evidence_count": totals.get("contradicted_evidence_count"),
        "nearby_action_fp_count": totals.get("nearby_action_fp_count"),
        "main_missing_items": " | ".join(score.get("main_missing_items") or score.get("main_missing_elements") or []),
        "main_false_positive_claims": " | ".join(
            score.get("main_false_positive_claims")
            or score.get("main_false_positive_elements")
            or flags.get("false_positive_claims")
            or []
        ),
        "score_json": str(path.parent / "score_result.json"),
        "run_json": result.get("candidate_run_json") or "",
    }
    fields = list(row.keys())
    writable_path(path.parent).mkdir(parents=True, exist_ok=True)
    with writable_path(path).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerow(row)


def zero_denominator_score(reason: str) -> dict[str, Any]:
    return {
        "skipped": reason,
        "judge_summary_ja": "Stage3で評価可能なgold stepがないため、judge APIを呼ばずにskipした。",
        "chains": [],
        "error_flags": {
            "target_missing": [],
            "chain_mixing": False,
            "hallucinated_claims": [],
            "unsupported_evidence": [],
            "contradicted_evidence": [],
            "nearby_action_false_positives": [],
            "weak_grounding": False,
            "false_positive_claims": [],
            "notes_ja": [reason],
        },
        "candidate_action_claim_count": 0,
        "candidate_action_claim_slot_count": 0,
        "candidate_action_claim_true_positive_slot_count": 0,
        "hallucinated_claim_count": 0,
        "unsupported_evidence_count": 0,
        "contradicted_evidence_count": 0,
        "nearby_action_fp_count": 0,
        "main_missing_items": [],
        "main_false_positive_claims": [],
        "totals": {
            "behavior_step_recall": None,
            "behavior_step_recall_hits": 0,
            "behavior_step_recall_total": 0,
            "action_step_recall": None,
            "action_step_recall_hits": 0,
            "action_step_recall_total": 0,
            "action_step_precision": None,
            "action_step_precision_hits": 0,
            "action_step_precision_total": 0,
            "gold_required_item_count": 0,
            "gold_action_required_item_count": 0,
            "action_denominator_excludes_critical_evidence": True,
            "candidate_claim_precision": None,
            "candidate_claim_precision_hits": 0,
            "candidate_claim_precision_total": 0,
            "overclaim_slot_count": 0,
            "candidate_action_claim_true_positive_slot_count": 0,
            "candidate_action_claim_slot_count": 0,
            "candidate_action_claim_raw_slot_count": 0,
            "candidate_action_claim_duplicate_true_positive_slot_count": 0,
            "behavior_sequence_order": None,
            "behavior_sequence_order_hits": 0,
            "behavior_sequence_order_total": 0,
            "critical_evidence_recall": None,
            "critical_evidence_recall_hits": 0,
            "critical_evidence_recall_total": 0,
            "coarse_action_step_coverage": None,
            "coarse_action_step_coverage_hits": 0,
            "coarse_action_step_coverage_total": 0,
            "hallucinated_claim_count": 0,
            "unsupported_evidence_count": 0,
            "contradicted_evidence_count": 0,
            "nearby_action_fp_count": 0,
            "behavior_element_diagnostics": {
                kind: {"recall_hits": 0, "recall_total": 0, "precision_hits": 0, "precision_total": 0}
                for kind in sorted(ACTION_REQUIRED_ITEM_KINDS)
            },
        },
    }


def build_prompt(gold: dict[str, Any], candidate: dict[str, Any], chains: list[dict[str, Any]]) -> str:
    required_items = gold_required_items(chains)
    maxima = gold_maxima(chains)
    compact_gold = {
        "evaluation_unit": gold.get("evaluation_unit") or "action_claim_required_items",
        "case_id": gold.get("case_id") or gold.get("composite_id"),
        "gold_step_count": maxima["gold_step_count"],
        "gold_required_item_count": maxima["gold_required_item_count"],
        "gold_action_required_item_count": maxima["gold_action_required_item_count"],
        "gold_order_pair_count": maxima["gold_order_pair_count"],
        "gold_required_items": required_items,
        "critical_evidence_policy": gold.get("critical_evidence_policy") or gold.get("gold_policy_note"),
        "chains": chains,
    }
    schema = {
        "case_id": "string",
        "judge_summary_ja": "string",
        "chains": [
            {
                "chain_id": "string",
                "gold_required_item_scores": [
                    {
                        "item_id": "string",
                        "step_id": "string",
                        "kind": "subject|operation|object|command_line|critical_evidence",
                        "matched_candidate_excerpt": "string|null",
                        "score": "0|1",
                        "reason_ja": "string",
                    }
                ],
                "candidate_action_claim_scores": [
                    {
                        "candidate_claim_id": "string",
                        "candidate_step_id": "string|null",
                        "claim_excerpt": "string",
                        "normalized_action_claim_ja": "string",
                        "slot_scores": [
                            {
                                "slot_id": "string",
                                "kind": "subject|operation|object|command_line|critical_evidence",
                                "candidate_slot_excerpt": "string",
                                "matched_gold_item_id": "string|null",
                                "is_true_positive": "0|1",
                                "false_positive_type": "nearby_unrelated|hallucinated_value|alert_name_as_behavior|unsupported_negative|unsupported_inference|unsupported_evidence|contradicted_evidence|duplicate_claim|none",
                                "reason_ja": "string",
                            }
                        ],
                    }
                ],
                "order_pairs": [
                    {
                        "before_step_id": "string",
                        "after_step_id": "string",
                        "score": "0|1",
                        "reason_ja": "string",
                    }
                ],
            }
        ],
        "error_flags": {
            "target_missing": ["item_id"],
            "chain_mixing": "boolean",
            "hallucinated_claims": ["string"],
            "unsupported_evidence": ["string"],
            "contradicted_evidence": ["string"],
            "nearby_action_false_positives": ["string"],
            "weak_grounding": "boolean",
            "false_positive_claims": ["string"],
            "notes_ja": ["string"],
        },
        "candidate_action_claim_count": "integer",
        "candidate_action_claim_slot_count": "integer",
        "candidate_action_claim_true_positive_slot_count": "integer",
        "hallucinated_claim_count": "integer",
        "unsupported_evidence_count": "integer",
        "contradicted_evidence_count": "integer",
        "nearby_action_fp_count": "integer",
        "main_missing_items": ["string"],
        "main_false_positive_claims": ["string"],
    }
    return f"""You are a strict evaluator for Windows endpoint behavior-chain reconstruction.

Score CANDIDATE_OUTPUT against GOLD using action-claim metrics.

Core definitions:
- An action_claim is the smallest behavior assertion where one subject performs one operation against one object.
- A candidate code_step may contain multiple action_claims. Split it when it contains multiple subjects, operations, objects, command lines, or unrelated behaviors.
- The candidate's surface output is code_steps/code_sequence. The scoring unit is the action_claim you extract from those outputs.
- Each action_claim can have at most these scoring slots: subject, operation, object, command_line, critical_evidence.
- command_line is an attribute of the relevant action_claim. It is not an independent behavior step.
- critical_evidence is one slot per action_claim. If the candidate lists many evidence rows for the same claim, select the best support and score only one critical_evidence slot. Do not increase the denominator because evidence is verbose.

Primary metrics:
- behavior_step_recall: step-level recall over GOLD.gold_step_count. A gold step is covered when at least one required item from that step is recovered.
- action_step_recall: for every non-evidence GOLD.gold_required_items item (subject/operation/object/command_line), score 1 if the candidate reconstructs the same substantive value, otherwise 0.
- action_step_precision: score gold-aligned correctness on the same dynamic non-evidence required-item denominator as recall. The numerator is the number of unique true-positive candidate subject/operation/object/command_line slots that match gold required items.
- critical_evidence_recall: score critical_evidence separately. It is not part of the action_step_recall or action_step_precision denominator.
- candidate_claim_precision is a diagnostic: for every non-null candidate action_claim slot you list, mark it as true positive or false positive against gold. This diagnostic keeps the candidate-side denominator.
- behavior_sequence_order: score each gold order pair as 1 only when the related action claims are recovered and their relative order is correct.

Extraction and denominator rules:
- Action recall denominator is the number of non-critical-evidence GOLD.gold_required_items in the GOLD block. In this run it is {maxima["gold_action_required_item_count"]}.
- Main action precision denominator is the same non-critical-evidence required-item count. In this run it is {maxima["gold_action_required_item_count"]}.
- Step-level behavior_step_recall / coarse action-step coverage denominator is GOLD.gold_step_count. In this run it is {maxima["gold_step_count"]}.
- Behavior order denominator is GOLD.gold_order_pair_count. In this run it is {maxima["gold_order_pair_count"]}.
- Candidate-side overclaiming is not folded into the main precision denominator. It is reported by candidate_claim_precision and overclaim_slot_count.
- Do not list null, unknown, not observed, absent, or explicitly uncertain placeholder values as candidate slots.
- If a candidate says an observed gold value does not exist, or makes a negative claim that contradicts observed evidence, list that negative claim as a false positive slot.
- If the candidate mixes in a nearby unrelated behavior, split that nearby behavior into its own action_claims and score their slots as false positives unless they match gold.
- Duplicate true-positive slots may match the same gold item only once for the numerator. Repeated duplicate claims do not increase the main precision denominator; they remain in the candidate_claim_precision denominator and overclaim diagnostics.
- Do not score precision at the sentence, paragraph, major-claim, or coarse-step level.

Evidence policy:
- Gold uses critical_evidence, not arbitrary evidence count.
- Candidate evidence verbosity must not expand recall or precision denominators.
- CBC alert report_name/reason is evidence only.
- If GOLD critical_evidence_policy excludes CBC alerts or the gold evaluation unit contains "non_alert", then CBC alert report_name, reason, alert_name, alert_id, and watchlist.hit rows are not valid true-positive critical_evidence.
- If an alert name such as "Discovery - Query Registry" or "Persistence - Regmod Run or Runonce Key Modification" is emitted as the behavior operation, mark that operation slot as false positive with false_positive_type=alert_name_as_behavior.
- Fabricated concrete PID, event_id, alert_id, path, command line, process relation, registry path, or timestamp must reduce precision and be listed in hallucinated_claims.
- A real-but-noncritical extra evidence citation for an otherwise correct action_claim should not create additional denominator slots; unsupported or contradicted evidence should be counted in unsupported_evidence or contradicted_evidence diagnostics.

Scoring style:
- Give 0 for missing, ambiguous, partially wrong, unrelated-chain, or unsupported values. Do not use 0.5.
- Return JSON only. All scores must be integer 0 or 1.
- Use Japanese for reasons and summaries. Preserve raw paths, command lines, alert IDs, source_stream values, and timestamps exactly.

Expected JSON schema:
{json.dumps(schema, ensure_ascii=False, indent=2)}

GOLD:
{json.dumps(compact_gold, ensure_ascii=False, indent=2)}

CANDIDATE_OUTPUT:
{json.dumps(candidate, ensure_ascii=False, indent=2)}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", required=True, type=Path)
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--provider", choices=["openai", "anthropic"], default=None)
    parser.add_argument("--reasoning-effort", default="medium")
    parser.add_argument("--max-output-tokens", type=int, default=None)
    parser.add_argument("--stage", choices=["stage1", "stage2", "stage3"], default=None)
    parser.add_argument("--validation-steps", type=Path, default=None)
    args = parser.parse_args()

    env = load_env(ENV_PATH)
    model = select_judge_model(args, env)
    provider = infer_judge_provider(model, env, args.provider)

    gold = read_json(args.gold)
    chains = normalize_gold(gold, args.gold)
    chains = filter_chains_for_stage(chains, args.stage, args.validation_steps)
    candidate = candidate_output_from_run(args.run_json)
    case_id = gold.get("case_id") or gold.get("composite_id") or candidate.get("instance_id") or "unknown"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.out_dir or DEFAULT_OUT / f"{stamp}_{case_id}_{model}"
    writable_path(out_dir).mkdir(parents=True, exist_ok=True)

    maxima = gold_maxima(chains)
    if not chains or not maxima["gold_step_count"] or not maxima["gold_action_required_item_count"]:
        score = zero_denominator_score("no_evaluable_gold_steps")
        result = {
            "score_run_id": f"{stamp}_{case_id}_{model}_action_claim_metrics_score",
            "provider": provider,
            "model": model,
            "reasoning_effort": args.reasoning_effort,
            "gold_file": str(args.gold),
            "gold_required_items": gold_required_items(chains),
            "candidate_run_json": str(args.run_json),
            "score": score,
            "response_id": None,
            "usage": None,
        }
        write_json(out_dir / "score_result.json", result)
        write_summary_csv(out_dir / "score_summary.csv", result, candidate)
        print(out_dir)
        print(json.dumps(score["totals"], ensure_ascii=False, indent=2))
        return

    api_key = api_key_for_provider(provider, env)
    if not api_key:
        expected = "ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY"
        raise RuntimeError(f"{expected} is empty")
    prompt = build_prompt(gold, candidate, chains)
    write_text(out_dir / "judge_prompt.txt", prompt)

    output_text, response_id, usage = call_judge_model(
        provider,
        model,
        api_key,
        prompt,
        args.reasoning_effort,
        args.max_output_tokens,
    )
    write_text(out_dir / "judge_raw_output.txt", output_text)
    try:
        score = extract_json(output_text)
        score = recompute_totals(score, gold_maxima(chains))
    except Exception as exc:
        score = {"parse_error": str(exc), "raw_output_text": output_text}

    result = {
        "score_run_id": f"{stamp}_{case_id}_{model}_action_claim_metrics_score",
        "provider": provider,
        "model": model,
        "reasoning_effort": args.reasoning_effort,
        "gold_file": str(args.gold),
        "gold_required_items": gold_required_items(chains),
        "candidate_run_json": str(args.run_json),
        "score": score,
        "response_id": response_id,
        "usage": usage,
    }
    write_json(out_dir / "score_result.json", result)
    write_summary_csv(out_dir / "score_summary.csv", result, candidate)
    print(out_dir)
    print(json.dumps(score.get("totals", score), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
