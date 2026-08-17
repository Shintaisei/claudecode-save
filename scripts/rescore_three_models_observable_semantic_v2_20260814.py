#!/usr/bin/env python3
"""Observable-semantic re-score of every existing formally scored trial.

This script is intentionally non-destructive.  It loads the 384 adopted score
rows, preserves their strict decisions, and writes a second scoring layer that
credits only three documented representation/observability exceptions:

1. semantically equivalent operation labels (the reviewed v1 policy),
2. a document-input relation embedded in an emitted process command line, and
3. endpoint fields that were present in CBC but dropped by the audit adapter.

The launcher/interpreter distinction in normal chain 11 is reported as a
separate sensitivity result.  It is *not* included in the adopted score.
Relationship reversals, unsupported entities, and fabricated relations remain
wrong.  No model or judge API is called.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import rescore_three_models_all_trials_action_order_semantic_v1_20260814 as v1


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_observable_semantic_v2"
)
OUT_ROWS = OUT_DIR / "observable_rescore_all_384.jsonl"
OUT_CHANGES = OUT_DIR / "score_changes.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = OUT_DIR / "slide_tables.md"
OUT_HEADLINE_CSV = OUT_DIR / "headline_three_model.csv"
OUT_STAGE_CSV = OUT_DIR / "gpt55_normal_attack_stage.csv"
OUT_USECASE_CSV = OUT_DIR / "gpt55_usecase.csv"
OUT_STAGE2_REPORT = OUT_DIR / "gpt55_stage2_first_report.md"
OUT_FAILURE_CSV = OUT_DIR / "failure_analysis_by_model.csv"
PIPELINE_TRACE = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_pipeline_trace_errors_v1/gold_step_pipeline_trace.jsonl"
)

GPT55_REP1_NORMAL = (
    ROOT
    / "docs/current_experiment/results_2026-08-02"
    / "gpt55_normal8_attack8_three_stage_budget10_pilot_01"
    / "normal8/scores_codex_gpt56sol_v1/formal_scores.jsonl"
)
GPT55_REP1_ATTACK = (
    ROOT
    / "docs/current_experiment/results_2026-08-02"
    / "gpt55_normal8_attack8_three_stage_budget10_pilot_01"
    / "attack8_scores_codex_gpt56sol_v5_atomic_v1_20260803/per_run_scores.jsonl"
)

MODELS = v1.MODELS
PHASES = v1.PHASES
STAGES = v1.STAGES


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def normalized_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in v1.SOURCE_SPECS:
        for source_row in v1.read_jsonl(spec["path"]):
            normalized = v1.normalize_row(source_row, spec)
            # The provisional 96-PASS ledger contains replicate-01 rows, but
            # its PASS selection differs from the adopted 2026-08-03 headline
            # population.  Keep only replicate-02/03 here and rehydrate the
            # authoritative replicate-01 population below.
            if normalized["model"] == "gpt-5.5" and normalized["replicate"] == "replicate_01":
                continue
            rows.append(normalized)
    for label, path, phase in (
        ("gpt55_replicate_01_normal_adopted", GPT55_REP1_NORMAL, "normal8"),
        ("gpt55_replicate_01_attack_adopted", GPT55_REP1_ATTACK, "attack8"),
    ):
        spec = {
            "label": label,
            "path": path,
            "phase": phase,
            "replicate": "replicate_01",
            "legacy_attack": False,
        }
        rows.extend(
            v1.normalize_row(source_row, spec)
            for source_row in v1.read_jsonl(path)
        )
    if len(rows) != 384:
        raise AssertionError(f"expected 384 rows, got {len(rows)}")
    counts = Counter(row["model"] for row in rows)
    expected = Counter(
        {"gpt-4.1-mini": 144, "gpt-5.4-mini": 144, "gpt-5.5": 96}
    )
    if counts != expected:
        raise AssertionError(f"unexpected model counts: {counts}")
    return rows


def component_items(row: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for item in row["gold_items"]:
        result[str(item["step_id"])][str(item["kind"])] = dict(item)
    # The adopted attack replicate-01 ledger stores decisions but omits the
    # literal Gold values.  Rehydrate those values from the hashed source Gold
    # file so all three source-ledger formats are evaluated identically.
    gold = v1.policy_v1.read_json(v1.policy_v1.gold_path(row))
    gold_steps = {str(step["step_id"]): step for step in gold["gold_steps"]}
    field_by_kind = {
        "subject": "subject",
        "operation": "action",
        "object": "object",
        "critical_evidence": "critical_evidence_signature",
    }
    for step_id, kinds in result.items():
        source = gold_steps[step_id]
        for kind, field in field_by_kind.items():
            kinds[kind].setdefault("gold_value", source.get(field))
    return dict(result)


def claim_groups(row: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return v1.policy_v1.claim_groups(row)


def claim_text(slots: list[dict[str, Any]]) -> str:
    return " ".join(
        str(slot.get("candidate_slot_excerpt") or "") for slot in slots
    ).lower()


def basename(value: Any) -> str:
    text = str(value or "").replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1].lower()


def exe_token(value: Any) -> str:
    text = str(value or "").lower()
    match = re.search(r"[a-z0-9_.-]+\.exe", text)
    return match.group(0) if match else text.split(" ", 1)[0]


def slot_position(slots: list[dict[str, Any]]) -> int:
    return v1.policy_v1.claim_order(slots)


def find_slot(
    groups: dict[str, list[dict[str, Any]]], claim_id: str, kind: str
) -> dict[str, Any] | None:
    return next(
        (slot for slot in groups.get(claim_id, []) if slot["kind"] == kind),
        None,
    )


def embedded_document_claim(
    row: dict[str, Any],
    step_items: dict[str, dict[str, Any]],
    groups: dict[str, list[dict[str, Any]]],
) -> tuple[str, int] | None:
    """Find a process claim that explicitly embeds the Gold input document.

    This is deliberately limited to Word document-input Gold steps.  Merely
    mentioning a nearby file or a process elsewhere in the run is insufficient;
    the same emitted claim must contain both WINWORD.EXE and the exact Gold
    document basename.
    """
    action = step_items.get("operation", {}).get("gold_value")
    subject = step_items.get("subject", {}).get("gold_value")
    obj = step_items.get("object", {}).get("gold_value")
    if "文書" not in str(action) or exe_token(subject) != "winword.exe":
        return None
    target = basename(obj)
    if not target:
        return None
    for claim_id, slots in sorted(groups.items(), key=lambda pair: slot_position(pair[1])):
        text = claim_text(slots)
        if "winword.exe" in text and target in text:
            return claim_id, slot_position(slots)
    return None


def adapter_endpoint_rule(chain_id: str, step_id: str) -> tuple[str, str] | None:
    """Return (rule id, required observable endpoint fragment)."""
    if chain_id.startswith("chain_05_") and step_id == "N8V3-03-S02":
        return "adapter_local_port_loss", "0.0.0.0"
    if chain_id.startswith("chain_06_") and step_id == "N8V3-04-S01":
        return "adapter_local_port_loss", "10.193.66.115:58199"
    if chain_id.startswith("chain_24_") and step_id == "N8V3-08-S04":
        return "adapter_local_port_loss", "0.0.0.0"
    return None


def candidate_for_aligned_step(
    groups: dict[str, list[dict[str, Any]]], step_id: str, fragment: str
) -> tuple[str, int] | None:
    fragment = fragment.lower()
    for claim_id, slots in sorted(groups.items(), key=lambda pair: slot_position(pair[1])):
        aligned = v1.policy_v1.aligned_step(slots)
        if aligned == step_id and fragment in claim_text(slots):
            return claim_id, slot_position(slots)
    return None


def sensitivity_launcher_interpreter(
    row: dict[str, Any], step_id: str, scores: dict[str, int]
) -> int:
    """Non-adopted sensitivity check for cmd -> python -> script role semantics."""
    if not row["chain_id"].startswith("chain_11_") or step_id != "N8V3-07-S03":
        return scores["subject"]
    if scores["action"] and scores["object"]:
        groups = claim_groups(row)
        for slots in groups.values():
            if v1.policy_v1.aligned_step(slots) != step_id:
                continue
            text = claim_text(slots)
            if "python.exe" in text and "hello.py" in text:
                return 1
    return scores["subject"]


def rescore_row(row: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    semantic, _ = v1.rescore(row)
    actions = {d["step_id"]: d for d in semantic["action_decisions"]}
    items = component_items(row)
    groups = claim_groups(row)
    positions = v1.policy_v1.step_positions(row)
    changes: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []

    original_tp_slots = {
        str(slot["slot_id"])
        for slot in row.get("candidate_slots") or []
        if int(slot.get("include_in_denominator", 0))
        and int(slot.get("is_true_positive", 0))
    }
    observable_tp_slots = set(original_tp_slots)
    candidate_den = sum(
        int(slot.get("include_in_denominator", 0))
        for slot in row.get("candidate_slots") or []
    )

    for step_id, kinds in items.items():
        strict = {
            "subject": int(kinds["subject"]["score"]),
            "action": int(kinds["operation"]["score"]),
            "object": int(kinds["object"]["score"]),
            "evidence": int(kinds["critical_evidence"]["score"]),
        }
        observable = dict(strict)
        observable["action"] = int(actions[step_id]["semantic_score"])
        applied: list[str] = []
        adopted_position = list(positions.get(step_id, []))

        # Map newly accepted semantic action to the already emitted operation
        # slot.  This can increase candidate-slot precision without changing
        # the denominator.
        if observable["action"] and not strict["action"]:
            match = actions[step_id].get("matched_candidate") or {}
            claim_id = str(match.get("candidate_claim_id") or "")
            slot = find_slot(groups, claim_id, "operation")
            if slot:
                observable_tp_slots.add(str(slot["slot_id"]))
            applied.append("canonical_action_equivalence")

        endpoint = adapter_endpoint_rule(row["chain_id"], step_id)
        if endpoint and observable["subject"] and observable["action"]:
            rule_id, fragment = endpoint
            found = candidate_for_aligned_step(groups, step_id, fragment)
            if found:
                claim_id, position = found
                observable["object"] = 1
                adopted_position.append(position)
                slot = find_slot(groups, claim_id, "object")
                if slot:
                    observable_tp_slots.add(str(slot["slot_id"]))
                applied.append(rule_id)

        embedded = embedded_document_claim(row, kinds, groups)
        if embedded:
            claim_id, position = embedded
            observable["subject"] = 1
            observable["action"] = 1
            observable["object"] = 1
            adopted_position.append(position)
            # The candidate claim is still a process-create relation; do not
            # relabel its three explicit slots as a document-input relation.
            # Recall credits the represented relation, while precision keeps
            # judging the slots actually emitted.
            applied.append("embedded_document_input_relation")

        sensitivity_subject = sensitivity_launcher_interpreter(
            row, step_id, observable
        )
        strict_complete = int(
            strict["subject"] and strict["action"] and strict["object"]
        )
        observable_complete = int(
            observable["subject"]
            and observable["action"]
            and observable["object"]
        )
        sensitivity_complete = int(
            sensitivity_subject and observable["action"] and observable["object"]
        )
        step = {
            "step_id": step_id,
            "gold_subject": kinds["subject"]["gold_value"],
            "gold_action": kinds["operation"]["gold_value"],
            "gold_object": kinds["object"]["gold_value"],
            "action_class": actions[step_id]["gold_action_class"],
            "strict": strict,
            "observable": observable,
            "strict_complete": strict_complete,
            "observable_complete": observable_complete,
            "launcher_interpreter_sensitivity_subject": sensitivity_subject,
            "launcher_interpreter_sensitivity_complete": sensitivity_complete,
            "candidate_positions": sorted(set(adopted_position)),
            "applied_rules": applied,
        }
        steps.append(step)
        if applied or strict_complete != observable_complete:
            changes.append(
                {
                    "queue_id": row["queue_id"],
                    "model": row["model"],
                    "phase": row["phase"],
                    "replicate": row["replicate"],
                    "stage": row["stage"],
                    "chain_id": row["chain_id"],
                    **step,
                }
            )

    by_step = {step["step_id"]: step for step in steps}
    order_rows = []
    for pair in row.get("order_pairs") or []:
        left, right = v1.policy_v1.pair_step_ids(pair)
        left_step, right_step = by_step[left], by_step[right]
        left_pos = left_step["candidate_positions"]
        right_pos = right_step["candidate_positions"]
        # Keep every adopted order hit.  The representation-aware layer may
        # add a hit when a newly recovered endpoint step supplies the missing
        # position, but it must never invalidate an already correct pair.
        recovered_hit = int(
            left_step["observable_complete"]
            and right_step["observable_complete"]
            and any(a < b for a in left_pos for b in right_pos)
        )
        hit = max(int(pair["score"]), recovered_hit)
        order_rows.append(
            {
                "pair_id": pair["pair_id"],
                "left_step_id": left,
                "right_step_id": right,
                "observable_score": hit,
            }
        )

    return (
        {
            "schema_version": "three_model_observable_semantic_rescore_v2",
            "queue_id": row["queue_id"],
            "model": row["model"],
            "phase": row["phase"],
            "replicate": row["replicate"],
            "stage": row["stage"],
            "chain_id": row["chain_id"],
            "instance_id": row["instance_id"],
            "source_score_file": row["_source_path"],
            "source_score_row_sha256": row["_source_row_sha256"],
            "steps": steps,
            "order_pairs": order_rows,
            "candidate_slot_denominator": candidate_den,
            "strict_candidate_slot_tp": len(original_tp_slots),
            "observable_candidate_slot_tp": len(observable_tp_slots),
            "investigation": row.get("investigation") or {},
        },
        changes,
    )


def ratio(hit: int, den: int) -> float | None:
    return hit / den if den else None


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    steps = [step for row in rows for step in row["steps"]]
    step_den = len(steps)
    element_hits = sum(
        step["observable"][kind]
        for step in steps
        for kind in ("subject", "action", "object")
    )
    element_den = step_den * 3
    complete_hits = sum(step["observable_complete"] for step in steps)
    evidence_hits = sum(step["observable"]["evidence"] for step in steps)
    order_pairs = [pair for row in rows for pair in row["order_pairs"]]
    order_hits = sum(pair["observable_score"] for pair in order_pairs)
    candidate_den = sum(row["candidate_slot_denominator"] for row in rows)
    candidate_tp = sum(row["observable_candidate_slot_tp"] for row in rows)
    strict_element_hits = sum(
        step["strict"][kind]
        for step in steps
        for kind in ("subject", "action", "object")
    )
    strict_complete_hits = sum(step["strict_complete"] for step in steps)
    sensitivity_complete_hits = sum(
        step["launcher_interpreter_sensitivity_complete"] for step in steps
    )
    costs = [
        float(row["investigation"].get("cost_usd"))
        for row in rows
        if row["investigation"].get("cost_usd") is not None
    ]
    times = [
        float(row["investigation"].get("elapsed_seconds"))
        for row in rows
        if row["investigation"].get("elapsed_seconds") is not None
    ]
    return {
        "run_count": len(rows),
        "gold_step_count": step_den,
        "action": {
            "hits": element_hits,
            "denominator": element_den,
            "rate": ratio(element_hits, element_den),
        },
        "precision": {
            "hits": candidate_tp,
            "denominator": candidate_den,
            "rate": ratio(candidate_tp, candidate_den),
        },
        "complete_step": {
            "hits": complete_hits,
            "denominator": step_den,
            "rate": ratio(complete_hits, step_den),
        },
        "evidence": {
            "hits": evidence_hits,
            "denominator": step_den,
            "rate": ratio(evidence_hits, step_den),
        },
        "order": {
            "hits": order_hits,
            "denominator": len(order_pairs),
            "rate": ratio(order_hits, len(order_pairs)),
        },
        "strict_reference": {
            "action_hits": strict_element_hits,
            "action_denominator": element_den,
            "action_rate": ratio(strict_element_hits, element_den),
            "complete_hits": strict_complete_hits,
            "complete_denominator": step_den,
            "complete_rate": ratio(strict_complete_hits, step_den),
        },
        "launcher_interpreter_sensitivity_complete": {
            "hits": sensitivity_complete_hits,
            "denominator": step_den,
            "rate": ratio(sensitivity_complete_hits, step_den),
        },
        "average_cost_usd": sum(costs) / len(rows) if len(costs) == len(rows) else None,
        "average_elapsed_seconds": sum(times) / len(rows) if len(times) == len(rows) else None,
    }


def step_key(row: dict[str, Any], step_id: str) -> tuple[str, str, str, str, str, str]:
    return (
        row["model"],
        row["phase"],
        row["replicate"],
        row["stage"],
        row["chain_id"],
        step_id,
    )


def trace_key(row: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        row["model"],
        row["phase"],
        row["replicate"],
        row["stage"],
        row["chain_id"],
        row["step_id"],
    )


def exact_port_missing(trace: dict[str, Any]) -> bool:
    """Reject an evidence match that only shares the host but not Gold port."""
    gold = str(trace.get("gold_object") or "")
    ports = re.findall(r"(?::|port\s+)(\d{2,5})", gold.lower())
    if not ports:
        return False
    tokens = []
    semantic = trace.get("semantic_evidence_match") or {}
    tokens.extend(str(x).lower() for x in semantic.get("object_match_tokens") or [])
    tokens.extend(str(x).lower() for x in trace.get("matched_evidence_identifiers") or [])
    return not any(
        f"port:{port}" in token or f":{port}" in token
        for port in ports
        for token in tokens
    )


def failure_analysis(rescored: list[dict[str, Any]]) -> dict[str, Any]:
    traces = {trace_key(row): row for row in read_jsonl(PIPELINE_TRACE)}
    labels = (
        "調査段階／調査論点の設定漏れ",
        "調査段階／証跡探索の失敗",
        "まとめ段階／調査結果の採用漏れ",
        "まとめ段階／関係整理の誤り",
    )
    status_to_label = {
        "ISSUE_NOT_RAISED_FINAL_OMISSION": labels[0],
        "ISSUE_RAISED_EVIDENCE_NOT_FOUND_FINAL_OMISSION": labels[1],
        "EVIDENCE_FOUND_NOT_REFLECTED_IN_FINAL": labels[2],
        "EVIDENCE_FOUND_FINAL_RELATION_ERROR": labels[3],
    }
    result: dict[str, Any] = {}
    for model in MODELS:
        counts = Counter()
        untraceable = 0
        port_reclassified = 0
        failed_steps = 0
        missing_trace_keys: list[str] = []
        for row in rescored:
            if row["model"] != model:
                continue
            for step in row["steps"]:
                if step["observable_complete"]:
                    continue
                failed_steps += 1
                key = step_key(row, step["step_id"])
                trace = traces.get(key)
                if trace is None:
                    untraceable += 1
                    missing_trace_keys.append("/".join(key))
                    continue
                status = str(trace["pipeline_status"])
                if (
                    status == "EVIDENCE_FOUND_NOT_REFLECTED_IN_FINAL"
                    and exact_port_missing(trace)
                ):
                    status = "ISSUE_NOT_RAISED_FINAL_OMISSION"
                    port_reclassified += 1
                label = status_to_label.get(status)
                if label:
                    counts[label] += 1
                elif status in {
                    "FINAL_PARTIAL_WITHOUT_TRACEABLE_INVESTIGATION",
                    "FINAL_CORRECT_WITHOUT_TRACEABLE_INVESTIGATION",
                }:
                    untraceable += 1
                elif status == "EVIDENCE_FOUND_REFLECTED_CORRECTLY":
                    # The observable re-score can still reject a relation that
                    # the older trace considered correct (for example, wrong
                    # role orientation).  It is a synthesis/relation error.
                    counts[labels[3]] += 1
                else:
                    raise AssertionError(f"unmapped pipeline status: {status}")
        traceable = sum(counts.values())
        result[model] = {
            "failed_gold_steps": failed_steps,
            "traceable_failure_denominator": traceable,
            "untraceable_failure_steps": untraceable,
            "port_false_match_reclassified": port_reclassified,
            "counts": {label: counts[label] for label in labels},
            "percentages": {
                label: ratio(counts[label], traceable) for label in labels
            },
            "missing_trace_keys": missing_trace_keys,
        }
    return result


def is_headline(row: dict[str, Any]) -> bool:
    """The common 46-strata subset used by the existing slide tables."""
    if row["replicate"] != "replicate_01":
        return False
    missing_gpt55 = {
        ("attack8", "stage1", "s4_pt_04_powershell_c1"),
        ("attack8", "stage3", "s4_pt_03_mshta_c1"),
    }
    return (row["phase"], row["stage"], row["chain_id"]) not in missing_gpt55


def pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.2f}%"


def duration(value: float | None) -> str:
    if value is None:
        return "-"
    seconds = int(round(value))
    return f"{seconds // 60}分{seconds % 60:02d}秒"


def metric_row(label: str, value: dict[str, Any], include_cost: bool = False) -> str:
    cells = [
        label,
        pct(value["action"]["rate"]),
        pct(value["precision"]["rate"]),
        pct(value["complete_step"]["rate"]),
        pct(value["evidence"]["rate"]),
        pct(value["order"]["rate"]),
    ]
    if include_cost:
        cost = value["average_cost_usd"]
        cells.extend(["-" if cost is None else f"${cost:.3f}", duration(value["average_elapsed_seconds"])])
    return "| " + " | ".join(cells) + " |"


def build_report(summary: dict[str, Any]) -> str:
    lines = [
        "# 全384試行 Observable-semantic再採点 v2",
        "",
        "## 採点方針",
        "",
        "主体・対象の逆転、未提示の関係、捏造は不正解のままとした。行動名は同じ観測関係を表す場合のみ意味同値とした。さらに、Wordの起動コマンドラインに入力文書が明示された場合は文書入力関係の復元として扱い、監査ログ変換で欠落したlocal portは観測可能なIP・remote endpointまで一致した場合に限って対象を正解とした。`cmd.exe`と`python.exe`の実行主体の違いは採用値へ混ぜず、感度分析として別記した。",
        "",
        "## スライド用：3モデル全体比較（共通46 strata）",
        "",
        "| モデル | Action | Precision | Complete step | Evidence | Order | 平均コスト／試行 | 平均時間／試行 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for model in MODELS:
        lines.append(metric_row(model, summary["headline_by_model"][model], True))
    lines.extend(
        [
            "",
            "## スライド用：GPT-5.5 正常／攻撃",
            "",
            "| 対象 | Action | Precision | Complete step | Evidence | Order |",
            "|---|---:|---:|---:|---:|---:|",
            metric_row("正常行動", summary["gpt55_headline_phase"]["normal8"]),
            metric_row("攻撃行動", summary["gpt55_headline_phase"]["attack8"]),
            "",
            "## スライド用：GPT-5.5 Stage別",
            "",
            "| 対象 | Stage | Action | Precision | Complete step | Evidence | Order |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for phase, phase_label in (("normal8", "正常行動"), ("attack8", "攻撃行動")):
        for stage in STAGES:
            value = summary["gpt55_headline_phase_stage"][f"{phase}/{stage}"]
            row = metric_row(stage.replace("stage", "Stage "), value)
            lines.append(row.replace("| Stage", f"| {phase_label} | Stage", 1))
    lines.extend(
        [
            "",
            "## GPT-5.5 ユースケース別（共通46 strata）",
            "",
            "| 対象 | ユースケース | 試行数 | Gold step | Action | Precision | Complete step | Evidence | Order |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for key, value in sorted(summary["gpt55_headline_usecase"].items()):
        phase, chain = key.split("/", 1)
        phase_label = "正常" if phase == "normal8" else "攻撃"
        lines.append(
            f"| {phase_label} | {chain} | {value['run_count']} | {value['gold_step_count']} | "
            f"{pct(value['action']['rate'])} | {pct(value['precision']['rate'])} | "
            f"{pct(value['complete_step']['rate'])} | {pct(value['evidence']['rate'])} | "
            f"{pct(value['order']['rate'])} |"
        )
    lines.extend(
        [
            "",
            "## GPT-5.5 Stage 2 ユースケース別（各1試行）",
            "",
            "| 対象 | ユースケース | Gold step | Action | Precision | Complete step | Evidence | Order |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for key, value in sorted(summary["gpt55_stage2_usecase"].items()):
        phase, chain = key.split("/", 1)
        phase_label = "正常" if phase == "normal8" else "攻撃"
        lines.append(
            f"| {phase_label} | {chain} | {value['gold_step_count']} | "
            f"{pct(value['action']['rate'])} | {pct(value['precision']['rate'])} | "
            f"{pct(value['complete_step']['rate'])} | {pct(value['evidence']['rate'])} | "
            f"{pct(value['order']['rate'])} |"
        )
    lines.extend(
        [
            "",
            "## 失敗分析（Observable採点後・追跡可能な失敗内）",
            "",
            "| 大分類 | 小分類 | GPT-4.1-mini | GPT-5.4-mini | GPT-5.5 |",
            "|---|---|---:|---:|---:|",
        ]
    )
    failure_labels = (
        ("調査段階", "調査論点の設定漏れ", "調査段階／調査論点の設定漏れ"),
        ("調査段階", "証跡探索の失敗", "調査段階／証跡探索の失敗"),
        ("まとめ段階", "調査結果の採用漏れ", "まとめ段階／調査結果の採用漏れ"),
        ("まとめ段階", "関係整理の誤り", "まとめ段階／関係整理の誤り"),
    )
    for major, minor, key in failure_labels:
        values = [pct(summary["failure_analysis"][model]["percentages"][key]) for model in MODELS]
        lines.append(f"| {major} | {minor} | {values[0]} | {values[1]} | {values[2]} |")
    lines.extend(
        [
            "| 合計 |  | 100.00% | 100.00% | 100.00% |",
            "",
            "## 全採点台帳の範囲",
            "",
            f"全384試行・{summary['coverage']['gold_steps']:,} Gold stepを再採点した。4.1-miniと5.4-miniは各144試行、5.5は既存の正式採点済み96試行であり、5.5の未完了48試行を0点として補完していない。スライド用のモデル比較は、従来表と同じ共通46 strataに限定した。",
            "",
            "## 感度分析",
            "",
            "正常chain 11の `cmd.exe -> hello.py` と `python.exe -> hello.py` を実行主体の同値表現とみなす場合のComplete stepは summary JSONの `launcher_interpreter_sensitivity_complete` に記録した。採用表はGoldの主体定義を維持している。",
            "",
        ]
    )
    return "\n".join(lines)


def write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    replace = sys.argv[1:] == ["--replace-generated"]
    if sys.argv[1:] and not replace:
        raise SystemExit("usage: script [--replace-generated]")
    outputs = (
        OUT_ROWS,
        OUT_CHANGES,
        OUT_SUMMARY,
        OUT_REPORT,
        OUT_HEADLINE_CSV,
        OUT_STAGE_CSV,
        OUT_USECASE_CSV,
        OUT_STAGE2_REPORT,
        OUT_FAILURE_CSV,
    )
    if not replace:
        existing = [path for path in outputs if path.exists()]
        if existing:
            raise FileExistsError(f"create-only refusal: {existing[0]}")

    source_rows = normalized_rows()
    rescored: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    for row in source_rows:
        overlay, row_changes = rescore_row(row)
        rescored.append(overlay)
        changes.extend(row_changes)
    rescored.sort(key=lambda row: (row["model"], row["phase"], row["replicate"], row["stage"], row["chain_id"]))
    changes.sort(key=lambda row: (row["model"], row["phase"], row["replicate"], row["stage"], row["chain_id"], row["step_id"]))

    # The authoritative replicate-01 GPT-5.5 population contains 182 Gold
    # steps (two more than the provisional 96-PASS selection), so the adopted
    # 384-run ledger contains 1,573 steps in total.
    if sum(len(row["steps"]) for row in rescored) != 1573:
        raise AssertionError("Gold-step count changed")
    headline = [row for row in rescored if is_headline(row)]
    headline_counts = Counter(row["model"] for row in headline)
    if headline_counts != Counter({model: 46 for model in MODELS}):
        raise AssertionError(f"headline subset mismatch: {headline_counts}")

    summary = {
        "schema_version": "three_model_observable_semantic_rescore_summary_v2",
        "created_date": "2026-08-14",
        "coverage": {
            "intended_grid": 432,
            "rescored_existing_runs": len(rescored),
            "gold_steps": sum(len(row["steps"]) for row in rescored),
            "by_model": dict(Counter(row["model"] for row in rescored)),
            "headline_common_strata_per_model": 46,
        },
        "policy": {
            "adopted_exceptions": [
                "canonical_action_equivalence_with_existing_Gold_alignment",
                "embedded_Word_document_input_same_claim_exact_document_basename",
                "adapter_local_port_loss_requires_observable_endpoint_fragment_plus_subject_and_action",
            ],
            "not_forgiven": [
                "subject_object_reversal",
                "unsupported_or_fabricated_relation",
                "nearby_but_wrong_endpoint",
                "missing_retrieved_event_caused_by_query_row_limit",
            ],
            "launcher_interpreter_role": "reported only as sensitivity; excluded from adopted metrics",
            "judge_api_calls": 0,
            "model_api_calls": 0,
        },
        "full_ledger_by_model": {
            model: aggregate([row for row in rescored if row["model"] == model])
            for model in MODELS
        },
        "headline_by_model": {
            model: aggregate([row for row in headline if row["model"] == model])
            for model in MODELS
        },
        "gpt55_headline_phase": {
            phase: aggregate(
                [row for row in headline if row["model"] == "gpt-5.5" and row["phase"] == phase]
            )
            for phase in PHASES
        },
        "gpt55_headline_phase_stage": {
            f"{phase}/{stage}": aggregate(
                [
                    row
                    for row in headline
                    if row["model"] == "gpt-5.5"
                    and row["phase"] == phase
                    and row["stage"] == stage
                ]
            )
            for phase in PHASES
            for stage in STAGES
        },
        "gpt55_headline_usecase": {
            f"{phase}/{chain}": aggregate(
                [
                    row
                    for row in headline
                    if row["model"] == "gpt-5.5"
                    and row["phase"] == phase
                    and row["chain_id"] == chain
                ]
            )
            for phase in PHASES
            for chain in sorted(
                {
                    row["chain_id"]
                    for row in headline
                    if row["model"] == "gpt-5.5" and row["phase"] == phase
                }
            )
        },
        "gpt55_stage2_usecase": {
            f"{phase}/{chain}": aggregate(
                [
                    row
                    for row in headline
                    if row["model"] == "gpt-5.5"
                    and row["phase"] == phase
                    and row["stage"] == "stage2"
                    and row["chain_id"] == chain
                ]
            )
            for phase in PHASES
            for chain in sorted(
                {
                    row["chain_id"]
                    for row in headline
                    if row["model"] == "gpt-5.5"
                    and row["phase"] == phase
                    and row["stage"] == "stage2"
                }
            )
        },
        "rule_application_counts": dict(
            Counter(rule for change in changes for rule in change["applied_rules"])
        ),
        "changed_step_records": len(changes),
    }
    # Re-scoring does not alter resource use.  The mini-model source ledgers do
    # not carry per-run cost/time fields, so retain the already reconciled
    # common-46 values used in the existing FIT table.
    summary["headline_by_model"]["gpt-4.1-mini"]["average_cost_usd"] = 10.07 / 46
    summary["headline_by_model"]["gpt-4.1-mini"]["average_elapsed_seconds"] = 650.0
    summary["headline_by_model"]["gpt-5.4-mini"]["average_cost_usd"] = 3.20 / 46
    summary["headline_by_model"]["gpt-5.4-mini"]["average_elapsed_seconds"] = 67.0
    summary["resource_provenance"] = {
        "gpt-4.1-mini": "existing reconciled common-46 total: $10.07; existing displayed average time: 10m50s",
        "gpt-5.4-mini": "existing reconciled common-46 total: $3.20; existing displayed average time: 1m07s",
        "gpt-5.5": "summed from adopted per-run investigation ledgers for the common-46 population",
    }
    summary["failure_analysis"] = failure_analysis(rescored)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_ROWS, rescored)
    write_jsonl(OUT_CHANGES, changes)
    OUT_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    OUT_REPORT.write_text(build_report(summary), encoding="utf-8")
    # A compact first-delivery file lets the Stage-2 discussion proceed while
    # the complete tables and audits remain in the same immutable directory.
    stage2_lines = [
        "# GPT-5.5 Stage 2 再採点結果",
        "",
        "| 対象 | 試行数 | Gold step | Action | Precision | Complete step | Evidence | Order |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for phase, label in (("normal8", "正常行動"), ("attack8", "攻撃行動")):
        value = summary["gpt55_headline_phase_stage"][f"{phase}/stage2"]
        stage2_lines.append(
            f"| {label} | {value['run_count']} | {value['gold_step_count']} | "
            f"{pct(value['action']['rate'])} | {pct(value['precision']['rate'])} | "
            f"{pct(value['complete_step']['rate'])} | {pct(value['evidence']['rate'])} | {pct(value['order']['rate'])} |"
        )
    stage2_lines.extend(["", "## ユースケース別", "", "| 対象 | ユースケース | Gold step | Action | Precision | Complete step | Evidence | Order |", "|---|---|---:|---:|---:|---:|---:|---:|"])
    for key, value in sorted(summary["gpt55_stage2_usecase"].items()):
        phase, chain = key.split("/", 1)
        label = "正常" if phase == "normal8" else "攻撃"
        stage2_lines.append(
            f"| {label} | {chain} | {value['gold_step_count']} | {pct(value['action']['rate'])} | "
            f"{pct(value['precision']['rate'])} | {pct(value['complete_step']['rate'])} | "
            f"{pct(value['evidence']['rate'])} | {pct(value['order']['rate'])} |"
        )
    OUT_STAGE2_REPORT.write_text("\n".join(stage2_lines) + "\n", encoding="utf-8")

    headline_csv_rows = []
    for model in MODELS:
        value = summary["headline_by_model"][model]
        headline_csv_rows.append(
            [
                model,
                value["action"]["rate"],
                value["precision"]["rate"],
                value["complete_step"]["rate"],
                value["evidence"]["rate"],
                value["order"]["rate"],
                value["average_cost_usd"],
                value["average_elapsed_seconds"],
            ]
        )
    write_csv(
        OUT_HEADLINE_CSV,
        ["model", "action", "precision", "complete_step", "evidence", "order", "average_cost_usd", "average_elapsed_seconds"],
        headline_csv_rows,
    )

    stage_csv_rows = []
    for phase in PHASES:
        for stage in STAGES:
            value = summary["gpt55_headline_phase_stage"][f"{phase}/{stage}"]
            stage_csv_rows.append(
                [phase, stage, value["run_count"], value["gold_step_count"], value["action"]["rate"], value["precision"]["rate"], value["complete_step"]["rate"], value["evidence"]["rate"], value["order"]["rate"]]
            )
    write_csv(
        OUT_STAGE_CSV,
        ["phase", "stage", "run_count", "gold_step_count", "action", "precision", "complete_step", "evidence", "order"],
        stage_csv_rows,
    )

    usecase_csv_rows = []
    for key, value in sorted(summary["gpt55_headline_usecase"].items()):
        phase, chain = key.split("/", 1)
        usecase_csv_rows.append(
            [phase, chain, value["run_count"], value["gold_step_count"], value["action"]["rate"], value["precision"]["rate"], value["complete_step"]["rate"], value["evidence"]["rate"], value["order"]["rate"]]
        )
    write_csv(
        OUT_USECASE_CSV,
        ["phase", "chain_id", "run_count", "gold_step_count", "action", "precision", "complete_step", "evidence", "order"],
        usecase_csv_rows,
    )

    failure_rows = []
    for label in (
        "調査段階／調査論点の設定漏れ",
        "調査段階／証跡探索の失敗",
        "まとめ段階／調査結果の採用漏れ",
        "まとめ段階／関係整理の誤り",
    ):
        failure_rows.append(
            [label]
            + [summary["failure_analysis"][model]["percentages"][label] for model in MODELS]
        )
    write_csv(OUT_FAILURE_CSV, ["classification", *MODELS], failure_rows)

    print(json.dumps({"coverage": summary["coverage"], "headline_by_model": summary["headline_by_model"], "rule_application_counts": summary["rule_application_counts"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
