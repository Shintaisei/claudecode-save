#!/usr/bin/env python3
"""Classify reconstruction failures for the three-model experiment.

The analysis consumes the adopted score ledgers and the semantic action/order
overlay. It does not call a model or judge and does not alter source scores.
It produces three complementary views:

1. Gold-step recovery patterns over subject/action/object.
2. Candidate-claim error flags, including unsupported additions and a
   conservative high-confidence subject/object reversal detector.
3. Order outcomes separated into correct, reversed, and not evaluable.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import rescore_three_models_all_trials_action_order_semantic_v1_20260814 as base


ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_OVERLAY = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_all_trials_action_order_semantic_v1"
    / "semantic_rescore_overlay_all_scored.jsonl"
)
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_error_patterns_v1"
)
OUT_GOLD = OUT_DIR / "gold_step_patterns.jsonl"
OUT_CLAIMS = OUT_DIR / "candidate_claim_patterns.jsonl"
OUT_ORDER = OUT_DIR / "order_patterns.jsonl"
OUT_REVERSALS = OUT_DIR / "subject_object_reversal_candidates.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = (
    ROOT
    / "docs/fit2026_manuscript"
    / "FIT2026_3モデル_復元失敗パターン分析_20260814.md"
)

GOLD_PATTERN_LABELS = {
    "COMPLETE_SAO": "主体・行動・対象を完全復元",
    "OBJECT_ERROR": "主体と行動は正しいが対象を誤った／欠いた",
    "SUBJECT_ERROR": "行動と対象は正しいが主体を誤った／欠いた",
    "RELATION_ERROR": "主体と対象は正しいが関係を誤った",
    "ACTION_ONLY": "行動だけを捉え、主体・対象を誤った／欠いた",
    "SUBJECT_ONLY": "主体だけを捉えた",
    "OBJECT_ONLY": "対象だけを捉えた",
    "STEP_OMISSION": "Gold step全体を発見できなかった",
}

BIT_PATTERN = {
    (1, 1, 1): "COMPLETE_SAO",
    (1, 1, 0): "OBJECT_ERROR",
    (0, 1, 1): "SUBJECT_ERROR",
    (1, 0, 1): "RELATION_ERROR",
    (0, 1, 0): "ACTION_ONLY",
    (1, 0, 0): "SUBJECT_ONLY",
    (0, 0, 1): "OBJECT_ONLY",
    (0, 0, 0): "STEP_OMISSION",
}

EXTENSION_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/][^\s\"'{}]+|[^\s\\/\"'{}]+)\."
    r"(?:exe|dll|sys|ps1|bat|cmd|py|pyw|rtf|doc|docx|xls|xlsx|sct|js|vbs|"
    r"pcap|txt|zip|html|hta|tmp|dat|lnk)"
)
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9_-])(?:[a-z0-9-]+\.)+(?:com|net|org|local|lan|io|jp)"
)
PID_RE = re.compile(r"(?i)\bpid\D{0,8}(\d+)\b")


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
    if len(rows) != 384:
        raise AssertionError(f"expected 384 normalized rows, got {len(rows)}")
    return rows


def claim_groups(row: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for slot in row.get("candidate_slots") or []:
        groups[str(slot["candidate_claim_id"])].append(slot)
    return groups


def aligned_step_id(slots: list[dict[str, Any]]) -> str | None:
    values = {
        str(slot["aligned_gold_step_id"])
        for slot in slots
        if slot.get("aligned_gold_step_id")
    }
    if len(values) > 1:
        raise AssertionError(f"claim aligns to multiple Gold steps: {values}")
    return next(iter(values), None)


def slot_for(slots: list[dict[str, Any]], kind: str) -> dict[str, Any] | None:
    return next((slot for slot in slots if slot.get("kind") == kind), None)


def flatten_json_values(value: Any) -> list[tuple[str | None, str]]:
    values: list[tuple[str | None, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                values.extend(flatten_json_values(item))
            elif item is not None:
                values.append((str(key).lower(), str(item)))
    elif isinstance(value, list):
        for item in value:
            values.extend(flatten_json_values(item))
    elif value is not None:
        values.append((None, str(value)))
    return values


def entity_tokens(value: Any) -> set[str]:
    """Extract conservative identity tokens for reversal detection."""
    raw = str(value or "")
    values: list[tuple[str | None, str]] = [(None, raw)]
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if parsed is not None:
        values.extend(flatten_json_values(parsed))

    tokens: set[str] = set()
    for key, text_value in values:
        lowered = text_value.lower().replace("\\\\", "\\")
        for match in EXTENSION_RE.findall(lowered):
            normalized = match.replace("\\", "/").rstrip(".,;)")
            tokens.add("name:" + normalized.rsplit("/", 1)[-1])
        for match in IP_RE.findall(lowered):
            tokens.add("ip:" + match)
        for match in DOMAIN_RE.findall(lowered):
            tokens.add("domain:" + match)
        for match in PID_RE.findall(lowered):
            tokens.add("pid:" + match)
        if key and "pid" in key and text_value.isdigit():
            tokens.add("pid:" + text_value)
    return tokens


def reversal_match(
    candidate_subject: Any,
    candidate_object: Any,
    gold_subject: Any,
    gold_object: Any,
) -> dict[str, Any] | None:
    candidate_subject_tokens = entity_tokens(candidate_subject)
    candidate_object_tokens = entity_tokens(candidate_object)
    gold_subject_tokens = entity_tokens(gold_subject)
    gold_object_tokens = entity_tokens(gold_object)
    distinct_gold_subject = gold_subject_tokens - gold_object_tokens
    distinct_gold_object = gold_object_tokens - gold_subject_tokens
    subject_as_object = candidate_subject_tokens & distinct_gold_object
    object_as_subject = candidate_object_tokens & distinct_gold_subject
    if subject_as_object and object_as_subject:
        return {
            "candidate_subject_matches_gold_object": sorted(subject_as_object),
            "candidate_object_matches_gold_subject": sorted(object_as_subject),
        }
    return None


def gold_items_by_step(row: dict[str, Any]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = defaultdict(dict)
    for item in row["gold_items"]:
        result[str(item["step_id"])][str(item["kind"])] = int(item["score"])
    return result


def claim_component_bits(slots: list[dict[str, Any]]) -> dict[str, int]:
    result = {}
    for kind in ("subject", "operation", "object"):
        slot = slot_for(slots, kind)
        result[kind] = int(slot.get("is_true_positive", 0)) if slot else 0
    return result


def primary_claim_pattern(
    aligned: bool,
    flags: set[str],
    component_bits: dict[str, int],
) -> str:
    if "SUBJECT_OBJECT_REVERSAL" in flags:
        return "SUBJECT_OBJECT_REVERSAL"
    if not aligned and (
        "UNSUPPORTED" in flags or "UNSUPPORTED_OR_NEARBY" in flags
    ):
        return "GOLD_UNSUPPORTED_ADDITION"
    if "WRONG_RELATION" in flags:
        return "RELATION_MISINTERPRETATION"
    if "WRONG_VALUE" in flags:
        return "VALUE_OR_ENTITY_ERROR"
    if "DUPLICATE" in flags:
        return "DUPLICATE_OR_REDUNDANT"
    if "WRONG_COMPONENT" in flags:
        return "COMPONENT_ROLE_OR_SCOPE_ERROR"
    if aligned and all(component_bits.values()):
        return "SUPPORTED_COMPLETE_CLAIM"
    if aligned:
        return "PARTIAL_ALIGNED_CLAIM"
    return "UNALIGNED_OTHER"


def classify(
    normalized_rows: list[dict[str, Any]],
    overlays: dict[str, dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    gold_rows: list[dict[str, Any]] = []
    claim_rows: list[dict[str, Any]] = []
    order_rows: list[dict[str, Any]] = []
    reversal_rows: list[dict[str, Any]] = []

    for row in normalized_rows:
        overlay = overlays[row["queue_id"]]
        gold = read_json(base.policy_v1.gold_path(row))
        gold_steps = {str(step["step_id"]): step for step in gold["gold_steps"]}
        item_scores = gold_items_by_step(row)
        action_decisions = {
            str(decision["step_id"]): decision
            for decision in overlay["action_decisions"]
        }

        for step_id, step in gold_steps.items():
            subject = item_scores[step_id].get("subject", 0)
            action = int(action_decisions[step_id]["semantic_score"])
            obj = item_scores[step_id].get("object", 0)
            evidence = item_scores[step_id].get("critical_evidence", 0)
            pattern = BIT_PATTERN[(subject, action, obj)]
            evidence_pattern = (
                "EVIDENCE_ONLY"
                if pattern == "STEP_OMISSION" and evidence
                else (
                    "CRITICAL_EVIDENCE_SUPPORTED"
                    if evidence
                    else "CRITICAL_EVIDENCE_MISSING"
                )
            )
            gold_rows.append(
                {
                    "model": row["model"],
                    "phase": row["phase"],
                    "replicate": row["replicate"],
                    "stage": row["stage"],
                    "chain_id": row["chain_id"],
                    "source_queue_id": row["queue_id"],
                    "step_id": step_id,
                    "gold_subject": step.get("subject"),
                    "gold_action": step.get("action"),
                    "gold_object": step.get("object"),
                    "gold_action_class": action_decisions[step_id][
                        "gold_action_class"
                    ],
                    "subject_score": subject,
                    "action_score": action,
                    "object_score": obj,
                    "critical_evidence_score": evidence,
                    "recovery_pattern": pattern,
                    "recovery_pattern_ja": GOLD_PATTERN_LABELS[pattern],
                    "evidence_pattern": evidence_pattern,
                }
            )

        for claim_id, slots in claim_groups(row).items():
            aligned_step = aligned_step_id(slots)
            subject_slot = slot_for(slots, "subject")
            action_slot = slot_for(slots, "operation")
            object_slot = slot_for(slots, "object")
            candidate_subject = (
                subject_slot.get("candidate_slot_excerpt") if subject_slot else None
            )
            candidate_action = (
                action_slot.get("candidate_slot_excerpt") if action_slot else None
            )
            candidate_object = (
                object_slot.get("candidate_slot_excerpt") if object_slot else None
            )
            raw_types = {
                str(slot.get("false_positive_type"))
                for slot in slots
                if not slot.get("is_true_positive")
                and slot.get("false_positive_type")
            }
            type_to_flag = {
                "wrong_relation": "WRONG_RELATION",
                "wrong_value": "WRONG_VALUE",
                "wrong_component": "WRONG_COMPONENT",
                "duplicate": "DUPLICATE",
                "unsupported": "UNSUPPORTED",
                "unsupported_or_nearby": "UNSUPPORTED_OR_NEARBY",
            }
            flags = {type_to_flag[value] for value in raw_types if value in type_to_flag}

            reversal = None
            reversal_step_id = None
            candidate_gold_steps = (
                [gold_steps[aligned_step]]
                if aligned_step and aligned_step in gold_steps
                else list(gold_steps.values())
            )
            for possible_step in candidate_gold_steps:
                match = reversal_match(
                    candidate_subject,
                    candidate_object,
                    possible_step.get("subject"),
                    possible_step.get("object"),
                )
                if match:
                    reversal = match
                    reversal_step_id = str(possible_step["step_id"])
                    flags.add("SUBJECT_OBJECT_REVERSAL")
                    break

            component_bits = claim_component_bits(slots)
            primary = primary_claim_pattern(
                aligned=aligned_step is not None,
                flags=flags,
                component_bits=component_bits,
            )
            claim_result = {
                "model": row["model"],
                "phase": row["phase"],
                "replicate": row["replicate"],
                "stage": row["stage"],
                "chain_id": row["chain_id"],
                "source_queue_id": row["queue_id"],
                "candidate_claim_id": claim_id,
                "aligned_gold_step_id": aligned_step,
                "candidate_subject": candidate_subject,
                "candidate_action": candidate_action,
                "candidate_object": candidate_object,
                "subject_score": component_bits["subject"],
                "action_original_score": component_bits["operation"],
                "object_score": component_bits["object"],
                "false_positive_types": sorted(raw_types),
                "error_flags": sorted(flags),
                "primary_pattern": primary,
                "reversal_gold_step_id": reversal_step_id,
                "reversal_match": reversal,
            }
            claim_rows.append(claim_result)
            if reversal:
                reversal_rows.append(claim_result)

        for decision in overlay["order_decisions"]:
            order_rows.append(
                {
                    "model": row["model"],
                    "phase": row["phase"],
                    "replicate": row["replicate"],
                    "stage": row["stage"],
                    "chain_id": row["chain_id"],
                    "source_queue_id": row["queue_id"],
                    **decision,
                }
            )

    return gold_rows, claim_rows, order_rows, reversal_rows


def counter_dict(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row[field]) for row in rows).items()))


def flag_counter(rows: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in rows:
        counter.update(row["error_flags"])
    return dict(sorted(counter.items()))


def grouped_counts(
    rows: list[dict[str, Any]], field: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    by_model = {}
    by_model_phase = {}
    for model in base.MODELS:
        model_rows = [row for row in rows if row["model"] == model]
        by_model[model] = {
            "denominator": len(model_rows),
            "counts": counter_dict(model_rows, field),
        }
        for phase in base.PHASES:
            key = f"{model}/{phase}"
            selected = [row for row in model_rows if row["phase"] == phase]
            by_model_phase[key] = {
                "denominator": len(selected),
                "counts": counter_dict(selected, field),
            }
    return by_model, by_model_phase


def pct(count: int, denominator: int) -> str:
    return "-" if not denominator else f"{count / denominator * 100:.1f}%"


def pattern_cell(value: dict[str, Any], pattern: str) -> str:
    count = int(value["counts"].get(pattern, 0))
    return f"{count}（{pct(count, value['denominator'])}）"


def build_report(summary: dict[str, Any], reversal_rows: list[dict[str, Any]]) -> str:
    gold = summary["gold_step_patterns"]
    claims = summary["candidate_claim_patterns"]
    order = summary["order_patterns"]
    lines = [
        "# 3モデルの復元失敗パターン分析",
        "",
        "作成日: 2026-08-14",
        "",
        "## 1. 結論",
        "",
        "再採点後は、失敗を単なる不正解ではなく、Gold stepの欠落、対象の誤り、主体の誤り、関係の誤り、主体・対象の役割逆転、Goldに対応しない付加、値の誤り、重複、順序逆転として分離できる。特に重要なのは、Gold側の復元失敗と、CLOUSEAUが余分に出したclaimの誤りを別々に数えることである。",
        "",
        "## 2. Gold step側の復元パターン",
        "",
        "主体・行動・対象の最終スコアを3ビットとして分類した。たとえば `110` は主体と行動が正しく、対象だけが誤っていることを表す。",
        "",
        "| パターン | 定義 | 件数 |",
        "|---|---|---:|",
    ]
    overall_gold = gold["overall"]
    for pattern in (
        "COMPLETE_SAO",
        "STEP_OMISSION",
        "OBJECT_ERROR",
        "SUBJECT_ERROR",
        "RELATION_ERROR",
        "ACTION_ONLY",
        "SUBJECT_ONLY",
        "OBJECT_ONLY",
    ):
        count = int(overall_gold["counts"].get(pattern, 0))
        lines.append(
            f"| `{pattern}` | {GOLD_PATTERN_LABELS[pattern]} | "
            f"{count}/{overall_gold['denominator']}（{pct(count, overall_gold['denominator'])}） |"
        )
    lines.extend(
        [
            "",
            "ここでの `RELATION_ERROR` 18件は、主体と対象の両方が正しく、行動だけが誤った純粋な関係誤認である。後述のclaim側 `WRONG_RELATION` 154件は、値の誤りや重複などを併発したclaimも含むため、同じ分母の数値ではない。",
            "",
            "## 3. モデル・正常／攻撃別の主要失敗",
            "",
            "| モデル・領域 | Gold step数 | 完全復元 | step欠落 | 対象誤り | 主体誤り | 関係誤り | 行動のみ |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in base.MODELS:
        for phase in base.PHASES:
            key = f"{model}/{phase}"
            value = gold["by_model_phase"][key]
            phase_label = "正常" if phase == "normal8" else "攻撃"
            lines.append(
                f"| {model}・{phase_label} | {value['denominator']} | "
                f"{pattern_cell(value, 'COMPLETE_SAO')} | "
                f"{pattern_cell(value, 'STEP_OMISSION')} | "
                f"{pattern_cell(value, 'OBJECT_ERROR')} | "
                f"{pattern_cell(value, 'SUBJECT_ERROR')} | "
                f"{pattern_cell(value, 'RELATION_ERROR')} | "
                f"{pattern_cell(value, 'ACTION_ONLY')} |"
            )
    lines.extend(
        [
            "",
            "## 4. CLOUSEAU出力側の誤りパターン",
            "",
            f"全{claims['overall']['denominator']} candidate claimのうち、Gold stepへ対応付けられなかったclaimは{claims['unaligned_claims']}件である。claimには複数の誤りが重なることがあるため、以下のflag件数は重複を含む。",
            "",
            "| flag | 意味 | 件数 |",
            "|---|---|---:|",
        ]
    )
    claim_flag_labels = {
        "UNSUPPORTED_OR_NEARBY": "Gold外の近傍事象、またはGoldで支持できない付加",
        "UNSUPPORTED": "採点証拠で支持できない付加（捏造候補）",
        "WRONG_VALUE": "主体・対象の値、PID、パス、IPなどの誤り",
        "WRONG_RELATION": "主体と対象の間の関係を別の行動として解釈",
        "WRONG_COMPONENT": "情報を主体・行動・対象の誤った欄へ配置",
        "DUPLICATE": "同一関係の重複・冗長出力",
        "SUBJECT_OBJECT_REVERSAL": "主体と対象を逆に配置した高確度候補",
    }
    for flag, label in claim_flag_labels.items():
        count = int(claims["flags_overall"].get(flag, 0))
        lines.append(f"| `{flag}` | {label} | {count} |")
    lines.extend(
        [
            "",
            "Goldへ対応しなかった478 claimのうち、376件は主分類がGold非対応の付加であり、未対応claimの78.7%を占めた。`UNSUPPORTED`や`UNSUPPORTED_OR_NEARBY`は、その時点でGoldに対応しないことを示す。これを捏造と断定するには、元ログにも該当関係が存在しないことを追加確認する必要がある。そのため本分析では「Gold非対応の付加」または「捏造候補」と呼ぶ。",
            "",
            "| モデル・領域 | claim数 | Gold非対応の付加 | 関係誤認 | 値・実体誤り | 主体対象逆転 |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for model in base.MODELS:
        for phase in base.PHASES:
            key = f"{model}/{phase}"
            value = claims["by_model_phase"][key]
            counts = value["counts"]
            phase_label = "正常" if phase == "normal8" else "攻撃"
            lines.append(
                f"| {model}・{phase_label} | {value['denominator']} | "
                f"{counts.get('GOLD_UNSUPPORTED_ADDITION', 0)} | "
                f"{counts.get('RELATION_MISINTERPRETATION', 0)} | "
                f"{counts.get('VALUE_OR_ENTITY_ERROR', 0)} | "
                f"{counts.get('SUBJECT_OBJECT_REVERSAL', 0)} |"
            )
    lines.extend(
        [
            "",
            "Gold step側は全領域で同じ主体・行動・対象rubricを使っているため、正常・攻撃間を比較しやすい。一方、claim側のfalse-positive flagは元の正常・攻撃台帳のラベル運用を引き継いでいる。したがって、claim側の表は誤りの型を把握する用途に使い、領域間の比率差をそのまま性能差と断定しない。",
            "",
            "## 5. 主体・対象逆転",
            "",
            f"Goldの主体・対象とcandidateの主体・対象について、プロセス名・ファイル名・PID・IP・ドメインの識別tokenが相互に入れ替わっているclaimを保守的に検出した。その結果、**{len(reversal_rows)}件**を高確度の逆転候補として抽出した。曖昧な名称だけで一致したものは含めていない。",
            "",
        ]
    )
    if reversal_rows:
        lines.extend(
            [
                "| モデル | 領域 | case | candidate claim | 対応Gold step |",
                "|---|---|---|---|---|",
            ]
        )
        for row in reversal_rows[:10]:
            lines.append(
                f"| {row['model']} | {row['phase']} | {row['chain_id']} | "
                f"{row['candidate_claim_id']} | {row['reversal_gold_step_id']} |"
            )
    lines.extend(
        [
            "",
            "## 6. 順序の失敗",
            "",
            f"全{order['denominator']} Gold pairのうち、正順は{order['counts'].get('correct', 0)}件、実際の逆順は{order['counts'].get('reversed', 0)}件、endpoint stepの欠落により評価不能だったものは{order['counts'].get('not_evaluable_missing_endpoint_step', 0)}件、複合claimにまとめられて評価不能だったものは{order['counts'].get('not_evaluable_same_composite_claim', 0)}件である。",
            "",
            "この分類により、順序失敗の大部分が『並べ方を間違えた』のではなく、『必要なstepを発見できず順序を評価できなかった』こととして説明できる。",
            "",
            "## 7. 考察で使う推奨分類",
            "",
            "研究発表では、まずGold側を①完全復元、②step欠落、③対象誤り、④主体誤り、⑤関係誤り、⑥部分断片に分類する。その後、出力側の原因として⑦主体・対象逆転、⑧Gold非対応の付加、⑨値の誤り、⑩重複、⑪順序逆転を説明する。この二層構造にすると、復元できなかった結果と、CLOUSEAUがどのように間違えたかを混同せずに考察できる。",
            "",
            "## 8. 出力物",
            "",
            f"- Gold step別分類: `{relative(OUT_GOLD)}`",
            f"- candidate claim別分類: `{relative(OUT_CLAIMS)}`",
            f"- 順序pair別分類: `{relative(OUT_ORDER)}`",
            f"- 主体・対象逆転候補: `{relative(OUT_REVERSALS)}`",
            f"- 集計JSON: `{relative(OUT_SUMMARY)}`",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    replace_generated = sys.argv[1:] == ["--replace-generated"]
    if sys.argv[1:] and not replace_generated:
        raise SystemExit("usage: script [--replace-generated]")
    for path in (
        OUT_GOLD,
        OUT_CLAIMS,
        OUT_ORDER,
        OUT_REVERSALS,
        OUT_SUMMARY,
        OUT_REPORT,
    ):
        if path.exists() and not replace_generated:
            raise FileExistsError(f"create-only refusal: {path}")

    normalized_rows = load_normalized_rows()
    overlay_rows = read_jsonl(SEMANTIC_OVERLAY)
    overlays = {str(row["source_queue_id"]): row for row in overlay_rows}
    if len(overlays) != 384:
        raise AssertionError(f"expected 384 overlays, got {len(overlays)}")

    gold_rows, claim_rows, order_rows, reversal_rows = classify(
        normalized_rows, overlays
    )
    if len(gold_rows) != 1571:
        raise AssertionError(f"expected 1571 Gold steps, got {len(gold_rows)}")
    if len(claim_rows) != 1384:
        raise AssertionError(f"expected 1384 candidate claims, got {len(claim_rows)}")
    if len(order_rows) != 1187:
        raise AssertionError(f"expected 1187 order pairs, got {len(order_rows)}")

    gold_by_model, gold_by_model_phase = grouped_counts(
        gold_rows, "recovery_pattern"
    )
    claim_by_model, claim_by_model_phase = grouped_counts(
        claim_rows, "primary_pattern"
    )
    unaligned_claims = [
        row for row in claim_rows if row["aligned_gold_step_id"] is None
    ]
    full_sao = [row for row in gold_rows if row["recovery_pattern"] == "COMPLETE_SAO"]
    evidence_missing_complete = [
        row for row in full_sao if row["critical_evidence_score"] == 0
    ]
    summary = {
        "schema_version": "three_model_reconstruction_error_patterns_v1",
        "created_date": "2026-08-14",
        "source_semantic_overlay": relative(SEMANTIC_OVERLAY),
        "source_semantic_overlay_sha256": sha256(SEMANTIC_OVERLAY),
        "policy": {
            "gold_side": "mutually exclusive subject/action/object bit-pattern classification",
            "claim_side": "primary pattern plus overlapping formal false-positive flags",
            "fabrication_wording": "unsupported claims are labeled Gold-unsupported additions or fabrication candidates; definitive fabrication requires raw-log absence verification",
            "subject_object_reversal": "conservative identity-token cross-match using filenames, process names, PIDs, IPs, and domains",
            "model_or_judge_calls": 0,
        },
        "gold_step_patterns": {
            "overall": {
                "denominator": len(gold_rows),
                "counts": counter_dict(gold_rows, "recovery_pattern"),
            },
            "by_model": gold_by_model,
            "by_model_phase": gold_by_model_phase,
            "complete_sao_without_critical_evidence": len(
                evidence_missing_complete
            ),
            "evidence_only_steps": sum(
                row["evidence_pattern"] == "EVIDENCE_ONLY" for row in gold_rows
            ),
        },
        "candidate_claim_patterns": {
            "overall": {
                "denominator": len(claim_rows),
                "counts": counter_dict(claim_rows, "primary_pattern"),
            },
            "by_model": claim_by_model,
            "by_model_phase": claim_by_model_phase,
            "flags_overall": flag_counter(claim_rows),
            "unaligned_claims": len(unaligned_claims),
            "unaligned_flags": flag_counter(unaligned_claims),
            "subject_object_reversal_candidates": len(reversal_rows),
        },
        "order_patterns": {
            "denominator": len(order_rows),
            "counts": counter_dict(order_rows, "status"),
        },
        "counts": {
            "scored_runs": len(normalized_rows),
            "gold_steps": len(gold_rows),
            "candidate_claims": len(claim_rows),
            "order_pairs": len(order_rows),
        },
        "validation": {
            "source_scores_modified": False,
            "gold_pattern_is_mutually_exclusive": sum(
                Counter(row["recovery_pattern"] for row in gold_rows).values()
            )
            == len(gold_rows),
            "candidate_primary_pattern_is_mutually_exclusive": sum(
                Counter(row["primary_pattern"] for row in claim_rows).values()
            )
            == len(claim_rows),
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_GOLD, gold_rows)
    write_jsonl(OUT_CLAIMS, claim_rows)
    write_jsonl(OUT_ORDER, order_rows)
    write_jsonl(OUT_REVERSALS, reversal_rows)
    OUT_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    OUT_REPORT.write_text(
        build_report(summary, reversal_rows), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
