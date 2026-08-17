#!/usr/bin/env python3
"""Separate investigation-stage and result-synthesis error patterns.

This diagnostic reuses the previously generated Gold-step and candidate-claim
classifications. It does not change any score and makes no model/judge calls.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_error_patterns_v1"
)
SOURCE_GOLD = SOURCE_DIR / "gold_step_patterns.jsonl"
SOURCE_CLAIMS = SOURCE_DIR / "candidate_claim_patterns.jsonl"
SOURCE_ORDER = SOURCE_DIR / "order_patterns.jsonl"
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_investigation_vs_synthesis_v1"
)
OUT_GOLD = OUT_DIR / "gold_step_stage_errors.jsonl"
OUT_CLAIMS = OUT_DIR / "candidate_claim_stage_errors.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = (
    ROOT
    / "docs/fit2026_manuscript"
    / "FIT2026_調査ミスと結果とりまとめミスの分解_20260814.md"
)

MODELS = ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5")
PHASES = ("normal8", "attack8")

GOLD_STAGE_LABELS = {
    "STRICT_SUCCESS": "根拠を特定し、主体・行動・対象も完全復元",
    "INVESTIGATION_STEP_MISS": "必要なstepが結果に現れず、critical evidenceも提示されない（調査漏れ候補）",
    "INVESTIGATION_EVIDENCE_LOCALIZATION_MISS": "関係は完全復元したがcritical evidenceを提示できない（根拠特定・引用ミス候補）",
    "SYNTHESIS_ERROR_AFTER_EVIDENCE_FOUND": "critical evidenceは発見したが関係のとりまとめを誤る",
    "COMBINED_INVESTIGATION_AND_SYNTHESIS_ERROR": "critical evidenceが不足し、関係のとりまとめも不完全",
}

CLAIM_FLAG_TO_STAGE = {
    "UNSUPPORTED_OR_NEARBY": "INVESTIGATION_SCOPE_DRIFT",
    "WRONG_VALUE": "SYNTHESIS_ENTITY_VALUE_ERROR",
    "WRONG_RELATION": "SYNTHESIS_RELATION_ERROR",
    "WRONG_COMPONENT": "SYNTHESIS_COMPONENT_STRUCTURING_ERROR",
    "DUPLICATE": "SYNTHESIS_DUPLICATION",
    "SUBJECT_OBJECT_REVERSAL": "SYNTHESIS_SUBJECT_OBJECT_REVERSAL",
}


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


def classify_gold_stage(row: dict[str, Any]) -> str:
    complete = row["recovery_pattern"] == "COMPLETE_SAO"
    evidence = int(row["critical_evidence_score"]) == 1
    omitted = row["recovery_pattern"] == "STEP_OMISSION"
    if complete and evidence:
        return "STRICT_SUCCESS"
    if omitted and not evidence:
        return "INVESTIGATION_STEP_MISS"
    if complete and not evidence:
        return "INVESTIGATION_EVIDENCE_LOCALIZATION_MISS"
    if evidence:
        return "SYNTHESIS_ERROR_AFTER_EVIDENCE_FOUND"
    return "COMBINED_INVESTIGATION_AND_SYNTHESIS_ERROR"


def classify_claim_stage_flags(row: dict[str, Any]) -> list[str]:
    flags = {
        CLAIM_FLAG_TO_STAGE[flag]
        for flag in row["error_flags"]
        if flag in CLAIM_FLAG_TO_STAGE
    }
    if (
        "UNSUPPORTED" in row["error_flags"]
        and row["aligned_gold_step_id"] is None
    ):
        flags.add("SYNTHESIS_UNSUPPORTED_ASSERTION_CANDIDATE")
    return sorted(flags)


def counter(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row[field]) for row in rows).items()))


def flag_counter(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    values: Counter[str] = Counter()
    for row in rows:
        values.update(row[field])
    return dict(sorted(values.items()))


def grouped_gold(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {"overall": {"denominator": len(rows), "counts": counter(rows, "stage_pattern")}}
    result["by_model"] = {}
    result["by_model_phase"] = {}
    for model in MODELS:
        model_rows = [row for row in rows if row["model"] == model]
        result["by_model"][model] = {
            "denominator": len(model_rows),
            "counts": counter(model_rows, "stage_pattern"),
        }
        for phase in PHASES:
            selected = [row for row in model_rows if row["phase"] == phase]
            result["by_model_phase"][f"{model}/{phase}"] = {
                "denominator": len(selected),
                "counts": counter(selected, "stage_pattern"),
            }
    return result


def grouped_claim_flags(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {
        "overall": {
            "denominator": len(rows),
            "flag_counts": flag_counter(rows, "stage_error_flags"),
        },
        "by_model": {},
        "by_model_phase": {},
    }
    for model in MODELS:
        model_rows = [row for row in rows if row["model"] == model]
        result["by_model"][model] = {
            "denominator": len(model_rows),
            "flag_counts": flag_counter(model_rows, "stage_error_flags"),
        }
        for phase in PHASES:
            selected = [row for row in model_rows if row["phase"] == phase]
            result["by_model_phase"][f"{model}/{phase}"] = {
                "denominator": len(selected),
                "flag_counts": flag_counter(selected, "stage_error_flags"),
            }
    return result


def pct(count: int, denominator: int) -> str:
    return "-" if not denominator else f"{count / denominator * 100:.1f}%"


def cell(value: dict[str, Any], key: str) -> str:
    count = int(value["counts"].get(key, 0))
    return f"{count}（{pct(count, value['denominator'])}）"


def flag_cell(value: dict[str, Any], key: str) -> str:
    count = int(value["flag_counts"].get(key, 0))
    return f"{count}（{pct(count, value['denominator'])}）"


def build_report(summary: dict[str, Any]) -> str:
    gold = summary["gold_stage_patterns"]
    claims = summary["claim_stage_error_flags"]
    order = summary["order_consequences"]
    overall = gold["overall"]
    lines = [
        "# 調査時のミスと結果とりまとめ時のミスの分解",
        "",
        "作成日: 2026-08-14",
        "",
        "## 1. 分け方",
        "",
        "調査時のミスは、必要なGold stepやcritical evidenceを出力上で確認できなかったこと、またはGold外の近傍事象へ調査範囲がずれたことと定義する。結果とりまとめ時のミスは、得られた情報から主体・行動・対象を組み立てる際の値誤り、関係誤認、component配置誤り、主体対象逆転、重複、未支持claimの生成と定義する。",
        "",
        "モデル内部の調査過程そのものは直接観測できないため、調査時のミスはGold stepとcritical evidenceの出力有無から推定した診断ラベルである。critical evidenceが0でも、モデルが内部でログを見ていなかったと断定はできず、正確には根拠の特定・引用が最終出力で確認できなかったことを表す。",
        "",
        "また、critical evidenceが不足した状態で関係も不完全なケースは、どちらか一方へ無理に割り当てず複合ミスとした。この分類は最終精度を置き換えるものではなく、失敗が発生した段階を診断するための補助分析である。",
        "",
        "## 2. 全体結果",
        "",
        "| 段階パターン | 定義 | 件数 |",
        "|---|---|---:|",
    ]
    for key in (
        "STRICT_SUCCESS",
        "INVESTIGATION_STEP_MISS",
        "INVESTIGATION_EVIDENCE_LOCALIZATION_MISS",
        "SYNTHESIS_ERROR_AFTER_EVIDENCE_FOUND",
        "COMBINED_INVESTIGATION_AND_SYNTHESIS_ERROR",
    ):
        count = int(overall["counts"].get(key, 0))
        lines.append(
            f"| `{key}` | {GOLD_STAGE_LABELS[key]} | "
            f"{count}/{overall['denominator']}（{pct(count, overall['denominator'])}） |"
        )
    lines.extend(
        [
            "",
            "## 3. モデル別",
            "",
            "| モデル | Gold step数 | 根拠付き完全復元 | step調査漏れ | 根拠特定のみ失敗 | 根拠発見後のとりまとめミス | 調査＋とりまとめ複合ミス |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in MODELS:
        value = gold["by_model"][model]
        lines.append(
            f"| {model} | {value['denominator']} | "
            f"{cell(value, 'STRICT_SUCCESS')} | "
            f"{cell(value, 'INVESTIGATION_STEP_MISS')} | "
            f"{cell(value, 'INVESTIGATION_EVIDENCE_LOCALIZATION_MISS')} | "
            f"{cell(value, 'SYNTHESIS_ERROR_AFTER_EVIDENCE_FOUND')} | "
            f"{cell(value, 'COMBINED_INVESTIGATION_AND_SYNTHESIS_ERROR')} |"
        )
    lines.extend(
        [
            "",
            "## 4. モデル・正常／攻撃別",
            "",
            "| モデル・領域 | Gold step数 | 根拠付き完全復元 | step調査漏れ | 根拠特定のみ失敗 | 根拠発見後のとりまとめミス | 複合ミス |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in MODELS:
        for phase in PHASES:
            key = f"{model}/{phase}"
            value = gold["by_model_phase"][key]
            phase_label = "正常" if phase == "normal8" else "攻撃"
            lines.append(
                f"| {model}・{phase_label} | {value['denominator']} | "
                f"{cell(value, 'STRICT_SUCCESS')} | "
                f"{cell(value, 'INVESTIGATION_STEP_MISS')} | "
                f"{cell(value, 'INVESTIGATION_EVIDENCE_LOCALIZATION_MISS')} | "
                f"{cell(value, 'SYNTHESIS_ERROR_AFTER_EVIDENCE_FOUND')} | "
                f"{cell(value, 'COMBINED_INVESTIGATION_AND_SYNTHESIS_ERROR')} |"
            )
    lines.extend(
        [
            "",
            "## 5. とりまとめ時に現れた具体的な誤り",
            "",
            "candidate claimには複数の誤りが重なるため、以下は重複を許したflag件数である。括弧内は各モデルのcandidate claim数を分母とした割合である。",
            "",
            "| モデル | 値・実体誤り | 関係誤認 | component配置誤り | 主体対象逆転 | 重複 | 未支持assertion候補 | 近傍への調査ずれ |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in MODELS:
        value = claims["by_model"][model]
        lines.append(
            f"| {model} | "
            f"{flag_cell(value, 'SYNTHESIS_ENTITY_VALUE_ERROR')} | "
            f"{flag_cell(value, 'SYNTHESIS_RELATION_ERROR')} | "
            f"{flag_cell(value, 'SYNTHESIS_COMPONENT_STRUCTURING_ERROR')} | "
            f"{flag_cell(value, 'SYNTHESIS_SUBJECT_OBJECT_REVERSAL')} | "
            f"{flag_cell(value, 'SYNTHESIS_DUPLICATION')} | "
            f"{flag_cell(value, 'SYNTHESIS_UNSUPPORTED_ASSERTION_CANDIDATE')} | "
            f"{flag_cell(value, 'INVESTIGATION_SCOPE_DRIFT')} |"
        )
    lines.extend(
        [
            "",
            "`未支持assertion候補`はGold未対応かつ元台帳で `unsupported` とされたclaimである。捏造と断定するには元ログ不存在の追加確認が必要である。`近傍への調査ずれ`は `unsupported_or_nearby` であり、実在するがGold対象外の事象を拾った可能性を含む。",
            "",
            "### 正常・攻撃別の出力ミス",
            "",
            "| モデル・領域 | claim数 | 値・実体誤り | 関係誤認 | 主体対象逆転 | 未支持assertion候補 | 近傍への調査ずれ |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in MODELS:
        for phase in PHASES:
            key = f"{model}/{phase}"
            value = claims["by_model_phase"][key]
            phase_label = "正常" if phase == "normal8" else "攻撃"
            lines.append(
                f"| {model}・{phase_label} | {value['denominator']} | "
                f"{flag_cell(value, 'SYNTHESIS_ENTITY_VALUE_ERROR')} | "
                f"{flag_cell(value, 'SYNTHESIS_RELATION_ERROR')} | "
                f"{flag_cell(value, 'SYNTHESIS_SUBJECT_OBJECT_REVERSAL')} | "
                f"{flag_cell(value, 'SYNTHESIS_UNSUPPORTED_ASSERTION_CANDIDATE')} | "
                f"{flag_cell(value, 'INVESTIGATION_SCOPE_DRIFT')} |"
            )
    lines.extend(
        [
            "",
            "正常・攻撃の元台帳ではfalse-positive labelの運用に差があるため、この表は誤りの型を比較する診断用であり、領域間の割合差をそのまま性能差とはみなさない。",
            "",
            "## 6. モデル差の読み取り",
            "",
            "GPT-4.1-miniは、GPT-5.4-miniよりstep調査漏れが少ない一方、値・実体誤りの割合が高い。関係誤認率は両モデルでほぼ同じである。つまり、4.1は情報を比較的多く拾うが具体的な主体・対象値の組み立てで崩れ、5.4はその前段の発見で止まる傾向が強い。",
            "",
            "GPT-5.4-miniはstep調査漏れが最も多く、特に攻撃側で顕著である。主体・対象を逆転する高確度候補も3モデル中で最も多い。主な問題は情報の発見不足であり、発見後にも構造化ミスが残る。",
            "",
            "GPT-5.5は根拠付き完全復元が最も多く、主体対象逆転も検出されなかった。ただし正常側では値・実体誤りと関係誤認、攻撃側ではstep調査漏れとGold外の近傍claimが残る。したがって、正常と攻撃で改善すべき段階が異なる。",
            "",
            "GPT-5.5は正式採点可能な96/144試行に基づくため、4.1・5.4との件数比較ではなく各モデル内の割合と誤り構成を中心に読む。",
            "",
            "## 7. 順序への影響",
            "",
            f"順序pairでは、実際の逆順は{order['reversed']}件だったのに対し、endpoint stepの欠落で評価不能だったものは{order['missing_endpoint']}件だった。順序性能の主要な制約も、とりまとめ時の並べ替えより上流のstep調査漏れである。",
            "",
            "## 8. 出力物",
            "",
            f"- Gold step別段階分類: `{relative(OUT_GOLD)}`",
            f"- candidate claim別段階flag: `{relative(OUT_CLAIMS)}`",
            f"- 集計JSON: `{relative(OUT_SUMMARY)}`",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    replace_generated = sys.argv[1:] == ["--replace-generated"]
    if sys.argv[1:] and not replace_generated:
        raise SystemExit("usage: script [--replace-generated]")
    for path in (OUT_GOLD, OUT_CLAIMS, OUT_SUMMARY, OUT_REPORT):
        if path.exists() and not replace_generated:
            raise FileExistsError(f"create-only refusal: {path}")

    gold_source_rows = read_jsonl(SOURCE_GOLD)
    claim_source_rows = read_jsonl(SOURCE_CLAIMS)
    order_source_rows = read_jsonl(SOURCE_ORDER)
    gold_rows = [
        {**row, "stage_pattern": classify_gold_stage(row)}
        for row in gold_source_rows
    ]
    claim_rows = [
        {**row, "stage_error_flags": classify_claim_stage_flags(row)}
        for row in claim_source_rows
    ]
    if len(gold_rows) != 1571 or len(claim_rows) != 1384:
        raise AssertionError("unexpected source row counts")

    gold_summary = grouped_gold(gold_rows)
    claim_summary = grouped_claim_flags(claim_rows)
    order_counts = Counter(row["status"] for row in order_source_rows)
    summary = {
        "schema_version": "three_model_investigation_vs_synthesis_v1",
        "created_date": "2026-08-14",
        "source_files": [
            {"path": relative(path), "sha256": sha256(path)}
            for path in (SOURCE_GOLD, SOURCE_CLAIMS, SOURCE_ORDER)
        ],
        "diagnostic_policy": {
            "investigation_error": "Gold-step/critical-evidence miss or unsupported-nearby scope drift",
            "synthesis_error": "entity, relation, component, role, duplicate, or unsupported-assertion error after/while forming claims",
            "combined_error": "critical evidence missing and subject/action/object reconstruction also incomplete",
            "not_a_replacement_for_accuracy": True,
            "model_or_judge_calls": 0,
        },
        "gold_stage_patterns": gold_summary,
        "claim_stage_error_flags": claim_summary,
        "order_consequences": {
            "correct": int(order_counts.get("correct", 0)),
            "reversed": int(order_counts.get("reversed", 0)),
            "missing_endpoint": int(
                order_counts.get("not_evaluable_missing_endpoint_step", 0)
            ),
        },
        "counts": {
            "gold_steps": len(gold_rows),
            "candidate_claims": len(claim_rows),
            "order_pairs": len(order_source_rows),
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_GOLD, gold_rows)
    write_jsonl(OUT_CLAIMS, claim_rows)
    OUT_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    OUT_REPORT.write_text(build_report(summary), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
