#!/usr/bin/env python3
"""Re-score action and order for every formally scored 4.1/5.4/5.5 trial.

This is a non-destructive overlay. Subject, object, and critical-evidence
scores are copied unchanged from the adopted score ledgers. Action uses the
same evidence-constrained canonical-class policy as the GPT-5.5 96-PASS
re-score. Order is reported as both all-Gold-pair coverage and conditional
accuracy over pairs whose endpoint steps were located in distinct claims.

The intended experiment grid contains 432 cells. The two mini models have all
144 cells each. GPT-5.5 has 96 formally scored PASS cells; its other 48 cells
are recorded as unavailable and are not silently converted to zero or PASS.
No model or judge API is called, and source ledgers are never modified.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import rescore_gpt55_96pass_action_order_semantic_v1_20260814 as policy_v1


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "three_model_all_trials_action_order_semantic_v1"
)
OUT_ROWS = OUT_DIR / "semantic_rescore_overlay_all_scored.jsonl"
OUT_CHANGES = OUT_DIR / "action_score_changes.jsonl"
OUT_COVERAGE = OUT_DIR / "intended_trial_coverage.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = (
    ROOT
    / "docs/fit2026_manuscript"
    / "FIT2026_3モデル全試行_行動順序_意味クラス再採点_20260814.md"
)

SOURCE_SPECS = (
    {
        "label": "normal_replicate_01",
        "path": ROOT
        / "docs/current_experiment/results_2026-08-01"
        / "normal8_three_model_three_stage_formal_19_retry_02"
        / "scores_codex_sol_v1/formal_scores.jsonl",
        "phase": "normal8",
        "replicate": "replicate_01",
        "legacy_attack": False,
    },
    {
        "label": "normal_replicates_02_03",
        "path": ROOT
        / "docs/current_experiment/results_2026-08-06"
        / "mini_reps_02_03_v5_scores_normal_codex_sol_v1/formal_scores.jsonl",
        "phase": "normal8",
        "replicate": None,
        "legacy_attack": False,
    },
    {
        "label": "attack_replicate_01",
        "path": ROOT
        / "docs/current_experiment/results_2026-07-27"
        / "atlasv2_s3_s4_attack8_process_chain_v5_formal"
        / "two_model_baseline_replicate_01"
        / "scores_codex_manual_double_review_v5_atomic_alignment"
        / "formal_adopted_reviews_v5.jsonl",
        "phase": "attack8",
        "replicate": "replicate_01",
        "legacy_attack": True,
    },
    {
        "label": "attack_replicates_02_03",
        "path": ROOT
        / "docs/current_experiment/results_2026-08-06"
        / "mini_reps_02_03_v5_scores_attack_codex_sol_v1/per_run_scores.jsonl",
        "phase": "attack8",
        "replicate": None,
        "legacy_attack": False,
    },
    {
        "label": "gpt55_formal_96pass",
        "path": ROOT
        / "docs/current_experiment/results_2026-08-07"
        / "gpt55_three_replicate_96pass_scores_codex_sol_provisional_v2"
        / "formal_scores_96pass.jsonl",
        "phase": None,
        "replicate": None,
        "legacy_attack": False,
    },
)

MODELS = ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5")
PHASES = ("normal8", "attack8")
REPLICATES = ("replicate_01", "replicate_02", "replicate_03")
STAGES = ("stage1", "stage2", "stage3")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def relative(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def parse_legacy_attack_item_step(item_id: str) -> str:
    parts = item_id.split(":")
    if len(parts) < 3:
        raise ValueError(f"cannot parse legacy Gold item id: {item_id}")
    return parts[-2]


def normalize_row(
    source_row: dict[str, Any], spec: dict[str, Any]
) -> dict[str, Any]:
    row = deepcopy(source_row)
    queue_id = str(row["queue_id"])
    queue_parts = queue_id.split("/")

    if spec["legacy_attack"]:
        if len(queue_parts) != 4:
            raise ValueError(f"unexpected legacy attack queue id: {queue_id}")
        model, stage, run_name, instance_id = queue_parts
        chain_id = re.sub(rf"_{re.escape(stage)}$", "", run_name)
        row["model"] = model
        row["stage"] = stage
        row["chain_id"] = chain_id
        row["instance_id"] = instance_id
        row["gold_path"] = (
            "data/current_experiment/gold/"
            "atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727/"
            f"by_chain/{chain_id}/chain_gold.json"
        )
        normalized_items = []
        for item in row["gold_items"]:
            normalized_item = deepcopy(item)
            normalized_item["step_id"] = parse_legacy_attack_item_step(
                str(item["item_id"])
            )
            normalized_items.append(normalized_item)
        row["gold_items"] = normalized_items
        normalized_slots = []
        for slot in row.get("candidate_slots") or []:
            normalized_slot = deepcopy(slot)
            aligned = normalized_slot.get("aligned_gold_step_id")
            if aligned:
                # The replicate-01 adopted ledger prefixes the bare Gold step
                # id with "chain_id:"; later ledgers store the bare id.
                normalized_slot["aligned_gold_step_id"] = str(aligned).rsplit(
                    ":", 1
                )[-1]
            normalized_slots.append(normalized_slot)
        row["candidate_slots"] = normalized_slots
        normalized_pairs = []
        for pair in row.get("order_pairs") or []:
            normalized_pair = deepcopy(pair)
            pair_suffix = str(pair["pair_id"]).rsplit(":", 1)[-1]
            before, after = pair_suffix.split("->", 1)
            normalized_pair["before_step_id"] = before
            normalized_pair["after_step_id"] = after
            normalized_pairs.append(normalized_pair)
        row["order_pairs"] = normalized_pairs
        row["run_sha256"] = (
            row.get("source_decision_sha256")
            or row.get("decision_sha256")
            or sha256_json(source_row)
        )
    else:
        model = str(row.get("model") or queue_parts[-4])
        stage = str(row.get("stage") or queue_parts[-3])
        chain_id = str(row.get("chain_id") or "")
        if not chain_id:
            run_name = queue_parts[-2]
            chain_id = re.sub(rf"_{re.escape(stage)}$", "", run_name)
        row["model"] = model
        row["stage"] = stage
        row["chain_id"] = chain_id
        row["instance_id"] = str(
            row.get("instance_id") or queue_parts[-1]
        )
        row["run_sha256"] = str(
            row.get("run_sha256")
            or row.get("decision_sha256")
            or sha256_json(source_row)
        )
        # Attack replicate-02/03 ledgers call this field emitted_step_id,
        # while the shared ordering policy expects candidate_step_id when no
        # explicit source_order is present.
        normalized_slots = []
        for slot in row.get("candidate_slots") or []:
            normalized_slot = deepcopy(slot)
            if (
                not normalized_slot.get("candidate_step_id")
                and normalized_slot.get("emitted_step_id")
            ):
                normalized_slot["candidate_step_id"] = normalized_slot[
                    "emitted_step_id"
                ]
            normalized_slots.append(normalized_slot)
        row["candidate_slots"] = normalized_slots

    row["phase"] = str(row.get("phase") or spec["phase"])
    row["replicate"] = str(row.get("replicate") or spec["replicate"])
    row["score_provenance"] = row.get("score_provenance") or spec["label"]
    row["_source_label"] = spec["label"]
    row["_source_path"] = relative(spec["path"])
    row["_source_row_sha256"] = sha256_json(source_row)

    if row["model"] not in MODELS:
        raise ValueError(f"unexpected model {row['model']}: {queue_id}")
    if row["phase"] not in PHASES:
        raise ValueError(f"unexpected phase {row['phase']}: {queue_id}")
    if row["replicate"] not in REPLICATES:
        raise ValueError(f"unexpected replicate {row['replicate']}: {queue_id}")
    if row["stage"] not in STAGES:
        raise ValueError(f"unexpected stage {row['stage']}: {queue_id}")
    return row


def frozen_from_row(row: dict[str, Any]) -> dict[str, dict[str, int]]:
    return {
        kind: {
            "hits": sum(
                int(item["score"])
                for item in row["gold_items"]
                if item["kind"] == kind
            ),
            "denominator": sum(
                1 for item in row["gold_items"] if item["kind"] == kind
            ),
        }
        for kind in ("subject", "object", "critical_evidence")
    }


def rescore(normalized: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    overlay, changes = policy_v1.rescore_row(normalized)
    overlay["schema_version"] = "three_model_action_order_semantic_rescore_overlay_v1"
    overlay["model"] = normalized["model"]
    overlay["source_score_file"] = normalized["_source_path"]
    overlay["source_score_label"] = normalized["_source_label"]
    overlay["source_score_row_sha256"] = normalized["_source_row_sha256"]
    if overlay["frozen_component_scores"] != frozen_from_row(normalized):
        raise AssertionError(
            f"frozen component mismatch: {normalized['queue_id']}"
        )
    for change in changes:
        change["model"] = normalized["model"]
        change["source_score_file"] = normalized["_source_path"]
        change["source_score_row_sha256"] = normalized["_source_row_sha256"]
    return overlay, changes


def ratio(hits: int, denominator: int) -> float | None:
    return hits / denominator if denominator else None


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    frozen = {}
    for kind in ("subject", "object", "critical_evidence"):
        hits = sum(row["frozen_component_scores"][kind]["hits"] for row in rows)
        denominator = sum(
            row["frozen_component_scores"][kind]["denominator"] for row in rows
        )
        frozen[kind] = {
            "hits": hits,
            "denominator": denominator,
            "recall": ratio(hits, denominator),
        }
    action_den = sum(row["action_totals"]["denominator"] for row in rows)
    action_old = sum(row["action_totals"]["original_hits"] for row in rows)
    action_new = sum(row["action_totals"]["semantic_hits"] for row in rows)
    pair_den = sum(
        row["order_totals"]["all_gold_pair_denominator"] for row in rows
    )
    coverage = sum(
        row["order_totals"]["original_coverage_hits"] for row in rows
    )
    evaluable = sum(
        row["order_totals"]["conditional_evaluable_pairs"] for row in rows
    )
    correct = sum(row["order_totals"]["conditional_correct"] for row in rows)
    reversed_count = sum(
        row["order_totals"]["conditional_reversed"] for row in rows
    )
    not_evaluable = sum(
        row["order_totals"]["not_evaluable_missing_or_merged"] for row in rows
    )
    return {
        "scored_run_count": len(rows),
        "frozen_components": frozen,
        "action": {
            "denominator": action_den,
            "original_hits": action_old,
            "original_recall": ratio(action_old, action_den),
            "semantic_hits": action_new,
            "semantic_recall": ratio(action_new, action_den),
            "added_hits": action_new - action_old,
        },
        "order": {
            "all_gold_pair_denominator": pair_den,
            "ordered_pair_coverage_hits": coverage,
            "ordered_pair_coverage_recall": ratio(coverage, pair_den),
            "conditional_evaluable_pairs": evaluable,
            "conditional_correct": correct,
            "conditional_accuracy": ratio(correct, evaluable),
            "conditional_reversed": reversed_count,
            "not_evaluable_missing_or_merged": not_evaluable,
        },
    }


def action_class_aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[str, int]] = defaultdict(
        lambda: {"denominator": 0, "original_hits": 0, "semantic_hits": 0}
    )
    for row in rows:
        for decision in row["action_decisions"]:
            bucket = grouped[decision["gold_action_class"]]
            bucket["denominator"] += 1
            bucket["original_hits"] += int(decision["original_score"])
            bucket["semantic_hits"] += int(decision["semantic_score"])
    return {
        key: {
            **value,
            "original_recall": ratio(value["original_hits"], value["denominator"]),
            "semantic_recall": ratio(value["semantic_hits"], value["denominator"]),
            "added_hits": value["semantic_hits"] - value["original_hits"],
        }
        for key, value in sorted(grouped.items())
    }


def trial_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        row["model"],
        row["phase"],
        row["replicate"],
        row["stage"],
        row["chain_id"],
    )


def intended_coverage(
    normalized_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    mini_rows = [row for row in normalized_rows if row["model"] != "gpt-5.5"]
    cases_by_phase = {
        phase: sorted({row["chain_id"] for row in mini_rows if row["phase"] == phase})
        for phase in PHASES
    }
    if any(len(cases_by_phase[phase]) != 8 for phase in PHASES):
        raise AssertionError(f"expected eight cases per phase: {cases_by_phase}")
    scored = {trial_key(row): row for row in normalized_rows}
    if len(scored) != len(normalized_rows):
        raise AssertionError("duplicate normalized trial key")
    coverage = []
    for model in MODELS:
        for phase in PHASES:
            for replicate in REPLICATES:
                for stage in STAGES:
                    for chain_id in cases_by_phase[phase]:
                        key = (model, phase, replicate, stage, chain_id)
                        row = scored.get(key)
                        coverage.append(
                            {
                                "model": model,
                                "phase": phase,
                                "replicate": replicate,
                                "stage": stage,
                                "chain_id": chain_id,
                                "score_status": (
                                    "semantic_rescore_complete"
                                    if row
                                    else "not_in_formal_scored_ledger"
                                ),
                                "source_queue_id": row["queue_id"] if row else None,
                                "source_score_file": row["_source_path"] if row else None,
                            }
                        )
    if len(coverage) != 432:
        raise AssertionError(f"expected 432 intended cells, got {len(coverage)}")
    return coverage


def percent(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def result_row(label: str, coverage: str, value: dict[str, Any]) -> str:
    action = value["action"]
    order = value["order"]
    return (
        f"| {label} | {coverage} | "
        f"{action['original_hits']}/{action['denominator']} "
        f"({percent(action['original_recall'])}) | "
        f"{action['semantic_hits']}/{action['denominator']} "
        f"({percent(action['semantic_recall'])}) | +{action['added_hits']} | "
        f"{order['ordered_pair_coverage_hits']}/{order['all_gold_pair_denominator']} "
        f"({percent(order['ordered_pair_coverage_recall'])}) | "
        f"{order['conditional_correct']}/{order['conditional_evaluable_pairs']} "
        f"({percent(order['conditional_accuracy'])}) | "
        f"{order['conditional_reversed']} | "
        f"{order['not_evaluable_missing_or_merged']} |"
    )


def build_report(summary: dict[str, Any]) -> str:
    coverage = summary["coverage"]
    lines = [
        "# 3モデル全試行：行動・順序の意味クラス再採点",
        "",
        "作成日: 2026-08-14",
        "",
        "## 1. 対象範囲",
        "",
        "GPT-4.1-mini、GPT-5.4-mini、GPT-5.5について、現在の正式採点台帳に存在する全試行を同一規則で再採点した。意図した実験格子は、3モデル×正常・攻撃各8ケース×3段階×3反復の432試行である。このうち正式採点可能なのは384試行であり、GPT-4.1-miniとGPT-5.4-miniは各144/144試行、GPT-5.5は96/144試行である。GPT-5.5の残り48試行は正式96 PASS台帳に存在しないため、0点や成功として補完せず「採点不能」として明示した。",
        "",
        f"全体の再採点完了数は **{coverage['scored_cells']}/{coverage['intended_cells']}試行**、未採点は **{coverage['unavailable_cells']}試行** である。",
        "",
        "## 2. 再採点規則",
        "",
        "主体・対象・critical evidenceは既存の正式判定を一切変更していない。行動だけを、既存のGold stepへの対応付けを前提として、ログ上同じ意味を持つ共通行動クラスで再判定した。たとえば `process_start` と `process_create`、`read/open/load` と実行入力の使用のように、表現は違っても同じ証跡関係を述べている場合を一致とする。対応付けられていない近傍イベントや、異なる行動クラスには加点しない。",
        "",
        "| 共通行動クラス | まとめる関係 |",
        "|---|---|",
        "| `PROCESS_CREATE` | 親プロセスが子プロセスを生成・開始した |",
        "| `INPUT_USE` | 文書・スクリプト・コマンドを実行入力として使用した |",
        "| `FILE_CREATE_WRITE` | ファイルを生成・書き込みした |",
        "| `REGISTRY_WRITE` | レジストリ値を作成・変更した |",
        "| `NETWORK_CONNECT` | リモートエンドポイントへ接続した |",
        "| `NETWORK_LISTEN` | ローカルエンドポイントで待ち受けた |",
        "",
        "順序は二つに分けた。順序coverageは全Gold隣接pairのうち、両stepと順序を復元できた割合である。条件付き順序正確性は、両stepを別々のclaimとして発見できたpairだけを分母にし、その並びが正しいかを見る。片方のstepが欠けたpairを「逆順」とは扱わない。",
        "",
        "## 3. モデル別結果",
        "",
        "| モデル | 採点可能試行 | 行動・従来 | 行動・意味クラス | 追加hit | 順序coverage | 条件付き順序正確性 | 逆順 | endpoint欠損等 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for model in MODELS:
        value = summary["aggregates"]["by_model"][model]
        model_coverage = coverage["by_model"][model]
        coverage_label = (
            f"{model_coverage['scored_cells']}/{model_coverage['intended_cells']}"
        )
        lines.append(result_row(model, coverage_label, value))
    lines.extend(
        [
            "",
            "## 4. モデル×正常・攻撃別結果",
            "",
            "| モデル・領域 | 採点可能試行 | 行動・従来 | 行動・意味クラス | 追加hit | 順序coverage | 条件付き順序正確性 | 逆順 | endpoint欠損等 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in MODELS:
        for phase in PHASES:
            key = f"{model}/{phase}"
            value = summary["aggregates"]["by_model_phase"][key]
            model_phase_coverage = coverage["by_model_phase"][key]
            coverage_label = (
                f"{model_phase_coverage['scored_cells']}/"
                f"{model_phase_coverage['intended_cells']}"
            )
            phase_label = "正常" if phase == "normal8" else "攻撃"
            lines.append(result_row(f"{model}・{phase_label}", coverage_label, value))
    lines.extend(
        [
            "",
            "## 5. 読み方",
            "",
            "行動の意味クラス再採点は、既存採点の取りこぼしを修正するためのものであり、主体や対象が誤っているclaimを正解へ変えるものではない。そのため、研究発表では「行動単語の一致率」ではなく、「正しいGold stepに対応付いたclaimが、同じ証跡関係を表していた割合」と説明する。",
            "",
            "また、条件付き順序正確性が高くても、順序coverageが低ければchain全体を復元できたとは言えない。前者は発見済みstepの並べ方、後者はstep発見を含む全体復元を測っている。この二つを分けることで、「順番を間違えた」のか「そもそも必要な行動を発見できなかった」のかを区別できる。",
            "",
            "## 6. 出力物",
            "",
            f"- run別overlay: `{relative(OUT_ROWS)}`",
            f"- 行動変更一覧: `{relative(OUT_CHANGES)}`",
            f"- 432試行coverage表: `{relative(OUT_COVERAGE)}`",
            f"- 集計JSON: `{relative(OUT_SUMMARY)}`",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    replace_generated = sys.argv[1:] == ["--replace-generated"]
    if sys.argv[1:] and not replace_generated:
        raise SystemExit("usage: script [--replace-generated]")
    for path in (OUT_ROWS, OUT_CHANGES, OUT_COVERAGE, OUT_SUMMARY, OUT_REPORT):
        if path.exists() and not replace_generated:
            raise FileExistsError(f"create-only refusal: {path}")

    source_inventory = []
    normalized_rows = []
    for spec in SOURCE_SPECS:
        source_rows = read_jsonl(spec["path"])
        source_inventory.append(
            {
                "label": spec["label"],
                "path": relative(spec["path"]),
                "sha256": sha256_file(spec["path"]),
                "row_count": len(source_rows),
            }
        )
        normalized_rows.extend(normalize_row(row, spec) for row in source_rows)

    if len(normalized_rows) != 384:
        raise AssertionError(f"expected 384 scored rows, got {len(normalized_rows)}")
    model_counts = Counter(row["model"] for row in normalized_rows)
    if model_counts != Counter(
        {"gpt-4.1-mini": 144, "gpt-5.4-mini": 144, "gpt-5.5": 96}
    ):
        raise AssertionError(f"unexpected model counts: {model_counts}")

    overlays = []
    changes = []
    for row in normalized_rows:
        overlay, row_changes = rescore(row)
        overlays.append(overlay)
        changes.extend(row_changes)
    overlays.sort(key=trial_key)
    changes.sort(
        key=lambda row: (
            row["model"], row["phase"], row["replicate"], row["stage"],
            row["chain_id"], row["step_id"]
        )
    )

    action_decisions = sum(len(row["action_decisions"]) for row in overlays)
    order_decisions = sum(len(row["order_decisions"]) for row in overlays)
    if action_decisions != 1571:
        raise AssertionError(
            f"expected 1571 action decisions, got {action_decisions}"
        )
    if order_decisions != 1187:
        raise AssertionError(
            f"expected 1187 order decisions, got {order_decisions}"
        )

    # The generalized run must reproduce the already-reviewed GPT-5.5 overlay.
    prior_gpt55_path = (
        ROOT
        / "docs/current_experiment/results_2026-08-14"
        / "gpt55_96pass_action_order_semantic_v1"
        / "semantic_rescore_overlay_96pass.jsonl"
    )
    prior_gpt55 = {
        row["source_queue_id"]: row for row in read_jsonl(prior_gpt55_path)
    }
    current_gpt55 = {
        row["source_queue_id"]: row
        for row in overlays
        if row["model"] == "gpt-5.5"
    }
    if set(prior_gpt55) != set(current_gpt55):
        raise AssertionError("GPT-5.5 queue set differs from prior 96-PASS overlay")
    for queue_id, prior in prior_gpt55.items():
        current = current_gpt55[queue_id]
        for field in (
            "frozen_component_scores",
            "action_decisions",
            "action_totals",
            "order_decisions",
            "order_totals",
        ):
            if prior[field] != current[field]:
                raise AssertionError(
                    f"GPT-5.5 policy regression in {field}: {queue_id}"
                )

    coverage_rows = intended_coverage(normalized_rows)
    coverage_by_model = {}
    coverage_by_model_phase = {}
    for model in MODELS:
        model_rows = [row for row in coverage_rows if row["model"] == model]
        coverage_by_model[model] = {
            "intended_cells": len(model_rows),
            "scored_cells": sum(
                row["score_status"] == "semantic_rescore_complete"
                for row in model_rows
            ),
        }
        coverage_by_model[model]["unavailable_cells"] = (
            coverage_by_model[model]["intended_cells"]
            - coverage_by_model[model]["scored_cells"]
        )
        for phase in PHASES:
            key = f"{model}/{phase}"
            phase_rows = [row for row in model_rows if row["phase"] == phase]
            scored = sum(
                row["score_status"] == "semantic_rescore_complete"
                for row in phase_rows
            )
            coverage_by_model_phase[key] = {
                "intended_cells": len(phase_rows),
                "scored_cells": scored,
                "unavailable_cells": len(phase_rows) - scored,
            }

    by_model = {
        model: aggregate([row for row in overlays if row["model"] == model])
        for model in MODELS
    }
    by_model_phase = {
        f"{model}/{phase}": aggregate(
            [
                row
                for row in overlays
                if row["model"] == model and row["phase"] == phase
            ]
        )
        for model in MODELS
        for phase in PHASES
    }
    by_model_stage = {
        f"{model}/{stage}": aggregate(
            [
                row
                for row in overlays
                if row["model"] == model and row["stage"] == stage
            ]
        )
        for model in MODELS
        for stage in STAGES
    }
    summary = {
        "schema_version": "three_model_action_order_semantic_rescore_summary_v1",
        "created_date": "2026-08-14",
        "policy_dependency": relative(
            ROOT / "scripts/rescore_gpt55_96pass_action_order_semantic_v1_20260814.py"
        ),
        "policy": {
            "subject_object_critical_evidence": "frozen from adopted source scores",
            "action": "same evidence-constrained canonical action-class equivalence used in the GPT-5.5 96-PASS v1 overlay; an existing Gold-step alignment is required",
            "order_coverage": "original all-Gold-adjacent-pair score retained",
            "conditional_order": "only pairs whose endpoint Gold steps are located in distinct candidate claims are scored",
            "missing_endpoint_order_pair": "not evaluable, not reversed",
            "judge_api_calls": 0,
            "model_api_calls": 0,
        },
        "source_inventory": source_inventory,
        "coverage": {
            "intended_cells": len(coverage_rows),
            "scored_cells": len(overlays),
            "unavailable_cells": len(coverage_rows) - len(overlays),
            "by_model": coverage_by_model,
            "by_model_phase": coverage_by_model_phase,
        },
        "counts": {
            "scored_runs": len(overlays),
            "action_decisions": action_decisions,
            "action_changes": len(changes),
            "order_decisions": order_decisions,
        },
        "aggregates": {
            "overall_scored_only": aggregate(overlays),
            "by_model": by_model,
            "by_model_phase": by_model_phase,
            "by_model_stage": by_model_stage,
        },
        "action_by_canonical_class": {
            model: action_class_aggregate(
                [row for row in overlays if row["model"] == model]
            )
            for model in MODELS
        },
        "action_change_patterns": [
            {
                "model": model,
                "gold_action": gold_action,
                "candidate_operation": operation,
                "canonical_class": action_class,
                "count": count,
            }
            for (model, gold_action, operation, action_class), count in Counter(
                (
                    row["model"],
                    str(row["gold_action"]),
                    str((row.get("matched_candidate") or {}).get("candidate_operation")),
                    str(row["gold_action_class"]),
                )
                for row in changes
            ).most_common()
        ],
        "validation": {
            "source_ledgers_modified": False,
            "frozen_components_verified_per_run": True,
            "gpt55_96pass_overlay_exactly_reproduced": True,
            "intended_grid_cells_verified": 432,
        },
    }

    report = build_report(summary)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_ROWS.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in overlays
        ),
        encoding="utf-8",
    )
    OUT_CHANGES.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in changes
        ),
        encoding="utf-8",
    )
    OUT_COVERAGE.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in coverage_rows
        ),
        encoding="utf-8",
    )
    OUT_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    OUT_REPORT.write_text(report, encoding="utf-8")
    print(json.dumps(summary["aggregates"]["by_model"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
