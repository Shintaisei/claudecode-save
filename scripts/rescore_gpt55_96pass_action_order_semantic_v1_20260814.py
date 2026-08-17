#!/usr/bin/env python3
"""Create a non-destructive semantic re-score overlay for GPT-5.5 96 PASS.

Subject, object, and critical-evidence decisions are frozen.  Only action is
reconsidered through evidence-constrained canonical action classes.  Order is
reported both as the original all-Gold-pair coverage and as conditional order
accuracy over pairs whose two endpoint steps were located in distinct claims.

No model or judge API is called.  The original score JSONL is never modified.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "docs/current_experiment/results_2026-08-07"
    / "gpt55_three_replicate_96pass_scores_codex_sol_provisional_v2"
    / "formal_scores_96pass.jsonl"
)
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-14"
    / "gpt55_96pass_action_order_semantic_v1"
)
OUT_ROWS = OUT_DIR / "semantic_rescore_overlay_96pass.jsonl"
OUT_CHANGES = OUT_DIR / "action_score_changes.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = (
    ROOT
    / "docs/fit2026_manuscript"
    / "FIT2026_GPT55_行動順序_意味クラス再採点_20260814.md"
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def gold_path(row: dict[str, Any]) -> Path:
    value = row.get("gold_json") or row.get("gold_path")
    if not value:
        raise ValueError(f"gold path missing: {row.get('queue_id')}")
    return ROOT / str(value).replace("\\", "/")


def gold_action_class(step: dict[str, Any]) -> str:
    kind = str(step.get("evidence_kind") or "").lower()
    action = str(step.get("action") or "").lower()
    if kind in {
        "parent_child",
        "parent_child_command",
        "process_creation",
        "command_process_creation",
    }:
        return "PROCESS_CREATE"
    if kind in {"command_script", "document_input"}:
        return "INPUT_USE"
    if kind == "registry":
        return "REGISTRY_WRITE"
    if kind == "file":
        return "FILE_CREATE_WRITE"
    if kind in {"network", "command_network"}:
        if "listen" in action or "待ち受け" in action:
            return "NETWORK_LISTEN"
        return "NETWORK_CONNECT"
    raise ValueError(
        f"unsupported Gold evidence_kind={kind!r} step={step.get('step_id')}"
    )


def candidate_action_class(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    compact = text.replace("-", "_").replace(" ", "_")
    if not text:
        return None

    # Destructive operations are not treated as create/write or input use.
    if any(term in text for term in ("delete", "remove", "terminate", "削除")):
        return "OTHER"
    if any(
        term in compact
        for term in (
            "create_process",
            "process_create",
            "action_create_process",
            "process_start",
            "start_process",
            "spawn_process",
        )
    ) or any(term in text for term in ("プロセス作成", "子プロセス起動")):
        return "PROCESS_CREATE"
    if any(term in text for term in ("listen", "listener", "リッスン", "待ち受け")):
        return "NETWORK_LISTEN"
    if any(
        term in compact
        for term in (
            "network_connect",
            "connection_create",
            "action_connection_create",
            "connect_network",
        )
    ) or any(term in text for term in ("接続", "connection", "connect")):
        return "NETWORK_CONNECT"
    if "registry" in text or "レジストリ" in text:
        if any(term in text for term in ("write", "set", "add", "create", "書", "登録")):
            return "REGISTRY_WRITE"
    # Read/load/open is accepted as the lower-level input-use description for
    # an already aligned document/script Gold step.  The alignment prevents a
    # nearby arbitrary file read from being credited.
    if any(
        term in compact
        for term in (
            "execution_input",
            "batch_execution",
            "batch_command",
            "script_load",
            "load_script",
            "read_file",
            "file_read",
            "action_file_mod_open",
            "action_file_open_read",
        )
    ) or any(
        term in text
        for term in (
            "execute",
            "execution",
            "invoke",
            "script",
            "batch",
            "read",
            "open",
            "load",
            "実行",
            "読み取り",
            "読み込み",
            "開いて",
        )
    ):
        return "INPUT_USE"
    if any(
        term in compact
        for term in ("file_create_write", "file_write", "create_file", "materialize")
    ) or any(term in text for term in ("write", "created", "作成", "書き込み")):
        return "FILE_CREATE_WRITE"
    return "OTHER"


def claim_groups(row: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for slot in row.get("candidate_slots") or []:
        groups[str(slot["candidate_claim_id"])].append(slot)
    return groups


def claim_order(slots: list[dict[str, Any]]) -> int:
    values = [
        slot.get("source_order", slot.get("candidate_order"))
        for slot in slots
        if slot.get("source_order", slot.get("candidate_order")) is not None
    ]
    if values:
        return int(min(values))
    candidate_step = str(slots[0].get("candidate_step_id") or "")
    digits = "".join(char for char in candidate_step if char.isdigit())
    return int(digits) if digits else 10**9


def aligned_step(slots: list[dict[str, Any]]) -> str | None:
    values = {
        str(slot["aligned_gold_step_id"])
        for slot in slots
        if slot.get("aligned_gold_step_id")
    }
    if len(values) > 1:
        raise ValueError(f"claim aligned to multiple Gold steps: {sorted(values)}")
    return next(iter(values), None)


def step_positions(row: dict[str, Any]) -> dict[str, list[int]]:
    positions: dict[str, list[int]] = defaultdict(list)
    if row["phase"] == "normal8":
        for alignment in row.get("candidate_claim_alignments") or []:
            step_id = alignment.get("aligned_gold_step_id")
            if step_id:
                positions[str(step_id)].append(int(alignment["candidate_order"]))
    else:
        for slots in claim_groups(row).values():
            step_id = aligned_step(slots)
            if step_id:
                positions[step_id].append(claim_order(slots))
    return {key: sorted(set(value)) for key, value in positions.items()}


def pair_step_ids(pair: dict[str, Any]) -> tuple[str, str]:
    left = pair.get("before_step_id") or pair.get("left_step_id")
    right = pair.get("after_step_id") or pair.get("right_step_id")
    if not left or not right:
        raise ValueError(f"invalid order pair: {pair}")
    return str(left), str(right)


def rescore_row(row: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    gold = read_json(gold_path(row))
    steps = {str(step["step_id"]): step for step in gold["gold_steps"]}
    operation_items = {
        str(item["step_id"]): item
        for item in row["gold_items"]
        if item["kind"] == "operation"
    }
    groups = claim_groups(row)
    candidates_by_step: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for claim_id, slots in groups.items():
        step_id = aligned_step(slots)
        if not step_id:
            continue
        operation_slot = next(
            (slot for slot in slots if slot["kind"] == "operation"), None
        )
        if operation_slot is None:
            continue
        candidates_by_step[step_id].append(
            {
                "candidate_claim_id": claim_id,
                "candidate_order": claim_order(slots),
                "candidate_operation": operation_slot.get("candidate_slot_excerpt"),
                "candidate_action_class": candidate_action_class(
                    operation_slot.get("candidate_slot_excerpt")
                ),
                "subject_score": next(
                    (int(slot["is_true_positive"]) for slot in slots if slot["kind"] == "subject"),
                    0,
                ),
                "object_score": next(
                    (int(slot["is_true_positive"]) for slot in slots if slot["kind"] == "object"),
                    0,
                ),
            }
        )

    decisions: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    for step_id, step in steps.items():
        original = int(operation_items[step_id]["score"])
        target_class = gold_action_class(step)
        matching = sorted(
            (
                candidate
                for candidate in candidates_by_step.get(step_id, [])
                if candidate["candidate_action_class"] == target_class
            ),
            key=lambda value: (value["candidate_order"], value["candidate_claim_id"]),
        )
        semantic = int(bool(original or matching))
        decision = {
            "step_id": step_id,
            "gold_action": step.get("action"),
            "gold_evidence_kind": step.get("evidence_kind"),
            "gold_action_class": target_class,
            "original_score": original,
            "semantic_score": semantic,
            "matched_candidate": matching[0] if matching else None,
            "decision_reason": (
                "retained original action hit"
                if original
                else (
                    "aligned claim has the same evidence-constrained canonical action class"
                    if matching
                    else "no aligned candidate with the same canonical action class"
                )
            ),
        }
        decisions.append(decision)
        if semantic != original:
            changes.append(
                {
                    "queue_id": row["queue_id"],
                    "phase": row["phase"],
                    "replicate": row["replicate"],
                    "stage": row["stage"],
                    "chain_id": row["chain_id"],
                    **decision,
                }
            )

    positions = step_positions(row)
    order_decisions = []
    for pair in row.get("order_pairs") or []:
        left, right = pair_step_ids(pair)
        left_positions = positions.get(left, [])
        right_positions = positions.get(right, [])
        if not left_positions or not right_positions:
            semantic_score = None
            status = "not_evaluable_missing_endpoint_step"
        elif any(a < b for a in left_positions for b in right_positions):
            semantic_score = 1
            status = "correct"
        elif set(left_positions) & set(right_positions):
            semantic_score = None
            status = "not_evaluable_same_composite_claim"
        else:
            semantic_score = 0
            status = "reversed"
        order_decisions.append(
            {
                "pair_id": pair["pair_id"],
                "left_step_id": left,
                "right_step_id": right,
                "original_score": int(pair["score"]),
                "semantic_score": semantic_score,
                "status": status,
                "left_candidate_orders": left_positions,
                "right_candidate_orders": right_positions,
            }
        )

    frozen = {
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
    overlay = {
        "schema_version": "gpt55_action_order_semantic_rescore_overlay_v1",
        "source_queue_id": row["queue_id"],
        "source_run_sha256": row["run_sha256"],
        "source_score_provenance": row.get("score_provenance"),
        "phase": row["phase"],
        "replicate": row["replicate"],
        "stage": row["stage"],
        "chain_id": row["chain_id"],
        "instance_id": row["instance_id"],
        "frozen_component_scores": frozen,
        "action_decisions": decisions,
        "action_totals": {
            "denominator": len(decisions),
            "original_hits": sum(value["original_score"] for value in decisions),
            "semantic_hits": sum(value["semantic_score"] for value in decisions),
        },
        "order_decisions": order_decisions,
        "order_totals": {
            "all_gold_pair_denominator": len(order_decisions),
            "original_coverage_hits": sum(value["original_score"] for value in order_decisions),
            "conditional_evaluable_pairs": sum(
                value["semantic_score"] is not None for value in order_decisions
            ),
            "conditional_correct": sum(
                value["semantic_score"] == 1 for value in order_decisions
            ),
            "conditional_reversed": sum(
                value["semantic_score"] == 0 for value in order_decisions
            ),
            "not_evaluable_missing_or_merged": sum(
                value["semantic_score"] is None for value in order_decisions
            ),
        },
    }
    return overlay, changes


def ratio(hits: int, denominator: int) -> float | None:
    return hits / denominator if denominator else None


def aggregate(overlays: list[dict[str, Any]], selector: str) -> dict[str, Any]:
    rows = overlays if selector == "all" else [row for row in overlays if row["phase"] == selector]
    action_den = sum(row["action_totals"]["denominator"] for row in rows)
    action_old = sum(row["action_totals"]["original_hits"] for row in rows)
    action_new = sum(row["action_totals"]["semantic_hits"] for row in rows)
    pair_den = sum(row["order_totals"]["all_gold_pair_denominator"] for row in rows)
    pair_coverage = sum(row["order_totals"]["original_coverage_hits"] for row in rows)
    evaluable = sum(row["order_totals"]["conditional_evaluable_pairs"] for row in rows)
    correct = sum(row["order_totals"]["conditional_correct"] for row in rows)
    reversed_count = sum(row["order_totals"]["conditional_reversed"] for row in rows)
    not_evaluable = sum(row["order_totals"]["not_evaluable_missing_or_merged"] for row in rows)
    return {
        "run_count": len(rows),
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
            "ordered_pair_coverage_hits": pair_coverage,
            "ordered_pair_coverage_recall": ratio(pair_coverage, pair_den),
            "conditional_evaluable_pairs": evaluable,
            "conditional_correct": correct,
            "conditional_accuracy": ratio(correct, evaluable),
            "conditional_reversed": reversed_count,
            "not_evaluable_missing_or_merged": not_evaluable,
        },
    }


def percent(value: float | None) -> str:
    return "-" if value is None else f"{100 * value:.1f}%"


def report(summary: dict[str, Any], changes: list[dict[str, Any]]) -> str:
    lines = [
        "# GPT-5.5 96 PASS：行動・順序の意味クラス再採点",
        "",
        "作成日: 2026-08-14",
        "",
        "## 1. 結論",
        "",
        "主体・対象・critical evidenceの既存判定は変更せず、行動だけをログ根拠付きの共通行動クラスで再判定した。順序は、全Gold pairに対する復元範囲と、両端stepを復元した場合の順序正確性を分けた。",
        "",
        "行動は表現粒度の違いを吸収すると追加で復元扱いになる例がある。一方、順序の0の大半は逆順ではなく、pairの片方を復元していないために生じている。したがって、現在の結果を「順序を頻繁に間違える」と解釈するのは不正確である。",
        "",
        "## 2. 採点規則",
        "",
        "行動は、Gold stepとCLOUSEAU claimが既存の主体・対象等によって同じstepへalignmentされていることを前提に、operationを次の共通クラスへ正規化した。",
        "",
        "| 共通行動クラス | 許容する表現例 |",
        "|---|---|",
        "| `PROCESS_CREATE` | started、create_process、process_create、ACTION_CREATE_PROCESS |",
        "| `INPUT_USE` | document/script open、read、load、execution_input、batch execution |",
        "| `FILE_CREATE_WRITE` | create、write、materialize |",
        "| `REGISTRY_WRITE` | registry add、set、write |",
        "| `NETWORK_CONNECT` | connection create、connect |",
        "| `NETWORK_LISTEN` | listen、listener |",
        "",
        "同じクラスでも、主体・対象のalignmentがない近傍行動には得点を与えていない。process_createとscript実行、file writeとscript実行など、クラス自体が異なるものも不一致のままである。",
        "",
        "順序は、両端のGold stepが別々のcandidate claimとして特定できたpairだけを条件付き採点対象とした。片方が欠落したpairは逆順の0ではなく`not evaluable`とし、実際に右stepが先に出ている場合だけ逆順とした。従来の全Gold pairに対するcoverageも併記する。",
        "",
        "## 3. 集計結果",
        "",
        "| 対象 | 行動・従来 | 行動・意味クラス | 追加hit | 順序coverage | 条件付き順序正確性 | 逆順 | 欠落等で評価不能 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    labels = (("normal8", "正常"), ("attack8", "攻撃"), ("all", "全体"))
    for key, label in labels:
        value = summary["aggregates"][key]
        action = value["action"]
        order = value["order"]
        lines.append(
            "| {label} | {a0}/{ad}（{a0p}） | {a1}/{ad}（{a1p}） | +{add} | "
            "{oh}/{od}（{op}） | {oc}/{oe}（{oep}） | {rev} | {na} |".format(
                label=label,
                a0=action["original_hits"],
                a1=action["semantic_hits"],
                ad=action["denominator"],
                a0p=percent(action["original_recall"]),
                a1p=percent(action["semantic_recall"]),
                add=action["added_hits"],
                oh=order["ordered_pair_coverage_hits"],
                od=order["all_gold_pair_denominator"],
                op=percent(order["ordered_pair_coverage_recall"]),
                oc=order["conditional_correct"],
                oe=order["conditional_evaluable_pairs"],
                oep=percent(order["conditional_accuracy"]),
                rev=order["conditional_reversed"],
                na=order["not_evaluable_missing_or_merged"],
            )
        )
    lines.extend(
        [
            "",
            "`順序coverage`は従来指標と同じく、全Gold adjacent pairの両stepと順序を復元できた割合である。`条件付き順序正確性`は両stepを特定できたpairだけを分母にしており、純粋な並べ方の誤りを表す。両者は別の問いに答えるため、どちらか一方へ置き換えない。",
            "",
            "## 4. 行動判定が変わった主な型",
            "",
        ]
    )
    patterns = Counter(
        (
            str(row["gold_action"]),
            str((row.get("matched_candidate") or {}).get("candidate_operation")),
            str(row["gold_action_class"]),
        )
        for row in changes
    )
    lines.extend(
        [
            "| Gold表現 | CLOUSEAU表現 | 共通クラス | 変更件数 |",
            "|---|---|---|---:|",
        ]
    )
    for (gold_value, candidate, action_class), count in patterns.most_common():
        lines.append(
            f"| `{gold_value}` | `{candidate}` | `{action_class}` | {count} |"
        )
    lines.extend(
        [
            "",
            "## 5. 解釈上の注意",
            "",
            "この再採点はGoldを捨てた自由な意味採点ではない。既存alignmentとログ由来の行動クラスに制約し、明確に異なる行動へは得点を与えていない。主体・対象・critical evidenceの得点は元のままである。",
            "",
            "また、条件付き順序正確性が高くてもchain全体を復元できたことにはならない。step欠落は行動recallと順序coverageに残る。研究発表では、`stepをどこまで発見したか`と`発見したstepを正しく並べたか`を分けて説明する。",
            "",
            "## 6. 生成物",
            "",
            f"- 元スコア: `{relative(SOURCE)}`",
            f"- run別overlay: `{relative(OUT_ROWS)}`",
            f"- 行動変更一覧: `{relative(OUT_CHANGES)}`",
            f"- 集計JSON: `{relative(OUT_SUMMARY)}`",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    for path in (OUT_ROWS, OUT_CHANGES, OUT_SUMMARY, OUT_REPORT):
        if path.exists():
            raise FileExistsError(f"create-only refusal: {path}")

    source_rows = read_jsonl(SOURCE)
    if len(source_rows) != 96:
        raise ValueError(f"expected 96 source rows, got {len(source_rows)}")

    overlays: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    for row in source_rows:
        overlay, row_changes = rescore_row(row)
        overlays.append(overlay)
        changes.extend(row_changes)

    action_count = sum(len(row["action_decisions"]) for row in overlays)
    order_count = sum(len(row["order_decisions"]) for row in overlays)
    if action_count != 383:
        raise ValueError(f"expected 383 action decisions, got {action_count}")
    if order_count != 287:
        raise ValueError(f"expected 287 order decisions, got {order_count}")

    summary = {
        "schema_version": "gpt55_action_order_semantic_rescore_summary_v1",
        "source": relative(SOURCE),
        "source_sha256": sha256(SOURCE),
        "policy": {
            "subject_object_critical_evidence": "frozen from source scores",
            "action": "evidence-constrained canonical action-class equivalence on an existing aligned claim",
            "order_coverage": "original all-Gold-adjacent-pair score retained",
            "conditional_order": "score only pairs whose two endpoint Gold steps are located in candidate claims",
            "missing_endpoint_order_pair": "not evaluable, not reversed",
            "judge_api_calls": 0,
            "model_api_calls": 0,
        },
        "counts": {
            "runs": len(overlays),
            "action_decisions": action_count,
            "action_changes": len(changes),
            "order_decisions": order_count,
        },
        "aggregates": {
            key: aggregate(overlays, key) for key in ("normal8", "attack8", "all")
        },
        "action_change_patterns": [
            {
                "gold_action": gold_value,
                "candidate_operation": candidate,
                "canonical_class": action_class,
                "count": count,
            }
            for (gold_value, candidate, action_class), count in Counter(
                (
                    str(row["gold_action"]),
                    str((row.get("matched_candidate") or {}).get("candidate_operation")),
                    str(row["gold_action_class"]),
                )
                for row in changes
            ).most_common()
        ],
    }

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
    OUT_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    OUT_REPORT.write_text(report(summary, changes), encoding="utf-8")
    print(json.dumps(summary["aggregates"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
