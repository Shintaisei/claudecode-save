from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "current_experiment"
MAIN_ROOT = DOCS / "results_2026-08-02" / "gpt55_normal8_attack8_three_stage_budget10_pilot_01"
RETRY_ROOT = DOCS / "results_2026-08-03" / "gpt55_normal8_attack8_budget10_retry_01"

NORMAL_REPORT = DOCS / "gpt55_normal8_three_stage_codex_gpt56sol_results_20260803.json"
ATTACK_REPORT = DOCS / "gpt55_attack8_budget10_codex_gpt56sol_results_20260803.json"
NORMAL_BASELINE = DOCS / "normal8_two_model_three_stage_codex_sol_results_20260802.json"
ATTACK_BASELINE = DOCS / "attack8_two_model_three_stage_codex_sol_results_20260802.json"
EXPERIMENT_SUMMARY = MAIN_ROOT / "experiment_summary.json"
RETRY_SUMMARY = RETRY_ROOT / "retry_summary.json"

OUT_JSON = DOCS / "gpt55_normal_attack8_budget10_codex_gpt56sol_combined_results_20260803.json"
OUT_MD = DOCS / "gpt55_normal_attack8_budget10_codex_gpt56sol_combined_results_20260803.md"
RECONCILIATION_JSON = MAIN_ROOT / "final_composite_provenance_20260803.json"
FORMAL_ADDENDUM_JSON = MAIN_ROOT / "formal_scoring_addendum_20260803.json"

COUNT_FIELDS = (
    "gold_action_hits",
    "gold_action_denominator",
    "candidate_slot_tp",
    "candidate_slot_denominator",
    "behavior_step_hits",
    "behavior_step_denominator",
    "critical_evidence_hits",
    "critical_evidence_denominator",
    "order_pair_hits",
    "order_pair_denominator",
)


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ratio(hits: int, denominator: int) -> float | None:
    return hits / denominator if denominator else None


def with_ratios(counts: dict[str, Any]) -> dict[str, Any]:
    out = dict(counts)
    out.update(
        {
            "action_recall": ratio(out["gold_action_hits"], out["gold_action_denominator"]),
            "candidate_precision": ratio(out["candidate_slot_tp"], out["candidate_slot_denominator"]),
            "behavior_step_recall": ratio(out["behavior_step_hits"], out["behavior_step_denominator"]),
            "critical_evidence_recall": ratio(out["critical_evidence_hits"], out["critical_evidence_denominator"]),
            "order_recall": ratio(out["order_pair_hits"], out["order_pair_denominator"]),
        }
    )
    return out


def counts_from_normal(value: dict[str, Any]) -> dict[str, int]:
    return {field: int(value[field]) for field in COUNT_FIELDS}


def counts_from_attack(value: dict[str, Any]) -> dict[str, int]:
    return {field: int(value[field]) for field in COUNT_FIELDS}


def add_counts(*values: dict[str, int]) -> dict[str, int]:
    return {field: sum(value[field] for value in values) for field in COUNT_FIELDS}


def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {field: 0 for field in COUNT_FIELDS}
    for row in rows:
        for field in COUNT_FIELDS:
            counts[field] += int(row["totals"][field])
    counts["case_count"] = len(rows)
    return with_ratios(counts)


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.2f}%"


def num(value: float | int) -> str:
    return f"{value:,.0f}"


def usd(value: float) -> str:
    return f"${value:,.6f}"


def write_create_only(path: Path, text: str) -> None:
    payload = text.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        if path.read_bytes() != payload:
            raise RuntimeError(f"create-only conflict: {path}")
        print(f"REUSE {path.relative_to(ROOT)}")
        return
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    print(f"CREATED {path.relative_to(ROOT)}")


def main() -> None:
    normal = load(NORMAL_REPORT)
    attack = load(ATTACK_REPORT)
    normal_baseline = load(NORMAL_BASELINE)
    attack_baseline = load(ATTACK_BASELINE)
    experiment_summary = load(EXPERIMENT_SUMMARY)
    retry_summary = load(RETRY_SUMMARY)
    attack_resources = load(ROOT / attack["resource_comparison_file"])

    if normal["status"] != "PASS" or normal["cross_field_validation"]["status"] != "PASS":
        raise RuntimeError("normal scoring did not pass")
    if attack["validation"]["status"].lower() != "pass":
        raise RuntimeError("attack scoring did not pass")
    if retry_summary["status"] != "PASS":
        raise RuntimeError("normal Discord retry did not pass")

    normal_overall = with_ratios(counts_from_normal(normal["gpt55_metrics"]["overall"]))
    attack_overall = with_ratios(counts_from_attack(attack["headline_overall"]))
    combined_overall = with_ratios(add_counts(normal_overall, attack_overall))
    combined_overall["headline_run_count"] = 46

    by_domain = {
        "normal": {"headline_run_count": 24, **normal_overall},
        "attack": {"headline_run_count": 22, **attack_overall},
        "combined": combined_overall,
    }

    by_stage: dict[str, dict[str, Any]] = {}
    for stage in ("stage1", "stage2", "stage3"):
        stage_counts = add_counts(
            counts_from_normal(normal["gpt55_metrics"]["by_stage"][stage]),
            counts_from_attack(attack["by_stage"][stage]),
        )
        by_stage[stage] = with_ratios(stage_counts)
        by_stage[stage]["headline_run_count"] = 16 - (1 if stage in {"stage1", "stage3"} else 0)

    normal_comparison = normal["three_model_comparison"]["by_model"]
    attack_comparison = attack["comparison"]["matched_22_strata"]
    comparison_by_model: dict[str, dict[str, Any]] = {}
    for model in ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"):
        counts = add_counts(
            counts_from_normal(normal_comparison[model]),
            counts_from_attack(attack_comparison[model]),
        )
        comparison_by_model[model] = with_ratios(counts)
        comparison_by_model[model]["matched_run_count"] = 46

    excluded_instances = set(attack["budget_impact"]["excluded_instances"])
    stage_comparison: dict[str, dict[str, dict[str, Any]]] = {}
    normal_model_stage = normal_baseline["metrics"]["by_model_stage"]
    attack_rows = attack_baseline["rows"]
    for model in ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"):
        stage_comparison[model] = {}
        for stage in ("stage1", "stage2", "stage3"):
            if model == "gpt-5.5":
                normal_counts = counts_from_normal(normal["gpt55_metrics"]["by_stage"][stage])
                attack_counts = counts_from_attack(attack["by_stage"][stage])
            else:
                normal_counts = counts_from_normal(normal_model_stage[f"{model}/{stage}"])
                eligible_rows = [
                    row
                    for row in attack_rows
                    if row["model"] == model
                    and row["stage"] == stage
                    and row["instance_id"] not in excluded_instances
                ]
                attack_counts = counts_from_attack(aggregate_rows(eligible_rows))
            stage_comparison[model][stage] = with_ratios(add_counts(normal_counts, attack_counts))
            stage_comparison[model][stage]["matched_run_count"] = 16 - (
                1 if stage in {"stage1", "stage3"} else 0
            )

    resources_by_model: dict[str, dict[str, Any]] = {}
    for model in ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"):
        normal_resource = normal_comparison[model]
        attack_resource = attack_resources[model]
        resources_by_model[model] = {
            "matched_run_count": 46,
            "total_tokens": int(normal_resource["tokens"]) + int(attack_resource["total_tokens"]),
            "cost_usd": float(normal_resource["cost_usd"]) + float(attack_resource["cost_usd"]),
            "elapsed_seconds": float(normal_resource["elapsed_seconds"])
            + float(attack_resource["elapsed_seconds"]),
            "chief_leads": int(normal_resource["chief_leads"])
            + int(attack_resource["lead_call_count"]),
            "investigator_questions": int(normal_resource["investigator_questions"])
            + int(attack_resource["investigator_question_count"]),
            "sql_queries": int(normal_resource["sql_queries"]) + int(attack_resource["sql_query_count"]),
            "api_calls": (
                int(normal_resource["api_calls"]) + int(attack_resource["api_calls"])
                if "api_calls" in attack_resource
                else None
            ),
        }

    gpt55_valid_cost = resources_by_model["gpt-5.5"]["cost_usd"]
    censored_cost = float(attack["budget_impact"]["excluded_cost_usd"])
    ledger_recorded_cost = float(experiment_summary["cumulative_cost_usd"]) + float(
        retry_summary["retry_audit"]["cost_estimate"]["total_cost_usd"]
    )
    if abs((gpt55_valid_cost + censored_cost) - ledger_recorded_cost) > 1e-8:
        raise RuntimeError("cost reconciliation mismatch")

    by_case = {
        "normal": {
            case: with_ratios(counts_from_normal(value))
            for case, value in normal["gpt55_metrics"]["by_case"].items()
        },
        "attack": {
            case: with_ratios(counts_from_attack(value)) for case, value in attack["by_case"].items()
        },
    }

    source_hashes = {
        "normal_report_sha256": sha256(NORMAL_REPORT),
        "attack_report_sha256": sha256(ATTACK_REPORT),
        "experiment_summary_sha256": sha256(EXPERIMENT_SUMMARY),
        "retry_summary_sha256": sha256(RETRY_SUMMARY),
    }
    status_reconciliation = {
        "original_collection": {
            "expected_runs": 48,
            "original_status_counts": experiment_summary["status_counts"],
            "original_recorded_cost_usd": experiment_summary["cumulative_cost_usd"],
        },
        "effective_formal_population": {
            "pass": 46,
            "budget_censored": 2,
            "missing": 0,
            "normal_retry_adopted": True,
            "retry_status": retry_summary["status"],
            "censored_instances": attack["budget_impact"]["excluded_instances"],
        },
        "classification_rule": (
            "run_budget_guard.budget_censored=true is CENSORED even if the hard stop interrupts final JSON; "
            "it is retained but excluded from headline accuracy. Non-budget failures require a create-only retry."
        ),
        "recorded_cost": {
            "headline_valid_runs_usd": gpt55_valid_cost,
            "budget_censored_runs_usd": censored_cost,
            "effective_grid_total_usd": ledger_recorded_cost,
            "unfinalized_original_timeout_usage_included": False,
        },
        "source_hashes": source_hashes,
    }

    formal_addendum = {
        "schema_version": "atlasv2_gpt55_budget10_formal_scoring_addendum_v1",
        "status": "APPLIED_CREATE_ONLY",
        "experiment_contract": str((MAIN_ROOT / "experiment_contract.json").relative_to(ROOT)).replace("\\", "/"),
        "experiment_contract_sha256": sha256(MAIN_ROOT / "experiment_contract.json"),
        "reviewer": "independent Codex gpt-5.6-sol",
        "external_judge_api_used": False,
        "rubric": (
            "v5 atomic process-chain; subject/operation/object; fixed Gold and candidate slots; complete-three "
            "behavior; critical evidence separate; adjacent order pairs; PID and hidden alert mapping non-scoring"
        ),
        "inclusion": {
            "normal": "23 source PASS plus one create-only retry PASS",
            "attack": "22 non-censored PASS; two hard-budget-censored runs excluded",
            "matched_model_comparison": "same 46 eligible normal/attack case-stage strata for all three models",
        },
        "budget_policy": attack["formal_contract_addendum_proposal"]["proposed_clauses"],
        "fixed_denominator_totals": {
            key: combined_overall[key]
            for key in (
                "gold_action_denominator",
                "candidate_slot_denominator",
                "behavior_step_denominator",
                "critical_evidence_denominator",
                "order_pair_denominator",
            )
        },
        "artifacts": {
            "combined_json": str(OUT_JSON.relative_to(ROOT)).replace("\\", "/"),
            "combined_md": str(OUT_MD.relative_to(ROOT)).replace("\\", "/"),
            "normal_score_root": normal["formal_contract_append_proposal"]["proposed_append"]["formal_normal8_scoring"]["score_root"],
            "attack_score_root": str(
                (MAIN_ROOT / "attack8_scores_codex_gpt56sol_v5_atomic_v1_20260803").relative_to(ROOT)
            ).replace("\\", "/"),
            "reconciliation": str(RECONCILIATION_JSON.relative_to(ROOT)).replace("\\", "/"),
        },
        "source_hashes": source_hashes,
    }

    combined = {
        "schema_version": "gpt55_normal_attack8_budget10_codex_gpt56sol_combined_v1",
        "status": "PASS_WITH_BUDGET_CENSORING",
        "reviewer": "independent Codex gpt-5.6-sol",
        "external_judge_api_used": False,
        "population": {
            "collected_runs": 48,
            "headline_runs": 46,
            "normal_headline_runs": 24,
            "attack_headline_runs": 22,
            "budget_censored_runs": 2,
            "missing_runs": 0,
        },
        "headline": combined_overall,
        "by_domain": by_domain,
        "by_stage": by_stage,
        "by_case": by_case,
        "matched_three_model_comparison": comparison_by_model,
        "matched_three_model_stage_comparison": stage_comparison,
        "matched_resources_by_model": resources_by_model,
        "budget_impact": attack["budget_impact"],
        "recorded_cost_reconciliation": status_reconciliation["recorded_cost"],
        "retry": retry_summary,
        "status_reconciliation": status_reconciliation,
        "cross_field_validation": {
            "status": "PASS",
            "normal": normal["cross_field_validation"],
            "attack": attack["validation"],
            "combined_arithmetic": True,
            "cost_reconciliation": True,
        },
        "failure_analysis": {
            "normal": normal["diagnostics"],
            "attack": attack["failure_analysis"],
            "combined_interpretation": (
                "gpt-5.5 materially improves recall, complete behavior recovery, critical evidence, and order over "
                "the mini models. Precision improves less because it emits more nearby or over-connected slots. "
                "Attack Stage 1 remains the weakest eligible stage; Stage 2 is strongest."
            ),
        },
        "formal_addendum": str(FORMAL_ADDENDUM_JSON.relative_to(ROOT)).replace("\\", "/"),
        "source_hashes": source_hashes,
    }

    def metric_row(label: str, value: dict[str, Any]) -> str:
        return (
            f"| {label} | {value.get('headline_run_count', value.get('matched_run_count', ''))} | "
            f"{pct(value['action_recall'])} | {pct(value['candidate_precision'])} | "
            f"{pct(value['behavior_step_recall'])} | {pct(value['critical_evidence_recall'])} | "
            f"{pct(value['order_recall'])} |"
        )

    md: list[str] = [
        "# GPT-5.5 normal8 + attack8 budget-$10 formal results",
        "",
        "## 結論",
        "",
        "48試行を収集し、正常Discord Stage 2の非budget timeoutはcreate-only retryでPASSした。",
        "精度のheadlineは正常24件と攻撃22件の計46件である。攻撃2件はhard budgetで停止したため、",
        "ゼロ点にはせずbudget-censoredとして精度分母から除外した。欠測は0件で、Codex gpt-5.6-solによる",
        "v5 atomic採点と全cross-field監査はPASSした。OpenAI judge API/API scorerは使用していない。",
        "",
        "## 全体精度（headline eligible）",
        "",
        "| 範囲 | 試行 | Action recall | Candidate precision | 完全step | Critical evidence | Order recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
        metric_row("正常", by_domain["normal"]),
        metric_row("攻撃", by_domain["attack"]),
        metric_row("合計", by_domain["combined"]),
        "",
        "## Stage別（正常＋攻撃、gpt-5.5）",
        "",
        "| Stage | 試行 | Action recall | Candidate precision | 完全step | Critical evidence | Order recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for stage in ("stage1", "stage2", "stage3"):
        md.append(metric_row(stage.replace("stage", "Stage "), by_stage[stage]))

    md.extend(
        [
            "",
            "Stage 1が最弱で、Stage 2が最も高い。Stage 1/3は各1件がbudget-censoredのため15件、Stage 2は16件である。",
            "",
            "## 3モデル比較（同じ46 strata）",
            "",
            "| モデル | 試行 | Action recall | Candidate precision | 完全step | Critical evidence | Order recall |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"):
        md.append(metric_row(f"`{model}`", comparison_by_model[model]))

    md.extend(
        [
            "",
            "## モデル×Stage（同じeligible strata）",
            "",
            "| モデル | Stage | 試行 | Action recall | Precision | 完全step | Critical | Order |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"):
        for stage in ("stage1", "stage2", "stage3"):
            value = stage_comparison[model][stage]
            md.append(
                f"| `{model}` | {stage.replace('stage', 'Stage ')} | {value['matched_run_count']} | "
                f"{pct(value['action_recall'])} | {pct(value['candidate_precision'])} | "
                f"{pct(value['behavior_step_recall'])} | {pct(value['critical_evidence_recall'])} | "
                f"{pct(value['order_recall'])} |"
            )

    md.extend(
        [
            "",
            "## コスト・時間・探索量（同じ46 strata）",
            "",
            "| モデル | Tokens | Cost | Wall time | Chief leads | Investigator質問 | SQL queries |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for model in ("gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"):
        value = resources_by_model[model]
        md.append(
            f"| `{model}` | {num(value['total_tokens'])} | {usd(value['cost_usd'])} | "
            f"{value['elapsed_seconds'] / 3600:.2f}時間 | {num(value['chief_leads'])} | "
            f"{num(value['investigator_questions'])} | {num(value['sql_queries'])} |"
        )

    md.extend(
        [
            "",
            "gpt-5.5のheadline 46件は$171.880681、budget-censored 2件は$20.395164、",
            "retryを含む最終成果物ledger総額は$192.275845である。元の1800秒timeout試行はfinal ledgerを",
            "生成していないため、その未確定usageはこの額に含まれない。",
            "",
            "## Budget-censored 2件",
            "",
            "| 攻撃ケース | Stage | 記録cost | 扱い |",
            "|---|---:|---:|---|",
            "| `s4_pt_04_powershell_c1` | Stage 1 | $10.298952 | headline除外、凍結保持 |",
            "| `s4_pt_03_mshta_c1` | Stage 3 | $10.096212 | headline除外、凍結保持 |",
            "",
            "上限超過分は過剰請求ではなく、guard判定後に許可された最後のAPI callが閾値をまたいだ離散的overshootである。",
            "いずれも次の新規callは止まり、探索の暴走は$10付近で抑止できた。",
            "",
            "## ケース別（gpt-5.5）",
            "",
            "| 種別 | ケース | Action recall | Precision | 完全step | Critical | Order |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for domain in ("normal", "attack"):
        for case, value in by_case[domain].items():
            md.append(
                f"| {domain} | `{case}` | {pct(value['action_recall'])} | "
                f"{pct(value['candidate_precision'])} | {pct(value['behavior_step_recall'])} | "
                f"{pct(value['critical_evidence_recall'])} | {pct(value['order_recall'])} |"
            )

    md.extend(
        [
            "",
            "## 考察",
            "",
            "- gpt-5.5はmini 2モデルよりAction、完全step、Critical、Orderを大幅に改善した。特に正常ではOrder 84.44%、Critical 76.81%まで上昇した。",
            "- 攻撃はStage 1の初動復元が弱い一方、Stage 2/3ではprocess lineageと後続pivotの回収が大きく改善した。",
            "- Precisionの伸びはRecallほど大きくない。正常ではover-connected slot、攻撃ではnearby telemetryが主因である。",
            "- $10 guardは48件中2件で作動した。censored分を0点化せず除外したため、モデル精度と実行予算制約を混同していない。",
            "",
            "## 監査・成果物",
            "",
            f"- 正常詳細: `{NORMAL_REPORT.relative_to(ROOT).as_posix()}`",
            f"- 攻撃詳細: `{ATTACK_REPORT.relative_to(ROOT).as_posix()}`",
            f"- 統合JSON: `{OUT_JSON.relative_to(ROOT).as_posix()}`",
            f"- provenance reconciliation: `{RECONCILIATION_JSON.relative_to(ROOT).as_posix()}`",
            f"- formal addendum: `{FORMAL_ADDENDUM_JSON.relative_to(ROOT).as_posix()}`",
            "",
        ]
    )

    write_create_only(RECONCILIATION_JSON, json.dumps(status_reconciliation, ensure_ascii=False, indent=2) + "\n")
    write_create_only(FORMAL_ADDENDUM_JSON, json.dumps(formal_addendum, ensure_ascii=False, indent=2) + "\n")
    write_create_only(OUT_JSON, json.dumps(combined, ensure_ascii=False, indent=2) + "\n")
    write_create_only(OUT_MD, "\n".join(md))


if __name__ == "__main__":
    main()
