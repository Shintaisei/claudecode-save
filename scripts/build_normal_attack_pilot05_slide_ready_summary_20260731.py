from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


SOURCE = Path(
    "docs/current_experiment/"
    "normal_attack_full_ledger_pilot05_formal_results_20260730.json"
)
OUTPUT_JSON = Path(
    "docs/current_experiment/"
    "normal_attack_full_ledger_pilot05_slide_ready_summary_20260731.json"
)
OUTPUT_MD = Path(
    "docs/current_experiment/"
    "normal_attack_full_ledger_pilot05_slide_ready_summary_20260731.md"
)

CASE_LABELS = {
    "normal_chain10_gpt41": "正常: Discord Run-key",
    "attack_s4pt03_gpt41": "攻撃: mshta C1",
    "normal_chain02_gpt54": "正常: Python HTTP",
    "attack_s3pt01_gpt54": "攻撃: Word document",
}

RUN_CAUSES = {
    ("normal_chain10_gpt41", "stage1"): "近傍Discord処理へ漂流し、対象2 edgeを候補化できず",
    ("normal_chain10_gpt41", "stage2"): "process-create edgeをexecution_contextへ圧縮",
    ("normal_chain10_gpt41", "stage3"): "Actionは回収したが順序逆転・Gold外chain追加",
    ("attack_s4pt03_gpt41", "stage1"): "前半process edgeのみ、network・後段pivotを欠落",
    ("attack_s4pt03_gpt41", "stage2"): "exact-time 0件後、時間緩和pivotをせず早期停止",
    ("attack_s4pt03_gpt41", "stage3"): "450 callの過剰探索でも最終network edge以外をatomic化できず",
    ("normal_chain02_gpt54", "stage1"): "親子process-createをexecution_contextへ圧縮",
    ("normal_chain02_gpt54", "stage2"): "38秒前の別DNS chainを誤選択",
    ("normal_chain02_gpt54", "stage3"): "追加探索が誤ったDNS chainを精緻化",
    ("attack_s3pt01_gpt54", "stage1"): "msf.rtf openをprocess-startとして誤型付け",
    ("attack_s3pt01_gpt54", "stage2"): "同じ誤型付け＋Gold外一時file候補",
    ("attack_s3pt01_gpt54", "stage3"): "同じ誤型付け＋Gold外file/module候補増加",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metric_text(metric: dict, allow_na: bool = False) -> str:
    denominator = metric["denominator"]
    if denominator == 0 and allow_na:
        return "0/0 (n/a)"
    percentage = 0.0 if denominator == 0 else metric["value"] * 100
    return f"{metric['hits']}/{denominator} ({percentage:.2f}%)"


def sum_path(rows: list[dict], *path: str) -> float | int:
    total: float | int = 0
    for row in rows:
        value = row
        for key in path:
            value = value[key]
        total += value
    return total


def accuracy_columns(metrics: dict) -> list[str]:
    return [
        metric_text(metrics["action_recall"]),
        metric_text(metrics["candidate_precision"], allow_na=True),
        metric_text(metrics["behavior_step_recall"]),
        metric_text(metrics["critical_evidence_recall"]),
        metric_text(metrics["order_recall"]),
    ]


def main() -> None:
    for output in (OUTPUT_JSON, OUTPUT_MD):
        if output.exists():
            raise FileExistsError(f"create-only output already exists: {output}")

    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    runs = source["runs"]

    total_operational = {
        "run_count": len(runs),
        "wall_seconds": round(sum_path(runs, "operational", "elapsed_seconds"), 3),
        "api_calls": int(
            sum_path(runs, "operational", "total", "llm_api_call_count")
        ),
        "input_tokens": int(sum_path(runs, "operational", "total", "input_tokens")),
        "output_tokens": int(
            sum_path(runs, "operational", "total", "output_tokens")
        ),
        "cached_input_tokens": int(
            sum_path(runs, "operational", "total", "cached_input_tokens")
        ),
        "total_tokens": int(sum_path(runs, "operational", "total", "total_tokens")),
        "cost_usd": round(
            sum_path(runs, "operational", "total", "estimated_cost_usd"), 8
        ),
    }

    accuracy_by_model = {
        row["model"]: row["metrics"]
        for row in source["accuracy_aggregates"]["by_model"]
    }
    model_per_use_case = []
    for row in source["operational_aggregates"]["by_model"]:
        case_count = 2
        accuracy = accuracy_by_model[row["model"]]
        model_per_use_case.append(
            {
                "model": row["model"],
                "case_count": case_count,
                "runs_per_case": 3,
                "api_calls": row["llm_api_call_count"] / case_count,
                "input_tokens": row["input_tokens"] / case_count,
                "output_tokens": row["output_tokens"] / case_count,
                "cached_input_tokens": row["cached_input_tokens"] / case_count,
                "total_tokens": row["total_tokens"] / case_count,
                "cost_usd": row["estimated_cost_usd"] / case_count,
                "wall_seconds": row["elapsed_seconds"] / case_count,
                "accuracy_per_case_average": {
                    name: {
                        "hits": accuracy[name]["hits"] / case_count,
                        "denominator": accuracy[name]["denominator"] / case_count,
                        "value": accuracy[name]["value"],
                    }
                    for name in (
                        "action_recall",
                        "candidate_precision",
                        "behavior_step_recall",
                        "critical_evidence_recall",
                        "order_recall",
                    )
                },
            }
        )

    module_totals = []
    for role in ("chief", "investigator", "sql_qa"):
        module = {
            "role": role,
            "api_calls": int(
                sum_path(
                    runs, "operational", "roles", role, "llm_api_call_count"
                )
            ),
            "input_tokens": int(
                sum_path(runs, "operational", "roles", role, "input_tokens")
            ),
            "output_tokens": int(
                sum_path(runs, "operational", "roles", role, "output_tokens")
            ),
            "cached_input_tokens": int(
                sum_path(
                    runs,
                    "operational",
                    "roles",
                    role,
                    "cached_input_tokens",
                )
            ),
            "total_tokens": int(
                sum_path(runs, "operational", "roles", role, "total_tokens")
            ),
            "llm_seconds": round(
                sum_path(
                    runs,
                    "operational",
                    "roles",
                    role,
                    "llm_api_duration_seconds_sum",
                ),
                3,
            ),
            "cost_usd": round(
                sum_path(
                    runs,
                    "operational",
                    "roles",
                    role,
                    "estimated_cost_usd",
                ),
                8,
            ),
        }
        module["api_call_share"] = module["api_calls"] / total_operational["api_calls"]
        module["token_share"] = module["total_tokens"] / total_operational["total_tokens"]
        module["cost_share"] = module["cost_usd"] / total_operational["cost_usd"]
        module_totals.append(module)

    trial_ledgers = []
    module_ledgers = []
    for run in runs:
        total = run["operational"]["total"]
        trial_ledgers.append(
            {
                "pair_id": run["pair_id"],
                "case_label": CASE_LABELS[run["pair_id"]],
                "scenario_group": run["scenario_group"],
                "model": run["model"],
                "stage": run["stage"],
                "input_tokens": total["input_tokens"],
                "output_tokens": total["output_tokens"],
                "cached_input_tokens": total["cached_input_tokens"],
                "total_tokens": total["total_tokens"],
                "api_calls": total["llm_api_call_count"],
                "chief_api_calls": run["operational"]["roles"]["chief"][
                    "llm_api_call_count"
                ],
                "investigator_api_calls": run["operational"]["roles"][
                    "investigator"
                ]["llm_api_call_count"],
                "sql_qa_api_calls": run["operational"]["roles"]["sql_qa"][
                    "llm_api_call_count"
                ],
                "cost_usd": total["estimated_cost_usd"],
                "wall_seconds": run["operational"]["elapsed_seconds"],
                "accuracy": run["accuracy"],
                "primary_failure_cause": RUN_CAUSES[
                    (run["pair_id"], run["stage"])
                ],
            }
        )
        for role in ("chief", "investigator", "sql_qa"):
            module = run["operational"]["roles"][role]
            module_ledgers.append(
                {
                    "pair_id": run["pair_id"],
                    "case_label": CASE_LABELS[run["pair_id"]],
                    "model": run["model"],
                    "stage": run["stage"],
                    "role": role,
                    "api_calls": module["llm_api_call_count"],
                    "input_tokens": module["input_tokens"],
                    "output_tokens": module["output_tokens"],
                    "cached_input_tokens": module["cached_input_tokens"],
                    "total_tokens": module["total_tokens"],
                    "llm_seconds": module["llm_api_duration_seconds_sum"],
                    "cost_usd": module["estimated_cost_usd"],
                }
            )

    causes = {
        "tag_counts_are_overlapping": True,
        "causal_edge_missing_runs": sum(
            bool(run["failure_analysis"]["causal_edge_missing"]) for run in runs
        ),
        "nearby_behavior_overconnection_runs": sum(
            bool(run["failure_analysis"]["nearby_behavior_overconnection"])
            for run in runs
        ),
        "hallucination_tagged_runs": sum(
            bool(run["failure_analysis"]["hallucination"]) for run in runs
        ),
        "early_stop_runs": sum(
            bool(run["failure_analysis"]["early_stop"]) for run in runs
        ),
        "critical_evidence_miss": {
            "hits": source["accuracy_aggregates"]["overall"][
                "critical_evidence_hits"
            ],
            "denominator": source["accuracy_aggregates"]["overall"][
                "critical_evidence_denominator"
            ],
        },
        "false_positive_slot_types": source["accuracy_aggregates"]["overall"][
            "false_positive_types"
        ],
        "root_cause_interpretation": [
            {
                "axis": "process-instance selection",
                "evidence": "Python HTTP Stage 2/3はtargetの38秒前にある別DNS chainを選択し、追加探索も誤系列を詳細化した。",
            },
            {
                "axis": "causal frontier / downstream pivot",
                "evidence": "mshta chainはPowerShell・cmd・payloadを発見しても次の親として再帰pivotできず、後段edgeを失った。",
            },
            {
                "axis": "evidence-to-atomic-action mapping",
                "evidence": "Wordのmsf.rtf openやPython/Discordのprocess-createがexecution_contextまたは別operationへ圧縮された。",
            },
            {
                "axis": "candidate admission",
                "evidence": "観測済みだがGold外のfile/module/update activityを主要候補へ昇格し、precisionを下げた。",
            },
            {
                "axis": "critical-evidence binding",
                "evidence": "行動の意味を部分的に復元してもcanonical row/action/targetへ束縛できず、48/48 evidenceを失った。",
            },
            {
                "axis": "stopping",
                "evidence": "明確な早期停止は1/12であり、全体低精度を回数制限だけでは説明できない。",
            },
        ],
    }

    audit_failures = []
    if len(runs) != 12:
        audit_failures.append("run count is not 12")
    if sum(row["api_calls"] for row in module_totals) != total_operational["api_calls"]:
        audit_failures.append("module API calls do not sum to total")
    if sum(row["total_tokens"] for row in module_totals) != total_operational["total_tokens"]:
        audit_failures.append("module tokens do not sum to total")
    if abs(sum(row["cost_usd"] for row in module_totals) - total_operational["cost_usd"]) > 1e-8:
        audit_failures.append("module cost does not sum to total")
    if source["audits"]["operational"]["status"] != "PASS":
        audit_failures.append("source operational audit is not PASS")
    if source["audits"]["accuracy"]["status"] != "PASS":
        audit_failures.append("source accuracy audit is not PASS")
    if source["external_judge_api_used"]:
        audit_failures.append("external judge API flag is true")

    payload = {
        "schema_version": "normal_attack_pilot05_slide_ready_summary_v1",
        "source_formal_results": str(SOURCE),
        "source_formal_results_sha256": sha256(SOURCE),
        "communication_job": (
            "研究発表の聴衆が、pilot05の全体性能とコストを把握し、"
            "低精度の主因が単純な探索回数不足ではなく、process選択・因果pivot・"
            "atomic候補化・critical evidence束縛にあると理解できること。"
        ),
        "overall_operational": total_operational,
        "model_per_use_case": model_per_use_case,
        "module_totals": module_totals,
        "accuracy": {
            "overall": source["accuracy_aggregates"]["overall"],
            "by_scenario_group": source["accuracy_aggregates"][
                "by_scenario_group"
            ],
            "by_case": source["accuracy_aggregates"]["by_case"],
            "by_stage": source["accuracy_aggregates"]["by_stage"],
            "by_model_stage": source["accuracy_aggregates"]["by_model_stage"],
        },
        "cause_summary": causes,
        "trial_ledgers": trial_ledgers,
        "module_ledgers": module_ledgers,
        "audit": {
            "status": "PASS" if not audit_failures else "FAIL",
            "failures": audit_failures,
            "trial_count": len(trial_ledgers),
            "module_row_count": len(module_ledgers),
            "external_judge_api_used": False,
        },
    }
    if audit_failures:
        raise ValueError(audit_failures)

    overall_accuracy = source["accuracy_aggregates"]["overall"]
    lines = [
        "# pilot05 研究発表用サマリ",
        "",
        "## Slide 1 — 12試行の全体像",
        "",
        "**中心メッセージ：全体Action recallは24.31%。費用は$2.89、逐次実行時間は79.83分だった。**",
        "",
        "| Runs | API calls | Input | Output | Cached input | Total tokens | Cost | Wall time |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {total_operational['run_count']} | {total_operational['api_calls']:,} | "
            f"{total_operational['input_tokens']:,} | {total_operational['output_tokens']:,} | "
            f"{total_operational['cached_input_tokens']:,} | {total_operational['total_tokens']:,} | "
            f"${total_operational['cost_usd']:.6f} | "
            f"{total_operational['wall_seconds'] / 60:.2f} min |"
        ),
        "",
        "| Action recall | Candidate precision | Complete step | Critical evidence | Order |",
        "|---:|---:|---:|---:|---:|",
        "| " + " | ".join(accuracy_columns(overall_accuracy)) + " |",
        "",
        "注：モデルごとに異なる2ケースを担当しているため、モデル値はケース難易度を統制した直接比較ではない。",
    ]
    lines.extend(
        [
            "",
            "### モデル別・1ユースケース当たり（Stage 1〜3の1セット）",
            "",
            "| Model | API calls | Input | Output | Cached | Total tokens | Cost | Wall min |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in model_per_use_case:
        lines.append(
            f"| {row['model']} | {row['api_calls']:,.1f} | "
            f"{row['input_tokens']:,.1f} | {row['output_tokens']:,.1f} | "
            f"{row['cached_input_tokens']:,.1f} | {row['total_tokens']:,.1f} | "
            f"${row['cost_usd']:.6f} | {row['wall_seconds'] / 60:.2f} |"
        )
    lines.extend(
        [
            "",
            "| Model | Action recall | Precision | Complete step | Critical evidence | Order |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in model_per_use_case:
        metrics = row["accuracy_per_case_average"]
        lines.append(
            f"| {row['model']} | "
            + " | ".join(
                [
                    metric_text(metrics["action_recall"]),
                    metric_text(metrics["candidate_precision"]),
                    metric_text(metrics["behavior_step_recall"]),
                    metric_text(metrics["critical_evidence_recall"]),
                    metric_text(metrics["order_recall"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "精度の割合は2ケースのmicro-averageであり、分子・分母だけを2で割って1ケース当たり平均として表示した。",
            "",
            "## Slide 2 — SQL QAが処理量と費用の約7割を占める",
            "",
            "| Module | API calls | Call share | Total tokens | Token share | LLM sec | Cost | Cost share |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for module in module_totals:
        lines.append(
            f"| {module['role']} | {module['api_calls']:,} | "
            f"{module['api_call_share'] * 100:.2f}% | {module['total_tokens']:,} | "
            f"{module['token_share'] * 100:.2f}% | {module['llm_seconds']:.3f} | "
            f"${module['cost_usd']:.6f} | {module['cost_share'] * 100:.2f}% |"
        )

    lines.extend(
        [
            "",
            "Cached inputはinput tokenの内数であり、Total tokensへ二重加算していない。ModuleのLLM secはAPI call所要時間の合計で、試行wall timeとは定義が異なる。",
            "",
            "## Slide 3 — 未取得の主因は探索回数より「edge化と候補化」",
            "",
            f"- Gold action miss: {overall_accuracy['gold_action_denominator'] - overall_accuracy['gold_action_hits']}/{overall_accuracy['gold_action_denominator']}",
            f"- 完全step miss: {overall_accuracy['behavior_step_denominator'] - overall_accuracy['behavior_step_hits']}/{overall_accuracy['behavior_step_denominator']}",
            f"- Critical evidence miss: {overall_accuracy['critical_evidence_denominator'] - overall_accuracy['critical_evidence_hits']}/{overall_accuracy['critical_evidence_denominator']}",
            f"- Order miss: {overall_accuracy['order_pair_denominator'] - overall_accuracy['order_pair_hits']}/{overall_accuracy['order_pair_denominator']}",
            f"- Causal edge欠落タグ: {causes['causal_edge_missing_runs']}/12 run",
            f"- 近傍行動の過剰接続: {causes['nearby_behavior_overconnection_runs']}/12 run",
            f"- 幻覚・未裏付け証拠タグ: {causes['hallucination_tagged_runs']}/12 run",
            f"- 明確な早期停止: {causes['early_stop_runs']}/12 run",
            "",
            "原因タグは重複する。早期停止は1件だけであり、低精度を単純な回数制限では説明できない。",
            "",
            "## Slide 4 — 4ユースケースで異なる失敗パターンが現れた",
            "",
            "| Group | Model | Use case | Action recall | Precision | Complete step | Critical | Order |",
            "|---|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in source["accuracy_aggregates"]["by_case"]:
        metrics = row["metrics"]
        lines.append(
            f"| {row['scenario_group']} | {row['model']} | "
            f"{CASE_LABELS[row['pair_id']]} | "
            + " | ".join(accuracy_columns(metrics))
            + " |"
        )

    lines.extend(
        [
            "",
            "- Discord：Stage進行でrecallは回復したが、順序逆転とGold外候補でprecisionが低い。",
            "- mshta：長い後段chainへのrecursive pivot不足。大量探索でもedge coverageが増えない。",
            "- Python HTTP：初回に別process instanceを選ぶと、後続探索が誤系列を精緻化した。",
            "- Word：core 2-stepは安定したが、文書openの誤型付けとGold外候補追加でprecisionが低下。",
            "",
            "## Slide 5 — Stage 1が最も安定し、Stage 3はRecallとPrecisionがトレードオフ",
            "",
            "| Stage | Action recall | Precision | Complete step | Critical | Order |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in source["accuracy_aggregates"]["by_stage"]:
        lines.append(
            f"| {row['stage']} | " + " | ".join(accuracy_columns(row["metrics"])) + " |"
        )

    lines.extend(
        [
            "",
            "Stage 2はexact-time検索後の早期停止と誤process選択の影響を受けた。Stage 3は完全stepが回復した一方、candidate slotが57まで増え、precisionは22.81%へ低下した。",
            "",
            "## Slide 6 — モデル×Stage値はケース割当を含む記述統計",
            "",
            "| Model | Stage | Action recall | Precision | Complete step | Critical | Order |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in source["accuracy_aggregates"]["by_model_stage"]:
        lines.append(
            f"| {row['model']} | {row['stage']} | "
            + " | ".join(accuracy_columns(row["metrics"]))
            + " |"
        )

    lines.extend(
        [
            "",
            "4.1-miniは11 Gold step/Stage、5.4-miniは5 Gold step/Stageを担当する。真のモデル比較には、両モデルを4ケースすべてで実行する24試行が必要である。",
            "",
            "## Slide 7 — 原因を6つのモジュール改善軸へ変換する",
            "",
            "| 原因 | 観測 | 改善軸 |",
            "|---|---|---|",
            "| Process-instance選択 | Python HTTP Stage 2/3で38秒前の別chainを選択 | anchor再検証・PID+時刻instance gate |",
            "| Downstream pivot | mshtaでPowerShell以降のedgeを失う | typed unresolved-frontier ledger |",
            "| Atomic action化 | 親子edgeや文書openをexecution_contextへ圧縮 | subject/operation/object正規化器 |",
            "| Candidate admission | Gold外file/moduleを主要chainへ昇格 | evidence-backedかつchain-relevant admission gate |",
            "| Critical evidence束縛 | 0/48 | canonical row/action/target binder |",
            "| Stop判定 | exact-time 0件後に1 runだけ早期停止 | 0件時の時間緩和・代替pivot必須化 |",
            "",
            "## Slide 8 — 次の実験で切り分けるべきこと",
            "",
            "1. 同一4ケースを両モデルで実行し、ケース難易度を統制する。",
            "2. Anchor validation、typed edge ledger、candidate admissionを独立A/Bする。",
            "3. Critical evidence binderはchain reconstructionと別指標で改善する。",
            "4. API回数ではなく、Gold edge到達率・誤instance滞在率・Gold外candidate率を中間KPIにする。",
            "",
            "# Appendix A — 試行別 total ledger",
            "",
            "| Case | Model | Stage | Input | Output | Cached | Total | Calls | Chief | Inv | SQL | Cost | Wall min |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in trial_ledgers:
        lines.append(
            f"| {row['case_label']} | {row['model']} | {row['stage']} | "
            f"{row['input_tokens']:,} | {row['output_tokens']:,} | "
            f"{row['cached_input_tokens']:,} | {row['total_tokens']:,} | "
            f"{row['api_calls']:,} | {row['chief_api_calls']:,} | "
            f"{row['investigator_api_calls']:,} | {row['sql_qa_api_calls']:,} | "
            f"${row['cost_usd']:.6f} | {row['wall_seconds'] / 60:.2f} |"
        )

    lines.extend(
        [
            "",
            "# Appendix B — 試行・モジュール別 ledger",
            "",
            "| Case | Model | Stage | Module | Calls | Input | Output | Cached | Total | LLM sec | Cost |",
            "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in module_ledgers:
        lines.append(
            f"| {row['case_label']} | {row['model']} | {row['stage']} | "
            f"{row['role']} | {row['api_calls']:,} | {row['input_tokens']:,} | "
            f"{row['output_tokens']:,} | {row['cached_input_tokens']:,} | "
            f"{row['total_tokens']:,} | {row['llm_seconds']:.3f} | "
            f"${row['cost_usd']:.6f} |"
        )

    lines.extend(
        [
            "",
            "# Appendix C — 試行別の主原因",
            "",
            "| Case | Model | Stage | Action recall | Primary cause |",
            "|---|---|---|---:|---|",
        ]
    )
    for row in trial_ledgers:
        lines.append(
            f"| {row['case_label']} | {row['model']} | {row['stage']} | "
            f"{metric_text(row['accuracy']['action_recall'])} | "
            f"{row['primary_failure_cause']} |"
        )

    lines.extend(
        [
            "",
            "# Method notes",
            "",
            "- Costはfull-pipeline per-call ledgerから算出し、Chief・Investigator・SQL QAをすべて含む。",
            "- Total tokensはinput+output。Cached inputはinputの内数。",
            "- Module LLM secは各roleのAPI latency合計。Wall minは試行全体の経過時間。",
            "- Accuracyはv5 atomic rubric。PIDとhidden alert mappingは非採点、critical evidenceとorderは別判定。",
            "- gpt-4.1-mini / Discord Stage 3は修正前TEMP VIEW wrapperの共通guard迂回を含む既知の技術的交絡であり、完了済みthoughtを1回だけ採用して再実行していない。",
            "- OpenAI judge API/API scorerは不使用。",
            "- Operational audit / accuracy audit: PASS。",
            "",
            f"機械可読JSON：`{OUTPUT_JSON}`",
        ]
    )

    OUTPUT_JSON.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    OUTPUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(OUTPUT_JSON.resolve())
    print(OUTPUT_MD.resolve())


if __name__ == "__main__":
    main()
