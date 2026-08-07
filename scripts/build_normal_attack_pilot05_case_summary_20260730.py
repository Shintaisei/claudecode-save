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
    "normal_attack_full_ledger_pilot05_case_summary_20260730.json"
)
OUTPUT_MD = Path(
    "docs/current_experiment/"
    "normal_attack_full_ledger_pilot05_case_summary_20260730.md"
)


CASE_META = {
    "normal_chain10_gpt41": {
        "case_name": "Discord Run-key registry chain",
        "chain_id": "chain_10_e07_discord_run_key_registry_chain",
        "discussion": (
            "Stage 1は近傍のDiscord関連処理へ漂流して0点、Stage 2はRun値書込み、"
            "Stage 3は2 Gold stepのaction componentを回収した。ただしStage 3は順序を"
            "逆転し、近傍update/setup/firefox chainを候補化したため、3 Stage合算では"
            "recall 50%に対してprecision 23.08%、order 0%となった。探索量を増やすと"
            "action recallは上がったが、候補採用と順序制御が追いついていない。"
        ),
        "technical_note": (
            "Stage 3の完了済みthoughtには修正前TEMP VIEW wrapperによる共通guard迂回が"
            "あり、再実行せず技術的交絡として扱う。"
        ),
    },
    "attack_s4pt03_gpt41": {
        "case_name": "mshta C1 multi-stage attack chain",
        "chain_id": "s4_pt_03_mshta_c1",
        "discussion": (
            "9 stepの長いchainに対し、Stage 1は前半のprocess edgeを部分取得、Stage 2は"
            "exact-time queryが0件の後に早期停止、Stage 3は450 LLM callを使いながら"
            "最終payload network edgeだけを完全取得した。3 Stage合算Action recallは"
            "12.35%、完全stepは7.41%である。問題は単純な探索回数不足ではなく、発見した"
            "PowerShell/cmd/payloadを次の親として因果pivotし、atomic edgeへ変換する機構にある。"
        ),
        "technical_note": None,
    },
    "normal_chain02_gpt54": {
        "case_name": "Python SimpleHTTPServer network chain",
        "chain_id": "chain_02_e01_python_simplehttpserver_network_chain",
        "discussion": (
            "Stage 1はtarget chainの中央stepを完全取得したが、親子process-createを"
            "execution_contextへ埋め込み、3 step中1 stepに留まった。Stage 2/3はtargetの"
            "38秒前にあるDNS packet-capture chainを選び、追加探索も誤ったprocess instanceを"
            "詳細化したため0点だった。3 Stage合算Action recall/precisionはともに14.81%。"
            "初回process-instance選択を検証するcheckpointが最優先の改善点である。"
        ),
        "technical_note": None,
    },
    "attack_s3pt01_gpt54": {
        "case_name": "Word document processing",
        "chain_id": "s3_pt_01_word_document_processing",
        "discussion": (
            "全StageでWINWORD→WINWORD /Embeddingは完全取得し、Action recall 66.67%、"
            "order 100%を安定して維持した。一方、msf.rtfのpathを取得しても文書openを"
            "process createとして候補化し、critical evidenceも採用できなかった。Stageが"
            "進むほどGold外の一時file/module activityが増え、precisionは66.67%→44.44%→"
            "26.67%へ低下した。検索不足ではなく、event-to-action正規化とcandidate admissionの問題である。"
        ),
        "technical_note": None,
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sum_field(rows: list[dict], *path: str) -> float | int:
    total: float | int = 0
    for row in rows:
        value = row
        for key in path:
            value = value[key]
        total += value
    return total


def metric_text(metric: dict, allow_na: bool = False) -> str:
    denominator = metric["denominator"]
    if denominator == 0 and allow_na:
        return "0/0 (n/a)"
    value = 0.0 if denominator == 0 else metric["value"] * 100
    return f"{metric['hits']}/{denominator} ({value:.2f}%)"


def case_operational(runs: list[dict]) -> dict:
    role_summary = {}
    for role in ("chief", "investigator", "sql_qa"):
        role_summary[role] = {
            "api_calls": int(
                sum_field(runs, "operational", "roles", role, "llm_api_call_count")
            ),
            "llm_seconds": round(
                sum_field(
                    runs,
                    "operational",
                    "roles",
                    role,
                    "llm_api_duration_seconds_sum",
                ),
                3,
            ),
            "cost_usd": round(
                sum_field(
                    runs, "operational", "roles", role, "estimated_cost_usd"
                ),
                8,
            ),
        }
    return {
        "wall_seconds": round(sum_field(runs, "operational", "elapsed_seconds"), 3),
        "api_calls": int(
            sum_field(runs, "operational", "total", "llm_api_call_count")
        ),
        "input_tokens": int(sum_field(runs, "operational", "total", "input_tokens")),
        "output_tokens": int(
            sum_field(runs, "operational", "total", "output_tokens")
        ),
        "cached_input_tokens": int(
            sum_field(runs, "operational", "total", "cached_input_tokens")
        ),
        "cost_usd": round(
            sum_field(runs, "operational", "total", "estimated_cost_usd"), 8
        ),
        "chief_leads": int(
            sum_field(runs, "operational", "total", "chief_lead_count")
        ),
        "investigator_questions": int(
            sum_field(
                runs, "operational", "total", "investigator_question_count"
            )
        ),
        "sql_queries": int(
            sum_field(runs, "operational", "total", "sql_query_count")
        ),
        "lead_guard_triggers": int(
            sum_field(
                runs, "operational", "total", "lead_guard_trigger_count"
            )
        ),
        "roles": role_summary,
    }


def main() -> None:
    for output in (OUTPUT_JSON, OUTPUT_MD):
        if output.exists():
            raise FileExistsError(f"create-only output already exists: {output}")

    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    accuracy_by_case = {
        row["pair_id"]: row for row in source["accuracy_aggregates"]["by_case"]
    }
    runs_by_case: dict[str, list[dict]] = {}
    for run in source["runs"]:
        runs_by_case.setdefault(run["pair_id"], []).append(run)

    cases = []
    for pair_id in CASE_META:
        runs = sorted(runs_by_case[pair_id], key=lambda row: row["stage"])
        accuracy = accuracy_by_case[pair_id]["metrics"]
        stage_rows = []
        for run in runs:
            stage_rows.append(
                {
                    "stage": run["stage"],
                    "accuracy": run["accuracy"],
                    "operational": {
                        "wall_seconds": run["operational"]["elapsed_seconds"],
                        **run["operational"]["total"],
                    },
                    "review_summary_ja": run["review_summary_ja"],
                }
            )
        cases.append(
            {
                "pair_id": pair_id,
                "scenario_group": accuracy_by_case[pair_id]["scenario_group"],
                "model": accuracy_by_case[pair_id]["model"],
                **CASE_META[pair_id],
                "three_stage_accuracy": accuracy,
                "three_stage_operational": case_operational(runs),
                "stage_results": stage_rows,
            }
        )

    expected_pairs = set(CASE_META)
    observed_pairs = set(runs_by_case)
    denominator_totals = {
        name: sum(case["three_stage_accuracy"][name] for case in cases)
        for name in (
            "gold_action_denominator",
            "candidate_slot_denominator",
            "behavior_step_denominator",
            "critical_evidence_denominator",
            "order_pair_denominator",
        )
    }
    overall = source["accuracy_aggregates"]["overall"]
    expected_denominators = {
        name: overall[name] for name in denominator_totals
    }
    audit_failures = []
    if observed_pairs != expected_pairs:
        audit_failures.append(
            f"pair coverage mismatch: observed={sorted(observed_pairs)}"
        )
    if any(len(runs_by_case[pair_id]) != 3 for pair_id in expected_pairs):
        audit_failures.append("not every case has exactly three Stage runs")
    if denominator_totals != expected_denominators:
        audit_failures.append("case denominator totals do not equal formal overall")
    if source["external_judge_api_used"]:
        audit_failures.append("external judge API flag is true")

    payload = {
        "schema_version": "normal_attack_pilot05_case_summary_v1",
        "source_formal_results": str(SOURCE),
        "source_formal_results_sha256": sha256(SOURCE),
        "scope": {
            "normal_case_count": 2,
            "attack_case_count": 2,
            "stages_per_case": 3,
            "run_count": 12,
        },
        "scenario_two_case_accuracy": source["accuracy_aggregates"][
            "by_scenario_group"
        ],
        "cases": cases,
        "audit": {
            "status": "PASS" if not audit_failures else "FAIL",
            "pair_run_counts": dict(
                sorted(
                    Counter(run["pair_id"] for run in source["runs"]).items()
                )
            ),
            "case_denominator_totals": denominator_totals,
            "formal_overall_denominators": expected_denominators,
            "failures": audit_failures,
            "external_judge_api_used": False,
        },
    }
    if audit_failures:
        raise ValueError(audit_failures)

    lines = [
        "# pilot05 ユースケース別精度・考察",
        "",
        "正常2ユースケース、攻撃2ユースケースについて、各3 Stageを合算した精度と調査コストをケース単位で示す。",
        "モデルごとにケース割当が異なるため、ケース難易度を統制したモデル間比較ではない。",
        "",
        "## 正常2ケース・攻撃2ケース合算",
        "",
        "| group | Action recall | Candidate precision | Complete step | Critical evidence | Order |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for group in source["accuracy_aggregates"]["by_scenario_group"]:
        metrics = group["metrics"]
        lines.append(
            "| {group} | {action} | {precision} | {step} | {critical} | {order} |".format(
                group=group["scenario_group"],
                action=metric_text(metrics["action_recall"]),
                precision=metric_text(metrics["candidate_precision"], allow_na=True),
                step=metric_text(metrics["behavior_step_recall"]),
                critical=metric_text(metrics["critical_evidence_recall"]),
                order=metric_text(metrics["order_recall"]),
            )
        )

    lines.extend(
        [
            "",
            "## 4ユースケース個別集計",
            "",
            "| group | model | case | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for case in cases:
        metrics = case["three_stage_accuracy"]
        operational = case["three_stage_operational"]
        lines.append(
            "| {group} | {model} | `{case_id}` | {action} | {precision} | {step} | {critical} | {order} | {calls:,} | ${cost:.6f} | {wall:.2f} |".format(
                group=case["scenario_group"],
                model=case["model"],
                case_id=case["chain_id"],
                action=metric_text(metrics["action_recall"]),
                precision=metric_text(metrics["candidate_precision"], allow_na=True),
                step=metric_text(metrics["behavior_step_recall"]),
                critical=metric_text(metrics["critical_evidence_recall"]),
                order=metric_text(metrics["order_recall"]),
                calls=operational["api_calls"],
                cost=operational["cost_usd"],
                wall=operational["wall_seconds"] / 60,
            )
        )

    for case in cases:
        lines.extend(
            [
                "",
                f"## {case['case_name']}",
                "",
                f"- group: `{case['scenario_group']}`",
                f"- model: `{case['model']}`",
                f"- chain: `{case['chain_id']}`",
                "",
                "| Stage | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for stage in case["stage_results"]:
            metrics = stage["accuracy"]
            operational = stage["operational"]
            lines.append(
                "| {stage} | {action} | {precision} | {step} | {critical} | {order} | {calls:,} | ${cost:.6f} | {wall:.2f} |".format(
                    stage=stage["stage"],
                    action=metric_text(metrics["action_recall"]),
                    precision=metric_text(metrics["candidate_precision"], allow_na=True),
                    step=metric_text(metrics["behavior_step_recall"]),
                    critical=metric_text(metrics["critical_evidence_recall"]),
                    order=metric_text(metrics["order_recall"]),
                    calls=operational["llm_api_call_count"],
                    cost=operational["estimated_cost_usd"],
                    wall=operational["wall_seconds"] / 60,
                )
            )
        lines.extend(["", case["discussion"]])
        if case["technical_note"]:
            lines.extend(["", f"注記：{case['technical_note']}"])
        lines.extend(
            [
                "",
                "役割別3 Stage合算：",
                "",
                "| role | API calls | LLM sec | Cost |",
                "|---|---:|---:|---:|",
            ]
        )
        for role, role_metrics in case["three_stage_operational"]["roles"].items():
            lines.append(
                f"| {role} | {role_metrics['api_calls']:,} | "
                f"{role_metrics['llm_seconds']:.3f} | "
                f"${role_metrics['cost_usd']:.6f} |"
            )

    lines.extend(
        [
            "",
            "## 横断考察",
            "",
            "- 長いattack chainでは、API callを増やすだけでは後段recallは改善しなかった。未解決edgeを次の親へ昇格するtyped pivotが必要である。",
            "- Wordの2-step chainでは順序は保てたが、取得済み文書open証拠をsubject/operation/objectへ正規化できず、完全stepとcritical evidenceを失った。一方、Discordの2-step chainはStage 3で出力順を逆転した。",
            "- 誤ったprocess instanceを最初に選ぶと、Stage 2/3の追加探索が誤系列を精緻化した。初回pivot後のanchor再検証が必要である。",
            "- Candidate precision低下は、幻覚だけでなく、観測済みだがGold外のfile/module activityを主要chainへ昇格したことでも発生した。",
            "- 全4ケースでcritical evidenceは0%だった。行動内容の復元とcanonical row/action/targetの証拠束縛を別モジュールとして改善すべきである。",
            "",
            "## 監査",
            "",
            "- case summary audit: PASS",
            "- 各caseのrun数: 3",
            "- 4 caseの分母合計は正式overallと一致",
            "- 外部judge API使用: false",
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
