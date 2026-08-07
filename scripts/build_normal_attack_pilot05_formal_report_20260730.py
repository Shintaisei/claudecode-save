"""Build the create-only formal report for the 12-run pilot05 experiment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-30/"
    / "normal_attack_full_ledger_pilot_05"
)
ANALYSIS_ROOT = RESULT_ROOT / "analysis_codex_single_review_v1"
OPERATIONAL = ANALYSIS_ROOT / "operational_ledger_v1.json"
ACCURACY = ANALYSIS_ROOT / "formal_accuracy_aggregate_v1.json"
ACCURACY_AUDIT = ANALYSIS_ROOT / "formal_accuracy_audit_v1.json"
REVIEWS = ANALYSIS_ROOT / "codex_review_v5_atomic_v1.jsonl"
MANIFEST = RESULT_ROOT / "pilot_selection_manifest.json"
OUTPUT_JSON = (
    ROOT
    / "docs/current_experiment/"
    / "normal_attack_full_ledger_pilot05_formal_results_20260730.json"
)
OUTPUT_MD = OUTPUT_JSON.with_suffix(".md")


def read_json(path: Path) -> dict[str, Any]:
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
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pct(metric: dict[str, Any]) -> str:
    value = metric.get("value")
    percentage = "n/a" if value is None else f"{value * 100:.2f}%"
    return f"{metric['hits']}/{metric['denominator']} ({percentage})"


def money(value: float) -> str:
    return f"${value:.6f}"


def minutes(value: float) -> str:
    return f"{value / 60:.2f}"


def metric_cells(metrics: dict[str, Any]) -> list[str]:
    return [
        pct(metrics[name])
        for name in (
            "action_recall",
            "candidate_precision",
            "behavior_step_recall",
            "critical_evidence_recall",
            "order_recall",
        )
    ]


def render_accuracy_table(
    title: str,
    rows: list[dict[str, Any]],
    keys: tuple[str, ...],
) -> list[str]:
    header = [
        *keys,
        "Action recall",
        "Candidate precision",
        "Behavior-step recall",
        "Critical evidence",
        "Order recall",
    ]
    lines = [
        f"## {title}",
        "",
        "| " + " | ".join(header) + " |",
        "|" + "|".join(["---"] * len(keys) + ["---:"] * 5) + "|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [str(row[key]) for key in keys]
                + metric_cells(row["metrics"])
            )
            + " |"
        )
    lines.append("")
    return lines


def main() -> None:
    required = (OPERATIONAL, ACCURACY, ACCURACY_AUDIT, REVIEWS, MANIFEST)
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("missing formal source artifact(s): " + ", ".join(missing))
    for target in (OUTPUT_JSON, OUTPUT_MD):
        if target.exists():
            raise FileExistsError(f"create-only target exists: {target}")

    operational = read_json(OPERATIONAL)
    accuracy = read_json(ACCURACY)
    accuracy_audit = read_json(ACCURACY_AUDIT)
    reviews = read_jsonl(REVIEWS)
    manifest = read_json(MANIFEST)
    if operational["deterministic_audit"]["status"] != "PASS":
        raise SystemExit("operational audit is not PASS")
    if accuracy_audit["status"] != "PASS":
        raise SystemExit("accuracy audit is not PASS")
    if operational["run_count"] != 12 or len(accuracy["by_run"]) != 12:
        raise SystemExit("formal report requires exactly 12 runs")

    operations_by_instance = {
        row["instance_id"]: row for row in operational["runs"]
    }
    reviews_by_id = {row["queue_id"]: row for row in reviews}
    combined_runs: list[dict[str, Any]] = []
    for scored in accuracy["by_run"]:
        operation = operations_by_instance[scored["instance_id"]]
        review = reviews_by_id[scored["queue_id"]]
        combined_runs.append(
            {
                "pair_id": scored["pair_id"],
                "scenario_group": scored["scenario_group"],
                "model": scored["model"],
                "stage": scored["stage"],
                "instance_id": scored["instance_id"],
                "operational": operation,
                "accuracy": scored["metrics"],
                "review_summary_ja": scored["review_summary_ja"],
                "failure_analysis": scored["failure_analysis"],
                "known_technical_defects": operation[
                    "known_technical_defects"
                ],
                "review_run_sha256": review["run_sha256"],
            }
        )

    source_hashes = {
        str(path.relative_to(ROOT)): sha256(path) for path in required
    }
    formal = {
        "schema_version": "normal_attack_full_ledger_pilot05_formal_v1",
        "experiment_scope": {
            "normal_use_cases": 2,
            "attack_use_cases": 2,
            "stages_per_use_case": 3,
            "run_count": 12,
            "models": ["gpt-4.1-mini", "gpt-5.4-mini"],
            "repetitions_per_model_stage_case": 1,
            "gpt_5_5_used": False,
            "window_policy": "exact five-minute reference window",
        },
        "selection_manifest": manifest,
        "operational_aggregates": operational["aggregates"],
        "accuracy_aggregates": {
            key: accuracy[key]
            for key in (
                "overall",
                "by_model",
                "by_stage",
                "by_scenario_group",
                "by_model_stage",
                "by_model_scenario",
                "by_case",
            )
        },
        "runs": combined_runs,
        "interpretation_limits": [
            accuracy["interpretation_limit"],
            (
                "Each model is assigned different normal and attack cases; "
                "model totals are descriptive rather than a controlled "
                "head-to-head model comparison."
            ),
            (
                "The retained gpt-4.1-mini normal Stage 3 thought predates the "
                "physical Stage 3 filter fix and is explicitly marked as "
                "technically confounded."
            ),
        ],
        "audits": {
            "operational": operational["deterministic_audit"],
            "accuracy": accuracy_audit,
            "source_hashes": source_hashes,
            "status": "PASS",
        },
        "external_judge_api_used": False,
    }
    OUTPUT_JSON.write_text(
        json.dumps(formal, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# 正常・攻撃 full-ledger pilot05 正式結果",
        "",
        "正常2ユースケース、攻撃2ユースケースについて、各Stage 1/2/3を1回ずつ、"
        "`gpt-4.1-mini`または`gpt-5.4-mini`で実行した12試行の正式集計である。",
        "GPT-5.5およびOpenAI judge API/API scorerは使用していない。",
        "",
        "## 実験整合性",
        "",
        f"- run数: {operational['run_count']}/12",
        "- 全ケースの参照時間窓: 5分",
        "- agent call上限: 実験としては無制限",
        "- 1 leadの安全弁: Investigator 20質問、SQL 80回、または20分",
        "- 精度採点: Codex単独review + v5 atomic決定論的監査",
        f"- accuracy audit: {accuracy_audit['status']}",
        f"- operational audit: {operational['deterministic_audit']['status']}",
        "",
        "## 全体精度",
        "",
        "| Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |",
        "|---:|---:|---:|---:|---:|",
        "| "
        + " | ".join(metric_cells(accuracy["overall"]))
        + " |",
        "",
    ]
    lines += render_accuracy_table("モデル別精度", accuracy["by_model"], ("model",))
    lines += render_accuracy_table("Stage別精度", accuracy["by_stage"], ("stage",))
    lines += render_accuracy_table(
        "正常・攻撃別精度",
        accuracy["by_scenario_group"],
        ("scenario_group",),
    )

    lines += [
        "## 試行別API・token・費用・時間",
        "",
        "| group | model | Stage | case | Chief calls | Investigator calls | SQL QA calls | Input | Output | Cached | Cost | Wall min | leads | questions | SQL | guard |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in combined_runs:
        op = row["operational"]
        total = op["total"]
        roles = op["roles"]
        lines.append(
            "| "
            + " | ".join(
                [
                    row["scenario_group"],
                    row["model"],
                    row["stage"],
                    row["pair_id"],
                    str(roles["chief"]["llm_api_call_count"]),
                    str(roles["investigator"]["llm_api_call_count"]),
                    str(roles["sql_qa"]["llm_api_call_count"]),
                    f"{total['input_tokens']:,}",
                    f"{total['output_tokens']:,}",
                    f"{total['cached_input_tokens']:,}",
                    money(float(total["estimated_cost_usd"])),
                    minutes(float(op["elapsed_seconds"])),
                    str(total["chief_lead_count"]),
                    str(total["investigator_question_count"]),
                    str(total["sql_query_count"]),
                    str(total["lead_guard_trigger_count"]),
                ]
            )
            + " |"
        )
    lines.append("")

    lines += [
        "## 試行・役割別LLM ledger",
        "",
        "| group | model | Stage | case | role | API calls | Input | Output | Cached | LLM sec | Cost | cross-agent tool calls |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in combined_runs:
        for role in ("chief", "investigator", "sql_qa"):
            ledger = row["operational"]["roles"][role]
            lines.append(
                "| "
                + " | ".join(
                    [
                        row["scenario_group"],
                        row["model"],
                        row["stage"],
                        row["pair_id"],
                        role,
                        str(ledger["llm_api_call_count"]),
                        f"{ledger['input_tokens']:,}",
                        f"{ledger['output_tokens']:,}",
                        f"{ledger['cached_input_tokens']:,}",
                        f"{ledger['llm_api_duration_seconds_sum']:.3f}",
                        money(float(ledger["estimated_cost_usd"])),
                        str(ledger["cross_agent_tool_call_count"]),
                    ]
                )
                + " |"
            )
    lines.append("")

    lines += [
        "## 試行別精度",
        "",
        "| group | model | Stage | case | Action recall | Precision | Complete step | Critical evidence | Order |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in combined_runs:
        lines.append(
            "| "
            + " | ".join(
                [
                    row["scenario_group"],
                    row["model"],
                    row["stage"],
                    row["pair_id"],
                    *metric_cells(row["accuracy"]),
                ]
            )
            + " |"
        )
    lines.append("")

    lines += [
        "## 未取得・精度低下の原因",
        "",
    ]
    for row in combined_runs:
        lines += [
            f"### {row['model']} / {row['stage']} / {row['pair_id']}",
            "",
            row["review_summary_ja"] or "要約なし。",
            "",
            "```json",
            json.dumps(
                row["failure_analysis"],
                ensure_ascii=False,
                indent=2,
            ),
            "```",
            "",
        ]
        if row["known_technical_defects"]:
            lines += [
                "既知の技術的交絡:",
                "",
                "```json",
                json.dumps(
                    row["known_technical_defects"],
                    ensure_ascii=False,
                    indent=2,
                ),
                "```",
                "",
            ]

    lines += [
        "## 解釈上の制約",
        "",
        "- モデルごとに割り当てた正常・攻撃ケースが異なるため、モデル集計は記述統計であり、同一ケースでの厳密な優劣比較ではない。",
        "- `gpt-4.1-mini`の正常Stage 3は、修正前TEMP VIEW wrapperの共通ガード迂回を含む完了済み思考である。再実行せず、技術的交絡として明示した。",
        "- PIDおよびhidden alert mappingは非採点であり、critical evidenceとorderはactionとは別に評価した。",
        "",
        "## 機械可読成果物",
        "",
        f"- `{OUTPUT_JSON.relative_to(ROOT)}`",
        f"- `{OPERATIONAL.relative_to(ROOT)}`",
        f"- `{ACCURACY.relative_to(ROOT)}`",
        f"- `{ACCURACY_AUDIT.relative_to(ROOT)}`",
        "",
    ]
    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(OUTPUT_JSON)
    print(OUTPUT_MD)


if __name__ == "__main__":
    main()
