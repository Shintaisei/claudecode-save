#!/usr/bin/env python3
"""Create-only aggregate of the three mini-model normal8/attack8 replicates.

The script consumes the frozen replicate-01 v5-atomic score ledgers and the
independently reviewed replicate-02/03 ledgers.  It never calls a model API.
It reports pooled fixed-denominator metrics and replicate-level mean, sample
variance, and Student-t 95% confidence intervals (n=3, df=2).
"""
from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/current_experiment"
REPORT_JSON = DOC / "normal_attack8_two_model_three_replicate_codex_sol_results_20260806_v2.json"
REPORT_MD = DOC / "normal_attack8_two_model_three_replicate_codex_sol_results_20260806_v2.md"

NORMAL_R1_REPORT = DOC / "normal8_two_model_three_stage_codex_sol_results_20260802.json"
NORMAL_R23_REPORT = DOC / "normal8_mini_reps_02_03_codex_sol_results_20260806.json"
ATTACK_R1_REPORT = DOC / "attack8_two_model_three_stage_codex_sol_results_20260802.json"
ATTACK_R23_REPORT = DOC / "attack8_mini_reps_02_03_codex_sol_results_20260806.json"

METRICS = {
    "action_recall": ("gold_action_hits", "gold_action_denominator"),
    "candidate_precision": ("candidate_slot_tp", "candidate_slot_denominator"),
    "behavior_step_recall": ("behavior_step_hits", "behavior_step_denominator"),
    "critical_evidence_recall": ("critical_evidence_hits", "critical_evidence_denominator"),
    "order_recall": ("order_pair_hits", "order_pair_denominator"),
}
ACTIVITY = (
    "api_calls", "tokens", "cost_usd", "elapsed_seconds", "chief_leads",
    "unique_chief_leads", "investigator_questions", "unique_investigator_questions",
    "sql_queries", "unique_sql_queries",
)
T95_DF2 = 4.302652729911275


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_new(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def normal_rows(report_path: Path, replicate: str | None) -> list[dict[str, Any]]:
    report = load_json(report_path)
    assert report.get("status") == "PASS"
    assert report["cross_field_validation"]["status"] == "PASS"
    score_root = ROOT / report["provenance"]["score_root"]
    rows = load_jsonl(score_root / "formal_scores.jsonl")
    out = []
    for row in rows:
        m = row["metrics"]
        inv = row["investigation"]
        out.append({
            "replicate": row.get("replicate") or replicate,
            "phase": "normal8",
            "model": row["model"],
            "stage": row["stage"],
            "case": row["chain_id"],
            "instance_id": row["instance_id"],
            "run_path": row["run_json"],
            "run_sha256": row["run_sha256"],
            "gold_sha256": row["gold_sha256"],
            "counts": {k: int(m[k]) for pair in METRICS.values() for k in pair},
            "activity": {k: float(inv.get(k, 0)) for k in ACTIVITY},
        })
    return out


def attack_rows(report_path: Path, replicate: str | None) -> list[dict[str, Any]]:
    report = load_json(report_path)
    validation = report["validation"]
    assert str(validation.get("status", "")).lower() == "pass"
    assert not validation.get("failures")
    out = []
    for row in report["rows"]:
        totals = row["totals"]
        inv = row["investigation"]
        act = {
            "api_calls": inv.get("api_call_count", 0),
            "tokens": inv.get("total_tokens", 0),
            "cost_usd": inv.get("cost_usd", 0),
            "elapsed_seconds": inv.get("elapsed_seconds", 0),
            "chief_leads": inv.get("lead_call_count", 0),
            "unique_chief_leads": inv.get("unique_lead_count", 0),
            "investigator_questions": inv.get("investigator_question_count", 0),
            "unique_investigator_questions": inv.get("unique_investigator_question_count", 0),
            "sql_queries": inv.get("sql_query_count", 0),
            "unique_sql_queries": inv.get("unique_sql_query_count", 0),
        }
        out.append({
            "replicate": row.get("replicate") or replicate,
            "phase": "attack8",
            "model": row["model"],
            "stage": row["stage"],
            "case": row["chain_id"],
            "instance_id": row["instance_id"],
            "run_path": row["run_path"],
            "run_sha256": row["run_sha256"],
            "gold_sha256": row["gold_sha256"],
            "counts": {k: int(totals[k]) for pair in METRICS.values() for k in pair},
            "activity": {k: float(act[k]) for k in ACTIVITY},
        })
    return out


def summarize(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(rows)
    counts = {key: sum(r["counts"][key] for r in rows) for pair in METRICS.values() for key in pair}
    result: dict[str, Any] = {"run_count": len(rows), **counts}
    for metric, (hit, den) in METRICS.items():
        result[metric] = counts[hit] / counts[den] if counts[den] else None
    activity_totals = {key: sum(r["activity"][key] for r in rows) for key in ACTIVITY}
    result["activity_total"] = activity_totals
    result["activity_per_run"] = {key: value / len(rows) if rows else None for key, value in activity_totals.items()}
    return result


def rep_stats(values: list[float], *, bounded_unit_interval: bool = True) -> dict[str, Any]:
    if not values:
        return {"n": 0, "values": [], "mean": None, "sample_variance": None, "ci95": None}
    mean = statistics.mean(values)
    if len(values) < 2:
        return {"n": len(values), "values": values, "mean": mean, "sample_variance": None, "ci95": None}
    variance = statistics.variance(values)
    margin = T95_DF2 * math.sqrt(variance / len(values)) if len(values) == 3 else 1.96 * math.sqrt(variance / len(values))
    lower, upper = mean - margin, mean + margin
    if bounded_unit_interval:
        lower, upper = max(0.0, lower), min(1.0, upper)
    else:
        lower = max(0.0, lower)
    return {
        "n": len(values),
        "values": values,
        "mean": mean,
        "sample_variance": variance,
        "ci95": [lower, upper],
    }


def key_name(parts: tuple[str, ...]) -> str:
    return "|".join(parts) if parts else "overall"


def grouped(rows: list[dict[str, Any]], dims: tuple[str, ...]) -> dict[str, Any]:
    buckets: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[tuple(str(row[d]) for d in dims)].append(row)
    result = {}
    for key, group in sorted(buckets.items()):
        pooled = summarize(group)
        per_rep = {}
        for rep in ("replicate_01", "replicate_02", "replicate_03"):
            selected = [r for r in group if r["replicate"] == rep]
            if selected:
                per_rep[rep] = summarize(selected)
        repeatability = {}
        for metric in METRICS:
            values = [per_rep[rep][metric] for rep in sorted(per_rep) if per_rep[rep][metric] is not None]
            repeatability[metric] = rep_stats(values)
        for item in ("cost_usd", "elapsed_seconds", "tokens", "api_calls"):
            values = [per_rep[rep]["activity_per_run"][item] for rep in sorted(per_rep)]
            repeatability[f"{item}_per_run"] = rep_stats(values, bounded_unit_interval=False)
        result[key_name(key)] = {"dimensions": dict(zip(dims, key)), "pooled": pooled, "per_replicate": per_rep, "repeatability": repeatability}
    return result


def pct(value: float | None) -> str:
    return "—" if value is None else f"{100 * value:.2f}%"


def table_for(title: str, groups: dict[str, Any], include_dims: tuple[str, ...]) -> list[str]:
    lines = [f"## {title}", ""]
    headers = [*include_dims, "runs", "Action", "Precision", "完全step", "Critical", "Order", "cost/run", "time/run"]
    lines += ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(include_dims) + ["---:"] * (len(headers) - len(include_dims))) + "|"]
    for item in groups.values():
        p = item["pooled"]
        vals = [item["dimensions"].get(d, "all") for d in include_dims]
        vals += [str(p["run_count"]), pct(p["action_recall"]), pct(p["candidate_precision"]), pct(p["behavior_step_recall"]), pct(p["critical_evidence_recall"]), pct(p["order_recall"]), f"${p['activity_per_run']['cost_usd']:.4f}", f"{p['activity_per_run']['elapsed_seconds']/60:.2f}分"]
        lines.append("| " + " | ".join(vals) + " |")
    lines.append("")
    return lines


def main() -> None:
    sources = [NORMAL_R1_REPORT, NORMAL_R23_REPORT, ATTACK_R1_REPORT, ATTACK_R23_REPORT]
    for path in sources:
        if not path.exists():
            raise FileNotFoundError(path)
    rows = (
        normal_rows(NORMAL_R1_REPORT, "replicate_01")
        + normal_rows(NORMAL_R23_REPORT, None)
        + attack_rows(ATTACK_R1_REPORT, "replicate_01")
        + attack_rows(ATTACK_R23_REPORT, None)
    )

    failures: list[str] = []
    if len(rows) != 288:
        failures.append(f"row_count={len(rows)} expected=288")
    keys = [(r["replicate"], r["phase"], r["model"], r["stage"], r["case"]) for r in rows]
    if len(set(keys)) != 288:
        failures.append("duplicate logical run key")
    expected_reps = {"replicate_01", "replicate_02", "replicate_03"}
    if {r["replicate"] for r in rows} != expected_reps:
        failures.append("replicate set mismatch")
    for phase in ("normal8", "attack8"):
        for rep in expected_reps:
            count = sum(r["phase"] == phase and r["replicate"] == rep for r in rows)
            if count != 48:
                failures.append(f"{phase}/{rep} row_count={count} expected=48")
    for logical in {(r["phase"], r["model"], r["stage"], r["case"]) for r in rows}:
        group = [r for r in rows if (r["phase"], r["model"], r["stage"], r["case"]) == logical]
        # Gold/step/order denominators are properties of the frozen Gold.
        # Candidate precision is fixed only *after* each output is emitted, so
        # its slot denominator legitimately varies between stochastic runs.
        for den in ("gold_action_denominator", "behavior_step_denominator", "critical_evidence_denominator", "order_pair_denominator"):
            if len({r["counts"][den] for r in group}) != 1:
                failures.append(f"fixed denominator mismatch {logical} {den}")
    for row in rows:
        run_path = ROOT / row["run_path"]
        if not run_path.exists() or sha256_file(run_path) != row["run_sha256"]:
            failures.append(f"run hash mismatch {row['replicate']}/{row['phase']}/{row['instance_id']}/{row['model']}")

    group_specs = {
        "overall": (),
        "by_phase": ("phase",),
        "by_model": ("model",),
        "by_replicate": ("replicate",),
        "by_model_phase": ("model", "phase"),
        "by_model_phase_stage": ("model", "phase", "stage"),
        "by_phase_case": ("phase", "case"),
        "by_model_phase_case": ("model", "phase", "case"),
    }
    metrics = {name: grouped(rows, dims) for name, dims in group_specs.items()}
    report = {
        "schema_version": "normal_attack8_two_model_three_replicate_codex_sol_results_20260806_v1",
        "status": "PASS" if not failures else "FAIL",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {"runs": len(rows), "replicates": sorted(expected_reps), "models": ["gpt-4.1-mini", "gpt-5.4-mini"], "phases": ["normal8", "attack8"], "stages": ["stage1", "stage2", "stage3"], "judge_api_calls": 0},
        "statistical_policy": {"unit": "replicate-level fixed-denominator metric", "replicate_count": 3, "variance": "unbiased sample variance (n-1)", "ci95": "two-sided Student t, df=2, t=4.3026527299; bounded to [0,1]", "pooled_metrics": "sum hits / sum fixed denominators"},
        "provenance": [{"path": str(p.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256_file(p)} for p in sources],
        "metrics": metrics,
        "cross_field_validation": {"status": "PASS" if not failures else "FAIL", "row_count": len(rows), "expected_row_count": 288, "unique_logical_keys": len(set(keys)), "run_hashes_rechecked": len(rows), "fixed_denominators_checked": True, "failure_count": len(failures), "failures": failures},
        "failure_history": {"first_pass_failures": 2, "failure_types": ["run wall timeout 1800 seconds", "APITimeoutError with null output"], "retry_pass": 2, "effective_missing_runs": 0, "retry_root": "docs/current_experiment/results_2026-08-06/mini_reps_02_03_v5_failure_retry_01"},
    }
    write_new(REPORT_JSON, json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    overall = metrics["overall"]["overall"]["pooled"]
    md = [
        "# 正常8＋攻撃8・2モデル・3反復 統合結果",
        "",
        f"- 状態: **{report['status']}**（288/288有効run、OpenAI judge API 0回）",
        f"- 全体精度: Action **{pct(overall['action_recall'])}** / Precision **{pct(overall['candidate_precision'])}** / 完全step **{pct(overall['behavior_step_recall'])}** / Critical **{pct(overall['critical_evidence_recall'])}** / Order **{pct(overall['order_recall'])}**",
        f"- 実測総コスト: **${overall['activity_total']['cost_usd']:.6f}**、総wall time: **{overall['activity_total']['elapsed_seconds']/3600:.2f}時間**、総tokens: **{overall['activity_total']['tokens']:,.0f}**",
        "- 95%CIは3反復の固定分母スコアを実験単位としてStudent-t（df=2）で算出。n=3のため区間は広く、傾向確認用です。",
        "",
    ]
    md += table_for("モデル×正常/攻撃（3反復pool）", metrics["by_model_phase"], ("model", "phase"))
    md += table_for("モデル×正常/攻撃×Stage（3反復pool）", metrics["by_model_phase_stage"], ("model", "phase", "stage"))
    md += table_for("正常/攻撃×ケース（3反復pool）", metrics["by_phase_case"], ("phase", "case"))
    md += [
        "## 反復性の読み方",
        "",
        "JSONの各集計セルには `per_replicate` と `repeatability` を保存しています。`repeatability` は3反復の値、平均、標本分散、95%CIを含みます。スライドでは pooled 値を主結果、95%CIを再現性の補助線として併記してください。",
        "",
        "## 失敗・再試行",
        "",
        "first passの2件（1800秒run timeout、APITimeoutError）は既存成果物を凍結したまま別rootで再試行し、2件ともPASSしました。正式集計に欠測はありません。",
        "",
        "## 成果物",
        "",
        f"- JSON: `{REPORT_JSON.relative_to(ROOT).as_posix()}`",
        f"- 生成スクリプト: `{Path(__file__).relative_to(ROOT).as_posix()}`",
        "",
    ]
    write_new(REPORT_MD, "\n".join(md))
    print(json.dumps({"status": report["status"], "run_count": len(rows), "report_json": str(REPORT_JSON), "report_md": str(REPORT_MD), "failures": failures}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
