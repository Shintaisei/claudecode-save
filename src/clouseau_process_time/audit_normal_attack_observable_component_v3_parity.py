#!/usr/bin/env python3
"""Audit whether the historical normal run is comparable to attack v3.

This is a read-only source audit.  It never modifies historical cases, Gold,
runs, or scores.  It writes a versioned JSON and Markdown parity-gate report.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
NORMAL_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "cbc_23_chain_stage_cases_2026-06-12.jsonl"
)
NORMAL_GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "cbc_non_alert_behavior_chain_gold_2026-06-11"
)
NORMAL_VALIDATION = (
    ROOT
    / "docs/current_experiment/chain_gold_validation_non_alert_2026-06-11"
    / "chain_gold_db_validation_steps_non_alert_2026-06-11.csv"
)
NORMAL_RUN_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-06-09"
    / "formal_23_chain_experiment_2rep_20260612/replicate_01"
    / "runs/gpt-5.4-mini"
)
ATTACK_VALIDATION = (
    ROOT
    / "docs/current_experiment"
    / "atlasv2_s3_s4_attack8_observable_component_v3_build_validation_20260726.json"
)
OUT_JSON = (
    ROOT
    / "docs/current_experiment"
    / "normal_attack_observable_component_v3_parity_gate_20260726.json"
)
OUT_MD = (
    ROOT
    / "docs/current_experiment"
    / "normal_attack_observable_component_v3_parity_gate_20260726.md"
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def normal_case_audit(cases: list[dict[str, Any]]) -> dict[str, Any]:
    stage_counts = Counter(str(case["stage"]) for case in cases)
    stage3 = {str(case["chain_id"]): case for case in cases if case["stage"] == "stage3"}
    chain_sets = {
        stage: {str(case["chain_id"]) for case in cases if case["stage"] == stage}
        for stage in ("stage1", "stage2", "stage3")
    }
    window_minutes: Counter[float] = Counter()
    for case in cases:
        model_input = case["model_ready_input"]["input"]
        start = parse_utc(model_input["chain_window_start_utc"])
        end = parse_utc(model_input["chain_window_end_utc"])
        window_minutes[(end - start).total_seconds() / 60] += 1
    return {
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "chain_count": len(stage3),
        "same_chain_set_all_stages": (
            chain_sets["stage1"] == chain_sets["stage2"] == chain_sets["stage3"]
        ),
        "window_minutes_distribution": {
            str(key): value for key, value in sorted(window_minutes.items())
        },
        "stage3_cases": stage3,
    }


def normal_gold_audit(
    cases_by_chain: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    with NORMAL_VALIDATION.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    sample_action_counts: Counter[str] = Counter()
    samples_inside = 0
    outside_rows: list[dict[str, Any]] = []
    sample_parse_failures: list[dict[str, str]] = []
    gold_pid_mentions = 0
    for row in rows:
        sample_text = row.get("stage3_sample") or ""
        try:
            sample = json.loads(sample_text)
        except json.JSONDecodeError as exc:
            sample_parse_failures.append(
                {
                    "chain_id": row["chain_id"],
                    "step_id": row["step_id"],
                    "error": str(exc),
                }
            )
            continue
        sample_action_counts[str(sample.get("action"))] += 1
        case = cases_by_chain[row["chain_id"]]
        model_input = case["model_ready_input"]["input"]
        timestamp = parse_utc(str(sample["timestamp_utc"]))
        start = parse_utc(model_input["chain_window_start_utc"])
        end = parse_utc(model_input["chain_window_end_utc"])
        if start <= timestamp <= end:
            samples_inside += 1
        else:
            outside_rows.append(
                {
                    "chain_id": row["chain_id"],
                    "step_id": row["step_id"],
                    "sample_row_id": sample.get("id"),
                    "sample_timestamp_utc": sample.get("timestamp_utc"),
                    "window_start_utc": model_input["chain_window_start_utc"],
                    "window_end_utc": model_input["chain_window_end_utc"],
                    "sample_action": sample.get("action"),
                }
            )
        combined = " ".join(
            str(row.get(key) or "")
            for key in ("subject", "action", "object", "evidence_basis")
        ).lower()
        if "pid" in combined:
            gold_pid_mentions += 1

    summaries: list[dict[str, str]]
    with (NORMAL_GOLD_ROOT / "chain_summary.csv").open(
        "r", encoding="utf-8", newline=""
    ) as handle:
        summaries = list(csv.DictReader(handle))
    evaluable = [row for row in summaries if row["evaluable"].lower() == "true"]
    step_counts = Counter(int(row["gold_step_count"]) for row in evaluable)

    canonical_primary_actions = {
        "ACTION_CREATE_PROCESS",
        "ACTION_CONNECTION_CREATE",
        "ACTION_CONNECTION_ESTABLISHED",
    }
    weak_proxy_actions = {
        action: count
        for action, count in sample_action_counts.items()
        if action not in canonical_primary_actions
    }
    return {
        "validation_step_count": len(rows),
        "evaluable_chain_count": len(evaluable),
        "gold_step_count_distribution": {
            str(key): value for key, value in sorted(step_counts.items())
        },
        "average_gold_steps_per_chain": (
            sum(int(row["gold_step_count"]) for row in evaluable) / len(evaluable)
        ),
        "validation_sample_parse_failure_count": len(sample_parse_failures),
        "validation_sample_parse_failures": sample_parse_failures,
        "validation_samples_inside_declared_window": samples_inside,
        "validation_samples_outside_declared_window": len(outside_rows),
        "validation_sample_inside_rate": samples_inside / len(rows),
        "outside_window_rows": outside_rows,
        "sample_action_counts": dict(sample_action_counts),
        "weak_or_indirect_proxy_action_counts": weak_proxy_actions,
        "module_load_proxy_count": sample_action_counts["ACTION_LOAD_MODULE"],
        "gold_rows_with_pid_text": gold_pid_mentions,
        "canonical_evidence_field_present": False,
        "gold_exhaustiveness_audit_present": False,
    }


def normal_run_audit() -> dict[str, Any]:
    paths = sorted(NORMAL_RUN_ROOT.rglob("*_run.json"))
    stage_counts: Counter[str] = Counter()
    root_valid = 0
    output_valid = 0
    errors = 0
    invalid_outputs: list[dict[str, str]] = []
    config_counts: Counter[str] = Counter()
    policy_counts: Counter[str] = Counter()
    for path in paths:
        stage_counts[path.parent.name] += 1
        try:
            payload = read_json(path)
            root_valid += 1
        except (OSError, json.JSONDecodeError) as exc:
            invalid_outputs.append({"path": rel(path), "layer": "run", "error": str(exc)})
            continue
        if payload.get("error"):
            errors += 1
        configs = payload.get("configs") or {}
        config_counts[json.dumps(configs, sort_keys=True, ensure_ascii=False)] += 1
        policy_counts[str(configs.get("agent_call_limit_policy", "not_recorded"))] += 1
        try:
            json.loads(str(payload.get("output_text") or ""))
            output_valid += 1
        except json.JSONDecodeError as exc:
            invalid_outputs.append(
                {"path": rel(path), "layer": "output_text", "error": str(exc)}
            )
    return {
        "run_count": len(paths),
        "stage_counts": dict(stage_counts),
        "root_json_valid_count": root_valid,
        "output_json_valid_count": output_valid,
        "error_count": errors,
        "invalid_outputs": invalid_outputs,
        "config_counts": dict(config_counts),
        "agent_call_limit_policy_counts": dict(policy_counts),
        "all_unbounded_by_experiment": (
            len(paths) > 0
            and all(
                json.loads(config_text).get(key) is None
                for config_text in config_counts
                for key in ("max_investigations", "max_questions", "max_queries")
            )
        ),
    }


def write_markdown(report: dict[str, Any], out_path: Path) -> None:
    normal = report["normal_historical"]
    gold = normal["gold"]
    runs = normal["run"]
    attack = report["attack_v3_reference"]
    lines = [
        "# 正常・攻撃 observable-component v3 比較可能性監査",
        "",
        f"- 判定: **{report['parity_gate_status']}**",
        f"- 作成時刻: `{report['created_at_utc']}`",
        "- 目的: 旧正常 gpt-5.4-mini 結果を攻撃 observable-component v3 と正式比較できるかを判定する。",
        "",
        "## 結論",
        "",
        "旧正常スコアは参考値として保持するが、攻撃v3との正式な精度差には使わない。"
        "正常側を同じGold構築規則、同じneutral anchor、同じ5分窓、同じ出力schema、"
        "同じ無制限Agent契約、同じCodex item-level採点で新規に実行する必要がある。",
        "",
        "## 機械監査結果",
        "",
        f"- 正常ケース: {normal['cases']['case_count']}件、"
        f"Stage別 {normal['cases']['stage_counts']}、5分窓 {normal['cases']['window_minutes_distribution']}",
        f"- 正常Gold: {gold['validation_step_count']} step、"
        f"平均 {gold['average_gold_steps_per_chain']:.3f} step/chain",
        f"- 正常Gold代表証跡の窓内: {gold['validation_samples_inside_declared_window']}/"
        f"{gold['validation_step_count']}、窓外: {gold['validation_samples_outside_declared_window']}",
        f"- 正常Goldのmodule-load代理証跡: {gold['module_load_proxy_count']} step",
        f"- 正常run: {runs['run_count']}件、output JSON valid "
        f"{runs['output_json_valid_count']}/{runs['run_count']}、error {runs['error_count']}",
        f"- 正常runのAgent上限: unbounded={runs['all_unbounded_by_experiment']}; "
        f"policy={runs['agent_call_limit_policy_counts']}",
        f"- 攻撃v3: {attack['chain_count']} chain、"
        f"{attack['gold_step_count_unique']} Gold step、"
        f"DB照合 mismatch={attack['source_database_mismatch_count']}、"
        f"exhaustiveness pass={attack['gold_exhaustiveness_pass_chain_count']}/"
        f"{attack['chain_count']}",
        "",
        "## parity gate",
        "",
    ]
    for gate in report["failed_gates"]:
        lines.append(f"- FAIL: {gate}")
    lines.extend(
        [
            "",
            "## 次の正式実験",
            "",
            "1. 正常ユースケースを observable-component v3 で再構築し、各stepを窓内の"
            "canonical CBC primary rowとPIDに固定する。",
            "2. Stage 1/2/3で同一Gold・neutral anchor・5分窓を使い、"
            "alert対応関係の推測は採点しない。",
            "3. gpt-5.4-miniを `unbounded_by_experiment`、`max_tokens=24576` で新規1反復する。",
            "4. 攻撃v3と同じCodex item-level二重レビュー＋不一致第三レビューで採点する。",
            "5. 同一契約で得た正常と攻撃のみを主比較に採用し、旧正常値はhistorical referenceと明記する。",
            "",
            "精度を正常値へ合わせるための事後的なGold・prompt調整は行わない。"
            "揃えるのは測定条件であり、精度は観測結果として報告する。",
            "",
        ]
    )
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-json", type=Path, default=OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=OUT_MD)
    args = parser.parse_args()

    cases = read_jsonl(NORMAL_CASES)
    case_audit = normal_case_audit(cases)
    gold_audit = normal_gold_audit(case_audit.pop("stage3_cases"))
    run_audit = normal_run_audit()
    attack = read_json(ATTACK_VALIDATION)
    failed_gates: list[str] = []
    if gold_audit["validation_samples_outside_declared_window"]:
        failed_gates.append("all Gold canonical evidence must be inside the declared five-minute window")
    if gold_audit["module_load_proxy_count"]:
        failed_gates.append("every scored action must use its own canonical primary-action row")
    if not gold_audit["canonical_evidence_field_present"]:
        failed_gates.append("every Gold step must carry canonical_evidence and PID identity")
    if not gold_audit["gold_exhaustiveness_audit_present"]:
        failed_gates.append("every Gold component must pass an independent exhaustiveness audit")
    if not run_audit["all_unbounded_by_experiment"]:
        failed_gates.append("all model runs must use agent_call_limit_policy=unbounded_by_experiment")
    if run_audit["output_json_valid_count"] != run_audit["run_count"]:
        failed_gates.append("all adopted runs must have valid output_text JSON")

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "parity_gate_status": "FAIL_REQUIRES_NEW_NORMAL_V3_RUN" if failed_gates else "PASS",
        "historical_results_preserved": True,
        "formal_comparison_authorized": not failed_gates,
        "normal_historical": {
            "cases": case_audit,
            "gold": gold_audit,
            "run": run_audit,
        },
        "attack_v3_reference": attack,
        "failed_gates": failed_gates,
        "required_resolution": {
            "gold": "new versioned normal observable-component v3 Gold with window-contained canonical primary rows and PID identity",
            "run": "new gpt-5.4-mini replicate with unbounded_by_experiment and valid JSON for every case",
            "scoring": "same Codex item-level double review and third-review adjudication used for attack v3",
            "prohibited": "post-hoc tuning of Gold or prompt to make normal and attack accuracy converge",
        },
        "sources": {
            "normal_cases": rel(NORMAL_CASES),
            "normal_gold_root": rel(NORMAL_GOLD_ROOT),
            "normal_validation": rel(NORMAL_VALIDATION),
            "normal_run_root": rel(NORMAL_RUN_ROOT),
            "attack_validation": rel(ATTACK_VALIDATION),
        },
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_markdown(report, args.out_md)
    print(args.out_json)
    print(args.out_md)
    print(report["parity_gate_status"])


if __name__ == "__main__":
    main()
