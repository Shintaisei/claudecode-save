#!/usr/bin/env python3
"""Strictly audit and summarize attack8 neutral5 run artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_neutral5_stage_cases_20260726.jsonl"
)
DEFAULT_COST_CSV = ROOT / "clouseau_api_costs.csv"
STAGES = ("stage1", "stage2", "stage3")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json_new(path: Path, payload: Any) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing audit: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def cost_index(path: Path) -> dict[str, list[dict[str, str]]]:
    if not path.exists():
        return {}
    result: dict[str, list[dict[str, str]]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            run_id = str(row.get("run_id") or "")
            if run_id:
                result.setdefault(run_id, []).append(row)
    return result


def numeric(row: dict[str, str], *names: str) -> float:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return float(value)
    return 0.0


def audit(args: argparse.Namespace) -> dict[str, Any]:
    cases = read_jsonl(args.cases)
    expected = {str(case["instance_id"]): case for case in cases}
    runs = sorted((args.result_root / "runs").glob("*/*/*_run.json"))
    costs = cost_index(args.cost_csv)
    failures: list[dict[str, Any]] = []
    run_reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    stage_counts: Counter[str] = Counter()
    totals = Counter()
    cost_total = 0.0

    for path in runs:
        try:
            run = read_json(path)
        except Exception as exc:
            failures.append(
                {"check": "run_json", "path": str(path), "error": str(exc)}
            )
            continue
        instance_id = str(run.get("instance_id") or "")
        stage = str(run.get("experiment_stage") or "")
        case = expected.get(instance_id)
        problems: list[str] = []
        if case is None:
            problems.append("instance_id_not_in_cases")
        if instance_id in seen:
            problems.append("duplicate_instance_id")
        seen.add(instance_id)
        if case is not None and stage != case.get("stage"):
            problems.append("stage_mismatch")
        if stage not in STAGES:
            problems.append("invalid_stage")
        else:
            stage_counts[stage] += 1
        if run.get("error") not in (None, ""):
            problems.append("run_error")
        configs = run.get("configs") or {}
        for key in ("max_investigations", "max_questions", "max_queries"):
            if configs.get(key) is not None:
                problems.append(f"{key}_is_not_null")
        if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
            problems.append("agent_call_limit_policy_mismatch")
        if case is not None:
            contract = case.get("paired_stage_contract") or {}
            if contract.get("alert_mapping_scored") is not False:
                problems.append("alert_mapping_scored_not_false")
            anchor = str(case.get("investigation_time_anchor_utc") or "")
            compact_anchor = anchor.replace("T", " ").replace("Z", "")[:19]
            clue = str(run.get("clue") or "")
            window = case.get("time_window_utc") or {}
            window_start = (
                str(window.get("episode_start") or "")
                .replace("T", " ")
                .replace("Z", "")[:19]
            )
            window_end = (
                str(window.get("episode_end") or "")
                .replace("T", " ")
                .replace("Z", "")[:19]
            )
            if window_start and window_start not in clue:
                problems.append("window_start_missing_from_clue")
            if window_end and window_end not in clue:
                problems.append("window_end_missing_from_clue")
            if stage == "stage1":
                alert_rows = case.get("input_alert_rows") or []
                alert_time = (
                    str((alert_rows[0] if alert_rows else {}).get("time") or "")
                    .replace("T", " ")
                    .replace("Z", "")[:19]
                )
                if alert_time and alert_time not in clue:
                    problems.append("stage1_alert_anchor_missing_from_clue")
            elif compact_anchor and compact_anchor not in clue:
                problems.append("neutral_anchor_missing_from_clue")
            if "対応推測はタスクでも採点対象でもない" not in clue:
                problems.append("alert_mapping_exclusion_missing_from_clue")
            target_rule = str(contract.get("target_component_rule") or "")
            if target_rule and target_rule not in clue:
                problems.append("target_component_rule_missing_from_clue")

        output_valid = False
        output: dict[str, Any] | None = None
        try:
            parsed = json.loads(str(run.get("output_text") or ""))
            if isinstance(parsed, dict):
                output = parsed
                output_valid = True
        except Exception:
            pass
        if not output_valid or output is None:
            problems.append("invalid_output_text_json")
            code_steps = []
        else:
            code_steps = output.get("code_steps")
            if not isinstance(code_steps, list):
                problems.append("code_steps_not_list")
                code_steps = []

        usage = run.get("usage") or {}
        input_tokens = int(usage.get("input_tokens") or 0)
        output_tokens = int(usage.get("output_tokens") or 0)
        cached_tokens = int(usage.get("cached_input_tokens") or 0)
        totals.update(
            {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cached_input_tokens": cached_tokens,
                "code_steps": len(code_steps),
            }
        )
        if not code_steps:
            totals["empty_code_step_runs"] += 1

        run_id = str(run.get("run_id") or "")
        cost_rows = costs.get(run_id, [])
        if len(cost_rows) != 1:
            problems.append(f"cost_row_count_{len(cost_rows)}")
            run_cost = 0.0
        else:
            run_cost = numeric(
                cost_rows[0],
                "total_cost_usd",
                "call_total_usd",
                "total_cost",
                "cost_usd",
            )
            cost_total += run_cost
        report = {
            "instance_id": instance_id,
            "stage": stage,
            "model": run.get("model"),
            "run_id": run_id,
            "run_json": str(path),
            "output_json_valid": output_valid,
            "code_step_count": len(code_steps),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_input_tokens": cached_tokens,
            "cost_usd": run_cost,
            "problems": problems,
            "status": "pass" if not problems else "fail",
        }
        run_reports.append(report)
        if problems:
            failures.append(
                {
                    "check": "run_contract",
                    "instance_id": instance_id,
                    "problems": problems,
                }
            )

    missing = sorted(set(expected) - seen)
    unexpected = sorted(seen - set(expected))
    if missing:
        failures.append({"check": "missing_runs", "instance_ids": missing})
    if unexpected:
        failures.append({"check": "unexpected_runs", "instance_ids": unexpected})
    expected_stage_counts = {stage: 8 for stage in STAGES}
    if dict(stage_counts) != expected_stage_counts:
        failures.append(
            {
                "check": "stage_counts",
                "expected": expected_stage_counts,
                "actual": dict(stage_counts),
            }
        )
    if len(runs) != args.expected_count:
        failures.append(
            {
                "check": "run_count",
                "expected": args.expected_count,
                "actual": len(runs),
            }
        )

    return {
        "status": "pass" if not failures else "fail",
        "result_root": str(args.result_root.resolve()),
        "cases": str(args.cases.resolve()),
        "expected_run_count": args.expected_count,
        "actual_run_count": len(runs),
        "stage_counts": dict(stage_counts),
        "valid_output_json_count": sum(
            report["output_json_valid"] for report in run_reports
        ),
        "error_free_run_count": sum(
            "run_error" not in report["problems"] for report in run_reports
        ),
        "unbounded_agent_config_count": sum(
            not any(
                problem.endswith("_is_not_null")
                or problem == "agent_call_limit_policy_mismatch"
                for problem in report["problems"]
            )
            for report in run_reports
        ),
        "total_input_tokens": totals["input_tokens"],
        "total_output_tokens": totals["output_tokens"],
        "total_cached_input_tokens": totals["cached_input_tokens"],
        "total_tokens": totals["input_tokens"] + totals["output_tokens"],
        "total_cost_usd": round(cost_total, 8),
        "total_code_steps": totals["code_steps"],
        "empty_code_step_runs": totals["empty_code_step_runs"],
        "failures": failures,
        "runs": run_reports,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--result-root", type=Path, required=True)
    result.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    result.add_argument("--cost-csv", type=Path, default=DEFAULT_COST_CSV)
    result.add_argument("--expected-count", type=int, default=24)
    result.add_argument("--out", type=Path)
    result.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Print a progress audit without failing for missing runs/stage counts.",
    )
    return result


def main() -> None:
    args = parser().parse_args()
    report = audit(args)
    if args.out:
        write_json_new(args.out, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "pass" and not args.allow_incomplete:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
