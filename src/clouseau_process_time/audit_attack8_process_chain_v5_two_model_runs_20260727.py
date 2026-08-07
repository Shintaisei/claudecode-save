#!/usr/bin/env python3
"""Audit the two-model process-chain v5 formal baseline run artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STAGES = ("stage1", "stage2", "stage3")
MODELS = ("gpt-4.1-mini", "gpt-5.4-mini")
CONTRACT = "process_behavior_chain_normal23_parity_v5_formal"
SUITE = "atlasv2_s3_s4_attack8_process_chain_v5_formal"
DEFAULT_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
)
DEFAULT_COST_CSV = ROOT / "clouseau_api_costs.csv"


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
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_path_key(path: Path) -> tuple[str, str]:
    suffix = "_run.json"
    if not path.name.endswith(suffix) or len(path.parents) < 2:
        raise ValueError(f"not a model/stage run path: {path}")
    return path.parents[1].name, path.name[: -len(suffix)]


def write_json_new(path: Path, payload: Any) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing audit: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def compact_time(value: Any) -> str:
    return str(value or "").replace("T", " ").replace("Z", "")[:19]


def cost_index(path: Path) -> dict[str, list[dict[str, str]]]:
    if not path.exists():
        return {}
    result: dict[str, list[dict[str, str]]] = defaultdict(list)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            run_id = str(row.get("run_id") or "")
            if run_id:
                result[run_id].append(row)
    return dict(result)


def numeric(row: dict[str, str], *names: str) -> float:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return float(value)
    return 0.0


def audit(args: argparse.Namespace) -> dict[str, Any]:
    cases = read_jsonl(args.cases)
    expected_cases = {str(case["instance_id"]): case for case in cases}
    expected_keys = {
        (model, instance_id)
        for model in MODELS
        for instance_id in expected_cases
    }
    paths = sorted((args.result_root / "runs").glob("*/*/*_run.json"))
    replacement_paths = [path.resolve() for path in (args.replacement_run or [])]
    replacement_by_key: dict[tuple[str, str], Path] = {}
    for replacement in replacement_paths:
        if not replacement.is_file():
            raise FileNotFoundError(f"replacement run not found: {replacement}")
        key = run_path_key(replacement)
        if key in replacement_by_key:
            raise ValueError(f"duplicate replacement run key: {key}")
        replacement_by_key[key] = replacement
    if replacement_by_key:
        paths = [path for path in paths if run_path_key(path) not in replacement_by_key]
        paths.extend(replacement_by_key.values())
        paths = sorted(paths)
    costs = cost_index(args.cost_csv)

    failures: list[dict[str, Any]] = []
    run_reports: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    stage_counts: Counter[str] = Counter()
    model_counts: Counter[str] = Counter()
    model_stage_counts: Counter[tuple[str, str]] = Counter()
    totals: Counter[str] = Counter()
    model_totals: dict[str, Counter[str]] = defaultdict(Counter)
    total_cost = 0.0

    for path in paths:
        problems: list[str] = []
        try:
            run = read_json(path)
        except Exception as exc:
            failures.append(
                {"check": "run_json", "path": str(path), "error": str(exc)}
            )
            continue

        instance_id = str(run.get("instance_id") or "")
        model = str(run.get("model") or "")
        stage = str(run.get("experiment_stage") or "")
        key = (model, instance_id)
        case = expected_cases.get(instance_id)

        if key in seen:
            problems.append("duplicate_model_instance_id")
        seen.add(key)
        if key not in expected_keys:
            problems.append("unexpected_model_instance_id")
        if model not in MODELS:
            problems.append("unexpected_model")
        else:
            model_counts[model] += 1
        if case is None:
            problems.append("instance_id_not_in_cases")
        elif stage != str(case.get("stage") or ""):
            problems.append("stage_mismatch")
        if stage not in STAGES:
            problems.append("invalid_stage")
        else:
            stage_counts[stage] += 1
            model_stage_counts[(model, stage)] += 1

        if run.get("error") not in (None, ""):
            problems.append("run_error")
        if run.get("dry_run") is not False:
            problems.append("dry_run_not_false")

        configs = run.get("configs") or {}
        for name in ("max_investigations", "max_questions", "max_queries"):
            if configs.get(name) is not None:
                problems.append(f"{name}_is_not_null")
        if configs.get("agent_call_limit_policy") != "unbounded_by_experiment":
            problems.append("agent_call_limit_policy_mismatch")
        if configs.get("max_tokens") != 24576:
            problems.append("max_tokens_mismatch")

        experiment = run.get("atlasv2_s3_s4_attack8_paired_experiment") or {}
        if experiment.get("suite_group") != SUITE:
            problems.append("suite_group_mismatch")
        if experiment.get("contract_version") != CONTRACT:
            problems.append("contract_version_mismatch")

        expected_fields = run.get("expected_input_fields")
        clue = str(run.get("clue") or "")
        if stage == "stage1":
            required_stage1_fields = {
                "host",
                "focus_processes",
                "alert_time",
                "alert_id",
                "alert_name",
                "alert_reason",
                "alert_process",
                "alert_source_stream",
            }
            if (
                not isinstance(expected_fields, list)
                or not required_stage1_fields.issubset(set(expected_fields))
            ):
                problems.append("stage1_expected_input_fields_mismatch")
        elif stage in ("stage2", "stage3"):
            if expected_fields != ["host", "process", "timestamp"]:
                problems.append(f"{stage}_expected_input_fields_mismatch")

        if case is not None:
            window = case.get("time_window_utc") or {}
            start = compact_time(window.get("episode_start"))
            end = compact_time(window.get("episode_end"))
            if start and start not in clue:
                problems.append("window_start_missing_from_clue")
            if end and end not in clue:
                problems.append("window_end_missing_from_clue")
            contract = case.get("paired_stage_contract") or {}
            if contract.get("alert_mapping_scored") is not False:
                problems.append("alert_mapping_scored_not_false")
            # v5 intentionally withholds the target rule and neutral event
            # anchor from the model. Their absence is part of the contract.
            target_rule = str(contract.get("target_component_rule") or "")
            if target_rule and target_rule in clue:
                problems.append("hidden_target_component_rule_leaked")
            anchor = compact_time(case.get("investigation_time_anchor_utc"))
            if stage in ("stage2", "stage3") and anchor and anchor not in clue:
                problems.append("process_time_anchor_missing_from_clue")

        counts = run.get("adapter_counts") or {}
        if stage == "stage3":
            filter_mode = counts.get("cbc_alert_summary_filter_mode")
            if filter_mode not in {
                "sql_tool_temp_view",
                "physical_adapter_copy_v2",
            }:
                problems.append("stage3_filter_mode_mismatch")
            if counts.get("post_filter_cbc_alert_summary_rows") != 0:
                problems.append("stage3_alert_summary_rows_visible")
            if int(counts.get("post_filter_cbc_event_telemetry_rows") or 0) <= 0:
                problems.append("stage3_primary_cbc_telemetry_missing")
            if filter_mode == "physical_adapter_copy_v2" and (
                counts.get("shared_guarded_sql_tools_preserved") is not True
                or counts.get("shared_guarded_process_tree_tools_preserved")
                is not True
            ):
                problems.append("stage3_shared_guard_not_preserved")

        output_valid = False
        code_steps: list[Any] = []
        try:
            output = json.loads(str(run.get("output_text") or ""))
            if isinstance(output, dict):
                output_valid = True
                raw_steps = output.get("code_steps")
                if isinstance(raw_steps, list):
                    code_steps = raw_steps
                else:
                    problems.append("code_steps_not_list")
        except Exception:
            output = None
        if not output_valid:
            problems.append("invalid_output_text_json")

        usage = run.get("usage") or {}
        input_tokens = int(usage.get("input_tokens") or 0)
        output_tokens = int(usage.get("output_tokens") or 0)
        cached_tokens = int(usage.get("cached_input_tokens") or 0)
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
            total_cost += run_cost

        metrics = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_input_tokens": cached_tokens,
            "code_steps": len(code_steps),
            "empty_code_step_runs": int(not code_steps),
        }
        totals.update(metrics)
        model_totals[model].update(metrics)
        model_totals[model]["cost_micro_usd"] += round(run_cost * 1_000_000)

        report = {
            "model": model,
            "instance_id": instance_id,
            "stage": stage,
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
                    "model": model,
                    "instance_id": instance_id,
                    "problems": problems,
                }
            )

    missing = sorted(expected_keys - seen)
    unexpected = sorted(seen - expected_keys)
    if missing:
        failures.append({"check": "missing_runs", "keys": missing})
    if unexpected:
        failures.append({"check": "unexpected_runs", "keys": unexpected})

    expected_stage_counts = {stage: 16 for stage in STAGES}
    if dict(stage_counts) != expected_stage_counts:
        failures.append(
            {
                "check": "stage_counts",
                "expected": expected_stage_counts,
                "actual": dict(stage_counts),
            }
        )
    expected_model_counts = {model: 24 for model in MODELS}
    if dict(model_counts) != expected_model_counts:
        failures.append(
            {
                "check": "model_counts",
                "expected": expected_model_counts,
                "actual": dict(model_counts),
            }
        )
    expected_model_stage = {
        f"{model}/{stage}": 8 for model in MODELS for stage in STAGES
    }
    actual_model_stage = {
        f"{model}/{stage}": model_stage_counts[(model, stage)]
        for model in MODELS
        for stage in STAGES
    }
    if actual_model_stage != expected_model_stage:
        failures.append(
            {
                "check": "model_stage_counts",
                "expected": expected_model_stage,
                "actual": actual_model_stage,
            }
        )
    if len(paths) != 48:
        failures.append(
            {"check": "run_count", "expected": 48, "actual": len(paths)}
        )

    by_model: dict[str, Any] = {}
    for model in MODELS:
        item = model_totals[model]
        by_model[model] = {
            "run_count": model_counts[model],
            "stage_counts": {
                stage: model_stage_counts[(model, stage)] for stage in STAGES
            },
            "input_tokens": item["input_tokens"],
            "output_tokens": item["output_tokens"],
            "cached_input_tokens": item["cached_input_tokens"],
            "total_tokens": item["input_tokens"] + item["output_tokens"],
            "code_steps": item["code_steps"],
            "empty_code_step_runs": item["empty_code_step_runs"],
            "cost_usd": round(item["cost_micro_usd"] / 1_000_000, 8),
        }

    return {
        "status": "pass" if not failures else "fail",
        "audit_contract": "process_chain_v5_two_model_baseline_v1",
        "result_root": str(args.result_root.resolve()),
        "replacement_runs": [
            {
                "model": model,
                "instance_id": instance_id,
                "path": str(path),
                "sha256": sha256(path),
            }
            for (model, instance_id), path in sorted(replacement_by_key.items())
        ],
        "cases": str(args.cases.resolve()),
        "expected_run_count": 48,
        "actual_run_count": len(paths),
        "models": list(MODELS),
        "model_counts": dict(model_counts),
        "stage_counts": dict(stage_counts),
        "model_stage_counts": actual_model_stage,
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
        "stage3_filter_pass_count": sum(
            report["stage"] == "stage3"
            and not any(problem.startswith("stage3_") for problem in report["problems"])
            for report in run_reports
        ),
        "total_input_tokens": totals["input_tokens"],
        "total_output_tokens": totals["output_tokens"],
        "total_cached_input_tokens": totals["cached_input_tokens"],
        "total_tokens": totals["input_tokens"] + totals["output_tokens"],
        "total_cost_usd": round(total_cost, 8),
        "total_code_steps": totals["code_steps"],
        "empty_code_step_runs": totals["empty_code_step_runs"],
        "by_model": by_model,
        "failure_count": len(failures),
        "failures": failures,
        "runs": run_reports,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--cost-csv", type=Path, default=DEFAULT_COST_CSV)
    parser.add_argument(
        "--replacement-run",
        type=Path,
        action="append",
        help="replace the matching model/instance run with this create-only retry artifact",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args)
    write_json_new(args.out, report)
    print(
        json.dumps(
            {
                key: value
                for key, value in report.items()
                if key not in ("runs", "failures")
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if report["status"] != "pass":
        print(json.dumps(report["failures"], ensure_ascii=False, indent=2))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
