#!/usr/bin/env python3
"""Aggregate and audit the single-Codex-review Stage-3 pilot."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import codex_manual_attack8_scoring as scoring


METRICS = (
    "behavior_step_recall",
    "action_step_recall",
    "action_step_precision",
    "behavior_sequence_order",
    "critical_evidence_recall",
    "candidate_claim_precision",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json_new(path: Path, payload: Any) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl_new(path: Path, rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def cost_rows(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            run_id = str(row.get("run_id") or "")
            if run_id:
                result[run_id] = row
    return result


def metric_rollup(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for metric in METRICS:
        hits = sum(int(row["totals"][f"{metric}_hits"]) for row in rows)
        total = sum(int(row["totals"][f"{metric}_total"]) for row in rows)
        result[metric] = {
            "hits": hits,
            "total": total,
            "value": hits / total if total else None,
        }
    result["candidate_slots"] = sum(
        int(row["totals"]["candidate_action_claim_slot_count"]) for row in rows
    )
    result["candidate_true_positive_slots"] = sum(
        int(row["totals"]["candidate_action_claim_true_positive_slot_count"])
        for row in rows
    )
    result["overclaim_slots"] = (
        result["candidate_slots"] - result["candidate_true_positive_slots"]
    )
    result["input_tokens"] = sum(int(row["usage"]["input_tokens"]) for row in rows)
    result["output_tokens"] = sum(int(row["usage"]["output_tokens"]) for row in rows)
    result["cached_input_tokens"] = sum(
        int(row["usage"].get("cached_input_tokens") or 0) for row in rows
    )
    result["total_tokens"] = result["input_tokens"] + result["output_tokens"]
    result["cost_usd"] = sum(float(row["cost"]["total_cost_usd"]) for row in rows)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--validated-review", type=Path, required=True)
    parser.add_argument("--cost-log", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    queue_rows = scoring.read_jsonl(args.queue)
    queues = {str(row["queue_id"]): row for row in queue_rows}
    reviews = scoring.read_jsonl(args.validated_review)
    costs = cost_rows(args.cost_log)
    failures: list[str] = []
    adopted: list[dict[str, Any]] = []

    if len(queue_rows) != 4 or len(reviews) != 4:
        failures.append("queue/review count is not 4")
    if {str(row["queue_id"]) for row in reviews} != set(queues):
        failures.append("queue/review ID set mismatch")

    for review in reviews:
        queue = queues[str(review["queue_id"])]
        run_path = Path(queue["run_json"])
        run = json.loads(run_path.read_text(encoding="utf-8"))
        run_failures: list[str] = []
        try:
            output = json.loads(run["output_text"])
            if not isinstance(output, dict):
                run_failures.append("output_text root is not an object")
        except Exception as exc:
            run_failures.append(f"output_text invalid JSON: {exc}")
        if run.get("error"):
            run_failures.append(f"run error: {run['error']}")
        config = run.get("configs") or {}
        if (
            config.get("max_investigations"),
            config.get("max_questions"),
            config.get("max_queries"),
            config.get("agent_call_limit_policy"),
        ) != (None, None, None, "unbounded_by_experiment"):
            run_failures.append("agent-call configuration mismatch")
        if run.get("experiment_stage") != "stage3":
            run_failures.append("not Stage 3")
        if run.get("expected_input_fields") != ["host", "process", "timestamp"]:
            run_failures.append("unexpected Stage-3 input fields")
        counts = run.get("adapter_counts") or {}
        filter_mode = counts.get("cbc_alert_summary_filter_mode")
        if (
            filter_mode
            not in {"sql_tool_temp_view", "physical_adapter_copy_v2"}
            or counts.get("post_filter_cbc_alert_summary_rows") != 0
        ):
            run_failures.append("CBC alert summary filter mismatch")
        if filter_mode == "physical_adapter_copy_v2" and (
            counts.get("shared_guarded_sql_tools_preserved") is not True
            or counts.get("shared_guarded_process_tree_tools_preserved")
            is not True
        ):
            run_failures.append("Stage3 shared guard preservation mismatch")
        if sha256(run_path) != queue["run_sha256"]:
            run_failures.append("run SHA-256 mismatch")
        gold_path = Path(queue["gold_json"])
        if sha256(gold_path) != queue["gold_sha256"]:
            run_failures.append("Gold SHA-256 mismatch")
        if run_failures:
            failures.extend(
                f"{queue['model']}/{queue['instance_id']}: {item}"
                for item in run_failures
            )
        cost = costs.get(str(run["run_id"]))
        if cost is None:
            failures.append(f"{run['run_id']}: cost row not found")
            cost = {"call_total_usd": "0"}
        totals = scoring.totals_from_review(review, queue)
        adopted.append(
            {
                "queue_id": queue["queue_id"],
                "model": queue["model"],
                "stage": queue["stage"],
                "instance_id": queue["instance_id"],
                "reviewer_id": review["reviewer_id"],
                "decision_sha256": review["decision_sha256"],
                "run_sha256": queue["run_sha256"],
                "gold_sha256": queue["gold_sha256"],
                "contract_sha256": queue["contract_sha256"],
                "totals": totals,
                "usage": run["usage"],
                "cost": {
                    "total_cost_usd": float(cost["call_total_usd"]),
                },
                "code_step_count": len(
                    (json.loads(run["output_text"]).get("code_steps") or [])
                ),
                "decisions": {
                    "gold_items": review["gold_items"],
                    "order_pairs": review["order_pairs"],
                    "candidate_slots": review["candidate_slots"],
                },
            }
        )

    by_model: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in adopted:
        by_model[str(row["model"])].append(row)
        by_case[str(row["instance_id"])].append(row)

    payload = {
        "status": "pass" if not failures else "fail",
        "review_mode": (
            "single Codex item-level pilot review plus deterministic schema, "
            "denominator, totals, run/Gold-hash, Stage-3-filter, and cost audit"
        ),
        "judge_api_used": False,
        "case_count": len(adopted),
        "models": sorted(by_model),
        "stages": ["stage3"],
        "selected_usecases": sorted(by_case),
        "per_run": [
            {
                key: row[key]
                for key in (
                    "model",
                    "instance_id",
                    "totals",
                    "usage",
                    "cost",
                    "code_step_count",
                    "run_sha256",
                    "gold_sha256",
                    "decision_sha256",
                )
            }
            for row in adopted
        ],
        "by_model": {
            model: metric_rollup(rows) for model, rows in sorted(by_model.items())
        },
        "by_usecase": {
            instance_id: {
                model: metric_rollup(
                    [row for row in rows if row["model"] == model]
                )
                for model in sorted({str(row["model"]) for row in rows})
            }
            for instance_id, rows in sorted(by_case.items())
        },
        "overall": metric_rollup(adopted),
        "audit": {
            "run_count_expected": 4,
            "run_count_actual": len(adopted),
            "unresolved_conflicts": 0,
            "queue_sha256": sha256(args.queue),
            "validated_review_sha256": sha256(args.validated_review),
            "failure_count": len(failures),
            "failures": failures,
        },
    }
    write_jsonl_new(args.output_root / "single_codex_reviews.jsonl", adopted)
    write_json_new(args.output_root / "pilot_aggregate.json", payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
