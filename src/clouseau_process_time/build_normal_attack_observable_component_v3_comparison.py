"""Build a provenance-bound normal/attack observable-component v3 comparison.

This script is intentionally read-only with respect to run and score artifacts.
It refuses to overwrite its JSON and Markdown outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


METRICS = (
    "action_step_recall",
    "candidate_claim_precision",
    "behavior_step_recall",
    "behavior_sequence_order",
    "critical_evidence_recall",
)
STAGES = ("stage1", "stage2", "stage3")


def io_path(path: Path) -> Path:
    """Return a Windows extended-length path when the resolved path is long."""
    resolved = path.resolve()
    text = str(resolved)
    if len(text) >= 248 and not text.startswith("\\\\?\\"):
        return Path("\\\\?\\" + text)
    return resolved


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with io_path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(io_path(path).read_text(encoding="utf-8"))


def metric_record(normal: dict[str, Any], attack: dict[str, Any], key: str) -> dict[str, Any]:
    n = normal[key]
    a = attack[key]
    return {
        "normal": n,
        "attack": a,
        "absolute_delta_normal_minus_attack": n["value"] - a["value"],
        "normal_to_attack_ratio": None if a["value"] == 0 else n["value"] / a["value"],
    }


def validate_aggregate(name: str, data: dict[str, Any]) -> None:
    if data.get("complete") is not True:
        raise ValueError(f"{name} aggregate is not complete")
    if data.get("adopted_run_count") != 24:
        raise ValueError(f"{name} adopted_run_count is not 24")
    if data.get("excluded_conflict_count") != 0:
        raise ValueError(f"{name} has excluded conflicts")
    for stage in STAGES:
        stage_data = data.get("by_stage", {}).get(stage, {})
        if stage_data.get("adopted_run_count") != 8:
            raise ValueError(f"{name} {stage} adopted_run_count is not 8")
        for metric in METRICS:
            if metric not in stage_data.get("metrics", {}):
                raise ValueError(f"{name} {stage} missing {metric}")
    for metric in METRICS:
        if metric not in data.get("overall", {}):
            raise ValueError(f"{name} overall missing {metric}")


def validate_run_audit(name: str, data: dict[str, Any]) -> None:
    if str(data.get("status", "")).lower() != "pass":
        raise ValueError(f"{name} run audit did not pass")
    expected = {
        "actual_run_count": 24,
        "valid_output_json_count": 24,
        "error_free_run_count": 24,
        "unbounded_agent_config_count": 24,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ValueError(f"{name} run audit {key} is not {value}")
    if data.get("stage_counts") != {"stage1": 8, "stage2": 8, "stage3": 8}:
        raise ValueError(f"{name} run audit stage counts are not 8/8/8")


def format_fraction(record: dict[str, Any]) -> str:
    return f'{record["hits"]}/{record["total"]} = {record["value"]:.4f}'


def build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Normal / attack observable-component v3 formal comparison",
        "",
        "## Contract",
        "",
        "- Model: `gpt-5.4-mini`",
        "- Replicates: one formal pilot replicate per class",
        "- Cases: 8 normal and 8 attack use cases × 3 stages = 24 runs per class",
        "- Scope: neutral focus-process anchor and ±5-minute window",
        "- Scoring unit: observable semantic step components (subject/action/object)",
        "- Alert mapping: hidden or unavailable alert-to-Gold correspondence is not scored",
        "- Agent calls: unbounded by the experiment in all 48 runs",
        "- Review: offline Codex independent double review, third review for conflicts",
        "",
        "## Overall",
        "",
        "| Metric | Normal | Attack | Normal − attack | Ratio |",
        "|---|---:|---:|---:|---:|",
    ]
    for metric in METRICS:
        item = report["overall"][metric]
        ratio = item["normal_to_attack_ratio"]
        ratio_text = "n/a" if ratio is None else f"{ratio:.2f}×"
        lines.append(
            f'| {metric} | {format_fraction(item["normal"])} | '
            f'{format_fraction(item["attack"])} | '
            f'{item["absolute_delta_normal_minus_attack"]:+.4f} | {ratio_text} |'
        )

    lines.extend(["", "## By stage", ""])
    for stage in STAGES:
        lines.extend(
            [
                f"### {stage}",
                "",
                "| Metric | Normal | Attack | Normal − attack |",
                "|---|---:|---:|---:|",
            ]
        )
        for metric in METRICS:
            item = report["by_stage"][stage][metric]
            lines.append(
                f'| {metric} | {format_fraction(item["normal"])} | '
                f'{format_fraction(item["attack"])} | '
                f'{item["absolute_delta_normal_minus_attack"]:+.4f} |'
            )
        lines.append("")

    lines.extend(
        [
            "## Interpretation boundary",
            "",
            "This is a one-replicate paired-condition pilot, not an estimate of population-level "
            "model variance. The comparison is authorized because the run window, stage inputs, "
            "call-limit policy, scoring units, and review process are aligned. Differences in "
            "Gold sequence length and behavior composition remain part of the use-case difficulty "
            "and must be discussed rather than normalized away after observing the results.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal-aggregate", type=Path, required=True)
    parser.add_argument("--attack-aggregate", type=Path, required=True)
    parser.add_argument("--normal-run-audit", type=Path, required=True)
    parser.add_argument("--attack-run-audit", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()

    for output in (args.output_json, args.output_md):
        if output.exists():
            raise FileExistsError(f"refusing to overwrite {output}")

    normal = load_json(args.normal_aggregate)
    attack = load_json(args.attack_aggregate)
    normal_run = load_json(args.normal_run_audit)
    attack_run = load_json(args.attack_run_audit)
    validate_aggregate("normal", normal)
    validate_aggregate("attack", attack)
    validate_run_audit("normal", normal_run)
    validate_run_audit("attack", attack_run)

    report: dict[str, Any] = {
        "schema_version": "normal_attack_observable_component_v3_comparison_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pass",
        "formal_comparison_authorized": True,
        "contract": {
            "model": "gpt-5.4-mini",
            "replicate_count_per_class": 1,
            "runs_per_class": 24,
            "stage_counts_per_class": {"stage1": 8, "stage2": 8, "stage3": 8},
            "time_window_minutes": 5,
            "neutral_anchor": True,
            "observable_component_gold": True,
            "alert_mapping_scored": False,
            "agent_call_limit_policy": "unbounded_by_experiment",
            "review_route": "Codex-only independent double review with third review for conflicts",
        },
        "provenance": {
            "normal_aggregate": str(args.normal_aggregate.resolve()),
            "normal_aggregate_sha256": sha256(args.normal_aggregate),
            "attack_aggregate": str(args.attack_aggregate.resolve()),
            "attack_aggregate_sha256": sha256(args.attack_aggregate),
            "normal_run_audit": str(args.normal_run_audit.resolve()),
            "normal_run_audit_sha256": sha256(args.normal_run_audit),
            "attack_run_audit": str(args.attack_run_audit.resolve()),
            "attack_run_audit_sha256": sha256(args.attack_run_audit),
        },
        "overall": {
            metric: metric_record(normal["overall"], attack["overall"], metric)
            for metric in METRICS
        },
        "by_stage": {
            stage: {
                metric: metric_record(
                    normal["by_stage"][stage]["metrics"],
                    attack["by_stage"][stage]["metrics"],
                    metric,
                )
                for metric in METRICS
            }
            for stage in STAGES
        },
        "normal_run_resources": {
            key: normal_run[key]
            for key in (
                "total_input_tokens",
                "total_output_tokens",
                "total_tokens",
                "total_cost_usd",
                "total_code_steps",
                "empty_code_step_runs",
            )
        },
        "attack_run_resources": {
            key: attack_run[key]
            for key in (
                "total_input_tokens",
                "total_output_tokens",
                "total_tokens",
                "total_cost_usd",
                "total_code_steps",
                "empty_code_step_runs",
            )
        },
        "limitations": [
            "one replicate per class; no variance or significance estimate",
            "normal and attack use cases differ in Gold length and behavior composition",
            "the experiment measures reconstruction of observable semantic steps, not attack classification",
            "unavailable alert-to-Gold mapping inference is outside the score",
        ],
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    args.output_md.write_text(build_markdown(report), encoding="utf-8")


if __name__ == "__main__":
    main()
