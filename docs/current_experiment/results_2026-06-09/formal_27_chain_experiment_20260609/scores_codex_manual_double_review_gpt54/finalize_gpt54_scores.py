from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
MODEL = "gpt-5.4-mini"
STAGES = ("stage1", "stage2", "stage3")


def long_path(path: Path | str) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        return "\\\\?\\" + s
    return s


def read_json(path: Path) -> dict[str, Any]:
    with open(long_path(path), "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"JSON object expected: {path}")
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    os.makedirs(long_path(path.parent), exist_ok=True)
    with open(long_path(path), "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    os.makedirs(long_path(path.parent), exist_ok=True)
    with open(long_path(path), "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def file_exists(path: Path) -> bool:
    return os.path.isfile(long_path(path))


def load_targets() -> list[dict[str, str]]:
    with open(long_path(ROOT / "target_runs_gpt54.csv"), "r", encoding="utf-8", newline="") as f:
        return [r for r in csv.DictReader(f) if r.get("model") == MODEL and r.get("stage") in STAGES]


def load_comparison(stage: str, instance_id: str) -> dict[str, Any]:
    return read_json(ROOT / "comparisons" / MODEL / stage / instance_id / "review_pair_summary.json")


def validate_final(data: dict[str, Any], stage: str, instance_id: str) -> list[str]:
    issues: list[str] = []
    if data.get("model") != MODEL:
        issues.append(f"model={data.get('model')!r}")
    if data.get("stage") != stage:
        issues.append(f"stage={data.get('stage')!r}")
    if data.get("instance_id") != instance_id:
        issues.append(f"instance_id={data.get('instance_id')!r}")
    if stage == "stage3" and data.get("stage3_answerable_filter_applied") is not True:
        issues.append("stage3_answerable_filter_applied is not true")
    if stage != "stage3" and data.get("stage3_answerable_filter_applied") is not False:
        issues.append("stage3_answerable_filter_applied is not false")
    if not isinstance(data.get("gold_required_item_scores"), list):
        issues.append("gold_required_item_scores is not a list")
    if not isinstance(data.get("order_pair_scores"), list):
        issues.append("order_pair_scores is not a list")
    if not isinstance(data.get("totals"), dict):
        issues.append("totals is not an object")
    return issues


def rate(hits: int, total: int) -> float | None:
    return None if total == 0 else hits / total


def get_num(totals: dict[str, Any], key: str) -> int:
    value = totals.get(key, 0)
    return int(value) if isinstance(value, (int, float)) and value is not None else 0


def main() -> int:
    targets = load_targets()
    final_rows: list[dict[str, Any]] = []
    validation_errors: list[dict[str, Any]] = []
    by_stage: dict[str, dict[str, Any]] = {
        s: {
            "count": 0,
            "two_review_match_count": 0,
            "adjudicated_count": 0,
            "action_step_recall_hits": 0,
            "action_step_recall_total": 0,
            "critical_evidence_recall_hits": 0,
            "critical_evidence_recall_total": 0,
            "behavior_sequence_order_hits": 0,
            "behavior_sequence_order_total": 0,
            "candidate_claim_precision_hits": 0,
            "candidate_claim_precision_total": 0,
            "overclaim_slot_count": 0,
        }
        for s in STAGES
    }

    for row in targets:
        stage = row["stage"]
        instance_id = row["instance_id"]
        comparison = load_comparison(stage, instance_id)
        if comparison.get("two_review_pass") is True:
            source_kind = "two_review_match"
            source_path = ROOT / "review1" / MODEL / stage / instance_id / "codex_score_result.json"
            data = read_json(source_path)
            data = dict(data)
            data["finalization"] = {
                "final_source": source_kind,
                "review_pair_summary": str(ROOT / "comparisons" / MODEL / stage / instance_id / "review_pair_summary.json"),
                "source_review1_path": str(ROOT / "review1" / MODEL / stage / instance_id / "codex_score_result.json"),
                "source_review2_path": str(ROOT / "review2" / MODEL / stage / instance_id / "codex_score_result.json"),
            }
        else:
            source_kind = "adjudicated"
            source_path = ROOT / "adjudicated" / MODEL / stage / instance_id / "codex_score_result.json"
            if not file_exists(source_path):
                validation_errors.append(
                    {"stage": stage, "instance_id": instance_id, "issue": "adjudicated file missing", "path": str(source_path)}
                )
                continue
            data = read_json(source_path)

        issues = validate_final(data, stage, instance_id)
        if issues:
            validation_errors.append({"stage": stage, "instance_id": instance_id, "issue": "; ".join(issues), "path": str(source_path)})
            continue

        final_path = ROOT / "final" / MODEL / stage / instance_id / "codex_score_result.json"
        write_json(final_path, data)

        totals = data["totals"]
        stage_bucket = by_stage[stage]
        stage_bucket["count"] += 1
        stage_bucket["two_review_match_count"] += 1 if source_kind == "two_review_match" else 0
        stage_bucket["adjudicated_count"] += 1 if source_kind == "adjudicated" else 0
        for key in [
            "action_step_recall_hits",
            "action_step_recall_total",
            "critical_evidence_recall_hits",
            "critical_evidence_recall_total",
            "behavior_sequence_order_hits",
            "behavior_sequence_order_total",
            "candidate_claim_precision_hits",
            "candidate_claim_precision_total",
            "overclaim_slot_count",
        ]:
            stage_bucket[key] += get_num(totals, key)

        final_rows.append(
            {
                "model": MODEL,
                "stage": stage,
                "instance_id": instance_id,
                "final_source": source_kind,
                "action_step_recall_hits": get_num(totals, "action_step_recall_hits"),
                "action_step_recall_total": get_num(totals, "action_step_recall_total"),
                "critical_evidence_recall_hits": get_num(totals, "critical_evidence_recall_hits"),
                "critical_evidence_recall_total": get_num(totals, "critical_evidence_recall_total"),
                "behavior_sequence_order_hits": get_num(totals, "behavior_sequence_order_hits"),
                "behavior_sequence_order_total": get_num(totals, "behavior_sequence_order_total"),
                "candidate_claim_precision_hits": get_num(totals, "candidate_claim_precision_hits"),
                "candidate_claim_precision_total": get_num(totals, "candidate_claim_precision_total"),
                "overclaim_slot_count": get_num(totals, "overclaim_slot_count"),
                "final_path": str(final_path),
            }
        )

    aggregate = {"model": MODEL, "target_count": len(targets), "final_count": len(final_rows), "validation_errors": validation_errors, "by_stage": by_stage}
    for stage, bucket in by_stage.items():
        bucket["action_step_recall"] = rate(bucket["action_step_recall_hits"], bucket["action_step_recall_total"])
        bucket["critical_evidence_recall"] = rate(bucket["critical_evidence_recall_hits"], bucket["critical_evidence_recall_total"])
        bucket["behavior_sequence_order"] = rate(bucket["behavior_sequence_order_hits"], bucket["behavior_sequence_order_total"])
        bucket["candidate_claim_precision"] = rate(bucket["candidate_claim_precision_hits"], bucket["candidate_claim_precision_total"])

    write_csv(
        ROOT / "codex_score_final_gpt54.csv",
        final_rows,
        [
            "model",
            "stage",
            "instance_id",
            "final_source",
            "action_step_recall_hits",
            "action_step_recall_total",
            "critical_evidence_recall_hits",
            "critical_evidence_recall_total",
            "behavior_sequence_order_hits",
            "behavior_sequence_order_total",
            "candidate_claim_precision_hits",
            "candidate_claim_precision_total",
            "overclaim_slot_count",
            "final_path",
        ],
    )
    write_json(ROOT / "codex_score_final_aggregate_gpt54.json", aggregate)
    print(json.dumps(aggregate, ensure_ascii=False, indent=2))
    return 0 if len(final_rows) == len(targets) and not validation_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
