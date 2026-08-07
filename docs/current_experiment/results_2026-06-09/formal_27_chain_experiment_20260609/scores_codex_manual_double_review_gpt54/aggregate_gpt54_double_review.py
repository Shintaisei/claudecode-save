from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
MODEL = "gpt-5.4-mini"
REVIEWS = ("review1", "review2")
STAGES = ("stage1", "stage2", "stage3")


def long_path(path: Path | str) -> str:
    """Return a Windows long-path string; harmless on non-Windows."""
    p = Path(path)
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        return "\\\\?\\" + s
    return s


def exists_file(path: Path) -> bool:
    try:
        return os.path.isfile(long_path(path))
    except OSError:
        return False


def read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with open(long_path(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None, "top-level JSON is not an object"
        return data, None
    except Exception as exc:  # noqa: BLE001 - aggregate should report all failures.
        return None, f"{type(exc).__name__}: {exc}"


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


def load_targets() -> list[dict[str, str]]:
    target_csv = ROOT / "target_runs_gpt54.csv"
    with open(long_path(target_csv), "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if r.get("model") == MODEL and r.get("stage") in STAGES]


def score_map(items: Any, key_fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(items, list):
        return {}
    out: dict[str, Any] = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            out[f"__non_object_{i}"] = None
            continue
        key_parts = [str(item.get(k, "")) for k in key_fields]
        key = "|".join(key_parts) if any(key_parts) else str(item.get("item_id", f"idx:{i}"))
        out[key] = item.get("score")
    return out


def validate_review(data: dict[str, Any] | None, row: dict[str, str], review: str) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if data is None:
        return False, ["missing_or_unreadable_json"]
    if data.get("model") != MODEL:
        issues.append(f"model={data.get('model')!r}")
    if data.get("stage") != row["stage"]:
        issues.append(f"stage={data.get('stage')!r}")
    if data.get("instance_id") != row["instance_id"]:
        issues.append(f"instance_id={data.get('instance_id')!r}")
    reviewer = str(data.get("reviewer", ""))
    if review not in reviewer:
        issues.append(f"reviewer={reviewer!r}")
    if row["stage"] == "stage3" and data.get("stage3_answerable_filter_applied") is not True:
        issues.append("stage3_answerable_filter_applied is not true")
    if row["stage"] != "stage3" and data.get("stage3_answerable_filter_applied") is not False:
        issues.append("stage3_answerable_filter_applied is not false")
    if not isinstance(data.get("gold_required_item_scores"), list):
        issues.append("gold_required_item_scores is not a list")
    if not isinstance(data.get("order_pair_scores"), list):
        issues.append("order_pair_scores is not a list")
    if not isinstance(data.get("totals"), dict):
        issues.append("totals is not an object")
    if "judge_summary_ja" not in data:
        issues.append("judge_summary_ja missing")
    return not issues, issues


def comparable_totals(data: dict[str, Any] | None) -> dict[str, Any]:
    totals = data.get("totals", {}) if isinstance(data, dict) else {}
    if not isinstance(totals, dict):
        return {}
    keys = [
        "action_step_recall_hits",
        "action_step_recall_total",
        "critical_evidence_recall_hits",
        "critical_evidence_recall_total",
        "behavior_sequence_order_hits",
        "behavior_sequence_order_total",
        "candidate_claim_precision_hits",
        "candidate_claim_precision_total",
        "overclaim_slot_count",
    ]
    return {k: totals.get(k) for k in keys}


def main() -> int:
    targets = load_targets()
    rows: list[dict[str, Any]] = []
    aggregate: dict[str, Any] = {
        "model": MODEL,
        "target_count": len(targets),
        "by_stage": {stage: {"target_count": 0, "two_review_pass": 0, "needs_adjudication": 0} for stage in STAGES},
        "missing_or_invalid": [],
        "mismatches": [],
    }

    for row in targets:
        stage = row["stage"]
        instance_id = row["instance_id"]
        aggregate["by_stage"][stage]["target_count"] += 1

        review_data: dict[str, dict[str, Any] | None] = {}
        review_errors: dict[str, str | None] = {}
        schema_pass: dict[str, bool] = {}
        schema_issues: dict[str, list[str]] = {}
        paths: dict[str, Path] = {}

        for review in REVIEWS:
            path = ROOT / review / MODEL / stage / instance_id / "codex_score_result.json"
            paths[review] = path
            data, err = read_json(path) if exists_file(path) else (None, "file_missing")
            review_data[review] = data
            review_errors[review] = err
            ok, issues = validate_review(data, row, review)
            if err:
                issues = [err, *issues]
            schema_pass[review] = ok and err is None
            schema_issues[review] = issues

        r1 = review_data["review1"]
        r2 = review_data["review2"]
        totals_match = comparable_totals(r1) == comparable_totals(r2)
        required_scores_match = score_map(
            r1.get("gold_required_item_scores") if isinstance(r1, dict) else None,
            ("item_id", "step_id", "kind"),
        ) == score_map(
            r2.get("gold_required_item_scores") if isinstance(r2, dict) else None,
            ("item_id", "step_id", "kind"),
        )
        order_scores_match = score_map(
            r1.get("order_pair_scores") if isinstance(r1, dict) else None,
            ("before_step_id", "after_step_id"),
        ) == score_map(
            r2.get("order_pair_scores") if isinstance(r2, dict) else None,
            ("before_step_id", "after_step_id"),
        )
        two_review_pass = (
            schema_pass["review1"]
            and schema_pass["review2"]
            and totals_match
            and required_scores_match
            and order_scores_match
        )

        if two_review_pass:
            aggregate["by_stage"][stage]["two_review_pass"] += 1
        else:
            aggregate["by_stage"][stage]["needs_adjudication"] += 1
            if not schema_pass["review1"] or not schema_pass["review2"]:
                aggregate["missing_or_invalid"].append(instance_id)
            else:
                aggregate["mismatches"].append(instance_id)

        summary = {
            "model": MODEL,
            "stage": stage,
            "instance_id": instance_id,
            "review1_path": str(paths["review1"]),
            "review2_path": str(paths["review2"]),
            "review1_schema_pass": schema_pass["review1"],
            "review2_schema_pass": schema_pass["review2"],
            "review1_issues": schema_issues["review1"],
            "review2_issues": schema_issues["review2"],
            "totals_match": totals_match,
            "required_scores_match": required_scores_match,
            "order_scores_match": order_scores_match,
            "two_review_pass": two_review_pass,
            "review1_totals": comparable_totals(r1),
            "review2_totals": comparable_totals(r2),
        }
        write_json(ROOT / "comparisons" / MODEL / stage / instance_id / "review_pair_summary.json", summary)

        totals = comparable_totals(r1 if two_review_pass else None)
        rows.append(
            {
                "model": MODEL,
                "stage": stage,
                "instance_id": instance_id,
                "review1_schema_pass": schema_pass["review1"],
                "review2_schema_pass": schema_pass["review2"],
                "totals_match": totals_match,
                "required_scores_match": required_scores_match,
                "order_scores_match": order_scores_match,
                "two_review_pass": two_review_pass,
                **totals,
                "review1_issues": "; ".join(schema_issues["review1"]),
                "review2_issues": "; ".join(schema_issues["review2"]),
            }
        )

    fieldnames = [
        "model",
        "stage",
        "instance_id",
        "review1_schema_pass",
        "review2_schema_pass",
        "totals_match",
        "required_scores_match",
        "order_scores_match",
        "two_review_pass",
        "action_step_recall_hits",
        "action_step_recall_total",
        "critical_evidence_recall_hits",
        "critical_evidence_recall_total",
        "behavior_sequence_order_hits",
        "behavior_sequence_order_total",
        "candidate_claim_precision_hits",
        "candidate_claim_precision_total",
        "overclaim_slot_count",
        "review1_issues",
        "review2_issues",
    ]
    write_csv(ROOT / "codex_score_summary_gpt54.csv", rows, fieldnames)
    write_json(ROOT / "codex_score_aggregate_gpt54.json", aggregate)

    print(json.dumps(aggregate, ensure_ascii=False, indent=2))
    return 0 if not aggregate["missing_or_invalid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
