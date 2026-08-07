from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
MODEL = "gpt-5.4-mini"
REVIEW_DIRS = ("final_item_review1", "final_item_review2")
STAGES = ("stage1", "stage2", "stage3")


def long_path(path: Path | str) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        return "\\\\?\\" + s
    return s


def file_exists(path: Path) -> bool:
    return os.path.isfile(long_path(path))


def read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with open(long_path(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None, "top-level JSON is not an object"
        return data, None
    except Exception as exc:  # noqa: BLE001
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
    with open(long_path(ROOT / "codex_score_final_gpt54.csv"), "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if r.get("model") == MODEL and r.get("stage") in STAGES]


def validate_review(data: dict[str, Any] | None, stage: str, instance_id: str, review_dir: str) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if data is None:
        return False, ["missing_or_unreadable_json"]
    if data.get("model") != MODEL:
        issues.append(f"model={data.get('model')!r}")
    if data.get("stage") != stage:
        issues.append(f"stage={data.get('stage')!r}")
    if data.get("instance_id") != instance_id:
        issues.append(f"instance_id={data.get('instance_id')!r}")
    reviewer = str(data.get("reviewer", ""))
    if review_dir not in reviewer:
        issues.append(f"reviewer={reviewer!r}")
    if data.get("review_pass") is not True:
        issues.append("review_pass is not true")
    if data.get("recommended_action") != "accept":
        issues.append(f"recommended_action={data.get('recommended_action')!r}")
    checks = data.get("checks")
    if not isinstance(checks, dict):
        issues.append("checks is not an object")
    else:
        for key, value in checks.items():
            if value is not True:
                issues.append(f"check {key} is not true")
    if data.get("issues") not in ([], None):
        issues.append("issues is not empty")
    if "review_summary_ja" not in data:
        issues.append("review_summary_ja missing")
    return not issues, issues


def main() -> int:
    targets = load_targets()
    rows: list[dict[str, Any]] = []
    aggregate: dict[str, Any] = {
        "model": MODEL,
        "target_count": len(targets),
        "review_target_count": len(targets) * len(REVIEW_DIRS),
        "pass_count": 0,
        "fail_count": 0,
        "by_stage": {stage: {"target_count": 0, "double_pass_count": 0, "needs_attention": 0} for stage in STAGES},
        "failures": [],
    }

    for target in targets:
        stage = target["stage"]
        instance_id = target["instance_id"]
        aggregate["by_stage"][stage]["target_count"] += 1
        per_review: dict[str, bool] = {}
        per_issues: dict[str, list[str]] = {}

        for review_dir in REVIEW_DIRS:
            path = ROOT / review_dir / stage / instance_id / "review_result.json"
            data, err = read_json(path) if file_exists(path) else (None, "file_missing")
            ok, issues = validate_review(data, stage, instance_id, review_dir)
            if err:
                issues = [err, *issues]
            ok = ok and err is None
            per_review[review_dir] = ok
            per_issues[review_dir] = issues
            if ok:
                aggregate["pass_count"] += 1
            else:
                aggregate["fail_count"] += 1

        double_pass = all(per_review.values())
        if double_pass:
            aggregate["by_stage"][stage]["double_pass_count"] += 1
        else:
            aggregate["by_stage"][stage]["needs_attention"] += 1
            aggregate["failures"].append(
                {
                    "stage": stage,
                    "instance_id": instance_id,
                    "review1_ok": per_review["final_item_review1"],
                    "review2_ok": per_review["final_item_review2"],
                    "review1_issues": per_issues["final_item_review1"],
                    "review2_issues": per_issues["final_item_review2"],
                }
            )

        rows.append(
            {
                "model": MODEL,
                "stage": stage,
                "instance_id": instance_id,
                "final_item_review1_ok": per_review["final_item_review1"],
                "final_item_review2_ok": per_review["final_item_review2"],
                "double_pass": double_pass,
                "final_item_review1_issues": "; ".join(per_issues["final_item_review1"]),
                "final_item_review2_issues": "; ".join(per_issues["final_item_review2"]),
            }
        )

    write_csv(
        ROOT / "final_item_review_summary_gpt54.csv",
        rows,
        [
            "model",
            "stage",
            "instance_id",
            "final_item_review1_ok",
            "final_item_review2_ok",
            "double_pass",
            "final_item_review1_issues",
            "final_item_review2_issues",
        ],
    )
    write_json(ROOT / "final_item_review_aggregate_gpt54.json", aggregate)
    print(json.dumps(aggregate, ensure_ascii=False, indent=2))
    return 0 if aggregate["fail_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
