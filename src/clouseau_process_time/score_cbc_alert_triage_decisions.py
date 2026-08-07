"""Score alert-level and host-level dispositions for the TP/FP CBC suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_json(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def score_case(gold_path: Path, run_path: Path | None) -> dict:
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    expected = gold["decision_scoring"]
    actual: dict = {}
    if run_path and run_path.exists():
        run = json.loads(run_path.read_text(encoding="utf-8"))
        actual = parse_json(run.get("output_text"))
    decision = actual.get(expected["required_output_path"], {}) if isinstance(actual, dict) else {}
    if not isinstance(decision, dict):
        decision = {}
    alert_expected = expected["alert_disposition"]["expected"]
    host_expected = expected["host_disposition"]["expected"]
    alert_actual = decision.get("alert_disposition")
    host_actual = decision.get("host_disposition")
    return {
        "chain_id": gold["chain_id"],
        "run_path": str(run_path) if run_path else None,
        "alert_disposition_expected": alert_expected,
        "alert_disposition_actual": alert_actual,
        "alert_disposition_score": int(alert_actual == alert_expected),
        "host_disposition_expected": host_expected,
        "host_disposition_actual": host_actual,
        "host_disposition_score": int(host_actual == host_expected),
        "decision_score_max": 2,
        "decision_score": int(alert_actual == alert_expected) + int(host_actual == host_expected),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gold-root", type=Path, required=True)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for gold_path in sorted(args.gold_root.glob("by_chain/*/chain_gold.json")):
        chain_id = json.loads(gold_path.read_text(encoding="utf-8"))["chain_id"]
        matches = sorted(args.runs_root.glob(f"*{chain_id}_stage1*/run.json"))
        results.append(score_case(gold_path, matches[-1] if matches else None))
    summary = {
        "case_count": len(results),
        "decision_score": sum(row["decision_score"] for row in results),
        "decision_score_max": sum(row["decision_score_max"] for row in results),
        "rows": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: summary[key] for key in ("case_count", "decision_score", "decision_score_max")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
