"""Strict validator for the canonical-evidence S3 attack gold format.

The legacy chain validator searches free-text terms and assumes Stage 1 alert
IDs.  This validator instead verifies the exact CBC row IDs stored in the S3
gold, their immutable fields, window inclusion, per-case evidence uniqueness,
and Stage 3 visibility (no alert-summary dependency).
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db"
DEFAULT_GOLD = ROOT / "data/current_experiment/gold/atlasv2_s3_attack_behavior_chain_gold"
DEFAULT_OUT = ROOT / "docs/current_experiment/atlasv2_s3_attack_canonical_validation_20260719"


IMMUTABLE_FIELDS = ("timestamp_utc", "action", "process_path", "process_pid", "parent_path", "parent_pid", "process_cmdline", "object_name", "remote_ip", "remote_port", "netconn_domain", "childproc_name", "childproc_pid")


def load_cases(gold_root: Path) -> list[Path]:
    return sorted(gold_root.glob("by_chain/*/chain_gold.json"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--gold-root", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    rows = []
    for path in load_cases(args.gold_root):
        case = json.loads(path.read_text(encoding="utf-8"))
        start = case["input_scope"]["chain_window_start_utc"]
        end = case["input_scope"]["chain_window_end_utc"]
        seen_ids: set[int] = set()
        previous_time = ""
        for step in case["gold_steps"]:
            evidence = step["canonical_evidence"]
            status = "pass"
            reasons = []
            if len(evidence) != 1:
                status = "fail"
                reasons.append("each step must have exactly one primary canonical evidence row")
            record = evidence[0] if evidence else {}
            row_id = record.get("source_row_id")
            db_row = con.execute("SELECT * FROM cbc_events WHERE id = ?", (row_id,)).fetchone() if row_id else None
            if record.get("source_stream") != "cbc-edr" or record.get("source_table") != "cbc_events":
                status = "fail"
                reasons.append("primary evidence is not Stage 3-visible CBC telemetry")
            if db_row is None:
                status = "fail"
                reasons.append("canonical row missing from DB")
            else:
                for field in IMMUTABLE_FIELDS:
                    if record.get(field) != db_row[field]:
                        status = "fail"
                        reasons.append(f"canonical {field} differs from DB")
                if not start <= db_row["timestamp_utc"] <= end:
                    status = "fail"
                    reasons.append("evidence lies outside declared time window")
                if previous_time and db_row["timestamp_utc"] < previous_time:
                    status = "fail"
                    reasons.append("steps are not in nondecreasing observed-time order")
                previous_time = db_row["timestamp_utc"]
            if row_id in seen_ids:
                status = "fail"
                reasons.append("primary evidence row reused within case")
            seen_ids.add(row_id)
            rows.append({
                "chain_id": case["chain_id"], "case_group": case["case_group"], "step_id": step["step_id"],
                "source_table": record.get("source_table"), "source_row_id": row_id,
                "timestamp_utc": record.get("timestamp_utc"), "stage3_visible": record.get("source_table") == "cbc_events",
                "status": status, "reasons": "; ".join(reasons),
            })

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "canonical_evidence_validation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    passed = sum(row["status"] == "pass" for row in rows)
    summary = {
        "status": "passed" if passed == len(rows) else "failed",
        "chain_count": len(load_cases(args.gold_root)),
        "step_count": len(rows),
        "passed_step_count": passed,
        "failed_step_count": len(rows) - passed,
        "stage3_visible_step_count": sum(row["stage3_visible"] for row in rows),
        "notes": [
            "This validates canonical event identity and Stage 3 visibility, not whether a model reconstructed the behavior.",
            "Cases from the same S3 incident may overlap and must not be counted as independent attacks unless their provenance says otherwise.",
        ],
    }
    (args.out_dir / "canonical_evidence_validation_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
