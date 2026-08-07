#!/usr/bin/env python3
"""Build a Stage3-aligned non-alert chain gold dataset.

The original 2026-06-09 chain gold used CBC alert rows as part of the
supporting evidence.  This builder creates a separate gold root whose retained
steps are supported after alert-summary rows are removed.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SOURCE_GOLD_ROOT = ROOT / "data" / "current_experiment" / "gold" / "cbc_alert_behavior_chain_gold"
OUT_GOLD_ROOT = ROOT / "data" / "current_experiment" / "gold" / "cbc_non_alert_behavior_chain_gold_2026-06-11"
VALIDATION_STEPS = (
    ROOT
    / "docs"
    / "current_experiment"
    / "chain_gold_validation_2026-06-09"
    / "chain_gold_db_validation_steps_2026-06-09.csv"
)
OUT_VALIDATION_ROOT = (
    ROOT / "docs" / "current_experiment" / "chain_gold_validation_non_alert_2026-06-11"
)
EVALUATION_UNIT = "cbc_non_alert_behavior_chain_gold_2026-06-11"
POLICY_NOTE = (
    "CBC alert rows, alert IDs, alert names, report names, and alert reasons are "
    "not valid gold critical evidence. Retained steps must be supported by "
    "non-alert telemetry after alert-summary rows are removed."
)
MATERIAL_SAMPLE_FIELDS = [
    "stream_name",
    "type",
    "action",
    "process_path",
    "parent_path",
    "process_cmdline",
    "parent_cmdline",
    "object_type",
    "object_name",
    "childproc_name",
    "filemod_name",
    "regmod_name",
    "modload_name",
    "crossproc_name",
    "crossproc_api",
    "remote_ip",
    "remote_port",
    "local_ip",
    "local_port",
    "netconn_domain",
    "timestamp_utc",
    "id",
]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_validation(path: Path) -> tuple[dict[tuple[str, str], dict[str, str]], list[dict[str, str]]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows.extend(csv.DictReader(handle))
    return {(row["chain_id"], row["step_id"]): row for row in rows}, rows


def parse_sample(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def compact_sample(sample: dict[str, Any]) -> dict[str, Any]:
    return {key: sample[key] for key in MATERIAL_SAMPLE_FIELDS if sample.get(key) not in (None, "")}


def evidence_basis(row: dict[str, str]) -> str:
    table = row.get("stage3_best_table") or "non_alert_telemetry"
    sample = compact_sample(parse_sample(row.get("stage3_sample")))
    fields = []
    for key, value in sample.items():
        fields.append(f"{key}={value}")
        if len(fields) >= 8:
            break
    suffix = "; ".join(fields) if fields else f"terms={row.get('terms', '')}"
    return f"Non-alert telemetry ({table}) all-term support: {suffix}"


def source_type(row: dict[str, str]) -> str:
    table = row.get("stage3_best_table")
    if table == "cbc_events":
        return "CBC event telemetry"
    if table:
        return f"{table} telemetry"
    return "non-alert telemetry"


def non_alert_sample_log(row: dict[str, str]) -> str:
    table = row.get("stage3_best_table") or "non_alert_telemetry"
    sample = compact_sample(parse_sample(row.get("stage3_sample")))
    return f"{table} {json.dumps(sample, ensure_ascii=False, sort_keys=True)}"


def renumber_order_pairs(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "before_step_id": before["step_id"],
            "after_step_id": after["step_id"],
            "relation": "before",
        }
        for before, after in zip(steps, steps[1:])
    ]


def scrub_chain(gold: dict[str, Any], validation: dict[tuple[str, str], dict[str, str]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    chain_id = gold["chain_id"]
    retained: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for step in gold.get("gold_steps", []):
        step_id = step.get("step_id")
        row = validation.get((chain_id, step_id))
        if not row or row.get("stage3_status") != "pass":
            dropped.append(
                {
                    "chain_id": chain_id,
                    "step_id": step_id,
                    "order": step.get("order"),
                    "reason": row.get("stage3_status") if row else "missing_validation_row",
                    "best_table": row.get("best_table") if row else None,
                    "stage3_best_table": row.get("stage3_best_table") if row else None,
                }
            )
            continue
        item = dict(step)
        item["non_alert_source_status"] = "stage3_status=pass"
        item["original_evidence_basis"] = step.get("evidence_basis")
        item["evidence_basis"] = evidence_basis(row)
        item["critical_evidence_policy"] = POLICY_NOTE
        item["supporting_evidence"] = {
            "source_types": [source_type(row)],
            "sample_logs": [non_alert_sample_log(row)],
            "stage3_best_table": row.get("stage3_best_table"),
            "stage3_best_count": int(row.get("stage3_best_count") or 0),
        }
        item.pop("alert_evidence_basis", None)
        retained.append(item)

    for order, step in enumerate(sorted(retained, key=lambda value: int(value.get("order") or 0)), start=1):
        step["original_order"] = step.get("order")
        step["order"] = order

    cleaned = dict(gold)
    cleaned["evaluation_unit"] = EVALUATION_UNIT
    cleaned["gold_policy_note"] = POLICY_NOTE
    cleaned["critical_evidence_policy"] = POLICY_NOTE
    cleaned["source_gold_root"] = str(SOURCE_GOLD_ROOT.relative_to(ROOT))
    cleaned["source_validation_steps"] = str(VALIDATION_STEPS.relative_to(ROOT))
    cleaned["behavior_timeline"] = retained
    cleaned["gold_steps"] = retained
    cleaned["timeline_ja"] = [step.get("one_line_ja", "") for step in retained if step.get("one_line_ja")]
    cleaned["gold_order_pairs"] = renumber_order_pairs(retained)
    input_scope = dict(cleaned.get("input_scope") or {})
    input_scope["alert_count"] = 0
    input_scope["alert_names"] = []
    input_scope["source_streams"] = ["cbc-edr non-alert events"]
    input_scope["input_policy"] = POLICY_NOTE
    input_scope["gold_evidence_policy"] = POLICY_NOTE
    cleaned["input_scope"] = input_scope
    cleaned["dropped_alert_only_steps"] = dropped
    cleaned["gold_step_count"] = len(retained)
    return cleaned, dropped


def chain_summary_row(gold: dict[str, Any], dropped: list[dict[str, Any]], rel_file: str) -> dict[str, Any]:
    scope = gold.get("input_scope") or {}
    return {
        "chain_id": gold.get("chain_id"),
        "episode_id": gold.get("episode_id"),
        "chain_type": gold.get("chain_type"),
        "chain_title": gold.get("chain_title"),
        "source_window_ids": ";".join(gold.get("source_window_ids") or []),
        "focus_processes": ";".join(scope.get("focus_processes") or []),
        "chain_window_start_utc": scope.get("chain_window_start_utc"),
        "chain_window_end_utc": scope.get("chain_window_end_utc"),
        "gold_step_count": len(gold.get("gold_steps") or []),
        "dropped_alert_only_step_count": len(dropped),
        "evaluable": bool(gold.get("gold_steps")),
        "chain_gold_file": rel_file,
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def build(args: argparse.Namespace) -> None:
    source_root = args.source_gold_root
    out_root = args.out_gold_root
    out_validation_root = args.out_validation_root
    if out_root.exists():
        shutil.rmtree(out_root)
    if out_validation_root.exists():
        shutil.rmtree(out_validation_root)
    validation, validation_rows = read_validation(args.validation_steps)
    validation_pass = {key for key, row in validation.items() if row.get("stage3_status") == "pass"}

    summaries: list[dict[str, Any]] = []
    all_steps: list[dict[str, Any]] = []
    all_steps_jsonl: list[dict[str, Any]] = []
    dropped_steps: list[dict[str, Any]] = []
    index_chains: list[dict[str, Any]] = []

    for source_file in sorted((source_root / "by_chain").glob("*/chain_gold.json")):
        source_gold = read_json(source_file)
        cleaned, dropped = scrub_chain(source_gold, validation)
        rel_dir = Path("by_chain") / source_file.parent.name
        rel_file = rel_dir / "chain_gold.json"
        write_json(out_root / rel_file, cleaned)
        dropped_steps.extend(dropped)
        summary = chain_summary_row(cleaned, dropped, rel_file.as_posix())
        summaries.append(summary)
        index_chains.append(
            {
                **summary,
                "case_score_max": len(cleaned.get("gold_steps") or []) * 4
                + max(len(cleaned.get("gold_steps") or []) - 1, 0),
            }
        )
        for step in cleaned.get("gold_steps") or []:
            flat = {
                "chain_id": cleaned.get("chain_id"),
                "step_id": step.get("step_id"),
                "order": step.get("order"),
                "original_order": step.get("original_order"),
                "subject": step.get("subject"),
                "action": step.get("action"),
                "object": step.get("object"),
                "evidence_basis": step.get("evidence_basis"),
                "non_alert_source_status": step.get("non_alert_source_status"),
                "source_types": ";".join((step.get("supporting_evidence") or {}).get("source_types") or []),
            }
            all_steps.append(flat)
            all_steps_jsonl.append({**flat, "supporting_evidence": step.get("supporting_evidence")})

    index = {
        "evaluation_unit": EVALUATION_UNIT,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_gold_root": str(source_root.relative_to(ROOT)),
        "source_validation_steps": str(args.validation_steps.relative_to(ROOT)),
        "gold_policy_note": POLICY_NOTE,
        "chain_count": len(index_chains),
        "evaluable_chain_count": sum(1 for chain in index_chains if chain["evaluable"]),
        "zero_denominator_chain_count": sum(1 for chain in index_chains if not chain["evaluable"]),
        "gold_step_count": len(all_steps),
        "dropped_alert_only_step_count": len(dropped_steps),
        "chains": index_chains,
        "dropped_alert_only_steps": dropped_steps,
    }
    write_json(out_root / "chain_gold_index.json", index)
    write_csv(
        out_root / "chain_summary.csv",
        summaries,
        [
            "chain_id",
            "episode_id",
            "chain_type",
            "chain_title",
            "source_window_ids",
            "focus_processes",
            "chain_window_start_utc",
            "chain_window_end_utc",
            "gold_step_count",
            "dropped_alert_only_step_count",
            "evaluable",
            "chain_gold_file",
        ],
    )
    write_csv(
        out_root / "all_chain_steps.csv",
        all_steps,
        [
            "chain_id",
            "step_id",
            "order",
            "original_order",
            "subject",
            "action",
            "object",
            "evidence_basis",
            "non_alert_source_status",
            "source_types",
        ],
    )
    (out_root / "all_chain_steps.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in all_steps_jsonl),
        encoding="utf-8",
    )
    write_json(out_root / "dropped_alert_only_steps.json", dropped_steps)
    (out_root / "README.md").write_text(
        "\n".join(
            [
                "# CBC Non-Alert Behavior Chain Gold (2026-06-11)",
                "",
                "This gold root is derived from `cbc_alert_behavior_chain_gold` but removes CBC alert rows as valid gold evidence.",
                "",
                f"- Chains: {index['chain_count']}",
                f"- Evaluable chains: {index['evaluable_chain_count']}",
                f"- Zero-denominator chains: {index['zero_denominator_chain_count']}",
                f"- Retained non-alert-supported steps: {index['gold_step_count']}",
                f"- Dropped alert-only steps: {index['dropped_alert_only_step_count']}",
                "",
                "Policy: CBC alert IDs, alert names, report names, and alert reasons are not valid critical evidence for this gold.",
                "A retained step must have `stage3_status=pass` in the 2026-06-09 DB validation file.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    out_validation_root.mkdir(parents=True, exist_ok=True)
    retained_rows = [row for row in validation_rows if (row["chain_id"], row["step_id"]) in validation_pass]
    write_csv(out_validation_root / "chain_gold_db_validation_steps_non_alert_2026-06-11.csv", retained_rows, list(validation_rows[0].keys()))
    validation_summary = {
        "status": "passed_non_alert_gold_rebuild",
        "source_validation_steps": str(args.validation_steps.relative_to(ROOT)),
        "gold_root": str(out_root.relative_to(ROOT)),
        "chain_count": index["chain_count"],
        "evaluable_chain_count": index["evaluable_chain_count"],
        "zero_denominator_chain_count": index["zero_denominator_chain_count"],
        "gold_step_count": index["gold_step_count"],
        "dropped_alert_only_step_count": index["dropped_alert_only_step_count"],
        "dropped_alert_only_steps": [step["step_id"] for step in dropped_steps],
        "notes": [
            "CBC alert rows are excluded as valid gold evidence.",
            "Retained rows are the previous validation rows with stage3_status=pass.",
            "chain_03, chain_08, chain_20, and chain_27 have no retained steps and are zero-denominator chains.",
        ],
    }
    write_json(out_validation_root / "chain_gold_db_validation_summary_non_alert_2026-06-11.json", validation_summary)
    (out_validation_root / "README.md").write_text(
        "\n".join(
            [
                "# Non-Alert Gold Validation (2026-06-11)",
                "",
                "This validation package records the rebuild of Stage3-aligned gold that excludes CBC alert evidence.",
                "",
                f"- Retained steps: {index['gold_step_count']}",
                f"- Dropped alert-only steps: {index['dropped_alert_only_step_count']}",
                f"- Zero-denominator chains: {index['zero_denominator_chain_count']}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-gold-root", type=Path, default=SOURCE_GOLD_ROOT)
    parser.add_argument("--validation-steps", type=Path, default=VALIDATION_STEPS)
    parser.add_argument("--out-gold-root", type=Path, default=OUT_GOLD_ROOT)
    parser.add_argument("--out-validation-root", type=Path, default=OUT_VALIDATION_ROOT)
    build(parser.parse_args())


if __name__ == "__main__":
    main()
