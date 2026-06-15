from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
COMPONENT_LEDGER = ROOT / "data/current_experiment/scores/component_rubric_20260614/codex_component_double_reviews.jsonl"
LEGACY_27_FILTERED = ROOT / "data/current_experiment/scores/non_alert_existing_review_reaggregate_20260611/non_alert_per_case_scores.csv"
OUT_DIR = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_component_3run_filtered_20260614"

MODELS = {"gpt-4.1-mini", "gpt-5.4-mini"}
CURRENT_REPLICATES = {"replicate_01", "replicate_02"}
LEGACY_REPLICATE = "legacy_27_filtered_20260609"

FRAMEWORK_LABELS = {
    "dns_packet_capture_batch_chain": "collection_or_tool_invocation",
    "python_simplehttpserver_network_chain": "network_service_behavior",
    "sublime_python_script_execution_chain": "script_execution_chain",
    "cmdexe_other_chain": "command_shell_execution",
    "discord_run_key_registry_chain": "persistence_registry_run_key",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def as_int(row: dict[str, Any], field: str) -> int:
    return int(float(row.get(field) or 0))


def ratio(hit: int, total: int) -> str:
    if total == 0:
        return "NA"
    return f"{hit / total:.3f}"


def current_case_keys() -> set[tuple[str, str]]:
    return {
        (str(row["chain_id"]), str(row["stage"]))
        for row in read_jsonl(CASE_FILE)
    }


def normalize_component_row(row: dict[str, Any], source_set: str) -> dict[str, Any]:
    model = str(row.get("model") or "")
    chain_type = str(row.get("chain_type") or "")
    out = dict(row)
    out["model"] = model
    out["dataset_label"] = f"{model}_3run_filtered23_component"
    out["source_set"] = source_set
    out["framework_group"] = FRAMEWORK_LABELS.get(chain_type, chain_type or "unknown")
    out["evaluation_unit"] = "component_rubric_subject_action_object_evidence"
    return out


def load_current_two_reps(case_keys: set[tuple[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in read_jsonl(COMPONENT_LEDGER):
        model = str(row.get("model") or "")
        replicate = str(row.get("replicate") or "")
        key = (str(row.get("chain_id") or ""), str(row.get("stage") or ""))
        if model not in MODELS or replicate not in CURRENT_REPLICATES or key not in case_keys:
            continue
        out = normalize_component_row(row, "formal_23_chain_2rep_20260612")
        out["contract"] = "formal_json_code_steps"
        rows.append(out)
    return rows


def load_legacy_filtered(case_keys: set[tuple[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in read_csv(LEGACY_27_FILTERED):
        model = str(row.get("model") or "")
        key = (str(row.get("chain_id") or ""), str(row.get("stage") or ""))
        if model not in MODELS or key not in case_keys:
            continue
        out = normalize_component_row(row, "formal_27_chain_20260609_filtered_to_current_23")
        out["replicate"] = LEGACY_REPLICATE
        out["contract"] = "legacy_formal27_component_review_filtered_to_23"
        out["run_json"] = ""
        out["source_score_path"] = row.get("source_path", "")
        rows.append(out)
    return rows


def summarize(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[tuple(row.get(field) for field in fields)].append(row)

    out: list[dict[str, Any]] = []
    for key, bucket in sorted(buckets.items(), key=lambda item: tuple("" if v is None else str(v) for v in item[0])):
        ah = sum(as_int(row, "action_step_recall_hits") for row in bucket)
        at = sum(as_int(row, "action_step_recall_total") for row in bucket)
        eh = sum(as_int(row, "critical_evidence_recall_hits") for row in bucket)
        et = sum(as_int(row, "critical_evidence_recall_total") for row in bucket)
        oh = sum(as_int(row, "behavior_sequence_order_hits") for row in bucket)
        ot = sum(as_int(row, "behavior_sequence_order_total") for row in bucket)
        ph = sum(as_int(row, "candidate_claim_precision_hits") for row in bucket)
        pt = sum(as_int(row, "candidate_claim_precision_total") for row in bucket)
        summary = {field: key[i] for i, field in enumerate(fields)}
        summary.update(
            {
                "run_count": len(bucket),
                "chain_count": len({str(row.get("chain_id") or "") for row in bucket}),
                "replicate_count": len({str(row.get("replicate") or "") for row in bucket}),
                "action_step_recall_hits": ah,
                "action_step_recall_total": at,
                "action_step_recall": ratio(ah, at),
                "critical_evidence_recall_hits": eh,
                "critical_evidence_recall_total": et,
                "critical_evidence_recall": ratio(eh, et),
                "behavior_sequence_order_hits": oh,
                "behavior_sequence_order_total": ot,
                "behavior_sequence_order": ratio(oh, ot),
                "candidate_claim_precision_hits": ph,
                "candidate_claim_precision_total": pt,
                "candidate_claim_precision": ratio(ph, pt),
                "overclaim_slot_count": sum(as_int(row, "overclaim_slot_count") for row in bucket),
            }
        )
        out.append(summary)
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def md_table(rows: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


def write_manifest(rows: list[dict[str, Any]]) -> None:
    manifest = {
        "purpose": "Component-rubric 3-run aggregation for the current 23-chain scope.",
        "important_note": "The third set is not formal_23_chain replicate_03. It is the legacy formal_27_chain_20260609 run filtered to the current 23 chains.",
        "scoring_policy": "Content inclusion: count a hit when the substantive gold subject/action/object/evidence content appears in the candidate, even if wording or output structure differs. Alert-only evidence is not counted as non-alert evidence.",
        "inputs": {
            "current_2rep_component_ledger": COMPONENT_LEDGER.relative_to(ROOT).as_posix(),
            "legacy_27_filtered_component_scores": LEGACY_27_FILTERED.relative_to(ROOT).as_posix(),
            "current_case_scope": CASE_FILE.relative_to(ROOT).as_posix(),
            "legacy_raw_runs_source": "public_research/clouseau_atlasv2_27chain_2026_06/raw_runs and docs/current_experiment/results_2026-06-09/formal_27_chain_experiment_20260609/runs",
        },
        "row_counts": {
            "total_per_run_rows": len(rows),
            "by_model": {
                model: len([row for row in rows if row.get("model") == model])
                for model in sorted(MODELS)
            },
            "by_source_set": {
                source: len([row for row in rows if row.get("source_set") == source])
                for source in sorted({str(row.get("source_set") or "") for row in rows})
            },
        },
    }
    manifest_dir = OUT_DIR / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "input_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_summary(tables: dict[str, list[dict[str, Any]]]) -> None:
    overall_fields = ["dataset_label", "run_count", "chain_count", "replicate_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    stage_fields = ["dataset_label", "stage", "run_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    replicate_fields = ["model", "replicate", "source_set", "run_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    md = [
        "# Formal 23-Chain Component Rubric 3-Run Filtered Results",
        "",
        "This folder treats the legacy 27-chain run as the third set only after filtering it to the current 23-chain scope.",
        "",
        "Important: this is not a generated `formal_23_chain` `replicate_03`. The third set is `legacy_27_filtered_20260609`.",
        "",
        "Scoring policy: content inclusion. If the candidate contains the substantive gold subject/action/object/evidence content, it is counted as a hit even if wording or output structure differs. Alert-only evidence is not counted as non-alert evidence.",
        "",
        "## Overall 3-Run",
        "",
        md_table(tables["overall"], overall_fields),
        "",
        "## By Stage",
        "",
        md_table(tables["by_stage"], stage_fields),
        "",
        "## By Replicate Source",
        "",
        md_table(tables["by_replicate"], replicate_fields),
        "",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> None:
    case_keys = current_case_keys()
    current_rows = load_current_two_reps(case_keys)
    legacy_rows = load_legacy_filtered(case_keys)
    rows = sorted(
        current_rows + legacy_rows,
        key=lambda row: (
            str(row.get("model") or ""),
            str(row.get("replicate") or ""),
            str(row.get("stage") or ""),
            str(row.get("instance_id") or ""),
        ),
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(OUT_DIR / "ledgers" / "per_run_component_scores.csv", rows)
    tables = {
        "overall": summarize(rows, ("dataset_label",)),
        "by_stage": summarize(rows, ("dataset_label", "stage")),
        "by_replicate": summarize(rows, ("model", "replicate", "source_set")),
        "by_framework": summarize(rows, ("dataset_label", "framework_group")),
        "by_stage_framework": summarize(rows, ("dataset_label", "stage", "framework_group")),
    }
    for name, table in tables.items():
        write_csv(OUT_DIR / "tables" / f"{name}.csv", table)
    write_manifest(rows)
    write_summary(tables)
    print(json.dumps({"out_dir": OUT_DIR.relative_to(ROOT).as_posix(), "row_count": len(rows), "current_2rep_rows": len(current_rows), "legacy_27_filtered_rows": len(legacy_rows)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
