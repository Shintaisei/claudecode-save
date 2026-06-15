from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs/current_experiment/results_2026-06-09/component_rubric_final_comparison_20260614"
FILTERED_3RUN_DIR = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_component_3run_filtered_20260614"
COMPONENT_DIR = ROOT / "docs/current_experiment/results_2026-06-09/component_rubric_model_comparison_20260614"
COMPONENT_LEDGER = ROOT / "data/current_experiment/scores/component_rubric_20260614/codex_component_double_reviews.jsonl"


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


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


def display_label(dataset_label: str) -> str:
    labels = {
        "gpt-4.1-mini_3run_filtered23_component": "gpt-4.1-mini",
        "gpt-5.4-mini_3run_filtered23_component": "gpt-5.4-mini",
        "gpt-5.5_low_raw_component": "gpt-5.5 low raw",
    }
    return labels.get(dataset_label, dataset_label)


def as_int(row: dict[str, Any], field: str) -> int:
    return int(float(row.get(field) or 0))


def ratio(hit: int, total: int) -> str:
    if total == 0:
        return "NA"
    return f"{hit / total:.3f}"


def summarize_component_rows(rows: list[dict[str, Any]], group_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        buckets.setdefault(tuple(row.get(field) for field in group_fields), []).append(row)

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
        summary = {field: key[i] for i, field in enumerate(group_fields)}
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


def gpt55_rep1_rows() -> list[dict[str, Any]]:
    return [
        row
        for row in read_jsonl(COMPONENT_LEDGER)
        if row.get("dataset_label") == "gpt-5.5_low_raw_component"
        and row.get("two_review_adoptable") is True
    ]


def final_per_run_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in read_csv(FILTERED_3RUN_DIR / "ledgers" / "per_run_component_scores.csv"):
        out = dict(row)
        out["model_display"] = display_label(str(row.get("dataset_label") or ""))
        out["scope_note"] = "3run: formal23 rep1+rep2 + legacy27 filtered to current 23"
        rows.append(out)
    for row in gpt55_rep1_rows():
        out = dict(row)
        out["model_display"] = display_label(str(row.get("dataset_label") or ""))
        out["scope_note"] = "raw-text salvage; output contract failed; 3 complete runs"
        rows.append(out)
    return rows


def build_overall() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in read_csv(FILTERED_3RUN_DIR / "tables" / "overall.csv"):
        out = dict(row)
        out["model"] = display_label(str(row.get("dataset_label") or ""))
        out["scope_note"] = "3run: formal23 rep1+rep2 + legacy27 filtered to current 23"
        rows.append(out)
    for row in summarize_component_rows(gpt55_rep1_rows(), ("dataset_label",)):
        out = dict(row)
        out["model"] = display_label(str(row.get("dataset_label") or ""))
        out["scope_note"] = "raw-text salvage; output contract failed; 3 complete runs"
        rows.append(out)
    return rows


def build_by_stage() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in read_csv(FILTERED_3RUN_DIR / "tables" / "by_stage.csv"):
        out = dict(row)
        out["model"] = display_label(str(row.get("dataset_label") or ""))
        out["scope_note"] = "3run filtered23"
        rows.append(out)
    for row in summarize_component_rows(gpt55_rep1_rows(), ("dataset_label", "stage")):
        out = dict(row)
        out["model"] = display_label(str(row.get("dataset_label") or ""))
        out["scope_note"] = "raw-text salvage; 3 complete runs"
        rows.append(out)
    return rows


def build_by_replicate() -> list[dict[str, Any]]:
    return read_csv(FILTERED_3RUN_DIR / "tables" / "by_replicate.csv")


def write_summary(overall: list[dict[str, Any]], by_stage: list[dict[str, Any]], by_replicate: list[dict[str, Any]]) -> None:
    overall_fields = ["model", "run_count", "chain_count", "replicate_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count", "scope_note"]
    stage_fields = ["model", "stage", "run_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count", "scope_note"]
    replicate_fields = ["model", "replicate", "source_set", "run_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    md = [
        "# Component Rubric Final Comparison 2026-06-14",
        "",
        "Scoring policy: content inclusion. If the substantive gold subject/action/object/evidence appears in the candidate output, count it as a hit. Alert-only evidence is not counted as non-alert evidence.",
        "",
        "For gpt-4.1-mini and gpt-5.4-mini, the third set is the legacy 27-chain run filtered to the current 23-chain scope, not a generated formal23 `replicate_03`.",
        "",
        "For gpt-5.5, rows are raw-text salvage because the output contract failed; report separately from formal JSON compliance. The 3-run GPT-5.5 low set is now complete and double-reviewed.",
        "",
        "## Overall",
        "",
        md_table(overall, overall_fields),
        "",
        "## By Stage",
        "",
        md_table(by_stage, stage_fields),
        "",
        "## 4.1/5.4 By Source Set",
        "",
        md_table(by_replicate, replicate_fields),
        "",
    ]
    (OUT_DIR / "summary.md").write_text("\n".join(md).rstrip() + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(OUT_DIR / "final_comparison_per_run_component_scores.csv", final_per_run_rows())
    overall = build_overall()
    by_stage = build_by_stage()
    by_replicate = build_by_replicate()
    write_csv(OUT_DIR / "overall.csv", overall)
    write_csv(OUT_DIR / "by_stage.csv", by_stage)
    write_csv(OUT_DIR / "by_replicate_4_1_5_4.csv", by_replicate)
    write_summary(overall, by_stage, by_replicate)
    manifest = {
        "inputs": {
            "filtered_3run": (FILTERED_3RUN_DIR / "summary.md").relative_to(ROOT).as_posix(),
            "component_model_comparison": (COMPONENT_DIR / "summary.md").relative_to(ROOT).as_posix(),
        },
        "notes": [
            "gpt-4.1-mini and gpt-5.4-mini use 207 runs each: 138 formal23 2rep + 69 legacy27 filtered to current 23.",
        "gpt-5.5 low raw uses 207 runs: 23 chains x 3 stages x 3 complete replicates, all Codex double-reviewed with conservative conflict handling.",
        ],
    }
    (OUT_DIR / "input_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out_dir": OUT_DIR.relative_to(ROOT).as_posix(), "overall_rows": len(overall), "by_stage_rows": len(by_stage)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
