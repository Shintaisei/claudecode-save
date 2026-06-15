from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FINAL_DIR = ROOT / "docs/current_experiment/results_2026-06-09/component_rubric_final_comparison_20260614"
FILTERED_DIR = ROOT / "docs/current_experiment/results_2026-06-09/formal_23_chain_component_3run_filtered_20260614"
PUBLIC_DIR = ROOT / "public_research/clouseau_atlasv2_27chain_2026_06/results_23chain_20260614"

FINAL_LEDGER = FINAL_DIR / "final_comparison_per_run_component_scores.csv"
FILTERED_LEDGER = FILTERED_DIR / "ledgers/per_run_component_scores.csv"

FRAMEWORK_LABELS = {
    "dns_packet_capture_batch_chain": "collection_or_tool_invocation",
    "python_simplehttpserver_network_chain": "network_service_behavior",
    "sublime_python_script_execution_chain": "script_execution_chain",
    "cmdexe_other_chain": "command_shell_execution",
    "discord_run_key_registry_chain": "persistence_registry_run_key",
}


def read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


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
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def as_int(row: dict[str, Any], field: str) -> int:
    return int(float(row.get(field) or 0))


def ratio(hit: int, total: int) -> str:
    if total == 0:
        return "NA"
    return f"{hit / total:.3f}"


def model_name(row: dict[str, Any]) -> str:
    return str(row.get("model_display") or row.get("model") or "")


def summarize(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = tuple(model_name(row) if field == "model" else row.get(field) for field in fields)
        buckets[key].append(row)

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
                "action_step_recall": ratio(ah, at),
                "action_step_recall_hits": ah,
                "action_step_recall_total": at,
                "critical_evidence_recall": ratio(eh, et),
                "critical_evidence_recall_hits": eh,
                "critical_evidence_recall_total": et,
                "behavior_sequence_order": ratio(oh, ot),
                "behavior_sequence_order_hits": oh,
                "behavior_sequence_order_total": ot,
                "candidate_claim_precision": ratio(ph, pt),
                "candidate_claim_precision_hits": ph,
                "candidate_claim_precision_total": pt,
                "overclaim_slot_count": sum(as_int(row, "overclaim_slot_count") for row in bucket),
            }
        )
        out.append(summary)
    return out


def enrich_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scenario_by_chain: dict[str, tuple[str, str]] = {}
    framework_by_chain: dict[str, str] = {}
    for row in read_csv(FILTERED_LEDGER):
        chain_id = str(row.get("chain_id") or "")
        scenario_by_chain.setdefault(chain_id, (str(row.get("scenario_group") or ""), str(row.get("scenario_group_ja") or "")))
        framework_by_chain.setdefault(chain_id, str(row.get("framework_group") or ""))

    enriched: list[dict[str, Any]] = []
    for row in rows:
        out = dict(row)
        chain_id = str(out.get("chain_id") or "")
        chain_type = str(out.get("chain_type") or "")
        if not out.get("scenario_group"):
            scenario, scenario_ja = scenario_by_chain.get(chain_id, ("", ""))
            out["scenario_group"] = scenario
            out["scenario_group_ja"] = scenario_ja
        if not out.get("framework_group"):
            out["framework_group"] = framework_by_chain.get(chain_id) or FRAMEWORK_LABELS.get(chain_type, chain_type or "unknown")
        enriched.append(out)
    return enriched


def md_table(rows: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


def write_summary(overall: list[dict[str, Any]], by_stage: list[dict[str, Any]]) -> None:
    overall_fields = ["model", "run_count", "chain_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    stage_fields = ["model", "stage", "run_count", "action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_slot_count"]
    md = [
        "# Current Experiment Results: 23-Chain Component-Rubric Results",
        "",
        "This folder is the primary result folder for the current 23-chain experiment.",
        "",
        "Use this folder when writing the FIT2026 paper or slides. The older top-level `results/` folder is the earlier 27-chain public package result set and is kept for traceability.",
        "",
        "## What This Result Set Means",
        "",
        "| item | definition |",
        "| --- | --- |",
        "| Experiment unit | One behavior chain under one stage condition |",
        "| Final chain scope | 23 behavior chains |",
        "| Stages | `stage1`, `stage2`, `stage3` |",
        "| Main structured models | `gpt-4.1-mini`, `gpt-5.4-mini` |",
        "| Structured comparison scope | 23 chains x 3 stages x 3 sets = 207 rows per model |",
        "| GPT-5.5 scope | 23 chains x 3 stages x 3 sets = 207 raw-output salvage rows |",
        "| Scoring rubric | Component rubric with content-inclusion matching |",
        "| Current final ledger | `ledgers/final_comparison_per_run_component_scores.csv` |",
        "",
        "## Final Comparison Scope",
        "",
        "| model | rows | chain count | stage count | set count | treatment |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
        "| `gpt-4.1-mini` | 207 | 23 | 3 | 3 | formal23 rep1 + formal23 rep2 + legacy27 filtered to current 23 |",
        "| `gpt-5.4-mini` | 207 | 23 | 3 | 3 | formal23 rep1 + formal23 rep2 + legacy27 filtered to current 23 |",
        "| `gpt-5.5 low raw` | 207 | 23 | 3 | 3 | raw-output salvage; output contract failed |",
        "",
        "The third set for `gpt-4.1-mini` and `gpt-5.4-mini` is not a newly executed formal23 `replicate_03`. It is the current 23-chain subset extracted from the earlier 27-chain run and used as the practical third set.",
        "",
        "## Stage Definitions",
        "",
        "| stage | input clue | database visibility | interpretation |",
        "| --- | --- | --- | --- |",
        "| `stage1` | Process-time fields plus CBC alert summary fields | CBC alert summary, CBC EDR/NGAV telemetry, OS/browser logs | Alert-assisted reconstruction |",
        "| `stage2` | Process-time fields only | CBC alert summary still retrievable in DB | Model must discover alert context from the process/time starting point |",
        "| `stage3` | Process-time fields only | CBC alert summary hidden from SQL retrieval; CBC EDR/NGAV telemetry remains available | Tests reconstruction without the alert-summary shortcut |",
        "",
        "Stage3 does not remove all CBC data. It removes CBC alert summary rows from retrieval, while retaining CBC EDR/NGAV telemetry.",
        "",
        "## Metric Definitions",
        "",
        "| metric | denominator | meaning |",
        "| --- | --- | --- |",
        "| `action_step_recall` | `gold_step_count * 3` | Recovery of subject/action/object components |",
        "| `critical_evidence_recall` | `gold_step_count` | Recovery of critical non-alert evidence for each gold step |",
        "| `behavior_sequence_order` | `max(gold_step_count - 1, 0)` | Recovery of adjacent gold-step order |",
        "| `candidate_claim_precision` | candidate claim slots | Fraction of candidate claim slots that are correct/supported |",
        "| `overclaim_slot_count` | count only | Unsupported, wrong, or outside-gold claim slots |",
        "",
        "Matching uses content inclusion. If the candidate output contains the substantive gold content, it is counted as a hit even when wording or output structure differs. CBC alert-summary-only evidence is not counted as non-alert evidence.",
        "",
        "## Main Files",
        "",
        "| file | purpose |",
        "| --- | --- |",
        "| `summary.md` | Human-readable final result summary |",
        "| `overall.csv` | Overall model-level scores |",
        "| `by_stage.csv` | Stage-level scores |",
        "| `by_replicate_4_1_5_4.csv` | Source-set breakdown for 4.1/5.4 |",
        "| `by_scenario_group.csv` | Three-scenario-group results |",
        "| `by_stage_scenario_group.csv` | Stage x scenario-group results |",
        "| `by_framework_group.csv` | Detailed behavior-framework results |",
        "| `by_stage_framework_group.csv` | Stage x behavior-framework results |",
        "| `ledgers/final_comparison_per_run_component_scores.csv` | Per-run component-score ledger for all 621 rows |",
        "| `ledgers/4_1_5_4_3run_filtered23_per_run_component_scores.csv` | Per-run ledger for the 4.1/5.4 3-set comparison only |",
        "| `openai_cost_audit_note_20260614.md` | Cost and token audit note |",
        "| `openai_usage_audit_20260614.csv` | Cost/token detail |",
        "",
        "## Overall Result",
        "",
        md_table(overall, overall_fields),
        "",
        "## By Stage",
        "",
        md_table(by_stage, stage_fields),
        "",
        "## Reporting Caveat",
        "",
        "Use `gpt-5.5 low raw` as a raw-output salvage result. It is useful for discussing substantive reconstruction ability, but it is not directly contract-equivalent to the structured `gpt-4.1-mini` and `gpt-5.4-mini` results.",
        "",
    ]
    (PUBLIC_DIR / "summary.md").write_text("\n".join(md), encoding="utf-8")
    (PUBLIC_DIR / "README.md").write_text("\n".join(md), encoding="utf-8")


def write_definitions() -> None:
    md = [
        "# 23-Chain Experiment Result Definitions",
        "",
        "This file defines the terms used in the 23-chain result tables.",
        "",
        "## Current Final Result",
        "",
        "The current final experiment result is:",
        "",
        "- `gpt-4.1-mini`: 207 scored rows",
        "- `gpt-5.4-mini`: 207 scored rows",
        "- `gpt-5.5 low raw`: 207 scored/salvaged rows",
        "",
        "The main table is `overall.csv`.",
        "The main per-run evidence table is `ledgers/final_comparison_per_run_component_scores.csv`.",
        "",
        "## Why This Folder Exists",
        "",
        "The repository also contains older 27-chain results under `results/`. Those files are retained for history, but they are not the current final result set used for the 23-chain component-rubric analysis.",
        "",
        "For paper writing, use this folder first.",
        "",
        "## Dataset Labels",
        "",
        "| dataset label | meaning |",
        "| --- | --- |",
        "| `gpt-4.1-mini_3run_filtered23_component` | 23-chain component-rubric result for gpt-4.1-mini, 3 sets |",
        "| `gpt-5.4-mini_3run_filtered23_component` | 23-chain component-rubric result for gpt-5.4-mini, 3 sets |",
        "| `gpt-5.5_low_raw_component` | 23-chain component-rubric salvage result for gpt-5.5 low raw, 3 sets |",
        "",
        "## Set Definitions",
        "",
        "| set | models | source |",
        "| --- | --- | --- |",
        "| `replicate_01` | 4.1-mini / 5.4-mini / GPT-5.5 | formal 23-chain run |",
        "| `replicate_02` | 4.1-mini / 5.4-mini / GPT-5.5 | formal 23-chain run |",
        "| `replicate_03` | GPT-5.5 | formal 23-chain run |",
        "| `legacy_27_filtered_20260609` | 4.1-mini / 5.4-mini | earlier 27-chain run filtered to the current 23 chain IDs |",
        "",
        "## Gold And Evidence Rule",
        "",
        "The gold target is non-alert behavior reconstruction.",
        "",
        "- Alert summary can be the starting clue.",
        "- Alert summary alone is not counted as non-alert evidence.",
        "- Critical evidence credit requires substantive non-alert evidence content.",
        "- For Stage3, alert summary is hidden from SQL retrieval; CBC EDR/NGAV telemetry remains visible.",
        "",
        "## Scoring Rule",
        "",
        "The scoring rule is content inclusion, not exact JSON shape.",
        "",
        "A candidate receives credit when the substantive gold content appears in the output, even if:",
        "",
        "- wording differs,",
        "- Japanese/English phrasing differs,",
        "- output structure differs,",
        "- field names differ.",
        "",
        "This is why the GPT-5.5 raw-output salvage can be scored at component level, while still being marked as a contract-failed result.",
        "",
    ]
    (PUBLIC_DIR / "RESULT_DEFINITIONS_23CHAIN.md").write_text("\n".join(md), encoding="utf-8")


def main() -> None:
    rows = enrich_rows(read_csv(FINAL_LEDGER))
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    (PUBLIC_DIR / "ledgers").mkdir(parents=True, exist_ok=True)

    write_csv(PUBLIC_DIR / "ledgers/final_comparison_per_run_component_scores.csv", rows)
    write_csv(PUBLIC_DIR / "ledgers/4_1_5_4_3run_filtered23_per_run_component_scores.csv", read_csv(FILTERED_LEDGER))

    overall = summarize(rows, ("model",))
    by_stage = summarize(rows, ("model", "stage"))
    by_replicate = read_csv(FINAL_DIR / "by_replicate_4_1_5_4.csv")
    by_scenario = summarize(rows, ("model", "scenario_group"))
    by_stage_scenario = summarize(rows, ("model", "stage", "scenario_group"))
    by_framework = summarize(rows, ("model", "framework_group"))
    by_stage_framework = summarize(rows, ("model", "stage", "framework_group"))

    write_csv(PUBLIC_DIR / "overall.csv", overall)
    write_csv(PUBLIC_DIR / "by_stage.csv", by_stage)
    write_csv(PUBLIC_DIR / "by_replicate_4_1_5_4.csv", by_replicate)
    write_csv(PUBLIC_DIR / "by_scenario_group.csv", by_scenario)
    write_csv(PUBLIC_DIR / "by_stage_scenario_group.csv", by_stage_scenario)
    write_csv(PUBLIC_DIR / "by_framework_group.csv", by_framework)
    write_csv(PUBLIC_DIR / "by_stage_framework_group.csv", by_stage_framework)

    manifest = {
        "updated_at": "2026-06-16",
        "source_final_comparison": FINAL_DIR.relative_to(ROOT).as_posix(),
        "source_4_1_5_4_filtered": FILTERED_DIR.relative_to(ROOT).as_posix(),
        "row_counts": {
            "final_per_run_rows": len(rows),
            "overall_rows": len(overall),
            "by_stage_rows": len(by_stage),
        },
        "notes": [
            "GPT-5.5 low raw is a raw-output salvage result because the formal JSON/code_steps contract failed.",
            "GPT-5.5 low raw now includes 207 rows: 23 chains x 3 stages x 3 complete replicates.",
            "gpt-4.1-mini and gpt-5.4-mini use formal23 replicate_01/02 plus legacy27 filtered to current 23 chains as the practical third set.",
        ],
    }
    (PUBLIC_DIR / "input_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_summary(overall, by_stage)
    write_definitions()
    print(json.dumps({"public_dir": PUBLIC_DIR.relative_to(ROOT).as_posix(), "final_per_run_rows": len(rows), "overall_rows": len(overall), "by_stage_rows": len(by_stage)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
