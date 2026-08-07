"""Materialize Stage 3-only S3 attack cases and a 23+6 comparison manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GOLD_ROOT = ROOT / "data/current_experiment/gold/atlasv2_s3_attack_behavior_chain_gold"
OUT_CASES = ROOT / "data/current_experiment/cases/atlasv2_s3_attack_6_stage3_cases_20260719.jsonl"
EXISTING_23 = ROOT / "data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl"
COMBINED = ROOT / "data/current_experiment/cases/cbc_23_plus_atlasv2_s3_6_stage3_cases_20260719.jsonl"
MANIFEST = ROOT / "data/current_experiment/cases/atlasv2_s3_attack_6_stage3_cases_20260719_manifest.json"


def audit_stage3_input(model_ready_input: dict) -> list[str]:
    """Return prohibited terms if they occur in model-visible input only."""
    visible = json.dumps(model_ready_input, ensure_ascii=False).lower()
    prohibited = ("alert_id", "alert_name", "s-3.txt", "ground_truth", "atlasv2_labels", "attack technique")
    return [token for token in prohibited if token in visible]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gold-root", type=Path, default=GOLD_ROOT)
    parser.add_argument("--out", type=Path, default=OUT_CASES)
    parser.add_argument("--combined-out", type=Path, default=COMBINED)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()
    args.gold_root = args.gold_root.resolve()
    args.out = args.out.resolve()
    args.combined_out = args.combined_out.resolve()
    args.manifest = args.manifest.resolve()

    cases = []
    audits = []
    for index, gold_path in enumerate(sorted(args.gold_root.glob("by_chain/*/chain_gold.json")), start=1):
        gold = json.loads(gold_path.read_text(encoding="utf-8"))
        scope = gold["input_scope"]
        model_ready_input = {
            "input_id": f"s3_attack_input_{index:03d}",
            "stage": "stage3",
            "input": {
                "host": scope["host"],
                "focus_processes": scope["focus_processes"],
                "chain_window_start_utc": scope["chain_window_start_utc"],
                "chain_window_end_utc": scope["chain_window_end_utc"],
            },
            "db_filter": "remove cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; retain cbc_events telemetry",
        }
        violations = audit_stage3_input(model_ready_input)
        if violations:
            raise ValueError(f"model-visible input leaked prohibited terms: {violations}")
        anchor = gold["gold_steps"][0]["canonical_evidence"][0]
        case = {
            "instance_id": f"{gold['chain_id']}_stage3",
            "case_id": f"{gold['chain_id']}_stage3",
            "input_id": model_ready_input["input_id"],
            "stage": "stage3",
            "scenario": "atlasv2-attack-h1-s3",
            "database": "Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db",
            "host": scope["host"],
            "process_name": "; ".join(scope["focus_processes"]),
            "actor": "; ".join(scope["focus_processes"]),
            "expected_behavior": gold["observed_behavior"],
            "expected_behavior_category": gold["chain_type"],
            "context_label": gold["case_group"],
            "quality": "canonical_evidence_finalized_20260719",
            "difficulty": "process_time",
            "time_window_utc": {
                "episode_start": scope["chain_window_start_utc"],
                "episode_end": scope["chain_window_end_utc"],
                "analysis_scope": "S3 local investigation window; primary chain must stay in scope",
            },
            "anchor_event": {
                "source_stream": anchor["source_stream"],
                "source_table": anchor["source_table"],
                "source_row_id": anchor["source_row_id"],
                "timestamp_utc": anchor["timestamp_utc"],
                "process_name": anchor["process_path"],
                "process_path": anchor["process_path"],
                "process_cmdline": anchor["process_cmdline"],
                "parent_path": anchor["parent_path"],
                "action": anchor["action"],
            },
            "input_alert_rows": [],
            "model_ready_input": model_ready_input,
            "gold_chain_file": str(gold_path.relative_to(args.gold_root)),
            "chain_id": gold["chain_id"],
            "chain_type": gold["chain_type"],
            "formal_gold_root": str(args.gold_root.relative_to(ROOT)),
            "stage3_answerable_policy": "All gold steps have canonical cbc_events evidence and are Stage 3-visible; scenario narrative, labels, and alert summaries are excluded from model input.",
            "independence_note": gold["independence_note"],
        }
        if "alert_origin_provenance" in gold:
            case["input_provenance"] = gold["alert_origin_provenance"]
        cases.append(case)
        audits.append({"chain_id": gold["chain_id"], "stage": "stage3", "allowed_input_keys": list(model_ready_input["input"]), "prohibited_terms_found": violations, "status": "pass"})

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases), encoding="utf-8")
    existing_stage3 = [json.loads(line) for line in EXISTING_23.read_text(encoding="utf-8").splitlines() if json.loads(line)["stage"] == "stage3"]
    args.combined_out.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in [*existing_stage3, *cases]), encoding="utf-8")
    args.manifest.write_text(json.dumps({
        "stage": "stage3",
        "s3_case_count": len(cases),
        "existing_benign_case_count": len(existing_stage3),
        "combined_case_count": len(existing_stage3) + len(cases),
        "intentional_stage_omissions": {"stage1": "No attack alert summaries are provided.", "stage2": "Stage 3 is the primary study condition; create a separate condition only if needed."},
        "independence_note": [case["independence_note"] for case in cases],
        "input_provenance_conditions": sorted({case.get("input_provenance", {}).get("condition", "process_time_seeded") for case in cases}),
        "stage3_input_audit": audits,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(cases)} S3 Stage 3 cases and {len(existing_stage3) + len(cases)} combined Stage 3 cases")


if __name__ == "__main__":
    main()
