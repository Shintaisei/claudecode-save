#!/usr/bin/env python3
"""Build a paired ATLASv2 attack-reconstruction suite matching the normal suite.

The legacy attack24 suite changes its evaluation unit between stages:
Stage 1 scores 24 individual alert targets, while Stages 2/3 score eight
deduplicated process/time chains.  This builder instead keeps the same eight
behavior chains, Gold files, focus processes, and time windows in all stages.
"""

from __future__ import annotations

import argparse
import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SOURCE_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack24_stage_cases_20260723.jsonl"
)
OUT_CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_paired_stage_cases_20260724.jsonl"
)
OUT_GOLD_ROOT = (
    ROOT
    / "data/current_experiment/gold"
    / "atlasv2_s3_s4_attack8_paired_gold_20260724"
)
OUT_MANIFEST = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_paired_manifest_20260724.json"
)
OUT_VALIDATION = (
    ROOT
    / "docs/current_experiment"
    / "atlasv2_s3_s4_attack8_paired_build_validation_20260724.json"
)
STAGES = ("stage1", "stage2", "stage3")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def resolve_path(root_text: str, file_text: str) -> Path:
    return ROOT / Path(root_text.replace("\\", "/")) / Path(file_text.replace("\\", "/"))


def compact_db_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def representative_alert_row(gold: dict[str, Any]) -> int:
    provenance = gold.get("process_time_provenance") or {}
    selection_anchor = gold.get("selection_anchor") or {}
    value = provenance.get("representative_alert_row_id")
    if value is None:
        value = selection_anchor.get("source_alert_row")
    if value is None:
        raise ValueError(f"{gold.get('chain_id')}: representative alert row is missing")
    return int(value)


def alert_anchor(alert: dict[str, Any]) -> dict[str, Any]:
    timestamp = str(alert.get("time") or "")
    return {
        "source_stream": alert.get("source_stream"),
        "source_table": "cbc_alerts",
        "source_row_id": alert.get("source_row_id"),
        "timestamp_utc": timestamp,
        "database_time": compact_db_time(timestamp),
        "alert_id": alert.get("alert_id"),
        "alert_name": alert.get("alert_name"),
        "process_name": alert.get("process"),
        "process_path": alert.get("process"),
        "process_cmdline": None,
        "parent_path": None,
        "parent_cmdline": None,
        "severity": alert.get("severity"),
        "reason": alert.get("alert_reason"),
        "event_record_id": alert.get("alert_id"),
        "action": "cbc_alert",
    }


def scope_anchor(base: dict[str, Any]) -> dict[str, Any]:
    start = str(base["time_window_utc"]["episode_start"])
    return {
        "source_stream": "scope",
        "timestamp_utc": start,
        "database_time": compact_db_time(start),
        "alert_id": None,
        "alert_name": None,
        "process_name": base.get("process_name"),
        "process_path": None,
        "process_cmdline": None,
        "parent_path": None,
        "parent_cmdline": None,
        "severity": None,
        "reason": None,
        "event_record_id": None,
        "action": "scope",
    }


def find_representative_alert(
    stage1_cases: list[dict[str, Any]],
    scenario: str,
    row_id: int,
) -> dict[str, Any]:
    matches = [
        case
        for case in stage1_cases
        if case.get("scenario") == scenario
        and case.get("input_alert_rows")
        and int(case["input_alert_rows"][0].get("source_row_id")) == row_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{scenario} cbc_alerts row {row_id}: expected one Stage-1 source, "
            f"found {len(matches)}"
        )
    return copy.deepcopy(matches[0]["input_alert_rows"][0])


def paired_gold(
    source_gold: dict[str, Any],
    representative_alert: dict[str, Any],
) -> dict[str, Any]:
    gold = copy.deepcopy(source_gold)
    gold["stages_present"] = list(STAGES)
    gold["case_group"] = "attack_behavior_chain_paired"
    gold["suite_group"] = "atlasv2_s3_s4_attack8_paired"
    scope = gold.setdefault("input_scope", {})
    scope["input_policy"] = (
        "The same behavior chain is evaluated in every stage. Stage 1 supplies "
        "one representative CBC alert; Stage 2 supplies host/process/time with "
        "database alert summaries discoverable; Stage 3 supplies the same "
        "host/process/time while CBC alert-summary rows are hidden."
    )
    gold["paired_stage_contract"] = {
        "evaluation_unit": "behavior_chain",
        "same_gold_all_stages": True,
        "representative_alert_row_id": representative_alert.get("source_row_id"),
        "representative_alert_id": representative_alert.get("alert_id"),
        "hard_time_scope": False,
        "normal_suite_parity": (
            "The declared chain window is a search hint and primary reporting "
            "scope; the adapter database is not physically truncated."
        ),
    }
    return gold


def build_case(
    base: dict[str, Any],
    gold: dict[str, Any],
    gold_file: str,
    gold_root: Path,
    representative_alert: dict[str, Any],
    stage: str,
    chain_index: int,
) -> dict[str, Any]:
    case = copy.deepcopy(base)
    chain_id = str(base["chain_id"])
    instance_id = f"{chain_id}_{stage}"
    focus_processes = list(
        (gold.get("input_scope") or {}).get("focus_processes")
        or (base.get("model_ready_input") or {}).get("input", {}).get("focus_processes")
        or [base.get("process_name")]
    )
    model_input = {
        "host": base.get("host"),
        "focus_processes": focus_processes,
        "chain_window_start_utc": base["time_window_utc"]["episode_start"],
        "chain_window_end_utc": base["time_window_utc"]["episode_end"],
    }
    if stage == "stage1":
        # This mirrors the normal 27-chain model-ready schema.  The active
        # runner exposes the first selected alert as the initial clue.
        model_input["alerts"] = [copy.deepcopy(representative_alert)]

    case.update(
        {
            "instance_id": instance_id,
            "case_id": instance_id,
            "input_id": f"atlasv2_attack8_paired_{chain_index:02d}_{stage}",
            "stage": stage,
            "expected_behavior": gold.get("chain_title") or chain_id,
            "expected_behavior_category": gold.get("chain_type")
            or base.get("expected_behavior_category"),
            "context_label": "attack_behavior_chain_paired",
            "suite_group": "atlasv2_s3_s4_attack8_paired",
            "quality": "paired_normal_method_20260724",
            "difficulty": "alert_input" if stage == "stage1" else "process_time",
            "anchor_event": (
                alert_anchor(representative_alert)
                if stage == "stage1"
                else scope_anchor(base)
            ),
            "input_alert_rows": (
                [copy.deepcopy(representative_alert)] if stage == "stage1" else []
            ),
            "model_ready_input": {
                "input_id": f"atlasv2_attack8_paired_{chain_index:02d}",
                "stage": stage,
                "input": model_input,
            },
            "gold_chain_file": gold_file,
            "formal_gold_root": str(gold_root.relative_to(ROOT)),
            "stage_input_policy": (
                "Stage 1: representative CBC alert clue."
                if stage == "stage1"
                else (
                    "Stage 2: host/process/time only; CBC alert summaries remain "
                    "discoverable in the database."
                    if stage == "stage2"
                    else (
                        "Stage 3: same host/process/time; CBC alert summaries are "
                        "hidden while CBC event telemetry remains available."
                    )
                )
            ),
            "stage3_answerable_policy": (
                "Stage 3 uses the same Gold, filtered to validated canonical "
                "cbc_events evidence."
            ),
            "paired_stage_contract": {
                "evaluation_unit": "behavior_chain",
                "chain_index": chain_index,
                "same_gold_all_stages": True,
                "hard_time_scope": False,
                "representative_alert_row_id": representative_alert.get(
                    "source_row_id"
                ),
            },
        }
    )
    case["time_window_utc"]["analysis_scope"] = (
        "Finalized behavior-chain window; as in the normal reconstruction "
        "experiment, the runner may inspect surrounding database evidence but "
        "the primary chain must stay in the declared scope."
    )
    case.pop("enforce_time_scope", None)
    case.pop("investigation_time_anchor_utc", None)
    case.pop("investigation_time_anchor_policy", None)
    case.pop("input_provenance", None)
    if stage == "stage3":
        case["model_ready_input"]["db_filter"] = (
            "hide cbc_alerts / cbc-edr-alerts / cbc-ngav-alerts summary rows; "
            "retain cbc_events telemetry"
        )
    return case


def validate(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    stage_counts = Counter(case["stage"] for case in cases)
    checks.append(
        {
            "check": "stage_counts",
            "expected": {stage: 8 for stage in STAGES},
            "actual": dict(stage_counts),
            "status": "pass"
            if dict(stage_counts) == {stage: 8 for stage in STAGES}
            else "fail",
        }
    )
    ids = [case["instance_id"] for case in cases]
    checks.append(
        {
            "check": "instance_ids_unique",
            "actual": len(ids),
            "unique": len(set(ids)),
            "status": "pass" if len(ids) == len(set(ids)) else "fail",
        }
    )
    chain_sets = {
        stage: {case["chain_id"] for case in cases if case["stage"] == stage}
        for stage in STAGES
    }
    checks.append(
        {
            "check": "same_chain_set_all_stages",
            "counts": {stage: len(values) for stage, values in chain_sets.items()},
            "status": "pass"
            if chain_sets["stage1"] == chain_sets["stage2"] == chain_sets["stage3"]
            else "fail",
        }
    )
    for chain_id in sorted(chain_sets["stage1"]):
        rows = [case for case in cases if case["chain_id"] == chain_id]
        gold_paths = {
            (case["formal_gold_root"], case["gold_chain_file"]) for case in rows
        }
        signatures = {
            (
                case["host"],
                case["process_name"],
                case["time_window_utc"]["episode_start"],
                case["time_window_utc"]["episode_end"],
            )
            for case in rows
        }
        checks.append(
            {
                "check": "paired_chain_contract",
                "chain_id": chain_id,
                "stage_count": len(rows),
                "gold_path_count": len(gold_paths),
                "scope_signature_count": len(signatures),
                "status": "pass"
                if len(rows) == 3
                and len(gold_paths) == 1
                and len(signatures) == 1
                else "fail",
            }
        )
        for case in rows:
            stage = case["stage"]
            alerts = case.get("input_alert_rows") or []
            model_input = case["model_ready_input"]["input"]
            visibility_ok = (
                len(alerts) == 1 and len(model_input.get("alerts") or []) == 1
                if stage == "stage1"
                else not alerts
                and "alerts" not in model_input
                and "cbc_alert" not in model_input
            )
            checks.append(
                {
                    "check": "stage_visibility",
                    "instance_id": case["instance_id"],
                    "status": "pass" if visibility_ok else "fail",
                }
            )
            checks.append(
                {
                    "check": "normal_time_scope_parity",
                    "instance_id": case["instance_id"],
                    "status": "pass"
                    if not case.get("enforce_time_scope")
                    and not case.get("investigation_time_anchor_utc")
                    else "fail",
                }
            )
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cases", type=Path, default=SOURCE_CASES)
    parser.add_argument("--out-cases", type=Path, default=OUT_CASES)
    parser.add_argument("--out-gold-root", type=Path, default=OUT_GOLD_ROOT)
    parser.add_argument("--manifest", type=Path, default=OUT_MANIFEST)
    parser.add_argument("--validation", type=Path, default=OUT_VALIDATION)
    args = parser.parse_args()

    source_cases = read_jsonl(args.source_cases)
    stage1_sources = [case for case in source_cases if case.get("stage") == "stage1"]
    chain_bases = [case for case in source_cases if case.get("stage") == "stage2"]
    if len(chain_bases) != 8:
        raise ValueError(f"expected eight Stage-2 behavior chains, found {len(chain_bases)}")

    cases: list[dict[str, Any]] = []
    gold_index: list[dict[str, Any]] = []
    for index, base in enumerate(chain_bases, 1):
        source_gold_path = resolve_path(
            str(base["formal_gold_root"]), str(base["gold_chain_file"])
        )
        source_gold = json.loads(source_gold_path.read_text(encoding="utf-8"))
        alert_row_id = representative_alert_row(source_gold)
        alert = find_representative_alert(
            stage1_sources, str(base["scenario"]), alert_row_id
        )
        gold = paired_gold(source_gold, alert)
        gold_file = f"by_chain/{base['chain_id']}/chain_gold.json"
        target_gold_path = args.out_gold_root / gold_file
        write_json(target_gold_path, gold)
        gold_index.append(
            {
                "chain_id": base["chain_id"],
                "gold_chain_file": gold_file,
                "source_gold": str(source_gold_path.relative_to(ROOT)),
                "representative_alert_row_id": alert_row_id,
                "representative_alert_id": alert.get("alert_id"),
            }
        )
        for stage in STAGES:
            cases.append(
                build_case(
                    base,
                    gold,
                    gold_file,
                    args.out_gold_root,
                    alert,
                    stage,
                    index,
                )
            )

    checks = validate(cases)
    failures = [check for check in checks if check["status"] != "pass"]
    if failures:
        raise SystemExit(
            json.dumps(
                {"status": "fail", "failures": failures},
                ensure_ascii=False,
                indent=2,
            )
        )

    args.out_cases.parent.mkdir(parents=True, exist_ok=True)
    args.out_cases.write_text(
        "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases),
        encoding="utf-8",
    )
    write_json(args.out_gold_root / "chain_gold_index.json", gold_index)
    write_json(
        args.manifest,
        {
            "suite": "atlasv2_s3_s4_attack8_paired_20260724",
            "purpose": (
                "Attack reconstruction with the same paired evaluation-unit "
                "design as the normal 27-chain reconstruction experiment."
            ),
            "source_legacy_suite": str(args.source_cases.relative_to(ROOT)),
            "case_file": str(args.out_cases.relative_to(ROOT)),
            "gold_root": str(args.out_gold_root.relative_to(ROOT)),
            "stage_counts": {stage: 8 for stage in STAGES},
            "total_model_inputs": len(cases),
            "evaluation_unit": "eight behavior chains, fixed across all stages",
            "stage_conditions": {
                "stage1": "one representative CBC alert + host/process/time",
                "stage2": (
                    "host/process/time only; CBC alert summaries remain "
                    "discoverable in the database"
                ),
                "stage3": (
                    "same host/process/time; CBC alert summaries hidden; "
                    "cbc_events retained"
                ),
            },
            "time_scope_policy": (
                "Normal-suite parity: the declared chain window guides search "
                "and reporting, but does not physically truncate the adapter DB."
            ),
            "scoring_policy": (
                "Use the same score_element_order_with_gpt.py protocol. Keep "
                "critical_evidence_recall separate from action_step_recall and "
                "action_step_precision."
            ),
            "legacy_results_policy": (
                "The attack24 outputs remain an alert-target sensitivity study "
                "and must not be used as a paired Stage 1/2/3 comparison."
            ),
            "gold_index": gold_index,
            "validation": str(args.validation.relative_to(ROOT)),
        },
    )
    write_json(
        args.validation,
        {
            "status": "pass",
            "check_count": len(checks),
            "checks": checks,
        },
    )
    print(
        json.dumps(
            {
                "status": "pass",
                "cases": str(args.out_cases),
                "case_count": len(cases),
                "stage_counts": dict(Counter(case["stage"] for case in cases)),
                "gold_count": len(gold_index),
                "validation": str(args.validation),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
