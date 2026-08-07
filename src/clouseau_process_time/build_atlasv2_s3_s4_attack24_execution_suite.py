"""Build the runner-ready S3/S4 CBC attack-reconstruction suite.

Stage 1 evaluates every selected CBC alert target (24 inputs).  Stages 2/3
remove alert-summary information, so identical host/process/time inputs are
represented once rather than scored repeatedly against different Gold files.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "data/current_experiment/cases"
OUT = CASES / "atlasv2_s3_s4_attack24_stage_cases_20260723.jsonl"
MANIFEST = CASES / "atlasv2_s3_s4_attack24_execution_manifest_20260723.json"
VALIDATION = ROOT / "docs/current_experiment/atlasv2_s3_s4_attack24_execution_preflight_20260723.json"

SOURCES = [
    CASES / "atlasv2_s3_11_cbc_alert_stage1_cases_20260723.jsonl",
    CASES / "atlasv2_s3_4_process_time_stage2_cases_20260723.jsonl",
    CASES / "atlasv2_s3_4_process_time_stage3_cases_20260723.jsonl",
    CASES / "atlasv2_s4_13_cbc_attack_stage_cases_20260723.jsonl",
]
EXPECTED_STAGE_COUNTS = {"stage1": 24, "stage2": 8, "stage3": 8}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def visible_signature(case: dict[str, Any]) -> tuple[Any, ...]:
    model_input = case["model_ready_input"]["input"]
    return (
        model_input.get("host"),
        tuple(model_input.get("focus_processes", [])),
        model_input.get("chain_window_start_utc"),
        model_input.get("chain_window_end_utc"),
    )


def validate(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    stage_counts = Counter(case["stage"] for case in cases)
    checks.append({"check": "stage_counts", "expected": EXPECTED_STAGE_COUNTS, "actual": dict(stage_counts), "status": "pass" if dict(stage_counts) == EXPECTED_STAGE_COUNTS else "fail"})
    ids = [case["instance_id"] for case in cases]
    checks.append({"check": "instance_ids_unique", "actual": len(ids), "unique": len(set(ids)), "status": "pass" if len(ids) == len(set(ids)) else "fail"})
    for stage in ("stage2", "stage3"):
        scoped = [case for case in cases if case["stage"] == stage]
        signatures = [visible_signature(case) for case in scoped]
        checks.append({"check": f"{stage}_visible_input_unique", "actual": len(signatures), "unique": len(set(signatures)), "status": "pass" if len(signatures) == len(set(signatures)) else "fail"})
    stage1 = [case for case in cases if case["stage"] == "stage1"]
    alert_ids = {case["input_alert_rows"][0]["alert_id"] for case in stage1}
    checks.append({"check": "stage1_alert_target_inputs", "actual": len(stage1), "unique_alert_ids_global": len(alert_ids), "expected": {"alert_target_inputs": 24, "unique_alert_ids_global": 14}, "status": "pass" if len(stage1) == 24 and len(alert_ids) == 14 else "fail"})
    for case in cases:
        stage = case["stage"]
        model_input = case["model_ready_input"]["input"]
        checks.append({"check": "hard_time_scope_opt_in", "instance_id": case["instance_id"], "status": "pass" if case.get("enforce_time_scope") is True else "fail"})
        if stage == "stage1":
            checks.append({"check": "stage1_one_selected_alert", "instance_id": case["instance_id"], "status": "pass" if len(case.get("input_alert_rows", [])) == 1 and "cbc_alert" in model_input else "fail"})
        else:
            visible = json.dumps(model_input, ensure_ascii=False).lower()
            prohibited = [token for token in ("alert_id", "alert_name", "alert_reason", "cbc_alert", "ground_truth", "source_alert_row") if token in visible]
            checks.append({"check": "stage23_no_alert_summary_leak", "instance_id": case["instance_id"], "prohibited": prohibited, "status": "pass" if not prohibited else "fail"})
    return checks


def main() -> None:
    cases = [case for source in SOURCES for case in read_jsonl(source)]
    checks = validate(cases)
    failures = [check for check in checks if check["status"] != "pass"]
    if failures:
        raise SystemExit(json.dumps({"preflight": "failed", "failures": failures}, ensure_ascii=False, indent=2))
    OUT.write_text("".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases), encoding="utf-8")
    stage_commands = {
        "stage1": f"python src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py --cases {OUT.relative_to(ROOT)} --stage stage1 --run-all --dry-run",
        "stage2": f"python src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py --cases {OUT.relative_to(ROOT)} --stage stage2 --run-all --dry-run",
        "stage3": f"python src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py --cases {OUT.relative_to(ROOT)} --stage stage3 --run-all --exclude-cbc-alert-summary --dry-run",
    }
    manifest = {
        "suite": "atlasv2_s3_s4_cbc_attack_reconstruction_20260723",
        "model_execution_status": "not_run",
        "host": "WIN-32-H1",
        "investigation_window": "CBC alert create_time +/- 15 minutes (30 minutes total), physically enforced by enforce_time_scope=true",
        "evaluation_unit": {
            "stage1": "24 CBC alert-target inputs (S3/S4で各8 alert ID、シナリオ横断の文字列値としては14 unique alert IDs)",
            "stage2_stage3": "8 unique host/process/time inputs; no repeated visible input is scored against different Gold",
        },
        "stage_counts": EXPECTED_STAGE_COUNTS,
        "total_model_inputs": len(cases),
        "stage3_contract": "Run only with --exclude-cbc-alert-summary; runner fails closed otherwise. CBC event telemetry remains available.",
        "comparison_contract": "Stage 1 (24 alert-target inputs) and Stages 2/3 (8 deduplicated host/process/time contexts) are separate aggregates, not one-to-one paired comparisons. Boundary Word cases are reported separately from the main attack-reconstruction success aggregate. triage_decision is retained as a reference output and is not scored in this suite.",
        "dry_run_commands": stage_commands,
        "run_commands": {stage: command.replace(" --dry-run", "") for stage, command in stage_commands.items()},
        "source_case_files": [str(source.relative_to(ROOT)) for source in SOURCES],
        "preflight_validation": str(VALIDATION.relative_to(ROOT)),
    }
    # The source was once written by a terminal with a mismatched encoding.
    # Override that legacy display string with the canonical execution contract.
    manifest["evaluation_unit"]["stage1"] = (
        "24 CBC alert-target inputs across S3/S4 (14 unique alert IDs globally; "
        "alert ID, scenario, and process context may repeat across targets)"
    )
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    VALIDATION.write_text(json.dumps({"status": "pass", "check_count": len(checks), "checks": checks}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(cases), "stage_counts": dict(Counter(case["stage"] for case in cases)), "checks": len(checks), "status": "pass"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
