"""Create-only salvage of the completed pilot05 Stage 3 source run.

The model run completed successfully, but the paired wrapper failed while
copying to a 280-character Windows path. This script verifies the frozen source
hash and run invariants, adds the paired-experiment provenance block, and writes
the same thought to a shorter result root. It does not call any model API.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "data/current_experiment/runs/clouseau_reconstruction_outputs/"
    / (
        "20260730T060130Z_chain_10_e07_discord_run_key_registry_chain_"
        "stage3_gpt-4.1-mini_official"
    )
    / "run.json"
)
SOURCE_SHA256 = (
    "8d10f5a35c75e0abb51cf0db0f802c9bce39a0c09bb667b5cf16a84ec416922c"
)
CASES = (
    ROOT
    / "data/current_experiment/cases/"
    / "normal8_observable_component_v3_stage_cases_20260726.jsonl"
)
INSTANCE_ID = "chain_10_e07_discord_run_key_registry_chain_stage3"
DESTINATION = (
    ROOT
    / "docs/current_experiment/results_2026-07-30/"
    / "normal_attack_full_ledger_pilot_05/executions/"
    / "normal_chain10_gpt41/s3r2/runs/gpt-4.1-mini/stage3/"
    / f"{INSTANCE_ID}_run.json"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_case() -> dict[str, Any]:
    for line in CASES.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        if case["instance_id"] == INSTANCE_ID:
            return case
    raise ValueError(f"missing case {INSTANCE_ID}")


def main() -> None:
    if DESTINATION.exists():
        raise FileExistsError(f"create-only target exists: {DESTINATION}")
    actual_hash = sha256(SOURCE)
    if actual_hash != SOURCE_SHA256:
        raise ValueError(
            f"source hash mismatch expected={SOURCE_SHA256} actual={actual_hash}"
        )
    payload = json.loads(SOURCE.read_text(encoding="utf-8"))
    if payload.get("instance_id") != INSTANCE_ID:
        raise ValueError("source instance mismatch")
    if payload.get("model") != "gpt-4.1-mini":
        raise ValueError("source model mismatch")
    if payload.get("error") is not None:
        raise ValueError(f"source error: {payload['error']}")
    json.loads(payload["output_text"])
    audit = payload.get("usage_audit") or {}
    for field in (
        "full_pipeline_equals_role_total",
        "full_pipeline_equals_call_ledger",
        "callback_aggregate_equals_call_ledger",
    ):
        if audit.get(field) is not True:
            raise ValueError(f"source usage audit failed: {field}")
    case = load_case()
    gold = (
        ROOT
        / "data/current_experiment/gold/"
        / case["formal_gold_root"]
        / "by_chain"
        / case["chain_id"]
        / "chain_gold.json"
    )
    payload["atlasv2_s3_s4_attack8_paired_experiment"] = {
        "suite_group": case.get("suite_group"),
        "contract_version": (
            (case.get("paired_stage_contract") or {}).get("contract_version")
        ),
        "case_file": str(CASES),
        "chain_id": case["chain_id"],
        "stage": case["stage"],
        "gold": str(gold),
        "copied_from": str(SOURCE),
        "salvage_reason": (
            "model run completed; original paired-wrapper destination was "
            "280 characters and failed at the final Windows copy step"
        ),
        "source_run_sha256": SOURCE_SHA256,
        "model_api_reexecuted_for_salvage": False,
    }
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(DESTINATION)
    print(sha256(DESTINATION))


if __name__ == "__main__":
    main()
