#!/usr/bin/env python3
"""Build the versioned normal-parity v2 ATLASv2 attack8 suite.

The v1 neutral-five-minute suite used process identity as a component edge and
asked the model to enumerate the whole window.  That made routine activity by
the same process part of the apparent target component, although the normal
behavior-reconstruction experiment evaluates a semantic behavior chain rather
than an exhaustive process audit trail.

This wrapper preserves the validated 45 Gold steps, neutral anchors, and
five-minute windows while versioning a stricter, normal-parity behavior-chain
boundary.  It delegates all source-row and stage-contract validation to the v1
builder.
"""

from pathlib import Path

import build_atlasv2_s3_s4_attack8_neutral5_suite as builder


ROOT = Path(__file__).resolve().parents[2]
VERSION = "20260726"
SUITE = "atlasv2_s3_s4_attack8_neutral5_parity_v2"


def main() -> None:
    builder.OUT_CASES = (
        ROOT
        / "data/current_experiment/cases"
        / f"{SUITE}_stage_cases_{VERSION}.jsonl"
    )
    builder.OUT_GOLD_ROOT = (
        ROOT
        / "data/current_experiment/gold"
        / f"{SUITE}_gold_{VERSION}"
    )
    builder.OUT_MANIFEST = (
        ROOT
        / "data/current_experiment/cases"
        / f"{SUITE}_manifest_{VERSION}.json"
    )
    builder.OUT_VALIDATION = (
        ROOT
        / "docs/current_experiment"
        / f"{SUITE}_build_validation_{VERSION}.json"
    )
    builder.SUITE_GROUP = SUITE
    builder.CONTRACT_VERSION = "neutral_anchor_semantic_chain_normal_parity_v2"
    builder.TARGET_COMPONENT_RULE = (
        "Reconstruct the evidence-backed semantic behavior chain containing "
        "the focus-process observation at, or nearest to, the neutral anchor. "
        "Expand the chain only through observed parent/child, command, or "
        "target-object edges. Process identity may join rows that describe the "
        "same semantic action, but shared process name/PID or temporal "
        "proximity alone does not make routine file, registry, or module "
        "activity a separate chain step. Report observed ancillary activity "
        "outside the primary chain."
    )
    builder.main()


if __name__ == "__main__":
    main()
