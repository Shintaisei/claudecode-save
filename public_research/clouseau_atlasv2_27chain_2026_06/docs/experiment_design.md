# Experiment design

## Unit of evaluation

The base unit is a behavior chain. The current formal experiment uses 27 finalized chains from the ATLASv2 benign H1 / benign-1 environment.

Each chain is run under three input stages:

| Stage | Input condition | Meaning |
|---|---|---|
| `stage1` | CBC alert rows are provided as input | Alert-assisted reconstruction |
| `stage2` | Host, focus process, and time window only | Process/time starting point, alert summaries still available in DB |
| `stage3` | Same as stage2, but alert summary rows are removed from retrieval | Telemetry-heavy reconstruction without alert summary shortcut |

This yields 27 chains x 3 stages = 81 runs per model.

## Models

The completed package includes:

- `gpt-4.1-mini`
- `gpt-5.4-mini`

## Scenario basis

The raw chain categories come from `chain_type` / `expected_behavior_category` in the case metadata and gold chain index. The higher-level 3-class scenario grouping is an analysis layer built from those raw chain types. See `scenario_taxonomy.md`.

## Scoring metrics

The result tables include:

- action / behavior item recall,
- critical evidence recall,
- behavior sequence order,
- candidate claim precision,
- overclaim slot count.

The primary aggregate files are in `results/`.

## Important caveat

The aggregate CSVs retain numerator/denominator fractions. When comparing across scoring pipelines, check the denominator as well as the percentage, because final score files may encode item-level required fields differently.
