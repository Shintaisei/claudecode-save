# Experiment design

## Current Result Scope

The current final result set for paper writing is the 23-chain component-rubric result set in:

- `results_23chain_20260614/`

The older 27-chain result files remain in `results/` for traceability, but they are not the current final 23-chain result tables.

## Unit of evaluation

The base unit is a behavior chain. The current final analysis uses 23 finalized chains from the ATLASv2 benign H1 / benign-1 environment.

Each chain is run under three input stages:

| Stage | Input condition | Meaning |
|---|---|---|
| `stage1` | CBC alert rows are provided as input | Alert-assisted reconstruction |
| `stage2` | Host, focus process, and time window only | Process/time starting point, alert summaries still available in DB |
| `stage3` | Same as stage2, but alert summary rows are removed from retrieval | Telemetry-heavy reconstruction without alert summary shortcut |

This yields 23 chains x 3 stages = 69 runs per model per set.

For `gpt-4.1-mini` and `gpt-5.4-mini`, the final comparison uses three sets:

- formal23 `replicate_01`,
- formal23 `replicate_02`,
- and the older 27-chain run filtered to the current 23 chain IDs.

This gives 23 chains x 3 stages x 3 sets = 207 rows per model.

For `gpt-5.5`, the package includes one raw-output salvage set: 23 chains x 3 stages = 69 rows.

## Models

The completed package includes:

- `gpt-4.1-mini`
- `gpt-5.4-mini`
- `gpt-5.5 low raw` as a one-set raw-output salvage result

## Scenario basis

The raw chain categories come from `chain_type` / `expected_behavior_category` in the case metadata and gold chain index. The higher-level 3-class scenario grouping is an analysis layer built from those raw chain types. See `scenario_taxonomy.md`.

## Scoring metrics

The result tables include:

- action / behavior item recall,
- critical evidence recall,
- behavior sequence order,
- candidate claim precision,
- overclaim slot count.

The primary current aggregate files are in `results_23chain_20260614/`.

## Important caveat

The aggregate CSVs retain numerator/denominator fractions. When comparing across scoring pipelines, check the denominator as well as the percentage, because final score files may encode item-level required fields differently.
