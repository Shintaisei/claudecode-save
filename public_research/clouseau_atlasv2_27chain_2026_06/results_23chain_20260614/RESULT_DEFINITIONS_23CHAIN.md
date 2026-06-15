# 23-Chain Experiment Result Definitions

This file defines the terms used in the 23-chain result tables.

## Current Final Result

The current final experiment result is:

- `gpt-4.1-mini`: 207 scored rows
- `gpt-5.4-mini`: 207 scored rows
- `gpt-5.5 low raw`: 207 scored/salvaged rows

The main table is `overall.csv`.
The main per-run evidence table is `ledgers/final_comparison_per_run_component_scores.csv`.

## Why This Folder Exists

The repository also contains older 27-chain results under `results/`. Those files are retained for history, but they are not the current final result set used for the 23-chain component-rubric analysis.

For paper writing, use this folder first.

## Dataset Labels

| dataset label | meaning |
| --- | --- |
| `gpt-4.1-mini_3run_filtered23_component` | 23-chain component-rubric result for gpt-4.1-mini, 3 sets |
| `gpt-5.4-mini_3run_filtered23_component` | 23-chain component-rubric result for gpt-5.4-mini, 3 sets |
| `gpt-5.5_low_raw_component` | 23-chain component-rubric salvage result for gpt-5.5 low raw, 3 sets |

## Set Definitions

| set | models | source |
| --- | --- | --- |
| `replicate_01` | 4.1-mini / 5.4-mini / GPT-5.5 | formal 23-chain run |
| `replicate_02` | 4.1-mini / 5.4-mini / GPT-5.5 | formal 23-chain run |
| `replicate_03` | GPT-5.5 | formal 23-chain run |
| `legacy_27_filtered_20260609` | 4.1-mini / 5.4-mini | earlier 27-chain run filtered to the current 23 chain IDs |

## Gold And Evidence Rule

The gold target is non-alert behavior reconstruction.

- Alert summary can be the starting clue.
- Alert summary alone is not counted as non-alert evidence.
- Critical evidence credit requires substantive non-alert evidence content.
- For Stage3, alert summary is hidden from SQL retrieval; CBC EDR/NGAV telemetry remains visible.

## Scoring Rule

The scoring rule is content inclusion, not exact JSON shape.

A candidate receives credit when the substantive gold content appears in the output, even if:

- wording differs,
- Japanese/English phrasing differs,
- output structure differs,
- field names differ.

This is why the GPT-5.5 raw-output salvage can be scored at component level, while still being marked as a contract-failed result.
