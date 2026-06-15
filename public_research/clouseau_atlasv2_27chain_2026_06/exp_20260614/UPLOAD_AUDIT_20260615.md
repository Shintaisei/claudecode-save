# Upload Audit 2026-06-15

This audit checks whether the GitHub package contains the current 23-chain experiment results and the GPT-5.5 one-run result set.

## Raw Output Coverage

| source folder | model | run count | expected count | status |
| --- | --- | ---: | ---: | --- |
| `01_experiment_raw_outputs/f23_2rep/replicate_01/` | `gpt-4.1-mini` | 69 | 23 chains x 3 stages = 69 | OK |
| `01_experiment_raw_outputs/f23_2rep/replicate_01/` | `gpt-5.4-mini` | 69 | 23 chains x 3 stages = 69 | OK |
| `01_experiment_raw_outputs/f23_2rep/replicate_02/` | `gpt-4.1-mini` | 69 | 23 chains x 3 stages = 69 | OK |
| `01_experiment_raw_outputs/f23_2rep/replicate_02/` | `gpt-5.4-mini` | 69 | 23 chains x 3 stages = 69 | OK |
| `01_experiment_raw_outputs/legacy27_raw/legacy27/` | `gpt-4.1-mini` | 81 | legacy 27 chains x 3 stages = 81 | OK |
| `01_experiment_raw_outputs/legacy27_raw/legacy27/` | `gpt-5.4-mini` | 81 | legacy 27 chains x 3 stages = 81 | OK |
| `01_experiment_raw_outputs/gpt55_r1/replicate_01/` | `gpt-5.5` | 69 | 23 chains x 3 stages = 69 | OK |

## Final Scored Ledger Coverage

The final comparison ledger is:

- `03_aggregated_results/ledgers/final_comparison_per_run_component_scores.csv`

| model label in ledger | rows | interpretation | status |
| --- | ---: | --- | --- |
| `gpt-4.1-mini` | 207 | 23 chains x 3 stages x 3 sets | OK |
| `gpt-5.4-mini` | 207 | 23 chains x 3 stages x 3 sets | OK |
| `gpt-5.5 low raw` | 69 | 23 chains x 3 stages x 1 raw-output salvage set | OK |

For GPT-5.5, stage coverage is 23 rows for each of `stage1`, `stage2`, and `stage3`.

## Review Result

- The 23-chain experiment package is present.
- The GPT-5.5 raw output package is present.
- GPT-5.5 scored/salvaged results are present in the final comparison ledger and overall aggregate tables.
- The first upload had the right files, but two copied README files were mojibake. They have been replaced with readable UTF-8/ASCII documentation in this follow-up commit.

## Caveat For Reporting

GPT-5.5 should be described as a one-set raw-output salvage result. It is useful for comparing substantive reconstruction ability, but it is not directly contract-equivalent to the structured `gpt-4.1-mini` and `gpt-5.4-mini` runs.
