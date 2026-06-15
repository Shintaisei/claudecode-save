# OpenAI Cost Audit Note 2026-06-16

## Summary

The local API cost log is useful for token counting, but it is not reliable as a dollar ledger for the GPT-5.5 experiment because `call_total_usd` was recorded as `0.00` for GPT-5.5 calls.

For the completed GPT-5.5 low experiment, use the progress-side conservative estimate:

| item | value |
| --- | ---: |
| GPT-5.5 low valid runs | 207 |
| Replicates | 3 |
| Runs per replicate | 69 |
| Input tokens in `clouseau_api_costs.csv` | 5,555,335 |
| Output tokens in `clouseau_api_costs.csv` | 2,191,309 |
| Logged GPT-5.5 `call_total_usd` | $0.00 |
| Conservative completed-cost estimate | $93.52 |

## Interpretation

The earlier account-level usage amount and the local CSV were not directly comparable because the CSV failed to price GPT-5.5 rows. The correct way to report this package is therefore:

- token volume is taken from local run logs,
- GPT-5.5 dollar cost is treated as a reconstructed estimate,
- `call_total_usd=0.00` rows are a logging defect, not free calls.

## Current Experiment Status

The GPT-5.5 low run set is complete:

| replicate | stage1 | stage2 | stage3 | total |
| --- | ---: | ---: | ---: | ---: |
| replicate_01 | 23 | 23 | 23 | 69 |
| replicate_02 | 23 | 23 | 23 | 69 |
| replicate_03 | 23 | 23 | 23 | 69 |
| total | 69 | 69 | 69 | 207 |

Scoring was performed inside Codex with local file review. No API-based judge was used for the review/scoring stage.

## Practical Caveat

Do not use `clouseau_api_costs.csv` alone to estimate GPT-5.5 spending unless the model pricing columns are fixed. For future high-cost model runs, enforce a nonzero per-call cost check before continuing beyond a pilot batch.
