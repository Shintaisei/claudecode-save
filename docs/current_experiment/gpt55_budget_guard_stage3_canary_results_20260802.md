# GPT-5.5 run-budget guard Stage 3 canary (2026-08-02)

## Verdict

- The normal Discord canary completed without a budget trigger and passed the deterministic run audit.
- The attack mshta canary exposed a real SQL-QA context expansion. The soft cost stop fired at $6.042672 and the hard stop censored the run at $8.108157.
- The guard therefore prevented an unbounded GPT-5.5 run. The attack artifact is valid JSON and retained for diagnosis, but it is excluded from formal accuracy scoring because it is budget-censored.
- No broad GPT-5.5 experiment was started after this canary.

## Guard configuration

| Dimension | Soft | Hard |
|---|---:|---:|
| API calls | 350 | 400 |
| Total tokens | 1,600,000 | 2,000,000 |
| Estimated cost | $6.00 | $8.00 |
| Accepted Chief leads | 20 | 24 |

Other limits were one LLM call = 600 seconds, one run = 1,800 seconds, and one lead = 1,200 seconds. At the soft threshold the agent stops opening new frontier leads and finalizes with unresolved items; at the hard threshold it stops new model calls and marks the run budget-censored.

## Run-level results

| Phase | Audit | Wall time | API calls | Input | Output | Cached input | Total tokens | Cost | Accepted Chief leads | Budget result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Normal Discord Stage 3 | PASS | 904.250 s (15.07 min) | 51 | 379,464 | 72,070 | 216,576 | 451,534 | $3.084828 | 4 | Not triggered |
| Attack mshta Stage 3 | FAIL for formal use | 633.125 s (10.55 min) | 33 | 1,284,980 | 68,563 | 302,848 | 1,353,543 | $8.108157 | 3 | Soft + hard; censored |
| **Canary total** | — | **1,537.375 s (25.62 min)** | **84** | **1,664,444** | **140,633** | **519,424** | **1,805,077** | **$11.192985** | **7** | Batch cap $20 not reached |

## Module-level usage

### Normal Discord Stage 3

| Module | API calls | Input | Output | Cached input | Total tokens | LLM time |
|---|---:|---:|---:|---:|---:|---:|
| Chief | 9 | 85,623 | 38,331 | 52,608 | 123,954 | 528.718 s |
| Investigator | 12 | 38,704 | 13,304 | 15,104 | 52,008 | 137.922 s |
| SQL QA | 30 | 255,137 | 20,435 | 148,864 | 275,572 | 223.264 s |

Activity ledger: 5 attempted/unique lead calls (4 accepted by the budget ledger), 8 unique Investigator questions, 22 unique SQL queries, and no repeated lead, question, or query. The output contained 4 code steps.

### Attack mshta Stage 3

| Module | API calls | Input | Output | Cached input | Total tokens | LLM time |
|---|---:|---:|---:|---:|---:|---:|
| Chief | 5 | 67,862 | 23,857 | 10,496 | 91,719 | 198.360 s |
| Investigator | 9 | 43,987 | 17,798 | 15,872 | 61,785 | 162.049 s |
| SQL QA | 19 | 1,173,131 | 26,908 | 276,480 | 1,200,039 | 268.389 s |

Activity ledger: 3 unique Chief leads, 6 unique Investigator questions, 13 unique SQL queries, and no repeated lead, question, or query. The partial output contained 8 code steps and reached the observed `mshta.exe -> powershell.exe -> powershell.exe -> ortrta.net / 10.193.66.115:8443` chain, but the run remains non-scorable due to the hard budget stop.

## Why the attack cost expanded

The failure mode was not excessive Chief lead count. SQL QA consumed 1,200,039 of 1,353,543 total tokens (88.66%). Several SQL-QA calls received very large prior-result context:

| Call | Module | Input tokens | Output tokens | Long-context pricing | Cost |
|---:|---|---:|---:|---|---:|
| 21 | SQL QA | 273,034 | 3,235 | Yes | $2.026891 |
| 30 | SQL QA | 193,568 | 3,074 | No | $1.060060 |
| 29 | SQL QA | 193,230 | 756 | No | $0.981342 |
| 17 | SQL QA | 131,616 | 2,023 | No | $0.172146 |
| 16 | SQL QA | 121,841 | 787 | No | $0.625327 |

Call 21 crossed the GPT-5.5 long-context input threshold (272,000 tokens). The existing 30-row SQL result guard bounds row count, but wide rows can still contribute hundreds of thousands of characters. This is the next control point: add a byte/token cap and deterministic projection/truncation for SQL result text before it is reinserted into model context. A lower pre-finalization soft cost threshold is also advisable because completing the active lead after the $6 soft stop added about $2.07 before the hard stop.

## Provenance

- Result root: `docs/current_experiment/results_2026-08-02/gpt55_budget_guard_stage3_canary_01`
- Normal run SHA-256: `b2c9b89b08c1aee13a414836746878682bcf27dda8a28c2e0a35f354a66e04df`
- Attack run SHA-256: `7692be6e0d1108590278038c2c2cb795ca1a74d303a1ca29de43d2c475d7b3cd`
- Deterministic summary: `gpt55_budget_guard_stage3_canary_01/canary_summary.json`

