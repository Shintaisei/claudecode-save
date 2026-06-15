# Aggregated Results

This folder contains the aggregate tables used as the current paper/discussion baseline.

## Final Comparison Scope

| model | runs | chain count | stage count | set count | note |
| --- | ---: | ---: | ---: | ---: | --- |
| `gpt-4.1-mini` | 207 | 23 | 3 | 3 | 2 formal 23-chain sets plus 1 filtered legacy27 set |
| `gpt-5.4-mini` | 207 | 23 | 3 | 3 | 2 formal 23-chain sets plus 1 filtered legacy27 set |
| `gpt-5.5 low raw` | 69 | 23 | 3 | 1 | raw-output salvage scoring only |

## Primary Tables

| file | use |
| --- | --- |
| `summary.md` | Human-readable final summary. Start here. |
| `overall.csv` | Overall model-level metrics. |
| `by_stage.csv` | Stage-level metrics for stage1 / stage2 / stage3. |
| `by_replicate_4_1_5_4.csv` | 4.1/5.4 three-set breakdown. The third set is the filtered legacy27 subset. |
| `by_scenario_group.csv` | Three-scenario-group aggregate table. |
| `by_stage_scenario_group.csv` | Stage x scenario-group aggregate table. |
| `by_framework_group.csv` | Detailed behavior-framework aggregate table. |
| `by_stage_framework_group.csv` | Stage x behavior-framework aggregate table. |
| `ledgers/final_comparison_per_run_component_scores.csv` | Per-run ledger for all 483 comparison rows: 207 + 207 + 69. |
| `ledgers/4_1_5_4_3run_filtered23_per_run_component_scores.csv` | Per-run ledger for the 4.1/5.4 three-set filtered23 comparison only. |
| `openai_cost_audit_note_20260614.md` | Cost audit note explaining the GPT-5.5 undercount and API spend mismatch. |
| `openai_usage_audit_20260614.csv` | Token/cost audit detail. |

## Metric Notes

- The main component fields are `action_step_recall`, `critical_evidence_recall`, `order_score`, `precision_proxy`, and overclaim counts.
- Fractions in the CSVs should be preferred when checking denominator definitions.
- GPT-5.5 has high component scores in this table, but must be reported with the caveat that its raw output did not follow the structured output contract.
- Scenario-group tables use the current 23-chain chain IDs. The legacy27 set is filtered to those same 23 chain IDs before aggregation.
