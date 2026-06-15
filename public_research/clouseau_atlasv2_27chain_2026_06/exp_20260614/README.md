# Component-Rubric Experiment Package 2026-06-14

This folder is the latest handoff package for the 23-chain CLOUSEAU / ATLASv2 component-rubric experiment.

It includes raw model outputs, scoring ledgers, aggregate result tables, cost audit material, and discussion notes used as the basis for the FIT2026 paper discussion.

## Scope

| model | raw run scope | scored comparison scope |
| --- | ---: | ---: |
| `gpt-4.1-mini` | 23 chains x 3 stages x 3 sets = 207 runs | 207 runs |
| `gpt-5.4-mini` | 23 chains x 3 stages x 3 sets = 207 runs | 207 runs |
| `gpt-5.5 low raw` | 23 chains x 3 stages x 1 set = 69 runs | 69 salvaged runs |

For `gpt-4.1-mini` and `gpt-5.4-mini`, the third set is not a newly named `formal23 replicate_03`; it is the current 23-chain subset extracted from the earlier 27-chain experiment and treated as the practical third set. This matches the experiment decision used for the final aggregate tables.

For `gpt-5.5 low raw`, the output contract differed from the structured 4.1/5.4 runs. The package therefore keeps the raw output and the conservative component-rubric salvage scores separately documented.

## Folder Layout

| folder | role |
| --- | --- |
| `01_experiment_raw_outputs/` | Raw per-run output JSON. Includes `f23_2rep/`, `legacy27_raw/`, and `gpt55_r1/`. |
| `02_scoring_ledgers/` | Component-rubric scoring ledgers, Codex double-review records, conflict/adoption records, and review rubric. |
| `03_aggregated_results/` | Final aggregate tables and per-run ledgers for the paper/discussion tables. |
| `04_discussion_base/` | Discussion source material: detailed discussion, usecase deep dive, model-argument deep dive, Investigator/SQL deep dive, and operational cost/time analysis. |

## Key Files

1. `03_aggregated_results/summary.md`
2. `03_aggregated_results/overall.csv`
3. `03_aggregated_results/by_stage.csv`
4. `03_aggregated_results/by_scenario_group.csv`
5. `03_aggregated_results/ledgers/final_comparison_per_run_component_scores.csv`
6. `04_discussion_base/detailed_discussion_20260614.md`
7. `04_discussion_base/usecase_deep_dive_20260614/usecase_deep_dive.md`
8. `04_discussion_base/model_argument_deep_dive_20260614/model_argument_deep_dive.md`
9. `04_discussion_base/investigator_sql_deep_dive_20260614/investigator_sql_deep_dive.md`

## Review Notes

- Component scoring uses the older part-level rubric requested for `action_step_recall`, `critical_evidence_recall`, order, precision proxy, and overclaim counts.
- A component is counted as a hit when the required content is substantively present, even if surface wording differs.
- CBC alert-summary-only evidence is not counted as non-alert evidence.
- GPT-5.5 scores must be described as raw-output salvage results, not as fully contract-compliant structured results.
