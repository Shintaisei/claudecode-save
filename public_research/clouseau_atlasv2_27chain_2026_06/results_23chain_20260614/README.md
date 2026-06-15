# Current Experiment Results: 23-Chain Component-Rubric Results

This folder is the primary result folder for the current 23-chain experiment.

Use this folder when writing the FIT2026 paper or slides. The older top-level `results/` folder is the earlier 27-chain public package result set and is kept for traceability.

## What This Result Set Means

| item | definition |
| --- | --- |
| Experiment unit | One behavior chain under one stage condition |
| Final chain scope | 23 behavior chains |
| Stages | `stage1`, `stage2`, `stage3` |
| Main structured models | `gpt-4.1-mini`, `gpt-5.4-mini` |
| Structured comparison scope | 23 chains x 3 stages x 3 sets = 207 rows per model |
| GPT-5.5 scope | 23 chains x 3 stages x 1 set = 69 raw-output salvage rows |
| Scoring rubric | Component rubric with content-inclusion matching |
| Current final ledger | `ledgers/final_comparison_per_run_component_scores.csv` |

## Final Comparison Scope

| model | rows | chain count | stage count | set count | treatment |
| --- | ---: | ---: | ---: | ---: | --- |
| `gpt-4.1-mini` | 207 | 23 | 3 | 3 | formal23 rep1 + formal23 rep2 + legacy27 filtered to current 23 |
| `gpt-5.4-mini` | 207 | 23 | 3 | 3 | formal23 rep1 + formal23 rep2 + legacy27 filtered to current 23 |
| `gpt-5.5 low raw` | 69 | 23 | 3 | 1 | raw-output salvage; output contract failed |

The third set for `gpt-4.1-mini` and `gpt-5.4-mini` is not a newly executed formal23 `replicate_03`. It is the current 23-chain subset extracted from the earlier 27-chain run and used as the practical third set.

## Stage Definitions

| stage | input clue | database visibility | interpretation |
| --- | --- | --- | --- |
| `stage1` | Process-time fields plus CBC alert summary fields | CBC alert summary, CBC EDR/NGAV telemetry, OS/browser logs | Alert-assisted reconstruction |
| `stage2` | Process-time fields only | CBC alert summary still retrievable in DB | Model must discover alert context from the process/time starting point |
| `stage3` | Process-time fields only | CBC alert summary hidden from SQL retrieval; CBC EDR/NGAV telemetry remains available | Tests reconstruction without the alert-summary shortcut |

Stage3 does not remove all CBC data. It removes CBC alert summary rows from retrieval, while retaining CBC EDR/NGAV telemetry.

## Metric Definitions

| metric | denominator | meaning |
| --- | --- | --- |
| `action_step_recall` | `gold_step_count * 3` | Recovery of subject/action/object components |
| `critical_evidence_recall` | `gold_step_count` | Recovery of critical non-alert evidence for each gold step |
| `behavior_sequence_order` | `max(gold_step_count - 1, 0)` | Recovery of adjacent gold-step order |
| `candidate_claim_precision` | candidate claim slots | Fraction of candidate claim slots that are correct/supported |
| `overclaim_slot_count` | count only | Unsupported, wrong, or outside-gold claim slots |

Matching uses content inclusion. If the candidate output contains the substantive gold content, it is counted as a hit even when wording or output structure differs. CBC alert-summary-only evidence is not counted as non-alert evidence.

## Main Files

| file | purpose |
| --- | --- |
| `summary.md` | Human-readable final result summary |
| `overall.csv` | Overall model-level scores |
| `by_stage.csv` | Stage-level scores |
| `by_replicate_4_1_5_4.csv` | Source-set breakdown for 4.1/5.4 |
| `by_scenario_group.csv` | Three-scenario-group results |
| `by_stage_scenario_group.csv` | Stage x scenario-group results |
| `by_framework_group.csv` | Detailed behavior-framework results |
| `by_stage_framework_group.csv` | Stage x behavior-framework results |
| `ledgers/final_comparison_per_run_component_scores.csv` | Per-run component-score ledger for all 483 rows |
| `ledgers/4_1_5_4_3run_filtered23_per_run_component_scores.csv` | Per-run ledger for the 4.1/5.4 3-set comparison only |
| `openai_cost_audit_note_20260614.md` | Cost and token audit note |
| `openai_usage_audit_20260614.csv` | Cost/token detail |

## Overall Result

| model | rows | action recall | evidence recall | order | precision proxy | overclaims |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `gpt-4.1-mini` | 207 | 0.466 | 0.195 | 0.201 | 0.366 | 1190 |
| `gpt-5.4-mini` | 207 | 0.798 | 0.703 | 0.553 | 0.584 | 651 |
| `gpt-5.5 low raw` | 69 | 0.940 | 0.928 | 0.889 | 0.667 | 350 |

## Reporting Caveat

Use `gpt-5.5 low raw` as a raw-output salvage result. It is useful for discussing substantive reconstruction ability, but it is not directly contract-equivalent to the structured `gpt-4.1-mini` and `gpt-5.4-mini` results.

