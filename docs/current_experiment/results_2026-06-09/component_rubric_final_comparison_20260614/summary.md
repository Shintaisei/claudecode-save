# Component Rubric Final Comparison 2026-06-14

Scoring policy: content inclusion. If the substantive gold subject/action/object/evidence appears in the candidate output, count it as a hit. Alert-only evidence is not counted as non-alert evidence.

For gpt-4.1-mini and gpt-5.4-mini, the third set is the legacy 27-chain run filtered to the current 23-chain scope, not a generated formal23 `replicate_03`.

For gpt-5.5, rows are raw-text salvage because the output contract failed; report separately from formal JSON compliance. The 3-run GPT-5.5 low set is now complete and double-reviewed.

## Overall

| model | run_count | chain_count | replicate_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count | scope_note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini | 207 | 23 | 3 | 0.466 | 0.195 | 0.201 | 0.366 | 1190 | 3run: formal23 rep1+rep2 + legacy27 filtered to current 23 |
| gpt-5.4-mini | 207 | 23 | 3 | 0.798 | 0.703 | 0.553 | 0.584 | 651 | 3run: formal23 rep1+rep2 + legacy27 filtered to current 23 |
| gpt-5.5 low raw | 207 | 23 | 3 | 0.918 | 0.906 | 0.868 | 0.640 | 1235 | raw-text salvage; output contract failed; 3 complete runs |

## By Stage

| model | stage | run_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count | scope_note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini | stage1 | 69 | 0.639 | 0.292 | 0.341 | 0.433 | 422 | 3run filtered23 |
| gpt-4.1-mini | stage2 | 69 | 0.414 | 0.128 | 0.111 | 0.285 | 506 | 3run filtered23 |
| gpt-4.1-mini | stage3 | 69 | 0.345 | 0.164 | 0.151 | 0.382 | 262 | 3run filtered23 |
| gpt-5.4-mini | stage1 | 69 | 0.791 | 0.574 | 0.579 | 0.559 | 215 | 3run filtered23 |
| gpt-5.4-mini | stage2 | 69 | 0.800 | 0.754 | 0.540 | 0.597 | 213 | 3run filtered23 |
| gpt-5.4-mini | stage3 | 69 | 0.802 | 0.779 | 0.540 | 0.594 | 223 | 3run filtered23 |
| gpt-5.5 low raw | stage1 | 69 | 0.937 | 0.908 | 0.897 | 0.658 | 374 | raw-text salvage; 3 complete runs |
| gpt-5.5 low raw | stage2 | 69 | 0.915 | 0.908 | 0.857 | 0.620 | 415 | raw-text salvage; 3 complete runs |
| gpt-5.5 low raw | stage3 | 69 | 0.903 | 0.903 | 0.849 | 0.643 | 446 | raw-text salvage; 3 complete runs |

## 4.1/5.4 By Source Set

| model | replicate | source_set | run_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini | legacy_27_filtered_20260609 | formal_27_chain_20260609_filtered_to_current_23 | 69 | 0.475 | 0.056 | 0.175 | 0.356 | 495 |
| gpt-4.1-mini | replicate_01 | formal_23_chain_2rep_20260612 | 69 | 0.491 | 0.277 | 0.167 | 0.335 | 373 |
| gpt-4.1-mini | replicate_02 | formal_23_chain_2rep_20260612 | 69 | 0.432 | 0.251 | 0.262 | 0.410 | 322 |
| gpt-5.4-mini | legacy_27_filtered_20260609 | formal_27_chain_20260609_filtered_to_current_23 | 69 | 0.822 | 0.790 | 0.619 | 0.563 | 90 |
| gpt-5.4-mini | replicate_01 | formal_23_chain_2rep_20260612 | 69 | 0.802 | 0.651 | 0.484 | 0.545 | 307 |
| gpt-5.4-mini | replicate_02 | formal_23_chain_2rep_20260612 | 69 | 0.769 | 0.667 | 0.556 | 0.629 | 254 |
