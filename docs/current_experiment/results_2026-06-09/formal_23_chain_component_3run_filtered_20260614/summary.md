# Formal 23-Chain Component Rubric 3-Run Filtered Results

This folder treats the legacy 27-chain run as the third set only after filtering it to the current 23-chain scope.

Important: this is not a generated `formal_23_chain` `replicate_03`. The third set is `legacy_27_filtered_20260609`.

Scoring policy: content inclusion. If the candidate contains the substantive gold subject/action/object/evidence content, it is counted as a hit even if wording or output structure differs. Alert-only evidence is not counted as non-alert evidence.

## Overall 3-Run

| dataset_label | run_count | chain_count | replicate_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_3run_filtered23_component | 207 | 23 | 3 | 0.466 | 0.195 | 0.201 | 0.366 | 1190 |
| gpt-5.4-mini_3run_filtered23_component | 207 | 23 | 3 | 0.798 | 0.703 | 0.553 | 0.584 | 651 |

## By Stage

| dataset_label | stage | run_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_3run_filtered23_component | stage1 | 69 | 0.639 | 0.292 | 0.341 | 0.433 | 422 |
| gpt-4.1-mini_3run_filtered23_component | stage2 | 69 | 0.414 | 0.128 | 0.111 | 0.285 | 506 |
| gpt-4.1-mini_3run_filtered23_component | stage3 | 69 | 0.345 | 0.164 | 0.151 | 0.382 | 262 |
| gpt-5.4-mini_3run_filtered23_component | stage1 | 69 | 0.791 | 0.574 | 0.579 | 0.559 | 215 |
| gpt-5.4-mini_3run_filtered23_component | stage2 | 69 | 0.800 | 0.754 | 0.540 | 0.597 | 213 |
| gpt-5.4-mini_3run_filtered23_component | stage3 | 69 | 0.802 | 0.779 | 0.540 | 0.594 | 223 |

## By Replicate Source

| model | replicate | source_set | run_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini | legacy_27_filtered_20260609 | formal_27_chain_20260609_filtered_to_current_23 | 69 | 0.475 | 0.056 | 0.175 | 0.356 | 495 |
| gpt-4.1-mini | replicate_01 | formal_23_chain_2rep_20260612 | 69 | 0.491 | 0.277 | 0.167 | 0.335 | 373 |
| gpt-4.1-mini | replicate_02 | formal_23_chain_2rep_20260612 | 69 | 0.432 | 0.251 | 0.262 | 0.410 | 322 |
| gpt-5.4-mini | legacy_27_filtered_20260609 | formal_27_chain_20260609_filtered_to_current_23 | 69 | 0.822 | 0.790 | 0.619 | 0.563 | 90 |
| gpt-5.4-mini | replicate_01 | formal_23_chain_2rep_20260612 | 69 | 0.802 | 0.651 | 0.484 | 0.545 | 307 |
| gpt-5.4-mini | replicate_02 | formal_23_chain_2rep_20260612 | 69 | 0.769 | 0.667 | 0.556 | 0.629 | 254 |

