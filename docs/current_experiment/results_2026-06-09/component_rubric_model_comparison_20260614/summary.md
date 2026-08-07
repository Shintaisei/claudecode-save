# Component-Rubric Model Comparison 2026-06-14

Primary metric definition: component rubric from the earlier Codex review flow. This is intentionally separate from the stricter behavior-plus-evidence step metric.

GPT-5.5 rows must be reported as raw-text salvage when contract=raw_text_contract_failed, because the run violated the formal JSON/code_steps output contract.

Queue status: `{"available_run_count": 483, "adopted_review_count": 483, "valid_unreviewed_count_at_last_queue_build": 0, "invalid_run_count": 0, "missing_run_count": 138}`

## Overall

| dataset_label | contract | run_count | chain_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2rep_component | formal_json_code_steps | 138 | 23 | 0.462 | 0.264 | 0.214 | 0.372 | 695 |
| gpt-4.1-mini_old_1run_component | legacy_formal27_component_review | 69 | 23 | 0.475 | 0.056 | 0.175 | 0.356 | 495 |
| gpt-5.4-mini_2rep_component | formal_json_code_steps | 138 | 23 | 0.785 | 0.659 | 0.520 | 0.587 | 561 |
| gpt-5.4-mini_old_1run_component | legacy_formal27_component_review | 69 | 23 | 0.822 | 0.790 | 0.619 | 0.563 | 90 |
| gpt-5.5_low_raw_component | raw_text_contract_failed | 207 | 23 | 0.918 | 0.906 | 0.868 | 0.640 | 1235 |

## By Stage

| dataset_label | contract | stage | run_count | action_step_recall | critical_evidence_recall | behavior_sequence_order | candidate_claim_precision | overclaim_slot_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2rep_component | formal_json_code_steps | stage1 | 46 | 0.641 | 0.354 | 0.345 | 0.452 | 232 |
| gpt-4.1-mini_2rep_component | formal_json_code_steps | stage2 | 46 | 0.392 | 0.192 | 0.131 | 0.286 | 300 |
| gpt-4.1-mini_2rep_component | formal_json_code_steps | stage3 | 46 | 0.351 | 0.246 | 0.167 | 0.383 | 163 |
| gpt-4.1-mini_old_1run_component | legacy_formal27_component_review | stage1 | 23 | 0.636 | 0.169 | 0.333 | 0.408 | 190 |
| gpt-4.1-mini_old_1run_component | legacy_formal27_component_review | stage2 | 23 | 0.456 | 0.000 | 0.071 | 0.285 | 206 |
| gpt-4.1-mini_old_1run_component | legacy_formal27_component_review | stage3 | 23 | 0.333 | 0.000 | 0.119 | 0.381 | 99 |
| gpt-5.4-mini_2rep_component | formal_json_code_steps | stage1 | 46 | 0.751 | 0.446 | 0.476 | 0.548 | 189 |
| gpt-5.4-mini_2rep_component | formal_json_code_steps | stage2 | 46 | 0.813 | 0.769 | 0.571 | 0.605 | 182 |
| gpt-5.4-mini_2rep_component | formal_json_code_steps | stage3 | 46 | 0.792 | 0.762 | 0.512 | 0.604 | 190 |
| gpt-5.4-mini_old_1run_component | legacy_formal27_component_review | stage1 | 23 | 0.872 | 0.831 | 0.786 | 0.629 | 26 |
| gpt-5.4-mini_old_1run_component | legacy_formal27_component_review | stage2 | 23 | 0.774 | 0.723 | 0.476 | 0.537 | 31 |
| gpt-5.4-mini_old_1run_component | legacy_formal27_component_review | stage3 | 23 | 0.821 | 0.815 | 0.595 | 0.522 | 33 |
| gpt-5.5_low_raw_component | raw_text_contract_failed | stage1 | 69 | 0.937 | 0.908 | 0.897 | 0.658 | 374 |
| gpt-5.5_low_raw_component | raw_text_contract_failed | stage2 | 69 | 0.915 | 0.908 | 0.857 | 0.620 | 415 |
| gpt-5.5_low_raw_component | raw_text_contract_failed | stage3 | 69 | 0.903 | 0.903 | 0.849 | 0.643 | 446 |

