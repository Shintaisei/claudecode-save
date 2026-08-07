# Formal Model Comparison 2026-06-14

Scope: complete comparable blocks only. gpt-4.1-mini and gpt-5.4-mini use two complete replicates; gpt-5.5 uses the first complete low-reasoning replicate. Partial gpt-5.5 replicate_02 rows are excluded from headline comparison.

Metric unit: behavior_plus_evidence_step. Recall denominator is gold steps; precision denominator is candidate steps; sequence-order denominator is gold steps.

## Overall

| dataset_label | run_count | chain_count | evaluable_chain_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2complete_reps | 138 | 23 | 23 | 390 | 369 | 0.123 | 0.130 | 0.126 | 0.121 |
| gpt-5.4-mini_2complete_reps | 138 | 23 | 23 | 390 | 410 | 0.313 | 0.298 | 0.305 | 0.313 |
| gpt-5.5_low_1complete_rep | 69 | 23 | 23 | 195 | 0 | 0.000 | NA | NA | 0.000 |

## By Stage

| dataset_label | stage | stage_label | run_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2complete_reps | stage1 | alert_clue | 46 | 130 | 141 | 0.169 | 0.156 | 0.162 | 0.162 |
| gpt-4.1-mini_2complete_reps | stage2 | process_time_clue | 46 | 130 | 140 | 0.092 | 0.086 | 0.089 | 0.092 |
| gpt-4.1-mini_2complete_reps | stage3 | non_alert_telemetry_only | 46 | 130 | 88 | 0.108 | 0.159 | 0.128 | 0.108 |
| gpt-5.4-mini_2complete_reps | stage1 | alert_clue | 46 | 130 | 124 | 0.185 | 0.194 | 0.189 | 0.185 |
| gpt-5.4-mini_2complete_reps | stage2 | process_time_clue | 46 | 130 | 137 | 0.385 | 0.365 | 0.375 | 0.385 |
| gpt-5.4-mini_2complete_reps | stage3 | non_alert_telemetry_only | 46 | 130 | 149 | 0.369 | 0.322 | 0.344 | 0.369 |
| gpt-5.5_low_1complete_rep | stage1 | alert_clue | 23 | 65 | 0 | 0.000 | NA | NA | 0.000 |
| gpt-5.5_low_1complete_rep | stage2 | process_time_clue | 23 | 65 | 0 | 0.000 | NA | NA | 0.000 |
| gpt-5.5_low_1complete_rep | stage3 | non_alert_telemetry_only | 23 | 65 | 0 | 0.000 | NA | NA | 0.000 |

## By Security Framework Group

| dataset_label | framework_group | run_count | chain_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2complete_reps | collection_or_tool_invocation | 30 | 5 | 90 | 86 | 0.044 | 0.047 | 0.045 | 0.044 |
| gpt-4.1-mini_2complete_reps | command_shell_execution | 12 | 2 | 30 | 32 | 0.000 | 0.000 | 0.000 | 0.000 |
| gpt-4.1-mini_2complete_reps | network_service_behavior | 78 | 13 | 156 | 208 | 0.244 | 0.183 | 0.209 | 0.244 |
| gpt-4.1-mini_2complete_reps | persistence_registry_run_key | 6 | 1 | 18 | 12 | 0.000 | 0.000 | 0.000 | 0.000 |
| gpt-4.1-mini_2complete_reps | script_execution_chain | 12 | 2 | 96 | 31 | 0.062 | 0.194 | 0.094 | 0.052 |
| gpt-5.4-mini_2complete_reps | collection_or_tool_invocation | 30 | 5 | 90 | 99 | 0.089 | 0.081 | 0.085 | 0.089 |
| gpt-5.4-mini_2complete_reps | command_shell_execution | 12 | 2 | 30 | 42 | 0.367 | 0.262 | 0.306 | 0.367 |
| gpt-5.4-mini_2complete_reps | network_service_behavior | 78 | 13 | 156 | 215 | 0.571 | 0.414 | 0.480 | 0.571 |
| gpt-5.4-mini_2complete_reps | persistence_registry_run_key | 6 | 1 | 18 | 16 | 0.278 | 0.312 | 0.294 | 0.278 |
| gpt-5.4-mini_2complete_reps | script_execution_chain | 12 | 2 | 96 | 38 | 0.094 | 0.237 | 0.134 | 0.094 |
| gpt-5.5_low_1complete_rep | collection_or_tool_invocation | 15 | 5 | 45 | 0 | 0.000 | NA | NA | 0.000 |
| gpt-5.5_low_1complete_rep | command_shell_execution | 6 | 2 | 15 | 0 | 0.000 | NA | NA | 0.000 |
| gpt-5.5_low_1complete_rep | network_service_behavior | 39 | 13 | 78 | 0 | 0.000 | NA | NA | 0.000 |
| gpt-5.5_low_1complete_rep | persistence_registry_run_key | 3 | 1 | 9 | 0 | 0.000 | NA | NA | 0.000 |
| gpt-5.5_low_1complete_rep | script_execution_chain | 6 | 2 | 48 | 0 | 0.000 | NA | NA | 0.000 |

