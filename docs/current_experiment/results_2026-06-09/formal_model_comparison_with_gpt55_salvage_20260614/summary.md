# Formal Model Comparison With GPT-5.5 Salvage 2026-06-14

All score rows are Codex-reviewed. Strict-json rows use two accepted reviews. GPT-5.5 salvage rows use two independent Codex reviews; disagreements are accepted only after conservative adjudication using max(candidate_step_count) and min(hit counts).

GPT-5.5 strict-json scoring remains a format-failure baseline because the runs did not emit formal JSON/code_steps. GPT-5.5 salvage is a separate raw-text evaluation and should be reported separately from strict-json scores.

## Full Available Runs

| dataset_label | scoring_mode | run_count | chain_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order | adjudicated_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2rep_strict | strict_json | 138 | 23 | 390 | 369 | 0.123 | 0.130 | 0.126 | 0.121 | 0 |
| gpt-5.4-mini_2rep_strict | strict_json | 138 | 23 | 390 | 410 | 0.313 | 0.298 | 0.305 | 0.313 | 0 |
| gpt-5.5_low_103run_salvage | raw_text_salvage | 103 | 23 | 314 | 668 | 0.822 | 0.386 | 0.525 | 0.822 | 83 |
| gpt-5.5_low_103run_strict_json | strict_json_format_failed | 103 | 23 | 314 | 0 | 0.000 | NA | NA | 0.000 | 0 |

## Replicate 1 Comparable Block

| dataset_label | scoring_mode | run_count | chain_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order | adjudicated_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_rep1_strict | strict_json | 69 | 23 | 195 | 187 | 0.179 | 0.187 | 0.183 | 0.174 | 0 |
| gpt-5.4-mini_rep1_strict | strict_json | 69 | 23 | 195 | 222 | 0.333 | 0.293 | 0.312 | 0.333 | 0 |
| gpt-5.5_low_rep1_salvage | raw_text_salvage | 69 | 23 | 195 | 443 | 0.810 | 0.357 | 0.495 | 0.810 | 55 |
| gpt-5.5_low_rep1_strict_json | strict_json_format_failed | 69 | 23 | 195 | 0 | 0.000 | NA | NA | 0.000 | 0 |

## Full Available By Stage

| dataset_label | stage | stage_label | run_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order | adjudicated_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2rep_strict | stage1 | alert_clue | 46 | 130 | 141 | 0.169 | 0.156 | 0.162 | 0.162 | 0 |
| gpt-4.1-mini_2rep_strict | stage2 | process_time_clue | 46 | 130 | 140 | 0.092 | 0.086 | 0.089 | 0.092 | 0 |
| gpt-4.1-mini_2rep_strict | stage3 | non_alert_telemetry_only | 46 | 130 | 88 | 0.108 | 0.159 | 0.128 | 0.108 | 0 |
| gpt-5.4-mini_2rep_strict | stage1 | alert_clue | 46 | 130 | 124 | 0.185 | 0.194 | 0.189 | 0.185 | 0 |
| gpt-5.4-mini_2rep_strict | stage2 | process_time_clue | 46 | 130 | 137 | 0.385 | 0.365 | 0.375 | 0.385 | 0 |
| gpt-5.4-mini_2rep_strict | stage3 | non_alert_telemetry_only | 46 | 130 | 149 | 0.369 | 0.322 | 0.344 | 0.369 | 0 |
| gpt-5.5_low_103run_salvage | stage1 | alert_clue | 35 | 106 | 217 | 0.821 | 0.401 | 0.539 | 0.821 | 26 |
| gpt-5.5_low_103run_salvage | stage2 | process_time_clue | 34 | 104 | 223 | 0.837 | 0.390 | 0.532 | 0.837 | 28 |
| gpt-5.5_low_103run_salvage | stage3 | non_alert_telemetry_only | 34 | 104 | 228 | 0.808 | 0.368 | 0.506 | 0.808 | 29 |
| gpt-5.5_low_103run_strict_json | stage1 | alert_clue | 35 | 106 | 0 | 0.000 | NA | NA | 0.000 | 0 |
| gpt-5.5_low_103run_strict_json | stage2 | process_time_clue | 34 | 104 | 0 | 0.000 | NA | NA | 0.000 | 0 |
| gpt-5.5_low_103run_strict_json | stage3 | non_alert_telemetry_only | 34 | 104 | 0 | 0.000 | NA | NA | 0.000 | 0 |

## Full Available By Framework Group

| dataset_label | framework_group | run_count | chain_count | gold_step_total | candidate_step_total | recall | precision | f1 | behavior_sequence_order | adjudicated_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4.1-mini_2rep_strict | collection_or_tool_invocation | 30 | 5 | 90 | 86 | 0.044 | 0.047 | 0.045 | 0.044 | 0 |
| gpt-4.1-mini_2rep_strict | command_shell_execution | 12 | 2 | 30 | 32 | 0.000 | 0.000 | 0.000 | 0.000 | 0 |
| gpt-4.1-mini_2rep_strict | network_service_behavior | 78 | 13 | 156 | 208 | 0.244 | 0.183 | 0.209 | 0.244 | 0 |
| gpt-4.1-mini_2rep_strict | persistence_registry_run_key | 6 | 1 | 18 | 12 | 0.000 | 0.000 | 0.000 | 0.000 | 0 |
| gpt-4.1-mini_2rep_strict | script_execution_chain | 12 | 2 | 96 | 31 | 0.062 | 0.194 | 0.094 | 0.052 | 0 |
| gpt-5.4-mini_2rep_strict | collection_or_tool_invocation | 30 | 5 | 90 | 99 | 0.089 | 0.081 | 0.085 | 0.089 | 0 |
| gpt-5.4-mini_2rep_strict | command_shell_execution | 12 | 2 | 30 | 42 | 0.367 | 0.262 | 0.306 | 0.367 | 0 |
| gpt-5.4-mini_2rep_strict | network_service_behavior | 78 | 13 | 156 | 215 | 0.571 | 0.414 | 0.480 | 0.571 | 0 |
| gpt-5.4-mini_2rep_strict | persistence_registry_run_key | 6 | 1 | 18 | 16 | 0.278 | 0.312 | 0.294 | 0.278 | 0 |
| gpt-5.4-mini_2rep_strict | script_execution_chain | 12 | 2 | 96 | 38 | 0.094 | 0.237 | 0.134 | 0.094 | 0 |
| gpt-5.5_low_103run_salvage | collection_or_tool_invocation | 24 | 5 | 75 | 162 | 0.733 | 0.340 | 0.464 | 0.733 | 14 |
| gpt-5.5_low_103run_salvage | command_shell_execution | 9 | 2 | 21 | 66 | 0.810 | 0.258 | 0.391 | 0.810 | 7 |
| gpt-5.5_low_103run_salvage | network_service_behavior | 52 | 13 | 104 | 306 | 0.962 | 0.327 | 0.488 | 0.962 | 49 |
| gpt-5.5_low_103run_salvage | persistence_registry_run_key | 6 | 1 | 18 | 25 | 0.833 | 0.600 | 0.698 | 0.833 | 5 |
| gpt-5.5_low_103run_salvage | script_execution_chain | 12 | 2 | 96 | 109 | 0.740 | 0.651 | 0.693 | 0.740 | 8 |
| gpt-5.5_low_103run_strict_json | collection_or_tool_invocation | 24 | 5 | 75 | 0 | 0.000 | NA | NA | 0.000 | 0 |
| gpt-5.5_low_103run_strict_json | command_shell_execution | 9 | 2 | 21 | 0 | 0.000 | NA | NA | 0.000 | 0 |
| gpt-5.5_low_103run_strict_json | network_service_behavior | 52 | 13 | 104 | 0 | 0.000 | NA | NA | 0.000 | 0 |
| gpt-5.5_low_103run_strict_json | persistence_registry_run_key | 6 | 1 | 18 | 0 | 0.000 | NA | NA | 0.000 | 0 |
| gpt-5.5_low_103run_strict_json | script_execution_chain | 12 | 2 | 96 | 0 | 0.000 | NA | NA | 0.000 | 0 |
