# GPT-5.5 Low Raw-Text Salvage Evaluation 2026-06-14

Scope: 103 valid GPT-5.5 low runs only. Three quota-failed invalid runs and missing future runs are excluded. Formal JSON/code_steps scoring remains 0 because the output contract failed; this salvage score is a separate Codex manual review of the raw natural-language output.

## Overall

| run_count | chain_count | gold_step_total | candidate_step_total | recall | precision | behavior_sequence_order |
| --- | --- | --- | --- | --- | --- | --- |
| 103 | 23 | 314 | 668 | 0.822 | 0.386 | 0.822 |

## By Stage

| stage | run_count | gold_step_total | candidate_step_total | recall | precision | behavior_sequence_order |
| --- | --- | --- | --- | --- | --- | --- |
| stage1 | 35 | 106 | 217 | 0.821 | 0.401 | 0.821 |
| stage2 | 34 | 104 | 223 | 0.837 | 0.390 | 0.837 |
| stage3 | 34 | 104 | 228 | 0.808 | 0.368 | 0.808 |

## By Framework Group

| framework_group | run_count | chain_count | gold_step_total | candidate_step_total | recall | precision | behavior_sequence_order |
| --- | --- | --- | --- | --- | --- | --- | --- |
| collection_or_tool_invocation | 24 | 5 | 75 | 162 | 0.733 | 0.340 | 0.733 |
| command_shell_execution | 9 | 2 | 21 | 66 | 0.810 | 0.258 | 0.810 |
| network_service_behavior | 52 | 13 | 104 | 306 | 0.962 | 0.327 | 0.962 |
| persistence_registry_run_key | 6 | 1 | 18 | 25 | 0.833 | 0.600 | 0.833 |
| script_execution_chain | 12 | 2 | 96 | 109 | 0.740 | 0.651 | 0.740 |
