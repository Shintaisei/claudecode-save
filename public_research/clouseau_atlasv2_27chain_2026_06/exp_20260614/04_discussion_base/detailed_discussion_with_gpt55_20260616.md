# Detailed Results And Discussion With GPT-5.5 2026-06-16

This document summarizes the current 23-chain experiment after adding the completed GPT-5.5 low raw result. It is intended as a paper-writing base for FIT2026. The numeric source is `results_23chain_20260614/`, especially `overall.csv`, `by_stage.csv`, `by_scenario_group.csv`, `by_framework_group.csv`, and `ledgers/final_comparison_per_run_component_scores.csv`.

## Scope

| model | scored rows | chain count | stage count | set count | treatment |
| --- | ---: | ---: | ---: | ---: | --- |
| gpt-4.1-mini | 207 | 23 | 3 | 3 | formal23 rep1 + formal23 rep2 + legacy27 filtered to current 23 |
| gpt-5.4-mini | 207 | 23 | 3 | 3 | formal23 rep1 + formal23 rep2 + legacy27 filtered to current 23 |
| gpt-5.5 low raw | 207 | 23 | 3 | 3 | raw-output salvage; output contract failed |

The main comparison uses the component rubric: action component recall, critical evidence recall, behavior sequence order, candidate claim precision, and overclaim count. GPT-5.5 must be reported as a raw-output salvage result because it did not comply with the formal JSON/code_steps output contract. Its substantive reconstruction accuracy is still informative, but it is not contract-equivalent to the structured gpt-4.1-mini and gpt-5.4-mini outputs.

## Headline Result

| model | runs | action recall | evidence recall | order | precision | overclaims |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 207 | 0.466 | 0.195 | 0.201 | 0.366 | 1190 |
| gpt-5.4-mini | 207 | 0.798 | 0.703 | 0.553 | 0.584 | 651 |
| gpt-5.5 low raw | 207 | 0.918 | 0.906 | 0.868 | 0.640 | 1235 |

The main result is that gpt-5.4-mini substantially improves over gpt-4.1-mini across all reconstruction metrics while reducing overclaims. GPT-5.5 low raw further improves recall and ordering, but it also increases total overclaims and failed the required structured-output contract. Therefore, GPT-5.5 should be framed as evidence of high latent reconstruction ability under raw-text salvage, not as the best deployable configuration for this pipeline.

The strongest publishable comparison is gpt-5.4-mini versus gpt-4.1-mini: evidence recall rises from 0.195 to 0.703, order rises from 0.201 to 0.553, and overclaims fall from 1190 to 651. This suggests that the model upgrade improves both evidence grounding and sequence reconstruction, not merely verbosity.

## Stage Effects

| model | stage | runs | action recall | evidence recall | order | precision | overclaims |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | stage1 | 69 | 0.639 | 0.292 | 0.341 | 0.433 | 422 |
| gpt-4.1-mini | stage2 | 69 | 0.414 | 0.128 | 0.111 | 0.285 | 506 |
| gpt-4.1-mini | stage3 | 69 | 0.345 | 0.164 | 0.151 | 0.382 | 262 |
| gpt-5.4-mini | stage1 | 69 | 0.791 | 0.574 | 0.579 | 0.559 | 215 |
| gpt-5.4-mini | stage2 | 69 | 0.800 | 0.754 | 0.540 | 0.597 | 213 |
| gpt-5.4-mini | stage3 | 69 | 0.802 | 0.779 | 0.540 | 0.594 | 223 |
| gpt-5.5 low raw | stage1 | 69 | 0.937 | 0.908 | 0.897 | 0.658 | 374 |
| gpt-5.5 low raw | stage2 | 69 | 0.915 | 0.908 | 0.857 | 0.620 | 415 |
| gpt-5.5 low raw | stage3 | 69 | 0.903 | 0.903 | 0.849 | 0.643 | 446 |

The stage result is important because stage3 hides CBC alert-summary rows from SQL retrieval while retaining CBC EDR/NGAV telemetry. gpt-5.4-mini does not collapse in stage3; in fact, its evidence recall is highest in stage3 at 0.779. This supports the claim that the reconstruction can be driven by non-alert telemetry rather than only by copying the alert summary.

For gpt-4.1-mini, stage1 is clearly easier than stage2 and stage3. It benefits from explicit alert-assisted cues, but struggles when it must recover the behavior from process-time context and database evidence. For GPT-5.5, stage differences are small: recall stays above 0.90 in all stages. The main stage-related weakness for GPT-5.5 is not recall but precision: stage2 precision is 0.620 and stage3 precision is 0.643, with overclaims increasing to 446 in stage3.

The careful interpretation is: stage3 is not inherently impossible after alert-summary removal, but stronger models are needed to reconstruct from remaining telemetry. This should not be phrased as "alerts are unnecessary"; rather, it shows that alert summaries are not the only recoverable evidence path in this dataset.

## Scenario Effects

| model | scenario group | runs | chains | action recall | evidence recall | order | precision | overclaims |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | explicit_execution_chain | 135 | 15 | 0.501 | 0.237 | 0.243 | 0.351 | 734 |
| gpt-4.1-mini | multi_step_tool_chain | 63 | 7 | 0.428 | 0.158 | 0.176 | 0.382 | 416 |
| gpt-4.1-mini | semantic_interpretation_chain | 9 | 1 | 0.506 | 0.148 | 0.167 | 0.444 | 40 |
| gpt-5.4-mini | explicit_execution_chain | 135 | 15 | 0.865 | 0.824 | 0.764 | 0.640 | 345 |
| gpt-5.4-mini | multi_step_tool_chain | 63 | 7 | 0.746 | 0.602 | 0.431 | 0.469 | 288 |
| gpt-5.4-mini | semantic_interpretation_chain | 9 | 1 | 0.642 | 0.481 | 0.333 | 0.719 | 18 |
| gpt-5.5 low raw | explicit_execution_chain | 135 | 15 | 0.978 | 0.975 | 0.972 | 0.609 | 787 |
| gpt-5.5 low raw | multi_step_tool_chain | 63 | 7 | 0.851 | 0.839 | 0.796 | 0.673 | 421 |
| gpt-5.5 low raw | semantic_interpretation_chain | 9 | 1 | 0.988 | 0.889 | 0.889 | 0.802 | 27 |

Explicit execution chains are the most favorable setting for stronger models. gpt-5.4-mini reaches evidence recall 0.824 and GPT-5.5 reaches 0.975. These cases typically contain direct process names, command lines, network connections, or registry operations that can be matched to the gold behavior.

Multi-step tool chains are harder. They combine multiple processes or tools, so the model may recover individual events while losing order or adding nearby but non-gold evidence. This is visible in gpt-5.4-mini: action recall is 0.746, but order is only 0.431 and precision is 0.469. GPT-5.5 improves the same group to action 0.851, evidence 0.839, and order 0.796, but still produces 421 overclaims.

The semantic interpretation group is the Discord Run key case only. Its n is small, so it should be treated as a case study rather than a general category-level conclusion. GPT-5.5 performs well on it, but the paper should not overgeneralize from one chain.

## Framework-Level Observations

This table is the full framework grouping in `by_framework_group.csv` for the accepted 23-chain scope. The category sizes are uneven: `network_service_behavior` has 13 chains, `collection_or_tool_invocation` has 5 chains, `command_shell_execution` and `script_execution_chain` have 2 chains each, and `persistence_registry_run_key` has only 1 chain. Therefore, framework-level claims should rely mainly on the larger groups; the 1-2 chain groups are useful as concrete cases, not broad category estimates.

| model | framework group | runs | chains | action recall | evidence recall | order | precision | overclaims |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | collection_or_tool_invocation | 45 | 5 | 0.469 | 0.207 | 0.211 | 0.317 | 341 |
| gpt-4.1-mini | command_shell_execution | 18 | 2 | 0.437 | 0.133 | 0.148 | 0.326 | 124 |
| gpt-4.1-mini | network_service_behavior | 117 | 13 | 0.513 | 0.256 | 0.265 | 0.356 | 610 |
| gpt-4.1-mini | persistence_registry_run_key | 9 | 1 | 0.506 | 0.148 | 0.167 | 0.444 | 40 |
| gpt-4.1-mini | script_execution_chain | 18 | 2 | 0.389 | 0.111 | 0.151 | 0.569 | 75 |
| gpt-5.4-mini | collection_or_tool_invocation | 45 | 5 | 0.778 | 0.585 | 0.556 | 0.397 | 232 |
| gpt-5.4-mini | command_shell_execution | 18 | 2 | 0.763 | 0.733 | 0.593 | 0.429 | 93 |
| gpt-5.4-mini | network_service_behavior | 117 | 13 | 0.885 | 0.842 | 0.803 | 0.683 | 252 |
| gpt-5.4-mini | persistence_registry_run_key | 9 | 1 | 0.642 | 0.481 | 0.333 | 0.719 | 18 |
| gpt-5.4-mini | script_execution_chain | 18 | 2 | 0.715 | 0.618 | 0.341 | 0.643 | 56 |
| gpt-5.5 low raw | collection_or_tool_invocation | 45 | 5 | 0.911 | 0.904 | 0.900 | 0.583 | 366 |
| gpt-5.5 low raw | command_shell_execution | 18 | 2 | 0.889 | 0.889 | 0.889 | 0.490 | 193 |
| gpt-5.5 low raw | network_service_behavior | 117 | 13 | 0.996 | 0.991 | 0.991 | 0.634 | 594 |
| gpt-5.5 low raw | persistence_registry_run_key | 9 | 1 | 0.988 | 0.889 | 0.889 | 0.802 | 27 |
| gpt-5.5 low raw | script_execution_chain | 18 | 2 | 0.794 | 0.778 | 0.722 | 0.854 | 55 |

Network service behavior is the clearest success area. The recurring Python SimpleHTTPServer chains give direct evidence through command lines and network connections, and both gpt-5.4-mini and GPT-5.5 recover them strongly. GPT-5.5 nearly saturates recall and order in this group, but its precision remains lower than the recall metrics because it often adds surrounding context or extra causal claims.

Collection/tool invocation is harder than network service behavior because DNS/tshark/batch execution often creates nearby tool, shell, and file evidence. Models may identify the broad behavior while including extra process or log details that are not part of the gold chain.

The smaller framework groups should be used carefully. Script execution chains show a different pattern: GPT-5.5 has high precision at 0.854 but lower recall than its network-service performance. This suggests that when GPT-5.5 recognizes the Sublime/cmd/python/script structure, it tends to state fewer unsupported claims, but it still misses some components or evidence in the longer execution chain. However, this group has only 2 chains. The command-shell group also has only 2 chains and shows a GPT-5.5 precision weakness at 0.490 with 193 overclaims. The persistence registry result is one Discord Run key chain, so it should be described as a case example rather than a stable framework-level effect.

## Replicate And Model Variability

| model | replicate/source set | action | evidence | order | precision | overclaims |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | legacy_27_filtered_20260609 | 0.475 | 0.056 | 0.175 | 0.356 | 495 |
| gpt-4.1-mini | replicate_01 | 0.491 | 0.277 | 0.167 | 0.335 | 373 |
| gpt-4.1-mini | replicate_02 | 0.432 | 0.251 | 0.262 | 0.410 | 322 |
| gpt-5.4-mini | legacy_27_filtered_20260609 | 0.822 | 0.790 | 0.619 | 0.563 | 90 |
| gpt-5.4-mini | replicate_01 | 0.802 | 0.651 | 0.484 | 0.545 | 307 |
| gpt-5.4-mini | replicate_02 | 0.769 | 0.667 | 0.556 | 0.629 | 254 |
| gpt-5.5 low raw | replicate_01 | 0.940 | 0.928 | 0.889 | 0.667 | 350 |
| gpt-5.5 low raw | replicate_02 | 0.904 | 0.892 | 0.865 | 0.785 | 173 |
| gpt-5.5 low raw | replicate_03 | 0.909 | 0.897 | 0.849 | 0.537 | 712 |

The GPT-5.5 three-run block is now complete. Its recall and order are stable across replicates: action/evidence/order standard deviations are all about 0.016. Precision is less stable, with standard deviation about 0.102. This means GPT-5.5 consistently recovers the correct behavior, but the amount of extra unsupported or outside-gold output varies substantially by run.

For gpt-4.1-mini and gpt-5.4-mini, the third set is not a same-condition formal23 replicate; it is the legacy 27-chain run filtered to the current 23-chain scope. Those rows are useful for increasing coverage, but source-set effects should be acknowledged. The cleanest same-condition comparison for exact repeatability remains the formal23 replicate_01 and replicate_02 subset.

## GPT-5.5 Chain-Level Detail

| chain | type | runs | action | evidence | order | precision | overclaims | interpretation |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| chain_01 | DNS packet capture | 9 | 0.605 | 0.593 | 0.556 | 0.617 | 58 | Hardest GPT-5.5 chain; batch/tshark evidence is recovered inconsistently. |
| chain_07 | Sublime Python script | 9 | 0.726 | 0.700 | 0.654 | 0.870 | 30 | Conservative output, but misses parts of the long multi-process chain. |
| chain_10 | Discord Run key | 9 | 0.988 | 0.889 | 0.889 | 0.802 | 27 | Strong recovery of registry persistence semantics, but still not perfect on evidence/order. |
| chain_19 | SimpleHTTPServer | 9 | 1.000 | 1.000 | 1.000 | 0.461 | 134 | Perfect recall with many extra claims; good example of recall-precision tradeoff. |
| chain_24 | cmd/bat/python chain | 9 | 0.889 | 0.889 | 0.889 | 0.482 | 153 | High overclaim case; extra shell/batch context expands the candidate denominator. |
| chain_26 | SimpleHTTPServer | 9 | 1.000 | 1.000 | 1.000 | 0.468 | 122 | Perfect behavior/evidence recovery but verbose or over-broad candidate claims. |

The GPT-5.5 chain-level pattern is clear: recall failures are concentrated in complex tool-chain reconstruction, while precision failures also occur in otherwise easy network-service cases. In other words, GPT-5.5 is often right about the core behavior, but it is not disciplined about limiting the answer to the gold chain.

This distinction is valuable for the paper. It allows the result to be stated as: stronger models can recover latent behavior from telemetry, but output control remains a separate problem. A high-recall model still needs structure, evidence gating, or post-processing to avoid overclaiming.

## Cost And Runtime Interpretation

The gpt-4.1-mini and gpt-5.4-mini cost estimates are sourced from `clouseau_api_costs.csv` through the local cost-effectiveness aggregation in `exp_20260614/04_discussion_base/deep_dive_20260614/cost_effectiveness_by_model.csv`; those rows are marked `logged+local_price_estimate`. The GPT-5.5 cost estimate is sourced separately from `results_23chain_20260614/openai_cost_audit_note_20260614.md` and `data/current_experiment/scores/formal_23_chain_gpt55_low_3rep_20260613/progress.json`, because the local API ledger recorded GPT-5.5 `call_total_usd` as zero.

| model | runs | total cost estimate | avg/run | cost source | action hits | evidence hits | order hits | precision hits |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 207 | $3.64 | $0.0176 | logged+local price estimate | 818 | 114 | 76 | 686 |
| gpt-5.4-mini | 207 | $4.35 | $0.0210 | logged+local price estimate | 1400 | 411 | 209 | 914 |
| gpt-5.5 low raw | 207 | $93.52 | $0.4518 | progress-side reconstructed estimate | 1611 | 530 | 328 | 2891 |

| model | cost/action hit | cost/evidence hit | cost/order hit | cost/precision hit |
| --- | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | $0.0045 | $0.0320 | $0.0479 | $0.0053 |
| gpt-5.4-mini | $0.0031 | $0.0106 | $0.0208 | $0.0048 |
| gpt-5.5 low raw | $0.0580 | $0.1764 | $0.2851 | $0.0323 |

The cost conclusion is different from the raw accuracy conclusion. gpt-5.4-mini is the best cost-performance point in this experiment: it greatly improves accuracy over gpt-4.1-mini with only a small increase in estimated total cost. GPT-5.5 gives the highest recall, but at far higher cost per recovered component.

The GPT-5.5 cost estimate should be treated as reconstructed rather than ledger-authoritative because the local `clouseau_api_costs.csv` recorded GPT-5.5 `call_total_usd` as zero. The token log still shows 207 GPT-5.5 rows with 5,555,335 input tokens and 2,191,309 output tokens, and the progress-side conservative completed-cost estimate is $93.52. The paper should report this as an estimate and avoid claiming exact billing precision.

## Recommended Paper Claims

1. In this 23-chain experiment, gpt-5.4-mini provides a strong accuracy and cost-performance improvement over gpt-4.1-mini.
2. GPT-5.5 low raw shows the highest substantive reconstruction ability, especially for recall and ordering, but failed the structured-output contract and produced many overclaims.
3. Stage3 performance indicates that alert summaries are not the only path to reconstruction; non-alert CBC telemetry can support behavior recovery when the model is strong enough.
4. Scenario difficulty is not uniform. Explicit execution chains are easiest, multi-step tool chains are harder, and semantic/persistence results should be treated as a case study because they contain only one chain.
5. The main remaining engineering problem is not only better reasoning, but answer discipline: constraining the model to report only supported behavior/evidence steps.

## Claims To Avoid

- Do not say GPT-5.5 is strictly the best model for the pipeline. It has the best raw reconstruction scores, but it failed the output contract and is expensive.
- Do not say alert summaries are unnecessary. The correct claim is that stage3 remains answerable in this dataset using non-alert telemetry.
- Do not present semantic_interpretation_chain as a broad category result. It is one Discord Run key chain.
- Do not describe the 4.1/5.4 third set as a generated formal23 replicate. It is legacy27 filtered to the current 23-chain scope.
- Do not claim the GPT-5.5 dollar cost is exact billing. It is a reconstructed estimate based on token logs and conservative pricing.

## Review Gate Status

This draft must pass two independent Codex reviews before being treated as the accepted discussion base. Reviewer outputs and the final adoption note should be stored in this directory.
