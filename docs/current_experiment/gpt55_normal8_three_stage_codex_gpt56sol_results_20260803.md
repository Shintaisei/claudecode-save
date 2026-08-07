# GPT-5.5 normal8 three-stage independent Codex review (2026-08-03)

Headline: **24/24 runs scored**. Retry disposition: **PASS**. Missing: なし（retry PASSを正式採用）. Independent reviewer: Codex gpt-5.6-sol. Judge API/API scorer calls: 0.

## GPT-5.5 overall

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| gpt-5.5 | 24 | 78.74% | 42.12% | 55.07% | 76.81% | 84.44% |

## Three-model comparison

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 24 | 51.21% | 44.35% | 24.64% | 1.45% | 42.22% |
| gpt-5.4-mini | 24 | 21.26% | 38.26% | 5.80% | 11.59% | 8.89% |
| gpt-5.5 | 24 | 78.74% | 42.12% | 55.07% | 76.81% | 84.44% |

## GPT-5.5 by Stage

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| stage1 | 8 | 73.91% | 36.17% | 43.48% | 69.57% | 86.67% |
| stage2 | 8 | 84.06% | 42.96% | 60.87% | 82.61% | 86.67% |
| stage3 | 8 | 78.26% | 48.65% | 60.87% | 78.26% | 80.00% |

## GPT-5.5 by use case

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| chain_02_e01_python_simplehttpserver_network_chain | 3 | 92.59% | 75.76% | 77.78% | 77.78% | 100.00% |
| chain_04_e03_dns_packet_capture_batch_chain | 3 | 61.90% | 72.22% | 33.33% | 61.90% | 66.67% |
| chain_05_e03_python_simplehttpserver_network_chain | 3 | 83.33% | 38.46% | 50.00% | 100.00% | 100.00% |
| chain_06_e04_python_simplehttpserver_network_chain | 3 | 66.67% | 14.29% | 0.00% | 100.00% | n/a |
| chain_09_e07_cmdexe_other_chain | 3 | 88.89% | 13.33% | 66.67% | 100.00% | n/a |
| chain_10_e07_discord_run_key_registry_chain | 3 | 83.33% | 21.74% | 83.33% | 66.67% | 66.67% |
| chain_11_e07_sublime_python_script_execution_chain | 3 | 85.19% | 58.97% | 66.67% | 66.67% | 100.00% |
| chain_24_e18_cmdexe_other_chain | 3 | 88.89% | 62.75% | 66.67% | 91.67% | 100.00% |

## Investigation behavior

Chief leads 122 (unique 120, 98.36%); investigator questions 233 (unique 233); SQL queries 755 (unique 755). Total 12,846,524 tokens, $73.158927, 16893.782s; mean/run 535,271.8 tokens, $3.048289, 703.908s.

## Error diagnostics

FP types: `{"duplicate": 48, "unsupported": 4, "wrong_component": 65, "wrong_relation": 29, "wrong_value": 78}`. Unaligned/overconnection slots: 65. Hallucination-like unsupported slots: 4. Missing Gold-step reasons: `{"partial_atomic_component_recovery": 26, "no_aligned_candidate_claim": 5}`.

## Formal integrity

All run/audit/Gold hashes, every Gold item, frozen candidate slot, adjacent order pair, and fixed denominator are recorded. Gold subject/operation/object hits are derived only from unique included literal-TP `matched_gold_item_id` coverage; a behavior step requires all three. Critical evidence is separate. PID identity and hidden alert mapping are not scored. Cross-field validation: PASS, 0 failures.

## Formal contract append proposal

No existing contract was edited. The proposed append records the independent reviewer, v5 rubric, retry inclusion/censoring rule, retry disposition, headline run count, missing-cell policy, and versioned score root. Machine-readable proposal: `scores_codex_gpt56sol_v1/formal_contract_append_proposal.json`.
