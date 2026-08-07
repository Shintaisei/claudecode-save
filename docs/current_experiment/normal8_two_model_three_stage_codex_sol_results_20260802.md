# Normal8 two-model, three-stage Codex formal score (2026-08-02)

48/48 runs were scored locally under the v5 atomic process-chain rubric. Full retry audit and cross-field consistency are PASS. OpenAI judge API/API scorer calls: 0.

## Overall

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| all 48 runs | 48 | 36.23% | 42.37% | 15.22% | 6.52% | 25.56% |

## By model

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 24 | 51.21% | 44.35% | 24.64% | 1.45% | 42.22% |
| gpt-5.4-mini | 24 | 21.26% | 38.26% | 5.80% | 11.59% | 8.89% |

## By stage

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| stage1 | 16 | 38.41% | 45.69% | 17.39% | 4.35% | 26.67% |
| stage2 | 16 | 34.06% | 38.21% | 8.70% | 6.52% | 23.33% |
| stage3 | 16 | 36.23% | 43.48% | 19.57% | 8.70% | 26.67% |

## By model and stage

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini/stage1 | 8 | 53.62% | 43.02% | 21.74% | 4.35% | 46.67% |
| gpt-4.1-mini/stage2 | 8 | 44.93% | 39.24% | 13.04% | 0.00% | 33.33% |
| gpt-4.1-mini/stage3 | 8 | 55.07% | 51.35% | 39.13% | 0.00% | 46.67% |
| gpt-5.4-mini/stage1 | 8 | 23.19% | 53.33% | 13.04% | 4.35% | 6.67% |
| gpt-5.4-mini/stage2 | 8 | 23.19% | 36.36% | 4.35% | 13.04% | 13.33% |
| gpt-5.4-mini/stage3 | 8 | 17.39% | 29.27% | 0.00% | 17.39% | 6.67% |

## By use case

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| chain_02_e01_python_simplehttpserver_network_chain | 6 | 37.04% | 51.28% | 22.22% | 5.56% | 16.67% |
| chain_04_e03_dns_packet_capture_batch_chain | 6 | 24.60% | 70.45% | 14.29% | 4.76% | 11.11% |
| chain_05_e03_python_simplehttpserver_network_chain | 6 | 55.56% | 47.62% | 16.67% | 25.00% | 100.00% |
| chain_06_e04_python_simplehttpserver_network_chain | 6 | 33.33% | 13.64% | 0.00% | 0.00% | n/a |
| chain_09_e07_cmdexe_other_chain | 6 | 55.56% | 15.87% | 16.67% | 33.33% | n/a |
| chain_10_e07_discord_run_key_registry_chain | 6 | 52.78% | 42.22% | 8.33% | 0.00% | 50.00% |
| chain_11_e07_sublime_python_script_execution_chain | 6 | 40.74% | 50.00% | 16.67% | 5.56% | 33.33% |
| chain_24_e18_cmdexe_other_chain | 6 | 30.56% | 66.67% | 16.67% | 0.00% | 22.22% |

## Investigation behavior

Chief leads 447 (unique 381, 85.23%); investigator questions 1,556 (unique 1,549); SQL queries 2,395 (unique 2,370). Total tokens 20,545,933, cost $6.764427, elapsed 18359.845s. Mean/run: 428,040.3 tokens, $0.140926, 382.497s.

## Error diagnostics

Missing-step reasons: `{"no_aligned_candidate_claim": 64, "partial_atomic_component_recovery": 53}`. Missing atomic components: `{"object": 104, "operation": 77, "subject": 83}`. Unaligned candidate claims: 22; overconnection slots: 63; hallucination-like unsupported/corrupted slots: 1. FP types: `{"duplicate": 28, "unsupported": 1, "wrong_component": 63, "wrong_relation": 20, "wrong_value": 92}`.

## Formal integrity

Gold subject/operation/object hits are derived only from unique included literal-TP `matched_gold_item_id` coverage. Behavior steps require all three components. Critical evidence and adjacent order pairs are separate diagnostics. PID identity and hidden-alert mapping are not scored; `action` is normalized to `operation`. Every run/case/Gold hash, Gold item, fixed candidate slot, order pair, and denominator is retained in `scores_codex_sol_v1/formal_scores.jsonl` and the provenance manifest. Cross-field validation: PASS (0 failures).
