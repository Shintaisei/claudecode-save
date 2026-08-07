# Normal8 mini-model replicate 02/03 Codex formal score (2026-08-06)

96/96 normal runs were source-audit PASS and scored locally under the same v5 atomic process-chain rubric as replicate 01. OpenAI judge API/API scorer calls: 0. Cross-field deterministic audit: PASS.

## Overall

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| all 96 runs | 96 | 37.92% | 41.05% | 18.48% | 5.07% | 26.67% | $13.712557 | 717.91 min |

## By replicate

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| replicate_02 | 48 | 37.20% | 39.09% | 16.67% | 5.07% | 23.33% | $6.824179 | 339.69 min |
| replicate_03 | 48 | 38.65% | 43.13% | 20.29% | 5.07% | 30.00% | $6.888378 | 378.22 min |

## By model

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 48 | 51.69% | 39.56% | 26.81% | 0.72% | 43.33% | $10.311475 | 652.69 min |
| gpt-5.4-mini | 48 | 24.15% | 44.64% | 10.14% | 9.42% | 10.00% | $3.401082 | 65.22 min |

## By stage

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stage1 | 32 | 38.04% | 43.93% | 18.48% | 5.43% | 31.67% | $4.129730 | 217.89 min |
| stage2 | 32 | 38.77% | 40.38% | 20.65% | 3.26% | 23.33% | $5.037526 | 270.47 min |
| stage3 | 32 | 36.96% | 39.08% | 16.30% | 6.52% | 25.00% | $4.545301 | 229.55 min |

## By model and stage

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini/stage1 | 16 | 52.90% | 44.24% | 28.26% | 2.17% | 53.33% | $3.010448 | 195.41 min |
| gpt-4.1-mini/stage2 | 16 | 55.07% | 40.00% | 30.43% | 0.00% | 40.00% | $3.842111 | 248.37 min |
| gpt-4.1-mini/stage3 | 16 | 47.10% | 34.95% | 21.74% | 0.00% | 36.67% | $3.458916 | 208.90 min |
| gpt-5.4-mini/stage1 | 16 | 23.19% | 43.24% | 8.70% | 8.70% | 10.00% | $1.119282 | 22.48 min |
| gpt-5.4-mini/stage2 | 16 | 22.46% | 41.33% | 10.87% | 6.52% | 6.67% | $1.195415 | 22.10 min |
| gpt-5.4-mini/stage3 | 16 | 26.81% | 49.33% | 10.87% | 13.04% | 13.33% | $1.086385 | 20.65 min |

## By use case

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| chain_02_e01_python_simplehttpserver_network_chain | 12 | 37.04% | 41.67% | 19.44% | 5.56% | 20.83% | $1.495031 | 77.57 min |
| chain_04_e03_dns_packet_capture_batch_chain | 12 | 26.19% | 67.35% | 15.48% | 2.38% | 13.89% | $1.616530 | 85.97 min |
| chain_05_e03_python_simplehttpserver_network_chain | 12 | 43.06% | 34.44% | 25.00% | 12.50% | 58.33% | $1.795083 | 96.65 min |
| chain_06_e04_python_simplehttpserver_network_chain | 12 | 38.89% | 15.91% | 0.00% | 0.00% | n/a | $1.671568 | 89.67 min |
| chain_09_e07_cmdexe_other_chain | 12 | 55.56% | 21.51% | 16.67% | 25.00% | n/a | $1.810483 | 89.21 min |
| chain_10_e07_discord_run_key_registry_chain | 12 | 69.44% | 52.08% | 41.67% | 8.33% | 66.67% | $1.680701 | 89.54 min |
| chain_11_e07_sublime_python_script_execution_chain | 12 | 35.19% | 37.25% | 8.33% | 2.78% | 33.33% | $1.838786 | 100.24 min |
| chain_24_e18_cmdexe_other_chain | 12 | 38.19% | 53.92% | 20.83% | 2.08% | 27.78% | $1.804375 | 89.07 min |

## By model and use case

| Group | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini/chain_02_e01_python_simplehttpserver_network_chain | 6 | 53.70% | 43.94% | 33.33% | 0.00% | 41.67% | $1.087509 | 70.29 min |
| gpt-4.1-mini/chain_04_e03_dns_packet_capture_batch_chain | 6 | 36.51% | 67.65% | 23.81% | 0.00% | 19.44% | $1.164684 | 77.68 min |
| gpt-4.1-mini/chain_05_e03_python_simplehttpserver_network_chain | 6 | 55.56% | 27.78% | 33.33% | 0.00% | 66.67% | $1.451666 | 90.08 min |
| gpt-4.1-mini/chain_06_e04_python_simplehttpserver_network_chain | 6 | 50.00% | 15.25% | 0.00% | 0.00% | n/a | $1.254524 | 81.27 min |
| gpt-4.1-mini/chain_09_e07_cmdexe_other_chain | 6 | 72.22% | 21.67% | 33.33% | 0.00% | n/a | $1.285034 | 78.51 min |
| gpt-4.1-mini/chain_10_e07_discord_run_key_registry_chain | 6 | 77.78% | 38.89% | 33.33% | 0.00% | 83.33% | $1.278323 | 81.24 min |
| gpt-4.1-mini/chain_11_e07_sublime_python_script_execution_chain | 6 | 48.15% | 39.39% | 11.11% | 5.56% | 66.67% | $1.416213 | 92.07 min |
| gpt-4.1-mini/chain_24_e18_cmdexe_other_chain | 6 | 59.72% | 55.13% | 37.50% | 0.00% | 55.56% | $1.373521 | 81.55 min |
| gpt-5.4-mini/chain_02_e01_python_simplehttpserver_network_chain | 6 | 20.37% | 36.67% | 5.56% | 11.11% | 0.00% | $0.407521 | 7.28 min |
| gpt-5.4-mini/chain_04_e03_dns_packet_capture_batch_chain | 6 | 15.87% | 66.67% | 7.14% | 4.76% | 8.33% | $0.451846 | 8.29 min |
| gpt-5.4-mini/chain_05_e03_python_simplehttpserver_network_chain | 6 | 30.56% | 61.11% | 16.67% | 25.00% | 50.00% | $0.343417 | 6.57 min |
| gpt-5.4-mini/chain_06_e04_python_simplehttpserver_network_chain | 6 | 27.78% | 17.24% | 0.00% | 0.00% | n/a | $0.417044 | 8.40 min |
| gpt-5.4-mini/chain_09_e07_cmdexe_other_chain | 6 | 38.89% | 21.21% | 0.00% | 50.00% | n/a | $0.525449 | 10.70 min |
| gpt-5.4-mini/chain_10_e07_discord_run_key_registry_chain | 6 | 61.11% | 91.67% | 50.00% | 16.67% | 50.00% | $0.402378 | 8.30 min |
| gpt-5.4-mini/chain_11_e07_sublime_python_script_execution_chain | 6 | 22.22% | 33.33% | 5.56% | 0.00% | 0.00% | $0.422573 | 8.17 min |
| gpt-5.4-mini/chain_24_e18_cmdexe_other_chain | 6 | 16.67% | 50.00% | 4.17% | 4.17% | 0.00% | $0.430853 | 7.51 min |

## Investigation behavior

Chief leads 861 (unique 714, 82.93%); Investigator questions 3,044 (unique 3,031); SQL queries 4,675 (unique 4,649). API calls 11,007; input/output/cached/total tokens 37,814,915/2,432,165/23,519,616/40,247,080; cost $13.712557; aggregate wall time 717.91 min. Mean/run: 114.66 calls, 419,240.4 tokens, $0.142839, 7.48 min.

## Error diagnostics

Missing-step reasons: `{"no_aligned_candidate_claim": 123, "partial_atomic_component_recovery": 102}`. Missing atomic components: `{"object": 204, "operation": 156, "subject": 154}`. Unaligned candidate claims: 38; overconnection slots: 112; hallucination-like unsupported/corrupted slots: 7. FP types: `{"duplicate": 72, "unsupported": 7, "wrong_component": 112, "wrong_relation": 59, "wrong_value": 201}`.

## Formal integrity

Gold subject/operation/object hits are derived only from unique included literal-TP `matched_gold_item_id` coverage. Behavior steps require all three components. Critical evidence and adjacent Gold order pairs are separate diagnostics. PID identity and hidden-alert mapping are not scored; `action` is normalized to `operation`. Every run/Gold hash, Gold item, fixed candidate slot, adjacent order pair, denominator, and per-run total is retained in the score root. Ledger counts: 96 runs, 1104 Gold items, 765 candidate slots, 180 order pairs. Cross-field validation: PASS (0 failures).
