# GPT-5.5 96 PASS provisional Codex review (2026-08-07)

**96/144 logical runs are scored.** The other 48 are excluded as missing, not scored as zero. This is a provisional, missingness-aware view and must not be presented as a balanced three-replicate estimate.

## Observed PASS headline

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-5.5 observed PASS | 96 | 67.45% | 48.29% | 55.35% | 63.45% | 59.23% | $375.520159 | 1456.91 min |

## By replicate

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| replicate_01 | 46 | 68.52% | 46.37% | 58.33% | 65.00% | 58.96% | $174.091714 | 601.50 min |
| replicate_02 | 39 | 66.47% | 49.93% | 56.21% | 60.36% | 56.15% | $166.851856 | 673.35 min |
| replicate_03 | 11 | 66.67% | 51.52% | 35.29% | 70.59% | 78.26% | $34.576589 | 182.06 min |

## By normal / attack

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| attack8 | 41 | 62.54% | 51.25% | 61.01% | 56.88% | 47.46% | $202.121542 | 647.80 min |
| normal8 | 55 | 73.94% | 45.35% | 47.88% | 72.12% | 78.18% | $173.398617 | 809.11 min |

## By Stage

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stage1 | 36 | 56.78% | 41.79% | 44.14% | 49.66% | 47.71% | $148.565410 | 568.37 min |
| stage2 | 32 | 74.55% | 55.18% | 61.83% | 74.05% | 66.67% | $121.140028 | 479.35 min |
| stage3 | 28 | 73.21% | 48.65% | 62.62% | 69.16% | 65.82% | $105.814721 | 409.20 min |

## By replicate and domain

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| replicate_01/attack8 | 22 | 62.16% | 50.36% | 60.36% | 57.66% | 46.07% | $100.932787 | 319.94 min |
| replicate_01/normal8 | 24 | 78.74% | 42.12% | 55.07% | 76.81% | 84.44% | $73.158927 | 281.56 min |
| replicate_02/attack8 | 19 | 62.93% | 52.20% | 61.68% | 56.07% | 48.86% | $101.188755 | 327.86 min |
| replicate_02/normal8 | 20 | 72.58% | 46.88% | 46.77% | 67.74% | 71.43% | $65.663101 | 345.48 min |
| replicate_03/normal8 | 11 | 66.67% | 51.52% | 35.29% | 70.59% | 78.26% | $34.576589 | 182.06 min |

## By domain and Stage

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| attack8/stage1 | 15 | 48.37% | 41.75% | 45.12% | 40.24% | 32.84% | $81.164206 | 239.54 min |
| attack8/stage2 | 14 | 72.00% | 60.00% | 72.00% | 69.33% | 55.74% | $62.665565 | 209.04 min |
| attack8/stage3 | 12 | 69.95% | 52.67% | 68.85% | 63.93% | 57.14% | $58.291771 | 199.23 min |
| normal8/stage1 | 21 | 67.72% | 41.83% | 42.86% | 61.90% | 71.43% | $67.401204 | 328.83 min |
| normal8/stage2 | 18 | 77.98% | 50.19% | 48.21% | 80.36% | 84.21% | $58.474463 | 270.31 min |
| normal8/stage3 | 16 | 77.54% | 44.58% | 54.35% | 76.09% | 80.00% | $47.522950 | 209.97 min |

## By use case

| Group | Runs | Action recall | Precision | Complete step | Critical | Order | Cost | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| attack8/s3_pt_01_word_document_processing | 5 | 56.67% | 31.48% | 50.00% | 30.00% | 20.00% | $18.279929 | 73.96 min |
| attack8/s3_pt_02_regsvr32_remote_sct | 5 | 86.67% | 43.33% | 86.67% | 66.67% | 80.00% | $23.130106 | 90.81 min |
| attack8/s3_pt_03_regsvr32_long_chain | 6 | 56.94% | 58.16% | 54.17% | 56.25% | 40.48% | $24.176814 | 96.70 min |
| attack8/s3_pt_04_powershell_mid_chain | 6 | 80.16% | 58.05% | 78.57% | 80.95% | 66.67% | $26.549070 | 104.08 min |
| attack8/s4_pt_01_word_w1 | 4 | 66.67% | 48.48% | 62.50% | 62.50% | 41.67% | $15.822824 | 60.48 min |
| attack8/s4_pt_02_word_w3 | 6 | 44.44% | 25.00% | 44.44% | 16.67% | 16.67% | $16.822924 | 69.10 min |
| attack8/s4_pt_03_mshta_c1 | 3 | 44.44% | 63.16% | 44.44% | 40.74% | 33.33% | $16.177233 | 36.08 min |
| attack8/s4_pt_04_powershell_c1 | 6 | 61.90% | 65.00% | 61.90% | 61.90% | 52.78% | $61.162642 | 116.58 min |
| normal8/chain_02_e01_python_simplehttpserver_network_chain | 8 | 80.56% | 80.56% | 58.33% | 62.50% | 75.00% | $22.355185 | 111.62 min |
| normal8/chain_04_e03_dns_packet_capture_batch_chain | 8 | 61.31% | 74.64% | 33.93% | 62.50% | 64.58% | $28.050962 | 132.81 min |
| normal8/chain_05_e03_python_simplehttpserver_network_chain | 7 | 83.33% | 40.23% | 50.00% | 100.00% | 100.00% | $17.033245 | 79.37 min |
| normal8/chain_06_e04_python_simplehttpserver_network_chain | 8 | 66.67% | 16.67% | 0.00% | 100.00% | n/a | $21.547939 | 111.94 min |
| normal8/chain_09_e07_cmdexe_other_chain | 6 | 66.67% | 12.50% | 50.00% | 66.67% | n/a | $24.704569 | 102.72 min |
| normal8/chain_10_e07_discord_run_key_registry_chain | 4 | 87.50% | 20.59% | 87.50% | 62.50% | 75.00% | $15.085233 | 61.28 min |
| normal8/chain_11_e07_sublime_python_script_execution_chain | 7 | 84.13% | 56.99% | 66.67% | 61.90% | 85.71% | $24.025184 | 114.50 min |
| normal8/chain_24_e18_cmdexe_other_chain | 7 | 80.95% | 55.28% | 53.57% | 89.29% | 100.00% | $20.596300 | 94.87 min |

## Missingness warning

PASS distribution: `{"replicate_01": 46, "replicate_02": 39, "replicate_03": 11}`; domain distribution: `{"attack8": 41, "normal8": 55}`. Replicate 03 contains only the early normal PASS cells before quota exhaustion. Do not compare replicate means causally or use the 96-run headline as the final GPT-5.5 number.

## Integrity

Deterministic consistency audit: **PASS**. Checked 96 run/audit/Gold bindings, 1149 Gold action items, 1605 candidate slots, 383 behavior steps, 383 critical-evidence items, and 287 order pairs. Judge/API scorer calls: 0.

## Provenance

Exact-hash reused decisions: 45; deterministic new normal scores: 31; new manual attack semantic reviews: 20. Existing artifacts were not overwritten.
