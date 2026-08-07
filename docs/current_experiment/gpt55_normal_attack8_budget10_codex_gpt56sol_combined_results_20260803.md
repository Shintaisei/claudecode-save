# GPT-5.5 normal8 + attack8 budget-$10 formal results

## 結論

48試行を収集し、正常Discord Stage 2の非budget timeoutはcreate-only retryでPASSした。
精度のheadlineは正常24件と攻撃22件の計46件である。攻撃2件はhard budgetで停止したため、
ゼロ点にはせずbudget-censoredとして精度分母から除外した。欠測は0件で、Codex gpt-5.6-solによる
v5 atomic採点と全cross-field監査はPASSした。OpenAI judge API/API scorerは使用していない。

## 全体精度（headline eligible）

| 範囲 | 試行 | Action recall | Candidate precision | 完全step | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| 正常 | 24 | 78.74% | 42.12% | 55.07% | 76.81% | 84.44% |
| 攻撃 | 22 | 64.60% | 51.05% | 62.83% | 60.18% | 50.55% |
| 合計 | 46 | 69.96% | 46.81% | 59.89% | 66.48% | 61.76% |

## Stage別（正常＋攻撃、gpt-5.5）

| Stage | 試行 | Action recall | Candidate precision | 完全step | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| Stage 1 | 15 | 54.24% | 36.78% | 38.98% | 47.46% | 45.45% |
| Stage 2 | 16 | 79.29% | 51.31% | 71.21% | 77.27% | 70.00% |
| Stage 3 | 15 | 75.44% | 51.81% | 68.42% | 73.68% | 69.05% |

Stage 1が最弱で、Stage 2が最も高い。Stage 1/3は各1件がbudget-censoredのため15件、Stage 2は16件である。

## 3モデル比較（同じ46 strata）

| モデル | 試行 | Action recall | Candidate precision | 完全step | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 46 | 39.93% | 44.13% | 24.73% | 7.14% | 22.06% |
| `gpt-5.4-mini` | 46 | 17.58% | 42.48% | 10.44% | 8.79% | 4.41% |
| `gpt-5.5` | 46 | 69.96% | 46.81% | 59.89% | 66.48% | 61.76% |

## モデル×Stage（同じeligible strata）

| モデル | Stage | 試行 | Action recall | Precision | 完全step | Critical | Order |
|---|---|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | Stage 1 | 15 | 34.46% | 39.35% | 18.64% | 1.69% | 20.45% |
| `gpt-4.1-mini` | Stage 2 | 16 | 40.91% | 47.93% | 22.73% | 3.03% | 22.00% |
| `gpt-4.1-mini` | Stage 3 | 15 | 44.44% | 44.71% | 33.33% | 17.54% | 23.81% |
| `gpt-5.4-mini` | Stage 1 | 15 | 15.82% | 38.89% | 10.17% | 5.08% | 2.27% |
| `gpt-5.4-mini` | Stage 2 | 16 | 21.21% | 47.19% | 13.64% | 12.12% | 8.00% |
| `gpt-5.4-mini` | Stage 3 | 15 | 15.20% | 40.00% | 7.02% | 8.77% | 2.38% |
| `gpt-5.5` | Stage 1 | 15 | 54.24% | 36.78% | 38.98% | 47.46% | 45.45% |
| `gpt-5.5` | Stage 2 | 16 | 79.29% | 51.31% | 71.21% | 77.27% | 70.00% |
| `gpt-5.5` | Stage 3 | 15 | 75.44% | 51.81% | 68.42% | 73.68% | 69.05% |

## コスト・時間・探索量（同じ46 strata）

| モデル | Tokens | Cost | Wall time | Chief leads | Investigator質問 | SQL queries |
|---|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 34,522,619 | $10.066705 | 8.31時間 | 647 | 2,608 | 3,858 |
| `gpt-5.4-mini` | 4,707,231 | $3.198750 | 0.85時間 | 185 | 171 | 356 |
| `gpt-5.5` | 30,275,532 | $171.880681 | 10.02時間 | 264 | 493 | 1,498 |

gpt-5.5のheadline 46件は$171.880681、budget-censored 2件は$20.395164、
retryを含む最終成果物ledger総額は$192.275845である。元の1800秒timeout試行はfinal ledgerを
生成していないため、その未確定usageはこの額に含まれない。

## Budget-censored 2件

| 攻撃ケース | Stage | 記録cost | 扱い |
|---|---:|---:|---|
| `s4_pt_04_powershell_c1` | Stage 1 | $10.298952 | headline除外、凍結保持 |
| `s4_pt_03_mshta_c1` | Stage 3 | $10.096212 | headline除外、凍結保持 |

上限超過分は過剰請求ではなく、guard判定後に許可された最後のAPI callが閾値をまたいだ離散的overshootである。
いずれも次の新規callは止まり、探索の暴走は$10付近で抑止できた。

## ケース別（gpt-5.5）

| 種別 | ケース | Action recall | Precision | 完全step | Critical | Order |
|---|---|---:|---:|---:|---:|---:|
| normal | `chain_02_e01_python_simplehttpserver_network_chain` | 92.59% | 75.76% | 77.78% | 77.78% | 100.00% |
| normal | `chain_04_e03_dns_packet_capture_batch_chain` | 61.90% | 72.22% | 33.33% | 61.90% | 66.67% |
| normal | `chain_05_e03_python_simplehttpserver_network_chain` | 83.33% | 38.46% | 50.00% | 100.00% | 100.00% |
| normal | `chain_06_e04_python_simplehttpserver_network_chain` | 66.67% | 14.29% | 0.00% | 100.00% | n/a |
| normal | `chain_09_e07_cmdexe_other_chain` | 88.89% | 13.33% | 66.67% | 100.00% | n/a |
| normal | `chain_10_e07_discord_run_key_registry_chain` | 83.33% | 21.74% | 83.33% | 66.67% | 66.67% |
| normal | `chain_11_e07_sublime_python_script_execution_chain` | 85.19% | 58.97% | 66.67% | 66.67% | 100.00% |
| normal | `chain_24_e18_cmdexe_other_chain` | 88.89% | 62.75% | 66.67% | 91.67% | 100.00% |
| attack | `s3_pt_01_word_document_processing` | 44.44% | 26.67% | 33.33% | 33.33% | 0.00% |
| attack | `s3_pt_02_regsvr32_remote_sct` | 77.78% | 46.67% | 77.78% | 66.67% | 66.67% |
| attack | `s3_pt_03_regsvr32_long_chain` | 70.83% | 60.71% | 70.83% | 70.83% | 57.14% |
| attack | `s3_pt_04_powershell_mid_chain` | 88.89% | 56.57% | 85.71% | 90.48% | 77.78% |
| attack | `s4_pt_01_word_w1` | 63.89% | 45.10% | 58.33% | 58.33% | 44.44% |
| attack | `s4_pt_02_word_w3` | 44.44% | 25.00% | 44.44% | 11.11% | 16.67% |
| attack | `s4_pt_03_mshta_c1` | 55.56% | 76.92% | 55.56% | 55.56% | 43.75% |
| attack | `s4_pt_04_powershell_c1` | 42.86% | 54.55% | 42.86% | 42.86% | 33.33% |

## 考察

- gpt-5.5はmini 2モデルよりAction、完全step、Critical、Orderを大幅に改善した。特に正常ではOrder 84.44%、Critical 76.81%まで上昇した。
- 攻撃はStage 1の初動復元が弱い一方、Stage 2/3ではprocess lineageと後続pivotの回収が大きく改善した。
- Precisionの伸びはRecallほど大きくない。正常ではover-connected slot、攻撃ではnearby telemetryが主因である。
- $10 guardは48件中2件で作動した。censored分を0点化せず除外したため、モデル精度と実行予算制約を混同していない。

## 監査・成果物

- 正常詳細: `docs/current_experiment/gpt55_normal8_three_stage_codex_gpt56sol_results_20260803.json`
- 攻撃詳細: `docs/current_experiment/gpt55_attack8_budget10_codex_gpt56sol_results_20260803.json`
- 統合JSON: `docs/current_experiment/gpt55_normal_attack8_budget10_codex_gpt56sol_combined_results_20260803.json`
- provenance reconciliation: `docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01/final_composite_provenance_20260803.json`
- formal addendum: `docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01/formal_scoring_addendum_20260803.json`
