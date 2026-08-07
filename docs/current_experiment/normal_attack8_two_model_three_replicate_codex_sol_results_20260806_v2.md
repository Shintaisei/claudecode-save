# 正常8＋攻撃8・2モデル・3反復 統合結果

- 状態: **PASS**（288/288有効run、OpenAI judge API 0回）
- 全体精度: Action **29.38%** / Precision **41.50%** / 完全step **20.37%** / Critical **7.91%** / Order **13.11%**
- 実測総コスト: **$44.596231**、総wall time: **32.82時間**、総tokens: **127,957,534**
- 95%CIは3反復の固定分母スコアを実験単位としてStudent-t（df=2）で算出。n=3のため区間は広く、傾向確認用です。

## モデル×正常/攻撃（3反復pool）

| model | phase | runs | Action | Precision | 完全step | Critical | Order | cost/run | time/run |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | attack8 | 72 | 35.66% | 43.26% | 30.49% | 11.89% | 12.06% | $0.2462 | 11.95分 |
| gpt-4.1-mini | normal8 | 72 | 51.53% | 41.03% | 26.09% | 0.97% | 42.96% | $0.2156 | 12.88分 |
| gpt-5.4-mini | attack8 | 72 | 14.56% | 37.81% | 13.44% | 6.46% | 2.86% | $0.0888 | 1.18分 |
| gpt-5.4-mini | normal8 | 72 | 23.19% | 42.48% | 8.70% | 10.14% | 9.63% | $0.0688 | 1.34分 |

## モデル×正常/攻撃×Stage（3反復pool）

| model | phase | stage | runs | Action | Precision | 完全step | Critical | Order | cost/run | time/run |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | attack8 | stage1 | 24 | 33.85% | 43.23% | 30.23% | 8.53% | 9.52% | $0.2419 | 11.12分 |
| gpt-4.1-mini | attack8 | stage2 | 24 | 37.21% | 47.06% | 31.01% | 11.63% | 16.19% | $0.2314 | 11.89分 |
| gpt-4.1-mini | attack8 | stage3 | 24 | 35.92% | 39.94% | 30.23% | 15.50% | 10.48% | $0.2654 | 12.82分 |
| gpt-4.1-mini | normal8 | stage1 | 24 | 53.14% | 43.82% | 26.09% | 2.90% | 51.11% | $0.1956 | 11.75分 |
| gpt-4.1-mini | normal8 | stage2 | 24 | 51.69% | 39.78% | 24.64% | 0.00% | 37.78% | $0.2228 | 13.74分 |
| gpt-4.1-mini | normal8 | stage3 | 24 | 49.76% | 39.62% | 27.54% | 0.00% | 40.00% | $0.2283 | 13.16分 |
| gpt-5.4-mini | attack8 | stage1 | 24 | 12.92% | 34.72% | 11.63% | 6.98% | 2.86% | $0.0828 | 1.11分 |
| gpt-5.4-mini | attack8 | stage2 | 24 | 18.09% | 47.62% | 17.05% | 7.75% | 3.81% | $0.1094 | 1.30分 |
| gpt-5.4-mini | attack8 | stage3 | 24 | 12.66% | 31.41% | 11.63% | 4.65% | 1.90% | $0.0741 | 1.14分 |
| gpt-5.4-mini | normal8 | stage1 | 24 | 23.19% | 46.15% | 10.14% | 7.25% | 8.89% | $0.0677 | 1.36分 |
| gpt-5.4-mini | normal8 | stage2 | 24 | 22.71% | 39.50% | 8.70% | 8.70% | 8.89% | $0.0711 | 1.39分 |
| gpt-5.4-mini | normal8 | stage3 | 24 | 23.67% | 42.24% | 7.25% | 14.49% | 11.11% | $0.0678 | 1.26分 |

## 正常/攻撃×ケース（3反復pool）

| phase | case | runs | Action | Precision | 完全step | Critical | Order | cost/run | time/run |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| attack8 | s3_pt_01_word_document_processing | 18 | 36.11% | 32.50% | 30.56% | 19.44% | 0.00% | $0.1168 | 5.12分 |
| attack8 | s3_pt_02_regsvr32_remote_sct | 18 | 30.86% | 29.76% | 29.63% | 20.37% | 13.89% | $0.1135 | 5.12分 |
| attack8 | s3_pt_03_regsvr32_long_chain | 18 | 19.91% | 39.27% | 15.28% | 7.64% | 9.52% | $0.1643 | 7.75分 |
| attack8 | s3_pt_04_powershell_mid_chain | 18 | 32.01% | 57.62% | 28.57% | 7.94% | 10.19% | $0.1751 | 8.30分 |
| attack8 | s4_pt_01_word_w1 | 18 | 27.78% | 39.22% | 22.22% | 4.17% | 9.26% | $0.1204 | 5.47分 |
| attack8 | s4_pt_02_word_w3 | 18 | 27.16% | 31.88% | 22.22% | 3.70% | 2.78% | $0.0854 | 3.55分 |
| attack8 | s4_pt_03_mshta_c1 | 18 | 19.34% | 47.47% | 17.28% | 9.26% | 3.47% | $0.2495 | 8.35分 |
| attack8 | s4_pt_04_powershell_c1 | 18 | 23.54% | 44.95% | 23.02% | 9.52% | 7.41% | $0.3149 | 8.87分 |
| normal8 | chain_02_e01_python_simplehttpserver_network_chain | 18 | 37.04% | 44.44% | 20.37% | 5.56% | 19.44% | $0.1155 | 5.91分 |
| normal8 | chain_04_e03_dns_packet_capture_batch_chain | 18 | 25.66% | 68.31% | 15.08% | 3.17% | 12.96% | $0.1410 | 7.36分 |
| normal8 | chain_05_e03_python_simplehttpserver_network_chain | 18 | 47.22% | 38.64% | 22.22% | 16.67% | 72.22% | $0.1622 | 8.20分 |
| normal8 | chain_06_e04_python_simplehttpserver_network_chain | 18 | 37.04% | 15.15% | 0.00% | 0.00% | — | $0.1510 | 7.52分 |
| normal8 | chain_09_e07_cmdexe_other_chain | 18 | 55.56% | 19.23% | 16.67% | 27.78% | — | $0.1457 | 6.52分 |
| normal8 | chain_10_e07_discord_run_key_registry_chain | 18 | 63.89% | 48.94% | 30.56% | 5.56% | 61.11% | $0.1418 | 7.27分 |
| normal8 | chain_11_e07_sublime_python_script_execution_chain | 18 | 37.04% | 41.10% | 11.11% | 3.70% | 33.33% | $0.1415 | 7.38分 |
| normal8 | chain_24_e18_cmdexe_other_chain | 18 | 35.65% | 57.04% | 19.44% | 1.39% | 25.93% | $0.1389 | 6.72分 |

## 反復性の読み方

JSONの各集計セルには `per_replicate` と `repeatability` を保存しています。`repeatability` は3反復の値、平均、標本分散、95%CIを含みます。スライドでは pooled 値を主結果、95%CIを再現性の補助線として併記してください。

## 失敗・再試行

first passの2件（1800秒run timeout、APITimeoutError）は既存成果物を凍結したまま別rootで再試行し、2件ともPASSしました。正式集計に欠測はありません。

## 成果物

- JSON: `docs/current_experiment/normal_attack8_two_model_three_replicate_codex_sol_results_20260806_v2.json`
- 生成スクリプト: `scripts/aggregate_normal_attack8_three_replicates_20260806.py`
