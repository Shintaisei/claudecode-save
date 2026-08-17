# FIT2026 結果数値の再整理

## 1. 表の前提

復元性能は、事前に定義したGold stepをどこまで復元したかと、出力したclaimがどこまで正しかったかを分けて示す。

- `Action`：Gold stepの主体・行動・対象を復元できた割合
- `Complete step`：主体・行動・対象の3要素が同時に揃ったGold stepの割合
- `Evidence`：Gold stepの根拠証跡を提示できた割合
- `Order`：Goldの隣接stepの順序を復元できた割合
- `Gold-target Precision`：出力claimのうち、事前Goldの関係へclaim全体が対応した割合
- `Supported-component Precision`：出力claimのうち、Gold対応または証跡付きで中心componentに接続された有効関係の割合

従来の`Precision`は主体・行動・対象のslot単位であり、creditが別claimへ分散するため、メインの結果表から外す。従来値は感度分析としてのみ残す。

## 2. 3モデルの全体比較

復元性能は、3モデルで共通して比較できる46 strataを使用する。Goldは182 step、隣接順序は136 pairである。Precisionのclaim数は、GPT-4.1-miniが152件、GPT-5.4-miniが97件、GPT-5.5が272件である。

| モデル | Action | Gold-target Precision | Supported-component Precision | Complete step | Evidence | Order | 平均コスト／試行 | 平均時間／試行 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| GPT-4.1-mini | 36.45%<br>199/546 | 25.66%<br>39/152 | 35.53%<br>54/152 | 19.23%<br>35/182 | 10.99%<br>20/182 | 23.53%<br>32/136 | $0.219 | 約10分50秒 |
| GPT-5.4-mini | 22.71%<br>124/546 | 26.80%<br>26/97 | 27.84%<br>27/97 | 12.09%<br>22/182 | 17.58%<br>32/182 | 10.29%<br>14/136 | $0.070 | 約1分07秒 |
| **GPT-5.5** | **75.09%**<br>410/546 | **45.59%**<br>124/272 | **73.53%**<br>200/272 | **72.53%**<br>132/182 | **66.48%**<br>121/182 | **63.24%**<br>86/136 | **$3.737** | **約13分04秒** |

GPT-5.5は、Goldとして定義した行動stepの復元、証跡提示、順序復元で最も高い性能を示した。また、Gold-target Precisionは45.59%だが、Gold外の証拠付きcomponent内関係を含めると73.53%であった。したがって、従来の低Precisionには、誤りだけでなく、モデルがGoldより広い有効関係を出力した影響が含まれていた。

一方、GPT-5.5が出力した272 claimのうち72件はSupported-componentでも不正解であった。内訳は、証跡不足または関係誤り31件、routine/context 26件、component外11件、重複4件である。よって「過剰出力がなくなった」とも言えない。

## 3. GPT-5.5の正常・攻撃別結果

| 対象 | Action | Gold-target Precision | Supported-component Precision | Complete step | Evidence | Order |
|---|---:|---:|---:|---:|---:|---:|
| 正常行動 | 89.37% | 41.09%<br>53/129 | 75.19%<br>97/129 | 85.51% | 76.81% | 84.44% |
| 攻撃行動 | 66.37% | 49.65%<br>71/143 | 72.03%<br>103/143 | 64.60% | 60.18% | 52.75% |

正常行動は、Gold stepの要素、完全step、証跡、順序を攻撃行動より高い割合で復元した。Gold-target Precisionは攻撃行動の方が高いが、Supported-component Precisionは正常75.19%、攻撃72.03%であり、証拠付きcomponentとして評価すると大差はない。

## 4. GPT-5.5のStage別結果

| 対象 | Stage | Action | Gold-target Precision | Supported-component Precision | Complete step | Evidence | Order |
|---|---|---:|---:|---:|---:|---:|---:|
| 正常行動 | Stage 1 | 86.96% | 38.30%<br>18/47 | 59.57%<br>28/47 | 82.61% | 69.57% | 86.67% |
| 正常行動 | Stage 2 | **94.20%** | 40.00%<br>18/45 | **86.67%**<br>39/45 | **91.30%** | **82.61%** | **86.67%** |
| 正常行動 | Stage 3 | 86.96% | **45.95%**<br>17/37 | 81.08%<br>30/37 | 82.61% | 78.26% | 80.00% |
| 攻撃行動 | Stage 1 | 41.67% | 32.50%<br>13/40 | 65.00%<br>26/40 | 36.11% | 33.33% | 24.14% |
| 攻撃行動 | Stage 2 | **79.07%** | **57.89%**<br>33/57 | **75.44%**<br>43/57 | **79.07%** | **74.42%** | 65.71% |
| 攻撃行動 | Stage 3 | 76.47% | 54.35%<br>25/46 | 73.91%<br>34/46 | 76.47% | 70.59% | **66.67%** |

正常・攻撃とも、Stage 1はStage 2よりActionとComplete stepが低い。この表が直接示すのは「アラート詳細を入力したStage 1が最も高性能ではなかった」ことまでである。アラート時刻が探索範囲を狭めたことは、調査履歴と事例を用いて考察で説明する。

## 5. GPT-5.5 Stage 2のユースケース別Precision

| 対象 | ユースケース | claim数 | Gold-target Precision | Supported-component Precision |
|---|---|---:|---:|---:|
| 攻撃 | s3_pt_01_word_document_processing | 4 | 25.00%<br>1/4 | 50.00%<br>2/4 |
| 攻撃 | s3_pt_02_regsvr32_remote_sct | 3 | 100.00%<br>3/3 | 100.00%<br>3/3 |
| 攻撃 | s3_pt_03_regsvr32_long_chain | 11 | 63.64%<br>7/11 | 90.91%<br>10/11 |
| 攻撃 | s3_pt_04_powershell_mid_chain | 10 | 60.00%<br>6/10 | 100.00%<br>10/10 |
| 攻撃 | s4_pt_01_word_w1 | 8 | 37.50%<br>3/8 | 37.50%<br>3/8 |
| 攻撃 | s4_pt_02_word_w3 | 6 | 33.33%<br>2/6 | 50.00%<br>3/6 |
| 攻撃 | s4_pt_03_mshta_c1 | 11 | 72.73%<br>8/11 | 72.73%<br>8/11 |
| 攻撃 | s4_pt_04_powershell_c1 | 4 | 75.00%<br>3/4 | 100.00%<br>4/4 |
| 正常 | chain_02_e01_python_simplehttpserver_network_chain | 4 | 50.00%<br>2/4 | 100.00%<br>4/4 |
| 正常 | chain_04_e03_dns_packet_capture_batch_chain | 7 | 57.14%<br>4/7 | 85.71%<br>6/7 |
| 正常 | chain_05_e03_python_simplehttpserver_network_chain | 4 | 50.00%<br>2/4 | 75.00%<br>3/4 |
| 正常 | chain_06_e04_python_simplehttpserver_network_chain | 2 | 50.00%<br>1/2 | 100.00%<br>2/2 |
| 正常 | chain_09_e07_cmdexe_other_chain | 11 | 9.09%<br>1/11 | 63.64%<br>7/11 |
| 正常 | chain_10_e07_discord_run_key_registry_chain | 9 | 22.22%<br>2/9 | 100.00%<br>9/9 |
| 正常 | chain_11_e07_sublime_python_script_execution_chain | 4 | 50.00%<br>2/4 | 100.00%<br>4/4 |
| 正常 | chain_24_e18_cmdexe_other_chain | 4 | 100.00%<br>4/4 | 100.00%<br>4/4 |

## 6. 失敗分析の分母

失敗分析は、共通46 strataではなく、現在利用できる正式採点済み全384試行を対象とする。GPT-4.1-miniとGPT-5.4-miniは各144試行・594 Gold step、GPT-5.5は96試行・385 Gold stepである。そのため、モデル間で失敗の絶対件数は直接比較せず、各モデル内の構成比を比較する。

| モデル | 未完全復元Gold step | 調査過程を追跡可能 | 追跡不可能 | 追跡可能率 |
|---|---:|---:|---:|---:|
| GPT-4.1-mini | 431 | **380** | 51 | 88.17% |
| GPT-5.4-mini | 519 | **461** | 58 | 88.82% |
| GPT-5.5 | 113 | **108** | 5 | 95.58% |

次の失敗分類表の分母は、上表の「調査過程を追跡可能」な未完全復元Gold stepである。各1 stepをどれか1分類にのみ割り当てる。

## 7. モデル別の失敗要因

| 大分類 | 小分類 | GPT-4.1-mini（n=380） | GPT-5.4-mini（n=461） | GPT-5.5（n=108） |
|---|---|---:|---:|---:|
| 調査段階 | 調査論点の設定漏れ | 165（43.42%） | 278（60.30%） | 49（45.37%） |
| 調査段階 | 証跡探索の失敗 | 49（12.89%） | 93（20.17%） | 24（22.22%） |
| まとめ段階 | 調査結果の採用漏れ | 93（24.47%） | 67（14.53%） | 23（21.30%） |
| まとめ段階 | 関係整理の誤り | 73（19.21%） | 23（4.99%） | 12（11.11%） |
| 合計 |  | **380（100.00%）** | **461（100.00%）** | **108（100.00%）** |

大分類で合算すると、調査段階の失敗はGPT-4.1-miniで214/380（56.32%）、GPT-5.4-miniで371/461（80.48%）、GPT-5.5で73/108（67.59%）である。GPT-5.5はGold stepの復元性能自体は大きく向上したが、残った失敗の過半数は、最終文の生成より前の調査段階で生じている。

またGPT-5.5では、調査論点の設定漏れ49件が最も多く、証跡探索の失敗24件と調査結果の採用漏れ23件が続いた。関係整理の誤りは、意味同値とinstance対応を再監査すると12件であった。したがって、改善方針は、最終出力形式だけでなく「調査すべき関係候補を漏れなく列挙すること」「検索方法を修正しながら証跡へ到達すること」「発見済み証跡を最終出力へ漏れなく反映すること」に重点を置く必要がある。

## 8. 結果から言えること

1. GPT-5.5は、他の2モデルよりGold stepの復元、証跡提示、順序復元の全てで高い性能を示した。
2. GPT-5.5の従来Precisionが低かった原因には、誤出力だけでなく、Goldより広い証拠付きcomponentを復元したことが含まれる。
3. Supported-componentで評価してもGPT-5.5の26.47%は不正解であり、関係誤り、routine/contextの混入、component外への逸脱、重複は残っている。
4. GPT-5.5の未完全復元Gold stepのうち追跡可能な108件を見ると、67.59%は調査段階の失敗である。したがって、プロンプトの最終出力形式だけでなく、論点生成と証跡探索の改善が必要である。

## 9. 引用した採点台帳

- Observable-semantic採点：`docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2/summary.json`
- Claim単位Precision採点：`docs/current_experiment/results_2026-08-15/three_model_supported_component_precision_v1/summary.json`
- Claim判定個票：`docs/current_experiment/results_2026-08-15/three_model_supported_component_precision_v1/claim_audit_all_1390.jsonl`
- 意味同値・失敗分類再監査：`docs/current_experiment/results_2026-08-15/failure_analysis_semantic_v3/summary.json`
