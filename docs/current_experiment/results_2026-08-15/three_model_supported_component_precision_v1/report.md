# Claim単位 Precision再採点 v1

## 結論

従来のslot単位Precisionは主体・行動・対象のcreditが別claimへ分散し、Gold外だが証拠付きのcomponent内関係も一律にfalse positiveとしていた。本再採点では、claim全体を1つの関係へatomicに対応させ、事前Goldへの選別能力と、証拠付きcomponent関係を出す能力を分離した。

Gold外の関係は、直接証跡、Goldとの明示edge接続、対象関係クラス、routine/context除外をすべて通った場合のみSupported-componentの正解とした。Gold外networkはGold endpoint系列または実験上のserver操作に限定し、Gold外registryはDiscordの起動・登録系列に限定した。

## 3モデル比較（従来と同じ共通46 strata）

| モデル | claim数 | Gold-target Precision | Supported-component Precision | 追加で正解となったcomponent関係 |
|---|---:|---:|---:|---:|
| gpt-4.1-mini | 152 | 25.66% | 35.53% | 15 |
| gpt-5.4-mini | 97 | 26.80% | 27.84% | 1 |
| gpt-5.5 | 272 | 45.59% | 73.53% | 76 |

GPT-5.5ではGold-targetの45.59%に対し、Supported-componentは73.53%となった。従来の低Precisionには、誤りだけでなく、Goldより広い証拠付きcomponentを出力した影響が含まれていた。したがって「出力の選別能力は改善しなかった」とは現在の値からは主張できない。

なお、従来値は主体・行動・対象のslot単位、本表はclaim単位である。分母が異なるため、従来の46.81%と本表の73.53%を同じPrecisionとして直接比較してはならない。

## GPT-5.5 Stage 2 ユースケース別

| 対象 | ユースケース | claim数 | Gold-target | Supported-component | 追加component関係 |
|---|---|---:|---:|---:|---:|
| 攻撃 | s3_pt_01_word_document_processing | 4 | 25.00% | 50.00% | 1 |
| 攻撃 | s3_pt_02_regsvr32_remote_sct | 3 | 100.00% | 100.00% | 0 |
| 攻撃 | s3_pt_03_regsvr32_long_chain | 11 | 63.64% | 90.91% | 3 |
| 攻撃 | s3_pt_04_powershell_mid_chain | 10 | 60.00% | 100.00% | 4 |
| 攻撃 | s4_pt_01_word_w1 | 8 | 37.50% | 37.50% | 0 |
| 攻撃 | s4_pt_02_word_w3 | 6 | 33.33% | 50.00% | 1 |
| 攻撃 | s4_pt_03_mshta_c1 | 11 | 72.73% | 72.73% | 0 |
| 攻撃 | s4_pt_04_powershell_c1 | 4 | 75.00% | 100.00% | 1 |
| 正常 | chain_02_e01_python_simplehttpserver_network_chain | 4 | 50.00% | 100.00% | 2 |
| 正常 | chain_04_e03_dns_packet_capture_batch_chain | 7 | 57.14% | 85.71% | 2 |
| 正常 | chain_05_e03_python_simplehttpserver_network_chain | 4 | 50.00% | 75.00% | 1 |
| 正常 | chain_06_e04_python_simplehttpserver_network_chain | 2 | 50.00% | 100.00% | 1 |
| 正常 | chain_09_e07_cmdexe_other_chain | 11 | 9.09% | 63.64% | 6 |
| 正常 | chain_10_e07_discord_run_key_registry_chain | 9 | 22.22% | 100.00% | 7 |
| 正常 | chain_11_e07_sublime_python_script_execution_chain | 4 | 50.00% | 100.00% | 2 |
| 正常 | chain_24_e18_cmdexe_other_chain | 4 | 100.00% | 100.00% | 0 |

## 判定カテゴリ

`gold_target_relation`は既存Goldへclaim全体が対応した関係、`supported_component_relation`はGold外だが直接証跡と明示edgeで中心componentへ接続した有効関係である。`routine_or_context`、`duplicate_relation`、`relation_error_or_unsupported`、`outside_component`は不正解のままとした。

## 境界の固定

networkは、Goldと同一のendpoint系列またはPython HTTP serverとして実験定義された待ち受けのみcomponent内とした。Discordの通常通信などは除外した。registryはDiscordのRun/RunOnce/shell-openなど起動・登録に直接関係するもののみ追加関係とし、Office Resiliency、Proxy/Wpad、MuiCache等はhousekeepingとして除外した。
