# Observable-semantic再採点結果

## 1. 再採点の対象と方針

既存の正式採点済み384試行を対象に、1,573件のGold stepを再採点した。内訳はGPT-4.1-miniが144試行、GPT-5.4-miniが144試行、GPT-5.5が96試行である。GPT-5.5の未採点48試行は0点として補完せず、利用可能な正式台帳の範囲として明示した。3モデルの比較表では、従来と同じ共通46 strataを使用した。

再採点では、主体・対象の逆転、別のendpoint、証跡にない関係、捏造は不正解のままとした。そのうえで、同じ観測関係を表す行動名、Wordの起動コマンドラインに入力文書が明示された関係、監査ログ変換時にlocal portだけが欠落したnetwork関係を正解として扱った。local portの欠落を許容する場合も、正しい主体とnetwork actionに加え、観測可能なIPまたはremote endpointの一致を必要とした。

`cmd.exe`と`python.exe`のどちらをscript実行の主体とするかはGoldの抽象化規則に関わるため、採用値へ混ぜていない。この差は感度分析として別に残した。

## 2. 先行して使用するGPT-5.5・Stage 2の結果

| 対象 | 試行数 | Gold step | Action | Precision | Complete step | Evidence | Order |
|---|---:|---:|---:|---:|---:|---:|---:|
| 正常行動 | 8 | 23 | 92.75% | 47.41% | 86.96% | 82.61% | 86.67% |
| 攻撃行動 | 8 | 43 | 79.07% | 57.89% | 79.07% | 74.42% | 65.71% |

正常行動では、監査ログから直接確認できるprocess、file、network、registryの関係は概ね復元できた。再採点前には、`0.0.0.0:8000`がadapter上で`0.0.0.0:0`になったケースや、remote endpointは一致するがlocal portを取得できないケースが対象不一致として落ちていた。観測可能な範囲に評価を合わせると、正常行動のComplete stepは60.87%から86.96%へ上昇した。

ただし、正常行動を実用上十分に選別できたとは言えない。たとえば`chain_09_e07_cmdexe_other_chain`はGold stepを完全に復元した一方、Precisionは9.09%であり、多数の周辺行動も出力した。したがって、正常行動では「必要な関係を回収できること」と「必要な関係だけを選べること」を分けて評価する必要がある。

攻撃行動では、`s3_pt_02_regsvr32_remote_sct`は全指標100%で復元できた。`s4_pt_03_mshta_c1`も9 Gold stepに対してComplete step 88.89%であり、長い行動列でも必ず失敗するわけではない。一方、`s4_pt_04_powershell_c1`は7 Gold stepであるにもかかわらずComplete step 42.86%に留まった。

この対比から、復元難易度をステップ数だけで説明することはできない。主な差は、初期の手掛かりから後続processやnetworkへpivotできるか、取得した証跡を最終行動列へ反映できるか、主体・行動・対象の向きを正しく構成できるかにある。

## 3. Stage 2のユースケース別結果

| 対象 | ユースケース | Gold step | Action | Precision | Complete step | Evidence | Order |
|---|---|---:|---:|---:|---:|---:|---:|
| 攻撃 | s3_pt_01_word_document_processing | 2 | 100.00% | 25.00% | 100.00% | 50.00% | 100.00% |
| 攻撃 | s3_pt_02_regsvr32_remote_sct | 3 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| 攻撃 | s3_pt_03_regsvr32_long_chain | 8 | 87.50% | 63.64% | 87.50% | 87.50% | 71.43% |
| 攻撃 | s3_pt_04_powershell_mid_chain | 7 | 85.71% | 60.00% | 85.71% | 85.71% | 66.67% |
| 攻撃 | s4_pt_01_word_w1 | 4 | 75.00% | 37.50% | 75.00% | 75.00% | 33.33% |
| 攻撃 | s4_pt_02_word_w3 | 3 | 66.67% | 33.33% | 66.67% | 33.33% | 50.00% |
| 攻撃 | s4_pt_03_mshta_c1 | 9 | 88.89% | 72.73% | 88.89% | 88.89% | 87.50% |
| 攻撃 | s4_pt_04_powershell_c1 | 7 | 42.86% | 75.00% | 42.86% | 42.86% | 33.33% |
| 正常 | chain_02_e01_python_simplehttpserver_network_chain | 3 | 100.00% | 75.00% | 100.00% | 100.00% | 100.00% |
| 正常 | chain_04_e03_dns_packet_capture_batch_chain | 7 | 80.95% | 80.95% | 71.43% | 71.43% | 66.67% |
| 正常 | chain_05_e03_python_simplehttpserver_network_chain | 2 | 100.00% | 50.00% | 100.00% | 100.00% | 100.00% |
| 正常 | chain_06_e04_python_simplehttpserver_network_chain | 1 | 100.00% | 50.00% | 100.00% | 100.00% | - |
| 正常 | chain_09_e07_cmdexe_other_chain | 1 | 100.00% | 9.09% | 100.00% | 100.00% | - |
| 正常 | chain_10_e07_discord_run_key_registry_chain | 2 | 100.00% | 22.22% | 100.00% | 50.00% | 100.00% |
| 正常 | chain_11_e07_sublime_python_script_execution_chain | 3 | 88.89% | 66.67% | 66.67% | 66.67% | 100.00% |
| 正常 | chain_24_e18_cmdexe_other_chain | 4 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |

発表で成功例として扱いやすいのは、復元と選別の両方が成立した`s3_pt_02_regsvr32_remote_sct`または`chain_24_e18_cmdexe_other_chain`である。失敗例には`s4_pt_04_powershell_c1`が適している。このケースはPrecisionが75.00%である一方、Complete stepが42.86%であり、「出力した関係の多くは正しいが、必要な行動を調査段階で十分に回収できなかった」という失敗を示せる。

`s3_pt_01_word_document_processing`はComplete step 100%だがPrecision 25.00%であるため、単純な成功例ではなく「Gold関係は含むが過剰接続が残る例」として使う方が適切である。

## 4. 3モデルの全体比較

| モデル | Action | Precision | Complete step | Evidence | Order | 平均コスト／試行 | 平均時間／試行 |
|---|---:|---:|---:|---:|---:|---:|---:|
| GPT-4.1-mini | 36.45% | 44.32% | 19.23% | 10.99% | 23.53% | $0.219 | 10分50秒 |
| GPT-5.4-mini | 22.71% | 43.36% | 12.09% | 17.58% | 10.29% | $0.070 | 1分07秒 |
| GPT-5.5 | 74.54% | 49.14% | 70.88% | 66.48% | 63.24% | $3.737 | 13分04秒 |

GPT-5.5は旧Strict採点のAction 69.96%から74.54%、Complete step 59.89%から70.88%、Precision 46.81%から49.14%、Order 61.76%から63.24%へ上昇した。Evidenceは証跡anchor自体の判定を変更していないため66.48%のままである。

完全ステップの上昇幅がActionより大きいのは、主体と行動を既に正しく復元していたが、adapterで欠落したlocal portや埋め込み表現のため対象だけが不正解だったステップが複数存在したためである。

一方、Precisionは再採点後も49.14%に留まった。したがって、モデルの高性能化と意味採点によって必要な関係の回収率は改善するが、周辺行動の過剰接続という課題は残る。

GPT-4.1-miniとGPT-5.4-miniの値は、旧スライドの集計値へ単純に差分を加えたものではない。現行の採用済みGold-item台帳を共通46 strataへ揃えて再集計した値であるため、旧表との差には台帳統一の影響も含まれる。

## 5. 失敗分析

Observable採点後も完全復元できなかったGold stepについて、調査過程を追跡できた失敗だけを分母として割合を算出した。

| 大分類 | 小分類 | GPT-4.1-mini | GPT-5.4-mini | GPT-5.5 |
|---|---|---:|---:|---:|
| 調査段階 | 調査論点の設定漏れ | 43.31% | 60.30% | 42.98% |
| 調査段階 | 証跡探索の失敗 | 12.86% | 20.17% | 21.05% |
| まとめ段階 | 調査結果の採用漏れ | 24.41% | 14.53% | 14.91% |
| まとめ段階 | 関係整理の誤り | 19.42% | 4.99% | 21.05% |
| 合計 |  | 100.00% | 100.00% | 100.00% |

GPT-5.5でも、失敗の64.03%は調査段階に生じている。特に、正しいendpointのportを含まないまま同一hostだけを根拠としていたケースを「証跡発見済み」とせず、調査論点の設定漏れへ戻した。これにより、旧表より調査段階の割合が増加している。

この結果から、GPT-5.5の主な残存課題は、最終文の表現だけではなく、必要な関係を調査対象として列挙し、正しい証跡まで探索する段階にあるといえる。ただし、調査過程を追跡できない失敗は割合の分母から除外しており、GPT-4.1-miniで51件、GPT-5.4-miniで58件、GPT-5.5で5件存在する。

## 6. 成果物

- 全結果とスライド用表: `docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2/slide_tables.md`
- GPT-5.5 Stage 2先行結果: `docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2/gpt55_stage2_first_report.md`
- 全384試行の再採点台帳: `docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2/observable_rescore_all_384.jsonl`
- 変更されたstepの監査台帳: `docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2/score_changes.jsonl`
- 集計値と採点規則: `docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2/summary.json`
- 閲覧用Excel: `outputs/019fdadc-05b6-70c2-a054-e19dcccc2d0c/FIT2026_observable_semantic_rescore_20260814.xlsx`
