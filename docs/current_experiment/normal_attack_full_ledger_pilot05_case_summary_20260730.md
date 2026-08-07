# pilot05 ユースケース別精度・考察

正常2ユースケース、攻撃2ユースケースについて、各3 Stageを合算した精度と調査コストをケース単位で示す。
モデルごとにケース割当が異なるため、ケース難易度を統制したモデル間比較ではない。

## 正常2ケース・攻撃2ケース合算

| group | Action recall | Candidate precision | Complete step | Critical evidence | Order |
|---|---:|---:|---:|---:|---:|
| attack | 22/99 (22.22%) | 22/57 (38.60%) | 5/33 (15.15%) | 0/33 (0.00%) | 4/27 (14.81%) |
| normal | 13/45 (28.89%) | 13/66 (19.70%) | 4/15 (26.67%) | 0/15 (0.00%) | 1/9 (11.11%) |

## 4ユースケース個別集計

| group | model | case | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| normal | gpt-4.1-mini | `chain_10_e07_discord_run_key_registry_chain` | 9/18 (50.00%) | 9/39 (23.08%) | 3/6 (50.00%) | 0/6 (0.00%) | 0/3 (0.00%) | 355 | $0.361902 | 22.37 |
| attack | gpt-4.1-mini | `s4_pt_03_mshta_c1` | 10/81 (12.35%) | 10/27 (37.04%) | 2/27 (7.41%) | 0/27 (0.00%) | 1/24 (4.17%) | 654 | $0.944232 | 34.35 |
| normal | gpt-5.4-mini | `chain_02_e01_python_simplehttpserver_network_chain` | 4/27 (14.81%) | 4/27 (14.81%) | 1/9 (11.11%) | 0/9 (0.00%) | 1/6 (16.67%) | 228 | $0.738250 | 13.10 |
| attack | gpt-5.4-mini | `s3_pt_01_word_document_processing` | 12/18 (66.67%) | 12/30 (40.00%) | 3/6 (50.00%) | 0/6 (0.00%) | 3/3 (100.00%) | 175 | $0.847305 | 10.02 |

## Discord Run-key registry chain

- group: `normal`
- model: `gpt-4.1-mini`
- chain: `chain_10_e07_discord_run_key_registry_chain`

| Stage | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stage1 | 0/6 (0.00%) | 0/18 (0.00%) | 0/2 (0.00%) | 0/2 (0.00%) | 0/1 (0.00%) | 192 | $0.204923 | 10.92 |
| stage2 | 3/6 (50.00%) | 3/6 (50.00%) | 1/2 (50.00%) | 0/2 (0.00%) | 0/1 (0.00%) | 63 | $0.062085 | 3.90 |
| stage3 | 6/6 (100.00%) | 6/15 (40.00%) | 2/2 (100.00%) | 0/2 (0.00%) | 0/1 (0.00%) | 100 | $0.094894 | 7.54 |

Stage 1は近傍のDiscord関連処理へ漂流して0点、Stage 2はRun値書込み、Stage 3は2 Gold stepのaction componentを回収した。ただしStage 3は順序を逆転し、近傍update/setup/firefox chainを候補化したため、3 Stage合算ではrecall 50%に対してprecision 23.08%、order 0%となった。探索量を増やすとaction recallは上がったが、候補採用と順序制御が追いついていない。

注記：Stage 3の完了済みthoughtには修正前TEMP VIEW wrapperによる共通guard迂回があり、再実行せず技術的交絡として扱う。

役割別3 Stage合算：

| role | API calls | LLM sec | Cost |
|---|---:|---:|---:|
| chief | 18 | 138.188 | $0.035274 |
| investigator | 71 | 348.442 | $0.101311 |
| sql_qa | 266 | 555.374 | $0.225318 |

## mshta C1 multi-stage attack chain

- group: `attack`
- model: `gpt-4.1-mini`
- chain: `s4_pt_03_mshta_c1`

| Stage | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stage1 | 7/27 (25.93%) | 7/12 (58.33%) | 1/9 (11.11%) | 0/9 (0.00%) | 1/8 (12.50%) | 196 | $0.236412 | 11.31 |
| stage2 | 0/27 (0.00%) | 0/0 (n/a) | 0/9 (0.00%) | 0/9 (0.00%) | 0/8 (0.00%) | 8 | $0.006022 | 0.34 |
| stage3 | 3/27 (11.11%) | 3/15 (20.00%) | 1/9 (11.11%) | 0/9 (0.00%) | 0/8 (0.00%) | 450 | $0.701798 | 22.69 |

9 stepの長いchainに対し、Stage 1は前半のprocess edgeを部分取得、Stage 2はexact-time queryが0件の後に早期停止、Stage 3は450 LLM callを使いながら最終payload network edgeだけを完全取得した。3 Stage合算Action recallは12.35%、完全stepは7.41%である。問題は単純な探索回数不足ではなく、発見したPowerShell/cmd/payloadを次の親として因果pivotし、atomic edgeへ変換する機構にある。

役割別3 Stage合算：

| role | API calls | LLM sec | Cost |
|---|---:|---:|---:|
| chief | 22 | 139.501 | $0.050664 |
| investigator | 147 | 761.711 | $0.228353 |
| sql_qa | 485 | 1107.607 | $0.665215 |

## Python SimpleHTTPServer network chain

- group: `normal`
- model: `gpt-5.4-mini`
- chain: `chain_02_e01_python_simplehttpserver_network_chain`

| Stage | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stage1 | 4/9 (44.44%) | 4/6 (66.67%) | 1/3 (33.33%) | 0/3 (0.00%) | 1/2 (50.00%) | 56 | $0.165340 | 2.96 |
| stage2 | 0/9 (0.00%) | 0/9 (0.00%) | 0/3 (0.00%) | 0/3 (0.00%) | 0/2 (0.00%) | 70 | $0.251600 | 4.74 |
| stage3 | 0/9 (0.00%) | 0/12 (0.00%) | 0/3 (0.00%) | 0/3 (0.00%) | 0/2 (0.00%) | 102 | $0.321310 | 5.39 |

Stage 1はtarget chainの中央stepを完全取得したが、親子process-createをexecution_contextへ埋め込み、3 step中1 stepに留まった。Stage 2/3はtargetの38秒前にあるDNS packet-capture chainを選び、追加探索も誤ったprocess instanceを詳細化したため0点だった。3 Stage合算Action recall/precisionはともに14.81%。初回process-instance選択を検証するcheckpointが最優先の改善点である。

役割別3 Stage合算：

| role | API calls | LLM sec | Cost |
|---|---:|---:|---:|
| chief | 19 | 81.078 | $0.110832 |
| investigator | 43 | 141.969 | $0.147819 |
| sql_qa | 166 | 392.892 | $0.479599 |

## Word document processing

- group: `attack`
- model: `gpt-5.4-mini`
- chain: `s3_pt_01_word_document_processing`

| Stage | Action recall | Precision | Complete step | Critical | Order | Calls | Cost | Wall min |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stage1 | 4/6 (66.67%) | 4/6 (66.67%) | 1/2 (50.00%) | 0/2 (0.00%) | 1/1 (100.00%) | 45 | $0.249428 | 3.08 |
| stage2 | 4/6 (66.67%) | 4/9 (44.44%) | 1/2 (50.00%) | 0/2 (0.00%) | 1/1 (100.00%) | 73 | $0.347611 | 3.80 |
| stage3 | 4/6 (66.67%) | 4/15 (26.67%) | 1/2 (50.00%) | 0/2 (0.00%) | 1/1 (100.00%) | 57 | $0.250266 | 3.13 |

全StageでWINWORD→WINWORD /Embeddingは完全取得し、Action recall 66.67%、order 100%を安定して維持した。一方、msf.rtfのpathを取得しても文書openをprocess createとして候補化し、critical evidenceも採用できなかった。Stageが進むほどGold外の一時file/module activityが増え、precisionは66.67%→44.44%→26.67%へ低下した。検索不足ではなく、event-to-action正規化とcandidate admissionの問題である。

役割別3 Stage合算：

| role | API calls | LLM sec | Cost |
|---|---:|---:|---:|
| chief | 16 | 86.893 | $0.115614 |
| investigator | 33 | 115.063 | $0.140923 |
| sql_qa | 126 | 375.204 | $0.590768 |

## 横断考察

- 長いattack chainでは、API callを増やすだけでは後段recallは改善しなかった。未解決edgeを次の親へ昇格するtyped pivotが必要である。
- Wordの2-step chainでは順序は保てたが、取得済み文書open証拠をsubject/operation/objectへ正規化できず、完全stepとcritical evidenceを失った。一方、Discordの2-step chainはStage 3で出力順を逆転した。
- 誤ったprocess instanceを最初に選ぶと、Stage 2/3の追加探索が誤系列を精緻化した。初回pivot後のanchor再検証が必要である。
- Candidate precision低下は、幻覚だけでなく、観測済みだがGold外のfile/module activityを主要chainへ昇格したことでも発生した。
- 全4ケースでcritical evidenceは0%だった。行動内容の復元とcanonical row/action/targetの証拠束縛を別モジュールとして改善すべきである。

## 監査

- case summary audit: PASS
- 各caseのrun数: 3
- 4 caseの分母合計は正式overallと一致
- 外部judge API使用: false

機械可読JSON：`docs\current_experiment\normal_attack_full_ledger_pilot05_case_summary_20260730.json`
