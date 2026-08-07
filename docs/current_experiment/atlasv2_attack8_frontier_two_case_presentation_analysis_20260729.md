# ATLAS v2 attack8 frontier-closure 2ケース分析（研究発表用）

作成日: 2026-07-29  
対象: `s3_pt_01_word_document_processing`、`s4_pt_03_mshta_c1`  
主分析: frontier-closure修正後の`gpt-4.1-mini`・`gpt-5.4-mini`、3 Stage、12 run  
参考分析: 修正前の`gpt-5.5` Stage 3、2 run  

## 1. 発表で先に示す結論

このpilotが示した中心的な結果は、モデルが攻撃系列をまったく発見できないことではなく、次の3段階で情報を失っていることである。

1. **探索範囲の選択**: 正しいfrontierを追うrunと、近傍の無関係系列へ逸脱するrunがある。
2. **証拠からchainへの統合**: investigatorが正しい親子edgeやnetwork edgeを返しても、Chiefが独立したbehavior stepへ昇格できない。
3. **最終表現**: subject / operation / objectの役割、重複除去、隣接順序が崩れる。

frontier-closure修正により、2モデル合計のAction recallは24.24%から42.93%、完全step recallは18.18%から34.85%、Critical evidenceは24.24%から51.52%へ上昇した。一方、候補slotが98から191へ約1.95倍に増え、Candidate precisionは48.98%から44.50%へ低下した。Order recallは12.96%から16.67%への小幅改善に留まった。

したがって、修正は「追加探索」に成功したが、「正しいchainへ圧縮して順序付ける機構」は未完成である。

## 2. 実験条件と指標

- 2ユースケース × 3 Stage × 2モデル = 12 run
- `max_investigations/max_questions/max_queries=null`
- `agent_call_limit_policy=unbounded_by_experiment`
- `frontier_closure_policy=observed_unresolved_frontier_review_v1`
- Stage 3ではCBC alert summaryを非表示
- OpenAI judge APIは不使用
- Actionは各Gold stepのsubject / operation / objectの3 component
- Behavior-step hitは3 componentがすべて取得できた場合のみ
- Critical evidenceとOrderはActionと別に採点
- PIDとhidden alert mappingは非採点

Candidate precisionの分母は固定された「出力候補slot数」であり、Gold actionの分母とは異なる。このため、Action recallとCandidate precisionの分母が一致しないのは採点設計上の仕様である。

## 3. モデル×Stage別の精度

| モデル | Stage | Action recall | Candidate precision | 完全step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| 4.1-mini | 1 | 13/33 = **39.39%** | 13/26 = **50.00%** | 3/11 = **27.27%** | 5/11 = **45.45%** | 0/9 = **0.00%** |
| 4.1-mini | 2 | 11/33 = **33.33%** | 11/25 = **44.00%** | 3/11 = **27.27%** | 5/11 = **45.45%** | 1/9 = **11.11%** |
| 4.1-mini | 3 | 14/33 = **42.42%** | 14/33 = **42.42%** | 4/11 = **36.36%** | 5/11 = **45.45%** | 2/9 = **22.22%** |
| 5.4-mini | 1 | 17/33 = **51.52%** | 17/32 = **53.12%** | 5/11 = **45.45%** | 7/11 = **63.64%** | 3/9 = **33.33%** |
| 5.4-mini | 2 | 11/33 = **33.33%** | 11/33 = **33.33%** | 3/11 = **27.27%** | 5/11 = **45.45%** | 0/9 = **0.00%** |
| 5.4-mini | 3 | 19/33 = **57.58%** | 19/42 = **45.24%** | 5/11 = **45.45%** | 7/11 = **63.64%** | 3/9 = **33.33%** |

モデル全体では、5.4-miniがAction、完全step、Critical、Orderで4.1-miniを上回った。

| モデル | Action recall | Candidate precision | 完全step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| 4.1-mini | 38/99 = **38.38%** | 38/84 = **45.24%** | 10/33 = **30.30%** | 15/33 = **45.45%** | 3/27 = **11.11%** |
| 5.4-mini | 47/99 = **47.47%** | 47/107 = **43.93%** | 13/33 = **39.39%** | 19/33 = **57.58%** | 6/27 = **22.22%** |

ただし各セルは1 runであり、Stage間の非単調性も大きい。Stage 3が最良に見えることを、入力情報量の因果効果や母集団のモデル順位として解釈してはいけない。

## 4. ケース別の難しさ

2モデル・3 Stageを合算すると、短いWord chainと長いmshta chainで失敗の性質が異なる。

| ケース | Gold step | Action recall | Candidate precision | 完全step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| Word document | 2 | 25/36 = **69.44%** | 25/99 = **25.25%** | 7/12 = **58.33%** | 10/12 = **83.33%** | 1/6 = **16.67%** |
| mshta C1 | 9 | 60/162 = **37.04%** | 60/92 = **65.22%** | 16/54 = **29.63%** | 24/54 = **44.44%** | 8/48 = **16.67%** |

- Wordは中心証拠を見つけやすくrecallは高いが、一時ファイル、Recent、レジストリ、周辺プロセスを独立行動として出し、precisionが低い。
- mshtaは出力した候補の正しさは比較的高いが、9 stepの長いchainを端から端まで接続できず、recallが低い。
- 両ケースともOrder recallは16.67%であり、短いchainでも順序付けは自明ではなかった。

## 5. ケース1: Word document processing

### 5.1 Gold chain

| Gold step | 正解行動 |
|---|---|
| W1 | `WINWORD.EXE`が`C:\Users\aalsahee\Downloads\s3take2\msf.rtf`を開く |
| W2 | `WINWORD.EXE`が別の`WINWORD.EXE`を子プロセスとして起動する |

このケースではEquation Editor、regsvr32、PowerShell、DNS収集系列への観測済みedgeはGoldに存在しない。時刻が近いだけの系列を接続してはいけない。

### 5.2 component取得状況

凡例: `●` = subject / operation / objectをすべて取得、`△` = 一部componentのみ、`—` = 未取得。

| モデル・Stage | W1 文書open | W2 Word子プロセス | 正しい順序 |
|---|---:|---:|---:|
| 4.1-mini Stage 1 | △ | ● | — |
| 4.1-mini Stage 2 | ● | — | — |
| 4.1-mini Stage 3 | — | — | — |
| 5.4-mini Stage 1 | ● | △ | ● |
| 5.4-mini Stage 2 | ● | ● | — |
| 5.4-mini Stage 3 | ● | ● | — |

### 5.3 途中過程でできていたこと

- 4.1-mini Stage 1は、`msf.rtf`のpathとWord子プロセスを取得した。
- 4.1-mini Stage 2は、文書openの3 componentを完全に取得し、Word子プロセスのcritical evidenceも保持していた。
- 5.4-mini Stage 2/3は、`pid 5592`のWord、`msf.rtf`、`pid 3368`の同名子プロセスを調査結果内で直接接続した。
- Critical evidenceは12判定中10件取得できており、主要なログ行を探す能力自体は高かった。

### 5.4 途中過程から最終出力までに失ったもの

- 4.1-mini Stage 1は文書openを`file_write`と表現し、operationを誤った。
- 4.1-mini Stage 2はWord子プロセスedgeをevidenceには保持したが、独立した`code_step`へ昇格しなかった。
- 5.4-mini Stage 2/3は両stepを取得したが、子プロセス起動を文書openより先に並べ、Orderを失った。
- 5.4-miniは`Zone.Identifier`、Recent shortcut、`index.dat`、一時RTF、Officeレジストリなどを独立候補化し、完全取得と同時にprecisionを落とした。

### 5.5 4.1-mini Stage 3の探索逸脱

このrunは26回の`investigate_lead`を実行したが、最終的なAction hitは0だった。

1. 初期調査では`WINWORD.EXE /n ...\msf.rtf`と`WINWORD.EXE /Embedding`を発見していた。
2. PID 1604の`explorer.exe`へpivotした。
3. explorer配下の`start_dns_logs.bat`、`tshark.exe`、`dumpcap.exe`、`python -m SimpleHTTPServer`へ探索が拡大した。
4. 最終出力はexplorer、cmd、tshark、pythonの5 stepとなり、Wordの2 Gold stepをすべて失った。

これは検索回数不足ではなく、**局所Gold chainを固定するledgerがないために、共有親プロセスの別branchへ移動した探索ドリフト**である。

## 6. ケース2: mshta C1

### 6.1 Gold chain

| ID | 正解行動 |
|---|---|
| M1 | `svchost.exe` → `mshta.exe` |
| M2 | `mshta.exe` → `10.193.66.115:8080` |
| M3 | `mshta.exe` → `powershell.exe` |
| M4 | `powershell.exe` → 別の`powershell.exe` |
| M5 | `powershell.exe` → `ortrta.net / 10.193.66.115:8443` |
| M6 | `powershell.exe` → `cmd.exe` |
| M7 | `cmd.exe` → `payload.exe` |
| M8 | `payload.exe` → 別の`payload.exe` |
| M9 | `payload.exe` → `ortrta.net / 10.193.66.115:9999` |

### 6.2 component取得状況

| Gold | 4.1 S1 | 4.1 S2 | 4.1 S3 | 5.4 S1 | 5.4 S2 | 5.4 S3 |
|---|---:|---:|---:|---:|---:|---:|
| M1 svchost→mshta | — | — | △ | — | △ | △ |
| M2 mshta→8080 | — | — | — | — | — | ● |
| M3 mshta→PowerShell | ● | ● | — | ● | — | △ |
| M4 PowerShell→PowerShell | — | △ | ● | ● | ● | ● |
| M5 PowerShell→8443 | △ | — | ● | — | — | — |
| M6 PowerShell→cmd | ● | — | — | ● | — | ● |
| M7 cmd→payload | — | ● | ● | ● | — | — |
| M8 payload→payload | — | — | ● | — | — | — |
| M9 payload→9999 | — | — | — | — | — | — |

### 6.3 できていたこと

- 両モデルとも、runによっては`mshta → PowerShell → PowerShell/cmd → payload`の複数hopを一次telemetryから復元できた。
- 5.4-mini Stage 3は前半のM1〜M4を連続して取り、M1→M2→M3→M4の3隣接pairを正しく復元した。
- 4.1-mini Stage 3は後半寄りのM4、M5、M7、M8を完全取得した。
- 4.1-mini Stage 3のinvestigator結果には、`PowerShell pid 3820 → ortrta.net:8443`、payload作成、`cmd pid 2168 → payload pid 4184`、`payload pid 3652 → ortrta.net:9999`が現れていた。
- 5.4-mini Stage 3のinvestigator結果には、`svchost → mshta`、`mshta → 8080`、`mshta → PowerShell`、`PowerShell → PowerShell/cmd`が現れていた。

このため、ログを正しく連結できればchain推論は可能である、という認識は妥当である。

### 6.4 できていなかったこと

- どのrunも9 stepすべてを取得していない。
- M9の`payload → 9999`は全6 runで完全未取得だった。
- 5.4-mini Stage 3は前半M1〜M4に強いが、8443以降の後半chainを失った。
- 4.1-mini Stage 3は後半M4/M5/M7/M8を取ったが、M3の`mshta → PowerShell`とM6の`PowerShell → cmd`を独立stepとして正しく表現できなかった。
- 4.1-mini Stage 3の最終出力では`cmd.exe`をsubjectにしながらobjectを`payload.exe`としたため、調査結果にあった`PowerShell → cmd`のedgeが`cmd → payload`へ変換された。
- network edgeを発見しても、通信主体、port、process instanceの組合せが揃わずcomponent TPにならない場合があった。

### 6.5 Stage 2の早期停止例

5.4-mini Stage 2は3 leadで終了し、Candidate precisionは83.33%だったが、Action recallは18.52%、完全step recallは11.11%だった。

調査担当は初回に`svchost → mshta → 8080 → PowerShell`を報告し、後続PowerShellが未確認だと明示していた。しかし最終出力は実質2 stepに圧縮され、後続frontierを十分に追わなかった。これは「少数の正しい候補」による高precisionであり、長系列復元としては不十分である。

## 7. 探索量と探索効率

| モデル | lead call | input tokens | Action hit | 完全step hit | Action hit / lead |
|---|---:|---:|---:|---:|---:|
| 4.1-mini | 111 | 499,224 | 38 | 10 | **0.34** |
| 5.4-mini | 23 | 180,873 | 47 | 13 | **2.04** |

4.1-miniは5.4-miniの約4.83倍のleadと約2.76倍のinput tokenを使ったが、Action hitと完全step hitは少なかった。したがって、無制限探索だけでは性能は保証されず、frontierの優先順位付けとbranch抑制が必要である。

ただし、`Action hit / lead`は実験後の記述統計であり、lead追加の因果効果を直接測る指標ではない。

## 8. 修正前後で何が変わったか

| 指標 | 修正前 | frontier-closure修正後 | 差 |
|---|---:|---:|---:|
| Action recall | 48/198 = 24.24% | 85/198 = **42.93%** | **+18.69 pp** |
| Candidate precision | 48/98 = 48.98% | 85/191 = **44.50%** | **-4.48 pp** |
| 完全step recall | 12/66 = 18.18% | 23/66 = **34.85%** | **+16.67 pp** |
| Critical evidence | 16/66 = 24.24% | 34/66 = **51.52%** | **+27.27 pp** |
| Order recall | 7/54 = 12.96% | 9/54 = **16.67%** | **+3.70 pp** |

修正の効果は、追加証拠と完全stepの回収には明確に現れた。一方、候補の絞り込みと順序統合は改善が小さい。次の改善対象は「さらに検索すること」よりも、「取得済みedgeを一つのtyped chainへ統合すること」である。

## 9. GPT-5.5参考値の扱い

frontier-closure修正前のGPT-5.5 Stage 3・2ケースは次の結果だった。

| モデル・条件 | Action recall | Candidate precision | 完全step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| GPT-5.5、修正前Stage 3 | 12/33 = **36.36%** | 12/21 = **57.14%** | 3/11 = **27.27%** | 4/11 = **36.36%** | 3/9 = **33.33%** |
| GPT-5.4-mini、修正後Stage 3 | 19/33 = **57.58%** | 19/42 = **45.24%** | 5/11 = **45.45%** | 7/11 = **63.64%** | 3/9 = **33.33%** |

GPT-5.5旧pilotは各runが1 leadで停止しており、修正後5.4-miniとはアーキテクチャ条件が異なる。よってモデル順位の比較には使えない。ただし、修正後5.4-miniが修正前GPT-5.5を複数recall指標で上回ったことは、**モデル規模だけでなく探索制御が結果を大きく左右する**ことを示す方向的証拠になる。

同じfrontier-closure条件のGPT-5.5 6 runはquota不足で未完了であり、正式な3モデル比較は保留する。

## 10. 原因をモジュール別に分解

| モジュール | できていたこと | できていなかったこと | 改善軸 |
|---|---|---|---|
| Chief lead generation | 複数frontierを生成可能になった | 4.1で共有親の別branchへ拡散 | Gold非依存のrelevance score、branch budget、lead fingerprint |
| Investigator | 親子、file、networkの一次証拠を多数取得 | query条件によって「見つかった／見つからない」が揺れる | entity/PID/timeを固定したcanonical query template |
| Frontier controller | 1 lead停止を解消 | coverage holeの体系的検出がない | chain先頭・中間・末尾の未接続点をledgerから生成 |
| Evidence integration | investigator結果をChiefへ返却 | 正しいedgeを独立stepへ昇格できない | typed edge ledger: subject/action/object/time/evidence/predecessor/successor |
| Candidate admission | recallを大きく改善 | supporting row、重複、周辺行動が候補化 | 一次証拠＋因果edge必須、supporting-only区分 |
| Serialization | valid JSONを出力 | role反転、operation正規化、step順序が崩れる | schema直前validator、dedup、timestamp/edge order validator |
| Model | 5.4は少ないleadで高回収 | 4.1は探索ドリフト、5.4は早期停止 | モデル別停止規則ではなく同一coverage条件を強制 |

## 11. 研究発表で使える主張

### 主張1

> Frontier closureは攻撃系列のAction recallを24.24%から42.93%、Critical evidence recallを24.24%から51.52%へ改善したが、候補slotを約1.95倍に増やし、precisionを4.48ポイント低下させた。

### 主張2

> 失敗の中心は証拠検索だけではなく、検索済み証拠をsubject–operation–objectのtyped edgeへ統合し、隣接順序を保持して最終JSONへ変換する段階にある。

### 主張3

> 長いmshta系列では4.1-miniが後半、5.4-miniが前半を部分的に復元した。両者が取得した証拠を一つのchain ledgerへ統合できれば、単独runより広いcoverageが得られる。

### 主張4

> 4.1-miniは5.4-miniの約4.8倍のleadを使用したが、Action hitは少なかった。探索回数の無制限化ではなく、未接続frontierの優先順位付けと近傍branchの抑制が必要である。

## 12. 発表時の制約

- 各モデル×Stage×ケースは1 runであり、統計的なモデル順位は主張しない。
- Stage間差にはモデルの確率的変動が含まれる。
- GPT-5.5は同じ修正条件で未実行のため、3モデル比較は未完成。
- 今回の分析は2ケースのmechanism studyであり、攻撃8ケース全体への一般化は正式実験後に行う。
- Stage 3の結果はCBC alert summary非表示であり、hidden alert mappingは採点していない。

## 13. 参照成果物

- 正式結果: `docs/current_experiment/atlasv2_attack8_frontier_pilot_12valid_codex_results_20260729.md`
- machine-readable結果: `docs/current_experiment/atlasv2_attack8_frontier_pilot_12valid_codex_results_20260729.json`
- atomic review: `docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01/scores_codex_frontier_pilot_single_review_v1/codex_review1_v5_atomic.jsonl`
- aggregate: `docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01/scores_codex_frontier_pilot_single_review_v1/formal_aggregate_v1.json`
- trace audit: `docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01/scores_codex_frontier_pilot_single_review_v1/trace_and_runtime_audit_v1.json`
- GPT-5.5旧Stage 3 pilot: `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_gpt55_stage3_two_usecase_pilot_20260728.json`
