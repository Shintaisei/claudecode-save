# ATLAS v2 attack8 frontier-closure pilot 正式結果

作成日: 2026-07-29  
result root: `docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01`

## 1. 結論

未解決frontierを再確認する修正後、同一2ユースケース・3 Stage・2モデルの有効12 runでは、修正前の同一条件より復元率が明確に上がった。

- Action recall: 48/198 = 24.24% → 85/198 = **42.93%**（+18.69 pp）
- Behavior-step recall: 12/66 = 18.18% → 23/66 = **34.85%**（+16.67 pp）
- Critical evidence: 16/66 = 24.24% → 34/66 = **51.52%**（+27.27 pp）
- Order recall: 7/54 = 12.96% → 9/54 = **16.67%**（+3.70 pp）
- Candidate precision: 48/98 = 48.98% → 85/191 = **44.50%**（-4.48 pp）

したがって、frontier-closure修正は「1論点で止まる」問題を緩和し、後続stepとcritical evidenceの取得を増やした。一方、候補slotが98から191へ約1.95倍になり、supporting evidenceの過剰列挙、重複、近傍行動の混入も増えた。改善は有効だが、長いchainの順序復元と候補選別は未解決である。

全体実験へのgateは **HOLD** とする。理由は、(1) `gpt-5.5` 6件がAPI 429 `insufficient_quota`で未実行、(2) Stage/ケース単位では非単調な悪化が残る、(3) Order recallが16.67%に留まるためである。既存12件は再実行せず、quota回復後に別versioned rootで`gpt-5.5` 6件だけを実行してgateを再判定する。

## 2. 実行状態

| モデル | 計画 | 有効run | 状態 |
|---|---:|---:|---|
| `gpt-4.1-mini` | 6 | 6 | errorなし、output valid JSON |
| `gpt-5.4-mini` | 6 | 6 | errorなし、output valid JSON |
| `gpt-5.5` | 6 | 0 | 全6件が429 `insufficient_quota`、`output_text=null` |

`gpt-5.5`の失敗成果物は保持し、上書き・削除・自動再試行していない。

有効12件では、`max_investigations/max_questions/max_queries=null`、
`agent_call_limit_policy=unbounded_by_experiment`、
`frontier_closure_policy=observed_unresolved_frontier_review_v1`を確認した。
Stage 3の初期入力はhost/process/timestampのみであり、CBC alert summary可視行は0件だった。
最終出力内の`supporting_alert_evidence`は3行あったが、モデルが一次telemetryから自発的に構成した補助記述であり、初期alert summaryの露出ではない。hidden alert mappingは採点していない。

## 3. 採点方式と監査

OpenAI judge APIおよびAPI judge scorerは使用していない。pilotとして単一Codex reviewを行い、次のv5 atomic rubricを適用した。

- Actionはsubject / operation / objectの3 component
- PIDは非採点
- hidden alert mappingは非採点
- Critical evidenceはActionと別判定
- OrderはGold隣接pair単位
- 1 candidate claimは最大1 Gold stepにだけ対応
- Gold Action hitは、included TP candidate slotの一意な`matched_gold_item_id`からのみ導出
- 重複componentはTPにせずcandidate FP

決定論的監査はPASSした。

| 監査項目 | 結果 |
|---|---:|
| review row | 12/12 |
| Action固定分母 | 198/198 |
| Candidate固定分母 | 191/191 |
| Behavior-step固定分母 | 66/66 |
| Critical evidence固定分母 | 66/66 |
| Order pair固定分母 | 54/54 |
| Gold 1 / TPなし | 0 |
| TP / Gold 0 | 0 |
| duplicate TP | 0 |
| candidate claimの複数Gold対応 | 0 |

run hash、Gold hash、全Gold item、全candidate slot、全order pairはscore rootに固定した。

## 4. モデル別の正式精度

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 38/99 = **38.38%** | 38/84 = **45.24%** | 10/33 = **30.30%** | 15/33 = **45.45%** | 3/27 = **11.11%** |
| `gpt-5.4-mini` | 47/99 = **47.47%** | 47/107 = **43.93%** | 13/33 = **39.39%** | 19/33 = **57.58%** | 6/27 = **22.22%** |
| **有効12件** | **85/198 = 42.93%** | **85/191 = 44.50%** | **23/66 = 34.85%** | **34/66 = 51.52%** | **9/54 = 16.67%** |

`gpt-5.4-mini`はAction、完全step、critical、orderで`gpt-4.1-mini`を上回った。Precisionだけは`gpt-4.1-mini`が1.31 pp高いが、両モデルとも44～45%であり、候補の半数以上はGold外だった。

## 5. Stage別

| Stage | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 30/66 = **45.45%** | 30/58 = **51.72%** | 8/22 = **36.36%** | 12/22 = **54.55%** | 3/18 = **16.67%** |
| Stage 2 | 22/66 = **33.33%** | 22/58 = **37.93%** | 6/22 = **27.27%** | 10/22 = **45.45%** | 1/18 = **5.56%** |
| Stage 3 | 33/66 = **50.00%** | 33/75 = **44.00%** | 9/22 = **40.91%** | 12/22 = **54.55%** | 5/18 = **27.78%** |

Stage 3がAction、完全step、orderで最良になった。これはalert summaryの利用ではなく、一次telemetryと追加frontier追跡による。一方でStage 2は候補数を増やした割にchain統合が弱く、全指標でStage 1/3を下回った。

## 6. モデル・Stage・ユースケース別

| モデル | Stage | ユースケース | Action | Precision | 完全step | Critical | Order |
|---|---|---|---:|---:|---:|---:|---:|
| 4.1-mini | 1 | Word document | 5/6 = 83.33% | 5/11 = 45.45% | 1/2 = 50.00% | 2/2 = 100.00% | 0/1 = 0.00% |
| 4.1-mini | 1 | mshta C1 | 8/27 = 29.63% | 8/15 = 53.33% | 2/9 = 22.22% | 3/9 = 33.33% | 0/8 = 0.00% |
| 4.1-mini | 2 | Word document | 3/6 = 50.00% | 3/11 = 27.27% | 1/2 = 50.00% | 2/2 = 100.00% | 0/1 = 0.00% |
| 4.1-mini | 2 | mshta C1 | 8/27 = 29.63% | 8/14 = 57.14% | 2/9 = 22.22% | 3/9 = 33.33% | 1/8 = 12.50% |
| 4.1-mini | 3 | Word document | 0/6 = 0.00% | 0/15 = 0.00% | 0/2 = 0.00% | 0/2 = 0.00% | 0/1 = 0.00% |
| 4.1-mini | 3 | mshta C1 | 14/27 = 51.85% | 14/18 = 77.78% | 4/9 = 44.44% | 5/9 = 55.56% | 2/8 = 25.00% |
| 5.4-mini | 1 | Word document | 5/6 = 83.33% | 5/17 = 29.41% | 1/2 = 50.00% | 2/2 = 100.00% | 1/1 = 100.00% |
| 5.4-mini | 1 | mshta C1 | 12/27 = 44.44% | 12/15 = 80.00% | 4/9 = 44.44% | 5/9 = 55.56% | 2/8 = 25.00% |
| 5.4-mini | 2 | Word document | 6/6 = 100.00% | 6/27 = 22.22% | 2/2 = 100.00% | 2/2 = 100.00% | 0/1 = 0.00% |
| 5.4-mini | 2 | mshta C1 | 5/27 = 18.52% | 5/6 = 83.33% | 1/9 = 11.11% | 3/9 = 33.33% | 0/8 = 0.00% |
| 5.4-mini | 3 | Word document | 6/6 = 100.00% | 6/18 = 33.33% | 2/2 = 100.00% | 2/2 = 100.00% | 0/1 = 0.00% |
| 5.4-mini | 3 | mshta C1 | 13/27 = 48.15% | 13/24 = 54.17% | 3/9 = 33.33% | 5/9 = 55.56% | 3/8 = 37.50% |

## 7. 修正前とのpaired比較

比較対象は、48-run baseline内の同一2ユースケース、同一Stage、同一2モデルである。

| モデル | 指標 | 修正前 | 修正後 | 差 |
|---|---|---:|---:|---:|
| 4.1-mini | Action | 26/99 = 26.26% | 38/99 = 38.38% | +12.12 pp |
| 4.1-mini | Precision | 26/54 = 48.15% | 38/84 = 45.24% | -2.91 pp |
| 4.1-mini | 完全step | 7/33 = 21.21% | 10/33 = 30.30% | +9.09 pp |
| 4.1-mini | Critical | 8/33 = 24.24% | 15/33 = 45.45% | +21.21 pp |
| 4.1-mini | Order | 2/27 = 7.41% | 3/27 = 11.11% | +3.70 pp |
| 5.4-mini | Action | 22/99 = 22.22% | 47/99 = 47.47% | +25.25 pp |
| 5.4-mini | Precision | 22/44 = 50.00% | 47/107 = 43.93% | -6.07 pp |
| 5.4-mini | 完全step | 5/33 = 15.15% | 13/33 = 39.39% | +24.24 pp |
| 5.4-mini | Critical | 8/33 = 24.24% | 19/33 = 57.58% | +33.33 pp |
| 5.4-mini | Order | 5/27 = 18.52% | 6/27 = 22.22% | +3.70 pp |

Stage 1とStage 3の改善が大きい。Stage 2は非単調で、4.1-miniのActionが15/33から11/33へ、5.4-miniのOrderが2/9から0/9へ悪化した。frontier修正は探索範囲を広げるが、毎runのGold chainへの収束を保証しない。

## 8. どこが取れていないか

### 8.1 Word document processing

Goldは次の2 stepである。

1. `WINWORD.EXE`が`C:\Users\aalsahee\Downloads\s3take2\msf.rtf`を開く
2. `WINWORD.EXE`が別の`WINWORD.EXE`を子プロセスとして起動する

主な失点は、証拠取得より最終表現にある。

- 4.1-mini Stage 1は文書pathとWord子プロセスを取得したが、文書openを`file_write`として出力したためoperationを失い、step順も逆転した。
- 4.1-mini Stage 2は文書openを完全復元したが、Word子プロセスedgeをevidenceに保持しただけで独立stepに昇格しなかった。
- 4.1-mini Stage 3は26回の`investigate_lead`を呼んだにもかかわらず、対象5分窓外のDNS/収集系近傍行動へ逸脱し、全componentを失った。
- 5.4-mini Stage 1は文書openを完全復元し、子Wordのsubject/operationも取ったがobject slotを落とした。
- 5.4-mini Stage 2/3は両stepの全componentを取ったが、子プロセスを文書openより先に並べたためOrderを失った。Stage 2ではsupporting file列挙と重複claimによりprecisionが22.22%まで低下した。

このケースでは「ログを正しくつなげれば推論可能」という認識でよい。Gold component自体は複数runで100%取得できており、残る失点はoperation正規化、独立step化、順序の最終serializationである。

### 8.2 mshta C1

Goldは次の9 stepである。

`svchost → mshta → 8080 → PowerShell → PowerShell → 8443 → cmd → payload → payload → 9999`

ただし、矢印はprocess起動とnetwork接続を混在させた概略であり、正式採点は各Gold stepのsubject/operation/objectで行う。

共通して弱いのは長系列の両端である。

- 前端: `svchost→mshta`のsubjectと`mshta→8080`
- 後端: `PowerShell→8443`、`cmd→payload`、`payload→payload`、`payload→9999`

4.1-mini Stage 3はfrontier追跡により、PowerShell self-spawn、8443、cmd後のpayload実行、payload self-spawnまで到達し、Action 14/27、precision 14/18になった。しかし`mshta→PowerShell`、`PowerShell→cmd`、9999を独立stepとして出力できず、連続orderは2/8だった。

5.4-mini Stage 3は8080と前半process frontierを取り、S01→S02→S03→S04の3隣接pairを復元した。一方、8443以降を追わず、`cmd→payload→payload→9999`をまとめて失った。つまり4.1-miniは後半寄り、5.4-miniは前半寄りの部分chainを返し、どちらも全chainを閉じていない。

Stage 2の5.4-miniは典型的な早期停止である。`svchost→mshta`のoperation/object、`mshta→PowerShell`のcritical evidence、PowerShell self-spawnは得たが、主語正規化と独立claim化に失敗して2 stepで終了した。Candidate precisionは83.33%でもAction recallは18.52%であり、「少数の正しい候補」だけでは長系列復元として不足する。

## 9. 原因をモデル・プロンプト・アーキテクチャへ分解

### モデル

- 4.1-miniは6 runで111 lead、平均18.5回。探索量は多いが、Stage 3 Wordのように近傍行動へ漂流しやすい。
- 5.4-miniは6 runで23 lead、平均3.83回。修正前の1 lead偏重は緩和したが、S4 Stage 2のような早期停止は残る。
- 5.4-miniは取得したcomponentの統合が概ね良いが、順序反転と後半frontierの見落としが残る。

### プロンプト／出力契約

- supporting evidenceを多く保持する指示はrecallを上げる一方、それを`code_sequence`へ昇格するadmission条件が弱く、unsupported FP 94、wrong-component FP 6、duplicate FP 6を生んだ。
- subject/operation/objectを必須slotとして最終検査する仕組みがなく、S01/S03のsubject欠落やWord子プロセスobject欠落が残った。
- Gold順を知らなくても、各claimの観測timestampと因果edgeから局所順序を検証できるが、最終JSON直前のadjacency検査がない。

### アーキテクチャ

- `observed_unresolved_frontier_review_v1`は有効で、leadを増やし、Action/step/criticalを大幅に改善した。
- ただしfrontierは「未解決edgeの存在」を再確認するだけで、全観測edgeを一つのtyped chain ledgerへ統合する機構ではない。
- 終了条件がfrontier単位であり、chain先頭・末尾・中間のcoverage holeを体系的に検出しない。
- SQL guardは8/12 runでprovenance記録済み、発動0件だった。今回の精度差はSQL scale guardによる打切りではない。先行完了4件はguard provenance導入前だが、完了済みrunを再実行しない方針に従い保持した。

## 10. 改善軸

次の改善は固定回数制限ではなく、状態ベースで行う。

1. Chiefにtyped chain ledgerを持たせ、各edgeを`subject / operation / object / time / evidence / predecessor / successor`で一意管理する。
2. 最終化前に、観測済みprocess/network edgeの未採用frontierだけでなく、chain内部のcoverage holeを検査する。
3. candidate admission gateを追加し、一次証拠と因果edgeの両方がない近傍行動はsupporting evidenceへ隔離する。
4. 同一Gold相当componentの重複claimをcollapseし、precision分母の膨張を抑える。
5. timestampとparent-child/network actorを使う局所order validatorを追加する。
6. モデル別に停止方針を分けず、unresolved frontierとcoverage holeが0になるまで続ける。ただし同一lead反復はfingerprintで停止する。

## 11. 調査行動・token

| モデル | lead call | unresolved frontier section | investigator question | input token | output token |
|---|---:|---:|---:|---:|---:|
| 4.1-mini | 111 | 115 | 193 | 499,224 | 31,306 |
| 5.4-mini | 23 | 22 | 20 | 180,873 | 37,880 |
| **合計** | **134** | **137** | **213** | **680,097** | **69,186** |

run artifactには価格または`estimated_cost_usd`が保存されていないため、正式な実測costは算出不能である。tokenはrun artifactのusageを合算した。価格表を後付けして推定costを出す場合は、実測costと区別して別フィールドへ記録する必要がある。

## 12. 成果物

- score root: `docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01/scores_codex_frontier_pilot_single_review_v1`
- atomic review: `codex_review1_v5_atomic.jsonl`
- aggregate: `formal_aggregate_v1.json`
- model/stage/case metrics: `metrics_by_model_stage_case_v1.json`
- run/trace audit: `trace_and_runtime_audit_v1.json`
- deterministic audit: `deterministic_audit_v1.json`
- machine-readable report: `docs/current_experiment/atlasv2_attack8_frontier_pilot_12valid_codex_results_20260729.json`

