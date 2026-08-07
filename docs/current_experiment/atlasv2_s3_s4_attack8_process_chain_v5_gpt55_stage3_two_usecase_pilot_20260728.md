# ATLAS v2 attack8 process-chain v5 GPT-5.5 Stage 3・2ユースケースpilot

作成日: 2026-07-28  
判定: **run・Codex採点・決定論的監査PASS**

## 1. 実験条件

`gpt-5.5`を、既存の`gpt-4.1-mini`・`gpt-5.4-mini` pilotと同じ2ケースへ適用した。

| 項目 | 設定 |
|---|---|
| Stage | Stage 3のみ |
| 初期入力 | host、focus process、timestamp |
| 対象ケース | S3-1 Word文書処理、S4-3 mshta長系列 |
| 時間窓 | ケースごとの固定5分窓 |
| CBC alert summary | 非表示。一次テレメトリのみ利用可能 |
| Gold | process-chain v5正式Gold |
| Agent呼び出し | `max_investigations/max_questions/max_queries=null`、`agent_call_limit_policy=unbounded_by_experiment` |
| 出力上限 | 24,576 token |
| 採点 | Codex単一pilot review＋決定論的監査。OpenAI judge API不使用 |
| rubric | subject/operation/object、critical evidence別診断、隣接order、candidate precision |
| 非採点 | PID、hidden alert mapping、攻撃ラベルの推測 |

2/2 runはerrorなし、`output_text`はvalid JSON、Stage 3から可視のCBC alert summaryは0行だった。

## 2. 採点結果

### 2.1 全体

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-5.5` | 12/33 = **36.36%** | 12/21 = **57.14%** | 3/11 = **27.27%** | 4/11 = **36.36%** | 3/9 = **33.33%** |

Behavior-stepは、同一Gold stepのsubject・operation・objectがすべて取れた場合だけ1 hitとした。Action hitはcandidate TP slotの`matched_gold_item_id`から決定論的に導出し、Gold側とcandidate側の不整合は0件だった。

### 2.2 ケース別

| ケース | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| S3-1 Word | 4/6 = **66.67%** | 4/6 = **66.67%** | 1/2 = **50.00%** | 1/2 = **50.00%** | 1/1 = **100.00%** |
| S4-3 mshta | 8/27 = **29.63%** | 8/15 = **53.33%** | 2/9 = **22.22%** | 3/9 = **33.33%** | 2/8 = **25.00%** |

## 3. 同一2ケースでのモデル比較

Action、precision、critical evidence、orderは既存pilotのCodex判断をそのまま使用した。Behavior-stepだけは、旧pilot報告が「一部componentでも対応したGold step」を数えていたため、今回の正式v5定義である「3 componentすべてhit」へ再計算した。

| モデル | Action recall | Candidate precision | Behavior-step recall（atomic再計算） | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 2/33 = **6.06%** | 2/17 = **11.76%** | 0/11 = **0.00%** | 1/11 = **9.09%** | 0/9 = **0.00%** |
| `gpt-5.4-mini` | 10/33 = **30.30%** | 10/30 = **33.33%** | 2/11 = **18.18%** | 4/11 = **36.36%** | 2/9 = **22.22%** |
| `gpt-5.5` | 12/33 = **36.36%** | 12/21 = **57.14%** | 3/11 = **27.27%** | 4/11 = **36.36%** | 3/9 = **33.33%** |

2ケースに限れば、`gpt-5.5`は`gpt-5.4-mini`よりAction、precision、完全step、orderが上がった。Critical evidenceは同率だった。ただしn=2のpilotなので、母集団性能の有意差とは扱わない。

## 4. 内部調査ログ

### 4.1 S3-1 Word

- 所要時間: 約16分28秒
- Chiefの`investigate_lead`: 1回
- Investigatorが展開したQA質問: 6件
- 最終candidate step: 2件
- top-level usage: input 25,167、output 16,949、合計42,116 token

QAは次の順に展開された。

1. 起点付近の`winword.exe`とPID/PPID/process GUIDの特定
2. 観測した2つのWordプロセス間の親子edge
3. 同じWordに接続するファイル操作
4. 同じWordに接続するレジストリ操作
5. network/DNS
6. CBC alert rowの有無

起点時刻14:31では0件だったため、14:33:17～14:33:20へ近傍探索し、`msf.rtf`を含むWord command line、Word子プロセス、ファイル操作を発見した。したがって長時間化の中心は、1回のChief tool callの中で6系統のQAとSQL/要約を直列に処理し、さらに長い調査要約と最終JSONを生成したことにある。

失点は検索不足より**証拠から行動表現への変換**で起きた。Gold S01は「WINWORD.EXEが`msf.rtf`を開いた」だが、出力S1は`process_create`、objectはWord processだった。command lineには`msf.rtf`が存在するためsubjectのみhitとし、operationとobjectはmissとした。S02のWord→子Wordは3 componentとも正解だった。

### 4.2 S4-3 mshta

- 所要時間: 約14分54秒
- Chiefの`investigate_lead`: 1回
- Investigatorが展開したQA質問: 5件
- 最終candidate step: 5件
- top-level usage: input 26,619、output 16,343、合計42,962 token

QAは次の順に展開された。

1. 起点前後10分の`mshta.exe`インスタンス列挙
2. PID 4724 / process GUIDに紐づく全activity
3. 親がmshta PID 4724であるchild process
4. `10.193.66.115`に対応するDNS
5. mshtaに対応するCBC alert row

この調査により、`svchost.exe`→`mshta.exe`、mshta→`10.193.66.115:8080`、mshta→`powershell.exe`までは一次証拠付きで発見した。一方、QA 3の条件が「親=mshta」に固定され、発見したPowerShell PID 2976を新しい親として再帰的に追う追加pivotを行わなかった。

そのため次の6 Gold step、計18 action componentを丸ごと失った。

1. PowerShell→別PowerShell
2. PowerShell→8443/tcp
3. PowerShell→cmd.exe
4. cmd.exe→payload.exe
5. payload.exe→別payload.exe
6. payload.exe→9999/tcp

さらに、Goldの主要process chainには含めないHTAキャッシュファイル操作とPowerShell終了を独立stepとして出したため、各3 slot、合計6 slotがoverclaimになった。起点のmshta生成もsubjectを`svchost.exe`ではなく`mshta.exe`としたため、因果edgeの向きで1 slot失った。

## 5. なぜ長いのに後段を調べなかったか

「実験上の呼び出し上限に達した」ためではない。3種類の上限はすべて`null`で、実験側のAgent call policyはunboundedだった。

実際には次の組合せである。

- Chiefは1件の広いleadを作る。
- Investigatorはその1件を5～6個のQAへ分解して直列実行する。
- QA結果を長いToolMessageへ統合する。
- Chiefはその結果から長い中間JSONと最終JSONを生成する。
- 最低1回の調査を終えれば終了できるため、発見した新しい子プロセスを再度`investigate_lead`へ渡す強制条件がない。

つまり、時間は既存leadの横方向の網羅に使われ、chainを下流へ伸ばす縦方向の再帰pivotには使われなかった。S4では検索時間窓は01:10まで確保されており、5分窓不足が主因ではない。filterがPID 4724/mshtaへ固定されたことと、Chiefの停止判断が主因である。

現行run artifactはQAごとのSQL開始・終了時刻、DB実行時間、row数、個別model usageを保存していない。このため約15分の厳密な秒単位内訳は復元できない。今後は`lead_id`、`question_id`、SQL start/end、row count、model start/end、usage、発見した次pivot、停止理由をstreaming JSONLで保存する必要がある。

## 6. 改善軸

モデル性能だけでなく、次のモジュール別に改善を分ける。

| モジュール | 今回の観測 | 改善 |
|---|---|---|
| Lead生成 | 1件の広いleadに依存 | 起点確認と下流展開を別leadへ分離 |
| Investigator | 同一PIDの横断調査はできる | 新しいchild PIDごとにfrontierへ追加 |
| QA/SQL | mshta周辺証拠は取得できる | descendant edge queryを再帰化 |
| 停止判定 | PowerShell発見後も1回で終了 | 未探索child、未閉包network edgeがあれば停止不可 |
| Evidence→step変換 | 文書pathを見たがprocess_create化 | subject/operation/object候補をevent typeから正規化 |
| 最終統合 | HTA file、terminationをGold相当step化 | 主要process chainとsupporting evidenceを分離 |
| Trace/計測 | 内部QA時間を分解できない | QA/SQL/model単位のstreaming traceを保存 |

## 7. token・cost

| ケース | input | output | total | 推定cost |
|---|---:|---:|---:|---:|
| S3-1 Word | 25,167 | 16,949 | 42,116 | USD 0.634305 |
| S4-3 mshta | 26,619 | 16,343 | 42,962 | USD 0.623385 |
| **合計** | **51,786** | **33,292** | **85,078** | **USD 1.257690** |

`clouseau_api_costs.csv`は実行時のprice tableに`gpt-5.5`がなく0 USDを記録した。そのためrepository内の実験price table（input USD 5/M、cached input USD 0.5/M、output USD 30/M）で推定した。top-level usageに内部sub-agentの全usageが含まれる保証はないため、costは保守的な記録値ベース推定である。

## 8. 結論

この2ケースでは`gpt-5.5`への変更で、行動componentの回収と余分な候補の抑制は改善した。一方、長いS4 chainの後半6 stepは依然として未取得であり、モデル変更だけでは解消していない。

したがって、**「モデルを強くすると一部は上がるが、主ボトルネックは再帰pivotと停止条件にも残る」**と判断する。次の比較実験ではGold、時間窓、採点を固定したまま、frontier型の下流展開と停止条件だけを変更するのが妥当である。

## 9. 成果物

- run root: `docs/current_experiment/results_2026-07-28/atlasv2_s3_s4_attack8_process_chain_v5_formal/gpt55_stage3_two_usecase_pilot_01`
- validated Codex review: `scores_codex_gpt55_stage3_two_case_v1/validated_reviews/review1.jsonl`
- deterministic audit: `scores_codex_gpt55_stage3_two_case_v1/deterministic_audit_v1.json`
- machine-readable summary: `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_gpt55_stage3_two_usecase_pilot_20260728.json`
