# ATLAS v2 attack8 process-chain v5：2モデル正式実験結果

作成日：2026-07-28  
対象：`gpt-4.1-mini`、`gpt-5.4-mini`  
実験単位：8ユースケース × 3 Stage × 2モデル = 48 run

## 1. 実験目的

正常由来行動と攻撃シナリオ由来行動を共通のprocess-level行動表現で扱い、入力情報を段階的に削減したときに、マルチAgentシステムが証拠付き行動列をどの程度復元できるかを評価する。

評価対象は、subject/action/object、3要素すべてを満たすbehavior step、隣接Gold step間の順序、critical evidence、Gold外の近傍行動を含む過剰接続である。PIDそのもの、非提示アラートとの対応推測、ATT&CKラベルは採点しない。

## 2. ユースケース

| ID | シナリオ | 対象 |
|---|---|---|
| S3-1 | S3 | Word文書処理 |
| S3-2 | S3 | regsvr32 remote SCT |
| S3-3 | S3 | regsvr32からC2までの長系列 |
| S3-4 | S3 | PowerShell中間起点 |
| S4-1 | S4 | Word W1 |
| S4-2 | S4 | Word W3 |
| S4-3 | S4 | mshtaからpayload・C2まで |
| S4-4 | S4 | PowerShell C1 |

Goldは8 chain・43 behavior stepである。各StageでAction要素129、critical evidence 43、隣接order pair 35を固定分母とする。

## 3. 実験条件

| 条件 | 初期手掛かり | 調査可能情報 |
|---|---|---|
| Stage 1 | アラート、host、focus process、time scope | アラート要約と一次テレメトリ |
| Stage 2 | host、focus process、time scope | 調査中にアラート要約を発見可能。一次テレメトリも利用可能 |
| Stage 3 | host、focus process、time scope | アラート要約は非表示。一次テレメトリのみ |

Agent呼出し回数は実験側で制限していない。全runで`max_investigations/max_questions/max_queries=null`、`agent_call_limit_policy=unbounded_by_experiment`を確認した。

## 4. 正式評価方法

正式採点はCodexのみで行い、OpenAI judge APIおよびAPI scorerは使用していない。

1. 2名のCodex reviewerが48件を互いの判定を見ずに採点した。
2. Candidateの各subject/action/object slotを、同一Gold stepの同種Gold itemへ対応付けた。
3. Action recallは、TP candidate slotの`matched_gold_item_id`によるunique Gold coverageから決定論的に算出した。
4. Candidate precisionはliteral TP slot数を固定candidate slot数で除した。
5. Behavior-step recallはsubject/action/objectの3要素すべてがhitしたstepだけを分子とした。
6. Critical evidenceとorder pairは別に二値判定した。
7. Candidate 29、critical evidence 12、order pair 6の計47不一致項目だけを、両reviewを見ない第三Codex reviewerが判定し、2-of-3で裁定した。

初期のv1-v4採点ではGold action scoreとcandidate TPを独立入力できたため、review1に74件の`Gold hit / candidate非TP`矛盾が生じた。旧スコアは診断履歴として保持するが、正式値には採用しない。v5 atomic-alignmentではこの二重入力を廃止し、最終48件で`gold1_without_tp=0`、`tp_gold0=0`を確認した。

## 5. 実行結果

- 完了run：48/48
- Stage別：16/16/16
- error：0
- invalid output JSON：0
- unresolved / stale / rejected：0 / 0 / 0
- 正式採用：48/48

| モデル | run | Input token | Output token | Total token | Code step | Empty run | Cost (USD) |
|---|---:|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 24 | 898,659 | 79,571 | 978,230 | 77 | 3 | 0.486777 |
| `gpt-5.4-mini` | 24 | 237,277 | 90,203 | 327,480 | 63 | 1 | 0.583868 |
| **合計** | **48** | **1,135,936** | **169,774** | **1,305,710** | **140** | **4** | **1.07064845** |

## 6. 正式スコア

### 6.1 モデル別

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 98/387 = **25.32%** | 98/228 = **42.98%** | 19/129 = **14.73%** | 21/129 = **16.28%** | 13/105 = **12.38%** |
| `gpt-5.4-mini` | 84/387 = **21.71%** | 84/186 = **45.16%** | 17/129 = **13.18%** | 27/129 = **20.93%** | 11/105 = **10.48%** |
| **全体** | **182/774 = 23.51%** | **182/414 = 43.96%** | **36/258 = 13.95%** | **48/258 = 18.60%** | **24/210 = 11.43%** |

### 6.2 Stage別

| Stage | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 47/258 = **18.22%** | 47/99 = **47.47%** | 6/86 = **6.98%** | 2/86 = **2.33%** | 6/70 = **8.57%** |
| Stage 2 | 72/258 = **27.91%** | 72/147 = **48.98%** | 18/86 = **20.93%** | 24/86 = **27.91%** | 12/70 = **17.14%** |
| Stage 3 | 63/258 = **24.42%** | 63/168 = **37.50%** | 12/86 = **13.95%** | 22/86 = **25.58%** | 6/70 = **8.57%** |

### 6.3 ユースケース別

| ユースケース | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| S3-1 Word文書処理 | 50.00% | 50.00% | 41.67% | 33.33% | 33.33% |
| S3-2 regsvr32 remote SCT | 38.89% | 25.93% | 22.22% | 33.33% | 33.33% |
| S3-3 regsvr32長系列 | 19.44% | 44.44% | 2.08% | 16.67% | 11.90% |
| S3-4 PowerShell中間起点 | 21.43% | 56.25% | 16.67% | 21.43% | 8.33% |
| S4-1 Word W1 | 26.39% | 44.19% | 4.17% | 16.67% | 11.11% |
| S4-2 Word W3 | 33.33% | 37.50% | 33.33% | 5.56% | 16.67% |
| S4-3 mshta C1 | 18.52% | 48.39% | 12.96% | 22.22% | 10.42% |
| S4-4 PowerShell C1 | 16.67% | 63.64% | 11.90% | 9.52% | 2.78% |

## 7. 詳細失敗分析

| モデル | Action miss | Incomplete step | Critical miss | Order miss | FP slot |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 289 | 110 | 108 | 92 | 130 |
| `gpt-5.4-mini` | 303 | 112 | 102 | 94 | 102 |

支配的な原因は次のとおりである。

1. **後続pivotの欠落**：入口プロセスまたは最初の通信を取得した後、子プロセス、payload、後段C2へ調査を継続しない。
2. **因果edgeとatomic componentの圧縮**：親子関係や通信先を取得しても、最終JSONで複数イベントを1つの曖昧なstepへまとめる。
3. **取得証拠の最終出力への未反映**：正しいCBC rowやprocess edgeを発見しても、最終`code_steps`に採用しない。
4. **近傍telemetryの過剰接続**：cache、registry、temporary file、module accessを対象chainの独立stepとして残す。
5. **停止判断**：`gpt-5.4-mini`は24件中21件で1回の`investigate_lead`後に停止し、出力は比較的保守的だがchain coverageが不足した。

`gpt-4.1-mini`はAction recallが3.61ポイント高い一方、FP slotが130件あり、近傍イベントの混入が多い。`gpt-5.4-mini`はCandidate precisionが2.18ポイント高いが、後続pivot欠落によるAction missが156 component、atomic/causal collapseが108 componentあり、長いattack chainを途中で止める。

代表例は次のとおりである。

- `gpt-4.1-mini` Stage 1 / S3-1：13回調査して文書・親子プロセス証拠を取得したが、Wordの文書openと子Word生成edgeを最終列へ再構成できずAction 1/6。
- `gpt-4.1-mini` Stage 2 / S4-4：1回のinteractionで停止し、後続PowerShell・payload・通信を復元できなかった。
- `gpt-5.4-mini` Stage 2 / S3-1：toolが既入力timestampを再要求して検索が進まずAction 0/6。Gold欠陥ではなくpipeline interaction failureである。
- `gpt-5.4-mini` Stage 3 / S3-2：複数PID系列を混在させ25 FPを生じた。PID値自体は非採点だが、異なるactor/action/object edgeの接続は誤りとした。

## 8. Stageが単調に低下しない理由

Stage 2が最良だった。Stage 2はprocess/time anchorから開始しつつ、調査中にアラート要約を発見できるため、raw telemetryと検知コンテキストの両方を利用できた。Stage 1は明示アラートを持つが、アラート時刻・名称がGold chainの開始点より後方にあり、調査が検知付近へ偏るケースがあった。Stage 3はアラート要約を利用できず、一次telemetryのfield表現を直接解釈する必要があるため、exact queryのfalse negativeとedge統合失敗が増えた。

## 9. Goldと実験設定の妥当性

- 43 Gold stepはcanonical CBC row、timestamp、ACTION、targetへ追跡可能である。
- 今回のmissを説明する明確なGold欠陥は検出されなかった。
- PID identityとhidden alert mappingは正式採点から除外した。
- 低Recallの主因はGoldや時間窓ではなく、検索継続、edge構成、証拠選別、最終統合にある。
- `gpt-5.4-mini`について、原ログと矛盾することを確認できた明示的な創作は0件だった。unsupported claimは近傍telemetryの過剰接続またはtraceで再確認できないoverclaimとして保守的に分類した。

## 10. 正常行動復元との関係

正常23ケースと同じsubject/action/object、critical evidence、隣接order、candidate precisionを使用したため、失敗の種類を共通語彙で比較できる。攻撃では特に長い多段chain、Living off the Land、同名プロセス反復、後続C2 pivotが加わるため、正常系より後続pivot欠落と因果edge collapseが支配的になる。

ただし、正常系と本実験ではユースケース数、chain長、モデル、反復数が完全には一致しない。数値の直接差を攻撃有無だけの因果効果として解釈せず、共通rubric上の傾向比較として扱う。

## 11. 結論

現行システムは、攻撃chain内の個別要素を一部取得できるが、完全なprocess-level行動列としての復元性能は低い。全体Action recall 23.51%に対し、Behavior-step recallは13.95%、Order recallは11.43%である。改善対象は検索回数の増加ではなく、観測済みedgeを保持する構造化ledger、上下流pivotの終了条件、最終出力時のGold外近傍イベント除外と証拠採用である。

## 12. 正式成果物

- Formal aggregate：`scores_codex_manual_double_review_v5_atomic_alignment/formal_aggregate_v5.json`
- Formal ledger：`scores_codex_manual_double_review_v5_atomic_alignment/formal_adopted_reviews_v5.jsonl`
- Metrics：`scores_codex_manual_double_review_v5_atomic_alignment/metrics_by_model_stage_case_v5.json`
- Merge validation：`scores_codex_manual_double_review_v5_atomic_alignment/merge_validation_v5.json`
- Adjudication manifest：`scores_codex_manual_double_review_v5_atomic_alignment/adjudication_manifest_v5.json`
- `gpt-4.1-mini`詳細分析：`scores_codex_manual_double_review_v5_atomic_alignment/detailed_failure_analysis_gpt41_v1.json`
- `gpt-5.4-mini`詳細分析：`scores_codex_manual_double_review_v5_atomic_alignment/detailed_failure_analysis_gpt54_v1.json`

