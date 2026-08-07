# ATLASv2 attack8 paired 正式実験契約

## 1. 正式実験として採用する設計

攻撃行動復元の正式実験には `atlasv2_s3_s4_attack8_paired_20260724` を使用する。
旧 `attack24` は個別アラート起点の感度調査として保存するが、
Stage 1/2/3 の性能比較には使用しない。

正式実験の評価単位は8個の行動チェーンである。
各チェーンの host、focus process、時間窓、Gold は3条件で固定する。

| 条件 | モデルへ渡す起点 | DBで利用できる証拠 |
|---|---|---|
| Stage 1 | 代表 CBC alert 1件 + host/process/time | CBC alert summary、CBC event、Security、Sysmon等 |
| Stage 2 | host/process/time | CBC alert summary、CBC event、Security、Sysmon等 |
| Stage 3 | Stage 2と同一 | CBC alert summaryのみ非表示。CBC event、Security、Sysmon等は利用可能 |

Stage間で評価ケース、Gold、時間窓、採点分母を変えない。

## 2. 行動チェーン

1. `s3_pt_01_word_document_processing`
2. `s3_pt_02_regsvr32_remote_sct`
3. `s3_pt_03_regsvr32_long_chain`
4. `s3_pt_04_powershell_mid_chain`
5. `s4_pt_01_word_w1`
6. `s4_pt_02_word_w2_w3`
7. `s4_pt_03_mshta_c1`
8. `s4_pt_04_powershell_c1`

入力数は `8 chains × 3 stages = 24`。

## 3. Agent 呼び出し回数

正式実験では Agent 呼び出し回数による打ち切りを使用しない。

- Chief investigation 回数上限: なし
- Investigator question 回数上限: なし
- QAAgent / SQL query 回数上限: なし
- 終了条件: 各 Agent が tool call を返さず、final answer を返した時点

実行フラグは `--unbounded-agent-calls`。
run JSON には次を保存する。

```json
{
  "max_investigations": null,
  "max_questions": null,
  "max_queries": null,
  "agent_call_limit_policy": "unbounded_by_experiment"
}
```

LangGraph は実装上 `recursion_limit` に整数を必要とするため、
実験上到達不能な `2147483647` をランタイム値として与える。
これは実験の停止条件や Agent 呼び出し回数上限として使用しない。

出力トークン上限 `max_tokens=8192` は1回のモデル応答形式に必要なAPI設定であり、
Agent/tool call 回数の打ち切りには使用しない。

## 4. 時間スコープ

正常行動復元実験と同様に、宣言した時間窓は探索起点と主チェーンの報告範囲に使う。
adapter DB を時間窓だけに物理切断しない。
周辺証拠を調査することは許可するが、主チェーンへ含めるには
parent/child、command line、PID/PPID、process GUID、target object等の観測接続が必要である。

## 5. 採点

正式 scorer は `score_element_order_with_gpt.py`。

主要指標:

- `behavior_step_recall`
- `action_step_recall`
- `action_step_precision`
- `behavior_sequence_order`
- `candidate_claim_precision`

独立診断指標:

- `critical_evidence_recall`

`critical_evidence` を `action_step_recall` / `action_step_precision` の分母へ混ぜない。
Stage 3 は validation CSV で `stage3_status=pass` の canonical `cbc_events` stepだけを採点する。

正式集計では同一 rubric の独立2レビューを行い、
不一致だけを第三レビューまたは事前定義した保守的規則で解消する。

## 6. 2026-07-24 試行

最初の試行条件:

- model: `gpt-4.1-mini`
- replicate: `replicate_01`
- 反復数: 1
- ケース数: 24
- Agent呼び出し回数上限: なし
- SQL playbook: `none`
- max output tokens per model call: `8192`
- cost logging: 有効

実行先:

`docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01/`

実行コマンド:

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py `
  --run `
  --models gpt-4.1-mini `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --log-cost
```

中断後の再開:

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py `
  --run --resume `
  --models gpt-4.1-mini `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --log-cost
```

## 7. 実験開始条件

- build validation: pass
- 24ケースがJSONとして読み込み可能
- Stage数が8/8/8
- 8 GoldがJSONとして読み込み可能
- 各チェーンで3条件のGold・scopeが同一
- Stage 3 validation: 45 steps pass
- scorer maxima: 各Stage 45 steps / 135 action items / 36 order pairs
- `gpt-4.1-mini` dry-runで call-count fieldsがすべて`null`

上記は2026-07-24に確認済み。

## 8. 正式採点の実行経路

正式採点は専用wrapper
`src/clouseau_process_time/score_attack8_paired_completed_double_review.py`
だけを入口とする。実験driverの `--score` もこのwrapperへ委譲し、
単発の `score_element_order_with_gpt.py` へ直接出力しない。
judge条件は `gpt-5`、`reasoning_effort=high` に固定する。

実験の実行中または終了後に、新しく完了したrunだけを通常追加入力するコマンド:

```powershell
python src/clouseau_process_time/score_attack8_paired_completed_double_review.py `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --judge-model gpt-5 `
  --reasoning-effort high
```

同じ正式経路はdriverからも起動できる。`--score` 単独では、
その時点で完成している妥当な `*_run.json` を自動検出する。

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py `
  --score `
  --models gpt-4.1-mini `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01
```

APIを呼ばず、完了runの検出と入力妥当性だけを確認する:

```powershell
python src/clouseau_process_time/score_attack8_paired_completed_double_review.py `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --list-only
```

既存レビューから比較・台帳・正式集計だけを再構築する:

```powershell
python src/clouseau_process_time/score_attack8_paired_completed_double_review.py `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --audit-only
```

専用wrapper導入前に、同じコマンド・同じjudge条件で作成済みと確認できる
レビューへprovenance sidecarを付与するbootstrapは、API呼び出しを防ぐため
必ず `--audit-only` と組み合わせる。

```powershell
python src/clouseau_process_time/score_attack8_paired_completed_double_review.py `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --audit-only `
  --bootstrap-provenance
```

二重レビューでconflictになったrunだけへ独立第三レビューを追加し、
後述の事前定義規則で裁定する:

```powershell
python src/clouseau_process_time/score_attack8_paired_completed_double_review.py `
  --result-root docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01 `
  --adjudicate-conflicts `
  --judge-model gpt-5 `
  --reasoning-effort high
```

通常追加入力は既存の妥当なreviewを再利用し、新規に完了したrunの不足reviewだけを
作成する。既存run JSONと既存 `score_result.json` は、妥当・不正・provenance不一致の
いずれでも上書きしない。再採点が必要な場合は別の `--score-root` を指定する。
`--force` は正式非上書き契約により拒否される。

## 9. 二重レビューの出力と採用ゲート

既定の出力root:

`replicate_01/scores_normal_parity_double_review/`

主な出力構造:

```text
scores_normal_parity_double_review/
  double_review_manifest.json
  double_review_status.json
  review1/<model>/<stage>/<instance_id>/score_result.json
  review1/<model>/<stage>/<instance_id>/score_result.provenance.json
  review2/<model>/<stage>/<instance_id>/score_result.json
  review2/<model>/<stage>/<instance_id>/score_result.provenance.json
  review3/<model>/<stage>/<instance_id>/score_result.json
  review3/<model>/<stage>/<instance_id>/score_result.provenance.json
  comparisons/<model>/<stage>/<instance_id>/review_pair_summary.json
  adjudications/<model>/<stage>/<instance_id>/adjudication_summary.json
  double_review_log.jsonl
  double_review_summary.csv
  adopted_double_reviews.jsonl
  resolved_by_third_review.jsonl
  review_conflicts.jsonl
  formal_aggregate_adopted_only.json
```

各review pairは最低でも次のゲートをすべて通過しなければならない。

1. `schema_valid`: scorer出力のchains/totals構造が妥当
2. `denominator_match`: Gold最大値と正式分母が一致
3. `completeness_valid`: Gold item、order pair、candidate slotが完全
4. `reference_valid`: Gold参照IDとitem kindが妥当
5. `totals_recompute_match`: item-level判定から再計算した合計と出力合計が一致
6. `provenance_match`: run/Gold/validation/scorer/judge条件のhashが一致
7. `totals_match`: 独立2レビューの正式合計が一致
8. `item_level_match`: 独立2レビューのitem-level判定が一致

通常の二重レビューでは、上記を満たす `two_review_adoptable=true` のpairだけを
`formal_aggregate_adopted_only.json` へ正式集計する。1つでも失敗したpairは
`review_conflicts.jsonl` へ記録し、次の事前定義した順序で解消・再監査されるまで
正式集計から除外する。第三レビュー後は、全reviewの品質・provenanceゲートを通過し、
裁定記録が完全な `adjudication_pass=true` のpairだけを解消済みとして追加採用できる。

conflict解消規則は今回の結果を見て新設するものではなく、正常行動実験で使用済みの
次の実装と同じ保守的方針を継承する。

- `scripts/resolve_gpt55_salvage_conflicts_conservative_20260614.py`
- `scripts/resolve_formal_23_chain_gpt55_low_conflicts_conservative_20260615.py`

適用順:

1. 独立した第三レビューを追加する。
2. itemまたは集計値ごとに3レビュー中2レビューが一致する場合は、
   その `2-of-3` 多数一致を採用する。
3. 三者不一致、欠損、または同一性を確定できず `2-of-3` で解消できない値だけに、
   既存normal実験と同じ保守的規則を適用する。
4. 保守的規則ではhit数は候補レビューの最小値、candidate precisionの分母は
   candidate denominatorの最大値を採用する。Gold由来の固定分母は本契約の
   Gold最大値を変更しない。
5. 解消結果へ、参照した3レビュー、`2-of-3` または保守的規則の適用箇所、
   採用したhit/denominatorを記録し、上記ゲートを再監査する。

再監査後に限り解消済みpairを正式集計へ移せる。それまでは
`review_conflicts.jsonl` に残し、`formal_aggregate_adopted_only.json` から除外する。

## 10. replicate_01 実行結果

### 10.1 実験本体

2026-07-24、次の条件で `gpt-4.1-mini` を1 replicate実行した。

- result root:
  `docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/replicate_01`
- 完了run: 24/24
- Stage別run数: Stage 1 = 8、Stage 2 = 8、Stage 3 = 8
- root run JSON妥当: 24/24
- `output_text` JSON妥当: 24/24
- run-level error: 0
- `max_investigations`: 全24runで `null`
- `max_questions`: 全24runで `null`
- `max_queries`: 全24runで `null`
- `agent_call_limit_policy`: 全24runで `unbounded_by_experiment`

token使用量と復元された `code_steps` は次のとおり。

| Stage | Runs | Input tokens | Output tokens | Cached input | `code_steps` |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 8 | 455,051 | 38,627 | 0 | 40 |
| Stage 2 | 8 | 328,235 | 33,610 | 0 | 39 |
| Stage 3 | 8 | 290,395 | 27,914 | 0 | 29 |
| **合計** | **24** | **1,073,681** | **100,151** | **0** | **108** |

run JSONには直接の請求額フィールドが記録されていないため、費用はtoken数からの
参考推定とする。2026-07-24確認時点の
[OpenAI公式 `gpt-4.1-mini` モデルページ](https://developers.openai.com/api/docs/models/gpt-4.1-mini)
に記載された通常API単価（入力 $0.40 / 1M tokens、出力 $1.60 / 1M tokens）を用いると、
実験本体の推定額は **$0.589714** である。これは実請求額の監査値ではない。

### 10.2 正式採点結果

24runすべてについて、`gpt-5`、`reasoning_effort=high` の独立二重レビューを完了した。
再構築監査では Stage別pair数が8/8/8、stale score 0、rejected run 0だった。
二重レビューのみで完全一致した1 pairを採用し、差分のある23 pairは本契約の
事前定義規則に従う第三レビュー対象とした。

1件のreview1でjudge応答のJSON parse errorが発生した。元の
`score_result.json` と `judge_raw_output.txt` は上書きせず固定し、
`review1_retry_01` に版付き再採点を作成した。元artifactのSHA-256は次のとおり。

- `score_result.json`:
  `cd3b3ba47e667e748b3330c8c169e76d2f765abde9e3b18c89d6bd89468575b1`
- `judge_raw_output.txt`:
  `672ef1d1d710dd546222d677b83d6dc563f723b7c1f140715ff4c32161ee7c95`

版付き再採点のprovenance、`supersedes` path/hash、再計算した
`retry_provenance_sha256` はすべて一致し、元artifactのhash不変も確認した。
`invalid_score_artifacts.jsonl` には `run_rejected=false` として監査証跡を残した。

初回第三レビュー23件のうち22件は全品質ゲートを通過した。残る1件はJSON構造と
totalsは妥当だったが、candidate slotが未知のGold item IDを参照していたため
`reference_valid=false` として採用しなかった。元のreview3を上書きせず、
`review3_retry_01` に版付き再採点を作成した。元artifactのSHA-256は次のとおり。

- `score_result.json`:
  `521fb0df3bdb1f972b453c7d77028a35d462b50bb549a932afd092e33f5dbef9`
- `judge_raw_output.txt`:
  `226235b50a397e6164c8b90ffc09352dd62256cdac716d009bb1f8e59e002b61`

`review3_retry_01` は全品質・provenanceゲートを通過し、`supersedes` path/hashと
`retry_reason=formal_quality_failure:reference_valid` も一致した。元review3のhashは
retry後も不変だった。

最終的な採用状態は次のとおり。

- completed double-review pairs: 24/24
- two-review adoptable: 1
- third-review adjudicated: 23
- formally adopted: 24/24
- Stage別正式採用数: 8/8/8
- unresolved conflict: 0
- stale score: 0
- rejected run: 0

`formal_aggregate_adopted_only.json` の正式metricsは次のとおり。

| Stage | Behavior recall | Action recall | Action precision | Order | Critical evidence | Candidate precision |
|---|---:|---:|---:|---:|---:|---:|
| Stage 1 | 15/45 (0.333333) | 42/135 (0.311111) | 41/135 (0.303704) | 6/36 (0.166667) | 1/45 (0.022222) | 41/251 (0.163347) |
| Stage 2 | 19/45 (0.422222) | 28/135 (0.207407) | 21/135 (0.155556) | 7/36 (0.194444) | 0/45 (0.000000) | 21/175 (0.120000) |
| Stage 3 | 12/45 (0.266667) | 13/135 (0.096296) | 9/135 (0.066667) | 1/36 (0.027778) | 0/45 (0.000000) | 9/150 (0.060000) |
| **全Stage** | **46/135 (0.340741)** | **83/405 (0.204938)** | **71/405 (0.175309)** | **14/108 (0.129630)** | **1/135 (0.007407)** | **71/576 (0.123264)** |

`Action recall` と `Action precision` のGold固定分母は、正常行動復元と同様に
`critical_evidence` を除外している。Stage 3は正常系と同じvalidation event filterを
適用した後も、Stage合計でGold steps 45、action items 135、order pairs 36である。

採点API使用量は、非上書き監査のため保持した旧版も含めて次のとおり。
`Output tokens` はreasoning tokensを内包するため、reasoning列を別途加算しない。

| Scope | API artifacts | Input tokens | Cached input | Uncached input | Output tokens | Reasoning tokens | Total tokens |
|---|---:|---:|---:|---:|---:|---:|---:|
| Effective reviews | 71 | 1,128,010 | 432,512 | 695,498 | 1,264,669 | 815,672 | 2,392,679 |
| Superseded audit trail | 2 | 61,740 | 0 | 61,740 | 43,092 | 25,536 | 104,832 |
| **All API calls** | **73** | **1,189,750** | **432,512** | **757,238** | **1,307,761** | **841,208** | **2,497,511** |

2026-07-24確認時点の
[OpenAI公式 `gpt-5` モデルページ](https://developers.openai.com/api/docs/models/gpt-5)
に記載された通常API単価（非cached入力 $1.25 / 1M、cached入力 $0.125 / 1M、
出力 $10.00 / 1M）を用いると、採点全API呼び出しの推定額は **$14.078222**、
うち有効reviewは **$13.570127**、旧版保持によるretry overheadは **$0.508095** である。
実験本体と採点を合わせた参考推定額は **$14.667936** であり、いずれも実請求額の
監査値ではない。

### 10.3 最終独立監査

2026-07-24、採点を実行したAgentとは別のsub-Agentが、API呼び出しや成果物編集を
行わないread-only監査を実施し、全項目PASS（失敗0件）と判定した。

- 正式採用24/24、Stage別8/8/8、二者一致採用1件、第三レビュー解消23件
- unresolved conflict、stale score、rejected runはいずれも0件
- review1/2の48件と有効review3の23件が、schema、分母、item集合、order pair、
  candidate slot、参照、totals再計算、provenanceの全ゲートを通過
- 第三レビュー対象23件の`adjudication_pass=true`を確認し、summaryを純粋関数で
  再生成して保存済みsummaryと完全一致
- 23件すべてで保守的fallbackのhits最小値、candidate分母最大値、Gold固定分母が
  独立再計算と一致
- retry 2件のsupersedes path/hash、raw出力、retry provenance hashを確認し、
  元artifactのhashが不変であることを確認
- 24件の採用台帳からStage別・全体aggregateを独立再計算し、
  `formal_aggregate_adopted_only.json`と完全一致
- Stage 3はvalidation pass 45/45、Gold steps 45、action items 135、
  order pairs 36で、全8ケースの`order_pair_set_complete=true`を確認

この独立監査をもって、`replicate_01`の実験結果と正式採点結果を確定する。

## 11. gpt-5.4-mini replicate_01

### 11.1 追加実験の固定条件

`gpt-4.1-mini`との同条件比較として、同じ8 behavior chainsをStage 1/2/3で
1回ずつ実行する。既存成果物を上書きしないため、追加実験のresult rootを次へ
分離する。

`docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_paired/gpt54mini_replicate_01/`

固定条件は次のとおり。

- experiment model: `gpt-5.4-mini`
- model alias: `gpt-5.4-mini`（snapshotへ固定しない）
- reasoning effort: `high`
- replicate: 1
- cases: 8 chains × 3 stages = 24 runs
- `max_investigations=null`
- `max_questions=null`
- `max_queries=null`
- `agent_call_limit_policy=unbounded_by_experiment`
- Stage 1/2/3の入力差、Gold、validation filter、指標分母は
  `gpt-4.1-mini replicate_01`と同一
- judge: OpenAI judge APIを使用せず、Codex sub-Agentによる手動構造化採点
- review: 互いの結果を参照しない独立Codex review1/2、不一致時は別Codex review3
- 正式採用: 全品質ゲートを通過した二者一致、または既定の第三レビュー裁定だけ
- 非上書き: 既存run、score、judge raw outputを削除・上書きしない

2026-07-26確認時点の
[OpenAI公式 `gpt-5.4-mini` モデルページ](https://developers.openai.com/api/docs/models/gpt-5.4-mini)
では、Responses API、reasoning effort `high`、structured outputs、function callingが
サポートされている。通常APIのテキストtoken単価はinput $0.75 / 1M、
cached input $0.075 / 1M、output $4.50 / 1Mである。

### 11.2 実行コマンド

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py `
  --run --resume `
  --models gpt-5.4-mini `
  --result-root docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_paired/gpt54mini_replicate_01 `
  --log-cost
```

正式採点はOpenAI judge APIを呼ぶ`--score`経路を使用しない。実験完了runを対象に、
2名のCodex sub-Agentが通常行動復元と同じcomponent rubricで独立採点する。
採点成果物は次へ分離する。

`docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_paired/gpt54mini_replicate_01/scores_codex_manual_double_review/`

各レビューは、run/Goldのhash、モデル、Stage、instance ID、全Gold item、
全order pair、全candidate slot、再計算可能なtotalsを構造化JSONLとして記録する。
第三のCodex sub-Agentが不一致をitem単位で裁定し、採点に参加していない
Codex sub-Agentが最終read-only監査を行う。

### 11.3 実行結果

2026-07-26、24 runの生成が完了した。初回成果物のうち
`s4_pt_04_powershell_c1_stage1`だけは`output_text` JSONがbase64文字列の途中で
切れていた。元runを削除・上書きせず、`max_tokens=32768`でversioned retryを
作成し、retryを当該ケースの有効runとして採用した。

- 初回不正run SHA-256:
  `ee1541e611113e5da08e6edab7498c9ccd50af2eb34920fc627cfda536115e0d`
- 有効retry run SHA-256:
  `930aff21b32e1f7fce335f9f2c531efe1f983808dd5c696237562737582de2ae`
- 有効run: 24/24
- Stage別有効run: 8/8/8
- root run JSON valid: 24/24
- `output_text` JSON valid: 24/24
- run-level error: 0
- `max_investigations/max_questions/max_queries`: 全24runで`null`
- `agent_call_limit_policy`: 全24runで`unbounded_by_experiment`
- 本番stderr: 0 byte

有効24runのtoken使用量と復元`code_steps`は次のとおり。retry前の不正runは
正式使用量から除外し、有効retryを含める。

| Stage | Runs | Input tokens | Cached input | Output tokens | `code_steps` |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 8 | 84,753 | 0 | 23,288 | 19 |
| Stage 2 | 8 | 89,366 | 0 | 26,880 | 31 |
| Stage 3 | 8 | 71,882 | 0 | 17,944 | 12 |
| **合計** | **24** | **246,001** | **0** | **68,112** | **62** |

11.1記載の通常API単価による有効24runの参考推定額は **$0.491005** である。
これは実請求額の監査値ではなく、不正な初回runのretry overheadも含まない。

### 11.4 Codex正式採点結果

OpenAI judge APIを使わず、Codex sub-Agentによるitem-level構造化採点を実施した。
完了runからhash固定queueを作り、独立review1/2、差分ケースのblind review3、
2-of-3 item裁定、非上書きbatch統合を行った。

- 正式採用: 24/24
- Stage別正式採用: 8/8/8
- 二者完全一致採用: 9
- 第三レビュー裁定: 15
- unresolved conflict: 0
- rejected effective run: 0
- Judge API call: 0
- 採点batch: 7件 + 16件 + retry 1件
- final score root:
  `scores_codex_manual_double_review/final_24`

正式metricsは次のとおり。

| Stage | Behavior recall | Action recall | Action precision | Order | Critical evidence | Candidate precision |
|---|---:|---:|---:|---:|---:|---:|
| Stage 1 | 11/45 (0.244444) | 28/135 (0.207407) | 20/135 (0.148148) | 2/36 (0.055556) | 4/45 (0.088889) | 22/91 (0.241758) |
| Stage 2 | 3/45 (0.066667) | 5/135 (0.037037) | 4/135 (0.029630) | 0/36 (0.000000) | 0/45 (0.000000) | 4/141 (0.028369) |
| Stage 3 | 5/45 (0.111111) | 12/135 (0.088889) | 9/135 (0.066667) | 1/36 (0.027778) | 3/45 (0.066667) | 12/55 (0.218182) |
| **全Stage** | **19/135 (0.140741)** | **45/405 (0.111111)** | **33/405 (0.081481)** | **3/108 (0.027778)** | **7/135 (0.051852)** | **38/287 (0.132404)** |

`Action precision`は正常行動復元および本書10.2と同じGold固定分母の正式指標で、
一般的な出力主張単位のprecisionに近い診断指標は`Candidate precision`である。

Stage 1はアラート入力が探索の起点として機能し、3 Stage中で最も高い。
Stage 2は31 `code_steps`・141 candidate slotsを出力した一方、candidate TPは4で、
近傍の別行動を対象chainへ混入する過剰復元が主な失点要因である。Stage 3は
candidate slotsを55まで絞りCandidate precision 0.218182を保ったが、
Action recall 0.088889であり、正解行動の大部分を回収できていない。

`gpt-4.1-mini`と比べ、`gpt-5.4-mini`は`code_steps`が108から62へ減り、
Candidate precisionは0.123264から0.132404へわずかに上昇したが、
Action recallは0.204938から0.111111、Action precisionは0.175309から
0.081481、Orderは0.129630から0.027778へ低下した。したがって、短く慎重な
出力によって候補単位のprecisionを保つ一方、chain coverageと順序復元を大きく
失ったと解釈する。

ただし、`gpt-4.1-mini`は`gpt-5` API Judge、`gpt-5.4-mini`はCodex手動二重レビュー
で採点した。rubricと分母は同一でもjudge経路が異なるため、厳密なモデル比較には
`gpt-4.1-mini`も同じCodex経路で再採点する必要がある。

blindレビューの透明性上、review1 batch 1とreview2 batch 2の各Agentは、
許可されたrubricを探す過程で、本書に記載済みの`gpt-4.1-mini`全体aggregateを
誤って閲覧したと申告した。相互のreview、case-level score、comparison、
adjudicationは閲覧しておらず、review1/2間のblind独立性は維持されたが、
このcross-model aggregate exposureは比較解釈上の制約として記録する。

### 11.5 最終独立監査

2026-07-26、採点に参加していないCodex sub-Agentが、API呼び出しや成果物編集を
行わないread-only監査を実施した。

- 8 chain、Gold 45 stepの`canonical_evidence`を元の`incident.db`内
  `cbc_events`へ直接照合した。45行 × 13主要field = 585比較で、
  欠損行0、field不一致0だった。
- 24 effective runのadapter databaseについて、各runに対応するGold行を
  135/135確認した。したがって、Gold行は全Stageで取得可能だった。
- 正式採用24/24、Stage別8/8/8、二者一致9件、review3裁定15件を再確認した。
- review schema、item集合、order pair、candidate slot、hash、2-of-3裁定、
  totals、Stage別・全体aggregateを独立再計算し、不一致0だった。
- unresolved conflict、stale score、rejected effective runはいずれも0だった。
- batch 1の採用7行だけは、最終merged rowに`run_sha256`、`gold_sha256`、
  `contract_sha256`、`queue_contract`を直接複製しておらず、`queue_id`経由の
  間接provenanceである。queueとreview成果物をたどれば完全照合できるが、
  単一rowで完結するarchiveではない。

この監査により、Goldの元ログ転記とCodex採点計算は妥当と確認した。ただし、
次節の入力契約上の問題は、採点計算の正しさとは別の実験妥当性問題である。

### 11.6 入力契約と解釈の事後診断

低いStage 2/3 scoreを調査した結果、`gpt-5.4-mini`の能力だけでは説明できない
入力時刻の意味の不一致を確認した。

元のS3 process-time caseには、selected CBC alert create timeを示す
`investigation_time_anchor_utc`があった。ところがpaired suite builderは
Stage 2/3で`anchor_event=scope_anchor(base)`を作り、`timestamp`を30分windowの
開始時刻へ置き換え、`investigation_time_anchor_utc`をpaired caseへ保持しなかった。
実際のpromptでも、例えばS3 long-chainはGoldの
`2022-07-19 14:36:16–14:37:23`に対して`timestamp=14:26:57`となった。

8 chainすべてで、promptの`timestamp`から最初のGold eventまで
9.30–12.74分離れていた。一方、正常行動復元の5分windowは先頭のcanonical
evidence時刻にanchoredされている。このため、field名やrubricは同じでも、
process-time timestampの意味は正常行動復元と同等ではなかった。

Agentは明示された30分の参考範囲より、`timestamp前後`を優先して狭く探索した。
代表例は次のとおり。

- `s3_pt_03_regsvr32_long_chain_stage2`:
  Gold 8行はadapterに存在したが、3件のleadはいずれも14:26:57前後を探索し、
  14:36:16以降へ到達せず`code_steps=[]`となった。
- `s3_pt_04_powershell_mid_chain_stage2`:
  14:25–14:29付近の別系列`cmd.exe → tshark.exe → dumpcap.exe`を採用し、
  14:36:16以降のGoldを取りこぼした。
- `s4_pt_03_mshta_c1_stage2`:
  Goldは00:53:39–00:54:53で30分範囲内だったが、00:41:14±5分中心の探索で
  false negativeとなった。00:26–00:56へ広げたtool結果にも0件という誤報があった。

さらにS4 WordのStage 2/3では、同じ`winword.exe`と大きく重なる30分window内に
W1、W2、W3の複数の実在clusterが含まれる。`s4_pt_02_word_w2_w3_stage2`では
InvestigatorがGold側PID 5980/2608も発見したが、Chiefは先行する別Gold caseの
W1 PID 3236/4572を採用した。これはモデルのcluster選択ミスであると同時に、
host/process/timeだけから採点対象clusterを一意に識別しにくいcase設計上の
曖昧さでもある。

また、現rubricはtimestampを独立したGold action itemにしていない。
`s4_pt_02_word_w2_w3_stage3`では、Goldが00:50/00:53のイベントであるのに、
出力は入力時刻00:41:14を各stepへ付与したまま、PID・親子componentへの
部分得点を得た。このため、現在のscoreは時刻正確性を過大評価し得る。

以上から、11.4の数値はartifactとして再現可能であり採点計算も正しいが、
特にStage 2/3を純粋なモデル性能として正式比較に用いるのは不適切である。
本replicateは入力契約不具合を含む診断runとして保持し、次の正式runでは少なくとも
以下を修正する。

1. 正常行動復元と同じ意味を持つevent/alert anchorを`timestamp`へ渡す。
2. 結論前に宣言window全体を検索したことを機械的に検証する。
3. 同一process・重複windowのcaseはPID、非重複window、または別の観測可能な
   discriminatorで一意化する。
4. timestampまたはcanonical event identityを採点項目へ追加する。
5. 実在するがGold外の近傍行動と、未観測・捏造claimをprecision診断で分離する。

## 12. 次回正式比較への移行

正常・攻撃を通した研究目的、修正版入力契約、評価方法、現在の結果の位置付け、
考察、再実験ロードマップは、次の統合成果物を最新版とする。

`docs/current_experiment/normal_attack_evidence_constrained_behavior_reconstruction_research_synthesis_20260726.md`

次回の正式比較では、モデルに与えていないCBCアラートとGoldの対応関係を
採点しない。全Stage共通の一次テレメトリ由来neutral process/time anchorから、
観測edgeで接続された対象chainを復元させる。Stage差はアラート要約の
初期提示・検索可能・非表示だけに限定する。

現在の`gpt54mini_replicate_01`は診断runとして保持する。Stage 2/3を含む全体値は、
修正版runが完了するまで正常行動復元との正式比較値に採用しない。

## 13. neutral-anchor・5分窓pilot契約（2026-07-26）

旧paired runを履歴として保持したまま、次の正式候補suiteを別名で生成した。

- case file:
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_neutral5_stage_cases_20260726.jsonl`
- Gold root:
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_neutral5_gold_20260726`
- build validation:
  `docs/current_experiment/atlasv2_s3_s4_attack8_neutral5_build_validation_20260726.json`
- pilot result root:
  `docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_neutral5/gpt54mini_replicate_01`

正式契約は以下である。

1. 評価単位はalert targetではなく、focus processを含む観測edge接続componentとする。
2. 全Stageでhost、focus process、neutral anchor、5分window、Goldを固定する。
3. Stage 1のみ代表CBC alertを追加提示するが、主timestampは共通neutral anchorとする。
4. Stage 2はalert summaryを検索可能、Stage 3はsummaryのみ非表示とする。
5. 提示されていないalert ID/title/reasonとGoldの対応推測を採点しない。
6. 正常系と同じsubject/action/object、order pair、candidate precisionを用い、
   critical evidenceは別診断とする。
7. Agent call上限は設けず、三つの上限値を`null`、
   `agent_call_limit_policy=unbounded_by_experiment`とする。

生成時および実行前preflightは、Stage別8/8/8、unique Gold 45、
全Goldの5分window内包含、neutral anchor key衝突0、Stage 2/3 alert漏洩0、
原本DBとの585 field比較不一致0を確認してpassした。

pilotは`gpt-5.4-mini`、reasoning明示指定なし、1反復で開始した。
24 runとCodex正式採点・監査が完了するまでは、本節のsuiteを正式比較結果として
採用しない。

## 14. neutral5品質ゲート失敗とnormal-parity v2（2026-07-26）

13節のneutral5第1反復は24 runを完了したが、厳格監査はfailだった。

- Stage別run: 8/8/8
- run-level error: 0
- Agent call上限なし: 24/24
- valid `output_text` JSON: 23/24
- 不正run: `s4_pt_04_powershell_c1_stage2`
- 原因: 最終JSONが文字列途中で切断
- 第1反復参考総量: input 268,223、output 122,035、cost $0.75032475
- 監査:
  `docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_neutral5/gpt54mini_replicate_01/run_audit_v1.json`

S3の12 runは診断目的でCodex review1/2/review3を完了した。Action recallは
0.407、Candidate precisionは0.287だった。ただし、第1反復は正常履歴runの
`max_tokens=24576`に対して8192であり、さらに5分窓全体の列挙とprocess
identity接続を指示していた。このため、出力切断と、同一processの付随操作を
Gold外stepとして過剰接続する条件差が残った。したがって第1反復は正式比較へ
採用しない。

Goldを追加・削除せず、同じ45行、neutral anchor、5分windowを保持した
normal-parity v2を別名で生成した。v2の評価単位は、focus processを含み、
observed parent/child、command、target-object edgeで展開する意味的behavior
chainである。同じprocess名/PIDまたは時間的近接だけではroutine file、
registry、module操作を主chainへ追加しない。

v2本番条件は次である。

- case:
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_neutral5_parity_v2_stage_cases_20260726.jsonl`
- Gold:
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_neutral5_parity_v2_gold_20260726`
- preflight:
  `docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_neutral5_parity_v2/gpt54mini_replicate_01_v2/preflight.json`
- result root:
  `docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_neutral5_parity_v2/gpt54mini_replicate_01_v2`
- model: `gpt-5.4-mini`
- reasoning effort: 明示指定なし
- max output tokens per model call: `24576`
- `max_investigations/max_questions/max_queries`: `null`
- `agent_call_limit_policy`: `unbounded_by_experiment`
- 未提示alert対応推測: 非採点

v2 preflightは24 case、Stage別8/8/8、neutral anchor一意8、Gold 45、
全Goldの5分window内包含、Stage 2/3 alert漏洩0、原本DBとの585 field比較
不一致0でpassした。v2が24/24 valid JSON、Codex二重レビュー、第三レビュー、
独立監査を完了するまでは正式比較値を確定しない。
## 15. Observable-component v3正式pilot契約（2026-07-26）

### 15.1 v2停止判定

v2のモデル実行は3件までを診断履歴として保持し、再開しない。独立した原DB監査により、旧45-step Goldは8ケース中7ケースで意味的stepが不足し、S4-2は観測edgeのないW2/W3を暗黙に結合していたことが判明したためである。また、旧neutral-anchor builderはfocus processに触れる候補を列挙した後、誤ってGold全体の最初の行を選択しており、S3-2のanchor rowは宣言した`regsvr32.exe`に触れていなかった。

これはモデル性能の失敗ではなく、正式採用前に検出されたbenchmark contractの失敗として扱う。旧run・Gold・scoreは削除・上書きしない。

### 15.2 v3成果物

- builder：`src/clouseau_process_time/build_atlasv2_s3_s4_attack8_observable_component_v3_suite.py`
- case：`data/current_experiment/cases/atlasv2_s3_s4_attack8_observable_component_v3_stage_cases_20260726.jsonl`
- Gold：`data/current_experiment/gold/atlasv2_s3_s4_attack8_observable_component_v3_gold_20260726`
- manifest：`data/current_experiment/cases/atlasv2_s3_s4_attack8_observable_component_v3_manifest_20260726.json`
- build validation：`docs/current_experiment/atlasv2_s3_s4_attack8_observable_component_v3_build_validation_20260726.json`
- Stage 3 validation：`docs/current_experiment/atlasv2_s3_s4_attack8_observable_component_v3_stage3_validation_steps_20260726.csv`
- formal result root：`docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_observable_component_v3/gpt54mini_replicate_01_v3`

### 15.3 固定したGoldと分母

8ケースのGold step数は`4, 3, 11, 11, 4, 4, 11, 11`、合計59である。S3-3/S3-4とS4-3/S4-4はそれぞれ同じ観測成分なので、focus anchorが異なってもGold row集合を同一にした。S4-2はW2だけへ変更した。

Stageごとの分母は次のとおりである。

| 指標 | 分母 |
|---|---:|
| Action recall（subject/action/object） | 177 |
| Critical evidence recall | 59 |
| Adjacent order recall | 51 |

hidden CBC alert ID/title/reason、未提示alertとGoldの対応推測、alert summaryを一次行動証拠の代わりにすることは採点対象外である。

### 15.4 Codex manual scoring schema v2

採点scriptは`src/clouseau_process_time/codex_manual_attack8_scoring.py`、schemaは`codex_manual_action_claim_review_v2`とする。

- candidate precisionのslotはsubject/action/objectだけに固定する。
- command lineはaction claimの属性であり、独立slotではない。
- critical evidenceはGold側の別診断とする。
- 各candidate claimをactor instance、operation family、target path/endpoint、orderで最大一つのGold stepへalignする。
- GoldがPIDを指定したsubjectはname-onlyでhitにしない。
- candidate denominatorは抽出時に固定し、reviewer判断で増減させない。
- literal TP slot precision、unique matched Gold数、duplicate TP数・率を分けて報告する。
- `false_positive_type`は固定enumの診断情報であり、review一致判定・多数決tupleへ含めない。
- order pairは、異なる二つのcandidate claimが対応Gold stepへalignし、正しい順にある場合だけhitとする。
- 二名の独立Codex review、相違項目だけ第三review、2-of-3を正式採用する。
- OpenAI judge APIは使用しない。

synthetic offline testはpass済みである。

### 15.5 preflight

本番前preflightは次を満たした。

- case 24、Stage別8/8/8
- Gold 59、全Stage換算177 step
- DB照合826 field、不一致0
- neutral anchorがfocus processへ実際に接続：8/8
- 5分scope内に全Gold evidence：8/8
- Stage 3でalert mappingなしに一意：8/8
- 同一成分・別anchorのGold row集合同一：2/2
- Stage 2/3 alert input leakage：0
- `max_tokens=24576`
- `max_investigations/max_questions/max_queries=null`
- `agent_call_limit_policy=unbounded_by_experiment`

Stage 1の表示timestampは、正常系の過去実験と同様に入力された代表アラート時刻とする。neutral anchorと5分scopeは共通探索情報として保持する。mandatoryなhost-wide disposition/alert classificationは要求しない。

### 15.6 本番実行

`gpt-5.4-mini`の正式pilot 1反復を、上記result rootで開始した。実行commandは次のとおりである。

```text
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py
  --cases data/current_experiment/cases/atlasv2_s3_s4_attack8_observable_component_v3_stage_cases_20260726.jsonl
  --result-root docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_observable_component_v3/gpt54mini_replicate_01_v3
  --validation-steps docs/current_experiment/atlasv2_s3_s4_attack8_observable_component_v3_stage3_validation_steps_20260726.csv
  --models gpt-5.4-mini --run --resume --max-tokens 24576 --log-cost
```

モデル出力を見る前にv3 Gold、prompt、分母、採点規則を固定した。結果へ合わせて同じreplicateのGoldやpromptを変更しない。

### 15.7 本番run完了とrun品質監査

`gpt-5.4-mini`の1反復は24/24件で完了した。正式なrun品質監査は
`run_audit_v3_contract_v2.json`でpassした。

| 項目 | 結果 |
|---|---:|
| run | 24/24 |
| Stage | 8 / 8 / 8 |
| output JSON妥当 | 24/24 |
| run error | 0 |
| stderr | 0 byte |
| unbounded Agent設定 | 24/24 |
| input token | 268,140 |
| output token | 84,923 |
| total token | 353,063 |
| cost | USD 0.5832585 |
| 出力code step | 74 |
| code step 0件のrun | 3 |

最初の`run_audit_v3.json`は、旧neutral5監査器がStage 1でもneutral anchor
そのものの表示を要求したため1件をfailにした。v3のStage 1は正常系と同様に
代表アラート時刻を表示し、5分windowを探索scopeとして渡す契約である。
監査器をStage 1ではalert anchor＋window、Stage 2/3ではneutral anchor＋window
を確認するよう修正し、既存監査を上書きせず
`run_audit_v3_contract_v2.json`として再監査した。

24 runでは、Stage 1/2/3の出力step数がそれぞれ29/25/20であった。
Stage 2の1件、Stage 3の2件が0 stepである。上限値は全件`null`である一方、
Chief Agentが実際に呼んだ`investigate_lead`はStage別8/12/11回であり、
上限到達による停止ではない。0 stepの一例では、モデルが存在しない`host`
列をSQL条件に使い、広い検索を絞り直さず終了した。これはGold欠落や
呼出し上限ではなく、調査queryの構成と再試行判断の失敗として採点後に分析する。

### 15.8 Codex正式採点queue

採点queueは次へ固定した。

`scores_codex_manual_double_review_v2/review_queue.jsonl`

- queue SHA-256：`bbe862ad318595889f8fcf1e4a7e7695bb7f84e29d0313ec2f4d62964e189869`
- run：24
- Gold item：Stageごと236（subject 59、operation 59、object 59、critical evidence 59）
- order pair：Stageごと51
- candidate slot：Stage 1/2/3で86/75/60
- `alert_mapping_scored=false`：24/24

この同一queueを、互いの判断を参照しないCodex sub-Agent 2名がreviewする。
OpenAI judge APIは使用しない。

採点に参加しないCodex sub-Agentのread-only queue/provenance監査はpassした。
24件・Stage別8/8/8、全hash、Gold item、order pair、candidate slot、
validation参照を再計算し、不一致、stale、rejected、excluded、duplicateは0であった。

### 15.9 Codex正式採点結果

review1/review2は24/24件を独立採点した。item-level完全一致は7件、
不一致を含む17件は判断値を伏せたconflict queueでreview3を実施した。
項目単位2-of-3により24/24件を正式採用し、未解消conflictは0である。
3者すべてでcandidate alignmentが異なった7 itemは、固定規則に従い
hitを保守的に0、candidate分母を固定のまま採用した。

| Stage | Action recall | Candidate precision | Critical evidence recall | Order recall |
|---|---:|---:|---:|---:|
| Stage 1 | 15/177 = **0.0847** | 15/86 = **0.1744** | 4/59 = **0.0678** | 3/51 = **0.0588** |
| Stage 2 | 23/177 = **0.1299** | 22/75 = **0.2933** | 8/59 = **0.1356** | 3/51 = **0.0588** |
| Stage 3 | 15/177 = **0.0847** | 16/60 = **0.2667** | 8/59 = **0.1356** | 3/51 = **0.0588** |
| **Overall** | **53/531 = 0.0998** | **53/221 = 0.2398** | **20/177 = 0.1130** | **9/153 = 0.0588** |

Action component別では、subject 13/177 = 0.0734、operation 25/177 =
0.1412、object 15/177 = 0.0847である。operation断片は比較的拾うが、
actor instanceと対象を同時に固定できないことが主要な欠落である。
candidate TPは53、unique matched Gold itemは52、duplicate TPは1
（duplicate TP rate 0.0189）であった。

正式集計は
`scores_codex_manual_double_review_v2/finalization_01/formal_outputs/`
に保存した。先行するreview3なしの`formal_outputs/`は、7/24だけを採用した
中間診断として保持し、正式値には用いない。

### 15.10 1ケースの具体例

`s3_pt_02_regsvr32_remote_sct_stage2`のGoldは次の3 stepである。

1. `svchost.exe / DcomLaunch` PID 648が`EQNEDT32.EXE` PID 6032を起動
2. `EQNEDT32.EXE` PID 6032が`regsvr32.exe` PID 6124を起動
3. `regsvr32.exe` PID 6124がremote SCT commandで
   `ortrta.net / 10.193.66.115:8080`へ接続

モデルは、2の親子関係をPID付きで復元し、3の`regsvr32.exe`、
remote SCT URL、domain/IP/portも取得した。一方、1を完全に落とし、
3のoperationをnetwork connectionではなく「スクリプト/URLを指定して実行」
と表現した。また、Gold外の`counters.dat`を「実体化したファイル」として
主系列へ追加した。

このrunの採点は、Action recall 5/9 = 0.5556、Critical evidence 2/3 =
0.6667、Order 1/2 = 0.5、Candidate precision 5/9 = 0.5556である。
これは「系列の中央と接続先は拾えるが、上流起点を落とし、routine fileを
過剰接続する」という典型例である。

### 15.11 結果の解釈

Stage 2がAction recallとCandidate precisionで最良だった。Stage 1の
アラート要約は平均性能を上げず、Word近傍の一時ファイル、Recent link、
Office cache等を主系列へ入れる過剰接続を誘発した。Stage 3はアラートなしでも
Stage 1と同じAction recallを維持し、evidence recallはStage 1より高かった。
したがって、今回の主因を「アラート要約がないこと」だけには帰せない。

3–4 stepの短系列12 runと11 stepの長系列12 runを分けると、Action recallは
0.1185対0.0934、Candidate precisionは0.1280対0.3854であった。
長系列は後段まで到達せずrecallが下がる一方、少数の比較的確かなstepだけを
出すためprecisionは高い。短いWord系列はstep数自体は多く出すが、
routine housekeepingを混ぜるためprecisionが低い。

S3/S4別ではAction recallが0.1149/0.0852、Candidate precisionが
0.2952/0.1897で、S4のWord・WerFault・Office一時ファイル周辺の境界分離が
より難しかった。上限なし設定でも調査失敗後に再試行しないrunがあり、
時間窓を10分へ広げるだけでは解決しない。改善仮説は、SQL schemaに従った
再query、各観測edgeを消費するまでの後段pivot、routine file除外の明示的
完了判定である。

### 15.12 正常系との比較可能性

入力Stage、5分scope、アラートの役割、subject/action/object、order、
critical evidence分離という実験構造は正常系へ揃えた。しかし、今回のv2は
GoldがPIDを指定した場合にname-onlyをhitにしない厳格identity規則と、
candidate slotをsubject/action/objectだけに固定する規則を追加している。
公表済み正常系値はcontent-inclusion型の過去reviewであり、完全なitem-level
provenanceも207件中69件に限られる。

したがって、正常系overallの0.798/0.703/0.553/0.584と今回の
0.0998/0.1130/0.0588/0.2398を、そのままモデル差として検定しない。
今回の値はattack v3内の正式pilot値である。正常・攻撃の正式な数値比較には、
正常系の少なくとも1反復を同じv2 identity/candidate規則で再reviewするか、
両方を同じ新しい共通rubricで再reviewする。攻撃側のGoldやpromptを
正常値へ近づけるために事後変更してはならない。

### 15.13 最終独立監査

採点に参加していないCodex sub-Agentが、reviewer独立性、全item集合、
decision/contract/run/Gold/validation hash、項目単位2-of-3、各run totals、
Stage/overall aggregateをread-onlyで再計算し、passした。

- 正式採用：24/24
- exact two-review：7
- third-review 2-of-3：17
- unresolved / stale / rejected / excluded / duplicate：0
- alert mapping採点item：0
- 保守fallback：candidate tuple 7、Gold/order 0
- queue SHA-256：`bbe862ad318595889f8fcf1e4a7e7695bb7f84e29d0313ec2f4d62964e189869`
- adopted ledger SHA-256：`c5732f151147f87c8463f396e2d0263985c737ae758bef90b449b0f4c1273910`
- formal aggregate SHA-256：`42cac9ea7d6697125c74b5816ad09bcce23aef86d673a66d1e5b515f3ed29770`
- run audit SHA-256：`832c7c35cf96860ee748343403ef2e82b5011808c6d92e5febe56aa8458f80bc`

## 16. 正常observable-component v3同条件反復（2026-07-26）

### 16.1 正式目的

攻撃側observable-component v3の値を、旧正常実験の異なるGold粒度・rubricと
直接比較しない。正常側も同じ中立anchor、5分窓、Stage定義、S/A/O採点、
PID strict、Codex manual double review、Agent呼出し上限なしで1反復し、
正常と攻撃の復元性能を正式比較する。

与えられていないCBC alert ID、title、reason、alert-to-Gold対応を推測する能力は
採点しない。alert summaryはStage 1/2の調査手掛かりであり、一次テレメトリの
行動stepを代替する正解ではない。

### 16.2 固定成果物とpreflight

- cases:
  `data/current_experiment/cases/normal8_observable_component_v3_stage_cases_20260726.jsonl`
- Gold:
  `data/current_experiment/gold/normal8_observable_component_v3_gold_20260726`
- manifest:
  `data/current_experiment/cases/normal8_observable_component_v3_manifest_20260726.json`
- build validation:
  `docs/current_experiment/normal8_observable_component_v3_build_validation_20260726.json`
- Stage 3 validation:
  `docs/current_experiment/normal8_observable_component_v3_stage3_validation_steps_20260726.csv`
- result root:
  `docs/current_experiment/results_2026-07-26/normal8_observable_component_v3/gpt54mini_replicate_01_v3`

preflightは24 case、Stage別8/8/8、8 chain、Gold 23 step、Action分母
Stage別69、critical evidence分母23、order分母15でpassした。全Goldは5分窓内、
全anchorはfocus processへ接続し、Stage 3一次証拠だけで23/23 stepを確認した。
`alert_mapping_scored=false`である。

### 16.3 本番run品質

`gpt-5.4-mini`第1反復は24/24、Stage別8/8/8で完了した。

- valid output JSON: 24/24
- error-free: 24/24
- stderr: 0 byte
- unbounded config: 24/24
- input/output/total token: 258,400 / 63,615 / 322,015
- cost: USD 0.4800675
- code steps: 52
- zero-code-step runs: 3

run auditは
`docs/current_experiment/results_2026-07-26/normal8_observable_component_v3/gpt54mini_replicate_01_v3/run_audit_normal_v3.json`
でpassした。

### 16.4 Codex正式採点

score rootは
`docs/current_experiment/results_2026-07-26/normal8_observable_component_v3/gpt54mini_replicate_01_v3/scores_codex_manual_double_review_v1`
である。外部judge APIは使用していない。

- queue: 24/24、Stage 8/8/8
- independent review1: 24/24 validation pass
- independent review2: 24/24 validation pass
- exact two-review: 19
- third-review 2-of-3: 5
- formal adoption: 24/24
- unresolved / stale / rejected / excluded: 0
- conservative fallback: 0
- alert mapping採点item: 0

| Stage | Action recall | Candidate precision | Behavior-step recall | Order recall | Critical evidence recall |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 11/69 = **0.1594** | 11/33 = **0.3333** | 5/23 = **0.2174** | 0/15 = **0.0000** | 0/23 = **0.0000** |
| Stage 2 | 25/69 = **0.3623** | 25/63 = **0.3968** | 12/23 = **0.5217** | 5/15 = **0.3333** | 8/23 = **0.3478** |
| Stage 3 | 17/69 = **0.2464** | 17/60 = **0.2833** | 10/23 = **0.4348** | 3/15 = **0.2000** | 2/23 = **0.0870** |
| **Overall** | **53/207 = 0.2560** | **53/156 = 0.3397** | **27/69 = 0.3913** | **8/45 = 0.1778** | **10/69 = 0.1449** |

component別Action recallはsubject 13/69、operation 26/69、object 14/69、
duplicate TPは0である。

### 16.5 攻撃との正式同条件比較

| 指標 | 正常 | 攻撃 | 正常−攻撃 |
|---|---:|---:|---:|
| Action recall | 0.2560 | 0.0998 | +0.1562 |
| Candidate precision | 0.3397 | 0.2398 | +0.0999 |
| Behavior-step recall | 0.3913 | 0.1638 | +0.2275 |
| Order recall | 0.1778 | 0.0588 | +0.1190 |
| Critical evidence recall | 0.1449 | 0.1130 | +0.0319 |

同条件でも攻撃は正常より低い。主因は長い攻撃系列で後段pivot前に調査を終えること、
PID単位のactor edgeを省略すること、正規process周辺のroutine rowを系列へ過剰接続
することである。5分窓には両群の全Goldが含まれ、Agent呼出しも無制限であるため、
今回の差を「30分窓が大きい」「呼出し回数が足りない」だけでは説明できない。

Stage 2は両群で最良であり、初期alertへのアンカリングを避けつつ、調査中に補助情報を
検索できる条件が有効である可能性がある。ただし各群1反復であり、分散・有意差は
未評価である。

### 16.6 provenance

- queue SHA-256:
  `ed5e4177e37eaac549ab8fe80582c5e3ef798af0109c07431f88c8e46b585413`
- review1 SHA-256:
  `a08446c67da55e27061e3cbe0e7029ad5f4ae5f6bbaa0b26ef108ae2e60bb64e`
- review2 SHA-256:
  `177355a1b48980f16f56a0ec9a9754f7961212e7b08ee51be9da59828a56cb07`
- review3 SHA-256:
  `2c79afaaf9c6192591abbe82fcd98878ec9f8e73833956aa0a919ede84a7af9e`
- adopted ledger SHA-256:
  `f9524e50881b2d60510d3a07895066e664956b93c28cecc6c450e7bd07502d16`
- formal aggregate SHA-256:
  `746705a52c080ca8fceb535327ff49763dbcf2a7d8c63ecc4c0007bdb4a323ba`
- run audit SHA-256:
  `5920cd67bd64e81f48a864c3af5aaa1b0587441e512229aa78935a1bba67bc77`
- queue provenance audit SHA-256:
  `342749bbbd04d89e559878c4f7234f55cd8b22eb8e73de759738b101dfd8bc04`
- formal comparison SHA-256:
  `70e6e10a9a725dd813250ac1fcbf13c32199a6ee530d24665d399180387a878b`

queue provenance独立監査は42 checks pass / 0 failである。初回監査v1のFAILは
監査側が`critical_evidence_signature`を正式採点値`evidence_basis`と取り違えた
ためであり、Goldまたはqueueの不整合ではない。v1は監査履歴として保持し、
prepare実装を直接再利用したv2で24/24 contract一致を確認した。重複した同値
`ppid=null` 1件は採点結果へ影響しないwarningとして記録した。

正式比較成果物は
`docs/current_experiment/normal_attack_observable_component_v3_formal_comparison_20260726.json`
および同名`.md`である。

## 17. Process-chain v4への正式移行（2026-07-27）

ユーザーの研究目的は、元の正常23ユースケースと同じ粒度・入力条件・component
rubricで、攻撃由来のプロセス行動列をどの程度復元できるかを測ることである。

事後監査の結果、observable-component v3は、PID strict、ファイル・通信edgeの
独立step化、モデルへのneutral anchorとtarget component ruleの提示により、
正常23ケースより細かく厳しい実験になっていた。このため、Section 15、16のv3値は
観測component粒度の診断pilotとして保持するが、正常23ケースとの正式比較値には
採用しない。

正式な攻撃再実験は
`process_behavior_chain_normal23_parity_v4`へ移行する。v4は次を固定する。

- process subject / semantic action / objectの因果的behavior chain
- PIDはprovenanceのみで非採点
- 一時ファイル・cache lifecycleは独立Gold stepにしない
- 5分窓
- Stage 1はalert+process+window、Stage 2はprocess+window、Stage 3は同入力でalert summary非表示
- neutral event anchorとtarget chain ruleをモデルへ提示しない
- subject/action/object、critical evidence別診断、隣接order pair、candidate precision
- hidden alert mapping、ATT&CK label、意図推定は非採点
- Agent呼出し回数は実験側で無制限

Goldは8 chain、44 stepで、Stage別Action分母132、critical evidence分母44、
order pair分母36である。24 case、Stage別8/8/8、全Goldの5分窓内包含、
source DB一致、Stage 3一次証拠44/44、PID token 0、raw file lifecycle step 0を
確認し、APIを使用しないpreflightはpassした。

v4の完全な契約と成果物一覧は
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v4_formal_contract_20260727.md`
を正本とする。既存v1-v3のrun、score、監査成果物は削除・上書きしない。

## 18. Process-chain v5正式Goldの採用（2026-07-27）

v4をモデル実行前に再レビューした結果、一次テレメトリだけでは確定しない
`payload取得先`、`C2候補`等の目的表現と、S4 W2の近接Word系列との境界曖昧性を
検出した。このためv4は候補版として保持し、正式runには使用しない。

修正版`process_behavior_chain_normal23_parity_v5_formal`では、目的表現を
観測事実へ限定し、S4 W2を独立した文書open・子process・通信・CBC alertを持つ
W3系列へ置換した。8 chain、43 Gold step、24 case（Stage別8/8/8）である。

原DBとの742 field比較はmismatch 0、semantic step 43/43、focus processと
確定窓による系列識別8/8、Stage 1 alert provenance 8/8、scored PID token 0、
hidden alert mapping採点なしで、正式レビューは`PASS`となった。

正常23ケースは21 chainが5分、1 chainが10分、1 chainが15分であるため、
正式な共通窓規則を「全case固定5分」ではなく「対象行動列を含むcase別確定窓を
全Stageで固定」と訂正する。攻撃8 chainはすべて5分以内に完全な系列が収まるため、
攻撃側の窓は全case 5分である。

正式Goldレビューと固定成果物は
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_review_20260727.md`
および同名`.json`を正本とする。gpt-4.1-miniの1反復は、このv5だけを用い、
API-free preflightとdry-runを通過した後に開始する。

API-free preflightは24 case、Stage別8/8/8、Gold 43、Action分母129、
critical evidence分母43、order pair分母35でpassした。dry-runも24/24件で完了し、
全件で`max_investigations/max_questions/max_queries = null`、
`agent_call_limit_policy = unbounded_by_experiment`を確認した。

gpt-4.1-miniの1反復は2026-07-27 15:01 JSTに次の新規rootで開始した。

`docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/gpt41mini_replicate_01`

開始時の親PIDは`32488`である。実行には`--run --resume --models gpt-4.1-mini
--max-tokens 24576 --log-cost`を用い、重複replicateは開始しない。

## 19. Stage 3・2ユースケースモデルpilotへの縮小（2026-07-27）

全24件へ直ちに進まず、実験設定と採点結果の解釈可能性を先に確認するため、
Section 18のgpt-4.1-mini全件runを停止した。停止時点で完成していたS3-1の
Stage 1/2は診断履歴として保持するが、本pilotの採点・比較には使用しない。

pilotでは同じStage 3ケースを両モデルへ入力する。

| case | 選定理由 | Gold step |
|---|---|---:|
| `s3_pt_01_word_document_processing_stage3` | 正常行動に近い短いWord境界ケース | 2 |
| `s4_pt_03_mshta_c1_stage3` | mshtaからPowerShell、payload、通信までの長い多段ケース | 9 |

モデルは`gpt-4.1-mini`と`gpt-5.4-mini`で、合計4 runである。全件で
Stage 3のCBC alert summaryを非表示とし、Agent呼出し回数は実験側で制限しない。
result rootは次である。

`docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/stage3_two_usecase_model_pilot_01`

API-free dry-runは4/4件でpassし、`max_investigations/max_questions/max_queries =
null`、`agent_call_limit_policy = unbounded_by_experiment`を確認した。

採点はOpenAI judge APIを用いずCodexが行う。正常23ケースと同じ
subject/action/object、critical evidence別診断、隣接order pair、
candidate precisionを用い、PIDとhidden alert mappingは採点しない。
全実験への移行判断は、スコアの高さだけではなく、4/4 valid run、Gold分母の整合、
候補行動の採点可能性、近傍行動の過剰接続が実験設定由来でないことを確認して行う。

### 19.1 pilot実行・Codex採点結果

4 runはすべてerrorなし、`output_text` valid JSON、Stage 3 alert summary可視行0件、
unbounded configで完了した。OpenAI judge APIは使用していない。
CodexがGold item、order pair、candidate slot単位で4件を採点し、schema、固定分母、
totals、run/Gold hash、Stage 3 filter、token/costを決定論的に再監査した。

pilotのため採点は単一Codexレビュー＋決定論的監査であり、正式な全実験では
独立Codex二重レビューと不一致時のitem単位第三レビューを用いる。

| モデル | Action recall | Candidate precision | Behavior-step recall | Order recall | Critical evidence recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 2/33 = **0.0606** | 2/17 = **0.1176** | 1/11 = **0.0909** | 0/9 = **0.0000** | 1/11 = **0.0909** |
| `gpt-5.4-mini` | 10/33 = **0.3030** | 10/30 = **0.3333** | 4/11 = **0.3636** | 2/9 = **0.2222** | 4/11 = **0.3636** |
| **全体** | **12/66 = 0.1818** | **12/47 = 0.2553** | **5/22 = 0.2273** | **2/18 = 0.1111** | **5/22 = 0.2273** |

tokenは`gpt-4.1-mini`が71,321、`gpt-5.4-mini`が25,809、合計97,130である。
costは順にUSD 0.0351524、USD 0.0459930、合計USD 0.0811454である。
queue/review validationは4/4 pass、unresolved conflict 0、audit failure 0である。

### 19.2 低スコアの原因

`gpt-4.1-mini`はS3-1で24回の調査を反復したが、調査中に得た文書・子processの
手掛かりを最終行動列へ統合できなかった。S4-3でもmshta→PowerShellを部分復元した
段階で後続pivotを落とした。回数制限による打切りではなく、反復検索、停止判断、
証拠選別、因果edge統合の失敗である。

`gpt-5.4-mini`はS3-1の文書openとS4-3前半のmshta通信、PowerShell系列を復元したが、
子Word edgeと後半のcmd・payload・通信を落とした。また近傍file/moduleを過剰接続し、
原DBに存在しないPowerShell PID 4994を追加した。原DBでPID 4994は
`process_pid`、`childproc_pid`とも0件で、実際の系列は4724→2976→3820→2168である。

v5 Goldはsemantic step 43/43、原DBとの742 field比較mismatch 0、
Stage 3一次証拠43/43を通過し、本pilotの2 chainも5分窓内に収まる。
hidden alert mappingは採点していない。したがって低スコアの主因はGold、時間窓、
alert非表示、Agent上限の不備ではなく、モデル／Agentシステムの検索品質、追跡継続、
証拠統合、過剰接続抑制である。

### 19.3 全実験へのgate判断

判定は**GO**とする。4/4 valid run、固定Gold分母、Stage 3非アラート条件、
unbounded設定、Codex item採点、hash・totals監査が成立し、失敗を実験設定不備ではなく
観測可能なモデル／Agent行動として説明できたためである。

全実験ではv5 Gold、case別確定窓、現行promptをbaselineとして固定し、
8ユースケース×3 Stageを各モデルで実行する。反復検索、早期停止、因果edge欠落、
近傍行動の過剰接続、存在しないprocess追加を失敗分類として記録する。
prompt／orchestration改善はbaseline完了後の別実験とし、途中で条件を変更しない。
なお本pilotは各モデル2 caseのみであり、数値を母集団性能としては採用しない。

正式pilot報告は
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_stage3_two_usecase_model_pilot_20260727.md`
および同名`.json`を正本とする。

## 20. Process-chain v5・2モデル正式baselineの開始（2026-07-27）

Section 19のpilotが4/4 valid run、Codex採点・監査PASS、全実験へのgate `GO`と
なったため、v5正式Goldと現行promptを変更せず、2モデルの正式baselineを開始した。

- model: `gpt-4.1-mini`, `gpt-5.4-mini`
- case: 8 chain × 3 Stage × 2 model = 48 run
- replicate: 各モデル1反復
- max token: 24,576
- Agent call: 実験側上限なし
- Stage 3: CBC alert summary非表示
- result root:
  `docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/two_model_baseline_replicate_01`

本番前preflightは24 case、Stage別8/8/8でpassした。2モデル合計48件のAPI-free
dry-runも完了し、Stage別16/16/16、`max_investigations/max_questions/max_queries=null`、
`agent_call_limit_policy=unbounded_by_experiment`、`max_tokens=24576`に対する
不一致は0件であった。

本番親プロセスは2026-07-27 16:45 JSTにPID `37020`で開始した。
実行commandは次のとおりである。

```text
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py
  --cases data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl
  --result-root docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/two_model_baseline_replicate_01
  --validation-steps docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage3_validation_steps_20260727.csv
  --models gpt-4.1-mini,gpt-5.4-mini
  --run --resume --max-tokens 24576 --log-cost
```

モデル実行は同一親プロセス内で逐次行い、先に`gpt-4.1-mini` 24件、続いて
`gpt-5.4-mini` 24件を実行する。中断時は同じcommandの`--resume`により未完了run
だけを再開し、既存runは削除・上書きしない。

完了後はOpenAI judge APIを用いず、正常23ケースと同じprocess-chain component
rubricでCodex正式採点を行う。PIDとhidden alert mappingは採点しない。

### 20.1 run完了とv5専用監査

2モデルの正式baselineは48/48件で完了した。親プロセスは正常終了し、stderrは
0 byteである。v5契約専用監査
`run_audit_v5_two_model_baseline_v3.json`はfailure 0でpassした。

| model | run | Stage 1/2/3 | input token | output token | total token | code step | empty run | cost (USD) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 24 | 8/8/8 | 898,659 | 79,571 | 978,230 | 77 | 3 | 0.486777 |
| `gpt-5.4-mini` | 24 | 8/8/8 | 237,277 | 90,203 | 327,480 | 63 | 1 | 0.583868 |
| **合計** | **48** | **16/16/16** | **1,135,936** | **169,774** | **1,305,710** | **140** | **4** | **1.07064845** |

全48件でerrorなし、`output_text` valid JSON、unbounded Agent設定を確認した。
Stage 3は16/16件で`sql_tool_temp_view`、CBC alert summary可視行0件、
CBC一次テレメトリ保持を確認した。

旧neutral5監査器を最初に適用した結果はfailとなったが、これは2モデルで同じ
`instance_id`を使う正規設計をduplicateと扱い、v5で意図的にモデルへ隠す
`target_component_rule`の表示を要求したためである。旧監査結果は診断履歴として
保持し、条件をv5契約へ合わせた専用監査v3を正式採用する。

Codex採点用score rootは次である。

`docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/two_model_baseline_replicate_01/scores_codex_manual_double_review_v1`

48件のreview queueを作成し、各項目をrun/Gold SHA-256、Gold item、order pair、
candidate slot、固定分母へ束縛した。外部judge APIは使用していない。

## 21. Process-chain v5・2モデル正式採点結果（2026-07-28）

2モデルのbaseline runは48/48件で完了し、run auditはfailure 0でpassした。正式採点はOpenAI judge APIを使用せず、Codexのblind二重reviewと不一致項目だけの第三reviewで行った。

初期のv1-v4採点ではGold action scoreとcandidate TP matchingを独立入力できたため、review1に74件の`Gold hit / candidate非TP`矛盾が生じた。旧採点は診断履歴として保持するが正式値には採用しない。正式v5 atomic-alignmentでは、subject/operation/objectのGold hitをTP candidate slotの`matched_gold_item_id`から決定論的に導出した。Critical evidenceとorderは別判定とした。

第三reviewの対象はcandidate slot 29、critical evidence 12、order pair 6の合計47項目である。2-of-3裁定後、48/48件を正式採用し、unresolved / stale / rejectedは0 / 0 / 0、`gold1_without_tp=0`、`tp_gold0=0`を確認した。

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 98/387 = **25.32%** | 98/228 = **42.98%** | 19/129 = **14.73%** | 21/129 = **16.28%** | 13/105 = **12.38%** |
| `gpt-5.4-mini` | 84/387 = **21.71%** | 84/186 = **45.16%** | 17/129 = **13.18%** | 27/129 = **20.93%** | 11/105 = **10.48%** |
| **全体** | **182/774 = 23.51%** | **182/414 = 43.96%** | **36/258 = 13.95%** | **48/258 = 18.60%** | **24/210 = 11.43%** |

Stage別ではStage 2がAction recall 27.91%、Candidate precision 48.98%、Behavior-step recall 20.93%、Critical evidence 27.91%、Order 17.14%で最良だった。Stage 1は明示アラートを持つが、アラート時刻・名称がchain開始より後方にあり、検知付近へ探索が偏るケースがあった。Stage 3ではアラート要約非表示により一次telemetryのfield表現を直接解釈する必要があり、exact queryのfalse negativeとedge統合失敗が増えた。

詳細分析では、`gpt-4.1-mini`にAction miss 289、incomplete step 110、critical miss 108、order miss 92、FP slot 130を確認した。`gpt-5.4-mini`ではAction miss 303、incomplete step 112、critical miss 102、order miss 94、FP slot 102だった。

両モデルに共通する主因は、後続pivot欠落、因果edge・atomic componentの圧縮、取得済み証拠の最終JSONへの未反映、近傍telemetryの過剰接続である。`gpt-4.1-mini`は反復検索が多いがedge統合に失敗しやすい。`gpt-5.4-mini`は24件中21件で1回の`investigate_lead`後に停止し、比較的保守的な出力だがchain coverageが不足した。

43 Gold stepはcanonical CBC row、timestamp、ACTION、targetへ追跡可能であり、今回の低スコアを説明する明確なGold欠陥は検出されなかった。主要な改善対象は時間窓やGoldではなく、構造化edge ledger、上下流pivotの終了条件、最終出力時の証拠採用・近傍イベント除外である。

正式報告：
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_two_model_formal_results_20260728.md`

正式JSON：
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_two_model_formal_results_20260728.json`

正式score root：
`docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/two_model_baseline_replicate_01/scores_codex_manual_double_review_v5_atomic_alignment`

## 22. GPT-5.5 Stage 3・2ユースケースpilot（2026-07-28）

モデル能力を上げた場合に同一実験条件で復元性能が上がるかを確認するため、process-chain v5正式GoldのStage 3から次の2ケースだけを`gpt-5.5`で実行した。

- `s3_pt_01_word_document_processing_stage3`
- `s4_pt_03_mshta_c1_stage3`

実験条件は既存pilotと同じである。初期入力はhost・focus process・timestamp、ケースごとの固定5分窓、CBC alert summary非表示、一次telemetry利用可能、`max_investigations/max_questions/max_queries=null`、`agent_call_limit_policy=unbounded_by_experiment`、`max_tokens=24576`とした。

2/2 runはerrorなし、`output_text` valid JSON、Stage 3 CBC alert summary可視行0で完了した。採点はOpenAI judge APIを使わず、Codexによる単一pilot reviewと決定論的監査で行った。subject/operation/objectのGold hitはincluded TP candidate slotの`matched_gold_item_id`から導出し、critical evidenceとorderは別判定、PIDとhidden alert mappingは非採点とした。Gold/actionとcandidate TPのcross-field不整合は0件、hash・分母・slot・order監査はPASSだった。

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-5.5` | 12/33 = **36.36%** | 12/21 = **57.14%** | 3/11 = **27.27%** | 4/11 = **36.36%** | 3/9 = **33.33%** |

ケース別ではS3-1 WordがAction 4/6、precision 4/6、完全step 1/2、critical 1/2、order 1/1だった。S4-3 mshtaはAction 8/27、precision 8/15、完全step 2/9、critical 3/9、order 2/8だった。

同一2ケースの既存pilot判断をv5 atomic定義へ揃えると、`gpt-4.1-mini`はAction 2/33、precision 2/17、完全step 0/11、critical 1/11、order 0/9、`gpt-5.4-mini`はAction 10/33、precision 10/30、完全step 2/11、critical 4/11、order 2/9となる。したがってn=2の範囲では`gpt-5.5`がAction、precision、完全step、orderを上回り、critical evidenceは`gpt-5.4-mini`と同率だった。

内部ログでは両runともChiefの`investigate_lead`は1回だったが、内部InvestigatorはS3-1で6件、S4-3で5件のQAを直列実行した。S3-1は文書pathとWord子プロセスまで取得したが、文書openを`process_create`として最終化したためoperation/objectを失った。S4-3はmshta→PowerShellまで取得したが、発見したPowerShellを新しい親として再帰pivotせず、PowerShell→PowerShell→cmd→payload→通信の後段6 stepを失った。

S3-1は約16分28秒、S4-3は約14分54秒を要した。時間はAgent call上限ではなく、1 lead内の5～6 QA、長い調査要約、長い最終JSON生成に使われた。現行artifactはQA/SQL単位の開始・終了時刻やmodel usageを保存していないため、厳密な待ち時間内訳は取得できない。

top-level usageは合計input 51,786、output 33,292、85,078 tokenだった。実行時cost loggerは`gpt-5.5` price未登録のため0 USDを記録した。repository内の実験price table（input USD 5/M、cached USD 0.5/M、output USD 30/M）による推定costはUSD 1.257690である。

結論は、モデル変更で候補精度と一部の復元性能は上がったが、長系列後半の欠落は残った、である。主要な次の改善対象は、frontier型の再帰pivot、未探索childが残る場合の停止禁止、event typeからsubject/operation/objectへの正規化、主要chainとsupporting evidenceの分離である。

正式pilot報告：
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_gpt55_stage3_two_usecase_pilot_20260728.md`

machine-readable summary：
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_gpt55_stage3_two_usecase_pilot_20260728.json`

score root：
`docs/current_experiment/results_2026-07-28/atlasv2_s3_s4_attack8_process_chain_v5_formal/gpt55_stage3_two_usecase_pilot_01/scores_codex_gpt55_stage3_two_case_v1`

## 23. 未解決フロンティア終了判定の原因調査と修正（2026-07-28）

攻撃runでChiefの`investigate_lead`が1回で終わりやすい原因を内部traceと実装から再監査した。
Agent呼び出し回数や論点数に1件という上限があったわけではない。上流CLOUSEAUの
`Clouseau.call_model`が最低調査回数だけを終了再考条件に使い、観測済みだが未追跡の
因果pivotを検査していなかったことが主因である。

回数ベース判定は上流初期公開commit `924d663`に由来し、その既定値は
`DEFAULT_INVESTIGATION_MIN=5`だった。ローカル攻撃runnerの有効な
`patch_cbc_prompts_clean`はこの最低値を1へ変更していた。このrunnerはルートrepositoryで
未追跡のため、値を1に変更した導入commit・担当session・意図は履歴から確定できない。
この値は最大回数ではないが、1回後にモデルがtool callを返さなければ評価段階へ進める
状態を作った。

直接再集計では、`gpt-4.1-mini`は24件中20件で複数lead、`gpt-5.4-mini`は24件中23件で
1 lead、`gpt-5.5` pilotは2件とも1 leadだった。S4-3の`gpt-5.5` traceでは、
ToolMessageがPowerShell pid 2976を「後続activityを別系列として追う必要がある」と
明記した直後、Chiefがtool callなしで`status=completed`を返していた。

修正として、最終回答直前に過去のToolMessageを読み直し、観測済みで対象行動列へ
因果的に接続する未調査edgeが残る場合だけ追加`investigate_lead`へ戻す
`observed_unresolved_frontier_review_v1`を追加した。固定の最小・最大lead数は追加して
いない。Investigatorは`unresolved_frontier`を構造化して返し、Chiefは件数合わせ、
同一leadの反復、時刻近接だけの追跡を行わない。

API-free単体テスト4件（prompt契約を含む）とStage 3・S4-3のdry-runはすべてPASSした。dry-runで
`max_investigations/max_questions/max_queries=null`、
`agent_call_limit_policy=unbounded_by_experiment`、
`frontier_closure_policy=observed_unresolved_frontier_review_v1`を確認した。

詳細な原因証跡、変更点、検証結果、修正後pilotのgateは次に記録した。

`docs/current_experiment/atlasv2_attack8_unresolved_frontier_fix_20260728.md`

## 24. Frontier-closure 2ケース・3 Stage・3モデルpilot（2026-07-29）

修正後pilotは、`s3_pt_01_word_document_processing`と`s4_pt_03_mshta_c1`の
Stage 1/2/3を、`gpt-4.1-mini`、`gpt-5.4-mini`、`gpt-5.5`で実行する18-run計画とした。

`gpt-4.1-mini` 6件と`gpt-5.4-mini` 6件はerrorなし・valid JSONで完了した。
`gpt-5.5` 6件はすべてAPI 429 `insufficient_quota`、`output_text=null`であり、
採点対象外とした。失敗成果物は保持し、上書き・削除・自動再試行していない。

有効12件はOpenAI judge APIを使わず、単一Codex pilot reviewと決定論的監査で採点した。
subject/operation/objectのGold hitはincluded TP candidate slotの
`matched_gold_item_id`から一意に導出し、critical evidenceとorderは別判定、
PIDとhidden alert mappingは非採点とした。run/Gold hash、全Gold item、
全candidate slot、全order pair、固定分母を監査し、`gold1_without_tp=0`、
`tp_gold0=0`、duplicate TP 0、candidate複数Gold対応0でPASSした。

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 38/99 = **38.38%** | 38/84 = **45.24%** | 10/33 = **30.30%** | 15/33 = **45.45%** | 3/27 = **11.11%** |
| `gpt-5.4-mini` | 47/99 = **47.47%** | 47/107 = **43.93%** | 13/33 = **39.39%** | 19/33 = **57.58%** | 6/27 = **22.22%** |
| **有効12件** | **85/198 = 42.93%** | **85/191 = 44.50%** | **23/66 = 34.85%** | **34/66 = 51.52%** | **9/54 = 16.67%** |

修正前の同一2ケース・3 Stage・2モデルとのpaired比較では、Action recallは
24.24%から42.93%、完全stepは18.18%から34.85%、critical evidenceは
24.24%から51.52%、orderは12.96%から16.67%へ改善した。Candidate precisionは、
候補分母が98から191へ増えたため48.98%から44.50%へ低下した。

有効12件では`investigate_lead` 134回、unresolved frontier section 137件だった。
`gpt-4.1-mini`は111 leadで探索量が多いが近傍行動への漂流があり、
`gpt-5.4-mini`は23 leadで統合精度は高いが後半chainの早期停止が残った。
SQL guardは8 runでprovenanceがあり、発動0件だったため、今回の精度差の原因ではない。
Stage 3の初期CBC alert summary可視行は0件である。最終出力中の
`supporting_alert_evidence` 3行は一次telemetryからの自発的補助記述であり、
hidden alert mappingとして採点していない。

結論は、frontier-closure修正は有効だが全体実験gateはHOLDである。
`gpt-5.5` quota回復後に、既存12件を再実行せず、別versioned retry rootで
失敗した6件だけを実行する。加えて、typed chain ledger、candidate admission gate、
component completeness、局所order validatorを次の改善軸とする。

正式報告：
`docs/current_experiment/atlasv2_attack8_frontier_pilot_12valid_codex_results_20260729.md`

machine-readable summary：
`docs/current_experiment/atlasv2_attack8_frontier_pilot_12valid_codex_results_20260729.json`

score root：
`docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01/scores_codex_frontier_pilot_single_review_v1`

## 25. 正常・攻撃 full-ledger pilot05（2026-07-30）

正常21件・攻撃8件への移行前gateとして、正常2ユースケースと攻撃2ユースケースを
選び、各Stage 1/2/3を1回ずつ実行した。モデル割当は`gpt-4.1-mini`と
`gpt-5.4-mini`で各6 run、合計12 runである。GPT-5.5は使用していない。

対象は次の4ケースである。

- 正常：`chain_10_e07_discord_run_key_registry_chain`
- 正常：`chain_02_e01_python_simplehttpserver_network_chain`
- 攻撃：`s4_pt_03_mshta_c1`
- 攻撃：`s3_pt_01_word_document_processing`

全12 runはerrorなし、`output_text` valid JSONで完了した。参照時間窓は全件5分、
実験上のAgent call上限は無制限とした。1 lead内の探索膨張だけを抑える安全弁として、
Investigator 20質問、SQL 80回、または20分で未解決frontierをChiefへ返す契約を使用した。
Stage 3ではCBC alert summaryを物理adapter copyから除外し、一次CBC event telemetryと
共通SQL/process-tree guardが維持されることを確認した。

full-pipeline callback ledgerでは、Chief、Investigator、SQL QAを含む全LLM callを
per-call usageへ束縛した。12 run合計はAPI call 1,412回、input 6,480,641、
output 384,897、cached input 3,689,600、合計token 6,865,538、
推定費用USD 2.891690、逐次wall time 4,789.781秒だった。

| role | API calls | input | output | cached | LLM sec | cost |
|---|---:|---:|---:|---:|---:|---:|
| Chief | 75 | 458,723 | 50,901 | 251,776 | 445.660 | USD 0.312384 |
| Investigator | 294 | 1,503,853 | 118,201 | 1,093,760 | 1,367.185 | USD 0.618406 |
| SQL QA | 1,043 | 4,518,065 | 215,795 | 2,344,064 | 2,431.077 | USD 1.960900 |

採点はOpenAI judge API/API scorerを使わず、Codex単独reviewとv5 atomic決定論的監査で
行った。subject/operation/objectのGold action hitは、固定candidate slotのTPと
`matched_gold_item_id`の一意coverageからのみ導出した。PIDとhidden alert mappingは
非採点、critical evidenceとorderは別判定である。12件、Gold action分母144、
candidate slot分母123、behavior step分母48、critical evidence分母48、
order pair分母36を監査し、Gold/TP不整合、duplicate TP coverage、
candidate claimの複数Gold対応はいずれも0でPASSした。

| 集計 | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 19/99 = **19.19%** | 19/66 = **28.79%** | 5/33 = **15.15%** | 0/33 = **0.00%** | 1/27 = **3.70%** |
| `gpt-5.4-mini` | 16/45 = **35.56%** | 16/57 = **28.07%** | 4/15 = **26.67%** | 0/15 = **0.00%** | 4/9 = **44.44%** |
| **全12 run** | **35/144 = 24.31%** | **35/123 = 28.46%** | **9/48 = 18.75%** | **0/48 = 0.00%** | **5/36 = 13.89%** |

モデルごとに異なるケースを割り当てたため、上記モデル別値は記述統計であり、
同一ケースpaired比較によるモデル優劣ではない。

主な精度低下要因は、取得済みparent/childやcommand-lineを独立したatomic actionへ
変換せず`execution_context`へ埋め込むこと、初回に誤った近傍process instanceを選び
検索量を増やしてもtarget chainへ戻らないこと、後続file/module activityをGold外の
candidateへ昇格してprecisionを下げること、初回exact-time queryが0件だった後に
Chiefが明示された時間緩和pivotを実行せず終了することである。探索量不足だけではなく、
process-instance選択、candidate構成、因果edgeのatomic化、停止判定を分離して改善する
必要がある。

`gpt-4.1-mini`正常Stage 3の1 runだけは、修正前TEMP VIEW wrapperが共通guardを迂回した
完了済みthoughtである。再実行せず、技術的交絡として正式報告に明示した。

正式報告：
`docs/current_experiment/normal_attack_full_ledger_pilot05_formal_results_20260730.md`

machine-readable summary：
`docs/current_experiment/normal_attack_full_ledger_pilot05_formal_results_20260730.json`

score / ledger root：
`docs/current_experiment/results_2026-07-30/normal_attack_full_ledger_pilot_05/analysis_codex_single_review_v1`

ユースケース別3 Stage合算・Stage別推移・考察：
`docs/current_experiment/normal_attack_full_ledger_pilot05_case_summary_20260730.md`

同machine-readable summary：
`docs/current_experiment/normal_attack_full_ledger_pilot05_case_summary_20260730.json`

研究発表用の全体→ケース→Stage→試行・module ledger→原因の再構成：
`docs/current_experiment/normal_attack_full_ledger_pilot05_slide_ready_summary_20260731.md`

同machine-readable summary：
`docs/current_experiment/normal_attack_full_ledger_pilot05_slide_ready_summary_20260731.json`

## 2026-08-02 正常8＋攻撃8 two-model formal 完了

同一コード版・同一v5 atomic process-chain rubricで、`gpt-4.1-mini` と
`gpt-5.4-mini` のみを対象に、正常8ケース＋攻撃8ケース×Stage 1/2/3、計96 runを完了した。
`gpt-5.5`は実行していない。

正常48 runは
`docs/current_experiment/results_2026-08-01/normal8_three_model_three_stage_formal_19_retry_02`
でdeterministic audit PASS。攻撃はformal_20の監査PASS 47 runを再利用し、失敗した
`gpt-4.1-mini / s3_pt_02_regsvr32_remote_sct / Stage 1`の原成果物を凍結したまま、
create-only retry rootで当該1 runだけを再実行した。retryはerrorなし、output JSON valid、
usage/config/hash監査PASSであり、元47＋retry 1のprovenance付き正式48 runを固定した。

採点は実験に参加していないCodex `gpt-5.6-sol` reviewerが行い、OpenAI judge APIと
API scorerは使用していない。96 run合算はAction recall 337/1188 = **28.37%**、
Candidate precision 337/762 = **44.23%**、Behavior-step recall 71/396 = **17.93%**、
Critical evidence 30/396 = **7.58%**、Order recall 38/300 = **12.67%**。
full-pipeline usage合算は43,242,622 tokens、記録cost **$14.5809597**。

正式報告：
`docs/current_experiment/normal_attack8_two_model_codex_sol_combined_results_20260802.md`

machine-readable summary：
`docs/current_experiment/normal_attack8_two_model_codex_sol_combined_results_20260802.json`

正常のitem-level score：
`docs/current_experiment/normal8_two_model_three_stage_codex_sol_results_20260802.json`

攻撃のitem-level score：
`docs/current_experiment/attack8_two_model_three_stage_codex_sol_results_20260802.json`

攻撃composite audit：
`docs/current_experiment/results_2026-08-02/attack8_two_model_three_stage_formal_20_composite_audit_20260802.json`

## 2026-08-03 GPT-5.5 normal8＋attack8 budget-$10 formal 完了

同一コード版・全ロール`gpt-5.5`で、正常8ケース＋攻撃8ケース×Stage 1/2/3、計48 runを収集した。
各runはsoft cost USD 8で新規frontier拡張を停止し、hard cost USD 10超過後は新規モデルcallを停止する
事前登録済みbudget guardを適用した。正常Discord Stage 2の非budget 1800秒timeoutは原成果物を凍結したまま、
create-only retry rootで当該1 runだけを同条件で再実行し、errorなし・output JSON valid・usage/config/hash監査PASSとなった。

正式headlineは正常24 runと攻撃22 runの計46 runである。攻撃の
`s4_pt_04_powershell_c1 / Stage 1`（USD 10.298952）と
`s4_pt_03_mshta_c1 / Stage 3`（USD 10.096212）はhard-budget-censoredとして凍結保持し、
ゼロ点にはせず精度分母から除外した。soft-triggeredでもfinal JSONが有効でcensoredではないrunはheadlineに含める。
全モデル比較は同じ46 case×stage strataの交差集合に固定する。元auditのFAIL表示は上書きせず、
create-only provenance reconciliationで有効分類を記録した。

採点は実験に参加していないCodex `gpt-5.6-sol` reviewerがv5 atomic process-chain rubricで行った。
OpenAI judge API/API scorerは使用していない。run/Gold hash、全Gold item、固定candidate slot、
behavior complete-three、critical evidence、隣接order pair、固定分母、totalsのcross-field監査はPASSした。
PIDとhidden alert mappingは非採点である。

46 run合算はAction recall 382/546 = **69.96%**、Candidate precision 382/816 = **46.81%**、
Behavior-step recall 109/182 = **59.89%**、Critical evidence 121/182 = **66.48%**、
Order recall 84/136 = **61.76%**。headline 46 runの記録costはUSD 171.880681、
budget-censored 2 runはUSD 20.395164、retryを含む最終成果物ledger総額は**USD 192.275845**である。
元のtimeout runはfinal ledgerを生成していないため、その未確定usageはこの金額に含めない。

正式報告：
`docs/current_experiment/gpt55_normal_attack8_budget10_codex_gpt56sol_combined_results_20260803.md`

machine-readable summary：
`docs/current_experiment/gpt55_normal_attack8_budget10_codex_gpt56sol_combined_results_20260803.json`

formal scoring addendum：
`docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01/formal_scoring_addendum_20260803.json`

provenance reconciliation：
`docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01/final_composite_provenance_20260803.json`

## 2026-08-06 正常8・攻撃8 two-model 3反復正式集計

`gpt-4.1-mini` と `gpt-5.4-mini` について、正常8ケース・攻撃8ケース × Stage 1/2/3 の replicate_01/02/03、合計288 runを同一コード系列と同一v5 atomic process-chain rubricで固定した。`gpt-5.5`はこの反復実験では実行していない。replicate_02/03 first passの190 PASSと2 FAILは既存artifactを凍結し、別versioned retry rootで失敗2件だけを再試行した。1800秒run timeoutと`APITimeoutError/output=null`はいずれもretry PASSとなり、正式sourceは192/192 PASS、3反復合計は288/288有効runである。

採点は実験非参加のCodex `gpt-5.6-sol` reviewerが正常96件と攻撃96件を独立に実施し、OpenAI judge API/API scorerは使用していない。全run/Gold/case hash、全Gold item、全candidate slot、全隣接order pair、固定Gold分母、totalsを保存し、Gold↔TP不整合、重複TP、source run/audit/output JSON、full-pipeline usageを再監査してPASSした。PIDとhidden alert mappingは非採点、critical evidenceはaction componentと分離した。

3反復poolのモデル×正常/攻撃結果は次の通りである。

| model | phase | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall | cost/run | wall/run |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | attack8 | 35.66% | 43.26% | 30.49% | 11.89% | 12.06% | $0.2462 | 11.95分 |
| `gpt-4.1-mini` | normal8 | 51.53% | 41.03% | 26.09% | 0.97% | 42.96% | $0.2156 | 12.88分 |
| `gpt-5.4-mini` | attack8 | 14.56% | 37.81% | 13.44% | 6.46% | 2.86% | $0.0888 | 1.18分 |
| `gpt-5.4-mini` | normal8 | 23.19% | 42.48% | 8.70% | 10.14% | 9.63% | $0.0688 | 1.34分 |

288 run全体の実測は127,957,534 tokens、16,652 API calls、USD 44.596231、wall time 32.82時間である。反復統計は各replicateの固定Gold分母スコアを実験単位とし、平均、標本分散、Student-t 95%CI（n=3, df=2）を保存した。candidate precisionの分母は各outputが発行したmeaningful subject/operation/object slot数であり、run内では固定されるが反復間で同一である必要はない。

最初の統合audit v1はcandidate slot分母まで反復間不変と誤って要求したためFAILになった。run・item採点値は変更せず、create-only v2でGold/step/critical/order分母の不変性とrun単位candidate分母固定を分離して再監査しPASSした。v1は削除・上書きせず、correction provenanceで非正式artifactとして明示した。

正式報告：
`docs/current_experiment/normal_attack8_two_model_three_replicate_codex_sol_results_20260806_v2.md`

machine-readable summary：
`docs/current_experiment/normal_attack8_two_model_three_replicate_codex_sol_results_20260806_v2.json`

normal replicate_02/03 item-level score：
`docs/current_experiment/normal8_mini_reps_02_03_codex_sol_results_20260806.json`

attack replicate_02/03 item-level score：
`docs/current_experiment/attack8_mini_reps_02_03_codex_sol_results_20260806.json`

aggregation correction provenance：
`docs/current_experiment/normal_attack8_two_model_three_replicate_aggregation_correction_20260806.json`
