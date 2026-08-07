# ATLASv2 S3/S4 attack24 実行計画レビュー

レビュー日: 2026-07-23  
対象計画: `atlasv2_s3_s4_attack24_execution_plan_20260723.md`  
結論: **GO — `gpt-5.4-mini`による40入力の初回実行を開始してよい。**

本レビューは、実験を開始できるかを判断するため、方法論と実行実装を分けて確認した。ここでのGOは「モデルが攻撃を復元できる」との結論ではない。定義した条件でモデルを走らせ、対応するGoldにより評価を開始できる、という開始可否の判断である。

## 1. レビュー対象

- 研究準備報告: `atlasv2_s3_s4_attack24_research_report_preparation_20260723.md`
- 実行計画: `atlasv2_s3_s4_attack24_execution_plan_20260723.md`
- 実行・採点契約: `atlasv2_s3_s4_attack24_execution_contract_20260723.md`
- case定義: `data/current_experiment/cases/atlasv2_s3_s4_attack24_stage_cases_20260723.jsonl`
- 専用ドライバ: `src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py`

## 2. 方法論レビュー

### 2.1 研究主張との整合

**判定: PASS**

計画の主評価は、CBCアラートの真偽分類や攻撃全体の完全復元ではなく、一次ログに基づく証跡付き行動列の復元である。これは「調査者が判断するための土台を自動構成する」という本研究の主張と整合する。

`triage_decision`を参考出力に留め、Gold採点の主対象を行動ステップ・証拠要素・順序に限定している。判断ラベルのGoldがない状態で、判断性能を主張しないため、評価対象の過剰拡張がない。

### 2.2 評価単位の整合

**判定: PASS（報告時の注意を明記済み）**

Stage 1は24件のCBC alert-target入力であり、Stage 2/3はアラート要約を除いた後に重複を統合した8件のhost/process/time入力である。したがって、三Stageの件数は一致せず、対応ありの一対一比較にはならない。

計画は次の二つを別集計すると定めている。

1. Stage 1: 現実のCBCアラートを開始点にした調査起点評価。
2. Stage 2/3: 一意なprocess-time文脈におけるアラート要約への依存性評価。

この区別が研究報告にも明記されているため、24件対8件の差をアラート要約の因果効果として誤読する危険は管理されている。

### 2.3 Goldの妥当性

**判定: PASS**

Goldはシナリオ記述やCBCアラート名から作るのではなく、親子関係、コマンドライン、通信等の実ログ証跡に紐付けている。S3/S4の個別検証は、それぞれ157/157、284/284でpassしている。

特に、Word文書起点と後続ローダの間に直接エッジがない場合、後続のpayload系列をGold必須ステップにしない。この境界ケースを主攻撃系列の成功率から分離する方針は、「もっともらしいが未観測の因果関係を補完しない」という研究上重要な制約を保持する。

### 2.4 Stage 3の比較妥当性

**判定: PASS**

Stage 3ではCBCアラート要約を検索できない。採点対象も、canonicalな`cbc_events`だけで裏付けられるステップに限定している。8ケース・45ステップを確認し、`cbc_alerts`要約に依存する採点ステップは0件だった。

よって、Stage 3で成績が低下した場合にも、「隠されたアラート要約がGoldの根拠だったため採点不能になった」のではなく、要約を使わない復元能力の差として解釈できる。

## 3. 実行実装レビュー

### 3.1 case構成

**判定: PASS**

実行前にcase JSONLを再読し、次を確認した。

| 検査 | 結果 |
| --- | ---: |
| 総case数 | 40 |
| Stage 1 | 24 |
| Stage 2 | 8 |
| Stage 3 | 8 |
| `enforce_time_scope=true` | 40/40 |
| Stage 3で`input_alert_rows`が空 | 8/8 |

### 3.2 時間範囲と情報隔離

**判定: PASS**

各caseで30分窓が物理的に強制される。これまでの40/40 dry-runのrun JSONでは`hard_time_scope_enforced=true`を確認済みである。

Stage 3は、専用ドライバが`--exclude-cbc-alert-summary`を必ず付与する。runner自体も、Stage 3でこのフラグがなければfail-closedで停止する。dry-run成果物では、Stage 3の8/8で`post_filter_cbc_alert_summary_rows=0`を確認済みである。

Stage 2/3の実際のChief入力には、Gold、期待行動、`alert_id`、アラート名称・理由が含まれていないことを確認済みである。Stage 1のみ、選定した1件のCBCアラート要約を開始情報として持つ。

### 3.3 Gold解決と採点接続

**判定: PASS**

専用ドライバのpreflightを再実行しpassした。ドライバは旧実験用の固定Gold rootを使用せず、各caseの`formal_gold_root`と`gold_chain_file`からGoldを解決する。Gold pathは40/40で解決した。

Stage 3用validation CSVには45件の`stage3_status=pass`行があり、scorer filterは8/8ケースで採点対象を残す。順序ペアは、旧Goldの二要素配列形式と新Goldのmapping形式をともに正規化して扱うため、Stage 3のフィルタ段階で形式差による失敗は起こらない。

### 3.4 実行コマンド

**判定: PASS**

以下のコマンドが、40入力を`gpt-5.4-mini`で実行し、Stage 3の隔離と費用ログを有効にする。

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py --run --models gpt-5.4-mini --log-cost
```

`--run`が明示されない限りモデルAPIは呼ばれない。`--score`はモデル実行後のrun JSONだけを対象にするため、dry-runを誤って採点することもない。

## 4. 未解決事項と開始可否

開始を妨げる実装上・方法論上のblockerは見つからなかった。以下は未解決事項ではなく、実行後に測定すべき評価対象である。

- 各モデルがどの攻撃段階まで復元できるか
- Stage 1/2/3で復元性能がどのように変わるか
- 30分の入力時間窓以内に各caseを完了できるか
- 実行時間、API費用、失敗・中断率

GPT-5.5の実行は本初回計画の対象外である。`gpt-5.4-mini`の40入力の費用・時間・出力品質を確認してから、別途追加実験として判断する。

## 5. 最終判断

**GO**。実行前ゲート、方法論、case構成、時間範囲、Stage 3要約隔離、Goldのケース別解決、採点接続、40/40 dry-runを確認した。`gpt-5.4-mini`による初回40入力実験を開始してよい。

実行開始後は、モデル出力の内容が期待より弱い場合もそのまま結果として保存し、成功例だけを選ぶ再実行を行わない。システムエラーが出た場合だけ、原因と対象caseを記録した上で再実行方針を検討する。
