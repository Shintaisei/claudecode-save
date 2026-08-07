# ATLASv2 S3/S4 attack24 実行計画

作成日: 2026-07-23  
実行対象: ATLASv2 `WIN-32-H1`、S3/S4のCBCアラート起点攻撃復元スイート  
開始モデル: `gpt-5.4-mini`  
状態: 実行前計画

## 1. 目的

本計画の目的は、準備済みの40入力スイートを、定義済みの入力隔離・時間範囲・Gold・採点規則を崩さずに実行し、攻撃行動列復元の結果を取得することである。

初回の実行対象を`gpt-5.4-mini`に限定する。GPT-5.5は既存実験で大きな費用が生じているため、attack24の入力・出力・採点が一貫して完了することを確認した後に、別途モデル比較として実施可否を判断する。本計画はGPT-5.5の実行を自動では開始しない。

## 2. 固定する実験条件

| 項目 | 固定値 |
| --- | --- |
| 対象ホスト | `WIN-32-H1` |
| 対象シナリオ | ATLASv2 S3、S4 |
| モデル | `gpt-5.4-mini` |
| Stage 1 | 24件のCBC alert-target入力 |
| Stage 2 | 8件の一意なhost/process/30分窓入力 |
| Stage 3 | 8件の一意なhost/process/30分窓入力。CBCアラート要約は非表示 |
| 総入力数 | 40 |
| 時間範囲 | 各CBCアラートの`create_time`の前後15分、計30分 |
| 時間範囲の適用 | `enforce_time_scope=true`によるadapter DBへの物理フィルタ |
| Stage 3の要約隔離 | `--exclude-cbc-alert-summary`。フラグなしではfail-closed |
| エージェント上限 | investigations=100、questions=200、queries=400、tokens=8192 |
| SQL playbook | `none` |
| Gold | 各caseの`formal_gold_root`と`gold_chain_file`で解決 |

## 3. 実行順序

### Step 0: 実行前ゲート

専用ドライバのpreflightを実行し、以下を満たすことを再確認する。

1. Stage構成が24 / 8 / 8、合計40である。
2. 40件すべてのGold pathが解決する。
3. Stage 3の8ケースが45個の`cbc_events`根拠ステップだけで採点可能である。
4. Stage 3のGoldが`cbc_alerts`要約に依存しない。
5. Stage 3の全実行コマンドに要約除外フラグが付与される。

このゲートが失敗した場合、モデル実行を開始しない。

### Step 1: モデル実行

40入力を`gpt-5.4-mini`で1回ずつ実行する。各入力のrun JSONを保存し、API費用ログを残す。

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py --run --models gpt-5.4-mini --log-cost
```

このコマンドはStage 3だけに`--exclude-cbc-alert-summary`を自動付与する。実行中に失敗したcaseがあれば、再実行を自動的には行わない。失敗時点のログと既存run JSONを保存し、原因を特定してから、失敗caseだけを再実行する方針を別途決める。

### Step 2: 実行完了性の確認

実行終了後、以下を確認する。

- 40件すべてのrun JSONが存在する。
- 各run JSONの`instance_id`、stage、モデルが期待値と一致する。
- 全caseで`hard_time_scope_enforced=true`である。
- Stage 3の8caseで`post_filter_cbc_alert_summary_rows=0`である。
- Stage 2/3の実際の入力にGold、期待行動、CBCアラート要約が混入していない。
- 失敗・中断・空出力を分母に含めない。

### Step 3: Gold採点

完了したrun JSONだけを、対応するcase Goldで採点する。

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py --score --models gpt-5.4-mini
```

Stage 3の採点では、45個の`stage3_status=pass`ステップを記録したvalidation CSVを必ず用いる。アラート要約への依存が残るステップを分母に入れない。

### Step 4: 集計・報告

次の単位を混ぜずに集計する。

1. **Stage 1（24件）**: CBCアラートを開始情報として用いる調査起点評価。
2. **Stage 2/3（各8件）**: 一意なhost/process/time文脈でのアラート要約依存性評価。
3. **境界ケース**: S3/S4のWord起点は、主攻撃行動列の成功率と別に報告する。
4. **攻撃段階**: 入口、ローダ、PowerShell、payload/C2の復元範囲を分ける。
5. **実用性**: caseごとの実行時間、30分窓以内の完了可否、API費用、失敗率を示す。

Stage 1の24件とStage 2/3の8件は一対一のペアではないため、対応ありの性能比較や単純な差分検定には用いない。

## 4. 成功条件

### 実行の成功

- 40入力のモデル実行が完了し、各入力が対応するrun JSONを生成する。
- 入力隔離・時間範囲・Stage 3要約隔離が実行成果物でも維持される。

### 採点の成功

- 40入力がケース固有のGoldで採点される。
- Stage 3の8入力は、定義済み45ステップのうち各caseで採点可能な分母を持つ。
- 順序採点が旧形式・新形式のGold order pairを正常に扱う。

### 研究上の成功

本実験の成否は、攻撃を必ず全復元できるかではない。各条件・攻撃段階・起点の具体性に対して、どこまでを一次ログで裏付けた行動列として復元できたかを報告可能な形で得ることを成功とする。

## 5. 停止・再実行の規則

- preflight失敗、Stage 3の要約非表示違反、Gold path不一致、または採点分母0を検出した場合は、その時点で停止する。
- API・ネットワーク・モデル側の一時エラーは、原因と対象caseを記録する。原因未確認のまま全体を再実行しない。
- モデル出力の内容が不十分でも、システムエラーでなければその出力を実験結果として保存する。後から成功出力だけを選ぶ再試行は行わない。
- GPT-5.5の追加実行は、この初回結果の費用・時間・失敗率をレビューした後にのみ判断する。

## 6. 実行後に作成する成果物

- モデル・Stage・caseごとのrun JSON
- caseごとの採点結果
- 実行時間・API費用の集計
- Stage別、攻撃段階別、境界ケース別の結果表
- 失敗・停止・再実行の台帳
- 研究報告用の結果・解釈ドキュメント

## 7. 実行判断

本計画は、準備済みの実行契約および開始可否レビューを前提とする。以下の二つのレビューでblockerがないことを確認してからStep 1を開始する。

1. 方法論レビュー: Goldの意味、評価単位、Stage比較、境界ケースの扱いが研究主張と整合するか。
2. 実行レビュー: case、時間範囲、要約隔離、Gold path、採点器、実行コマンドが実装上つながるか。

## 関連文書

- [準備報告](atlasv2_s3_s4_attack24_research_report_preparation_20260723.md)
- [実行・採点契約](atlasv2_s3_s4_attack24_execution_contract_20260723.md)
- [開始可否レビュー](atlasv2_s3_s4_attack24_execution_readiness_20260723.md)
