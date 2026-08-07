# ATLAS v2 attack8 未解決フロンティア終了判定の原因調査と修正

作成日: 2026-07-28

## 結論

攻撃実験でChiefの`investigate_lead`が1回で終わる現象は、論点数やAgent呼び出し回数に
1件という上限が設定されていたためではない。主因は、CLOUSEAUのChiefが最終回答へ
進むときに、調査結果中の「観測済みだが未追跡の因果ピボット」を検査せず、最低調査
回数だけで早期終了を判定していたことである。

ローカルの攻撃runnerは最低調査回数を1へ変更していた。この値は最大回数ではないが、
1回の`investigate_lead`後にモデルがtool callを返さなければ、そのまま評価段階へ進める
状態を作った。`gpt-5.4-mini`と`gpt-5.5`はこの経路を選びやすく、攻撃長系列の後続
pivotが欠落した。

今回の修正は固定の調査回数を増やすものではない。最終回答の直前に、観測済みで対象
行動列へ因果的に接続する未調査edgeが残るかを確認し、残る場合だけ追加の
`investigate_lead`へ戻す。

## 原因が入った場所

### 1. 上流CLOUSEAUの回数ベース終了判定

対象:

`external/Clouseau/artifact/chief_inspector.py`

`Clouseau.call_model`は、`current_iteration < DEFAULT_INVESTIGATION_MIN`の間だけ早期終了を
再考させる。条件を満たさなくなった後は、モデル応答にtool callがなければ
`agent_router`が評価段階へ送る。未解決のchild process、network endpoint、file/object
などを検査する条件はなかった。

`git blame`では、この回数ベース判定は上流の初期公開commit
`924d663`（2025-10-23）に由来する。同commitの既定値は
`DEFAULT_INVESTIGATION_MIN=5`だった。したがって、終了判定そのものは今回のv5 Gold、
採点方式、Stage 3化で新しく導入されたものではない。

### 2. ローカル攻撃runnerによる最低回数1への変更

対象:

`src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py`

同ファイルには`patch_cbc_prompts_clean`の再定義が複数あり、Python実行時に有効なのは
最後の定義である。その有効定義が`constants.DEFAULT_INVESTIGATION_MIN = 1`を設定して
いた。これにより上流既定値5より早く回数ベースの再考条件を抜ける。

このrunnerはルートrepositoryでは未追跡ファイルで、作成日時は2026-05-30だが、
導入commitと紐づくAgent sessionは確認できなかった。そのため、値を1に変更した人物・
作業セッション・意図をgit履歴から断定することはできない。

重要なのは、`1`は「最大1回」ではなく「最低1回」である点である。実際、
`gpt-4.1-mini`は攻撃正式run 24件中20件で複数leadを発行し、最大35回だった。一方、
`gpt-5.4-mini`は24件中23件が1回、1件だけ3回、`gpt-5.5` pilotは2件とも1回だった。
同じcontrollerでもモデルのtool-use判断によって停止位置が大きく変わるため、
回数ベース終了判定がモデル依存性を露出させたと判断する。

## 具体的な停止例

対象run:

`docs/current_experiment/results_2026-07-28/atlasv2_s3_s4_attack8_process_chain_v5_formal/gpt55_stage3_two_usecase_pilot_01/runs/gpt-5.5/stage3/s4_pt_03_mshta_c1_stage3_run.json`

1回目のToolMessageは、`mshta.exe pid 4724`から`powershell.exe pid 2976`への
parent/child edgeを観測したうえで、「このpowershell.exeの後続activityを別系列として
追う必要がある」と明記した。また、PowerShell command lineは長さ7750だが表示が途中で
切れ、完全値の取得には追加取得が必要とも明記した。

それでも次のChief応答はtool call 0件で`status=completed`を返した。つまり、検索担当は
次の調査対象を提示できていたが、Chiefの終了判定がその未解決pivotを機械的に確認しなかった。

## 実装した修正

### Chiefの意味ベース終了判定

`external/Clouseau/artifact/chief_inspector.py`へ
`review_frontier_before_finalizing`を追加した。

- 少なくとも1回の調査後、Chiefがtool callなしで最終化しようとした場合だけ動作する。
- 過去のToolMessageと作成中の最終回答を再確認する。
- 観測済みで因果的に接続する未調査edgeが残る場合だけ、追加tool callを採用する。
- 未解決edgeがなければ元の最終回答を維持する。
- 固定の最小・最大lead数は追加しない。

### Chief / Investigator契約

`src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py`の有効なpromptへ次を追加した。

- Chiefは必要なら複数の異なる`investigate_lead`を同一応答で発行できる。
- 観測済みの未調査edgeが残る間は最終化しない。
- 件数合わせ、同じleadの反復、時刻近接だけの追跡は禁止する。
- Investigatorは結果末尾に`## unresolved_frontier`を出し、entity、接続証拠、
  未確認edge、次の調査対象を列挙する。
- 直接接続edgeを確認済みの場合だけ`なし`とする。

### 実験設定への記録

`src/clouseau_process_time/run_clouseau_official_normal_behavior.py`で、run artifactへ
`frontier_closure_policy`を保存し、runtimeへ`frontier_closure_review_prompt`を渡せる
ようにした。攻撃runnerだけが
`observed_unresolved_frontier_review_v1`を有効化するため、既存の正常23実験や過去runの
条件は変更しない。

## APIを使わない検証

- `py_compile`: 変更対象3ファイルとテスト1ファイルがPASS。
- 単体テスト4件がPASS。
  - 未解決フロンティアあり: draft finalからtool callへ戻る。
  - 未解決フロンティアなし: 追加調査を強制しない。
  - policy未設定: 既存runの挙動を変更しない。
  - prompt契約: 複数lead許可、未解決edgeの停止禁止、`unresolved_frontier`、
    件数合わせ禁止を確認。
- Stage 3・S4-3・`gpt-5.5`のdry-runがPASS。
  - `max_investigations/max_questions/max_queries=null`
  - `agent_call_limit_policy=unbounded_by_experiment`
  - `frontier_closure_policy=observed_unresolved_frontier_review_v1`

dry-run成果物:

`docs/current_experiment/results_2026-07-28/atlasv2_s3_s4_attack8_process_chain_v5_formal/frontier_closure_fix_preflight_01`

## 実験結果の扱い

過去の4.1-mini、5.4-mini、5.5 pilotは変更前のarchitectureによる結果として保持し、
削除・上書きしない。修正後runは実験条件が変わるため、同じreplicateへ`--resume`せず、
新しいresult rootとpolicy versionで実行する。

修正後に2ケースpilotを行う場合は、単にlead回数が増えたかではなく、次をgateとする。

1. 未解決の観測edgeが残るときだけ追加leadが発行されたか。
2. 同じleadの反復や近傍行動の過剰接続が増えていないか。
3. S4-3でPowerShell以降の後続process/payload/network edgeが復元されたか。
4. Candidate precisionを維持しながらAction、完全step、Orderが改善したか。
