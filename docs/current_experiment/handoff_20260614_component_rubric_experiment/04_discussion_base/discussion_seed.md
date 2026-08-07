# Discussion Seed

このメモは、集計表から論文・発表用の考察へ展開するためのたたき台。数値は `03_aggregated_results` を正とする。

## Main Takeaways

1. `gpt-5.4-mini` は `gpt-4.1-mini` より明確に高い。
   - overall で action recall は 0.466 から 0.798、evidence recall は 0.195 から 0.703、order は 0.201 から 0.553 に上がる。
   - precision も 0.366 から 0.584 に上がり、overclaim は 1190 から 651 に減る。

2. `gpt-4.1-mini` は行動の一部を拾えるが、証跡と順序が弱い。
   - stage1 でも evidence recall は 0.292、stage2 は 0.128、stage3 は 0.164。
   - 行動らしい記述は出すが、ログ証跡と結びつけた再構成までは安定しない。

3. `gpt-5.4-mini` は stage2 / stage3 でも大きく崩れない。
   - stage1: action 0.791 / evidence 0.574 / order 0.579。
   - stage2: action 0.800 / evidence 0.754 / order 0.540。
   - stage3: action 0.802 / evidence 0.779 / order 0.540。
   - CBC alert を抜いた stage3 でも証跡 recall が落ちていないため、alert summary ではなく telemetry 側から必要情報を拾えている可能性がある。

4. `gpt-5.5 low raw` は内容回収力は非常に高いが、形式失敗を分けて報告する必要がある。
   - overall で action 0.940、evidence 0.928、order 0.889。
   - ただし raw text salvage であり、構造化出力契約に失敗している。
   - precision は 0.667、overclaim は69 runsで350。高 recall と引き換えに余計な主張も多い可能性がある。

## Scenario-Level Reading

`by_scenario_group.csv` の3分類では、`gpt-5.4-mini` は explicit execution 系で特に強い。

| model | scenario | action | evidence | order | precision |
| --- | --- | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | explicit_execution_chain | 0.501 | 0.237 | 0.243 | 0.351 |
| gpt-4.1-mini | multi_step_tool_chain | 0.428 | 0.158 | 0.176 | 0.382 |
| gpt-5.4-mini | explicit_execution_chain | 0.865 | 0.824 | 0.764 | 0.640 |
| gpt-5.4-mini | multi_step_tool_chain | 0.746 | 0.602 | 0.431 | 0.469 |
| gpt-5.5 low raw | explicit_execution_chain | 0.971 | 0.978 | 0.958 | 0.650 |
| gpt-5.5 low raw | multi_step_tool_chain | 0.903 | 0.903 | 0.861 | 0.681 |

考察候補:

- explicit execution はコマンド実行やネットワークサービス起動など、ログ上の因果が比較的明示的で、モデルが構造を追いやすい。
- multi-step tool chain は複数ツール・複数イベントをまたぐため、行動 recall より順序・証跡 recall が落ちやすい。
- semantic interpretation は chain_count が1なので、一般化した主張には使いにくい。補助的な例示に留める。

## Stage-Level Reading

- stage1 は CBC alert を含むため、起点をつかみやすい一方、alert 文面に引っ張られて過剰主張する可能性がある。
- stage2 はプロセス・時間範囲が中心で、alert に頼れないため、ログ探索能力と関係抽出能力が効く。
- stage3 は CBC alert 系 summary rows を抜いた条件。正解も alert-only evidence を除いて採点しているため、non-alert telemetry をどれだけ使えるかを見る条件。
- `gpt-5.4-mini` で stage3 が stage2 より悪化していない点は、alert が常に助けになるわけではなく、場合によってはノイズにもなり得ることを示唆する。

## Reporting Cautions

- 4.1/5.4 の3セット平均は、2セットの formal23 実験と1セットの legacy27 filtered 実験を混ぜている。再現実験としては妥当だが、完全に同一ランナー条件の3反復ではない。
- GPT-5.5 は1セットのみで、かつ raw text salvage。4.1/5.4 の formal JSON 成功条件と同列に「運用可能」とは言わない。
- precision と overclaim は発表時に必ず併記する。高 recall のモデルほど余計な補完を出している可能性があるため。
- 旧27 filtered を使った3セット目の由来は、`03_aggregated_results/by_replicate_4_1_5_4.csv` と `01_experiment_raw_outputs/filtered_3run_input_manifest.json` で確認できる。

## Suggested Figure/Table Plan

1. Main table: `overall.csv` から model x metric。
2. Stage table: `by_stage.csv` から stage別比較。
3. Scenario table: `by_scenario_group.csv` から explicit / multi-step / semantic の比較。
4. Caveat paragraph: GPT-5.5 は raw salvage、4.1/5.4 3セット目は legacy27 filtered。
