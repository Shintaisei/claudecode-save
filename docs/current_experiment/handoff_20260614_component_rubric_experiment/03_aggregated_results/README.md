# Aggregated Results

このフォルダの表を、現時点の発表・論文考察の土台にする。

## Primary Tables

| file | use |
| --- | --- |
| `summary.md` | 人間が読むための最終比較サマリ。まずこれを見る。 |
| `overall.csv` | モデル全体の代表値。 |
| `by_stage.csv` | stage1 / stage2 / stage3 別の代表値。 |
| `by_replicate_4_1_5_4.csv` | 4.1/5.4 の3セット内訳。3セット目が legacy27 filtered であることを確認する表。 |
| `by_scenario_group.csv` | 3分類の場面別集計。 |
| `by_stage_scenario_group.csv` | stage x 3分類の場面別集計。 |
| `by_framework_group.csv` | より細かい行動フレームワーク別集計。 |
| `by_stage_framework_group.csv` | stage x 行動フレームワーク別集計。 |
| `ledgers/final_comparison_per_run_component_scores.csv` | 最終比較に入れた全483 run相当の per-run ledger。 |
| `ledgers/4_1_5_4_3run_filtered23_per_run_component_scores.csv` | 4.1/5.4 の3セット filtered23 ledger。 |

## Current Final Comparison Scope

| model | scope |
| --- | --- |
| `gpt-4.1-mini` | 23 chains x 3 stages x 3 sets = 207 runs |
| `gpt-5.4-mini` | 23 chains x 3 stages x 3 sets = 207 runs |
| `gpt-5.5 low raw` | 23 chains x 3 stages x 1 set = 69 runs |

## Notes For Tables

- 4.1/5.4 の3セット目は formal23 replicate_03 ではなく、旧27チェーンを現在の23チェーンへフィルタしたもの。
- GPT-5.5 は raw text salvage。高スコアでも、構造化 JSON 契約には失敗している点を必ず併記する。
- `by_scenario_group.csv` は空分類を避けるため、同一 `chain_id` の legacy27 側分類から formal23/GPT-5.5 行へ補完済み。
