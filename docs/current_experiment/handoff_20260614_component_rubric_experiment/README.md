# Component Rubric Experiment Handoff 2026-06-14

このフォルダは、2026-06-14 時点の Clouseau/ATLAS 系モデル比較実験を次セッションへ引き継ぐための作業用パッケージです。発表・論文用の考察は、まず `03_aggregated_results` の集計を土台にする。

## フォルダ構成

| folder | role |
| --- | --- |
| `01_experiment_raw_outputs/` | 実験の生出力 JSON。最終比較に使う formal23 2周分、旧27チェーン filtered 用 raw、GPT-5.5 1周分を短い階層名で保存。 |
| `02_scoring_ledgers/` | 採点ルーブリック、Codex 2重レビュー、第三レビュー、旧27チェーン採点 CSV。監査・再集計時に使う。 |
| `03_aggregated_results/` | 現時点で発表用の土台にする集計表。overall、stage別、場面分類別、per-run ledger を含む。 |
| `04_discussion_base/` | 考察のたたき台。数値から言えそうなこと、制約、論文での注意点を書く。 |

## 最終比較の扱い

- `gpt-4.1-mini` と `gpt-5.4-mini` は 23チェーン x 3ステージ x 3セット。
- ただし3セット目は formal23 の `replicate_03` ではない。旧27チェーン実験を現在の23チェーン対象へフィルタしたものを「実質3セット目」として扱う。
- `gpt-5.5 low raw` は 23チェーン x 3ステージ x 1セットのみ。出力契約に失敗したため、JSON構造の成功とは別に、素の出力から内容を拾う salvage 評価として扱う。
- 採点方針は component rubric。主語・対象・行動・証跡などの正解内容が候補出力内に含まれていれば hit とする。表現やフィールド名が違っても内容が合えば可。alert-only evidence は non-alert evidence としては数えない。

## 代表値

| model | runs | action recall | evidence recall | order | precision | overclaims |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 207 | 0.466 | 0.195 | 0.201 | 0.366 | 1190 |
| gpt-5.4-mini | 207 | 0.798 | 0.703 | 0.553 | 0.584 | 651 |
| gpt-5.5 low raw | 69 | 0.940 | 0.928 | 0.889 | 0.667 | 350 |

## 次に見るファイル

1. `03_aggregated_results/summary.md`
2. `03_aggregated_results/overall.csv`
3. `03_aggregated_results/by_stage.csv`
4. `03_aggregated_results/by_scenario_group.csv`
5. `04_discussion_base/discussion_seed.md`

## 注意

このフォルダは引き継ぎと考察のための整理済みコピーであり、元データの完全な置き換えではない。元の実験フォルダ・採点フォルダへの参照は各サブフォルダの README と manifest に残している。
