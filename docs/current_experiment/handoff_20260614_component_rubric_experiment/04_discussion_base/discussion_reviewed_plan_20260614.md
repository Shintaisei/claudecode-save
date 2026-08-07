# Discussion Plan With Two-Review Gate 2026-06-14

この文書は、考察作業の進め方そのものを2レビューに通すための計画書。数値の正本は `03_aggregated_results/` と `04_discussion_base/deep_dive_20260614/`。

## Review Gate

| item | Reviewer A | Reviewer B | adopted handling |
| --- | --- | --- | --- |
| GPT-5.5の扱い | raw text salvage / 69 runs / 1反復として別枠ならOK | raw text salvage / output contract failedを明記すべき | 採用。正式JSON条件の同列比較にはしない。 |
| 4.1/5.4の3セット目 | legacy27 filtered であり純粋なformal23 replicate_03ではない | legacy filtered込みはsource-set差として扱うべき | 採用。3反復の確率的揺れとは書かない。 |
| n数 | semanticは1 chainなので一般化不可 | stage x semanticはさらに小n | 採用。semanticは事例扱い。 |
| cost/time | accuracy表とは別に token/cost/timestamp を再集計すべき | valid採点対象・partial・quota失敗を分けるべき | 採用。deep_dive表で別集計。 |
| 採点揺れ | conflict件数を論点化すべき | 2レビュー一致率と第三レビュー率を出すべき | 採用。reviewer_variability表を作成。 |
| 危険表現 | 「alert不要」「GPT-5.5最良」などは不可 | 「実運用可能」「一般に有効」は条件付きにすべき | 採用。各論点に禁止/修正版を置く。 |

## Discussion Modules

| module | question | primary evidence | review requirement |
| --- | --- | --- | --- |
| M1 Overall accuracy | モデル間で何が違うか | `overall.csv`, `summary.md` | recall/precision/overclaimを併記。 |
| M2 Cost/time | どのモデルがどれだけ高い/遅いか | `cost_time_by_model.csv`, `cost_effectiveness_by_model.csv` | ログ実費とローカル価格推定を分ける。 |
| M3 Stage effect | alert有無・入力条件で何が変わるか | `by_stage.csv`, `cost_time_by_model_stage.csv` | 「alert不要」とは言わない。 |
| M4 Scenario effect | 場面別に難易度差はあるか | `by_scenario_group.csv`, `by_framework_group.csv` | n数を併記。semanticは事例扱い。 |
| M5 Model/source-set variability | モデルのブレはどの程度か | `model_replicate_variability.csv`, `by_replicate_4_1_5_4.csv` | 3反復ではなくsource-set差込み。 |
| M6 Chain-level instability | どのchainで揺れるか | `top_chain_replicate_variability.csv` | 個別ケース分析の候補として扱う。 |
| M7 Reviewer/agent variability | 採点者側の揺れはどの程度か | `reviewer_variability_summary.csv`, `reviewer_conflict_fields.csv` | 採点の不確実性として明記。 |
| M8 Contract compliance | 内容回収力と出力契約遵守を分ける | `exclusion_and_queue_status.csv`, GPT-5.5 raw notes | GPT-5.5の過大評価を避ける。 |

## Output Rule

各論点は次の構造で書く。

1. 主張
2. 根拠数値
3. 解釈
4. 言ってよい範囲
5. 言ってはいけない表現
6. Reviewer A/B の指摘反映

## Current Status

- Plan review: completed by Reviewer A and Reviewer B.
- Data deep-dive tables: generated under `04_discussion_base/deep_dive_20260614/`.
- Detailed discussion draft: `detailed_discussion_20260614.md`.
- Detailed discussion 2-review: completed by Reviewer A and Reviewer B. M2/M5/M6/M7 had required fixes; `detailed_discussion_20260614.md` has been revised to address them.
- Final confirmation: Reviewer A = `FINAL_OK`, Reviewer B = `FINAL_OK`.
