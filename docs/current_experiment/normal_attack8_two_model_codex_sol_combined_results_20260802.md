# 正常8＋攻撃8 two-model formal：Codex Sol 統合結果

正常48件と攻撃48件、合計96件の実験・監査・Codex `gpt-5.6-sol` 採点が完了した。OpenAI judge API/API scorerは使用していない。正常は48/48 PASS、攻撃は元run 47件とcreate-only retry 1件を正式採用して48/48 PASSである。

| 対象 | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| 正常48件 | 150/414 = **36.23%** | 150/354 = **42.37%** | 21/138 = **15.22%** | 9/138 = **6.52%** | 23/90 = **25.56%** |
| 攻撃48件 | 187/774 = **24.16%** | 187/408 = **45.83%** | 50/258 = **19.38%** | 21/258 = **8.14%** | 15/210 = **7.14%** |
| **全96件** | **337/1188 = 28.37%** | **337/762 = 44.23%** | **71/396 = 17.93%** | **30/396 = 7.58%** | **38/300 = 12.67%** |

## モデル別（正常＋攻撃）

| モデル | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 238/594 = **40.07%** | 238/530 = **44.91%** | 51/198 = **25.76%** | 13/198 = **6.57%** | 32/150 = **21.33%** |
| `gpt-5.4-mini` | 99/594 = **16.67%** | 99/232 = **42.67%** | 20/198 = **10.10%** | 17/198 = **8.59%** | 6/150 = **4.00%** |

`gpt-4.1-mini`はRecall、完全step、順序で高い一方、調査量と費用も大きい。`gpt-5.4-mini`は候補数を抑えるためprecisionは近いが、後続pivotと因果edgeの回収不足によりRecallとOrderが低い。

## 調査量と費用

| 対象 | Tokens | Cost | Wall time合計 | Chief leads | Investigator questions | SQL queries |
|---|---:|---:|---:|---:|---:|---:|
| 正常48件 | 20,545,933 | $6.764427 | 18,359.845秒 | 447 | 1,556 | 2,395 |
| 攻撃48件 | 22,696,689 | $7.816533 | 16,606.682秒 | 408 | 1,325 | 1,973 |
| **全96件** | **43,242,622** | **$14.580960** | **34,966.527秒** | **855** | **2,881** | **4,368** |

Gold action hitはcandidate TP slotと`matched_gold_item_id`のunique coverageから決定論的に導出した。Gold hitとTP matchingの不一致は0、duplicate TPは0。PIDとhidden alert mappingは非採点、actionはoperationとして評価し、Critical evidenceと隣接order pairは別診断とした。攻撃の元失敗runは凍結保持し、retry SHA-256 `b6d70634d3a51682093eeb0b13833f68a0085092771aa316b470d626451fd21b`だけを正式採用した。

詳細は`normal8_two_model_three_stage_codex_sol_results_20260802.md`、`attack8_two_model_three_stage_codex_sol_results_20260802.md`、`results_2026-08-02/attack8_two_model_three_stage_formal_20_composite_audit_20260802.json`を参照。

