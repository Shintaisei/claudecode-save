# Attack8 2モデル×3 Stage Codex正式採点（2026-08-02）

OpenAI judge API/API scorerは不使用。47件のmain valid runと指定retry 1件を合成し、元の失敗runは凍結保持した。

## 主要指標

| 集計 | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| 全48件 | 187/774 = 24.16% | 187/408 = 45.83% | 50/258 = 19.38% | 21/258 = 8.14% | 15/210 = 7.14% |
| gpt-4.1-mini | 132/387 = 34.11% | 132/291 = 45.36% | 34/129 = 26.36% | 12/129 = 9.30% | 13/105 = 12.38% |
| gpt-5.4-mini | 55/387 = 14.21% | 55/117 = 47.01% | 16/129 = 12.40% | 9/129 = 6.98% | 2/105 = 1.90% |
| stage1 | 48/258 = 18.60% | 48/135 = 35.56% | 13/86 = 15.12% | 2/86 = 2.33% | 4/70 = 5.71% |
| stage2 | 76/258 = 29.46% | 76/135 = 56.30% | 20/86 = 23.26% | 7/86 = 8.14% | 8/70 = 11.43% |
| stage3 | 63/258 = 24.42% | 63/138 = 45.65% | 17/86 = 19.77% | 12/86 = 13.95% | 3/70 = 4.29% |

## ケース別

| ケース | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| s3_pt_01_word_document_processing | 15/36 = 41.67% | 15/39 = 38.46% | 3/12 = 25.00% | 2/12 = 16.67% | 0/6 = 0.00% |
| s3_pt_02_regsvr32_remote_sct | 18/54 = 33.33% | 18/39 = 46.15% | 6/18 = 33.33% | 4/18 = 22.22% | 3/12 = 25.00% |
| s3_pt_03_regsvr32_long_chain | 32/144 = 22.22% | 32/75 = 42.67% | 6/48 = 12.50% | 4/48 = 8.33% | 5/42 = 11.90% |
| s3_pt_04_powershell_mid_chain | 32/126 = 25.40% | 32/54 = 59.26% | 9/42 = 21.43% | 3/42 = 7.14% | 2/36 = 5.56% |
| s4_pt_01_word_w1 | 19/72 = 26.39% | 19/39 = 48.72% | 5/24 = 20.83% | 2/24 = 8.33% | 1/18 = 5.56% |
| s4_pt_02_word_w3 | 11/54 = 20.37% | 11/45 = 24.44% | 3/18 = 16.67% | 1/18 = 5.56% | 0/12 = 0.00% |
| s4_pt_03_mshta_c1 | 27/162 = 16.67% | 27/54 = 50.00% | 7/54 = 12.96% | 2/54 = 3.70% | 1/48 = 2.08% |
| s4_pt_04_powershell_c1 | 33/126 = 26.19% | 33/63 = 52.38% | 11/42 = 26.19% | 3/42 = 7.14% | 3/36 = 8.33% |

## 監査
- status: **pass**
- 48/48 rows、Action 774 items、candidate 408 slots、behavior 258 steps、critical 258 items、order 210 pairsを固定分母で照合。
- Gold=1/TPなし: 0、TP/Gold=0: 0、duplicate TP: 0。
- retry SHA-256: `b6d70634d3a51682093eeb0b13833f68a0085092771aa316b470d626451fd21b`

## 調査・失敗分析

| モデル | Chief leads / unique | Investigator questions / unique | SQL queries / unique | input / output tokens | cost (USD) | elapsed (s) |
|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 318 / 300 | 1,246 / 1,246 | 1,824 / 1,806 | 19,113,005 / 1,035,779 | 6.1097572 | 15,336.887 |
| gpt-5.4-mini | 90 / 85 | 79 / 79 | 149 / 149 | 2,359,320 / 188,585 | 1.7067753 | 1,269.795 |

- 未取得Gold step（run横断）: 188、隣接因果edge欠落: 195。
- 近傍/Gold外slot: 198、幻覚リスクclaim: 66。
- 主な未取得要因は、起点近傍だけで停止すること、正しい後続frontierへのpivot欠落、複数の観測を因果edgeとして統合できないこと、時刻近傍のDLL・一時ファイル・レジストリを主行動へ過剰接続すること。

機械可読な全run hash・case hash・Gold hash、全Gold item、candidate slot、order pair、固定分母はscore rootの `formal_scores.json` と `per_run_scores.jsonl` に記録した。
