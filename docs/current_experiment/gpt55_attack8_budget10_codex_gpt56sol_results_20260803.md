# gpt-5.5 Attack8 budget10 独立Codex正式採点（2026-08-03）

Reviewer: Codex gpt-5.6-sol。OpenAI judge API/API scorerは不使用。budget-censored 2件は凍結保持し、headline精度から除外した。

## Headline（22 PASS）

| Model（matched 22 strata） | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 112/339 = 33.04% | 112/255 = 43.92% | 28/113 = 24.78% | 12/113 = 10.62% | 11/91 = 12.09% |
| gpt-5.4-mini | 52/339 = 15.34% | 52/111 = 46.85% | 15/113 = 13.27% | 8/113 = 7.08% | 2/91 = 2.20% |
| gpt-5.5 | 219/339 = 64.60% | 219/429 = 51.05% | 71/113 = 62.83% | 68/113 = 60.18% | 46/91 = 50.55% |

## gpt-5.5 Stage別

| Stage | Action | Precision | Behavior | Critical | Order |
|---|---:|---:|---:|---:|---:|
| stage1 | 45/108 = 41.67% | 45/120 = 37.50% | 13/36 = 36.11% | 12/36 = 33.33% | 7/29 = 24.14% |
| stage2 | 99/129 = 76.74% | 99/171 = 57.89% | 33/43 = 76.74% | 32/43 = 74.42% | 22/35 = 62.86% |
| stage3 | 75/102 = 73.53% | 75/138 = 54.35% | 25/34 = 73.53% | 24/34 = 70.59% | 17/27 = 62.96% |

## gpt-5.5 ケース別

| Case | Action | Precision | Behavior | Critical | Order |
|---|---:|---:|---:|---:|---:|
| s3_pt_01_word_document_processing | 8/18 = 44.44% | 8/30 = 26.67% | 2/6 = 33.33% | 2/6 = 33.33% | 0/3 = 0.00% |
| s3_pt_02_regsvr32_remote_sct | 21/27 = 77.78% | 21/45 = 46.67% | 7/9 = 77.78% | 6/9 = 66.67% | 4/6 = 66.67% |
| s3_pt_03_regsvr32_long_chain | 51/72 = 70.83% | 51/84 = 60.71% | 17/24 = 70.83% | 17/24 = 70.83% | 12/21 = 57.14% |
| s3_pt_04_powershell_mid_chain | 56/63 = 88.89% | 56/99 = 56.57% | 18/21 = 85.71% | 19/21 = 90.48% | 14/18 = 77.78% |
| s4_pt_01_word_w1 | 23/36 = 63.89% | 23/51 = 45.10% | 7/12 = 58.33% | 7/12 = 58.33% | 4/9 = 44.44% |
| s4_pt_02_word_w3 | 12/27 = 44.44% | 12/48 = 25.00% | 4/9 = 44.44% | 1/9 = 11.11% | 1/6 = 16.67% |
| s4_pt_03_mshta_c1 | 30/54 = 55.56% | 30/39 = 76.92% | 10/18 = 55.56% | 10/18 = 55.56% | 7/16 = 43.75% |
| s4_pt_04_powershell_c1 | 18/42 = 42.86% | 18/33 = 54.55% | 6/14 = 42.86% | 6/14 = 42.86% | 4/12 = 33.33% |

## 監査・budget影響
- cross-field status: **pass**。22 score rows / 24 audit inventory、Action 339、candidate 429、behavior/critical 113、order 91。
- Gold=1/TPなし 0、TP/Gold=0 0、duplicate TP 0。
- 除外: `s4_pt_03_mshta_c1_stage3`、`s4_pt_04_powershell_c1_stage1`。除外2件のcost $20.395164、tokens 4,816,149。
- soft-triggered non-censored: 1件（headlineに含む）。Gold分母はAction -48、Behavior/Critical -16、Order -14。

## 調査行動・資源比較（matched 22）

| Model | Chief leads / unique | Questions | SQL | input / output tokens | cost | elapsed |
|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 300 / 283 | 1,147 | 1,675 | 15,322,468 / 907,730 | $4.857528 | 13,422.278s |
| gpt-5.4-mini | 85 / 80 | 76 | 144 | 2,271,649 / 182,070 | $1.643500 | 1,218.670s |
| gpt-5.5 | 142 / 140 | 260 | 743 | 15,513,859 / 1,915,149 | $98.721754 | 19,191.578s |

gpt-5.5のheadline 22件は1,481 API calls、cached input 8,460,672 tokensだった。

## 失敗分析
- Gold step無整合claim 39、不完全Behavior step 42、隣接因果edge欠落 45。
- nearby/unsupported slots 207、wrong-component slots 3。
- Long-chain runs often recover the central process lineage but omit the 8443 pivot or collapse 8080/8443 into one claim. Word cases frequently substitute normal.dotm, VBA modules, registry, API-call, or temporary-file activity for the Gold document-open edge. Nearby telemetry is therefore a major precision and causal-order failure mode.

## Formal contract追記案
- Pre-register soft/hard budget thresholds and inclusion policy before execution.
- A run with run_budget_guard.budget_censored=true is excluded from headline accuracy and retained as a frozen censored artifact; it is not scored as zero.
- A soft-triggered run that emits valid final JSON and is not budget-censored remains headline-eligible, with budget_limited status reported.
- All model comparisons use the intersection of headline-eligible case×stage strata; full-grid values may be shown only as labeled references.
- Publish the 24-run audit inventory, inclusion mask, run/audit hashes, excluded denominator delta, and censored resource use.
- Any rerun/replacement must use a new versioned root and declare both original and replacement hashes; never overwrite the censored run.
- Gold denominators are fixed by eligible strata; candidate precision denominator is three fixed subject/operation/object slots per emitted code step.

全run/Gold hash、全Gold item、candidate slot、order pair、固定分母、totals、モデル/Stage/ケース別比較はscore rootと報告JSONに記録した。
