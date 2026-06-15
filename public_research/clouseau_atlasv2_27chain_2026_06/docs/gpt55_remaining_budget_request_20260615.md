# GPT-5.5 Remaining Budget Estimate 2026-06-15

This note estimates the additional OpenAI API budget needed to finish the remaining GPT-5.5 experiment runs.

## Basis

Observed GPT-5.5 usage in the local audit:

| item | value |
| --- | ---: |
| successful GPT-5.5 runs already executed | 103 |
| input tokens already used | 2,793,958 |
| output tokens already used | 1,121,828 |
| model-only reconstructed cost | $204.57 |
| reported account-level usage including small non-GPT-5.5 costs | $214.98 |

The local cost log under-recorded GPT-5.5 calls as `$0.00`, so this estimate uses token-based reconstruction.

The price assumption used to match the reported bill is:

| token type | assumed price |
| --- | ---: |
| input | $15 / 1M tokens |
| output | $145 / 1M tokens |

This assumption reconstructs GPT-5.5 cost as:

```text
2,793,958 input tokens  * $15  / 1,000,000 = $41.91
1,121,828 output tokens * $145 / 1,000,000 = $162.67
model-only total = $204.57
```

The difference between `$204.57` and the reported `$214.98` is explained by non-GPT-5.5 costs and logged auxiliary calls.

## Average Per Successful Run

| item | per successful GPT-5.5 run |
| --- | ---: |
| input tokens | 27,126 |
| output tokens | 10,892 |
| model-only cost | $1.99 |
| account-level extrapolated cost | $2.09 |

The output side dominates the cost.

## Main Estimate: Finish From Current 103 Successful Runs

Target parity with the 23-chain three-set design is:

```text
23 chains x 3 stages x 3 sets = 207 successful runs
```

Already completed:

```text
103 successful GPT-5.5 runs
```

Remaining:

```text
207 - 103 = 104 successful runs
```

Estimated remaining tokens:

| item | estimate for 104 remaining successful runs |
| --- | ---: |
| input tokens | 2,821,084 |
| output tokens | 1,132,720 |
| total tokens | 3,953,804 |

Estimated remaining cost:

| estimate type | base estimate | +20% buffer | recommended request |
| --- | ---: | ---: | ---: |
| model-only token reconstruction | $206.56 | $247.87 | $250 |
| account-level extrapolation from reported `$214.98` | $217.07 | $260.48 | $260 |

Recommended budget request: **$260**.

This is the safer number because it uses the actual reported account-level usage, not only the model-only reconstruction.

## Conservative Alternative: If The Partial Second Set Is Discarded

If the current published/scored GPT-5.5 result is treated as only one complete set of 69 runs and the partial extra 34 successful runs are not reused, then the remaining work would be:

```text
207 - 69 = 138 successful runs
```

Estimated remaining tokens:

| item | estimate for 138 remaining successful runs |
| --- | ---: |
| input tokens | 3,743,361 |
| output tokens | 1,503,032 |
| total tokens | 5,246,393 |

Using the observed per-run averages:

| estimate type | base estimate | +20% buffer | recommended request |
| --- | ---: | ---: | ---: |
| model-only token reconstruction | $274.09 | $328.91 | $330 |
| account-level extrapolation | $288.03 | $345.64 | $350 |

Recommended budget request if discarding partial completed runs: **$350**.

## Suggested Request Text

GPT-5.5の追加実験を完遂するため、既存の実測token使用量に基づいて追加予算を申請したいです。現在までにGPT-5.5は103 successful runsを実行しており、input 2,793,958 tokens、output 1,121,828 tokensを消費しました。報告済み使用額$214.98と照合すると、GPT-5.5の実効単価はinput $15/M、output 約$145/M tokens相当で説明できます。

23チェーン x 3 stage x 3 setの設計では合計207 successful runsが必要であり、残りは104 successful runsです。実測平均では1 runあたりinput 27,126 tokens、output 10,892 tokens、アカウント実績ベースで約$2.09/runです。したがって残り104 runsは約$217.07、20%バッファ込みで約$260.48となります。追加申請額は保守的に **$260** としたいです。

もし途中まで完了した34 runsを再利用せず、公開済みの1 set 69 runsから2 set分を再実行する場合は、残り138 runsとなり、20%バッファ込みで約 **$350** が必要です。
