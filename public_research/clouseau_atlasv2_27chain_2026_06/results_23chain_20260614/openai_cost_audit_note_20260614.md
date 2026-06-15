# OpenAI Cost Audit Note 2026-06-14

## 結論

まひし用OpenAI APIアカウントで報告された本日までの使用料 `$214.98` は、ローカルログ上の `gpt-5.5` 実験だけで大部分を説明できる。

主因は、`gpt-5.5` の費用が `clouseau_api_costs.csv` 上で全103成功runとも `$0.00` と記録されていたこと、および以前の概算で `gpt-5.5` の出力単価を大きく過小評価していたこと。

## ローカルで確認できた使用量

対象: `data/current_experiment/runs/clouseau_reconstruction_outputs/**/run.json`

| model | run.json files | success | error | input tokens | output tokens | local estimate note |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| gpt-4.1-mini | 334 | 307 | 5 | 8,436,847 | 860,617 | 低単価なので数ドル規模 |
| gpt-5.4-mini | 244 | 231 | 2 | 2,340,662 | 724,609 | 低単価なので数ドル規模 |
| gpt-5.5 | 112 | 103 | 9 | 2,793,958 | 1,121,828 | 主な費用源 |

`gpt-5.5` の成功runは103件あり、1runあたり出力が8,000から18,000 tokens程度出ている。出力tokenが特に重い。

## $214.98との整合

ローカルの既存cost logで、`gpt-5.5` 以外に明示記録されている費用は概ね以下。

| cost log | logged total |
| --- | ---: |
| `clouseau_api_costs.csv` | `$5.57` |
| `data/current_experiment/costs/clouseau_api_costs.csv` | `$4.41` |
| subtotal | `$9.98` |

`gpt-5.5` について、入力単価を `$15/M tokens` と仮定し、出力単価を変えて計算すると以下になる。

| gpt-5.5 price assumption | gpt-5.5 cost | + logged non-gpt-5.5 | total |
| --- | ---: | ---: | ---: |
| input `$15/M`, output `$120/M` | `$176.53` | `$9.98` | `$186.51` |
| input `$15/M`, output `$140/M` | `$198.97` | `$9.98` | `$208.95` |
| input `$15/M`, output `$145/M` | `$204.57` | `$9.98` | `$214.55` |
| input `$15/M`, output `$150/M` | `$210.18` | `$9.98` | `$220.16` |

報告額 `$214.98` から逆算すると、`gpt-5.5` の出力単価は約 `$145/M tokens` 相当になる。したがって、報告額はローカルの `gpt-5.5` 実験ログとかなり整合する。

## なぜ以前の計算とズレたか

1. `clouseau_api_costs.csv` では `gpt-5.5` の103成功runがすべて `call_total_usd=0.00` になっていた。
2. 以前の概算では、`gpt-5.5` の高い出力単価を反映できていなかった。
3. `gpt-5.5` は出力が非常に長く、103成功runで `1,121,828 output tokens` 出ていた。
4. OpenAI側のCosts APIは、現在のキーでは `api.usage.read` 権限不足で取得できなかったため、公式内訳まではローカルから検証できない。

## 事故としての評価

「別用途で大量に使った」というより、今回の実験で `gpt-5.5` を走らせた分が主要因と見るのが自然。特に、出力契約に失敗してraw textが長く出たrunが多く、出力token課金が膨らんだ。

今後は、`gpt-5.5` 以上の高単価モデルでは、実験前に次を必須にする。

- `max_output_tokens` を厳しく制限する。
- 1runごとに実費見積もりを即時計算して、累積上限で停止する。
- `call_total_usd=0` のまま進めない。
- まず3から5件のpilotで実測tokenを取り、全量実験に外挿する。
- 高単価モデルは構造化出力契約をpilotで確認してから本実行する。
