# CLOUSEAU API設定と料金管理

## 置き場所

一番上の階層に、CLOUSEAU 用の設定と料金表を置く。

- `./.env.clouseau`
- `./.env.clouseau.example`
- `./clouseau_api_costs.csv`

`Clouseau/artifact/.env` は補助用とし、基本はルートの `./.env.clouseau` を正として扱う。

## APIキー設定

1. `./.env.clouseau` に API キーを書く。
2. 必要なら以下で `Clouseau/artifact/.env` に同期する。

```powershell
python scripts/sync_clouseau_env.py
```

## 料金表

`./clouseau_api_costs.csv` には以下を記録する。

- 呼び出しごとのコスト `call_total_usd`
- その時点までの累計 `cumulative_total_usd`

列は以下。

```text
timestamp,run_id,scenario,model,input_tokens,output_tokens,cached_input_tokens,input_cost_usd,output_cost_usd,cached_input_cost_usd,call_total_usd,cumulative_total_usd,note
```

## 料金の追加

価格を `./.env.clouseau` に入れたうえで、1回の呼び出しごとに以下で追加する。

```powershell
python scripts/log_clouseau_cost.py --run-id test01 --scenario s1 --model gpt-5 --input-tokens 12000 --output-tokens 800
```

必要なら価格をコマンドで直接渡してもよい。

```powershell
python scripts/log_clouseau_cost.py --run-id test01 --scenario s1 --model gpt-5 --input-tokens 12000 --output-tokens 800 --input-price-per-1m 1.25 --output-price-per-1m 10.0
```

## 料金の確認

```powershell
python scripts/show_clouseau_costs.py
```

これで以下が見える。

- 直近の呼び出しごとの料金
- run ごとの合計
- model ごとの合計
- 全体累計
