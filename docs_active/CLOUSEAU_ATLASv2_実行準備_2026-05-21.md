# CLOUSEAU ATLASv2 実行準備

## 目的

今回見つかった `U1-U6` のユースケースを、ATLASv2 の `incident.db` からそのまま実行できる形にする。

## 使う設定

ユースケース定義は以下。

- `Clouseau/artifact/scenarios/atlasv2/current_usecases.json`

現在の定義は以下の6件。

- `u1`: `m6 / repmgr.exe / normal`
- `u2`: `m6 / repwmiutils.exe / normal`
- `u3`: `s4 / tpautoconnsvc.exe / normal`
- `u4`: `s3 / searchprotocolhost.exe / normal`
- `u5`: `m4 / searchprotocolhost.exe / attack_context`
- `u6`: `s4 / searchprotocolhost.exe / attack_context`

## 実行スクリプト

- `scripts/run_atlasv2_clouseau_usecase.py`

このスクリプトは以下を行う。

1. `incident.db` から対象 actor の `4663/file` 証拠を抽出する
2. 周辺の Security / DNS / Firefox 情報を圧縮する
3. 1回の OpenAI API 呼び出しで JSON 形式の行動復元結果を返す
4. 必要なら API 料金を `clouseau_api_costs.csv` に追記する

## よく使うコマンド

一覧を見る:

```powershell
python scripts/run_atlasv2_clouseau_usecase.py --list
```

1ケースだけ実行する:

```powershell
python scripts/run_atlasv2_clouseau_usecase.py --usecase-id u1 --log-cost
```

証拠だけ作って API は呼ばない:

```powershell
python scripts/run_atlasv2_clouseau_usecase.py --usecase-id u1 --dry-run
```

全件回す:

```powershell
python scripts/run_atlasv2_clouseau_usecase.py --run-all --log-cost
```

## 出力先

実行結果は以下に保存する。

- `Clouseau/artifact/runs/atlasv2/`

1ファイルごとに以下が入る。

- `api_calls`
- `usage`
- `estimated_call_total_usd`
- `output_text`
- 抽出した evidence

## 注意

これは論文そのものの CLOUSEAU 実装ではなく、今回のローカル環境で不足していた本体部分を補う最小ランナーである。
ただし、ATLASv2 の `audit_logs / dns_logs / browser_logs` を使って、今回のユースケースを実際に回せる状態にはなっている。
