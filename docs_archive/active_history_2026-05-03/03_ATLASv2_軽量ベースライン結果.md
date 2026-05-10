# ATLAS v2 軽量ベースライン結果

更新日: 2026-05-03

## 1. 目的

`deep-loglizer` 自体のデータ変換までは完了したが、この端末では `torch` の DLL 読み込みが失敗し、LSTM / Transformer 実行が止まっている。
そのため、研究の流れを止めないために、まずは正常 day を学習して attack scenario を評価する軽量な next-event n-gram ベースラインを走らせた。

利用スクリプト:

- `scripts/run_atlasv2_ngram_baseline.py`

## 2. 実験設定

- train: `analysis_data/atlasv2_for_deep-loglizer/benign1_cu30/session_train.pkl`
- test: 各 attack scenario の packaged dataset
- session 単位: `computer_user` + 30分バケット
- モデル: next-event n-gram
- `window_size=5`
- `topk=5`
- `min_context_count=1`

評価の見方:

- `flagged_ratio`: 全 window のうち異常扱いになった割合
- `precision_proxy`: 異常扱い window のうち、実際に異常イベントを含む割合
- `recall_proxy`: 異常イベントを含む window をどれだけ拾えたか

## 3. 結果

| Scenario | Total windows | Flagged ratio | TP windows | Labeled anomalous windows | Precision proxy | Recall proxy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| S3 | 252,390 | 99.319% | 1,129 | 1,129 | 0.450% | 100% |
| S4 | 229,494 | 99.279% | 1,923 | 1,923 | 0.844% | 100% |
| M4 | 197,819 | 98.296% | 1,310 | 1,310 | 0.674% | 100% |
| M5 | 310,010 | 98.056% | 1,186 | 1,186 | 0.390% | 100% |
| M6 | 217,417 | 99.153% | 1,125 | 1,125 | 0.522% | 100% |

結果ファイル:

- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_s3/ngram_w5_top5.json`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_s4/ngram_w5_top5.json`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_m4/ngram_w5_top5.json`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_m5/ngram_w5_top5.json`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_m6/ngram_w5_top5.json`

## 4. 読み取り

このベースラインは異常 window を取り逃がしていない。
一方で、正常寄りの window もほぼ全部はじいており、`flagged_ratio` が 98% から 99% を超えている。

つまり ATLAS v2 では、

1. 異常は正常系列の中に少量だけ埋まっている
2. 正常 day だけで学習した単純な系列モデルは attack day の文脈差分をほぼ全部異常扱いする
3. 「異常を見つける」だけではなく「正常文脈を残して絞り込めるか」が本質になる

ということが改めて見えた。

## 5. 研究方針への含意

この結果は、すでに確認済みの
「異常シーケンス中のイベントの大半は正常である」
という観察と整合している。

既存の定量結果:

- `analysis_data/atlasv2_for_deep-loglizer/attack_session_normality_summary.json`
- 異常 session 内の正常イベント比率は各 scenario でおよそ 99.77% から 99.85%

したがって次の焦点は、

1. 異常シーケンスそのものを生成・比較対象にすること
2. 正常文脈を多く含む異常シーケンスの中で、どこが逸脱点になるかを見ること
3. 正常 day との単純差分ではなく、attack day 内の局所的な不自然さを捉えること

になる。

## 6. 実行コマンド

```powershell
python scripts\run_atlasv2_ngram_baseline.py `
  --data-dir analysis_data\atlasv2_for_deep-loglizer\exp_benign1_vs_s3 `
  --window-size 5 `
  --topk 5
```

scenario を変える場合は `exp_benign1_vs_s3` の部分を `s4`, `m4`, `m5`, `m6` に差し替える。

## 7. 次の一手

1. n-gram の `window_size` と `topk` を振って、過剰検知の下がり方を見る
2. session の切り方を `computer_process` などにも変えて比較する
3. `torch` 実行環境を別マシンまたは別 runtime で確保し、`deep-loglizer` の LSTM / Transformer に進む
4. 異常シーケンスから正常成分をどれだけ含むかを説明できる指標に落とす
