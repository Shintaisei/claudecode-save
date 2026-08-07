# 100event 純モデル third pass 比較

## 目的

`3000 event` の review set を、さらに `100 event` まで純モデルで圧縮できるかを確認する。

ここでは、second pass で採用した `top30 chunk = 3000 event` を入力とし、その内部を `10 event micro-chunk` に切って `top10 micro-chunk = 100 event` を作る。

求める条件は次の 2 点である。

1. `100 event` に `attack` が混ざること
2. 同時に `false positive` 側も残ること

## 固定条件

- first pass: `10分 sequence-level IsolationForest`
- second pass: `100 event chunk-level IsolationForest`
- third pass 入力: `top30 chunk = 3000 event`
- third pass 単位: `10 event micro-chunk`
- 最終 100event: `top10 micro-chunk`

実行スクリプト:
- [benchmark_third_pass_models.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/benchmark_third_pass_models.py:1)
- [export_thirdpass_top_microchunks.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/export_thirdpass_top_microchunks.py:1)

## まず見たモデル

third pass では、重さと second pass の結果を踏まえて、まず `IsolationForest` と `kNN` を比較した。

## 結果

### IsolationForest third pass

| scenario | first attack rank | top10 attack | 読み |
| --- | ---: | ---: | --- |
| `S3` | `135` | `0` | attack を 100event に残せない |
| `M4` | `168` | `0` | attack を 100event に残せない |
| `M6` | `null` | `0` | attack 不在 |
| `S4` | `13` | `0` | 300event までは近いが 100event では消える |

結論:
- `IF -> IF -> IF` の 3 段は、`100event` まで行くと細粒度で benign rare pattern に引っ張られやすい
- 3000event 圧縮には有効だが、100event の最終抽出器としては弱い

### kNN third pass

| scenario | first attack rank | top10 attack | top10 normal | 読み |
| --- | ---: | ---: | ---: | --- |
| `S3` | `56` | `0` | `100` | attack は残らない |
| `M4` | `3` | `1` | `99` | attack と FP の混在を作れる |
| `M6` | `null` | `0` | `100` | attack 不在 |
| `S4` | `9` | `1` | `99` | attack と FP の混在を作れる |

結論:
- `kNN` は `M4` と `S4` で `100event` に attack を残せた
- `S3` は `3000event` までは attack を残せても、`100event` まで行くと落ちる
- `M6` は first pass からの難しさがそのまま残る

## 研究上の読み

### 成立したこと

- `3000event -> 100event` も model-only で試せる
- `M4 / S4` では `kNN third pass` により、`attack を完全に消さず、false positive も残す 100event` を作れた

### まだ難しいこと

- `S3` は `100event` までの極端な圧縮で attack が落ちる
- `M6` は upstream 側の難しさが大きく、third pass では救えない

## 現時点の判断

### 標準手法として強い部分

- `数万 -> 3000event`: `IF second pass` でかなり安定

### 100event までの pure model 候補

- 第一候補: `kNN third pass`
- 理由:
  - `M4 / S4` で `top10 micro-chunk = 100event` に attack と FP の両方が残る
  - `IF third pass` より明確に良い

### ただし限界

- 単一の third-pass モデルで `S3 / M4 / M6 / S4` 全部をきれいに通す段階までは到達していない
- そのため、`100event` は今のところ
  - `M4 / S4`: pure model でもかなり使える
  - `S3`: attack-near を強く残すにはまだ追加工夫が必要
  - `M6`: difficulty case として逆考察に使いやすい

## 実ログ出力

kNN third pass の `100event` は review 可能な形で出力済み。

- [S3 kNN review100](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/thirdpass_model_benchmark_benign1to4/s3_knn_review100/top_micro_index.md:1)
- [M4 kNN review100](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/thirdpass_model_benchmark_benign1to4/m4_knn_review100/top_micro_index.md:1)
- [M6 kNN review100](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/thirdpass_model_benchmark_benign1to4/m6_knn_review100/top_micro_index.md:1)
- [S4 kNN review100](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/thirdpass_model_benchmark_benign1to4/s4_knn_review100/top_micro_index.md:1)

各ディレクトリには次がある。

- `top_micro_index.md`
- `top_micro_raw_events.json`
- `top_micro_flat_events.csv`
