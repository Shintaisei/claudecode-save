# 3000event 純モデル second pass 比較

## 目的

`3000 event` までの絞り込みを、`hybrid second pass` のような hand-crafted ルールではなく、`100 event chunk` に対する純モデル異常検知で置き換えられるかを確認する。

ここで固定したい論点は次の 2 点である。

1. `3000 event` を rule-based ではなく model-based に作れるか
2. そのとき `attack` が完全に消えず、同時に `false positive` も残るか

## 固定条件

- 学習データ
  - `Security benign-1to4`
- first pass
  - `10分 sequence`
  - `IsolationForest`
  - 既存の `iforest_benign1to4_*_cu10_g1_2_c010` を共通利用
- second pass
  - first pass で残った sequence の内部だけを対象
  - `100 event chunk` に分割
  - chunk ごとに異常スコアを付与
- 3000event の定義
  - `top30 chunk`
  - `100 event x 30 = 3000 event`

## 比較したモデル

- `IsolationForest`
- `LOF`
- `One-Class SVM`
- `SGD One-Class SVM`
- `kNN distance`

実行スクリプト:
- [benchmark_second_pass_models.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/benchmark_second_pass_models.py:1)
- [summarize_second_pass_model_benchmark.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/summarize_second_pass_model_benchmark.py:1)

結果サマリ:
- [summary_all.json](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/secondpass_model_benchmark_benign1to4/summary_all.json:1)

## 比較基準

通常の `chunk-level F1` だけでは今回の目的に合わないため、次を重視した。

1. `top10 chunk` に attack が入るか
2. `top30 chunk` に attack が入るか
3. `top10 / top30` の両方で `false positive` も残るか
4. `first_attack_rank` がどれだけ早いか

要するに、`attack を前に出しつつ、false positive も読む余地を残せるか` を見た。

## 結果

### S3

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| IF | no | yes (`4 event`) | `20` | top30 なら attack を残せる |
| LOF | no | no | `267` | 攻撃がかなり後ろ |
| OCSVM | no | no | `89` | 攻撃が残らない |
| SGD-OCSVM | no | no | `332` | 攻撃が残らない |
| kNN | no | no | `64` | 攻撃が残らない |

### M4

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| IF | yes (`1 event`) | yes | `2` | かなり良い |
| LOF | no | yes (`1 event`) | `11` | top10 では落ちる |
| OCSVM | no | no | `61` | 攻撃が残らない |
| SGD-OCSVM | no | no | `55` | 攻撃が残らない |
| kNN | yes (`1 event`) | yes | `10` | IF より少し弱いが悪くない |

### M6

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| IF | no | no | `null` | first pass 側で attack が残っていない |
| LOF | no | no | `null` | 同上 |
| OCSVM | no | no | `null` | 同上 |
| SGD-OCSVM | no | no | `null` | 同上 |
| kNN | no | no | `null` | 同上 |

### S4

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| IF | yes (`1 event`) | yes (`3 event`) | `3` | かなり良い |
| LOF | no | no | `468` | ほぼ使えない |
| OCSVM | no | no | `46` | 攻撃が残らない |
| SGD-OCSVM | no | no | `37` | 攻撃が残らない |
| kNN | no | yes (`1 event`) | `15` | top30 なら少し残る |

## 判断

### 採用する second pass

`100 event chunk` に対する `IsolationForest` を採用する。

理由:

- `S4` で `top10` の時点で attack が残る
- `M4` でも `top10` の時点で attack が残る
- `S3` は `top10` では落ちるが、`top30=3000 event` まで広げると attack を残せる
- `false positive chunk` は全 scenario で十分残る
- `LOF / OCSVM / SGD-OCSVM` は attack を前に出せない
- `kNN` は `M4` では良いが、`S4` と `S3` の安定性で IF に負ける

### 研究上の言い方

`3000 event` までの圧縮は、`first pass の sequence-level IsolationForest` に続いて、`second pass の 100-event chunk-level IsolationForest` を適用する 2 段階異常検知として実装できる。

このとき、`top30 chunk = 3000 event` を review set とすることで、`attack を完全に消さずに false positive も残す` という要件を、少なくとも `S3 / M4 / S4` では満たせた。

### 限界

- `M6` は second pass の問題というより、first pass の段階で attack を十分に残せていない
- `top30` という cutoff 自体は設計パラメータなので、今後は `top20 / top30 / top40` 感度比較もあり得る
- ただし、今回の論点である `3000 event をルールではなくモデルで作る` という点は満たせている

## 実装上の結論

今後の標準フローは次で進める。

1. `Security benign-1to4` で `10分 sequence-level IF`
2. 予測 positive sequence のみ残す
3. その内部を `100 event chunk` に切る
4. `chunk-level IF` を適用
5. `top30 chunk = 3000 event` を review set とする
6. その後段で `Sysmon minute` へ降りる

この構成なら、`3000` までの圧縮は純モデルで説明できる。

## 3000event review 出力

採用した `chunk-level IF` については、各 scenario の `top30 chunk = 3000 event` を review 可能な形で出力済み。

- [S3 review3000](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/secondpass_model_benchmark_benign1to4/s3_iforest_review3000/top_chunks_index.md:1)
- [M4 review3000](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/secondpass_model_benchmark_benign1to4/m4_iforest_review3000/top_chunks_index.md:1)
- [M6 review3000](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/secondpass_model_benchmark_benign1to4/m6_iforest_review3000/top_chunks_index.md:1)
- [S4 review3000](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/secondpass_model_benchmark_benign1to4/s4_iforest_review3000/top_chunks_index.md:1)

各 review ディレクトリには次がある。

- `top_chunks_index.md`
- `top_chunks_raw_events.json`
- `top_chunks_flat_events.csv`
