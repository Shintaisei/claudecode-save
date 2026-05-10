# 第二段階 抽出結果まとめ
更新日: 2026-05-08

## 1. 目的

第一段階では、

- `ユーザ単位・10分ごと`
- `1-2gram TF-IDF`
- `IsolationForest`

を用いることで、`S3 attack day` の

- `18 sequence`
- `257,887 log`

を

- `3 sequence`
- `118,495 log`

まで絞り込めた。

第二段階の目的は、この `118,495 log` に対して

- さらに読むべき範囲を小さくする
- 追跡の起点になりうる chunk を上位に出す

ことである。

## 2. 第二段階の入力

| 項目 | 内容 |
| --- | --- |
| 入力 | 第一段階で残った陽性 3 sequence |
| 総ログ数 | `118,495 log` |
| 攻撃ログ数 | `286` |
| 正常ログ数 | `118,209` |
| 分割単位 | `100 event chunk` |
| 入力表現 | `1-2gram TF-IDF` |

## 3. 比較した手法

手作業ヒューリスティックは使わず、次の rule-free 手法を比較した。

| 手法 | 考え方 |
| --- | --- |
| `chunk-level IsolationForest` | 正常 chunk から外れる chunk を上位化 |
| `chunk-level OneClassSVM` | 正常境界の外側にある chunk を上位化 |
| `chunk-level LOF` | 近傍密度が低い chunk を上位化 |
| `kNN distance` | 正常 chunk から遠い chunk を上位化 |
| `chunk-level SGDOneClassSVM` | 線形 one-class 境界からの外れを上位化 |
| `SVD reconstruction error` | 低次元再構成誤差が大きい chunk を上位化 |

## 4. 比較結果

| 手法 | first attack rank | top10 総イベント数 | top10 attack event | top10 normal event | threshold ベースの挙動 | 読み |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `IsolationForest` | 24 | 1,000 | 0 | 1,000 | 11 chunk 陽性だが attack chunk 0 | 局所化が弱い |
| `OneClassSVM` | 2 | 1,000 | 30 | 970 | 35 chunk 陽性, attack event 42 | 上位から読んでも attack に届きやすい |
| `LOF` | 1 | 1,000 | 38 | 962 | 175 chunk 陽性, attack event 109 | 最も早く attack に届く |
| `kNN distance` | 23 | 1,000 | 0 | 1,000 | `p95` では陽性 0 | 初動が弱い |
| `SGDOneClassSVM` | 24 | 1,000 | 0 | 1,000 | `p95` では陽性 0 | sparse chunk では差が出にくい |
| `SVD reconstruction error` | 2 | 1,000 | 1 | 999 | 32 chunk 陽性, attack event 39 | attack には届くが密度は薄い |

## 5. 有望だった手法

### 5.1 LOF

| 指標 | 値 |
| --- | ---: |
| `first attack rank` | `1` |
| `top1` | `100 event` |
| `top1 attack / normal` | `6 / 94` |
| `top3` | `300 event` |
| `top3 attack / normal` | `23 / 277` |
| `top10` | `1,000 event` |
| `top10 attack / normal` | `38 / 962` |

読み:

- 最初の `100 event` だけで attack に到達できる
- `top3 = 300 event` でも attack 近傍の normal を十分含む
- 起点抽出の観点では最も強い

### 5.2 OneClassSVM

| 指標 | 値 |
| --- | ---: |
| `first attack rank` | `2` |
| `top2` | `200 event` |
| `top2 attack / normal` | `1 / 199` |
| `top6` | `600 event` |
| `top6 attack / normal` | `18 / 582` |
| `top10` | `1,000 event` |
| `top10 attack / normal` | `30 / 970` |

読み:

- `top1` では外すが、`top2` で attack に到達する
- `top6` 以降で attack がまとまって出る
- LOF より保守的で、少し厚めに見る用途に向く

## 6. 最終的にどこまで圧縮できたか

### 6.1 現在の安全側設定

`top10 chunk` を確認対象にすると、

- `118,495 log`
- → `1,000 event`

まで圧縮できる。

削減率:

- 第一段階後から見て: 約 `99.2%` 削減
- attack day 全体から見て: 約 `99.6%` 削減

### 6.2 起点抽出だけを考えた場合の下限

| 手法 | 起点に必要な最小 chunk 数 | event 数 | attack / normal |
| --- | ---: | ---: | ---: |
| `LOF` | `top1` | `100` | `6 / 94` |
| `LOF` | `top3` | `300` | `23 / 277` |
| `OneClassSVM` | `top2` | `200` | `1 / 199` |
| `OneClassSVM` | `top6` | `600` | `18 / 582` |

したがって、

- 起点に attack が 1 件でも含まれればよい
- そこから関連ログをたどり始められればよい

という前提なら、第二段階は **`100〜300 event` 程度まで圧縮できる可能性がある**。

## 7. 正常行動抽出への示唆

第二段階後の上位 chunk は、連続した完全な行動列ではない。  
一方で、

- `LOF top10`: `attack 38 / normal 962`
- `OneClassSVM top10`: `attack 30 / normal 970`

であり、大半は正常ログである。

したがって、第二段階の出力は

- 連続した正常行動の完全再構成

よりも、

- 攻撃近傍の正常ログを追跡の起点として抽出する

用途に向いている。

## 8. 現時点の結論

現時点での第二段階の結論は次の通りである。

1. 手作業ヒューリスティックなしでも、chunk 単位の局所化は可能だった
2. `LOF` と `OneClassSVM` が有望であり、特に `LOF` は最も早く attack に到達した
3. 現在の安全側設定では `1,000 event` まで圧縮できる
4. 起点抽出だけを目的にするなら、`100〜300 event` までさらに圧縮できる可能性がある
5. 出力は「完全な行動再構成」より、「追跡の起点候補抽出」に向いている

## 9. 発表での言い方

「第二段階では、第一段階で残った 118,495 log を 100 event chunk に分割し、rule-free な異常スコアで順位付けした。その結果、LOF と OneClassSVM が有望であり、現在の安全側設定でも 1,000 event まで圧縮できた。さらに、起点抽出だけを目的にするなら、LOF では top1 から attack に到達できるため、100〜300 event 程度まで圧縮できる可能性がある。」
