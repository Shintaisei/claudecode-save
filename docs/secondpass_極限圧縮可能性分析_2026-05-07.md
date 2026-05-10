# second pass はどこまで圧縮できそうか

## 1. 問い

second pass の現在設定では `top10 chunk = 1,000 event` を確認対象にしている。  
しかし、研究目的が

- 連続した完全再構成ではなく
- 追跡の起点となる normal/attack 近傍ログ候補の抽出

であるなら、`1,000 event` はまだ多い可能性がある。  
ここでは、

**「起点さえ得られればよい」**

という前提で、second pass をどこまで圧縮できそうかを確認する。

## 2. 対象

- first pass 後の残り:
  - `118,495 log`
- second pass 候補:
  - `LOF`
  - `OneClassSVM`
  - 参考: `SVD reconstruction error`

1 chunk は `100 event`。

## 3. 極限圧縮の見方

ここでは次の観点でみる。

1. 最初に attack を含む chunk に到達するまで、何 chunk 読めばよいか
2. attack event をある程度保持するまで、何 chunk 必要か
3. その時点で normal log がどれだけ同居しているか

## 4. LOF

### 4.1 上位 chunk の累積

| 読む chunk 数 | 読む event 数 | 累積 attack event | 累積 normal event | 読み |
| --- | ---: | ---: | ---: | --- |
| `top1` | 100 | 6 | 94 | 最初の 100 event だけで attack に到達 |
| `top3` | 300 | 23 | 277 | かなり小さい量で attack 近傍文脈を持てる |
| `top5` | 500 | 23 | 477 | attack 量は増えず normal が増える |
| `top8` | 800 | 38 | 762 | attack を 30 件以上保持できる |
| `top10` | 1,000 | 38 | 962 | 現在の設定 |

### 4.2 読み

- `first attack rank = 1`
- `top1 = 100 event` で attack に到達できる
- `top3 = 300 event` で `attack 23 / normal 277`

したがって、**起点抽出だけなら `LOF` は `100〜300 event` までかなり圧縮できる可能性がある。**

## 5. OneClassSVM

### 5.1 上位 chunk の累積

| 読む chunk 数 | 読む event 数 | 累積 attack event | 累積 normal event | 読み |
| --- | ---: | ---: | ---: | --- |
| `top1` | 100 | 0 | 100 | 1つ目では attack に届かない |
| `top2` | 200 | 1 | 199 | 最小限 attack に到達 |
| `top3` | 300 | 1 | 299 | まだ seed としては薄い |
| `top6` | 600 | 18 | 582 | attack がまとまり始める |
| `top8` | 800 | 30 | 770 | attack を十分保持 |
| `top10` | 1,000 | 30 | 970 | 現在の設定 |

### 5.2 読み

- `first attack rank = 2`
- `top2 = 200 event` で attack に到達
- ただし `top2` 時点では `attack 1 / normal 199`

したがって、**OneClassSVM は極小圧縮はできるが、attack seed の密度は薄い。**

## 6. SVD reconstruction error

### 6.1 上位 chunk の累積

| 読む chunk 数 | 読む event 数 | 累積 attack event | 累積 normal event | 読み |
| --- | ---: | ---: | ---: | --- |
| `top1` | 100 | 0 | 100 | attack なし |
| `top2` | 200 | 1 | 199 | 最初の attack に到達 |
| `top3` | 300 | 1 | 299 | ほぼ normal のみ |
| `top10` | 1,000 | 1 | 999 | top10 でも attack 密度が低い |

### 6.2 読み

`first attack rank = 2` ではあるが、  
**起点としては attack が薄く、極限圧縮の候補としては弱い。**

## 7. どこまで圧縮できそうか

### 7.1 最小限の attack 到達だけを目標にする場合

- `LOF`: `top1 = 100 event`
- `OneClassSVM`: `top2 = 200 event`

この意味では、**理論上は `100〜200 event` まで圧縮可能**である。

### 7.2 起点として少し厚みを持たせたい場合

attack に 1 件当たるだけでなく、

- attack 近傍の normal log
- 複数の attack event

を一緒に見たいなら、

- `LOF`: `top3 = 300 event`
  - `attack 23 / normal 277`
- `OneClassSVM`: `top6 = 600 event`
  - `attack 18 / normal 582`

あたりが現実的な下限に見える。

### 7.3 現在の `top10 = 1,000 event` の位置づけ

`top10` は安全側の設定であり、

- 起点抽出だけを考えるならやや多い
- attack 保持量を厚めに見たいなら妥当

という位置づけである。

## 8. 結論

second pass は、現在 `1,000 event` まで絞っているが、  
**起点抽出を目的にするなら、さらに大きく圧縮できる可能性が高い。**

特に、

- `LOF` なら `100 event` で最初の attack に到達できる
- `LOF top3 = 300 event` なら `attack 23 / normal 277` を保持できる

ため、

**実務的な seed 候補抽出の下限は `100〜300 event` 程度**

と見積もるのが妥当である。

一方で、より保守的に

- 誤検知を少し避けたい
- attack をある程度まとまった量で持ちたい

なら、

- `OneClassSVM top6 = 600 event`
- `LOF top8 = 800 event`

あたりが候補になる。

## 9. 発表での言い方

「現在は `top10 chunk = 1,000 event` を確認対象としているが、これは安全側の設定である。起点抽出だけを目的にするなら、`LOF` では `top1 = 100 event`、`top3 = 300 event` でも attack に到達でき、かつ正常文脈も保持できる。したがって、second pass は最終的に `100〜300 event` 程度まで圧縮できる可能性がある。」
