# second pass 後の 1,000 event から正常行動を抽出できるか

## 1. 目的

second pass により `top10 chunk = 1,000 event` まで絞り込めた。  
ここでは、この `1,000 event` が

- 攻撃近傍の正常文脈の抽出に使えそうか
- 連続した正常行動の再構成に使えそうか

を整理する。

## 2. 前提

- 対象データ: `S3 attack day`
- first pass 採用構成:
  - `ユーザ単位・10分ごと`
  - `1-2gram TF-IDF`
  - `IsolationForest`
- first pass 後に残るログ量:
  - `118,495 log`
- second pass:
  - `100 event chunk`
  - `top10 chunk = 1,000 event`

比較対象として、second pass で有望だった `LOF` と `OneClassSVM` を見る。

## 3. 量としては正常ログを十分含む

### 3.1 LOF

- `top10 chunk = 1,000 event`
- `attack event = 38`
- `normal event = 962`
- `attack chunk = 4`
- `normal only chunk = 6`

### 3.2 OneClassSVM

- `top10 chunk = 1,000 event`
- `attack event = 30`
- `normal event = 970`
- `attack chunk = 4`
- `normal only chunk = 6`

### 3.3 読み

どちらの手法でも、`top10 chunk` の大半は正常ログである。  
したがって、

**「attack に近い場所の normal log を十分に残す」**

という意味では、second pass 後の `1,000 event` は有望である。

## 4. 時間・セッションのまとまり

### 4.1 LOF

`top10 chunk` はすべて

- `win-32-h1|aalsahee|20220719T1430Z`

の 1 セッションに集中していた。

選ばれた chunk index は

- `203, 204, 210, 243, 244, 308, 324, 325, 330, 741`

である。

### 4.2 OneClassSVM

`top10 chunk` は主に

- `win-32-h1|aalsahee|20220719T1430Z` が 8 chunk
- `win-32-h1|win-32-h1$|20220719T1420Z` が 2 chunk

に分かれた。

選ばれた chunk index は

- `71, 120, 183, 209, 233, 252, 282, 295, 331, 332`

である。

### 4.3 読み

重要なのは、`1,000 event` が

- 連続した 1 本の行動列

ではなく、

- `10分窓` の中からスコア上位の `100 event` 断片を集めたもの

だという点である。

特に `LOF` は 1 セッションに集中している一方で、chunk index は広く飛んでいる。  
そのため、

- **同じ attack session 内の局所文脈**

には強いが、

- **連続した時系列としての再構成**

にはまだ弱い。

## 5. 正常行動抽出という観点での評価

## 5.1 できそうなこと

- attack が起きたセッション周辺で、どの normal log が同居していたかを見る
- attack chunk の前後にある normal chunk を追加で読む
- 「attack 近傍の正常文脈」を候補として集める

特に `LOF` は top10 が 1 セッションに集中しているため、

**「attack session の中で、attack に近い normal log を回収する」**

という目的には合っている。

## 5.2 まだ難しいこと

- 1 本の normal behavior を連続して再構成する
- ユーザ行動全体を end-to-end に追う
- そのまま 9 マス表の「正常行動ユースケース」に落とす

理由は、top chunk が時間的に飛び飛びで、

**「優先的に読むべき局所断片」**

にはなっていても、

**「連続した行動列」**

にはなっていないからである。

## 6. 現時点の結論

現時点では、second pass 後の `1,000 event` から

- **attack 近傍の正常文脈を抽出することは十分可能**
- **ただし、そのまま連続した正常行動の再構成に使うのは難しい**

と整理するのが妥当である。

したがって、研究目的との対応は次のようになる。

- `関連ログの調達` という観点:
  - 有望
- `正常行動の再構成` という観点:
  - 追加処理が必要

## 7. 次にやるとよいこと

### 7.1 attack chunk の近傍展開

`LOF` で選ばれた attack chunk の

- 前後 `±1 chunk`
- 前後 `±2 chunk`

を追加で読むようにすると、  
局所的に連続した normal context を回収しやすくなる。

### 7.2 chunk 単位ではなく span 単位でまとめる

上位 chunk をそのまま並べるのではなく、

- 同一セッション
- 近い chunk index

をまとめて 1 つの review span にする方が、  
人が読む単位として自然になる。

### 7.3 LOF を基準に normal context 抽出用ルールを後付けする

主スコアリング自体は rule-free のまま維持し、  
後段で

- attack を含む chunk
- その近傍の normal chunk

だけを束ねると、  
正常行動ユースケースに使いやすい形へ近づく。
