# ATLAS v2 正常行動復元 統合ドキュメント
更新日: 2026-05-03

## 1. この文書の位置づけ

この文書は、今日までの検討内容を 1 本に集約した作業用マスターである。
今後はこの文書を起点に研究を進める。

盛り込む対象は次の 4 つ。

1. 研究の方向性と言語化
2. シーケンスモデルと実験方式の選定
3. 実際の正常行動候補の抽出工程
4. 今回の解析で分かったことと、次にやる実験

## 2. 研究の主題

### 2.1 最終ゴール

最終ゴールは、異常検知で浮いた対象に対して

- `攻撃`
- `正常`
- `決めきれない`

を整理できるようにすることである。

### 2.2 現在の主対象

ただし現時点の主対象はその前段であり、まず検証したいのは

**正常事象でも、起点アラートを手がかりに関連ログ探索が成立し、行動復元まで到達できるか**

である。

ここで重要なのは、最初から完全な正常シーケンスを取る必要はない点である。
今回の第一段階では、

- 異常候補として上がったシーケンスの中に正常ログが十分含まれている
- そこから関連ログを広げられる
- 最終的に正常行動として説明できる

なら研究として成立する。

つまり本研究の第一段階は、

- `正常を直接検知する研究`

ではなく、

- `異常候補の中から正常文脈を復元する研究`

である。

## 3. 実務で想定する分析フロー

実務の SOC / DFIR では、分析者は生ログ全体から始めるのではなく、まず異常候補を受け取る。
その後に、

1. 仮説の策定 / 更新
2. スコープ決定
3. 検索・収集
4. 絞り込み
5. 行動復元
6. 攻撃 / 正常の判断

を繰り返す。

このため、今回の研究も実務と同じく

- first pass で異常候補を広めに取る
- second pass で読める単位まで落として復元する

という二段構えを前提にする。

## 4. モデル選定と現在の実装方針

### 4.1 シーケンスモデルの方向性

当初の「単一ログから偽陽性候補の正常ログを生成する」方針は、

- 偽陽性そのものを単体 seed として扱いにくい
- 正常文脈が単一イベントに閉じない

ため、シーケンス中心の見方に切り替えた。

現在の主方針は、

1. 異常候補をシーケンスとして扱う
2. その中にどれだけ正常文脈が含まれるかを測る
3. 起点アラートから関連ログを広げて正常行動を復元する

である。

### 4.2 GitHub 実装の選定

GitHub 上の候補を調べた結果、ATLAS v2 に比較的つなぎやすい実装として `deep-loglizer` を採用した。

採用理由は次の通り。

1. ログシーケンス異常検知の代表的な実装である
2. session ベースの入力に素直に乗せられる
3. LSTM / Transformer 系への接続点として扱いやすい

### 4.3 現在の実行状況

ATLAS v2 から `deep-loglizer` 互換の session データを作るところまではできている。
ただしローカル環境では PyTorch の DLL 問題があり、深層モデル本体はまだ安定実行できていない。

そのため現在は、

- データ変換と session 設計
- local n-gram baseline
- candidate ranking
- candidate quality / coverage 解析

で研究を進めている。

## 5. 今回の抽出パイプライン

### 5.1 基本パイプライン

現在の抽出は次の 4 段階で行っている。

1. ATLAS v2 の JSONL を session 単位へ変換する
2. local n-gram baseline で局所逸脱を計算する
3. session 単位で候補を並べる
4. 上位候補の正常イベント比率と中身を確認する

### 5.2 主要スクリプト

- [scripts/prepare_atlasv2_for_deeploglizer.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/prepare_atlasv2_for_deeploglizer.py:1)
  ATLAS v2 JSONL を session 化する
- [scripts/package_atlasv2_deeploglizer_dataset.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/package_atlasv2_deeploglizer_dataset.py:1)
  benign 学習用 split と attack 評価用 split を 1 つの学習データセットへ束ねる
- [scripts/run_atlasv2_local_ngram_baseline.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/run_atlasv2_local_ngram_baseline.py:1)
  attack day 内の局所逸脱を計算する
- [scripts/train_atlasv2_deeploglizer.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/train_atlasv2_deeploglizer.py:1)
  deep-loglizer の LSTM / Transformer を使って sequence model を学習する
- [scripts/analyze_atlasv2_candidate_quality.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/analyze_atlasv2_candidate_quality.py:1)
  上位 candidate session の質を確認する
- [scripts/analyze_atlasv2_candidate_curve.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/analyze_atlasv2_candidate_curve.py:1)
  top-k coverage を見る

### 5.3 いま採用している二段構え

現在もっとも実務寄りで筋が良い方式は次である。

#### first pass

太めの process session で候補を取る。

- `computer_process + 10分`
  または
- `computer_process + 1分`

#### second pass

上位候補だけを `100 event` 前後まで再分割して読む。

現在は [prepare_atlasv2_for_deeploglizer.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/prepare_atlasv2_for_deeploglizer.py:60) に追加した `--max-events-per-session` を使い、

- `computer_process + 1分 + max_events_per_session=100`

で読解用 chunk を作れるようにしている。

### 5.4 候補ログを起こす全体の流れ

「候補のログを起こす」とは、attack day の全ログをいきなり人が読むのではなく、

1. まず coarse な単位で不自然そうな session を絞り込み
2. その中だけを finer な単位へ切って
3. 読める大きさの candidate 群として再提示する

という二段階の絞り込みを意味する。

現在の流れを平たく書くと次のようになる。

1. ATLAS v2 の JSONL から event を時系列順に並べる
2. `computer_process` を軸にして session を作る
3. まず `10分` か `1分` の time bucket で first pass 用 session を作る
4. benign 側で見た局所パターンと比べて、attack day 内の各 session に「どれだけ見慣れない event の並びがあるか」を local n-gram baseline で採点する
5. スコアの高い session を candidate として上位から並べる
6. その上位 candidate だけを、必要に応じて `1分 + 100 event chunk` へ再分割する
7. 再分割後の chunk を、人が読める長さの investigation 単位として使う

重要なのは、最初から `100 event chunk` を全件に対して作って順位付けしているわけではない点である。実務上はまず「どの process session が怪しいか」を粗く当て、その後に「その中のどこを読むか」を細かく切り出している。

local n-gram baseline が見ているのは、ざっくり言えば「その session 内の event template の並びが benign 側でどれだけ見慣れないか」である。つまりこれは、最終的な異常判定モデルというより、候補発見の first-pass detector として使っている。

### 5.5 有名モデルへ切り替えるときの位置づけ

local n-gram baseline は、あくまで lightweight な first pass である。最終的な sequence 異常検知としては、LSTM や Transformer のような既存モデルへ置き換える方が筋が良い。

今回追加した [scripts/train_atlasv2_deeploglizer.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/train_atlasv2_deeploglizer.py:1) では、`deep-loglizer` に入っている次の有名モデルをそのまま ATLAS v2 session に適用できる。

- `LSTM`
  DeepLog / LogAnomaly 系に近い next-log forecasting ベースの定番
- `Transformer`
  self-attention で sequence の依存を見る比較的新しい定番

想定フローは次の通りである。

1. benign 側 session を train に置く
2. attack day 側 session を test に置く
3. LSTM か Transformer で next-log forecasting を学習する
4. test session で top-k miss を anomaly とみなし、session 単位の F1 / recall / precision を評価する

つまり、session の切り方自体はルールで決めるが、その中身の正常/異常判定は既知モデルに任せる構成へ移せる。

実行イメージ:

```powershell
python scripts/package_atlasv2_deeploglizer_dataset.py `
  --train-dir analysis_data/atlasv2_for_deep-loglizer/benign1_cu30 `
  --test-dir analysis_data/atlasv2_for_deep-loglizer/attack_s3_cu30 `
  --output-dir analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_s3_model `
  --test-source session_train

python scripts/train_atlasv2_deeploglizer.py `
  --data-dir analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_s3_model `
  --model lstm `
  --feature-type sequentials `
  --window-size 10 `
  --epochs 20 `
  --batch-size 256 `
  --learning-rate 0.001 `
  --gpu -1
```

初手としては `LSTM + sequentials + next_log` が最も無難で、比較対象として `Transformer` を同条件で並べるのがよい。

## 6. ATLAS v2 で見ているシーケンス

### 6.1 `computer_process + 10分`

ATLAS v2 の各 scenario で `computer_process + 10分` を取ると、次の程度になる。

| Scenario | sessions_total | attack を含む session | attack を含まない session | 平均 event / session |
| --- | ---: | ---: | ---: | ---: |
| S3 | 137 | 8 | 129 | 1,882 |
| S4 | 128 | 14 | 114 | 1,807 |
| M4 | 124 | 13 | 111 | 1,613 |
| M5 | 155 | 11 | 144 | 2,036 |
| M6 | 129 | 14 | 115 | 1,712 |

この設定は first pass の候補発見には向いている。1つの process session に attack の前後文脈がまとまりやすく、「怪しい流れが起きた process を取りこぼしにくい」からである。

一方で、平均 1,600 から 2,000 event 級は人手読解には重い。したがってこの粒度は「候補を当てる粗い網」としては有効だが、そのまま investigation 単位にするには大きすぎる、と解釈するのが自然である。

### 6.2 `computer_process + 1分`

`1分` にすると典型サイズはかなり小さくなるが、一部の巨大 session がまだ残る。

| Scenario | sessions_total | 平均 event / session | 中央値 |
| --- | ---: | ---: | ---: |
| S3 | 642 | 401.7 | 119 |
| S4 | 573 | 403.7 | 115 |
| M4 | 490 | 408.2 | 116 |
| M5 | 669 | 471.6 | 124 |
| M6 | 564 | 391.6 | 116 |

ここで見るべきなのは、平均より中央値である。中央値が 115 から 124 程度なので、多くの session はかなり読みやすい大きさまで落ちている。平均がまだ大きいのは、一部の process が 1 分間に大量の event を吐くためである。

つまり `1分` 化はかなり効いているが、分割規則を time bucket だけに任せると heavy process の巨大 session は残る。このため second pass では event 数でさらに上限をかける意味がある。

### 6.3 `computer_process + 1分 + 100 event chunk`

読解単位としては、さらに `100 event` 前後へ落とせる。

top10 filtered candidates の平均 event 数:

| Scenario | top10 合計 events | 平均 event / candidate |
| --- | ---: | ---: |
| S3 | 824 | 82.4 |
| S4 | 840 | 84.0 |
| M4 | 803 | 80.3 |
| M5 | 892 | 89.2 |
| M6 | 969 | 96.9 |

この数字の意味は、「top10 までに入った有望 candidate を人が読むとき、1 candidate あたり平均 80 から 100 event 程度まで圧縮できている」ということである。これは SOC/DFIR の手読み単位としてかなり現実的で、attack の流れを追いながらも冗長さを抑えやすい。

要するに、3つの設定は役割が違う。

1. `computer_process + 10分`
   attack を含む流れを取りこぼしにくい coarse な候補発見
2. `computer_process + 1分`
   process の文脈を保ちつつ、読める大きさにかなり近づける中間表現
3. `computer_process + 1分 + 100 event chunk`
   上位候補を実際に調査・要約するための最終読解単位

したがって最終解釈は、「候補を起こす方法」と「人が読む方法」を分けている、である。候補発見ではやや大きめの session を使って recall を取り、読解フェーズでは小さな chunk に落として precision と可読性を取りにいっている。

## 7. 今回分かった重要な事実

### 7.1 異常シーケンスの中には正常文脈が大量に含まれる

候補 session を見ると、その中身はほぼ正常イベントで埋まっている。
従来の top candidate session では、正常イベント比率は概ね `99.7%` から `99.95%` 程度だった。

これは、今回の研究に必要な

- 異常候補の中に正常ログが埋まっている
- その正常文脈をたどって行動復元できる

という前提と整合している。

### 7.2 正常の土台は Windows Security ログである

今回の正常側イベントは、主に `Security` チャネルの

- `4656`
- `4658`
- `4663`
- `5156`
- `5158`
- `4660`

などから成っている。

したがって今回使えるのは、

- `正常業務全体の完全再現`

ではなく、

- **異常候補から切り出された Security 監査上の正常文脈**

である。

### 7.3 `100 event` は読むには良いが、拾うには細すぎる

`100 event` 前後の chunk は読みやすい。
しかし最初からこの粒度で候補抽出すると、attack 文脈が細切れになる。

filtered candidate の TP-window coverage は、top10 だと次のように落ちた。

| Scenario | top10 | top20 | top50 | top100 | top200 |
| --- | ---: | ---: | ---: | ---: | ---: |
| S3 | 31.3% | 31.3% | 76.1% | 95.5% | 100.0% |
| S4 | 18.5% | 27.2% | 62.0% | 84.8% | 100.0% |
| M4 | 0.0% | 2.0% | 48.0% | 96.0% | 100.0% |
| M5 | 18.5% | 35.4% | 43.1% | 72.3% | 100.0% |
| M6 | 37.3% | 37.3% | 40.7% | 88.1% | 100.0% |

つまり、

- `100 event` 前後は復元単位としては良い
- しかし初回候補抽出単位としては細すぎる

というトレードオフが確認できた。

## 8. 現時点の最終方針

以上から、現在の最終方針は次である。

1. **候補抽出は太め**
   `computer_process + 10分` または `computer_process + 1分` で行う
2. **行動復元は薄め**
   上位候補だけを `100 event` 前後へ再分割して読む
3. **評価対象は正常文脈の復元**
   chunk 単体で正常判定するのではなく、関連 chunk と関連ログを広げて正常行動として説明できるかを見る

要するに、

- `検知・候補抽出は太め`
- `復元・読解は 100 event 前後`

の二段構えを正式な主方針とする。

## 9. この方式で取れた正常行動は研究に使えるか

### 9.1 結論

**使える。**

理由は次の通り。

1. 実務と同じく異常候補起点で始めている
2. 候補が正常文脈を大量に含んでいる
3. second pass で人が読めるサイズまで落とせる
4. その上で関連ログを広げる設計と整合している

### 9.2 どういう意味で使えるか

今回使いたいのは、

- `正常そのもののきれいなサンプル`

ではなく、

- `異常候補から出発しても復元できる正常行動サンプル`

である。

この意味では、今回の候補は十分に研究材料になる。

### 9.3 注意点

ただし表現は正確にする必要がある。

- `正常行動一般`
ではなく
- **異常候補から切り出された Security 監査上の正常行動候補**

として扱うのが適切である。

## 10. 正常行動候補の仕分け

ここでは、現時点で得られている上位候補から、正常行動候補を `単発操作型 / 手続型 / 背景動作型` に仕分ける。

### 10.1 単発操作型

境界が比較的明瞭で、単独操作として読みやすい候補。

候補例:

- `notepad.exe`
  M6 の top candidate 群に出現
- `excel.exe`
  M4 / M6 に出現
- `wmplayer.exe`
  M4 に出現
- `scanhost.exe`
  S4 / M5 に出現

解釈:

- 単一アプリの起動・参照・閲覧系として切り出しやすい
- first pass 候補から second pass へ落としたときに、最も復元成立しやすい

### 10.2 手続型

複数操作のまとまりとして追う候補。

候補例:

- `winword.exe`
  S3 / S4 / M4 / M5 / M6 に出現
- `explorer.exe`
  S4 / M4 / M5 に出現
- `mmc.exe`
  S3 / S4 / M4 / M5 / M6 に出現
- `powershell.exe`
  S3 / S4 / M5 / M6 に出現
  ただし attack 混入があるため正常手続候補としては補助的に扱う

解釈:

- `explorer.exe -> winword.exe -> werfault.exe`
  のような前後関係を読むと、文書参照や周辺操作のまとまりとして見やすい
- `mmc.exe` も管理系の手続としてまとまりを持ちやすい

### 10.3 背景動作型

常駐・周期・副作用が混ざりやすく、境界が不明瞭な候補。

候補例:

- `searchindexer.exe`
- `taskhost.exe`
- `wmiapsrv.exe`
- `services.exe`
- `werfault.exe`
- `svchost.exe`

解釈:

- 行動の「本体」として追うより、背景として切り分ける対象
- 正常行動復元では、どこで探索を止めるかを考える訓練材料になる

## 11. 起点アラートの特異性整理

正常行動候補に対し、起点アラートの特異性は次の 3 段階で見る。

### 11.1 高特異性

候補空間をかなり狭く保てるもの。

例:

- 特定プロセス chunk
  `notepad.exe chunk`, `wmplayer.exe chunk`, `scanhost.exe chunk`
- 特定 Office プロセスの狭い chunk
  `winword.exe chunk`

### 11.2 中特異性

追加条件があれば使えるが、単独では分岐しやすいもの。

例:

- `explorer.exe session`
- `mmc.exe session`
- `excel.exe session`
- `winword.exe` の太め session

### 11.3 低特異性

候補が拡散しやすく、背景と混ざりやすいもの。

例:

- `searchindexer.exe`
- `taskhost.exe`
- `services.exe`
- `werfault.exe`
- ホスト単位・時間帯単位だけの起点

## 12. `3 x 3` 実験表

ここでは、まず今日時点で使える具体例を 9 マスへ仮配置する。
これは最終確定版ではなく、次回以降の実査定のための初期テーブルである。

| 起点特異性 \ 正常行動 | 単発操作型 | 手続型 | 背景動作型 |
| --- | --- | --- | --- |
| 高 | `notepad.exe`, `wmplayer.exe`, `scanhost.exe` | `winword.exe chunk` | `searchindexer.exe chunk` |
| 中 | `excel.exe`, `explorer.exe` | `winword.exe session`, `mmc.exe session` | `werfault.exe`, `wmiapsrv.exe` |
| 低 | host/time 単位の単発参照候補 | broad process 群の曖昧な連鎖 | `taskhost.exe`, `services.exe`, `svchost.exe` |

## 13. 各マスの成立見込み

### 13.1 成立しやすい

- `高特異性 x 単発操作型`
- `高特異性 x 手続型`

この領域は、最初の成立確認に最も向いている。

### 13.2 中心評価領域

- `中特異性 x 手続型`

ここが今回の主戦場である。
`winword.exe` や `mmc.exe` を起点に、どこまで前後の関連ログを復元できるかを見る。

### 13.3 破綻を観察しやすい

- `低特異性 x 背景動作型`
- `低特異性 x 手続型`

ここでは復元の成功例を積むというより、

- どこで候補が拡散するか
- どこで探索を止めるべきか

を観察する。

## 14. レベル 1 からレベル 3 の探索基準

### レベル 1: 最小復元範囲

- 同一ホスト
- 同一主体
- 同一 10 分または 1 分バケット

単発操作型はここで成立すればよい。

### レベル 2: 連鎖確認範囲

- 直前 / 直後の近接バケット
- 同一ユーザー、同一プロセス、同一オブジェクト
- `4688/4689` などの生成・終了

手続型はここまで広げて評価する。

### レベル 3: 背景分離範囲

- 反復 system / service イベント
- 慢性的 noisy process
- 周辺の常駐ジョブ

背景動作型は、ここで「どこまで追うか」より「どこで切るか」を評価する。

## 15. 今日の時点での結論

1. 実務寄りの二段構えは研究設計として妥当
2. 異常候補の中に正常文脈が十分含まれているので、第一段階の材料として使える
3. `100 event` 前後は復元単位として良いが、検知単位としては細すぎる
4. 今後の主課題は、候補を実際の正常行動事例へ落として、復元成立 / 不成立を記録すること
5. 研究上の正確な表現は
   **異常候補から切り出された Security 監査上の正常行動復元**
   である

## 16. 次にやること

1. `3 x 3` 表の各マスに対して、実際の candidate session を 1 つ以上固定する
2. 各 candidate について、レベル 1 からレベル 3 の関連ログ探索を行う
3. `復元成立 / 不成立 / 保留` を記録する
4. 成立したものは、主体・行為・対象・前後関係の要約を作る
5. その結果を用いて、第二段階の `攻撃 / 正常 / 保留` へつなげる

## 17. `3 x 3` 表の固定 candidate

ここでは、現時点で実際に固定する candidate を各マスに 1 つ以上割り当てる。
粒度は次のように使い分ける。

- 高特異性:
  `computer_process + 1分 + 100 event chunk`
- 中特異性:
  `computer_process + 10分`
- 低特異性:
  `computer_user + 10分`

| 起点特異性 \ 正常行動 | 固定 candidate | 位置づけ |
| --- | --- | --- |
| 高 x 単発操作型 | `M6: win-32-h1|notepad.exe|20220720T0025Z|chunk007` | 小さく切られた閲覧系 chunk |
| 高 x 手続型 | `S3: win-32-h1|mmc.exe|20220719T1500Z` | 管理系手続を含む process session |
| 高 x 背景動作型 | `M4: win-32-h1|searchindexer.exe|20220719T2236Z|chunk001` | 特定背景 process の chunk |
| 中 x 単発操作型 | `M4: win-32-h1|excel.exe|20220719T2300Z` | 単一アプリ中心の process session |
| 中 x 手続型 | `M5: win-32-h1|explorer.exe|20220719T2330Z` | 前後の Office / error 系 process とつながる session |
| 中 x 背景動作型 | `M5: win-32-h1|services.exe|20220719T2330Z` | サービス主体の session |
| 低 x 単発操作型 | `M6: win-32-h1|aalsahee|20220720T0020Z` | broad user-time から単発操作を掘り出す例 |
| 低 x 手続型 | `M5: win-32-h1|aalsahee|20220719T2330Z` | broad user-time から手続型を掘り出す例 |
| 低 x 背景動作型 | `M5: win-32-h1|win-32-h1$|20220719T2330Z` | broad machine-account 背景動作の例 |

## 18. レベル 1 からレベル 3 の探索結果

ここでの評価は、現在利用できる template 列、candidate session、周辺 session から行っている。
そのため、オブジェクトパスやコマンドラインの完全な意味まではまだ見えていない。
今回は

- 主体が切り出せるか
- 近傍 session に広げたときに行動のまとまりが見えるか
- 背景 process を切り分けられるか

で `成立 / 保留 / 不成立` を付ける。

### 18.1 高 x 単発操作型

candidate:
`M6: win-32-h1|notepad.exe|20220720T0025Z|chunk007`

- レベル 1:
  `notepad.exe` だけで構成された `100 event` chunk として読める
- レベル 2:
  同じ `0020-0029` 帯には `excel.exe`, `mmc.exe` もあり、ユーザー操作帯として前後関係を広げられる
- レベル 3:
  `searchindexer.exe`, `osppsvc.exe`, `wmiapsrv.exe` などの背景 process を分離可能

判定:
`成立`

要約:
特定アプリを起点に、周辺の閲覧 / 参照系操作へ広げられる。
単発操作型の正常行動復元例として最も扱いやすい。

### 18.2 高 x 手続型

candidate:
`S3: win-32-h1|mmc.exe|20220719T1500Z`

- レベル 1:
  `4689` と file access 群から、`mmc.exe` 主体のまとまりが見える
- レベル 2:
  同時間帯には `consent.exe`, `wmiapsrv.exe`, `taskhost.exe` などの補助 process があり、管理手続の周辺を広げられる
- レベル 3:
  `taskhost.exe` や `wmiapsrv.exe` を背景 / 補助として分離できる

判定:
`成立`

要約:
管理ツール主体の手続型正常行動として扱える。
主体が明瞭で、周辺 process を足してもまとまりを保ちやすい。

### 18.3 高 x 背景動作型

candidate:
`M4: win-32-h1|searchindexer.exe|20220719T2236Z|chunk001`

- レベル 1:
  `searchindexer.exe` の小さな背景 chunk として切り出せる
- レベル 2:
  近傍には `taskhost.exe`, `osppsvc.exe`, `wsqmcons.exe` などが並び、背景帯であることが見える
- レベル 3:
  背景 process 群として分離はできるが、ユーザー行動の本体まではつながらない

判定:
`成立`

要約:
背景動作としての切り分けには成功する。
ただし「人の正常行動そのもの」の復元ではなく、「背景として除外すべき正常動作」の復元例である。

### 18.4 中 x 単発操作型

candidate:
`M4: win-32-h1|excel.exe|20220719T2300Z`

- レベル 1:
  `108 event` の比較的小さい process session で、`excel.exe` 主体が明確
- レベル 2:
  同 host / 近傍帯に `winword.exe`, `explorer.exe`, `mmc.exe` があり、文書閲覧帯の一部として広げられる
- レベル 3:
  `taskhost.exe`, `searchindexer.exe` などの背景成分を落とせる

判定:
`成立`

要約:
単発アプリ中心の正常行動として読みやすく、process session の粒度でも十分扱える。

### 18.5 中 x 手続型

candidate:
`M5: win-32-h1|explorer.exe|20220719T2330Z`

- レベル 1:
  `explorer.exe` 主体の file access 帯として見える
- レベル 2:
  同じ `2330` 帯に `winword.exe`, `werfault.exe`, `mmc.exe`, `searchindexer.exe` があり、文書参照やその周辺手続へ広げやすい
- レベル 3:
  `services.exe`, `lsass.exe`, `system` などの背景寄り process を切り分けられる

判定:
`成立`

要約:
`explorer -> winword -> 周辺補助 process`
のような手続型正常行動候補として扱える。
今回の中心評価領域にもっとも近い。

### 18.6 中 x 背景動作型

candidate:
`M5: win-32-h1|services.exe|20220719T2330Z`

- レベル 1:
  `services.exe` 主体の file access 帯として切り出せる
- レベル 2:
  同時間帯に他の service / system process も多く、背景帯であることは見える
- レベル 3:
  背景成分としての説明はできるが、個別の正常手続まで落とし込むのは難しい

判定:
`保留`

要約:
背景として分離はできるが、「どの正常行動か」を説明するには弱い。
背景動作型の中心評価例として使える。

### 18.7 低 x 単発操作型

candidate:
`M6: win-32-h1|aalsahee|20220720T0020Z`

- レベル 1:
  user-time broad session のため、そのままでは太い
- レベル 2:
  process 分割すると `notepad.exe`, `excel.exe`, `mmc.exe` が見つかり、単発操作候補を切り出せる
- レベル 3:
  背景 process を除くと、人手で読める単発候補へ落とせる

判定:
`成立`

要約:
低特異性の broad candidate からでも、second pass を通せば単発操作型正常行動へ到達できる。
二段構えの有効性を示す例である。

### 18.8 低 x 手続型

candidate:
`M5: win-32-h1|aalsahee|20220719T2330Z`

- レベル 1:
  broad user-time session のままでは `48713 event` と大きく、単独では読めない
- レベル 2:
  process 分割すると `explorer.exe`, `winword.exe`, `powershell.exe`, `mshta.exe` などが現れ、手続候補は見える
- レベル 3:
  ただし attack 混入 process も同居しており、純粋な正常手続としては切り分けが難しい

判定:
`保留`

要約:
手続の存在は見えるが、正常だけのまとまりとして確定するには追加条件が必要。
低特異性起点の限界が出ている。

### 18.9 低 x 背景動作型

candidate:
`M5: win-32-h1|win-32-h1$|20220719T2330Z`

- レベル 1:
  `83982 event` の machine-account broad session で、非常に太い
- レベル 2:
  中身は `vmtoolsd.exe`, `repmgr.exe` など service / agent 系が中心
- レベル 3:
  背景 process 群としては説明できるが、特定の正常行動境界はほぼ立たない

判定:
`不成立`

要約:
低特異性かつ背景動作型では、候補が拡散しすぎて復元の起点として機能しにくい。

## 19. `復元成立 / 保留 / 不成立` の記録表

| 起点特異性 \ 正常行動 | 単発操作型 | 手続型 | 背景動作型 |
| --- | --- | --- | --- |
| 高 | 成立 | 成立 | 成立 |
| 中 | 成立 | 成立 | 保留 |
| 低 | 成立 | 保留 | 不成立 |

### 19.1 読み方

- 左上ほど成立しやすく、今回の観察とも整合する
- 中心評価領域は `中特異性 x 手続型`
- 右下の `低特異性 x 背景動作型` は、破綻条件を観察する領域になった

## 20. 成立した candidate の要約

### M6 `notepad.exe|20220720T0025Z|chunk007`

- 主体:
  `notepad.exe`
- 行為:
  file access 中心の閲覧 / 参照
- 対象:
  file object
- 前後関係:
  同時間帯の `excel.exe`, `mmc.exe` と並ぶユーザー操作帯

### S3 `mmc.exe|20220719T1500Z`

- 主体:
  `mmc.exe`
- 行為:
  管理ツール主体の file access
- 対象:
  file object
- 前後関係:
  `consent.exe`, `wmiapsrv.exe`, `taskhost.exe` などの補助 process と共起

### M4 `excel.exe|20220719T2300Z`

- 主体:
  `excel.exe`
- 行為:
  単発の文書参照 / 操作
- 対象:
  file object
- 前後関係:
  同 host の `winword.exe`, `explorer.exe` 帯へ接続しやすい

### M5 `explorer.exe|20220719T2330Z`

- 主体:
  `explorer.exe`
- 行為:
  文書参照帯の入り口
- 対象:
  file object
- 前後関係:
  `winword.exe`, `werfault.exe`, `mmc.exe` と同時間帯に出現

## 21. 第二段階 `攻撃 / 正常 / 保留` へのつなぎ

今回の第一段階の結果を踏まえると、第二段階への接続は次のようになる。

### 21.1 正常へ寄せやすいもの

- `notepad.exe`
- `excel.exe`
- `mmc.exe`
- `explorer.exe`
- `winword.exe` の一部 session

これらは、関連ログを広げたときに正常手続として説明しやすい。

### 21.2 保留になりやすいもの

- `services.exe`
- `searchindexer.exe`
- `taskhost.exe`
- `werfault.exe`

背景寄りで、正常と説明できても行動境界が曖昧になりやすい。

### 21.3 攻撃混入に注意すべきもの

- `powershell.exe`
- `regsvr32.exe`
- `mshta.exe`

これらは current dataset では attack 混入が強く、
正常復元の材料というより「正常文脈と攻撃文脈が混ざる難所」として扱うべきである。

## 22. この段階での結論

1. `3 x 3` の各マスに、少なくとも 1 つの具体 candidate を置けた
2. `高特異性 x 単発 / 手続` は復元成立しやすい
3. `中特異性 x 手続` は主評価領域として有望
4. `低特異性 x 背景` は不成立例として機能する
5. 実務寄りの二段構えは、単なる設計案ではなく、実際に正常行動候補を復元可能な形へ落とせる

## 23. いま何をやっているのか

ここは途中で分からなくなりやすいので、現在の作業の意味を明示する。

### 23.1 いまの段階の目的

いまやっているのは、`検知モデルを作ること` ではなく、

- 異常候補として浮いたシーケンスの中から
- 正常文脈を含む部分を切り出し
- 関連ログを広げることで
- 正常行動として説明できるか

を確かめる作業である。

つまり現在の問いは、

- `この candidate は攻撃か正常か`

をすぐ判定することではなく、

- `この candidate から出発すると、正常行動の復元が成立するか`

である。

### 23.2 いまの作業の流れ

流れは次の通り。

1. 異常候補を太めに取る
2. その中の上位候補を `100 event` 前後に切る
3. その chunk / session が何の file や object に触っているかを見る
4. 前後の process や近傍時間帯へ広げる
5. 「この候補は単発操作か、手続か、背景か」を判断する
6. 最後に `成立 / 保留 / 不成立` を付ける

ここで、`ObjectName` や前後 process を見る理由は、
`4656/4663/4658 が並んでいるだけ` の抽象列を、
`Downloads を開いた`, `courses.xlsx を参照した`, `Event Viewer の RecentViews を触った`
といった行動ストーリーへ変換するためである。

### 23.3 今回ここまでやる意味

この段階を踏むことで、次の第二段階に進める。

- 第一段階:
  正常行動復元が成立するか
- 第二段階:
  復元結果をもとに `攻撃 / 正常 / 保留` を判断する

いまはこの第一段階を、実データ上でちゃんと埋めているところである。

## 24. `ObjectName` と前後イベントを入れた具体ストーリー

`ObjectName` を見たことで、成立例の具体性が上がった。
以下は特に研究に使いやすい代表例である。

### 24.1 M6 `notepad.exe|20220720T0025Z|chunk007`

見えている object:

- `C:\Windows\System32\en-US\imageres.dll.mui`
- `C:\Users\aalsahee\Links\Desktop.lnk`
- `C:\`
- `C:\Users\aalsahee`
- `C:\Users`

近傍 process:

- `mmc.exe`
- `explorer.exe`
- `firefox.exe`
- `notepad.exe`

ストーリー:

ユーザー `aalsahee` の操作帯の中で、`notepad.exe` が desktop link や system resource に触れている。
単独の閲覧 / 参照系操作として解釈しやすく、単発操作型の成立例として扱いやすい。

### 24.2 S3 `mmc.exe|20220719T1500Z`

見えている object:

- `C:\Windows\Fonts\meiryo.ttc`
- `C:\Users\aalsahee\AppData\Local\Microsoft\Event Viewer\RecentViews`
- `C:\`
- `C:\Users`
- `C:\Users\aalsahee`

近傍 process:

- `firefox.exe`
- `tpautoconnect.exe`
- `mmc.exe`
- `explorer.exe`
- `winword.exe`

ストーリー:

`mmc.exe` が Event Viewer の recent view 情報や font resource に触っており、
管理ツール利用の文脈としてかなり自然である。
周辺に `explorer.exe` や `firefox.exe` が見えるので、ユーザー作業帯の中の管理手続として復元しやすい。

### 24.3 M4 `excel.exe|20220719T2300Z`

見えている object:

- `C:\Users\aalsahee\Downloads\courses.xlsx`
- `C:\Users\aalsahee\Downloads\696B1000`
- `C:\Users\aalsahee\Downloads`
- `C:\Users\aalsahee\AppData\Local\Temp\CVRA820.tmp.cvr`
- `C:\Users\aalsahee\Downloads\C49DCBE8.tmp`

近傍 process:

- `payload.exe`
- `winword.exe`
- `mmc.exe`
- `explorer.exe`
- `firefox.exe`

ストーリー:

`excel.exe` が `courses.xlsx` を中心に Downloads 配下の一時ファイルや関連 object に触っている。
これは文書閲覧 / 編集寄りの単発操作型正常行動としてかなり説明しやすい。

### 24.4 M5 `explorer.exe|20220719T2330Z`

見えている object:

- `C:\Users\aalsahee\Downloads\m5-2`
- `C:\Users\aalsahee\Downloads`
- `C:\Users\aalsahee`
- `C:\Users`
- `C:\Windows\System32\shellstyle.dll`

近傍 process:

- `explorer.exe`
- `winword.exe`
- `firefox.exe`
- `mmc.exe`
- `werfault.exe`
- `powershell.exe`

ストーリー:

`explorer.exe` が Downloads 配下の `m5-2` やその親 directory に触っており、
ユーザーがファイルを見つけて開く前段の操作として読める。
このあと `winword.exe` などへつながるなら、手続型正常行動の中心例として使いやすい。

### 24.5 M5 broad user-time `aalsahee|20220719T2330Z`

見えている object:

- `C:\Windows\System32\spoolss.dll`
- `C:\Program Files\Microsoft Office\Office14`
- `C:\Users\aalsahee`
- `C:\Users`

近傍 process:

- `explorer.exe`
- `winword.exe`
- `firefox.exe`
- `powershell.exe`
- `mshta.exe`

ストーリー:

この broad candidate 自体は大きすぎるが、
ユーザー `aalsahee` の作業帯としては `explorer.exe` と `winword.exe` を含んでおり、
そこから正常手続候補を掘り出せる。
一方で `powershell.exe` や `mshta.exe` も混ざるため、
低特異性起点では純粋な正常手続へ落とすのが難しいことも確認できる。
