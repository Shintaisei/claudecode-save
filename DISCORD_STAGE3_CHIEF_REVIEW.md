# Discord Run key stage3: Chief Agent アクション別レビュー

## この文書の目的

この文書は、Discord Run key registry chain の `stage3` に限定して、Chief Agent がどのように調査論点を立て、どの行動を拾い、どの行動を落とし、どの周辺ログを混ぜたのかを整理する。

`stage3` は、入力が `host=WIN-32-H1`、`process=reg.exe`、`timestamp=2022-07-16 15:05:00` のみであり、SQL検索対象から CBC alert summary rows が除外される条件である。つまり、アラート名やアラート集計サマリに頼らず、端末ログから行動列を復元できるかを見る条件である。

重要な注意点として、formal 23-chain runs では実際のSQL文そのものは保存されていない。そのため、ここでは SQL の正確性を直接評価するのではなく、Chief Agent の論点、QA/Investigator への質問、最終出力に採用された証跡から、調査過程を間接的に評価する。

## 正解チェーン

Discord Run key の `stage3` で復元すべき主行動は次の3つである。

| 正解step | 復元すべき行動 | 重要な証跡 |
|---|---|---|
| C10-S01 | `discord.exe` が `reg.exe` を子プロセスとして起動する | `pid=1204` の `discord.exe`、`childproc_name=c:\windows\system32\reg.exe`、子 `reg.exe` の `ppid=1204` |
| C10-S02 | `reg.exe` が Run key の `Discord` 値を照会する | `pid=5424`、`reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord` |
| C10-S03 | `reg.exe` が Run key の `Discord` 値を追加/更新する | `pid=5504`、`reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "...Update.exe --processStart Discord.exe" /f`、`ACTION_WRITE_VALUE`、`...\Run\Discord` |

このケースで難しい点は、近傍に以下のような周辺ログが存在することである。

- `HKCU\Software\Classes\Discord` への Discord URL protocol 登録
- Discord のファイル更新
- Discord の通信
- `firefox.exe`
- `cmd.exe`
- `nvidia-smi`
- `reg.exe` の DLL / MUI / NLS 参照

これらは端末上の観測事実ではあるが、Run key query/add の主行動列ではない。したがって、主行動に混ぜると過剰主張になる。

## Chief Agent に求められる役割

Chief Agent の役割は、最初の `reg.exe` 起点から、復元対象を正しく絞ることである。Discord stage3 では、特に次の5点が重要になる。

| 観点 | 成功条件 | 失敗例 |
|---|---|---|
| 論点設定 | `discord.exe -> reg.exe -> Run key` を中心論点にできる | 単に「reg.exeが何かした」「Discordが怪しい」で止まる |
| 調査範囲 | `15:05` 近傍の `pid=5424/5504` と `ppid=1204` に寄せる | 15:00-15:10 全体の周辺行動へ広げすぎる |
| 証跡選別 | query と add/write を主行動として採用する | `Classes\Discord` やファイル更新を主行動に混ぜる |
| 因果関係 | `discord.exe` が `reg.exe` を起動し、その `reg.exe` が Run key を操作したと並べる | `reg.exe` 単体の羅列になる |
| 過剰主張抑制 | 周辺ログを補助情報として扱い、主行動から外す | Discord 通信、Firefox、GPU関連ログまで主行動化する |

## 全体結果

| model | run | action recall | evidence recall | order | precision | overclaim | 読み取り |
|---|---:|---:|---:|---:|---:|---:|---|
| `gpt-4.1-mini` | rep1 | 5/9 | 1/3 | 0/2 | 2/6 | 4 | 主行動を一部拾うが、`cmd.exe/nvidia-smi` に逸れる |
| `gpt-4.1-mini` | rep2 | 7/9 | 2/3 | 0/2 | 5/6 | 1 | Run key には寄るが、query/add の時系列が弱い |
| `gpt-5.4-mini` | rep1 | 7/9 | 2/3 | 1/2 | 6/6 | 0 | 最も実用的。query/add を絞って復元 |
| `gpt-5.4-mini` | rep2 | 3/9 | 1/3 | 0/2 | 6/9 | 3 | 近傍の別レジストリ系列に寄る |
| `gpt-5.5 low raw` | rep1 | 9/9 | 3/3 | 2/2 | 12/20 | 8 | 正解は全部拾うが、Discord起動などを広く足す |
| `gpt-5.5 low raw` | rep2 | 9/9 | 3/3 | 2/2 | 9/12 | 3 | 正解は全部拾う。過剰は比較的抑制 |
| `gpt-5.5 low raw` | rep3 | 9/9 | 3/3 | 2/2 | 24/28 | 0 | 正解は全部拾うが、Discord周辺行動まで広く説明する |

## アクション別レビュー

### C10-S01: `discord.exe` が `reg.exe` を起動する

このステップは、単に `reg.exe` が実行されたことではなく、親プロセスが `discord.exe` であることを示す必要がある。ここを拾えると、Run key 操作が Discord の起動・更新処理に紐づく行動として説明できる。

| model | 挙動 |
|---|---|
| `gpt-4.1-mini` | `reg.exe` 実行には気づくが、親子関係を安定して主行動にできない。rep1 では `cmd.exe/nvidia-smi` へ逸れた。 |
| `gpt-5.4-mini` | rep1 では `ppid=1204` を使って `discord.exe` 起点を暗黙的に扱うが、最終行動は `reg.exe query/add` に圧縮される。 |
| `gpt-5.5 low raw` | `discord.exe` が `reg.exe` を子プロセスとして起動した点を明示しやすい。特に rep1/rep2 は親子関係の復元が強い。 |

読み取りとしては、`gpt-5.5` は因果の入口まで復元できる。一方、`gpt-5.4-mini` は最終出力を絞るため、親プロセス情報を根拠には使っていても、独立した行動ステップとして出さないことがある。

### C10-S02: `reg.exe query` による Run key 照会

このステップは、`pid=5424` の `reg.exe` が `HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord` を query したことを復元する必要がある。

| model | 挙動 |
|---|---|
| `gpt-4.1-mini` | `Run` や `Discord` という対象には寄るが、正確な query コマンドラインと PID を安定して出せない。 |
| `gpt-5.4-mini` | rep1 では `pid=5424` と query コマンドラインを正しく出す。証跡の選別が最もきれい。 |
| `gpt-5.5 low raw` | 3run すべてで query を拾う。証跡再現は最も安定している。 |

読み取りとしては、モデル性能が上がると、単に `reg.exe` や `Run key` を言うだけでなく、`query` と `add` の違いを分けて復元できるようになる。

### C10-S03: `reg.exe add` / `ACTION_WRITE_VALUE` による Run key 書き込み

このステップは、`pid=5504` の `reg.exe` が Run key の `Discord` 値を追加・更新したことを復元する必要がある。コマンドラインと `ACTION_WRITE_VALUE` の両方が重要な根拠になる。

| model | 挙動 |
|---|---|
| `gpt-4.1-mini` | Run key 書き込みらしい行動には寄るが、`query -> add/write` の順序と証跡が不安定。 |
| `gpt-5.4-mini` | rep1 では `reg.exe add` と `ACTION_WRITE_VALUE` を正しく採用する。rep2 では近傍の `Classes\Discord` 系列に引っ張られた。 |
| `gpt-5.5 low raw` | 3run すべてで書き込みを拾う。特に `ACTION_WRITE_VALUE` と `Run\Discord` の対応が強い。 |

読み取りとしては、`gpt-5.5` は正解証跡をほぼ落とさない。ただし、正解の周辺にある Discord の通常ファイル更新や通信も拾いやすく、主行動列が広がりやすい。

## モデル別の具体的な失敗・成功

### `gpt-4.1-mini`

`gpt-4.1-mini` は、`reg.exe` 起点であることは理解するが、Chief Agent の論点が広がりやすい。rep1 では、最終出力に `cmd.exe` と `nvidia-smi.exe` が混ざった。これは、近傍ログを探索する過程で「目についた実行イベント」を主行動として扱ってしまった例である。

良かった点は、完全に無関係な方向に行くわけではなく、`reg.exe` や Discord という中心語には到達できる点である。しかし、`discord.exe -> reg.exe -> Run key query/add` という行動列に絞り切る力が弱い。

研究結果としては、低性能モデルでは、アラート集計サマリがない stage3 で調査範囲を自力で制御することが難しい、と言える。

### `gpt-5.4-mini`

`gpt-5.4-mini` は、最も実用的な挙動を示す。rep1 では `reg.exe query` と `reg.exe add/write` を主行動としてきれいに復元し、過剰主張も出さなかった。

ただし、rep2 では `HKCU\Software\Classes\Discord` の URL protocol 登録など、近傍の別レジストリ系列に寄った。これは、Discord 関連のレジストリ操作が複数存在する場合、正解の Run key 操作と近傍のセットアップ操作を取り違える可能性を示している。

研究結果としては、`gpt-5.4-mini` は出力の絞り込みが強く、EDR初動調査支援として確認負荷が小さい。一方で、証跡が似た系列に分岐すると、取りこぼしが起きる。

### `gpt-5.5 low raw`

`gpt-5.5 low raw` は、正解行動の回収が最も強い。3run すべてで `discord.exe` 起点、`reg.exe query`、`reg.exe add/write` を高い精度で拾っている。

一方で、Discord の起動、ファイル更新、通信など、正解の周辺にある観測事実も広く説明しやすい。これは、調査能力が高い一方で、主行動列として残すべきものと補助情報として扱うべきものの境界が広がるという問題である。

研究結果としては、`gpt-5.5` は「証跡を見つける力」は最も強いが、「EDR初動調査で確認しやすい粒度に絞る力」は別課題として残る。

## Chief Agent の論点設定として見えるモデル差

| 観点 | `gpt-4.1-mini` | `gpt-5.4-mini` | `gpt-5.5 low raw` |
|---|---|---|---|
| 中心論点の設定 | `reg.exe` には寄るが散る | `Run key query/add` に絞れる | `Run key` も周辺文脈も広く拾う |
| 調査範囲の制御 | 弱い | 強い | 広い |
| 正解証跡の回収 | 不安定 | 高い | 最高 |
| 周辺ログの除外 | 弱い | 比較的強い | 説明に含めやすい |
| 最終出力の使いやすさ | 低い | 高い | 情報量は多いが確認負荷も大きい |

## 発表で使える主張

Discord Run key の stage3 では、アラート集計サマリがない状態でも、高性能モデルは端末ログから `discord.exe -> reg.exe query -> reg.exe add/write` の主行動列を復元できた。

ただし、モデル差は単に「正しい証跡を拾えるか」だけではない。`gpt-4.1-mini` は調査論点が散り、近傍ログを主行動に混ぜやすい。`gpt-5.4-mini` は主行動を絞る力が強く、EDR初動調査支援として確認しやすい出力になりやすい。`gpt-5.5` は正解証跡を最も安定して拾うが、Discord の通常ファイル更新や通信まで拾いやすく、確認負荷が増える。

したがって、この実験から言える一番大きな主張は、次の通りである。

> stage3 では、モデル性能が上がるほどアラート集計サマリなしでも正解証跡を回収できる。一方で、復元性能の向上と、主行動列への絞り込みは同じ能力ではない。EDR初動調査支援としては、証跡を広く拾うだけでなく、周辺ログを主行動から外す Chief Agent の論点制御が重要である。

## スライドに載せるなら

スライドでは、細かいログ名を全部出すより、次の3段で見せると伝わりやすい。

1. 正解行動列
   - `discord.exe -> reg.exe query -> reg.exe add/write`

2. モデル別の挙動
   - `gpt-4.1-mini`: 近傍ログに散る
   - `gpt-5.4-mini`: 主行動を絞る
   - `gpt-5.5`: 正解証跡を全部拾うが、周辺行動も拾う

3. 研究上の含意
   - 高性能モデルは証跡回収に強い
   - しかし絞り込みは別課題
   - Chief Agent の役割は「拾うこと」だけでなく「主行動として残すものを決めること」
