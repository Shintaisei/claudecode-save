# Discord Run key stage3: Chief Agent action-level review

## このメモの位置づけ

このメモは、Discord Run key registry chain の `stage3` に限定して、Chief Agent がどのように論点を立て、後段の調査に何を渡し、最終的にどの行動を主行動として採用したかを整理したもの。

`stage3` は、入力が `host=WIN-32-H1`、`process=reg.exe`、`timestamp=2022-07-16 15:05:00` のみであり、SQL検索対象から CBC alert summary rows が除外される条件である。つまり、アラート名やアラート要約に頼らず、CBC EDR/NGAV telemetry などの端末ログから行動列を復元できるかを見る条件である。

重要な注意点として、formal 23-chain runs では実際のSQL文や完全なSQL traceは保存されていない。そのため、ここでは「SQLを正しく生成したか」を直接評価するのではなく、Chief Agentの論点、QA/Investigatorへの質問、最終出力に採用された証跡から、調査過程を間接的に評価する。

## 正解チェーン

Discord Run key の stage3 で復元すべき主行動は次の3つ。

| 正解step | 復元すべき行動 | 重要な証跡 |
|---|---|---|
| C10-S01 | `discord.exe` が `reg.exe` を子プロセスとして起動する | `pid=1204` の `discord.exe`、`childproc_name=c:\windows\system32\reg.exe`、子 `reg.exe` の `ppid=1204` |
| C10-S02 | `reg.exe` が Run key の `Discord` 値を照会する | `pid=5424`、`reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord` |
| C10-S03 | `reg.exe` が Run key の `Discord` 値を追加/更新する | `pid=5504`、`reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "...Update.exe --processStart Discord.exe" /f`、`ACTION_WRITE_VALUE`、`...\Run\Discord` |

このケースでは、近傍に `HKCU\Software\Classes\Discord`、Discordのファイル更新、`firefox.exe`、`cmd.exe`、`nvidia-smi`、Discord通信なども存在する。これらは観測事実ではあるが、Run key query/add の主行動列ではないため、主行動に混ぜると過剰主張になる。

## stage3でChief Agentに求められること

Chief Agentの役割は、最初の `reg.exe` 起点から、復元対象を正しく絞ることである。Discord stage3では、特に次の5点を見る。

| 観点 | 成功条件 | 失敗例 |
|---|---|---|
| 論点設定 | `discord.exe -> reg.exe -> Run key` を中心論点にできる | 単に「reg.exeが何かした」「Discordが怪しい」で止まる |
| 調査範囲 | `15:05` 近傍の `pid=5424/5504` と `ppid=1204` に寄せる | 15:00-15:10全体の周辺行動へ広げすぎる |
| 調査項目 | parent/child、PID/PPID、command line、registry path、write actionを確認させる | DLL load、ファイルアクセス、通信に寄りすぎる |
| ノイズ抑制 | `Classes\Discord`、`RunOnce`、Discord通常処理を主行動から外す | URL protocol登録、ファイル更新、通信を主行動に混ぜる |
| 一貫性 | 一度見つけた `Run\Discord` query/add を維持する | 後段で `nvidia-smi` や別レジストリパスに逸れる |

## モデル別の概要

| model | stage3でのChief Agentの動き | 結果の読み取り |
|---|---|---|
| `gpt-4.1-mini` | 最初は `reg.exe` 周辺を探すが、検索範囲が広く、DLL、Discord通常動作、`cmd.exe/nvidia-smi` などへ逸れる | 論点維持が弱く、Run keyの主行動列を安定して保持できない |
| `gpt-5.4-mini` | `Discord.exe` 初回起動に伴う Run key 登録という論点を立て、`query/add` に絞る回がある | 主行動への絞り込みが最も良いが、replicateによって `Classes\Discord` 側へ寄る |
| `gpt-5.5 low raw` | `pid=5424/5504`、`ppid=1204`、`query/add`、`ACTION_WRITE_VALUE` まで強く拾う | 正解回収は最も強いが、Discord本体のファイル更新・通信も主行動化しやすい |

## アクション別レビュー

### Action 1: `discord.exe` が `reg.exe` を起動する

正解は、`discord.exe` PID `1204` から `reg.exe` が子プロセスとして起動されることである。ここでは、単に `reg.exe` が存在するだけでなく、`ppid=1204`、`parent_process_path=...\discord.exe`、`childproc_name=c:\windows\system32\reg.exe` までつなぐ必要がある。

| model | できたこと | 落としたこと / 余計なこと |
|---|---|---|
| `gpt-4.1-mini` | replicate_02では `reg.exe` の親が `discord.exe` であることには触れた | replicate_01では途中で「discord.exeの子としてreg.exeは観測されない」と崩れ、`cmd.exe -> nvidia-smi` を主行動に混ぜた |
| `gpt-5.4-mini` | `ppid=1204` の `reg.exe` を捉え、Run key query/addへ接続した | final outputでは明示的な「discord.exeがreg.exeを起動した」stepを省略し、`reg.exe`側の2 stepだけに圧縮する回がある |
| `gpt-5.5 low raw` | `discord.exe pid=1204`、`childproc_name=reg.exe`、子 `reg.exe pid=5424/5504` を強く拾った | `discord.exe` 自体の起動や通常動作まで主行動に入れ、主チェーンが膨らむ回がある |

読み取り:

`gpt-5.4-mini` と `gpt-5.5` は、alert summaryなしでも親子関係を端末ログから拾えている。一方、`gpt-4.1-mini` は調査途中で論点がぶれ、親子関係を保持できない回がある。

### Action 2: `reg.exe query` による Run key照会

正解は、`pid=5424` の `reg.exe` が次のコマンドを実行することである。

```text
C:\Windows\System32\reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord
```

| model | できたこと | 落としたこと / 余計なこと |
|---|---|---|
| `gpt-4.1-mini` | replicate_02では `Run\Discord` に近い対象を出せた | `query` コマンドとして分離できず、`registry_key_modify` のような曖昧な操作に潰した。replicate_01では主行動から外れた |
| `gpt-5.4-mini` | replicate_01では `pid=5424`、`reg.exe query`、`HKCU\...\Run /v Discord`、証跡を正しく出した | replicate_02では `15:03` 台の `Classes\Discord` や別Run登録に寄り、正解の `query` を落とした |
| `gpt-5.5 low raw` | 3回とも `reg.exe query` と `pid=5424` を拾った | 付随証跡を多く出すため、`ACTION_PROCESS_TERMINATE` や周辺アクセスも証跡に含めやすい |

読み取り:

`query` は、モデル差がかなり出る。`gpt-4.1-mini` はRun keyらしさは掴めても、照会という行動種別とコマンドラインの保持が弱い。`gpt-5.4-mini` は正しく絞れる回があるが、近傍の `Classes\Discord` 登録に吸われる回がある。`gpt-5.5` は最も安定して拾う。

### Action 3: `reg.exe add` による Run key追加/更新

正解は、`pid=5504` の `reg.exe` が次のコマンドを実行し、`Run\Discord` に `Update.exe --processStart Discord.exe` を書き込むことである。

```text
C:\Windows\System32\reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "C:\Users\aalsahee\AppData\Local\Discord\Update.exe --processStart Discord.exe" /f
```

重要証跡は、`command_line` だけでなく `ACTION_WRITE_VALUE` と `HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\Discord` である。

| model | できたこと | 落としたこと / 余計なこと |
|---|---|---|
| `gpt-4.1-mini` | replicate_02では `Run\Discord` の変更に近い出力をした | `add` コマンド、`Update.exe --processStart Discord.exe`、`ACTION_WRITE_VALUE` の具体性が弱い |
| `gpt-5.4-mini` | replicate_01では `pid=5504`、`reg.exe add`、`Run\Discord`、`Update.exe --processStart Discord.exe`、証跡を正しく出した | replicate_02では `15:03:55 pid=2360` の近傍Run登録に寄り、正解時刻・正解PIDから外れた |
| `gpt-5.5 low raw` | 3回とも `reg.exe add`、`pid=5504`、`Run\Discord`、`ACTION_WRITE_VALUE` を拾った | `registry_add` と `registry_write_value` を別stepに分け、1つの正解行動を複数step化する回がある |

読み取り:

`add/write` は `gpt-5.5` が最も強い。`gpt-5.4-mini` は正解に到達する回では非常にきれいに絞れるが、同じDiscord初回起動系列にある別のレジストリ操作へ逸れることがある。`gpt-4.1-mini` は対象の雰囲気は掴めても、コマンドラインと書き込み証跡の粒度が不足する。

## 近傍ノイズの扱い

Discord stage3で特に重要なのは、正しいログを拾うだけでなく、近傍ノイズを主行動から外せるかである。

| 近傍ログ | 正しい扱い | モデル差 |
|---|---|---|
| `HKCU\Software\Classes\Discord` / URL protocol登録 | Discord関連だが、今回のRun key persistence主行動ではない | `gpt-4.1-mini` と `gpt-5.4-mini` replicate_02が混ぜやすい |
| `cmd.exe -> nvidia-smi` | 同時刻近傍の別行動。Run key chainではない | `gpt-4.1-mini` replicate_01が主行動化した |
| Discordファイル更新 | Discord初回起動の周辺動作。Run key query/addとは別 | `gpt-5.5` replicate_03が主行動に含めた |
| Discord通信 `discord.com:443` | 観測事実だが、reg.exe Run key chainではない | `gpt-5.5` replicate_02では除外、replicate_03では主行動化 |
| `reg.exe` DLL/MUI/NLSアクセス | 実行時の周辺アクセス。主行動ではない | `gpt-5.5` replicate_03は除外説明できた |

## Chief Agent観点でのモデル差

### `gpt-4.1-mini`

Chief Agentの論点設定が最も不安定だった。最初は `reg.exe` 周辺を調べるが、範囲を `15:00-15:10` に広げた後、`ctiuser.dll`、親PID、Discord子プロセス、ネットワーク、`cmd.exe/nvidia-smi` へ論点が散った。

特に replicate_01 では、途中で `reg.exe` と Discord Run key の論点を見失い、最終的に `cmd.exe` が `nvidia-smi.exe` を実行した行動を主行動に混ぜている。これは「検索範囲を広げた後に、何を主行動として残すか」の制御が弱いことを示す。

### `gpt-5.4-mini`

Chief Agentは、`Discord.exe` 初回起動に伴う Run key登録という中心論点を立てられる。replicate_01では、`reg.exe query` と `reg.exe add` を正しい時刻・PID・コマンドライン付きで復元し、過剰主張も0だった。

ただし replicate_02では、同じDiscord初回起動系列にある `HKCU\Software\Classes\Discord` や `15:03` 台の近傍Run登録に寄った。つまり、`gpt-5.4-mini` は出力を絞れるが、最初に選んだ局所系列がずれると、そのまま狭く間違える。

### `gpt-5.5 low raw`

Chief Agentは、`pid=5424/5504`、`ppid=1204`、`reg.exe query/add`、`ACTION_WRITE_VALUE` を安定して拾う。3 replicateすべてで action/evidence/order は満点だった。

一方で、調査範囲を広く持つため、Discord本体の起動、ファイル更新、通信、周辺子プロセスまで行動列に含めやすい。replicate_01/02では除外理由を書けているが、replicate_03ではDiscordファイル更新や通信を主行動として出している。これは「拾う力」は高いが、「主行動列に残すかどうか」の絞り込みが別課題であることを示す。

## 発表で使える結論

Discord Run key stage3では、アラート集計サマリがない状態でも、高性能モデルは端末ログから `discord.exe -> reg.exe query -> reg.exe add/write` の主行動列を復元できた。

ただし、モデルごとの失敗の仕方は異なる。`gpt-4.1-mini` は調査論点が散り、近傍ログを主行動に混ぜやすい。`gpt-5.4-mini` は主行動を絞る力が強いが、近傍の別レジストリ系列に寄ると取りこぼす。`gpt-5.5` は正解証跡を最も安定して拾うが、Discordの通常ファイル更新や通信まで拾いすぎる。

したがって、Chief Agentのモデル差は「正しい証跡を拾えるか」だけでなく、「拾った周辺証跡を主行動列から外せるか」に現れる。

## スライド用の短い言い方

> Discord Run key の stage3では、`gpt-5.5` は alert summaryなしでも `reg.exe query/add` と `ACTION_WRITE_VALUE` を安定して回収した。一方で、Discord本体のファイル更新や通信まで主行動に含める回があり、過剰主張が残った。`gpt-5.4-mini` は正しい局所系列に入れた場合、Run key行動を最もきれいに絞れたが、近傍の `Classes\Discord` 登録へ寄る回があった。`gpt-4.1-mini` は検索範囲拡大後に論点が散り、Run keyではない近傍行動を主行動に混ぜやすかった。

