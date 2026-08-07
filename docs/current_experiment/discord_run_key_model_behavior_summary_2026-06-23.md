# Discord Run key 例に見るモデル別の過剰・過小出力整理

作成日: 2026-06-23

このメモの目的は、`chain_10_e07_discord_run_key_registry_chain` を例にして、各モデルが何を復元できて、何を余計に含めて、何を落としたのかを説明できるようにすること。

結論から言うと、この例の過剰主張は「完全に存在しない挙動を作った」というより、同じ時間帯・同じ Discord/reg.exe 周辺に存在する本物のログを、今回の正解チェーンに含めすぎる境界判定の失敗として出ている。つまり、再現率が良くても、そのまま初動調査支援に使うには「対象チェーンと周辺ログの切り分け」がまだ課題として残る。

## この Discord 例の正解チェーン

対象チェーンは、Discord のインストール/初回起動付近で、`discord.exe` が `reg.exe` を使って Run key に Discord の自動起動設定を確認・追加する挙動である。

正解は大きく 3 ステップ。

| 順序 | 正解ステップ | 見るべき対象 |
|---:|---|---|
| 1 | `discord.exe` から `reg.exe` が起動される | `discord.exe` -> `C:\Windows\System32\reg.exe` |
| 2 | `reg.exe` が Run key の `Discord` 値を照会する | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Discord` |
| 3 | `reg.exe` が Run key の `Discord` 値を追加/更新する | `Update.exe --processStart Discord.exe` |

具体的には以下のようなコマンドラインが重要になる。

```text
C:\Windows\System32\reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord
C:\Windows\System32\reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "C:\Users\aalsahee\AppData\Local\Discord\Update.exe --processStart Discord.exe" /f
```

このチェーンで言う「復元できた」は、単に `reg.exe` や `Discord` という単語を拾うことではない。`discord.exe` から起動された `reg.exe` が、Run key の `Discord` 値を query し、続けて add/write した、という行動列として説明できることを指す。

## 過剰主張と過小出力の意味

この実験で問題になる過剰主張は、主に次の形で出る。

| 型 | 内容 | Discord 例での具体例 |
|---|---|---|
| 対象違い | レジストリ操作ではあるが、今回の Run key チェーンではない | `HKCU\Software\Classes\Discord`、Discord protocol 登録 |
| 近傍チェーン混入 | 同じ episode や近い時間の別行動を混ぜる | `nvidia-smi.exe`、`cmd.exe`、Sublime/Python 系の別チェーン |
| 周辺ノイズ混入 | 対象プロセスの周辺ログを行動ステップとして扱う | `ctiuser.dll`、`sechost.dll`、`imm32.dll`、`fltLib.dll` などの DLL access/module load |
| 正規アプリ通常動作の混入 | Discord の普通の起動や子プロセスを Run key チェーンに含める | `crashpad-handler`、`renderer`、`gpu-process` |
| alert 依存 | alert 名や alert summary を根拠にしすぎる | `Persistence - Regmod Run or Runonce Key Modification` だけで Run/RunOnce を断定する |

過小出力は、逆に必要な 3 ステップの一部を落とすこと。

| 型 | 内容 | Discord 例での具体例 |
|---|---|---|
| 空出力 | `code_steps` が空 | gpt-4.1-mini の stage2 で発生 |
| 親子関係落ち | query/add は出るが、`discord.exe` -> `reg.exe` が弱い | gpt-5.4-mini の一部 run |
| registry 対象落ち | `reg.exe` 実行は拾うが Run key の対象を示せない | gpt-4.1-mini stage3 |
| 証拠不足 | 行動は言うが、非 alert telemetry の根拠が弱い | stage1 で alert に引っ張られるケース |

発表では、過剰主張を「幻覚」とだけ言わない方がよい。今回の結果では、むしろ「近傍に実在するログを、対象チェーンの一部として含めすぎる問題」と説明した方が正確である。

## モデル別の全体傾向

Discord Run key chain のモデル別平均は以下。

| モデル | action recall | evidence recall | order | precision | overclaim/run | 解釈 |
|---|---:|---:|---:|---:|---:|---|
| `gpt-4.1-mini` | 0.506 | 0.148 | 0.167 | 0.488 | 4.44 | 起点周辺を拾うが、空出力や混入が多い |
| `gpt-5.4-mini` | 0.642 | 0.481 | 0.333 | 0.696 | 2.00 | Run key への意味付けは改善するが、順序と親子関係がまだ弱い |
| `gpt-5.5 low raw` | 1.000 | 0.667 | 0.667 | 0.783 | 3.67 | 必要情報はかなり拾えるが、周辺証拠を広げすぎることがある |

読み方としては、`gpt-5.5` は「Run key の query/add を見つける力」は強い。一方で、調査で見つけた周辺ログを広く説明しようとするため、precision や overclaim に課題が残る。`gpt-5.4-mini` は structured output としては扱いやすく、過剰主張も比較的少ないが、完全な行動列としては足りない。`gpt-4.1-mini` は、比較対象として「弱いモデルだと何が崩れるか」を示すのに使いやすい。

## 材料集めの過程で何が違うか

ここが重要。最終出力だけを見ると「復元できた/できなかった」に見えるが、実際にはモデルごとにログを探すときの癖が違う。

注意点として、`gpt-4.1-mini` と `gpt-5.4-mini` は中間の質問や SQL が十分に保存されていないため、ここでの評価は最終的に選ばれた証跡・claim からの間接評価である。一方、`gpt-5.5 low raw` は raw 出力に QAAgent への質問が残っており、材料集めの過程をかなり直接読める。

### 材料集めの比較

| モデル | 材料集めの動き | 見に行く材料 | その結果起きるミス |
|---|---|---|---|
| `gpt-4.1-mini` | 先に「registry persistence っぽい」という論点を立て、周辺ログからそれに合うものを拾う | `audit_logs`、`cbc-edr-alerts`、一部 `sysmon` / `cbc-edr` | 論点名が先行し、正しい command line / PID / registry object への接続が弱い |
| `gpt-5.4-mini` | Run key や command line に寄せて、対象 registry object を絞ろうとする | `cbc-edr`、`cbc-edr-alerts`、`msft-security`、一部 source 未確定 | query/add には届くが、親子関係や重複排除が弱い |
| `gpt-5.5 low raw` | 仮説を立てて、PID、command line、source_stream、親子関係、row id を順に確認する | `cbc-edr`、`cbc-ngav`、`msft-security`、`cbc-edr-alerts`、`sysmon` | 材料を集めすぎて、core step と補助証拠と周辺事象の区別が崩れる |

この違いを一言で言うと、`gpt-4.1-mini` は「それっぽい論点から広げる」、`gpt-5.4-mini` は「registry object に寄せて絞る」、`gpt-5.5` は「仮説検証で深掘るが拾いすぎる」。

### gpt-4.1-mini: 論点先行で材料を拾う

`gpt-4.1-mini` は、材料集めの段階で `Discovery - Query Registry` や `Persistence - Regmod Run or Runonce Key Modification` のような alert の意味に引っ張られやすい。

そのため、探索の方向性としては「registry persistence がありそう」「Discord 関連の registry 操作がありそう」というところまでは行く。しかし、そこから `PID 5424/5504`、`reg.exe query/add`、`HKCU\...\CurrentVersion\Run\Discord` という具体的な証拠に固定する力が弱い。

このモデルの材料集めのミスは、次の順で起きる。

1. alert 名や `Discord` / `reg.exe` から registry persistence の論点を立てる。
2. 近い時間帯にある registry や file access を広く拾う。
3. `Run`、`RunOnce`、`Software\Classes\Discord`、DLL access の区別が甘くなる。
4. 最終出力では、正解の一部と周辺ログが混ざる。

つまり、`gpt-4.1-mini` の問題は「材料を見つけられない」だけではない。見つけた材料を、今回の行動チェーンに属するものかどうかで選別できない。

逆に stage2 のように alert の誘導が弱い条件では、材料を集める起点を作れず `code_steps` が空になることがある。これは「広げすぎ」と「何も出せない」が同居しているということ。

### gpt-5.4-mini: 対象 registry object には寄るが、関係付けが浅い

`gpt-5.4-mini` は、`gpt-4.1-mini` よりも材料集めが具体的である。`reg.exe query HKCU\...\Run /v Discord` と `reg.exe add HKCU\...\Run /v Discord ...` のように、command line と registry object に寄せて証拠を集められる。

このモデルの良いところは、周辺ログをすべて拾うのではなく、Run key という対象にある程度絞れること。実際、代表的な claim では以下に到達している。

- `reg.exe` による `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` への `Discord` value add
- `reg.exe` による `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Discord` の query
- `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Discord` の regmod

一方で、材料集めのミスは「関係付けが浅い」こと。

| 集められる材料 | 弱いところ |
|---|---|
| `reg.exe query/add` の command line | PID、source_stream、event id が未確定になることがある |
| `HKU\S-1-5-21-...\Run\Discord` の regmod | `reg.exe add` の証拠なのか、別 step なのかの整理が弱い |
| `discord.exe` が親らしい情報 | `discord.exe` -> `reg.exe` の親子関係を独立 step として落とすことがある |
| alert row | supporting evidence として残すべきものを、行動根拠に近く扱うことがある |

つまり、`gpt-5.4-mini` は材料の探し方としてはかなり良くなる。ただし、集めた材料を「1つの時系列チェーン」に束ねるところで弱い。query/add の 2 点は掘れるが、`discord.exe` 起点、PID 対応、regmod との対応、周辺除外を最後まで詰め切れない。

発表で言うなら、`gpt-5.4-mini` は「材料探索は対象に寄るが、証拠同士の join が弱い」と表現できる。

### gpt-5.5: 仮説検証型で深掘るが、材料を捨てきれない

`gpt-5.5` は raw 出力に中間質問が残っており、材料集めの過程が一番見える。

Discord 例では、だいたい次のような順で調べている。

1. `WIN-32-H1`、`reg.exe`、`2022-07-16 15:05:00` 近傍を起点にする。
2. 近傍の `reg.exe` PID を探す。
3. PID `5424` と PID `5504` を見つける。
4. それぞれの command line を確認する。
   - PID `5424`: `reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord`
   - PID `5504`: `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "...Update.exe --processStart Discord.exe" /f`
5. `ppid=1204` と parent `discord.exe` を確認する。
6. `discord.exe` の parent が `update.exe` であることも確認する。
7. `cbc-edr` / `cbc-ngav` の `ACTION_WRITE_VALUE` で `HKU\S-1-5-21-...\Run\Discord` を確認する。
8. さらに `msft-security` の DLL access や process terminate まで周辺証拠として集める。

ここまでは、調査としてはかなり良い。強いのは、単に `Run key がある` と言うのではなく、PID、親子関係、command line、source_stream まで確認しようとする点である。

ただし、この深掘りがそのまま過剰主張にもつながる。`gpt-5.5` は「見つけた材料」を最後に捨てるのが苦手で、次のようなものまで出力に残しやすい。

| 集めた材料 | 本来の扱い | ミスになる扱い |
|---|---|---|
| `msft-security` の DLL access | `reg.exe` が動いた補助的な痕跡 | Run key チェーンの step として並べる |
| `ACTION_PROCESS_TERMINATE` | プロセス終了の補助情報 | 行動列の主要 step にする |
| 15:03 台の `HKCU\Software\Classes\Discord` | Discord 初期設定の別 registry 操作 | 15:05 の Run key チェーンに混ぜる |
| `cbc-edr-alerts` | 調査起点/参考情報 | 非 alert evidence と同じように扱う |

したがって `gpt-5.5` の材料集めは、探索能力としては最も良いが、出力段階で「これは正解チェーンの step」「これは補助証拠」「これは周辺事象」と分ける制御が必要になる。

### 材料集めのミスを研究課題として言うなら

この Discord 例から見える課題は、最終出力の precision だけではなく、調査過程での材料選択にもある。

発表では次のように言える。

> モデル間の差は、最終的な復元結果だけでなく、材料を集める段階にも表れた。弱いモデルは alert 名や registry persistence という論点から周辺ログを広く拾い、Run/RunOnce や別 registry 操作を混ぜやすい。中間のモデルは Run key の command line までは絞れるが、親子関係や regmod との対応付けが不安定である。強いモデルは PID、command line、source_stream、親子関係まで深掘りできるが、集めた補助証拠や周辺ログを捨てきれず、過剰主張として残る。したがって、本研究の次の課題は、ログ探索能力そのものだけでなく、集めた材料を対象チェーンの step、補助証拠、周辺事象に分類する制御である。

## 3 Agent のどこで点数差が生まれるか

CLOUSEAU の中間ログを見ると、点数差は「モデルが賢い/賢くない」だけではなく、3 つの役割で別々に出ている。

ここでは便宜上、次の 3 段階で見る。

| 段階 | 役割 | ここが強いと上がる点数 | ここが弱いと起きること |
|---|---|---|---|
| Chief | 調査仮説と lead を作る | action recall、order の土台 | 探す対象が広すぎる/ズレる |
| Investigator / QAAgent | lead に沿ってログ証拠を集める | evidence recall | command line、PID、source_stream、parent が欠ける |
| 最終統合 | 集めた材料を code_steps に採用/除外する | precision、order | 補助証拠や近傍ログを step に混ぜる |

Discord Run key の正解は、次の 3 点を同時に満たす必要がある。

| 必要要素 | 取れてほしい材料 | 点数への効き方 |
|---|---|---|
| 親子関係 | `discord.exe` -> `reg.exe`、できれば PID/PPID と parent command line | action recall、order |
| query | `reg.exe query HKCU\...\Run /v Discord` | action recall、evidence recall |
| add/write | `reg.exe add HKCU\...\Run /v Discord /d "...Update.exe --processStart Discord.exe"` と `ACTION_WRITE_VALUE` | action recall、evidence recall |
| 境界整理 | `Software\Classes\Discord`、DLL access、process terminate、Discord 通常子プロセスを step から外す | precision |

つまり、点数が上がる流れはこう。

1. Chief が「Discord 関連 registry」ではなく「Run key の query/add」として lead を切る。
2. Investigator / QAAgent が PID、command line、source_stream、parent、registry object を同時に取る。
3. 最終統合が、取れた材料を `対象 step`、`補助証拠`、`周辺事象` に分ける。

この 3 段階のうち、どこか 1 つが弱いと点数の落ち方が変わる。

## 代表 run で見る取得と脱落

### gpt-4.1-mini stage1: Chief は方向を立てるが、材料選択が広がる

代表: `replicate_01 stage1`

スコアは action recall 0.889、evidence recall 0.333、order 0.5、precision 0.583、overclaim 5。見かけ上 action recall は高いが、材料の選び方がかなり荒い。

中間ログでは、Chief は次のような lead を出している。

```text
2022-07-16 15:07:46 前後の Persistence - Regmod Run or Runonce Key Modification アラートに関連するプロセス 2360 と 5504 の動作を調査する。
parent process、command line、レジストリ変更の詳細を確認し、reg.exe の動作との関連を探る。
```

この lead は悪くない。`parent process`、`command line`、`レジストリ変更` を見に行こうとしている。ただし、起点が alert 名に強く寄っているため、調査対象が `Run key の Discord value` ではなく、`Discord 関連の registry 操作全般` に広がる。

Investigator の返答では、次の材料を拾っている。

| 材料 | 取れたか | 評価 |
|---|---|---|
| `reg.exe` の親が `discord.exe` | 取れている | 正解に近い |
| Discord 関連 registry | 取れている | ただし `Software\Classes\Discord` に寄る |
| Run key の変更 | 取れている | ただし command line / data が弱い |
| `ctiuser.dll` file access | 取れている | 補助証拠ではなく周辺ノイズ |
| query/add の分離 | 弱い | PID 5424=query、5504=add の切り分けに届かない |

最終統合では、取れた材料を以下の code_steps にしている。

| 最終 step | 正解との関係 | 問題 |
|---|---|---|
| `HKU\...\Software\Classes\Discord` read | 過剰/対象違い | Discord protocol 登録側であり、Run key ではない |
| `HKCU\...\CurrentVersion\Run` modify | 部分正解 | Run key には届くが、query/add の command line が弱い |
| `HKCU\...\CurrentVersion\RunOnce` modify | 過剰 | alert 名の Run or RunOnce に引っ張られている |
| `ctiuser.dll` file access | 過剰 | DLL access を行動 step として採用している |

この run で見えるのは、Chief が方向を立てても、Investigator の材料が広く、最終統合がそれを捨てられないと precision が落ちる、ということ。

点数への効き方は次の通り。

| 点数 | なぜそうなるか |
|---|---|
| action recall が高い | `reg.exe`、`discord.exe`、Run 系 registry という部品は拾っている |
| evidence recall が低い | exact な command line、PID/PPID、source_stream、Run\Discord write の証拠が弱い |
| precision が低い | `Software\Classes\Discord`、`RunOnce`、`ctiuser.dll` を step にした |
| order が半分 | 行動列というより同時刻周辺の材料列になっている |

したがって、`gpt-4.1-mini` は「Chief の仮説形成は最低限できるが、Investigator が正解証拠に寄せきれず、最終統合が周辺材料を落とせない」タイプである。

### gpt-5.4-mini stage2: Investigator は query/add に届くが、ID 接続が弱い

代表: `replicate_01 stage2`

スコアは action recall 0.778、evidence recall 0.667、order 0.5、precision 0.889、overclaim 1。4.1 より precision と evidence が大きく改善している。

中間ログでは、Investigator がかなり正解に近い材料を返している。

```text
- 2022-07-16 15:05:00 近傍の reg.exe は、discord.exe から起動されていた。
- 確認できた reg.exe の command line:
  - reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord
  - reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "...Update.exe --processStart Discord.exe" /f
- reg.exe add に対応する regmod があり、HKU\S-1-5-21-...\CurrentVersion\Run\Discord が観測された。
```

ここで 4.1 から改善しているのは、材料の粒度である。

| 材料 | gpt-4.1-mini | gpt-5.4-mini |
|---|---|---|
| registry 対象 | `Software\Classes\Discord` や `RunOnce` に広がる | `CurrentVersion\Run /v Discord` に寄る |
| command line | 弱い/欠ける | query/add の command line を取る |
| add の証拠 | Run っぽい modify | `HKU\S-1-5-21-...\Run\Discord` の regmod まで取る |
| 周辺ノイズ | `ctiuser.dll` を step 化 | network や alert を excluded_nearby に回す |

ただし、弱さも残っている。最終出力では次のような limitation が残る。

```text
PID/PPID、source_stream、event_record_id はこの時点では確定できていない。
parent_process として discord.exe が観測されたが、親プロセスの PID と command_line は未確定。
regmod 行の source_stream、event_record_id、PID/PPID は未確定。
```

つまり、`query/add という材料` は取れているが、`どの PID の、どの source_stream の、どの parent から来た事象か` の接続が浅い。

最終統合の動きはこう。

| 最終 step | 正解との関係 | 問題 |
|---|---|---|
| `reg.exe query HKCU\...\Run /v Discord` | 正解 | ただし PID/source が未確定 |
| `reg.exe add HKCU\...\Run /v Discord /d ...` | 正解 | ただし PID/source が未確定 |
| `HKU\S-1-5-21-...\Run\Discord` regmod | 証拠としては有用 | 独立 step にすると重複/過剰寄り |

点数への効き方は次の通り。

| 点数 | なぜそうなるか |
|---|---|
| action recall が上がる | query/add の command line に届いた |
| evidence recall が上がる | regmod object まで到達した |
| precision が上がる | `RunOnce` や DLL access をかなり落とせた |
| order が伸び切らない | parent-child と query/add/regmod の対応が完全には束ねられていない |

したがって、`gpt-5.4-mini` は「Investigator の対象発見能力が上がり、正解材料に近づく。ただし ID 接続と時系列統合が弱いので、order と evidence が頭打ちになる」タイプである。

### gpt-5.5 stage3: QA の反復で必要証拠に到達するが、最終統合で捨てきれない

代表: `replicate_01 stage3`

スコアは action recall 1.0、evidence recall 1.0、order 1.0、precision 0.6、overclaim 8。必要な材料は全部取れているが、余計な材料も残る。

Chief の lead はかなり具体的である。

```text
WIN-32-H1 の 2022-07-16 15:05:00 近傍に実行された reg.exe を調査対象とし、
parent process、command line、PID/PPID、event_record_id、source_stream、
対象 registry object を特定する。
```

この lead の時点で、4.1/5.4 より確認項目が細かい。特に `PID/PPID`、`source_stream`、`registry object` を同時に要求しているのが重要。

QAAgent の探索は、次のような反復になっている。

| QA の段階 | 取った材料 | その時点の限界 | 次に進めた理由 |
|---|---|---|---|
| 仮説1 | PID `5424` / `5504` の `msft-security` DLL access | command line、ppid、parent がない | PID が分かったので CBC EDR/NGAV を掘れる |
| 仮説2 | PID `5424` は query、PID `5504` は add、両方 `ppid=1204` | process_guid はない、DLL access も残る | parent PID `1204` を追える |
| 仮説3 | parent `discord.exe` PID `1204`、その parent `update.exe`、同一 process tree | `Software\Classes\Discord` など前後操作も見えてしまう | Run\Discord に対象を絞る必要が出る |
| 仮説4 | `ACTION_WRITE_VALUE` が `HKU\...\Run\Discord` に出る、source は `cbc-ngav` / `cbc-edr` | query 側の registry read event は明示的には弱い | add/write の evidence が固まる |

この反復によって、正解に必要な材料はほぼ揃う。

| 正解要素 | 取れた材料 |
|---|---|
| `discord.exe` -> `reg.exe` | `ppid=1204`、parent `discord.exe`、parent command line `--squirrel-firstrun` |
| query | PID `5424`、`reg.exe query HKCU\...\Run /v Discord` |
| add/write | PID `5504`、`reg.exe add HKCU\...\Run /v Discord /d "...Update.exe --processStart Discord.exe" /f` |
| write evidence | `ACTION_WRITE_VALUE`、`HKU\S-1-5-21-...\Run\Discord`、`cbc-ngav` / `cbc-edr` |
| process tree | parent `discord.exe` PID `1204`、さらに parent `update.exe` PID `660` |

ここまで取れているため、action/evidence/order は 1.0 になる。

しかし、QA が深掘りした副作用として、周辺材料も大量に取れている。

| 余計に取れた材料 | 本来の扱い | 最終で残ると何が悪いか |
|---|---|---|
| `sechost.dll`、`imm32.dll`、`ctiuser.dll`、`fltLib.dll` | `reg.exe` 実行の補助痕跡 | 行動 step にすると過剰 |
| `ACTION_PROCESS_TERMINATE` | process lifecycle の補助情報 | query/add と同列にすると過剰 |
| 15:03 台の `Software\Classes\Discord` | Discord の別 registry 初期設定 | Run key chain と混ぜると対象違い |
| `firefox.exe` handoff URL、Discord 子プロセス | 同一 parent 近傍の通常動作 | Run key 操作の step ではない |

つまり、`gpt-5.5` は「材料を取る Agent 性能」は高い。しかし、最終統合で材料を捨てる能力が追いつかず、precision が落ちる。

点数への効き方は次の通り。

| 点数 | なぜそうなるか |
|---|---|
| action recall が 1.0 | query/add/parent を全部取る |
| evidence recall が 1.0 | source_stream、PID、regmod object まで取る |
| order が 1.0 | parent -> query -> add/write の流れを説明できる |
| precision が低い | QA で取った DLL access、process terminate、別 registry 操作を捨てきれない |

したがって、`gpt-5.5` は「Chief と QAAgent の探索性能が上がって満点に近い材料を集めるが、最終統合の除外制御が弱く precision が下がる」タイプである。

## 点数向上を Agent 性能差として説明する

この Discord 例では、点数向上は次のように説明できる。

| 比較 | 上がる能力 | スコアへの反映 | 残る課題 |
|---|---|---|---|
| 4.1 -> 5.4 | Investigator が正しい registry object と command line に近づく | evidence recall と precision が上がる | PID/source/parent の接続が弱く order が伸びない |
| 5.4 -> 5.5 | Chief lead が具体化し、QA が PID/parent/source_stream/regmod まで反復確認する | action/evidence/order が 1.0 近くまで上がる | 集めた周辺材料を捨てきれず precision が落ちる |

もう少し具体的に言うと、4.1 から 5.4 への改善は「何を見るべきか」の改善である。`Discord 関連 registry` から `CurrentVersion\Run /v Discord` に寄るので、誤った registry 対象が減る。

5.4 から 5.5 への改善は「どう証拠を接続するか」の改善である。PID `5424/5504`、`ppid=1204`、parent `discord.exe`、`cbc-edr` / `cbc-ngav`、`ACTION_WRITE_VALUE` までつながるので、行動列として説明できる。

ただし 5.5 でも、「何を出力から落とすか」はまだ弱い。だから、この研究の結果は次のように言うのがよい。

> モデル性能が上がると、単に最終回答が自然になるのではなく、調査過程で確認する材料が変わる。弱いモデルは alert 名から広く拾うため過剰・対象違いが出る。中間モデルは Run key の command line まで届くが、PID や source_stream の接続が弱い。強いモデルは PID、親子関係、source_stream、registry object を反復確認できるため再現率と証拠再現率が上がる。一方で、強いモデルほど周辺材料も多く集めるため、最終段階で補助証拠と対象 step を分ける制御が必要になる。

## ステージ別・回数別のばらつき

ここでは、Discord Run key だけを stage × model × replicate で見る。数値は平均、括弧内は replicate 間の最小-最大である。`gpt-4.1-mini` と `gpt-5.4-mini` は各 stage 2 回、`gpt-5.5` は各 stage 3 回である。`gpt-5.5` は raw-text salvage なので、形式安定性とは分けて読む。

| model | stage | n | action | evidence | order | precision | overclaim |
|---|---:|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | stage1 | 2 | 0.833 (0.778-0.889) | 0.167 (0.000-0.333) | 0.500 (0.500-0.500) | 0.500 (0.417-0.583) | 6.0 (5-7) |
| `gpt-4.1-mini` | stage2 | 2 | 0.000 (0.000-0.000) | 0.000 (0.000-0.000) | 0.000 (0.000-0.000) | NA | 0.0 (0-0) |
| `gpt-4.1-mini` | stage3 | 2 | 0.667 (0.556-0.778) | 0.500 (0.333-0.667) | 0.000 (0.000-0.000) | 0.583 (0.333-0.833) | 2.5 (1-4) |
| `gpt-5.4-mini` | stage1 | 2 | 0.500 (0.333-0.667) | 0.000 (0.000-0.000) | 0.250 (0.000-0.500) | 0.875 (0.750-1.000) | 1.5 (0-3) |
| `gpt-5.4-mini` | stage2 | 2 | 0.722 (0.667-0.778) | 0.833 (0.667-1.000) | 0.500 (0.500-0.500) | 0.757 (0.625-0.889) | 3.5 (1-6) |
| `gpt-5.4-mini` | stage3 | 2 | 0.556 (0.333-0.778) | 0.500 (0.333-0.667) | 0.250 (0.000-0.500) | 0.833 (0.667-1.000) | 1.5 (0-3) |
| `gpt-5.5` | stage1 | 3 | 1.000 (1.000-1.000) | 0.667 (0.000-1.000) | 0.667 (0.000-1.000) | 0.815 (0.750-0.944) | 2.7 (2-3) |
| `gpt-5.5` | stage2 | 3 | 0.963 (0.889-1.000) | 1.000 (1.000-1.000) | 1.000 (1.000-1.000) | 0.813 (0.688-1.000) | 2.7 (0-5) |
| `gpt-5.5` | stage3 | 3 | 1.000 (1.000-1.000) | 1.000 (1.000-1.000) | 1.000 (1.000-1.000) | 0.736 (0.600-0.857) | 3.7 (0-8) |

### Stage1: alert があるので場所は当たりやすいが、alert に引っ張られる

Stage1 は alert row が入力に入る。Discord 例では `Discovery - Query Registry` と `Persistence - Regmod Run or Runonce Key Modification` が見えるため、モデルは registry persistence に向かいやすい。

ただし、この手がかりは両刃である。

| モデル | Stage1 の動き | ばらつき |
|---|---|---|
| `gpt-4.1-mini` | alert 名から `reg.exe` / Discord / registry に向かう。action は高いが、`RunOnce` や `ctiuser.dll` を混ぜる。 | 2 回とも action は高めだが evidence は 0.000-0.333、precision は低い。毎回「それっぽいが雑」。 |
| `gpt-5.4-mini` | alert に頼りすぎず、少数 step に抑える。過剰は少ないが、証拠がほぼ取れていない。 | replicate_01 は 1 step だけで precision 1.0、replicate_02 は 3 step で action は上がるが overclaim 3。保守的すぎる/少し広げるで揺れる。 |
| `gpt-5.5` | action は 3 回とも 1.0。Run key 行動自体は拾う。 | evidence/order が 0.0 の回と 1.0 の回に分かれる。alert 依存で終わる回は証拠点が落ちる。 |

Stage1 のポイントは、「alert があると調査開始は楽になるが、alert 名が `Run or RunOnce` なので境界ミスを誘発する」こと。弱いモデルほど alert の語に引っ張られ、強いモデルでも alert を根拠にしすぎる回がある。

発表での言い方:

> Stage1 はアラート起点として現実的だが、アラート名が強い誘導になる。Discord 例では Run key の方向に探索が向く一方で、RunOnce や alert summary に引っ張られるため、再現率は上がっても evidence と precision が不安定になる。

### Stage2: alert なしなので、材料集めの実力差が一番出る

Stage2 は host/process/time のみで、alert 名は入力にない。したがって、ログから `reg.exe query/add` を自力で掘れるかが問われる。

| モデル | Stage2 の動き | ばらつき |
|---|---|---|
| `gpt-4.1-mini` | 2 回とも `code_steps` が空。探索の足場を作れない。 | 完全に安定して悪い。action/evidence/order は全部 0。 |
| `gpt-5.4-mini` | query/add の command line と `Run\Discord` regmod に届く。Discord 例ではこのモデルの最良 stage。 | evidence は 0.667-1.000。overclaim は 1-6 で、正常 Discord 子プロセスなどを混ぜる回がある。 |
| `gpt-5.5` | 3 回とも evidence/order は 1.0。query/add と親子関係をかなり安定して取る。 | action は 0.889-1.000、precision は 0.688-1.000。1 回は `nvidia-smi` など近傍別候補を混ぜる。 |

Stage2 のポイントは、モデル性能差が最も説明しやすいこと。

- `gpt-4.1-mini`: alert の補助がないと探索を開始できない。
- `gpt-5.4-mini`: command line と Run key に届くが、ID 接続と除外が揺れる。
- `gpt-5.5`: 必要証拠はほぼ安定して取れるが、近傍ログを混ぜる回がある。

発表での言い方:

> Stage2 では alert 名がないため、ログ探索能力の差が直接出る。弱いモデルは空出力になり、中間モデルは query/add まで到達し、強いモデルは PID・親子関係・source_stream まで取る。したがって、Stage2 の改善は「アラート名をなぞった」のではなく、「端末ログから行動列を復元する能力」が上がったことを示しやすい。

### Stage3: alert summary を隠しても強いモデルは取れるが、周辺ログを広げやすい

Stage3 は alert summary row を SQL tool から隠す。ただし CBC EDR/NGAV telemetry は残る。したがって、Stage3 で取れることは「alert 文面なしでも telemetry から復元できる」ことを意味する。

| モデル | Stage3 の動き | ばらつき |
|---|---|---|
| `gpt-4.1-mini` | `reg.exe` 実行や一部 Run 関連は拾うが、順序は 2 回とも 0。片方は `nvidia-smi` を混ぜる。 | action は 0.556-0.778、precision は 0.333-0.833。何を拾うかが不安定。 |
| `gpt-5.4-mini` | うまくいく回は query/add を絞って precision 1.0、overclaim 0。悪い回は action 0.333/order 0。 | 2 回で差が大きい。Stage3 は「良いときはきれい、悪いときは親子/対象が落ちる」。 |
| `gpt-5.5` | 3 回とも action/evidence/order は 1.0。alert summary なしでも core chain は安定。 | precision は 0.600-0.857、overclaim は 0-8。周辺ログをどれだけ残すかで大きく揺れる。 |

Stage3 のポイントは、強いモデルでは recall が安定する一方、precision のばらつきが残ること。

特に `gpt-5.5` は、3 回とも必要な chain は取れている。しかし、replicate_01 は overclaim 8、replicate_03 は overclaim 0 であり、最終統合の「捨てる判断」が安定していない。つまり、材料探索は安定しているが、出力境界は安定していない。

発表での言い方:

> Stage3 では、強いモデルなら alert summary なしでも Run key の query/add を復元できる。一方で、alert がない分、周辺 telemetry を広く見に行き、DLL access や process terminate まで出力に残す回がある。したがって、Stage3 の課題は「見つけられない」よりも「見つけたものを対象チェーンに入れるか補助証拠に回すか」の制御である。

### replicate ばらつきのまとめ

replicate 間のばらつきは、モデルごとに違う。

| モデル | ばらつきの型 | 解釈 |
|---|---|---|
| `gpt-4.1-mini` | stage2 は安定して空、stage1/3 は拾う対象が揺れる | 探索の足場が弱く、alert や近傍ログに依存する |
| `gpt-5.4-mini` | query/add に届く回と、親子/対象が落ちる回がある | 対象発見は改善したが、証拠接続が安定していない |
| `gpt-5.5` | recall は安定、precision/overclaim が揺れる | 探索能力は高いが、最終出力の境界制御が不安定 |

このばらつきを研究結果として言うなら、次がよい。

> モデル性能が上がるにつれて、ばらつきの出方が変わる。弱いモデルは、そもそも対象行動を見つけられるかが不安定で、条件によって空出力になる。中間モデルは、Run key の query/add までは届くが、PID・親子関係・source_stream の接続が揺れる。強いモデルは、対象行動の再現率は安定して高いが、周辺ログをどこまで出力に含めるかが揺れる。したがって、今後の課題は探索能力の改善だけでなく、複数回実行時にも安定して同じ境界で行動列を切り出すことである。

## gpt-4.1-mini の動き

### 何ができたか

`gpt-4.1-mini` は、`reg.exe`、`Discord`、Run key っぽいもの、Persistence alert っぽいものを拾うことはある。stage1 の replicate_01 では action recall が 0.889 まで出ており、表面的には多くの要素を拾っている。

ただし、これは「正しい行動列として復元できた」というより、「alert 周辺のそれっぽい registry/process 事象を広く拾った」結果に近い。

### どう過剰に出すか

代表的な stage1 出力では、次のような混入が起きている。

| 出力されたもの | 判定 | 理由 |
|---|---|---|
| `HKU\...\Software\Classes\Discord` の read | 対象違い | Discord protocol/class 登録系であり、Run key `CurrentVersion\Run\Discord` ではない |
| `HKCU\...\CurrentVersion\Run\Discord` の modify | 部分的に正しい | Run key 更新に近いが、証拠や command line が弱い |
| `HKCU\...\CurrentVersion\RunOnce\Discord` の modify | 過剰 | 正解は `Run` であり、`RunOnce` は含めない |
| `C:\Windows\System32\ctiuser.dll` の file access | 過剰 | `reg.exe` 周辺の DLL access であり、Run key 行動そのものではない |

stage3 では `discord.exe` 配下の `reg.exe` 実行は拾うが、Run key の query/add 対象を示せず、近傍の `nvidia-smi.exe` 実行を混ぜるケースがある。これは「同じ時間帯の別チェーン」を対象チェーンに入れてしまう典型例。

### どう過小に出すか

stage2 では `code_steps` が空になる run があり、正解 3 ステップをまったく復元できない。つまり `gpt-4.1-mini` は、広く拾って過剰になる場合と、何も出せず過小になる場合の両方がある。

### 発表での言い方

`gpt-4.1-mini` は、アラート名や周辺語に反応して候補を広げるが、Run key の query/add を非 alert 証拠付きの行動列として安定に復元するには不十分だった、と説明できる。

## gpt-5.4-mini の動き

### 何ができたか

`gpt-5.4-mini` は、Discord 例では一番「研究結果として説明しやすい」中間モデルである。`reg.exe query` と `reg.exe add` を Run key 永続化の論点として扱えるようになっており、`HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord` に寄せた出力が出る。

代表的な stage2 では、次のような正しい方向の復元ができている。

| 出力されたもの | 判定 | 理由 |
|---|---|---|
| `reg.exe query HKCU\...\CurrentVersion\Run /v Discord` | 正しい | Run key の `Discord` 値照会に対応 |
| `reg.exe add HKCU\...\CurrentVersion\Run /v Discord /d ...Update.exe --processStart Discord.exe` | 正しい | Run key 永続化設定の追加/更新に対応 |
| `HKU\S-1-5-21-...\CurrentVersion\Run\Discord` の regmod | ほぼ対応する証拠 | `HKCU` の実体 SID 表現として対応しうるが、重複 step として出すと過剰寄り |

stage3 replicate_01 では candidate step 数 2、precision 1.0 で、query/add をかなり絞って出せている。ただし、`discord.exe` -> `reg.exe` の親子関係 step が落ちるため action recall は 0.778 止まりになる。

### どう過剰に出すか

`gpt-5.4-mini` の過剰主張は、`gpt-4.1-mini` よりは減るが、まだ以下が出る。

| 過剰の型 | 具体例 | 何が問題か |
|---|---|---|
| regmod の重複 | `HKU\...\Run\Discord` を独立 step として出す | `reg.exe add` の証拠としてはよいが、別行動として立てると重複 |
| Discord 通常動作混入 | `discord.exe --squirrel-firstrun`、`crashpad-handler`、`renderer`、`gpu-process` | Run key query/add のチェーンではなく、周辺の通常起動 |
| Protocol 登録混入 | `HKCU\Software\Classes\Discord` | Discord 関連 registry ではあるが、今回の Run key ではない |
| 証拠不確定 | source_stream や event id が `未確定` | 行動の意味は合っていても、調査支援としては根拠が弱い |

### どう過小に出すか

過小出力としては、親子関係が落ちやすい。つまり、`reg.exe query/add` は出せるが、「それが `discord.exe` から起動された」という起点の説明が弱くなる。

この弱さはインシデント調査では重要である。Run key 書き込みそのものだけでなく、どのアプリが、どの流れで、なぜ `reg.exe` を起動したかが、偽陽性判断の根拠になるため。

### 発表での言い方

`gpt-5.4-mini` は、Run key という意味的な対象には寄せられるようになった。ただし、親子関係・順序・重複排除がまだ弱く、「何が起きたか」の骨格は作れるが、そのまま最終判断に使うには境界整理が必要、と説明できる。

## gpt-5.5 low raw の動き

### 何ができたか

`gpt-5.5` は、Discord 例では action recall が非常に高い。多くの run で、以下をまとめて回収できている。

- `discord.exe` PID `1204` が親になる
- `reg.exe` PID `5424` が `query HKCU\...\Run /v Discord` を実行する
- `reg.exe` PID `5504` が `add HKCU\...\Run /v Discord /d "...Update.exe --processStart Discord.exe" /f` を実行する
- `HKU\S-1-5-21-...\CurrentVersion\Run\Discord` への `ACTION_WRITE_VALUE` が `cbc-edr` / `cbc-ngav` に残る

つまり、「実際に何が起きたか」を掘り当てる能力は最も高い。

ただし、このモデルは raw-text salvage として採点されているため、structured JSON と同列に「出力形式が安定した」とは言いにくい。発表では、内容面の能力と出力形式の安定性は分けて説明した方がよい。

### どう過剰に出すか

`gpt-5.5` の過剰主張は、弱いモデルのような単純な取り違えではなく、「調査で見えた周辺証拠を丁寧に列挙しすぎる」形で出やすい。

stage3 replicate_01 では、action/evidence/order は 1.0 だが precision は 0.6、overclaim は 8 になっている。理由は、正解 3 ステップは全部拾えている一方で、次のような周辺ログも行動候補として広がるため。

| 出力・言及される周辺ログ | なぜ過剰になるか |
|---|---|
| `sechost.dll`、`imm32.dll`、`ctiuser.dll`、`api-ms-win-core-synch-l1-2-0.dll`、`fltLib.dll` | `reg.exe` 実行時の DLL access/module load であり、Run key query/add の行動ステップではない |
| `ACTION_PROCESS_TERMINATE` | プロセス終了の観測であり、Run key 永続化設定の中核行動ではない |
| Discord の通常子プロセス | Run key 操作の背景にはなるが、正解チェーンの step ではない |
| 15:03 台の `HKCU\Software\Classes\Discord` 登録 | Discord 関連の別 registry 操作であり、15:05 の Run key チェーンではない |

このタイプの過剰主張は、調査ログとしては有用な情報を含むことがある。しかし、評価上は「対象チェーンを復元する」という目的から外れるため、precision を下げる。

### どう過小に出すか

`gpt-5.5` は Discord 例では過小出力よりも過剰出力が目立つ。必要な行動はほぼ拾えているが、その周辺まで広げる。したがって、発表上は「再現率は高いが、対象チェーンと補助証拠の切り分けが課題」と言うのが合う。

### 発表での言い方

`gpt-5.5` は、正解チェーンの主要要素をかなり回収できる。一方で、初動調査支援としては、見つけた事実をすべて行動列に入れるのではなく、「対象チェーンの step」「補助証拠」「周辺事象」に分ける後段処理が必要、と説明できる。

## ステージ別の見え方

### Stage1: alert あり

Stage1 は CBC alert の起点情報があるため、`Discovery - Query Registry` や `Persistence - Regmod Run or Runonce Key Modification` に引っ張られやすい。

良い点は、registry persistence っぽい方向に探索が向きやすいこと。悪い点は、alert 名から `RunOnce` まで含めたり、alert summary を根拠として扱ったりすること。

Discord 例では、stage1 は「場所を当てる助けにはなるが、alert 名に引っ張られて過剰主張も出る」と言える。

### Stage2: process/time 起点

Stage2 は host/process/time だけから調べるため、alert 名の誘導は弱い。その分、ログから `reg.exe query/add` を見つけられるかが問われる。

Discord 例では、`gpt-5.4-mini` や `gpt-5.5` で stage2 がかなり良い。特に `gpt-5.5` replicate_01 stage2 は action/evidence/order/precision が 1.0、overclaim 0 のベストケースになっている。

ただし弱いモデルでは空出力になりやすい。`gpt-4.1-mini` の stage2 は `code_steps` が空になる run があり、探索力の差が出る。

### Stage3: alert summary を隠す

Stage3 は alert summary rows を見せず、非 alert telemetry から復元できるかを見る条件である。

この条件で復元できると、「alert 名をなぞっただけではなく、端末ログから実際の行動を復元した」と言いやすい。一方で、alert がない分、モデルが周辺ログを広く見に行き、DLL access や process terminate などを含めすぎることがある。

Discord 例では、`gpt-5.5` は stage3 でも正解チェーンを拾えるが、周辺証拠を広げすぎて overclaim が増えるケースがある。

## この例から見える研究結果の言い方

この Discord 例は、「再現率は良かったが、それ以外に課題が残る」という終わり方にしてよい。ただし、そのままだと弱いので、何が良くて何が残ったかを分けて言う。

良かった点。

- 正規・汎用ツールである `reg.exe` の利用について、単なるアラート名ではなく、`query` -> `add/write` という端末上の行動列として復元できるケースがある。
- 特に強いモデルでは、`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Discord` と `Update.exe --processStart Discord.exe` まで到達できる。
- Stage3 でも復元できるため、alert summary をなぞっただけではなく、非 alert telemetry に基づく復元可能性がある。

残った課題。

- 必要な step は拾えるが、近傍の本物ログを含めすぎる。
- `Run` と `RunOnce`、`CurrentVersion\Run` と `Software\Classes\Discord` のような registry 対象の境界が崩れることがある。
- `reg.exe` 周辺の DLL access/module load を、行動チェーンの step として出してしまうことがある。
- `discord.exe` の通常起動や子プロセスを、Run key 操作の一部として混ぜることがある。
- query/add は拾えても、`discord.exe` -> `reg.exe` の親子関係や順序が弱いことがある。

したがって、発表の締め方は次がよい。

> 本実験では、正規・汎用ツールに起因する EDR アラートについて、アラート名だけでなく、端末ログから「実際に何が起きたか」を行動列として復元できる可能性を確認した。Discord Run key の例では、強いモデルは `reg.exe` による Run key の query/add を高い再現率で回収できた。一方で、同じ時間帯・同じプロセス周辺に存在する別 registry 操作、DLL access、通常の Discord 子プロセスまで行動列に含める過剰主張が残った。したがって、今後の課題は、復元した事実を「対象チェーンの step」「補助証拠」「周辺事象」に分離し、偽陽性候補の判断根拠として使える粒度に整えることである。

## 「過剰主張」を聞かれたときの短い説明

短く言うならこう。

> 過剰主張は、存在しない攻撃を作るというより、近い時間・同じ親プロセス・同じアプリ周辺にある本物のログを、今回説明すべき行動チェーンに含めすぎる問題です。Discord の例では、正解は `reg.exe` による Run key の query/add ですが、モデルによっては `RunOnce`、`Software\Classes\Discord`、DLL access、`nvidia-smi`、Discord の通常子プロセスまで混ぜます。つまり、再現率は高くても、アナリストに提示するには対象行動と周辺事象の境界整理が必要です。

## 「研究として何が嬉しいのか」を聞かれたときの答え

この研究で嬉しいのは、「偽陽性を自動で白判定する」ことではない。そこまで言うと過剰主張になる。

言える範囲は次。

> EDR アラート後の初動調査で、正規・汎用ツールが本当に何をしたのかを、端末ログ上の行動列として提示できる。これにより、アナリストは alert 名だけでなく、`どのプロセスが`、`どのコマンドで`、`どの registry/file/network object に対して`、`どの順序で` 操作したかを確認できる。偽陽性候補の判断そのものを自動化するのではなく、その判断に必要な根拠整理を支援する。

Discord 例なら、こう言える。

> Discord の Run key アラートでは、単に「Persistence - Regmod Run or Runonce Key Modification」というアラートを見るだけでは、攻撃的な永続化なのか、Discord の通常インストール/初回起動に伴う自動起動登録なのか判断しにくい。本研究の復元結果は、`discord.exe` が `reg.exe` を起動し、`HKCU\...\Run\Discord` を query して、`Update.exe --processStart Discord.exe` を登録した、という判断材料を提示する。これが初動調査支援としての価値である。

## 発表で避けた方がよい言い方

避けた方がよい言い方は以下。

| 避ける表現 | 理由 | 代わりに言う表現 |
|---|---|---|
| 偽陽性を判定できる | ユーザー意図や業務正当性まではログだけでは確定できない | 偽陽性候補の判断根拠を整理する |
| 攻撃ではないと分かる | 正常/悪性の最終判定は過剰 | 端末ログ上では Discord の Run key 登録行動として説明できる |
| LLM でインシデント分析を自動化できた | 範囲が広すぎる | EDR アラート後の初動調査で、端末内行動列の復元を支援できる |
| 再現率が高いので有効 | precision/order/overclaim の課題を隠してしまう | 再現率は高いが、周辺事象を分離する課題が残る |
| 正常行動の復元をやっていないからやる | 動機が弱い | 正規・汎用ツール由来のアラートは偽陽性候補になりやすく、判断根拠の整理が必要 |

## まとめ

Discord Run key の例は、この研究の立ち位置を説明するのにかなり使える。

この例で示せることは、`reg.exe` という正規ツールによる Run key 操作を、アラート名ではなく端末ログの行動列として復元できること。一方で、モデルは周辺の本物ログを拾いすぎるため、復元結果をそのまま最終判断にするのではなく、対象チェーン、補助証拠、周辺事象に分ける必要がある。

したがって、研究結果の締めは次の形が一番自然。

> 強いモデルでは、正規・汎用ツールに起因する EDR アラートについて、端末ログから主要な行動列を高い再現率で復元できることが分かった。一方で、近傍ログや通常動作を対象チェーンに含める過剰主張、親子関係・順序の不安定さ、証拠の粒度には課題が残る。よって本研究の成果は、偽陽性の自動判定ではなく、アナリストが偽陽性候補を判断するための行動列と根拠を整理する支援として位置付ける。
