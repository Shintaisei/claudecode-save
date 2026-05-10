# ATLAS v2 実務寄りシーケンス実験

更新日: 2026-05-03

## 1. 目的

研究の本筋を「実務の分析自動化」に寄せるため、次の 3 点を見直した。

1. session の切り方を、分析者が追いやすい単位に寄せる
2. window の持ち方を変えて、正常文脈をどこまで残せるかを見る
3. benign day と attack day の丸ごと比較だけでなく、attack day 内の局所逸脱を見る

## 2. 実務寄りの前提

SOC や DFIR で追いやすい単位として、今回は次を重視した。

- `computer_user + 10分`
  同一ホスト上で同一ユーザの短時間行動を追う
- `computer_process + 10分`
  同一ホスト上で同一プロセス系統の短時間行動を追う

特に `computer_process` は、
プロセス起点で行動連鎖を見る実務の見方に近い。

## 3. 追加したもの

- `scripts/prepare_atlasv2_for_deeploglizer.py`
  - `session_mode=computer_process` を追加
- `scripts/run_atlasv2_local_ngram_baseline.py`
  - attack day 内だけで next-event の局所逸脱を見る軽量ベースライン

## 4. 実験設定

### 4.1 benign vs attack の丸ごと比較

- benign: `msft-security-h1-benign-1.jsonl`
- attack: `S3`
- benign 側は学習量を増やすため `200,000 events` を使用
- モデル: next-event n-gram

比較した条件:

1. `computer_user + 30分`、`window=3/5/10`
2. `computer_user + 10分`、`window=3/5`
3. `computer_process + 10分`、`window=3/5`

### 4.2 attack day 内の局所逸脱

- 対象: `attack_s3_*` と一部 `attack_s4_cu30`
- split: `session_train`
  - この split に異常 session が含まれるため
- モデル: attack day 内の windows だけで context を作る local n-gram

## 5. 結果

### 5.1 benign vs attack の丸ごと比較

| Setting | Flagged ratio | Precision proxy | Recall proxy |
| --- | ---: | ---: | ---: |
| `computer_user + 30分`, `w=3` | 98.609% | 0.378% | 100% |
| `computer_user + 30分`, `w=5` | 99.319% | 0.450% | 100% |
| `computer_user + 30分`, `w=10` | 99.773% | 0.576% | 100% |
| `computer_user + 10分`, `w=3` | 94.360% | 0.408% | 100% |
| `computer_user + 10分`, `w=5` | 96.259% | 0.480% | 100% |
| `computer_process + 10分`, `w=3` | 94.234% | 0.408% | 100% |
| `computer_process + 10分`, `w=5` | 96.016% | 0.457% | 100% |

読み取り:

- `window` を長くすると正常まで巻き込みやすくなる
- `30分` から `10分` に縮めると、過剰検知は少し下がる
- `computer_process` は `computer_user` より少しだけ正常を残しやすい
- ただし、丸ごと比較の時点ではまだ `94%` 台が限界で、実務の一次絞り込みとしては粗い

### 5.2 attack day 内の局所逸脱

| Setting | Flagged ratio | Precision proxy | Recall proxy |
| --- | ---: | ---: | ---: |
| `S3`, `computer_user + 30分`, `w=5`, `topk=3` | 3.493% | 1.588% | 12.400% |
| `S4`, `computer_user + 30分`, `w=5`, `topk=3` | 4.144% | 3.365% | 16.641% |
| `S3`, `computer_user + 10分`, `w=5`, `topk=3` | 3.428% | 1.683% | 12.489% |
| `S3`, `computer_process + 10分`, `w=5`, `topk=3` | 1.554% | 1.895% | 6.710% |
| `S3`, `computer_user + 10分`, `w=3`, `topk=5` | 1.696% | 1.375% | 6.051% |
| `S3`, `computer_process + 10分`, `w=3`, `topk=5` | 0.683% | 1.914% | 3.404% |

読み取り:

- attack day 内だけで見ると、`flagged_ratio` は一気に `0.7%` から `4%` 台まで下がる
- これは「正常を正常として残す」という意味では、丸ごと比較よりかなり実務向き
- その代わり recall は落ちる
- `computer_process + 10分` は特に絞り込みが強く、少数の浮いた window を出す設定になった

### 5.3 attack day 全体での局所逸脱比較

train/test に分けず、attack day の `session_train + session_test` をまとめて評価した。
この形のほうが実務の「その日のログ全体から候補を出す」に近い。

条件:

- `window_size=5`
- `topk=3`
- `min_context_count=3`

| Scenario | `computer_user + 10分` flagged ratio | `computer_user + 10分` recall | `computer_process + 10分` flagged ratio | `computer_process + 10分` recall |
| --- | ---: | ---: | ---: | ---: |
| S3 | 3.497% | 12.400% | 1.571% | 6.710% |
| S4 | 4.119% | 16.641% | 1.482% | 4.736% |
| M4 | 4.305% | 17.405% | 1.771% | 5.717% |
| M5 | 6.556% | 12.816% | 1.595% | 5.893% |
| M6 | 4.140% | 11.071% | 1.695% | 7.234% |

読み取り:

- `computer_user + 10分` は broad sweep に向く
  - 4% 前後、M5 でも 6.6% 程度に候補を抑えつつ、recall は 11% から 17% を確保
- `computer_process + 10分` は triage sweep に向く
  - 1.5% 前後まで候補を絞れる
  - その代わり recall は 4.7% から 7.2% に落ちる

これは実務的には、

1. まず `computer_user + 10分` で広めに候補を出す
2. 次に `computer_process + 10分` でプロセス単位へ絞る

という二段構えが自然だと読める。

### 5.4 `computer_process + 10分` で浮きやすかったプロセス例

S3 から M6 を見ると、`computer_process + 10分` では攻撃に近いプロセスが上位に出やすかった。

- S3
  - `powershell.exe`
  - `regsvr32.exe`
  - `payload.exe`
  - `cmd.exe`
- S4
  - `powershell.exe`
  - `winword.exe`
  - `payload.exe`
  - `mshta.exe`
  - `cmd.exe`
- M4
  - `winword.exe`
  - `payload.exe`
  - `python.exe`
  - `cmd.exe`
- M5
  - `powershell.exe`
  - `payload.exe`
  - `mshta.exe`
  - `cmd.exe`
- M6
  - `powershell.exe`
  - `payload.exe`
  - `python.exe`
  - `regsvr32.exe`
  - `cmd.exe`

少なくとも「何でも上位に来る」状態ではなく、攻撃チェーンで気になる実行主体に寄ってきている。
この点は、偽陽性候補の質を議論する前提としてかなり重要。

### 5.5 broad sweep の候補効率

`computer_user + 10分` の local baseline で、`flagged_windows` が多い上位 10 session を見ると、
anomalous windows の大半をかなり少ない候補で拾えていた。

| Scenario | top10 user sessions に含まれた flagged TP coverage |
| --- | ---: |
| S3 | 100.0% |
| S4 | 98.1% |
| M4 | 100.0% |
| M5 | 96.1% |
| M6 | 91.1% |

読み取り:

- broad sweep は候補数をかなり圧縮できる
- しかも attack day 全体の flagged TP の大半を top10 session で押さえられる
- 実務上は、まずここで host/day 内の注目時間帯を決めるのが有効

### 5.6 benign 由来ノイズ抑制つき process triage

benign day の `computer_process + 10分` local baseline を見ると、
慢性的に noisy なプロセスがかなりはっきり出た。

主な noisy process:

- `repmgr.exe`
- `svchost.exe`
- `firefox.exe`
- `-`

この 4 つを triage 候補から除き、残りを `flagged_windows` 順に並べた。

| Scenario | top10 filtered process sessions に含まれた flagged TP coverage |
| --- | ---: |
| S3 | 63.9% |
| S4 | 50.6% |
| M4 | 36.6% |
| M5 | 60.3% |
| M6 | 38.0% |

読み取り:

- `process` 側単体の global 指標は高くなかったが、
  benign 由来の noisy process を落として top10 候補に絞ると、
  4 シナリオでは 5割前後から 6割超まで anomalous windows をカバーできた
- `M4` は Office 系の大きな文脈に異常が薄く混ざるため弱い
- それでも `winword.exe`, `powershell.exe`, `regsvr32.exe`, `mshta.exe` など、
  実務で見たい主体が上位に残りやすくなった

### 5.7 `NewProcessName` 追加の試行

`prepare_atlasv2_for_deeploglizer.py` に `NewProcessName` を組み込み、
`event_actor` にも使うようにした。

効果:

- 全体の `flagged_ratio` や recall は大きくは改善しなかった
- ただし `payload.exe` が具体名で見えるようになり、
  `-` に埋もれていた一部イベントの解釈性は上がった

したがって、現時点では
「指標の大幅改善策」というより
「候補の読解性を上げる補助」
として有用だったと整理する。

### 5.8 上位候補 session の中身

今回いちばん見たかった点として、
「実際に分析者へ渡す上位候補 session は、どれだけ正常を含んでいるか」
を broad sweep と triage sweep の両方で測った。

#### broad sweep

対象:

- `computer_user + 10分`
- `flagged_windows` 順 top10 session

| Scenario | Top10 sessions の normal event ratio |
| --- | ---: |
| S3 | 99.861% |
| S4 | 99.787% |
| M4 | 99.792% |
| M5 | 99.898% |
| M6 | 99.853% |

#### triage sweep

対象:

- `computer_process + 10分`
- `repmgr.exe`, `svchost.exe`, `firefox.exe`, `-` を抑制
- `flagged_windows` 順 top10 session

| Scenario | Top10 sessions の normal event ratio |
| --- | ---: |
| S3 | 99.918% |
| S4 | 99.674% |
| M4 | 99.697% |
| M5 | 99.900% |
| M6 | 99.955% |

読み取り:

- broad sweep でも triage sweep でも、
  上位候補 session の中身はほぼ正常イベントで占められている
- つまり今の候補は、
  「異常だけを濃く抜き出した塊」ではなく
  **正常文脈を大量に含んだまま浮いている調査候補**
  になっている
- これは、今回の研究で狙っている
  「偽陽性候補の正常性」
  とかなり整合している

### 5.9 broad から triage への圧縮率

`computer_user + 10分` broad sweep の top10 session と、
`computer_process + 10分` triage sweep の top10 session を比較すると、
候補サイズは大きく削れている。

| Scenario | Event reduction | TP-window retention |
| --- | ---: | ---: |
| S3 | 91.9% 削減 | 32.9% 維持 |
| S4 | 84.9% 削減 | 14.0% 維持 |
| M4 | 91.7% 削減 | 11.4% 維持 |
| M5 | 89.5% 削減 | 28.1% 維持 |
| M6 | 90.0% 削減 | 26.5% 維持 |

読み取り:

- triage sweep は broad sweep に比べて、調査対象イベント数を約 85% から 92% 減らせる
- その代わり anomalous windows は一部捨てる
- ただし、残った候補は process 単位で解釈しやすく、
  実務では「最初の精査対象」として扱いやすい

### 5.10 代表候補

`computer_process + 10分` の filtered top candidates では、
次のような session が前に出た。

- S3
  - `powershell.exe`
  - `regsvr32.exe`
- S4
  - `powershell.exe`
  - `mshta.exe`
  - `winword.exe`
- M4
  - `winword.exe`
- M5
  - `powershell.exe`
  - `mshta.exe`
  - `winword.exe`
- M6
  - `powershell.exe`
  - `regsvr32.exe`

例:

- S3 `powershell.exe` session
  - normal event ratio: 約 `99.47%`
  - precision proxy: 約 `29.3%`
  - recall proxy: 約 `63.0%`
- S3 `regsvr32.exe` session
  - normal event ratio: 約 `98.90%`
  - precision proxy: 約 `27.9%`
  - recall proxy: 約 `53.1%`

ここから言えるのは、
**本当に見たい候補ほど「正常がほとんどだが、その中に異常が薄く混ざる」**
という構造になっていること。
この構造が見えたのは、今回のループでいちばん大きい成果。

### 5.11 top-k を増やしたときの見落とし曲線

`top10` 固定が妥当かを確認するため、
`top1 / top3 / top5 / top10 / top20 / top50` の coverage を見た。

#### broad sweep

`computer_user + 10分`, `flagged_windows` 順

- S3
  - `top1` で TP-window coverage `70.7%`
  - `top5` で `76.4%`
  - `top10` で `100%`
- S4
  - `top1` で `67.2%`
  - `top5` で `87.8%`
  - `top10` で `98.1%`
  - `top20` で `100%`
- M4
  - `top3` で `58.8%`
  - `top5` で `71.1%`
  - `top10` で `100%`
- M5
  - `top3` で `42.1%`
  - `top5` で `77.6%`
  - `top10` で `96.1%`
  - `top20` で `100%`
- M6
  - `top3` で `4.0%`
  - `top5` で `66.9%`
  - `top10` で `91.1%`
  - `top20` で `100%`

読み取り:

- broad sweep は `top10` 前後でかなり強い
- ただしシナリオ差があるため、見落としを嫌うなら `top20` まで見るほうが安全

#### triage sweep

`computer_process + 10分`, noisy process 抑制あり

- S3
  - `top1` で `46.0%`
  - `top5` で `73.0%`
  - `top20` で `95.2%`
  - `top50` で `100%`
- S4
  - `top1` で `31.2%`
  - `top3` で `57.1%`
  - `top20` で `93.5%`
  - `top50` で `100%`
- M4
  - `top3` で `54.2%`
  - `top20` で `93.8%`
  - `top50` で `100%`
- M5
  - `top1` で `38.7%`
  - `top10` で `66.1%`
  - `top50` で `96.8%`
- M6
  - `top1` で `54.5%`
  - `top10` で `54.5%`
  - `top20` で `89.1%`
  - `top50` で `100%`

読み取り:

- triage sweep は `top10` 固定だと見落としが大きい
- 実務では
  1. broad sweep で `top10` から `top20`
  2. triage sweep で `top20` を基本、必要に応じて `top50`
  くらいの運用が自然
- したがって、`top10` は説明用の切り方としてはよいが、運用上の固定値にはしないほうがよい

### 5.12 今回の正常データは何由来か

候補 session の正常部分がどんな行動由来かを要約した。
代表例として `S3` と `M5` の broad/triage を見る。

#### broad sweep の正常由来

ファイル:

- `analysis_data/atlasv2_for_deep-loglizer/attack_s3_cu10/candidate_behavior_top10.json`
- `analysis_data/atlasv2_for_deep-loglizer/attack_m5_cu10/candidate_behavior_top10.json`

特徴:

- ほぼ全て `Security` チャネル由来
- 主な Event ID は
  - `4656`
  - `4658`
  - `4663`
  - 一部 `5156`, `5158`, `4660`
- つまり土台は
  **オブジェクトアクセス / ファイル操作 / 接続監査**
  が中心

`S3 broad` の正常プロセス上位:

- `firefox.exe`
- `payload.exe`
- `tpautoconnect.exe`
- `repmgr.exe`
- `svchost.exe`
- `winword.exe`

`M5 broad` の正常プロセス上位:

- `repmgr.exe`
- `payload.exe`
- `svchost.exe`
- `firefox.exe`
- `tpautoconnect.exe`
- `explorer.exe`
- `wmiprvse.exe`
- `winword.exe`
- `upd.exe`

#### triage sweep の正常由来

ファイル:

- `analysis_data/atlasv2_for_deep-loglizer/attack_s3_cp10/candidate_behavior_top10.json`
- `analysis_data/atlasv2_for_deep-loglizer/attack_m5_cp10/candidate_behavior_top10.json`

特徴:

- こちらも中心は `Security` チャネル
- Event ID は broad と同じく `4656/4658/4663` が支配的
- ただし process 単位に絞るため、候補の正常文脈はより解釈しやすい

`S3 triage` の正常プロセス上位:

- `winword.exe`
- `mmc.exe`
- `werfault.exe`
- `powershell.exe`
- `regsvr32.exe`

`M5 triage` の正常プロセス上位:

- `explorer.exe`
- `winword.exe`
- `mmc.exe`
- `werfault.exe`
- `powershell.exe`
- `services.exe`
- `searchindexer.exe`
- `mshta.exe`

解釈:

- 今回の正常データは「一般的な benign day 全体」ではなく、
  **Security 監査上で観測されるファイルアクセス系の正常文脈**
  に強く寄っている
- その中に Office、ブラウザ、管理ツール、システムサービスの通常動作が乗っている
- 研究目的にはかなり合っている
  ただし「通常業務の全行動」を代表するというより
  **Windows Security ログ上の正常文脈**
  として使うのが正確

## 6. 実務目線での解釈

### 6.1 benign vs attack 丸ごと比較

この見方は、
「その day 全体が benign day と比べてどれだけ違うか」
を強く見てしまう。

そのため、attack に直接関係ない運用差分や文脈差分まで異常扱いしやすい。
実務でそのまま使うと、調査対象が広すぎる。

### 6.2 attack day 内の局所逸脱

こちらは、
「その day の中で相対的にどこが浮くか」
を見るので、分析者の見方に近い。

特に次のような運用に向く。

1. まず host/day 単位で怪しい日を決める
2. その中で `computer_process + 短時間` の局所逸脱を出す
3. 浮いた session / window だけを詳細調査に回す

これは「自動で異常判定を完結させる」より、
「人が見るべき候補を細く出す」設計に近い。

## 7. 現時点の結論

今回の比較では、研究の次の主軸はかなり明確になった。

1. session は `30分` より `10分` 前後の短時間がよい
2. 実務寄りには `computer_user` より `computer_process` が有望
3. 丸ごと benign 比較は補助にとどめ、主系は attack day 内の局所逸脱に置くのがよい
4. 偽陽性候補の質を上げるには、まず「全体差分」ではなく「局所的に浮いた正常寄り window」を取る必要がある
5. 実運用に近い形では、`computer_user + 10分` の broad sweep と、
   benign 由来 noisy process を落とした `computer_process + 10分` の triage sweep を組み合わせるのが最も筋がよい
6. 上位候補 session の中身は実際に 99.7% から 99.95% 程度が正常イベントであり、
   「正常を多く含む調査候補」を作る流れとして十分意味がある
7. `top10` は説明用には使えるが、見落とし観点では broad は `top20`、triage は `top20` から `top50` を見る運用のほうが安全
8. 今回の正常データは主に `Security` チャネルの `4656/4658/4663` を中心としたファイルアクセス監査由来で、研究用途には十分使える

## 8. 次の一手

1. `computer_user + 10分` の top user sessions を broad sweep として固定する
2. `computer_process + 10分` では benign 由来 noisy process を抑制した top process sessions を triage sweep として固定する
3. 上位候補について、正常イベント比率と前後イベント列を再計測する
4. process 起点の連鎖を足して、単発 window ではなく前後関係つき候補にする
5. PyTorch が動く環境で、同じ session 設定を `deep-loglizer` の LSTM / Transformer に持ち込んで比較する

## 9. 薄いシーケンスでの再実験

### 9.1 背景

`computer_process + 10分` でも 1 session あたりの event 数は平均 `1,600` から `2,000` 程度あり、
実務の first pass としてはまだ太い。

そこで、次の 2 段階でシーケンスを細くした。

1. `computer_process + 1分`
2. `computer_process + 1分 + max_events_per_session=100`

2 は、1 分バケット内で巨大 session が生じた場合に `100 event` ごとへ chunk する設定である。
このために [prepare_atlasv2_for_deeploglizer.py](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/scripts/prepare_atlasv2_for_deeploglizer.py:24) に `--max-events-per-session` を追加した。

### 9.2 `computer_process + 1分` のサイズ

`1分` に縮めると、全体平均はまだ数百 event だが、中央値はかなり小さくなる。

| Scenario | sessions_total | 平均 event / session | 中央値 |
| --- | ---: | ---: | ---: |
| S3 | 642 | 401.7 | 119 |
| S4 | 573 | 403.7 | 115 |
| M4 | 490 | 408.2 | 116 |
| M5 | 669 | 471.6 | 124 |
| M6 | 564 | 391.6 | 116 |

解釈:

- 「典型的な」session はほぼ `100 event` 前後まで薄くなる
- ただし一部の巨大 process session が残り、平均はまだ高い

### 9.3 `computer_process + 1分` の局所逸脱結果

同じ local n-gram 設定 `window_size=5`, `topk=3`, `min_context_count=3` で再実験した。

| Scenario | flagged ratio | precision proxy | recall proxy |
| --- | ---: | ---: | ---: |
| S3 | 1.542% | 1.706% | 6.339% |
| S4 | 1.463% | 2.752% | 5.091% |
| M4 | 1.754% | 2.077% | 6.015% |
| M5 | 1.582% | 1.397% | 6.101% |
| M6 | 1.688% | 1.928% | 6.654% |

これは `10分` 版と大きくは変わらず、全体の異常率は抑えられている一方で、
候補上位にはまだ大きい session が残る。

### 9.4 `computer_process + 1分 + 100 event chunk` のサイズ

`100 event` 上限を入れると、上位候補のサイズはかなり扱いやすくなる。

top10 filtered process candidates の平均 event 数:

| Scenario | top10 合計 events | 平均 event / candidate |
| --- | ---: | ---: |
| S3 | 824 | 82.4 |
| S4 | 840 | 84.0 |
| M4 | 803 | 80.3 |
| M5 | 892 | 89.2 |
| M6 | 969 | 96.9 |

つまり、分析者が見る 1 候補を `80` から `100 event` 程度に揃えること自体は可能だった。

### 9.5 `100 event` 近傍にしたときの coverage

一方で、薄くしすぎると攻撃文脈も細切れになり、候補 coverage が大きく落ちた。

filtered process candidates の TP-window coverage:

| Scenario | top10 | top20 | top50 | top100 | top200 |
| --- | ---: | ---: | ---: | ---: | ---: |
| S3 | 31.3% | 31.3% | 76.1% | 95.5% | 100.0% |
| S4 | 18.5% | 27.2% | 62.0% | 84.8% | 100.0% |
| M4 | 0.0% | 2.0% | 48.0% | 96.0% | 100.0% |
| M5 | 18.5% | 35.4% | 43.1% | 72.3% | 100.0% |
| M6 | 37.3% | 37.3% | 40.7% | 88.1% | 100.0% |

解釈:

- `100 event` 級まで細くすると、top10 では明確に薄すぎる
- `top50` でもシナリオによっては回収不足が残る
- `top100` から `top200` まで見て初めて、従来の triage coverage に近づく

### 9.6 実務目線での結論

この再実験から、次のことが言える。

1. `1シーケンス ≒ 100 event` は、可読性や人手確認のしやすさという意味ではかなり魅力的
2. ただし、その粒度を最初から triage 単位にすると、攻撃文脈が細切れになって見落としが増える
3. 実務で使うなら、
   - first pass はやや太めの `computer_process + 10分` または `computer_process + 1分`
   - second pass で `100 event` 級 chunk に再分割して詳しく見る
   の 2 段構えが自然

要するに、`100 event` 前後のシーケンスは **復元や読解の単位としては良い** が、
**初回の候補抽出単位としては細すぎる**。
今回の研究では、

- 候補抽出:
  `10分` または `1分` の process session
- 行動復元:
  上位候補を `100 event` 前後へ再分割

という役割分担のほうが実務と整合的である。
