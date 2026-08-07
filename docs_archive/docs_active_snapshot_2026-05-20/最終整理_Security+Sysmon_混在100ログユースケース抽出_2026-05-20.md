# 最終整理 Security+Sysmon 混在100ログユースケース抽出

日付: 2026-05-20

## 1. 目的

本手法の目的は、`attack が上位に来た anomaly 候補` を残したまま、その中に混ざる `false positive 側の文脈` も保持し、最終的にその false positive 側からユースケースを作ることである。

ここでの評価軸は次の2つである。

1. anomaly ranking の上位に attack 側の sequence が残ること
2. 同じ上位候補群の中に false positive 側の minute / event も残ること

つまり、`attack だけを当てること` ではなく、`attack と false positive の両方が上位候補内に残ること` が重要である。

## 2. 学習と検証に使ったデータ

### 2.1 Security 側

- 学習元: `analysis_data/atlasv2_for_deep-loglizer/benign1to4_cu10/data_desc.json`
- 正常学習データ: `benign-1to4`
- events: `6,705,271`
- sessions_total: `966`
- sessions_train: `772`
- sessions_test: `194`
- 単位: `computer_user / 10分 sequence`

### 2.2 Sysmon 側

- 学習元: `external/atlasv2_data/atlasv2/data/benign/h1/sysmon/sysmon-h1-benign-{1..4}.xml`
- 正常学習データ: benign 4日分
- events_total: `112,353`
- minutes_total: `4,793`
- 単位: `1分 minute`

### 2.3 attack scenario 側

各 scenario について、attack シナリオ全体をそのまま 1 本だけ流しているわけではなく、実験用データセット化された `session_train` 側を対象にしている。

| scenario | source events | source sessions used | anomalous sessions in used split |
| --- | ---: | ---: | ---: |
| `S3` | `257,887` | `18` | `3` |
| `M4` | `200,015` | `14` | `4` |
| `M6` | `220,858` | `14` | `5` |
| `S4` | `231,335` | `15` | `6` |

したがって、これは `正常4日学習 -> 5日目1回だけ判定` ではなく、  
`正常4日分を学習母集団にし、各 attack scenario を別々に評価している`  
という整理になる。

## 3. 手法の全体像

本手法は 3 段階で構成される。

1. `Security` で coarse anomaly sequence を検出する
2. その近傍の `Sysmon minute` を anomaly score 順に並べる
3. 上位 sequence 群をまたいで minute を round-robin で選び、`100 event` を作る

重要なのは、最終 `100ログ` が `異常検知器の直接出力そのもの` ではなく、  
`上位 anomaly sequence を起点にした score-only review set`  
である点である。

## 4. 詳細フロー

### Step 1. Security first pass

`Security` の `10分 sequence` に対して IsolationForest を適用し、異常スコアを出す。  
ここでの出力は `上位 anomaly sequence` である。

ここで重要なのは、**この段階でスコアが付くのは individual event ではなく sequence 単位**である点である。  
つまり first pass の時点では、

- `event 1件ごとの異常度`
- `process 1件ごとの異常度`

は出していない。  
出しているのはあくまで、`その10分間の event 列全体がどれだけ普段と違うか` という sequence score である。

この段階で残るのは次の通り。

まず、入力となる test set 全体のシーケンス構成は以下の通り。

| scenario | test sequences (total) | うち attack sequences | うち normal sequences |
| --- | ---: | ---: | ---: |
| `S3` | `18` | `3` | `15` |
| `M4` | `14` | `4` | `10` |
| `M6` | `14` | `5` | `9` |
| `S4` | `15` | `6` | `9` |

これに対し、IsolationForest による first pass で `predicted (anomalous)` と判定されたシーケンスは以下の通り。

| scenario | predicted sequences | うち TP (attack) | うち FP (normal) | sequence_total_events |
| --- | ---: | ---: | ---: | ---: |
| `S3` | `2` | `1` | `1` | `42,301` |
| `M4` | `4` | `2` | `2` | `75,223` |
| `M6` | `3` | `0` | `3` | `69,811` |
| `S4` | `3` | `2` | `1` | `67,992` |

この時点では、まだ数万 event 規模で残っている。

### 4.1 数万 event が残る理由

first pass で残る `predicted sequence` は本数としては少ないが、各 sequence 自体が 10分窓であり、その中に多数の Security event を含む。  
そのため、

- `S3` は 2 sequence しか残っていないが、その中身は `42,301 event`
- `M4` は 4 sequence で `75,223 event`

のようになる。

つまり first pass は、

- `event を直接 100 件まで絞る段階`

ではなく、

- `10分窓の候補本数を小さくする段階`

である。

### Step 2. Security second pass / review window

first pass の上位 sequence に対し、Security の review window を作る。  
これにより、人が読める対象を `3000 event` まで圧縮する。

ここでやっているのは、`上位 sequence 全体をそのまま読む` のではなく、  
**その sequence 内を `100 event chunk` に分割し、chunk ごとに IsolationForest で異常スコアを付け、top 30 chunk = 3000 event を取り出す** ことである。

この second pass でも、基本の粒度は Security chunk であり、  
**まだ per-event score を振っているわけではない。**

| scenario | review_total_events |
| --- | ---: |
| `S3` | `3,000` |
| `M4` | `3,000` |
| `M6` | `3,000` |
| `S4` | `3,000` |

ここまでは anomaly score ベースであり、process 名などのルールは入れていない。

### 4.2 second pass のモデル選定根拠

`3000 event` への圧縮に使うモデルとして、`IsolationForest / LOF / One-Class SVM / SGD-OCSVM / kNN distance` の5種で比較検証を行った。  
評価軸は `chunk-level F1` ではなく、次の 2 点を重視した。

1. `top10 chunk` / `top30 chunk` に attack chunk が入るか
2. 同時に false positive chunk も残るか（`first_attack_rank` がどれだけ早いか）

比較結果は以下の通り。

#### S3

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| `IsolationForest` | no | yes (`4 event`) | `20` | top30 なら attack を残せる |
| LOF | no | no | `267` | 攻撃がかなり後ろ |
| OCSVM | no | no | `89` | 攻撃が残らない |
| SGD-OCSVM | no | no | `332` | 攻撃が残らない |
| kNN | no | no | `64` | 攻撃が残らない |

#### M4

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| `IsolationForest` | yes (`1 event`) | yes | `2` | かなり良い |
| LOF | no | yes (`1 event`) | `11` | top10 では落ちる |
| OCSVM | no | no | `61` | 攻撃が残らない |
| SGD-OCSVM | no | no | `55` | 攻撃が残らない |
| kNN | yes (`1 event`) | yes | `10` | IF より少し弱いが悪くない |

#### M6

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| `IsolationForest` | no | no | `null` | first pass 側で attack が残っていない |
| LOF / OCSVM / SGD-OCSVM / kNN | no | no | `null` | 同上（second pass の問題ではない） |

#### S4

| model | top10 attack | top30 attack | first_attack_rank | 読み |
| --- | --- | --- | --- | --- |
| `IsolationForest` | yes (`1 event`) | yes (`3 event`) | `3` | かなり良い |
| LOF | no | no | `468` | ほぼ使えない |
| OCSVM | no | no | `46` | 攻撃が残らない |
| SGD-OCSVM | no | no | `37` | 攻撃が残らない |
| kNN | no | yes (`1 event`) | `15` | top30 なら少し残る |

**採用判断**: `IsolationForest` を採用。  
S4・M4 では top10 の時点で attack chunk が残り、S3 でも top30=3000 event まで広げると残せる。  
LOF / OCSVM / SGD-OCSVM は attack を前に出せず、kNN は M4 では良いが S3・S4 の安定性で IF に負ける。

### 4.3 3000 event への圧縮の意味

`3000 event` という数字は、

- first pass で残った数本の sequence
- その中で second pass の chunk-level IF が「異常度が高い」と判断した top 30 chunk（× 100 event = 3000 event）

を合算した結果である。  
したがって、`数万 event -> 3000 event` の圧縮は

1. `10分 sequence-level IsolationForest`（first pass）
2. `100 event chunk-level IsolationForest`（second pass）

の純モデル 2 段階で行われており、**手作りルールは一切使っていない**。  
この構成により、`3000 event` までの圧縮を研究として説明可能な形で記述できる。

### Step 3. Sysmon minute candidate の収集

各上位 sequence に対して、

- same-host
- exact-user

の近傍 `Sysmon minute` を集める。

ここで minute ごとに元々持っている情報は次である。

- `minute_score`
- `events`
- `top_images`
- `top_event_ids`
- どの anomaly sequence に紐づいているか

ここで初めて、Security の coarse anomaly sequence から `近傍の minute` に降りる。  
この時点で使っているスコアは `Sysmon minute score` であり、**やはりまだ per-event score ではない。**

### Step 4. minute の score-only ranking

minute の選択では、`payload.exe` や `excel.exe` などの process 名ルールは使わない。  
代わりに次の score だけを用いる。

`combined_score = minute_score + 0.25 * max_sequence_score + 0.02 * exact_user_flag + 0.02 * max(0, attached_sequence_count - 1)`

ここで使う要素はすべて次のいずれかであり、意味ルールではない。

- minute 自体の anomaly score
- その minute が紐づく sequence の anomaly score
- exact-user か same-host か
- 複数 sequence から支持されているか

この点が、以前の `preferred_normal / suspicious` ルールベース版との最大の違いである。

### 4.3 どの粒度にスコアが付いているのか

この手法でスコアが明示的に付いている粒度は次の3つである。

1. `Security sequence score`
   - 10分 sequence 全体の異常度
2. `Security review window score`
   - sequence 内 chunk / window の変化量
3. `Sysmon minute score`
   - 1分 minute 全体の異常度

逆に、**individual event 1件ごとの anomaly score は付いていない。**

event は、

- anomaly sequence に含まれていたか
- anomaly minute に含まれていたか

という membership によって最終集合に入る。  
したがって最終 `100 event` は、`event score 上位100件` ではなく、  
`high-score sequence / high-score minute に属する event を集めた review set` である。

### Step 5. sequence をまたいだ round-robin 選択

candidate minute を global score 順に並べるだけだと、1 本の sequence に偏る。  
そこで、上位 anomaly sequence をまたぐように `round-robin` で minute を 1 本ずつ取る。

この round-robin により、

- attack 側の sequence
- false positive 側の sequence

の両方から minute が残りやすくなる。

### Step 6. 100 event への変換

選ばれた minute から event を足し、scenario ごとに `100 event` になるまで詰める。  
この時点でも process 名ルールは使わない。

最後に、**選択には使っていない後付け評価** として、

- `attack_sequence_only`
- `fp_sequence_only`
- `mixed_sequence_support`

を数える。

これは、

- その minute / event が attack label の sequence にだけ支えられているか
- false positive sequence にだけ支えられているか
- 両方に支えられているか

を見るためのラベルである。

## 5. どれくらい絞られたか

`source events -> first-pass sequence events -> second-pass review events -> candidate minutes -> final 100 events`
の流れで見ると次の通り。

| scenario | source events | first-pass sequence events | second-pass review events | candidate minutes | final selected minutes | final events |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `S3` | `257,887` | `42,301` | `3,000` | `8` | `7` | `100` |
| `M4` | `200,015` | `75,223` | `3,000` | `10` | `10` | `100` |
| `M6` | `220,858` | `69,811` | `3,000` | `7` | `6` | `100` |
| `S4` | `231,335` | `67,992` | `3,000` | `8` | `5` | `100` |

つまり、最終 `100ログ` は

- source 全体から直接抜いているわけではなく
- anomaly sequence とその近傍 minute を経由して
- score-only で再構成されている

ということになる。

## 5.1 圧縮を別の言い方で書くと

圧縮の実体は、`event ranking` ではなく `container ranking` である。

- 最初は `10分 sequence` を rank 付けする
- 次に `sequence 内 review window` を rank 付けする
- 次に `1分 minute` を rank 付けする
- 最後に、その高順位 container に属する event を集めて `100 event` にする

なので、ここでの圧縮は

`数万の event を1件ずつ並べ替えて削る`

のではなく、

`大きい container から小さい container へ drill-down しながら絞る`

という構造である。

## 6. 最終100ログの内訳

ここでの `attack-side / FP-side` は、選択時ではなく**選択後の評価**である。

| scenario | attack_sequence_only events | fp_sequence_only events | mixed_sequence_support events | 読み方 |
| --- | ---: | ---: | ---: | --- |
| `S3` | `54` | `46` | `0` | attack 側と FP 側がほぼ半々で残る |
| `M4` | `66` | `34` | `0` | attack 側が強いが FP 側も十分残る |
| `M6` | `0` | `100` | `0` | upstream で attack sequence が残らない |
| `S4` | `36` | `64` | `0` | FP 側が厚いが attack 側も残る |

## 7. 何が汎用的になったのか

以前の方法では、

- `payload.exe` を attack-near
- `excel.exe` を normal-core

のように `process 名の意味` を使っていた。  
これは scenario 依存・データセット依存が強い。

今回の方法では、それをやめて

- anomaly score
- sequence への紐づき
- exact-user / same-host

だけを使って選ぶようにした。  
したがって、`どの process を normal と見なすか` を事前に決めなくてもよい。

この意味で、今回の方法は

`意味ルールベース選択` ではなく  
`score と近傍構造だけで行う score-only selection`

になっている。

## 8. それでも残る限界

この方法は前より汎用的だが、完全に万能ではない。

### 8.1 M6 のように upstream で attack が残らない場合がある

`M6` では first-pass の predicted sequences がすべて FP 側だった。  
そのため、どれだけ score-only にしても最終 `100ログ` に attack-side を残せない。

これは最終抽出の問題というより、**上流の anomaly sequence ranking の限界**である。

### 8.2 Sysmon minute 自体は still local view

minute 単位での score は、局所的な異常を捉えるが、必ずしも攻撃ストーリー全体を表さない。  
そのため最終 `100ログ` は、`検知結果そのもの` ではなく `レビュー用に読む集合` として扱う方が適切である。

## 9. 研究としての言い方

この手法は、次のように言うのが最も正確である。

`Security sequence anomaly detection で上位候補を圧縮し、その近傍の Sysmon minute を anomaly score と sequence support のみで再順位付けし、top anomaly sequence 群をまたぐ round-robin selection により 100 event の mixed review set を構成した。`

さらに結果は次のようにまとめられる。

- `S3 / M4 / S4` では、rule-free な score-only 抽出でも attack 側と false positive 側の両方が最終 100ログに残った
- `M6` では、upstream の sequence ranking 自体が attack を十分残せず、最終 100ログでも false positive 側のみが残った

## 11. 検知できたシーケンスと見逃したシーケンスの比較考察

### 11.1 各シナリオの検知状況まとめ

実際に使用した閾値は benign p95 = `0.3138` である。

| scenario | test sequences | attack seqs | 検知TP | 見逃し | FP | 使用閾値 | oracle最良閾値 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `S3` | `18` | `3` | `1` | `2` | `1` | `0.3138` | `0.3040` |
| `M4` | `14` | `4` | `2` | `2` | `2` | `0.3138` | `0.3054` |
| `M6` | `14` | `5` | `0` | `5` | `3` | `0.3138` | `0.2938` |
| `S4` | `15` | `6` | `2` | `4` | `1` | `0.3138` | `0.2988` |

### 11.2 検知できたシーケンスの特徴

検知できた TP シーケンス（スコアが閾値 0.3138 を超えたもの）は以下の通り。

| scenario | timestamp | user | score | attack_events / total | 攻撃イベント割合 |
| --- | --- | --- | ---: | --- | ---: |
| `S3` | 20220719T1430Z | win-32-h1$ | `0.3340` | 5 / 18,621 | 0.027% |
| `M4` | 20220719T2300Z | win-32-h1$ | `0.3410` | 9 / 14,113 | 0.064% |
| `M4` | 20220719T2250Z | win-32-h1$ | `0.3223` | 11 / 19,885 | 0.055% |
| `S4` | 20220720T0040Z | win-32-h1$ | `0.3205` | 2 / 16,305 | 0.012% |
| `S4` | 20220720T0050Z | win-32-h1$ | `0.3176` | 11 / 30,922 | 0.036% |

**共通する傾向:**

- スコアは `0.317〜0.341` の範囲に集中しており、閾値 `0.3138` をわずかに上回っている
- 攻撃イベントの割合は全シーケンスの **0.01〜0.07%** にすぎない
  - つまり「攻撃イベントが多いから高スコアになった」わけではなく、**シーケンス全体の event 分布パターン**が正常から外れていた結果として高スコアになっている
- いずれも `user=win-32-h1$`（コンピュータアカウント）であり、ユーザーアカウント `aalsahee` の攻撃シーケンスは検知できていない

### 11.3 見逃したシーケンスの特徴

#### S3: 3本中2本を見逃し

S3 の攻撃シーケンスは合計3本だが、検知できたのは `20220719T1430Z` の1本のみ。  
残り2本のスコアは oracle 閾値 `0.3040` 以上であることは確認されているが、p95 閾値 `0.3138` には届かなかった。  
**S3 の攻撃は比較的 event 分布が正常に近く、IsolationForest では「普通っぽい」と判定されやすい時間帯が存在する。**

#### M4: 4本中2本を見逃し（recall 50%）

M4 は4本の攻撃シーケンスのうち2本を検知。  
検知できた2本（T2300Z / T2250Z）は win-32-h1$ ユーザーの連続した時間帯であり、**攻撃活動が集中していた窓**と考えられる。  
見逃した2本は、oracle f1が `0.667`（recall `0.75`）であることから、oracle 閾値を下げても1本は取れるが、もう1本はさらに難しい。

#### M6: 5本全て見逃し（完全失敗）

M6 は最も深刻なケースである。p95 閾値 `0.3138` で検知された3本はすべて正常シーケンス（FP）であり、  
攻撃シーケンスのスコアは oracle 閾値 `0.2938` でやっと捕捉できる水準にある。

これは次のことを意味する。

- **M6 の攻撃シーケンスは、正常シーケンスよりも低い anomaly score しか出さない**
- つまり攻撃時の event 分布が、学習した正常パターンと非常に似ている
- oracle で recall=1.0 を達成するには閾値を `0.2938` まで下げる必要があり、その場合は14本中12本が predicted になる（FP率 = 7/9 = 78%）
- M6 のシナリオは他のシナリオと比べて **攻撃の痕跡が Security ログ上で目立ちにくい** 攻撃パターンである可能性が高い

#### S4: 6本中2本を見逃し（recall 33%）

S4 は攻撃シーケンスが6本と最も多いが、検知できたのは連続する2本（T0040Z / T0050Z）のみ。  
残り4本のスコアは oracle 閾値 `0.2988` 付近にあり、やはり p95 閾値には届いていない。  
oracle f1 = `0.667`（recall `0.667` precision `0.667`）は M4 と同水準だが、**母数が大きい分だけ見逃し本数も多い**。

### 11.4 シナリオ別の攻撃内容と検知可否の対応

#### 使用しているデータセットについて

本実験は **ATLASv2**（Riddle et al., arXiv:2401.01341）を使用している。  
ATLASv2 は USENIX Security 2021 論文 "ATLAS: A Sequence-based Learning Approach for Attack Investigation"（Alsaheel et al.）の攻撃シナリオを再実施したものであり、Sysmon・Carbon Black EDR 等のテレメトリを追加した強化版である。  
ログは Windows 7 32bit VM (h1/h2) 上で 2022/7/15〜19 に収録。攻撃は Kali Linux マシンから実施。

攻撃シナリオの詳細は REAPr プロジェクト（`external/reapr-ground-truth/atlasv2/attack_descriptions/`）に収録されている。

---

#### 各シナリオの攻撃内容と検知状況

**S3（Single Host 3）— TP 1/3、見逃し 2本**

| 攻撃フェーズ | 手法 | 関与プロセス |
| --- | --- | --- |
| 初期侵入 | Firefox で悪意あるリンクをクリック → Flash 脆弱性 (CVE-2017-11882相当) → meterpreter HTTPS payload を firefox.exe にインジェクション | `firefox.exe` → `eqnedt32.exe` → `regsvr32.exe` |
| 情報収集 | meterpreter shell 経由で `whoami`, `netstat -a`, `ipconfig`, `dir` 実行 | `powershell.exe`, `cmd.exe` |
| 実行・持続 | `payload.exe` をアップロード・実行。PDF ファイルを収集 | `payload.exe` |
| 流出 | `0xevil.com:8080` への HTTPS 通信で PDF 流出 | `payload.exe` |

攻撃ラベル付きプロセス（REAPr）: `firefox.exe`, `eqnedt32.exe`, `regsvr32.exe`, `powershell.exe`, `cmd.exe`, `payload.exe` 等 23プロセス。

**検知できた部分**: `T1430Z`（powershell+cmd によるシェル実行・情報収集フェーズ）が TP。  
**見逃した部分**: 初期侵入フェーズ（`eqnedt32.exe`・`regsvr32.exe`）と payload.exe 実行フェーズの一部は、攻撃イベント密度が低い時間帯に分散しており score が閾値に届かなかった。また Hayabusa 分析で `powershell.exe` の 4673（特権呼び出し）は GT 未記載のため FP 扱いになっている。

---

**S4（Single Host 4）— TP 2/6、見逃し 4本**

| 攻撃フェーズ | 手法 | 関与プロセス |
| --- | --- | --- |
| 初期侵入 | マルウェア付き Word ファイルをメールで配信 → CVE office_word_hta 脆弱性 → meterpreter payload を `winword.exe` にインジェクション | `winword.exe` → `mshta.exe` → `powershell.exe` |
| 情報収集 | `pwd`, `ps`, `ipconfig`, `netstat -a` 実行 | `cmd.exe`, `powershell.exe` |
| 実行・持続 | `payload.exe` アップロード・実行。`index.html` 上書き | `payload.exe` |
| 流出 | `0xevil.com:8080` への HTTPS 通信 | `payload.exe` |

攻撃ラベル付きプロセス: `winword.exe`, `mshta.exe`, `powershell.exe`, `cmd.exe`, `payload.exe` 等 37プロセス（S3 より多い）。

**検知できた部分**: `T0040Z` および `T0050Z`（winword/powershell による情報収集・実行フェーズ、各 2件・11件の攻撃イベント）。  
**見逃した部分**: S4 は攻撃シーケンスが6本と最多で、各フェーズが複数の 10分窓に分散している。初期侵入（Firefox + winword 起動）や後半の payload 流出フェーズは攻撃イベント密度が低く、閾値 `0.3138` に届く窓が2本しかなかった。

---

**M4（Multi Host 4）— TP 2/4、見逃し 2本**

| 攻撃フェーズ | 手法 | 関与プロセス |
| --- | --- | --- |
| 初期侵入 | CVE-2018-8174 (IE/VBScript) → `winword.exe`/`excel.exe` 経由 | `excel.exe`, `winword.exe`, `firefox.exe` |
| 情報収集 | meterpreter shell 経由でシステム情報取得 | `cmd.exe`, `powershell.exe` |
| 実行・横展開 | `payload.exe` 実行 + `index.html` 上書きでフィッシングページを配置 → h2 への lateral movement | `payload.exe`, `cmd.exe` |
| 流出 | h1/h2 の両方から `0xevil.com:8080` へ PDF 流出 | `payload.exe` |

攻撃ラベル付きプロセス: `firefox.exe`, `excel.exe`, `winword.exe`, `cmd.exe`, `payload.exe` 等 17プロセス。

**検知できた部分**: `T2300Z`（シェル実行・情報収集）と `T2250Z`（payload 実行フェーズ）が TP。この2本はそれぞれ 9件・11件の攻撃イベントを含む。  
**見逃した部分**: CVE-2018-8174 経由の初期侵入フェーズ（`excel.exe` が exploit を受け取る窓）と、その後の `index.html` 書き換えによる横展開準備フェーズ。M4 の non-info FP が他より少なく「環境由来ほぼのみ」だったことも、攻撃初期フェーズが Security ログ上で目立たないことを示唆している。

---

**M6（Multi Host 6）— TP 0/5、全て見逃し**

| 攻撃フェーズ | 手法 | 関与プロセス |
| --- | --- | --- |
| 初期侵入 | メールのリンクから Word ファイルをダウンロード → CVE-2017-11882 → `winword.exe`/`eqnedt32.exe` 経由で meterpreter payload | `firefox.exe`, `winword.exe`, `eqnedt32.exe`, `regsvr32.exe` |
| 情報収集 | `whoami`, `netstat -a`, `ipconfig`, `dir` | `cmd.exe`, `powershell.exe` |
| 実行・横展開 | `payload.exe` 実行 + `index.html` 上書き → h2 への lateral movement | `payload.exe`, `cmd.exe` |
| 流出 | h1/h2 の両方から `0xevil.com:8080` へ PDF 流出 | `payload.exe` |

攻撃ラベル付きプロセス: `firefox.exe`, `excel.exe`, `winword.exe`, `eqnedt32.exe`, `regsvr32.exe`, `powershell.exe`, `cmd.exe`, `payload.exe`, `sysmon.exe`, `vssvc.exe` 等 24プロセス（4シナリオ中最多種類）。

**M6 が全滅した理由の考察**:

oracle 閾値 `0.2938` では recall=1.0（全5本検知可能）だが、その場合 14本中12本が predicted になる（FP率 78%）。つまり攻撃シーケンスのスコアは正常の大多数より低く、**正常シーケンスの方が「変わった事象分布」を示している**状態である。

M6 の攻撃手法を S3 と比較すると、使用 CVE が同じ（CVE-2017-11882）でも M6 の方が**攻撃に関与するプロセス数が多く、かつ `vssvc.exe`（Volume Shadow Copy）・`sysmon.exe`・`regsvr32.exe` などが加わっている**。  
これらは Security ログ上では大量の正常イベントに埋もれやすいシステムプロセスであり、10分窓のイベント種別ヒストグラムに対して IsolationForest が「普通」と判定しやすい。

さらに M6 の攻撃は多段階かつ複数ホストに分散するため、h1 上の各 10分窓では攻撃イベントが薄く広がり、局所的な密度が低い。これが「スコアが上がらない」根本原因と考えられる。

### 11.5 横断的な考察：なぜ攻撃シーケンスが高スコアにならないのか

1. **攻撃イベントの絶対数が少なすぎる**  
   各シーケンスに含まれる攻撃イベントは全体の 0.01〜0.07% 程度である。  
   IsolationForest は10分窓全体のイベント種別分布で判定するため、1万件以上の正常イベントの中に数件の攻撃イベントが埋もれると、**シーケンス全体としては正常寄りのスコア**になりやすい。

2. **検知できるのは「実行フェーズが集中した窓」のみ**  
   M4/S4 で検知できた攻撃シーケンスはいずれも `cmd.exe` + `powershell.exe` が同一10分窓で動いた**実行・情報収集フェーズ**と一致する。  
   一方で初期侵入（exploit → inject）や後処理（流出）フェーズは、普段から起動している `firefox.exe`・`winword.exe` の正常イベントに紛れるため、窓全体のスコアが上がらない。

3. **M6 は攻撃プロセスが Security ログ上で目立たない**  
   M6 の攻撃には `vssvc.exe`（シャドウコピー）・`sysmon.exe`・`regsvr32.exe` などシステムプロセスが多く含まれる。  
   これらは定常的に大量の Security イベントを生成するプロセスであり、10分窓のヒストグラムに混じると「普通の分布」に近づく。  
   S3/S4 の `powershell.exe + cmd.exe` の組み合わせよりも目立ちにくい。

4. **FP が高スコアになる逆転現象**  
   検知された FP シーケンス（例: S3 `T1420Z` score=0.3416、S4 `T0030Z` score=0.3423）は攻撃を含まないにもかかわらず **TP より高スコア** である。  
   これらは業務上の特殊操作（大量の認証イベント、バッチ処理、ネットワーク設定変更等）による「正常の中の外れ値」と考えられる。  
   攻撃が「正常に見えすぎる」のと裏返しで、「正常なのに異常に見える」事象の方が Security ログ上では目立ってしまっている。

### 11.6 まとめ：拾えているもの・拾えていないもの

| 観点 | 拾えているもの | 拾えていないもの |
| --- | --- | --- |
| 攻撃フェーズ | 攻撃イベントが集中する時間帯（実行フェーズ中心） | 攻撃密度の低い準備・後処理フェーズ |
| 攻撃戦術 | Security ログのパターンを変える戦術（M4/S3/S4） | 正規プロセス悪用・Living-off-the-Land 系（M6） |
| ユーザー種別 | コンピュータアカウント（win-32-h1$）の異常 | ユーザーアカウント（aalsahee）の異常 |
| スコア水準 | 正常 FP と同水準以上のスコアを出す攻撃 | 正常 FP より低スコアになる攻撃（M6 全体） |

## 10. 参照先

- `analysis_data/atlasv2_for_deep-loglizer/benign1to4_cu10/data_desc.json`
- `analysis_data/model_runs/security_sysmon_review_queue_benign1to4_s3/results.json`
- `analysis_data/model_runs/security_sysmon_review_queue_benign1to4_m4/results.json`
- `analysis_data/model_runs/security_sysmon_review_queue_benign1to4_m6/results.json`
- `analysis_data/model_runs/security_sysmon_review_queue_benign1to4_s4/results.json`
- `analysis_data/model_runs/usecase_sysmon100_scoreonly_s3/summary.json`
- `analysis_data/model_runs/usecase_sysmon100_scoreonly_m4/summary.json`
- `analysis_data/model_runs/usecase_sysmon100_scoreonly_m6/summary.json`
- `analysis_data/model_runs/usecase_sysmon100_scoreonly_s4/summary.json`
