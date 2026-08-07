# ATLASv2 S3/S4：CBCアラート起点・攻撃復元24ユースケース仕様

作成日: 2026-07-23  
状態: **実行準備完了。Gold・実行用JSONL・30分ハード時間範囲を作成済み。モデル実行は未実施**  
対象ホスト: `WIN-32-H1`  
対象DB:

- `Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db`
- `Clouseau/artifact/scenarios/atlasv2/attack/h1/s4/incident.db`

関連する選定根拠:

- [S3: 11件の選定根拠](atlasv2_s3_11_cbc_attack_alert_selection_20260723.md)
- [S4: 13件の選定根拠](atlasv2_s4_13_cbc_attack_alert_selection_20260723.md)

## 1. 目的と実験単位

本追加実験では、CBCが実際に発報した攻撃関連アラートを調査起点にし、観測ログから証跡付き攻撃行動列をどこまで復元できるかを測る。評価対象は、アラートの文面を再述できるかではなく、親子関係・コマンドライン・通信・ファイル操作等の一次ログから、行動の前後関係を構成できるかである。

実験単位は、次の形式の**アラート起点入力**とする。

```text
1件のCBCアラート行
  + 同一ホスト
  + アラート対象のプロセス実体（実行ファイル・PID・発生時刻）
  + 全ケースで同一規則により決めた時間窓
```

24件は24個の独立インシデントではない。同じ攻撃行為に対する複数のCBC検知を、異なる実務上の調査起点として比較する入力群である。したがって、同じ攻撃クラスタに属するアラート種別の違いは、**起点アラートの具体性が復元に与える影響**を測るために保持する。

ただし、アラート要約を取り除くStage 2/3では、同一のhost・process・time入力を異なるGoldに対して反復採点しない。このためStage 1は24 alert-target入力、Stage 2/3は一意なprocess-time入力へ縮約する。

| シナリオ | アラート起点入力 | 独立した観測クラスタ | 主な攻撃手法 |
|---|---:|---:|---|
| S3 | 11 | 3 | 悪性RTF、Equation Editor、`regsvr32`、PowerShell、payload/C2 |
| S4 | 13 | 4 | 悪性Word、`mshta`、hidden/encoded PowerShell、payload/C2 |
| 合計 | **24** | **7** | 文書起点からコード実行・外部通信まで |

| 評価条件 | S3 | S4 | 合計 | 評価単位 |
|---|---:|---:|---:|---|
| Stage 1 | 11 | 13 | **24** | CBC alert-target input |
| Stage 2 | 4 | 4 | **8** | unique host/process/time input |
| Stage 3 | 4 | 4 | **8** | unique host/process/time input |
| 総入力数 | 19 | 21 | **40** | モデル実行単位 |

## 2. 選定規則（S3・S4共通）

次の条件をすべて満たすCBCアラートを採用する。

1. `cbc_alerts`に実在する行である。
2. 対象プロセスのPID・実行ファイル・アラート作成時刻を取得でき、`host + process + time`の入力を一意に構成できる。
3. アラート時点のCBC／Sysmonテレメトリで、対象実行ファイル・親子関係・コマンドライン・通信のいずれかから攻撃系列への関与を確認できる。ATLASv2のプロセスGTは補助根拠として使うが、PID再利用があるためPIDだけでは判定しない。
4. 同一プロセスに対しても、検知対象の不審性が異なる`report_name`は別入力として残す。
5. 同一PID・親PID・`alert_id`・`report_name`の再掲だけは、一つの入力に統合する。
6. 明確な親子・通信関係を持つ成功確認ケースだけでなく、後続攻撃との直接エッジが弱い文書起点ケースも残す。後者は、過剰な因果推論をしない限界評価である。

この規則により、S3では生行12件から重複1件を統合して11件、S4では攻撃関連候補15件から証跡不足のWord 1件を除外し、PowerShell重複1件を統合して13件とした。

## 3. 攻撃段階とGoldの基本方針

攻撃段階はCBCのアラート名ではなく、観測ログの行為の役割で分ける。

| 段階 | 行為 | Goldに採る一次証跡の例 |
|---|---|---|
| 入口 | 悪性文書を開く／Office子プロセスを起動する | Wordの作成、子Word、外部`:8080`通信 |
| ローダ | `regsvr32`や`mshta`が次段を取得・起動する | 親子関係、`scrobj.dll`／HTA、外部通信 |
| スクリプト実行 | PowerShellがコードを実行する | hidden／encoded／`IEX`コマンド、親子関係 |
| payload実行 | `cmd`からpayloadを起動する | `PowerShell → cmd → payload.exe` |
| 外部通信 | payloadが外部サーバへ接続する | `ortrta.net`、IP、port |

Goldは以下の原則で作る。

- 各ステップには、DB中の具体的なログ証跡を対応付ける。
- CBC alert summaryのタイトルやreasonを、行動ステップそのものとしてGoldに入れない。
- 観測済みの親子・通信・コマンド・オブジェクト関係でつながる範囲だけを、一つの行動列にする。
- 同じホスト・近い時刻でも、直接エッジがない別系列を因果的につながない。
- 文書起点ケースでは、Wordから後続の`mshta`／Equation Editorへ直接つながる証跡がない限り、後続ローダをGold必須ステップにしない。
- 各ケースの出力には、復元できた系列に加えて、不確実な接続を不確実として残せたかを記録する。

## 4. 攻撃クラスタの地図

```text
S3
  S3-C1: Word PID5592 ──（直接エッジ未確定）── Equation Editor PID6032
  S3-C2: Equation Editor PID6032 → regsvr32 PID6124 → 10.193.66.115:8080
  S3-C3: Equation Editor PID2244 → regsvr32 PID3992 → PowerShell PID2340
         → cmd PID1880 → payload.exe PID3208/4964 → ortrta.net:9999

S4
  S4-W1: Word PID3236 → 子Word PID4572、外部:8080
  S4-W2: Word PID5980 → 子Word PID3784、外部:8080
  S4-W3: Word PID2608 → 子Word PID3060、外部:8080
  S4-C1: svchost PID644 → mshta PID4724 → PowerShell PID2976 → PowerShell PID3820
         → cmd PID2168 → payload.exe PID4184/3652 → ortrta.net:9999
```

S3-C1は入口の境界ケースであり、S3-C2／C3と因果的に結ぶことをGoldは要求しない。S4-W1〜W3も同様に、WordエピソードとS4-C1を直接結ぶ観測エッジはないため、同一の一本の行動列として採点しない。

## 5. S3：11件の詳細仕様

### S3の時間的な観測事実

| クラスタ | 主な観測時刻UTC | 観測済みの関係 | Goldで扱う範囲 |
|---|---|---|---|
| S3-C1 | 14:33:20頃 | Word `PID5592`が`msf.rtf`を開く | Word文書実行。後続への直接因果は未確定 |
| S3-C2 | 14:33:24–14:33:42 | Equation Editor `PID6032 → regsvr32 PID6124`、`:8080`通信 | Equation Editor、`regsvr32`、外部通信 |
| S3-C3 | 14:36:16–14:37:27 | Equation Editor `PID2244 → regsvr32 PID3992 → PowerShell PID2340 → cmd PID1880 → payload`、C2 | 観測可能な連結系列全体 |

| ID | row | 起点アラート（短縮） | クラスタ | 期待する最小復元範囲 | ケース種別 |
|---|---:|---|---|---|---|
| S3-01 | 29 | Word `normal.dotm` | S3-C1 | Wordが`msf.rtf`を開く | 境界：入口 |
| S3-02 | 21 | `regsvr32` suspicious LOLBin | S3-C2 | EqnEdt → `regsvr32` → `:8080` | 明確な連結 |
| S3-03 | 28 | `regsvr32` loading `scrobj.dll` | S3-C2 | EqnEdt → `regsvr32` → `:8080` | 明確な連結 |
| S3-04 | 17 | `regsvr32` network connection | S3-C2 | EqnEdt → `regsvr32` → `:8080` | 明確な連結 |
| S3-05 | 4 | `regsvr32` loading `scrobj.dll` | S3-C3 | EqnEdt → `regsvr32` → PowerShell → cmd → payload → C2 | 長い系列・前方復元 |
| S3-06 | 18 | `regsvr32` suspicious LOLBin | S3-C3 | EqnEdt → `regsvr32` → PowerShell → cmd → payload → C2 | 長い系列・前方復元 |
| S3-07 | 19 | `regsvr32` network connection | S3-C3 | EqnEdt → `regsvr32` → PowerShell → cmd → payload → C2 | 長い系列・前方復元 |
| S3-08 | 7 | PowerShell `IEX` | S3-C3 | `regsvr32` → PowerShell → cmd → payload → C2 | 中間起点・前後復元 |
| S3-09 | 6 | PowerShell URL download | S3-C3 | `regsvr32` → PowerShell → cmd → payload → C2 | 中間起点・前後復元 |
| S3-10 | 5 | PowerShell downloading behavior | S3-C3 | `regsvr32` → PowerShell → cmd → payload → C2 | 中間起点・前後復元 |
| S3-11 | 20 | PowerShell interpreter | S3-C3 | `regsvr32` → PowerShell → cmd → payload → C2 | 広い検知・中間起点 |

S3-02〜04、S3-05〜07、S3-08〜11は、それぞれ同じ観測クラスタを復元対象とする。これは重複した採点を目的とするのではなく、同一系列に対して**異なるCBCアラートの具体性が、調査の開始と復元結果に与える影響**を比較するためである。

## 6. S4：13件の詳細仕様

### S4の時間的な観測事実

| クラスタ | 主な観測時刻UTC | 観測済みの関係 | Goldで扱う範囲 |
|---|---|---|---|
| S4-W1 | 00:49:14–00:50:34 | Word `PID3236 → 子Word PID4572`、`:8080`通信 | Word親子・通信 |
| S4-W2 | 00:50:42–00:52:13 | Word `PID5980 → 子Word PID3784`、`:8080`通信 | Word親子・通信 |
| S4-W3 | 00:53:29–00:53:56 | Word `PID2608 → 子Word PID3060`、`:8080`通信 | Word親子・通信 |
| S4-C1 | 00:53:43–00:54:57 | `svchost → mshta → PowerShell PID2976 → PowerShell PID3820 → cmd → payload → C2` | 観測可能な連結系列全体 |

| ID | row | 起点アラート（短縮） | クラスタ | 期待する最小復元範囲 | ケース種別 |
|---|---:|---|---|---|---|
| S4-01 | 5 | Word `normal.dotm` | S4-W1 | Word → 子Word、`:8080`通信 | 境界：入口・広い検知 |
| S4-02 | 25 | Office suspicious VBL | S4-W1 | Word → 子Word、`:8080`通信 | 入口・具体的検知 |
| S4-03 | 32 | Word `normal.dotm` | S4-W2 | Word → 子Word、`:8080`通信 | 境界：入口・広い検知 |
| S4-04 | 6 | Office suspicious VBL | S4-W2 | Word → 子Word、`:8080`通信 | 入口・具体的検知 |
| S4-05 | 14 | Word `normal.dotm` | S4-W3 | Word → 子Word、`:8080`通信 | 境界：入口・広い検知 |
| S4-06 | 19 | Office suspicious VBL | S4-W3 | Word → 子Word、`:8080`通信 | 入口・具体的検知 |
| S4-07 | 31 | `svchost` launching HTA | S4-C1 | `svchost → mshta → PS → PS → cmd → payload → C2` | 長い系列・ローダ起点 |
| S4-08 | 18 | `mshta` launching scripts | S4-C1 | `svchost → mshta → PS → PS → cmd → payload → C2` | 長い系列・ローダ起点 |
| S4-09 | 9 | hidden PowerShell / unusual parent | S4-C1 | `mshta → PS2976 → PS3820 → cmd → payload → C2` | 中間起点 |
| S4-10 | 16 | hidden encoded PowerShell | S4-C1 | `mshta → PS2976 → PS3820 → cmd → payload → C2` | 中間起点 |
| S4-11 | 15 | PowerShell interpreter | S4-C1 | `mshta → PS2976 → PS3820 → cmd → payload → C2` | 広い検知・中間起点 |
| S4-12 | 30 | PowerShell encoded instructions | S4-C1 | `mshta → PS2976 → PS3820 → cmd → payload → C2` | 中間起点 |
| S4-13 | 10 | child PowerShell encoded instructions | S4-C1 | `PS2976 → PS3820 → cmd → payload → C2` | 後段起点 |

S4-W1〜W3は三つの別Wordエピソードであり、同じWordアラート種別でも別ユースケースとして残す。S4-07〜13は一つの長い攻撃クラスタに属するが、`mshta`、最初のPowerShell、後続PowerShellという異なる調査開始位置を比較できる。

## 7. Stage 1–3の入力と公平性

24ユースケースすべてに対し、正常行動復元実験と同じ三段階の情報削減を適用する。

| Stage | モデルに与える起点 | DB内のCBC alert summary | 問い |
|---|---|---|---|
| Stage 1 | host・対象プロセス・時間窓・当該CBCアラート要約 | 利用可能 | 現実のCBCアラート調査として復元できるか |
| Stage 2 | host・対象プロセス・時間窓 | 利用可能。ただし起点入力には含めない | アラート要約に頼らず調査を開始できるか |
| Stage 3 | host・対象プロセス・時間窓 | SQL探索対象から除外 | 下位テレメトリだけで復元できるか |

公平性を保つため、次を固定する。

- 同一ユースケースでは、3 Stageでhost・対象プロセス・時間窓・モデル・エージェント構成を同一にする。
- Stage間で変えるのは、起点アラート要約の提供と、CBC alert summaryへのアクセスだけである。
- GoldにはCBC alert title/reason由来の行動を含めず、Stage 3で観測可能な一次テレメトリに根拠を置く。
- Stage 3においてCBC summaryを隠す処理は、論理ビューではなく、全クエリが時間窓と除外規則を守ることを検証する。

## 8. 固定時間窓とハード制約

全38入力に対し、CBC alertの`create_time`を中心とする`±15分`、計30分の時間窓を採用した。CBCアラートが実テレメトリより遅れて生成されるため、攻撃行為が窓の前半にあっても観測できる設定である。

この時間範囲はプロンプトに書くだけではない。各caseに`enforce_time_scope: true`を設定し、実行器はadapter DBの`audit_logs`・`dns_requests`・`browser_history`から窓外行を物理的に除去する。dry-runで、S3/S4とも窓外行が0件になることを検証した。

Stage 3では、さらに`--exclude-cbc-alert-summary`を必須にした。指定なしのStage 3実行はfail-closedで停止し、CBC alert summaryが可視なStage 2相当の条件で誤って実行されることを防ぐ。CBC EDR/NGAVの下位イベントテレメトリは残る。

## 9. 作成済みの実験成果物

| 成果物 | 内容 | 完了条件 |
|---|---|---|
| 統合case JSONL | Stage 1=24、Stage 2=8、Stage 3=8。計40入力 | row、host、process/time、Stage条件、hard scopeが一意 |
| Gold | Stage 1用24件とStage 2/3用8件 | 各ステップがDBの一次ログで再現可能 |
| Stage 3 answerability | GoldがCBC alert summaryに依存しないことを検査 | Stage 3可視な一次証跡のみ採点 |
| 検証結果 | 選定row、時刻、PID/実行ファイル、Gold証跡、入力漏えい、重複、hard scope | S3=157/157、S4=264/264、統合=81/81 pass |
| レビュー記録 | S3/S4をそれぞれ独立レビューし、修正後に再レビュー | Goldの過剰接続・アラート文面依存・重複採点を解消 |

統合実行用の成果物は次である。

- `data/current_experiment/cases/atlasv2_s3_s4_attack24_stage_cases_20260723.jsonl`
- `data/current_experiment/cases/atlasv2_s3_s4_attack24_execution_manifest_20260723.json`
- `docs/current_experiment/atlasv2_s3_s4_attack24_execution_preflight_20260723.json`

レビューでは、少なくとも次を独立に確認した。

- **攻撃系列レビュー**: Goldの親子・通信・コマンド関係が実ログで成立するか。
- **実験条件レビュー**: アラート文面やシナリオ記述を、Stage 2/3の入力・Goldに持ち込んでいないか。

## 10. この24件で評価できること

1. 入口、ローダ、スクリプト実行という異なる攻撃段階から、どこまで証跡付きに系列を復元できるか。
2. 具体的な検知（`scrobj.dll`、HTA、hidden/encoded PowerShell）と広い検知（Office startup、PowerShell interpreter）で、復元の質がどう変わるか。
3. 同じ攻撃クラスタに対する複数アラートで、アラートの見出しに頼らず同じ観測系列へ到達できるか。
4. 直接証跡が途切れる文書起点で、攻撃の全体像を過剰に断定せず、観測済み範囲と限界を適切に出せるか。
5. Stage 1–3の差分から、CBCアラート要約がなくても残る復元能力を定量化できるか。

本実験の結論は「攻撃を必ず全復元できる」ではない。CBCアラートを受けた調査において、**どの条件なら、どこまでを、どの証跡に基づいて自動的に調査の土台として構成できるか**を示すことである。
