# ATLASv2 S3：CBCアラート起点・攻撃復元 11ユースケースの選定根拠

作成日: 2026-07-23  
対象: `Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db`  
目的: S3で攻撃に関連するCBCアラートを起点に、入力情報を段階的に減らしたときにも、観測ログから証跡付き攻撃行動列を復元できるかを評価する。

## 1. この文書で確定すること

S3については、**利用可能な攻撃関連CBCアラートを網羅し、重複を除いた11件**を実験ユースケースとする。

この11件は「11個の独立した攻撃」ではない。同じ攻撃行為に対し、CBCが着目点の異なる複数ルールを発火させるため、次の4個のアラート対象プロセスに対応する11個の**アラート起点入力**である。

| アラート対象プロセス | 対応する入力数 | 攻撃における位置 |
|---|---:|---|
| Word `PID 5592` | 1 | 悪性RTF文書を開く入口 |
| `regsvr32.exe PID 6124` | 3 | 第1のローダ実行・外部SCT取得 |
| `regsvr32.exe PID 3992` | 3 | 第2のローダ実行・PowerShell起動前 |
| `powershell.exe PID 2340` | 4 | 外部から取得したスクリプトの実行 |

`payload.exe`とそのC2通信は観測ログには存在するが、S3のCBC alert summaryには対応するアラート対象行がない。そのため、payload/C2は復元の終点になり得るが、アラート起点ユースケースには含めない。

## 2. 攻撃段階の定義

攻撃段階はCBCのアラート名ではなく、**観測ログ中の行為の役割**で定義する。根拠の優先順位は、(1) CBCイベントの親子関係、(2) コマンドライン、(3) 通信・ファイル等の直接証跡、(4) ATLASv2のシナリオ記述およびGTラベルによる検証、の順とする。GTラベルやシナリオ記述だけから因果関係を補わない。

| 段階 | 定義 | S3で観測される代表例 |
|---|---|---|
| 入口 | 悪性文書等、攻撃の起点となる対象を開く | Wordが`msf.rtf`を開く |
| ローダ実行 | 次のコードを取得・起動するために正規プログラムを悪用する | Equation Editor → `regsvr32`、外部SCT取得 |
| スクリプト実行 | 取得したコードをPowerShell等で実行する | `PowerShell -IEX ...` |
| payload実行 | 実行ファイルを起動する | `cmd → payload.exe` |
| 外部通信 | 外部サーバと通信する | `ortrta.net:9999` |

S3には時間的に二つのローダ系列がある。`PID 6124`と`PID 3992`は別段階ではなく、どちらもローダ実行段階である。ただし前者は短い系列、後者はPowerShell・payload・C2まで続く長い系列である。

```text
系列A（14:33頃）
Equation Editor PID6032 → regsvr32 PID6124 → 10.193.66.115:8080

系列B（14:36–14:37頃）
Equation Editor PID2244 → regsvr32 PID3992 → PowerShell PID2340
→ cmd PID1880 → payload.exe → ortrta.net:9999
```

なお、Word `PID 5592`が悪性RTFを開いたことは観測されるが、WordからEquation Editorへの直接親子関係は本データのログ上では確定しない。このケースは、攻撃入口アラートからの復元可能性と限界を測る境界ケースとして残す。

## 3. 選定基準

候補を恣意的に選ばないため、以下を順に適用する。

1. **実在するCBCアラートであること**: `cbc_alerts`の行を起点とする。
2. **対象プロセスを一意に指定できること**: `process_pid`、対象実行ファイル、作成時刻が取得でき、`host + process + time`の入力を構成できること。
3. **攻撃関連であること**: アラート時点のCBC／Sysmonテレメトリで対象実行ファイル・親子関係・コマンドライン・通信のいずれかから攻撃系列への関与を確認し、ATLASv2のプロセスGTを補助根拠として照合できること。PIDは再利用され得るため、PIDだけのGT照合では判定しない。
4. **アラート種別を保持すること**: 同一プロセスでも、CBCが異なる不審性を示している場合は別入力として残す。例えば`regsvr32`の`scrobj.dll`読込みと外部通信は、異なる調査起点である。
5. **論理的な重複だけを除くこと**: 同じ`process_pid`、親PID、`alert_id`、`report_name`の再掲は、調査起点を増やさないため1件に統合する。
6. **成功例だけに限定しないこと**: 親子関係・通信が明確なケースに加え、入口から後続系列への直接エッジが弱いWordケースも含める。これは手法の適用条件・限界を明示するためである。

この基準は、アラート名の具体性や、最終的に復元できそうかどうかを基準に事後選別するものではない。利用可能な攻撃関連アラートを母集団として取り、論理的重複のみを除く。

## 4. 母集団からの除外規則

| 除外対象 | 理由 |
|---|---|
| 正常プロセスに対するCBCアラート | 本実験は攻撃復元に限定する。例: DNSログ取得の`cmd`、`tshark`、`dumpcap`、LLMNR通信 |
| 対象PIDが空のアラート行 | `host + process + time`のアラート起点を構成できない。S3には`python.exe`として格納されつつ対象PIDを持たない行があるが、入力条件を一意に定められないため除外する |
| 同一プロセス・同一検知の再掲 | 新たな調査起点にならない。`regsvr32 PID6124`の「Making Network Connections」は同一`alert_id`・同一`report_name`で2行あるため1件に統合する |

## 5. 選定された11ユースケース

以下の「CBC alert row」は`incident.db`の`cbc_alerts.id`である。時刻はアラート作成時刻であり、実際のテレメトリ発生時刻とは異なる場合がある。

| ID | CBC alert row | 作成時刻UTC | 対象プロセス | CBCアラート種別（`report_name`） | 攻撃段階 | 選定理由 |
|---|---:|---|---|---|---|---|
| S3-01 | 29 | 14:36:55 | Word `PID 5592` | Office Application Startup – `normal.dotm` | 入口 | 入口側の唯一の攻撃関連アラート。直接エッジが弱い限界ケース |
| S3-02 | 21 | 14:36:55 | `regsvr32 PID 6124` | Suspicious LOLBin (`scrobj.dll`) Behavior – Child Process or Network Connection | ローダ | 正規ツール悪用と子プロセス／通信に着目 |
| S3-03 | 28 | 14:36:55 | `regsvr32 PID 6124` | Attempted Whitelisting Bypass – Regsvr32 Loading `scrobj.dll` | ローダ | `scrobj.dll`読込みに着目した具体的検知 |
| S3-04 | 17 | 14:36:55 | `regsvr32 PID 6124` | RegSvr32 Making Network Connections | ローダ | `regsvr32`の外部通信に着目 |
| S3-05 | 4 | 14:41:57 | `regsvr32 PID 3992` | Attempted Whitelisting Bypass – Regsvr32 Loading `scrobj.dll` | ローダ | 長い系列のローダ起点 |
| S3-06 | 18 | 14:41:58 | `regsvr32 PID 3992` | Suspicious LOLBin (`scrobj.dll`) Behavior – Child Process or Network Connection | ローダ | 子プロセス／通信に着目した同一ローダの別起点 |
| S3-07 | 19 | 14:41:57 | `regsvr32 PID 3992` | RegSvr32 Making Network Connections | ローダ | 通信に着目した同一ローダの別起点 |
| S3-08 | 7 | 14:41:57 | PowerShell `PID 2340` | Powershell Executing with Invoke-Expression | スクリプト実行 | `IEX`によるコード実行に着目 |
| S3-09 | 6 | 14:41:57 | PowerShell `PID 2340` | Powershell Downloading File From URL Detected | スクリプト実行 | URLからの取得に着目 |
| S3-10 | 5 | 14:41:58 | PowerShell `PID 2340` | PowerShell Downloading Behaviors Detected | スクリプト実行 | ダウンロード挙動一般に着目 |
| S3-11 | 20 | 14:41:58 | PowerShell `PID 2340` | Command and Scripting Interpreter – Powershell | スクリプト実行 | PowerShell利用自体を捉える広い検知 |

## 6. 件数の説明

| 数え方 | 件数 | 説明 |
|---|---:|---|
| 攻撃対象プロセスを持つCBCアラートの生行 | 12 | Word 1、`regsvr32 PID6124` 4、`regsvr32 PID3992` 3、PowerShell 4 |
| 論理的重複を統合後 | **11** | `regsvr32 PID6124`のネットワーク接続アラートが同一`alert_id`・同一検知として2行あるため1件に統合 |
| 実質的なCBCアラート種別 | 8 | Word 1、`regsvr32` 3種、PowerShell 4種 |
| アラート対象プロセス | 4 | Word、短い系列の`regsvr32`、長い系列の`regsvr32`、PowerShell |

したがって、11件は「11種類の攻撃手法」ではなく、**8種の検知ロジックが4つの攻撃プロセス実体に対して発火した11個のアラート起点**である。

## 7. 実験上の扱い

各ユースケースで、アラート種別の情報を与えるかどうかだけを段階的に変える。復元対象となる行動列は、CBC alert summaryの文面ではなく、CBC EDRイベント、Sysmon、Windows監査、DNS、ブラウザログ等の観測証跡から定義する。

| 条件 | モデルへの起点入力 | 検証したいこと |
|---|---|---|
| Stage 1 | host・process・時間窓・CBCアラート要約 | 実際のCBCアラート調査として、系列を復元できるか |
| Stage 2 | host・process・時間窓 | アラート要約を起点情報に使わなくても復元できるか |
| Stage 3 | host・process・時間窓。CBC alert summaryを探索対象から除外 | 下位テレメトリだけで復元できるか |

すべてのStageで、同一ユースケースには同一のhost・process・固定時間窓を使う。時間窓の幅と、DB／SQL検索をその窓に物理的に制限する方法は、この選定とは独立に事前固定する。アラート作成時刻が実テレメトリより遅れるため、作成時刻だけを根拠に窓を決めず、各系列の観測時刻を確認してから一律の規則を定める。

## 8. この設計で答える問い

この11件により、次を分けて評価する。

1. **アラートの具体性**: `IEX`や`scrobj.dll`のように具体的な検知と、「PowerShell利用」のように広い検知で、復元結果は変わるか。
2. **起点の位置**: 攻撃入口、ローダ、スクリプト実行のどこから調査を始めると、前後の系列をどこまで復元できるか。
3. **観測連結性**: 親子関係・コマンドライン・通信が揃うケースではどこまで復元でき、Word起点のように直接エッジが弱い場合にはどこで不確実性を残せるか。
4. **要約への依存**: 同じ11件に対してStage 1–3を適用し、CBCアラート要約を除いてもログ証跡から復元できる範囲を測る。

このため、成功率だけでなく「観測可能な行動を根拠付きで連結できたか」と「連結できない箇所を断定せず不確実として扱えたか」を評価に含める。
