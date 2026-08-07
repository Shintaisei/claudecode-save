# ATLASv2 S4：CBCアラート起点・攻撃復元 13ユースケースの選定根拠

作成日: 2026-07-23  
対象: `Clouseau/artifact/scenarios/atlasv2/attack/h1/s4/incident.db`  
目的: S4で攻撃に関連するCBCアラートを起点に、入力情報を段階的に減らしたときにも、観測ログから証跡付き攻撃行動列を復元できるかを評価する。

## 1. この文書で確定すること

S4については、**利用可能な攻撃関連CBCアラートを網羅し、論理的重複を除いた13件**を実験ユースケースとする。

13件は13個の独立した攻撃ではない。CBCが同じ攻撃行為の異なる特徴を複数の検知ルールで報告するため、次の6プロセス実体に対応する13個の**アラート起点入力**である。

| アラート対象プロセス | 入力数 | 攻撃における位置 |
|---|---:|---|
| Word `PID 3236` / 子Word `PID 4572` | 2 | 第1の悪性Word実行エピソード |
| Word `PID 5980` / 子Word `PID 3784` | 2 | 第2の悪性Word実行エピソード |
| Word `PID 2608` / 子Word `PID 3060` | 2 | 第3の悪性Word実行エピソード |
| `mshta.exe PID 4724` | 2 | スクリプトローダ |
| PowerShell `PID 2976` | 4 | 隠蔽・符号化されたPowerShell実行 |
| PowerShell `PID 3820` | 1 | 後続PowerShell、通信・payload起動前 |

`cmd.exe PID2168`、`payload.exe PID4184/3652`、および`ortrta.net:9999`への通信は観測ログに存在するが、対応するCBCアラート対象行はない。これらは復元対象の後段であり、アラート起点ユースケースには含めない。

## 2. 攻撃段階の定義とS4の観測系列

攻撃段階はCBCのアラート名ではなく、観測ログ中の行為の役割で定義する。根拠の優先順位は、(1) CBCイベント／Sysmonの親子関係、(2) コマンドライン、(3) 通信・ファイル等の直接証跡、(4) ATLASv2のシナリオ記述およびGTラベルによる検証、の順とする。PIDは再利用されるため、GTのPIDだけから攻撃性や因果関係を決めない。

| 段階 | 定義 | S4で観測される代表例 |
|---|---|---|
| 入口 | 悪性文書等、攻撃のきっかけとなる対象の実行 | Wordプロセス群が外部`10.193.66.115:8080`へ通信 |
| スクリプトローダ | 正規プログラムを用いて次のコードを取得・起動 | `svchost PID644 → mshta PID4724`、`mshta`の外部通信 |
| スクリプト実行 | PowerShell等で隠蔽・符号化されたコードを実行 | `mshta PID4724 → PowerShell PID2976 → PowerShell PID3820` |
| payload実行 | 実行ファイルを起動 | `PowerShell PID3820 → cmd PID2168 → payload.exe PID4184` |
| 外部通信 | 外部サーバと通信 | `payload.exe PID3652 → ortrta.net:9999` |

主系列として、次がログ上で連結している。

```text
svchost PID644 → mshta PID4724 → PowerShell PID2976 → PowerShell PID3820
→ cmd PID2168 → payload.exe PID4184/3652 → ortrta.net:9999
```

Word実行から`mshta`への直接親子関係は、ログ上では確定しない。一方、Wordの各エピソードでは外部`10.193.66.115:8080`への通信が観測される。このため、Word起点6件は入口側の関連証跡を復元できるか、および後続ローダ系列へ断定せず接続できるかを測る境界ケースとして扱う。

## 3. S3と共通の選定基準

1. **実在するCBCアラートであること**: `cbc_alerts`の行を起点とする。
2. **対象プロセスを一意に指定できること**: `process_pid`、対象実行ファイル、作成時刻が取得でき、`host + process + time`の入力を構成できること。
3. **攻撃関連であること**: アラート時点のCBC／Sysmonテレメトリで、対象実行ファイル・親子関係・コマンドライン・通信のいずれかから攻撃系列への関与を確認し、ATLASv2のプロセスGTを補助根拠として照合できること。
4. **アラート種別を保持すること**: 同一プロセスでも、CBCが異なる不審性を示している場合は別入力として残す。
5. **論理的な重複だけを除くこと**: 同じ`process_pid`、親PID、`alert_id`、`report_name`の再掲は、調査起点を増やさないため1件に統合する。
6. **成功例だけに限定しないこと**: 明確な親子・通信を持つ`mshta`／PowerShellに加え、後続ローダへの直接エッジがないWord起点も残し、適用条件と限界を評価する。

S4ではPIDが別時刻に別プロセスへ再利用されている例がある。例えば`PID 2976`は早い時刻にはCarbon Black関連プロセスとして使われ、攻撃時刻にはPowerShellとして使われる。したがって、対象の実行ファイルと時刻を確認せず、PIDだけでGTラベルを参照することはしない。

## 4. 選定された13ユースケース

「CBC alert row」は`incident.db`の`cbc_alerts.id`である。アラート作成時刻はテレメトリより遅れる場合がある。

| ID | CBC alert row | 作成時刻UTC | 対象プロセス | CBCアラート種別（`report_name`） | 攻撃段階 | 選定理由 |
|---|---:|---|---|---|---|---|
| S4-01 | 5 | 00:51:12 | Word `PID 3236` | Office Application Startup – `normal.dotm` | 入口 | 外部`:8080`通信を伴う第1 Wordエピソードの広い検知 |
| S4-02 | 25 | 00:51:12 | 子Word `PID 4572` | MS Office Applications Loading Suspicious Visual Basic Libraries | 入口 | `PID3236 → PID4572`の親子関係を持つ具体的検知 |
| S4-03 | 32 | 00:56:14 | Word `PID 5980` | Office Application Startup – `normal.dotm` | 入口 | 外部`:8080`通信を伴う第2 Wordエピソードの広い検知 |
| S4-04 | 6 | 00:56:14 | 子Word `PID 3784` | MS Office Applications Loading Suspicious Visual Basic Libraries | 入口 | `PID5980 → PID3784`の親子関係を持つ具体的検知 |
| S4-05 | 14 | 00:56:14 | Word `PID 2608` | Office Application Startup – `normal.dotm` | 入口 | 外部`:8080`通信を伴う第3 Wordエピソードの広い検知 |
| S4-06 | 19 | 00:56:14 | 子Word `PID 3060` | MS Office Applications Loading Suspicious Visual Basic Libraries | 入口 | `PID2608 → PID3060`の親子関係を持つ具体的検知 |
| S4-07 | 31 | 00:56:14 | `mshta PID 4724` | Svchost Launching HTA (CVE-2017-0199) | ローダ | `svchost → mshta`、外部通信、PowerShell起動を確認できる具体的検知 |
| S4-08 | 18 | 00:56:14 | `mshta PID 4724` | MSHTA Launching Script Interpreters | ローダ | 同じ`mshta`を、子スクリプト起動の観点から検知 |
| S4-09 | 9 | 00:56:14 | PowerShell `PID 2976` | Hidden Powershell with Unusual Parent | スクリプト実行 | 親`mshta`とhidden実行に着目 |
| S4-10 | 16 | 00:56:14 | PowerShell `PID 2976` | Powershell Executing Hidden - Encoded Commands | スクリプト実行 | hidden・符号化コマンドに着目 |
| S4-11 | 15 | 00:56:14 | PowerShell `PID 2976` | Command and Scripting Interpreter – Powershell | スクリプト実行 | PowerShell利用自体を捉える広い検知 |
| S4-12 | 30 | 00:56:14 | PowerShell `PID 2976` | Powershell Executed with Encoded Instructions | スクリプト実行 | 符号化された命令の実行に着目 |
| S4-13 | 10 | 00:56:14 | PowerShell `PID 3820` | Powershell Executed with Encoded Instructions | スクリプト実行 | 子PowerShellから通信・payload実行へ進む中間起点 |

## 5. 母集団からの除外規則と件数

| 除外対象 | 理由 |
|---|---|
| DNSログ取得の`cmd PID2268`、`tshark`、`dumpcap`に対するアラート | 実テレメトリ上で`start_dns_logs.bat`による通常のDNSログ取得であり、攻撃系列ではない |
| LLMNR通信、SysInternals利用に対するアラート | 攻撃系列との直接証跡がない |
| `process_pid`が空の`python.exe`行 | `host + process + time`のアラート起点を一意に構成できない |
| Word `PID3284`の`normal.dotm`アラート（row 8） | Word再起動は観測されるが、攻撃通信・後続ローダとの直接証跡がなく、攻撃関連の起点という基準を満たさない |
| PowerShell `PID3820`のrow 34 | row 10と同一PID・同一親PID・同一`alert_id`・同一`report_name`の再掲であり、1件に統合する |

| 数え方 | 件数 | 説明 |
|---|---:|---|
| 選定前の攻撃関連候補の生行 | 15 | Word 7、`mshta` 2、PowerShell `PID2976` 4、PowerShell `PID3820` 2 |
| 証跡不足のWord row 8を除外後 | 14 | 直接の攻撃関連証跡を満たす候補 |
| PowerShell `PID3820`の重複統合後 | **13** | row 34を統合する一方、row 8を除外するため最終件数は13 |
| 実質的なアラート種別 | 8 | Word 2、`mshta` 2、PowerShell 4種（符号化は2プロセスに発火） |

注: 上の生行数は、PIDの時刻再利用を解消し、通常のDNSログ取得等を最初から除外した「攻撃関連候補」の件数である。

## 6. 実験上の扱い

S3と同じ13件ではなく、S3の11件と**同じ条件定義**をS4の13件に適用する。各ユースケースについて、同一のhost・process・固定時間窓をStage間で共有する。

| 条件 | モデルへの起点入力 | 検証したいこと |
|---|---|---|
| Stage 1 | host・process・時間窓・CBCアラート要約 | 実際のCBCアラート調査として系列を復元できるか |
| Stage 2 | host・process・時間窓 | アラート要約を起点情報に使わなくても復元できるか |
| Stage 3 | host・process・時間窓。CBC alert summaryを探索対象から除外 | 下位テレメトリだけで復元できるか |

時間窓の幅と、DB／SQL検索をその範囲に物理的に制限する方法は、S3・S4を横断して事前固定する。アラート作成時刻には遅延があるため、作成時刻だけで窓を決めず、実際のテレメトリ時刻との対応を記録する。

## 7. この設計で答える問い

1. 文書起点・`mshta`起点・PowerShell起点で、攻撃系列を前後どこまで復元できるか。
2. 具体的な検知（HTA起動、hidden/encoded PowerShell）と広い検知（PowerShell利用、Office startup）で復元結果は変わるか。
3. Word起点のように直接因果が弱い場合、後続の攻撃を断定せず、関連証跡と不確実性を適切に示せるか。
4. CBCアラート要約を除いたStage 2・3でも、親子関係・コマンドライン・通信から復元できる範囲はどこまでか。
