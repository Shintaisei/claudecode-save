# LMD Collections 全体像・正常行動・形式調査

作成日: 2026-04-17

## 見るべき代表ファイル

保存先:

- `LMD_Collections/`

まず使うなら、以下の2つを見るのがよい。

- ラベル付き生CSV: `LMD_Collections/LMD-2023/LMD-2023 [2.3M Elements]/LMD-2023 [2.3M Elements]Checked/Labelled LMD-2023/LMD-2023 [2.3M Elements][Labelled]checked.csv`
- 前処理済みCSV: `LMD_Collections/LMD-2023/LMD-2023 [2.3M Elements]/LMD-2023 [2.3M Elements]Checked/Preprocessed LMD-2023/LMD-2023 [2.3M Elements][Labelled+Preprocessed]checked.csv`

LMD-2023 2.3M版は、データ量が最大で、Normal / EoRS / EoHT の3クラスが比較的そろっている。初期分析・分類実験の主軸にしやすい。

## データセット形式

### ラベル付き生CSV

LMD-2023 2.3Mのラベル付きCSVは94列。Sysmonのイベント項目を横持ちした形式。

重要列:

- `SystemTime`: イベント時刻
- `Label`: 正解ラベル
- `Computer`: ホスト名
- `EventID`: Sysmon Event ID
- `Image`: 実行ファイルまたはイベント主体のプロセス
- `CommandLine`: プロセス作成時のコマンドライン
- `ParentImage`, `ParentCommandLine`: 親プロセス
- `User`: 実行ユーザ
- `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationPortName`: ネットワーク接続
- `TargetFilename`: ファイル作成
- `TargetObject`, `Details`, `EventType`: レジストリ系イベント
- `QueryName`, `QueryStatus`, `QueryResults`: DNSクエリ
- `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`: ProcessAccess系

ラベル:

- `0`: Normal
- `1`: EoRS, Exploitation of Remote Services
- `2`: EoHT, Exploitation of Hashing Techniques / credential exploitation

### 前処理済みCSV

LMD-2023 2.3Mの前処理済みCSVは87列。主にカテゴリ変数がone-hot化されている。

含まれる特徴:

- `SystemTime`, `EventRecordID`, `Execution_ProcessID`, `ProcessId`
- `SystemTime_day`, `SystemTime_hour`, `SystemTime_minute`
- `Label`
- `EventID_1.0`, `EventID_2.0`, `EventID_3.0`, ...
- `Computer_*`
- `Initiated_*`
- `SourceIsIpv6_*`
- `DestinationPortName_*`
- `SystemTime_year_*`, `SystemTime_month_*`, `SystemTime_week_*`, `SystemTime_day_of_week_*`

注意:

- 空列や `Unnamed:*` 列が残っている。
- `Image`, `CommandLine`, `User`, `TargetObject` などの文字列情報はかなり落ちている。
- モデル入力には使いやすいが、行動解釈には生CSVが必要。

## LMD-2023 2.3M版の規模

ラベル付きCSV:

| ラベル | 意味 | 行数 |
|---:|---|---:|
| 0 | Normal | 1,632,903 |
| 1 | EoRS | 375,239 |
| 2 | EoHT | 135,866 |
| 合計 |  | 2,144,008 |

前処理済みCSV:

| ラベル | 意味 | 行数 |
|---:|---|---:|
| 0 | Normal | 1,611,637 |
| 1 | EoRS | 363,459 |
| 2 | EoHT | 131,104 |
| 合計 |  | 2,106,200 |

## タイムライン

LMD-2023 2.3M版は、連続した1つの実験ログではなく、複数期間のログを結合したコーパスに見える。

月別:

| 月 | Normal | EoRS | EoHT | 合計 |
|---|---:|---:|---:|---:|
| 2021-09 | 171,403 | 240,683 | 16,717 | 428,803 |
| 2022-10 | 428,803 | 0 | 0 | 428,803 |
| 2022-11 | 414,861 | 565 | 13,377 | 428,803 |
| 2023-11 | 428,803 | 0 | 0 | 428,803 |
| 2023-12 | 189,033 | 133,991 | 105,772 | 428,796 |

日別の主な流れ:

| 日付 | Normal | EoRS | EoHT | 読み取り |
|---|---:|---:|---:|---|
| 2021-09-07 | 44,516 | 348 | 3,099 | 正常に少量の攻撃ログが混在 |
| 2021-09-08 | 5,214 | 80,942 | 241 | EoRS中心 |
| 2021-09-09 | 0 | 86,404 | 0 | EoRSのみ |
| 2021-09-10 | 12,447 | 72,490 | 1,464 | EoRS中心、一部EoHT |
| 2021-09-11 | 73,983 | 499 | 11,913 | Normal + EoHT |
| 2021-09-12 | 35,243 | 0 | 0 | Normalのみ |
| 2022-10-10から2022-10-15 | 428,803 | 0 | 0 | Normalのみ |
| 2022-11-10から2022-11-15 | 414,861 | 565 | 13,377 | ほぼNormal、一部EoHT/EoRS |
| 2023-11-24から2023-11-29 | 428,803 | 0 | 0 | Normalのみ |
| 2023-12-03から2023-12-08 | 189,033 | 133,991 | 105,772 | EoRS/EoHTを含む攻撃期間 |

1時間あたりの件数が約3,600件になる箇所が多い。これは、一定周期で発生するネットワークイベントや、結合・サンプリング済みのログが強く影響している可能性がある。時系列モデルに使う場合は、単純なランダム分割ではなく、日付・ホスト・攻撃期間単位で分割した方がよい。

## ホスト構成

LMD-2023 2.3M版のラベル別ホスト分布:

| ラベル | 主なホスト |
|---|---|
| Normal | `LAPTOP-ROPR18AK` が大半、ほか `WINDOWS10EVAL.stefania.local`, `WIN-J23NIGGP1Q6.sysmon_set.local` |
| EoRS | `win-dc-128.attackrange.local`, `win-host-987.attackrange.local`, `win-dc-800.attackrange.local` |
| EoHT | `win-dc-800.attackrange.local`, `win-dc-128.attackrange.local`, `WIN-J23NIGGP1Q6.sysmon_set.local`, `win-host-987.attackrange.local` |

注意点として、Normalは `LAPTOP-ROPR18AK` にかなり偏っている。一方で攻撃はAttackRange系ホストに偏っている。そのため、モデルが「攻撃そのもの」ではなく「ホスト名・環境差」を学習する危険がある。

## 正常行動の中身

LMD-2023 2.3M版のNormalは、ほとんどがSysmon EventID 3のネットワーク接続。

NormalのEventID分布:

| EventID | 意味 | 件数 |
|---:|---|---:|
| 3 | Network connection | 1,399,345 |
| 5 | Process terminated | 174,734 |
| 1 | Process creation | 19,544 |
| 13 | Registry value set | 17,751 |
| 22 | DNS query | 9,929 |
| 11 | File create | 9,212 |
| 12 | Registry object create/delete | 661 |
| 4 | Sysmon service state changed | 443 |
| 16 | Sysmon configuration change | 344 |

Normalの主なプロセス:

- `System`
- `C:\Users\chrsm\AppData\Local\Programs\Opera\opera.exe`
- `C:\Windows\System32\dns.exe`
- `C:\Users\chrsm\AppData\Local\Microsoft\Teams\current\Teams.exe`
- `C:\Users\chrsm\AppData\Local\slack\app-4.26.2\slack.exe`
- `C:\Users\chrsm\AppData\Local\Programs\Microsoft VS Code\Code.exe`
- `C:\ProgramData\Microsoft\Windows Defender\...\MpCmdRun.exe`
- `C:\Users\chrsm\AppData\Local\Viber\Viber.exe`
- `C:\Windows\system32\CompatTelRunner.exe`
- `C:\Users\chrsm\AppData\Local\Programs\Python\Python39\python.exe`
- `C:\Windows\System32\cmd.exe`
- `C:\Windows\System32\notepad.exe`
- `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
- `OneDrive` 関連

Normalとして含まれる行動の例:

- Opera / EdgeによるWebアクセス
- Teams, Slack, Viberなどのコミュニケーションアプリ
- VS Code, Python実行
- Windows Defender
- Windows Update / SoftwareDistribution配下のファイル作成
- OneDrive同期
- DNS / Active Directory / DFSRなどのWindowsドメイン系サービス
- NetBIOS系のブロードキャスト通信
- Foxit Reader, Event Log Explorer, Genymotionなどのインストール/アンインストール痕跡
- `cmd.exe`, `ipconfig`, `sc.exe`, `notepad.exe` などの通常管理操作

Normalの主な宛先ポート名:

| 宛先ポート名 | 件数 | 読み取り |
|---|---:|---|
| `netbios-dgm` | 843,191 | NetBIOS Datagram |
| `netbios-ns` | 523,705 | NetBIOS Name Service |
| `ldap` | 5,486 | Active Directory照会 |
| `microsoft-ds` | 2,898 | SMB |
| `https` | 975 | Web通信 |
| `domain` | 828 | DNS |
| `epmap` | 742 | RPC Endpoint Mapper |

NormalのDNSクエリ例:

- `WINDOWS10EVAL`
- `_ldap._tcp.*.stefania.local`
- `_kerberos._tcp.*.stefania.local`
- `wpad`
- `oneclient.sfx.ms`
- `live.sysinternals.com`
- `wetransfer.com`
- `www.msftconnecttest.com`
- `www.google.com`
- Microsoft/Akamai/AzureEdge系ドメイン

## 攻撃側の見え方

EoRSでは、以下が目立つ。

- Splunk Universal Forwarder関連プロセスが多い
- `winrs.exe`, `WinrsHost.exe`
- `ipconfig`, `whoami`, `netstat -an`
- `eventvwr.msc`
- `PsExec.exe` の存在確認
- `cmd.exe`, `powershell.exe`

EoHTでは、以下が目立つ。

- `lsass.exe`
- `svchost.exe`
- `mimikatz.exe`
- `klist.exe`
- `LogonUI.exe`, `winlogon.exe`, `rdpclip.exe`
- ProcessAccess系のEventID 10が多い

ただし、攻撃ラベルにもSplunk収集系プロセスやWindows標準プロセスが多く含まれる。攻撃行動だけがきれいに抽出されているわけではなく、攻撃実行期間中の周辺ログも含んでいると見るべき。

## LMD-2022との違い

LMD-2022のラベル付きCSV:

| ラベル | 意味 | 行数 |
|---:|---|---:|
| 0 | Normal | 853,730 |
| 1 | EoRS | 565 |
| 2 | EoHT | 13,377 |
| 合計 |  | 867,672 |

LMD-2022はEoRSが565件しかなく、3クラス分類にはかなり不安定。正常行動はLMD-2023と似ており、`LAPTOP-ROPR18AK` の日常系ログと `WIN-J23NIGGP1Q6.sysmon_set.local` のドメイン系ログが中心。

LMD-2022のNormal上位プロセス:

- `System`
- `Opera`
- `dns.exe`
- `Teams`
- `Slack`
- `VS Code`
- `Windows Defender`
- `Viber`
- `Python`
- `cmd.exe`
- `notepad.exe`

LMD-2022はベースライン比較や過去版としては使えるが、主実験にはLMD-2023を使う方がよい。

## 研究で使うときの注意

### 1. ホスト名リーク

Normalと攻撃でホスト分布がかなり違う。`Computer_*` をそのまま特徴量に入れると、モデルが攻撃挙動ではなく環境差を覚える可能性がある。

対策:

- `Computer` を除外した実験を必ず作る。
- ホスト単位分割を試す。
- ホスト名あり/なしで性能差を見る。

### 2. 時刻リーク

攻撃が特定の日付・期間に集中している。`SystemTime_year`, `month`, `week`, `day_of_week`, `hour` を入れると、時期で分類できてしまう可能性がある。

対策:

- 時刻特徴あり/なしを比較する。
- ランダム分割だけでなく、日付単位のholdoutを使う。
- 2021/2022/2023を跨ぐ検証を行う。

### 3. 周辺ログ混入

攻撃ラベルには、攻撃コマンドだけでなく、その期間に同時発生したSplunk、Windowsサービス、DNS、ネットワーク、ログ収集系イベントも入っている。

対策:

- 「攻撃そのものの検知」なのか「攻撃期間の検知」なのかを研究目的で明確にする。
- `Image`, `CommandLine`, `EventID`, `TargetImage`, `GrantedAccess` などで解釈性分析を行う。

### 4. Normalの大半はネットワーク雑音

Normalの大半はEventID 3、特にNetBIOS系通信。これが多すぎるため、普通に学習するとEventID分布だけで分類が進む可能性がある。

対策:

- EventIDごとの層化サンプリングを検討する。
- EventID 3だけ、EventID 1だけ、EventID 10だけ、というサブタスクを作る。
- Normal/EoRS/EoHTを同じEventID分布に近づけて評価する。

## 結論

LMD Collectionsは、ラテラルムーブメント検知研究に使える。ただし、素直に前処理済みCSVをランダム分割して分類すると、ホスト名・時刻・EventID分布で高性能に見える危険がある。

おすすめの使い方:

- 主データはLMD-2023 2.3M版。
- 行動分析はラベル付き生CSVで行う。
- 初期分類は前処理済みCSVでよいが、`Computer_*` と時刻one-hotを抜いた版も必ず比較する。
- 評価はmacro F1、class-wise recall、PR-AUCを中心にする。
- ランダム分割、日付分割、ホスト分割の3種類を比較する。
- 「ラテラルムーブメント攻撃そのもの」ではなく、「Sysmonログ上の攻撃期間/攻撃カテゴリを検知するデータセット」と捉えるのが安全。

