# C_Data/96 正常行動と起点アラート分類表
> 作成日: 2026-04-15  
> 対象: `apt-persistence/Datasets/C_Data/96`  
> 入力: `Wazuh-Alerts/alerts.json`  
> 目的: 正常ホストに出たアラートを、正常行動復元の起点候補として分類する。

---

## 1. 位置づけ

この分類表は、`C_Data/96` の正常ホストに出た Wazuh アラートを、正常行動復元のための起点候補として整理した初版である。

ここではまだ「完全な行動復元」までは行わない。まず、どのアラートを起点にすると復元しやすいかを分類し、次の詳細分析で見るべきログを決める。

---

## 2. 生成ファイル

| ファイル | 内容 |
|---|---|
| `C_Data96_Wazuh_alerts_flat.csv` | Wazuhアラート1,458件を1行1イベントに展開したもの |
| `C_Data96_起点アラート分類表.csv` | ルール単位で集計し、カテゴリ・正常行動仮説・優先度を付けたもの |

---

## 3. 分類方針

| 優先度 | 意味 |
|---|---|
| A | 最初に復元対象にする。起点ログから関連ログへたどりやすい |
| B | 重要だが件数が多い、または文脈確認が必要。Aの後に扱う |
| C | Wazuh/SCA内部チェックやシステム定期処理が中心。復元対象としては低優先度 |

分類カテゴリは以下。

| カテゴリ | 意味 |
|---|---|
| Discovery / Account Discovery | `net.exe`, `net1.exe` などによるアカウント・システム情報確認 |
| Script / PowerShell | PowerShell、一時スクリプト、設定エクスポート、ログ圧縮 |
| TaskScheduler / Persistence類似 | `taskschd.dll` 読み込み、スケジュールタスク、Software Protection |
| Privilege / Logon | 特権操作失敗、ログオン、ログオフ、監査失敗 |
| File / DLL / Security Tool | DLL配置、Defender、Windows Update、ファイル生成 |
| SCA / Wazuh内部チェック | WazuhエージェントによるCISベンチマークや設定監査 |
| Windows System / License | ライセンス認証、Software Protection Platform |

---

## 4. カテゴリ別集計

| カテゴリ | ルール種類数 | アラート件数 | 初期判断 |
|---|---:|---:|---|
| Privilege / Logon | 5 | 885 | 件数は最大だが、`msedge.exe` などに偏るため初手には重い |
| SCA / Wazuh内部チェック | 400 | 407 | Wazuh自身の監査結果が中心。正常説明はしやすいが行動復元の題材としては弱い |
| Discovery / Account Discovery | 2 | 53 | Wazuh agent 起点の `net.exe` が見えており、最初の復元対象に向く |
| TaskScheduler / Persistence類似 | 2 | 35 | Persistence研究テーマに近い。TaskSchedulerログとの突合に向く |
| Script / PowerShell | 4 | 32 | PowerShell、Firefox設定ファイル、ログ圧縮があり、正常/攻撃の境界を説明しやすい |
| File / DLL / Security Tool | 6 | 19 | Windows UpdateやDefender由来の正常説明が期待できる |
| Windows System / License | 1 | 2 | 低優先度。Software Protection関連の定期処理として扱う |
| その他 | 25 | 25 | 個別確認が必要 |

---

## 5. 起点アラート分類表

| 優先度 | カテゴリ | 件数 | 起点アラート | 主なプロセス/親プロセス | 正常行動仮説 | 次に見るログ |
|---|---|---:|---|---|---|---|
| A | Discovery / Account Discovery | 37 | `Discovery activity executed` | `wazuh-agent.exe -> net.exe -> net1.exe` | Wazuh/SCAがアカウント・システム設定を確認した正常な監査処理 | Sysmon EID 1、同時刻のWazuh/SCAアラート |
| A | Discovery / Account Discovery | 16 | `A net.exe account discovery command was initiated` | `wazuh-agent.exe -> net.exe`, `net.exe -> net1.exe` | Wazuhエージェントによる `administrator` / `guest` アカウント確認 | Sysmon EID 1、Securityログオン情報 |
| A | TaskScheduler / Persistence類似 | 31 | `Process loaded taskschd.dll module...` | `svchost.exe`, `taskhostw.exe`, `sppsvc.exe`, `MicrosoftEdgeUpdate.exe`, `firefox.exe` | Windows標準タスク、Edge更新、Software Protection、アプリ処理によるタスク関連DLL読み込み | Sysmon EID 7、TaskScheduler.evtx、System.evtx |
| A | Script / PowerShell | 27 | `Scripting file created under Windows Temp or User folder` | `firefox.exe`, `Explorer.EXE` | Firefoxプロファイル設定ファイル、ユーザー操作、アプリ設定更新 | Sysmon EID 11、対象ファイルパス、前後のFirefox起動 |
| A | Script / PowerShell | 2 | `SecEdit.exe binary in a suspicious location launched by PowerShell` | `powershell.exe -> SecEdit.exe` | Wazuh/SCAによるWindowsセキュリティ設定のエクスポート | Sysmon EID 1、PowerShell親子関係、Temp出力ファイル |
| A | Script / PowerShell | 1 | `Suspicious file compression activity by powershell...logs.zip` | `powershell.exe` | ログ収集スクリプトによるEVTX/ログ圧縮 | Sysmon EID 1/11、`Downloads/Scripts/Collector` 配下 |
| B | Privilege / Logon | 854 | `Failed attempt to perform a privileged operation.` | `msedge.exe`, `dllhost.exe`, `explorer.exe`, `svchost.exe`, `firefox.exe` | ブラウザやWindowsサービスによる通常の権限要求失敗 | Security EID 4673、プロセス別代表例 |
| B | Privilege / Logon | 22 | `Windows logon success.` | `services.exe` | サービス・システム処理に伴うログオン | Security EID 4624、LogonType、User |
| B | File / DLL / Security Tool | 4 | `Lsass process was accessed by ... MsMpEng.exe ... possible credential dump` | `MsMpEng.exe` | Windows DefenderによるLSASS参照。攻撃類似だが正常セキュリティ製品動作の可能性が高い | Sysmon EID 10、Defenderパス、署名/親プロセス |
| B | File / DLL / Security Tool | 15 | `Possible DLL search order hijack...SoftwareDistribution...` | `svchost.exe` | Windows Update配下のDLL配置。DLL hijack風だが更新処理の可能性が高い | Sysmon EID 11、System/Windows Update関連イベント |
| C | SCA / Wazuh内部チェック | 407 | CIS/SCA/Wazuh関連ルール | Wazuh internal | Wazuhエージェントのベンチマーク評価・設定監査 | 復元対象ではなく背景ノイズとして整理 |
| C | Windows System / License | 2 | `License activation (slui.exe) failed.` | System | Windowsライセンス認証処理 | System.evtx、Software Protection関連 |

---

## 6. 最初に扱うべき3ケース

次の詳細分析では、以下の3ケースを優先する。

### C96-DISC-001: Wazuh agent による net.exe account discovery

| 項目 | 内容 |
|---|---|
| 起点ルール | `Discovery activity executed` / `A net.exe account discovery command was initiated` |
| 起点時刻例 | `2024-09-16T07:31:43Z` 前後 |
| プロセス連鎖 | `wazuh-agent.exe -> net.exe -> net1.exe` |
| コマンド例 | `net.exe accounts`, `net user administrator`, `net user guest` |
| ユーザー | `NT AUTHORITY\SYSTEM` |
| 正常行動仮説 | Wazuhエージェントがローカルアカウント・ポリシーを確認した監査処理 |
| 復元しやすさ | 高い。親プロセスとコマンドラインが明確 |

これは最初の正常行動復元ケースとして最も扱いやすい。攻撃に見える account discovery だが、親プロセスが `wazuh-agent.exe` であり、セキュリティ監査の正常動作として説明しやすい。

### C96-SCRIPT-001: Firefox による prefs.js 作成

| 項目 | 内容 |
|---|---|
| 起点ルール | `Scripting file created under Windows Temp or User folder` |
| 起点時刻例 | `2024-09-16T08:01:42Z` 前後 |
| プロセス | `C:\Program Files\Mozilla Firefox\firefox.exe` |
| 対象ファイル | `C:\Users\win10pro\AppData\Roaming\Mozilla\Firefox\Profiles\...\prefs.js` |
| ユーザー | `DESKTOP-A1U99I1\win10pro` |
| 正常行動仮説 | Firefox起動・設定更新に伴うプロファイル設定ファイル作成 |
| 復元しやすさ | 中〜高。ファイルパスがアプリ固有で説明しやすい |

これは「スクリプトファイル作成」というアラート名に対し、実際にはブラウザ設定ファイルだった可能性を示せる。偽陽性を正常と説明する題材として良い。

### C96-TASK-001: taskschd.dll 読み込み

| 項目 | 内容 |
|---|---|
| 起点ルール | `Process loaded taskschd.dll module. May be used to create delayed malware execution` |
| 起点時刻例 | `2024-09-16T07:51:24Z`, `2024-09-16T07:56:41Z`, `2024-09-16T08:01:47Z` |
| 主なプロセス | `svchost.exe`, `MicrosoftEdgeUpdate.exe`, `firefox.exe`, `sppsvc.exe` |
| 正常行動仮説 | Windows標準タスク、Edge更新、Software Protection、アプリ処理によるタスクスケジューラAPI利用 |
| 復元しやすさ | 中。TaskScheduler.evtxとの突合が必要 |

これは研究テーマの Persistence に近い。攻撃の永続化に見えうるが、正常な更新・タスク実行として説明できるかを見る。

---

## 7. 正常行動カタログ初版

| 正常行動カテゴリ | 起点になりうるアラート | 主な根拠 | 判断方針 |
|---|---|---|---|
| セキュリティエージェントの監査 | Discovery, net.exe account discovery, SecEdit | 親プロセスが `wazuh-agent.exe`、ユーザーがSYSTEM、コマンドがアカウント/ポリシー確認 | 正常として説明しやすい |
| ブラウザ利用・設定更新 | scripting file, taskschd.dll, privileged operation | `firefox.exe`, `msedge.exe`, プロファイル配下ファイル、ブラウザプロセス | ファイルパスと親子関係で正常判断 |
| Windows Update | DLL search order hijack風アラート | `C:\Windows\SoftwareDistribution\Download\...`、`svchost.exe` | Windows Update文脈なら正常寄り |
| Defender動作 | LSASS access | `MsMpEng.exe` がLSASSを参照 | セキュリティ製品の正常動作として扱うが、根拠確認が必要 |
| ライセンス/Software Protection | scheduled successfully, license activation failed | `sppsvc.exe`, Software Protection, Systemログ | 低優先度のWindows定期処理 |
| 開発・環境構築 | PowerShell, scripting file, file create | Git/Python/JetBrains/SoapUI等の導入済みソフト | 時刻とプロセスが結びつく場合に正常説明 |

---

## 8. 次にやること

1. `C96-DISC-001` について、前後30分の Sysmon EID 1 を抽出する
2. `wazuh-agent.exe -> net.exe -> net1.exe` の連鎖を時系列で並べる
3. 同時刻のWazuh SCA/CISアラートを確認する
4. 「攻撃のDiscoveryではなく、Wazuh監査による正常Discovery」として説明文を書く
5. 同じ形式で `C96-SCRIPT-001` と `C96-TASK-001` を分析する

---

## 9. 現時点の判断

初回の正常行動復元ケースは、Hayabusaではなく Wazuh 起点で十分に開始できる。

特に `C96-DISC-001` は、親プロセスが `wazuh-agent.exe` で、コマンドラインも `net.exe accounts` や `net user administrator` と明確である。攻撃検知であれば account discovery と見えるが、正常ホストでは Wazuh エージェントの監査処理として説明できる可能性が高い。

このケースを最初に完成させると、研究の主張である「アラートを起点に、正常行動として復元する」の最小例になる。
