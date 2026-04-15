# C_Data/96 ホスト行動タイムライン整理
> 作成日: 2026-04-15  
> 対象: `apt-persistence/Datasets/C_Data/96`  
> 目的: このホストで「いつ、何が起きていたのか」を先に理解し、次に何を取得すべきかを整理する。

---

## 1. まず結論

C_Data/96 は、ログ期間としては `2024-09-08 06:41` から `2024-09-16 17:57` まである。

ただし、203時間ずっと行動が記録されているわけではない。Sysmon上で濃い行動が見えているのは、主に以下の時間帯である。

| 時間帯 | 大まかな意味 |
|---|---|
| 2024-09-08 06:41頃 | 初期確認、Sysmon設定確認、タスクスケジューラ/GPO確認 |
| 2024-09-16 04:15〜07:06頃 | Chocolateyを使った大量ソフトウェア導入、Windows Update、Defender更新 |
| 2024-09-16 17:13〜17:57頃 | ユーザーログオン後の初期化、Google/Chrome/OneDrive、Wazuh監査、ブラウザ起動 |

Wazuhアラートは主に `2024-09-16 17:31〜18:03` 付近に集中している。  
つまり、**ホスト全体の行動理解はSysmonで行い、アラート起点の分析はWazuhで行う**、という分け方が必要。

---

## 2. 頭を整理するための見取り図

今見ている情報は、3層に分けると分かりやすい。

| 層 | 何を見るか | 役割 |
|---|---|---|
| ホスト全体の行動 | Sysmon全体、Description.yml | この端末で何が起きていたかを理解する |
| アラート化された行動 | Wazuh alerts.json | どの正常行動が怪しいと判定されたかを見る |
| 復元対象ケース | 起点アラート前後30分 | 1つのアラートから関連ログをたどる |

いま混乱しやすい理由は、**ホスト全体の時系列**と**Wazuhアラートの時系列**が同じではないからである。

Sysmonでは 9/16 早朝から大量のソフト導入が見える。  
一方、Wazuhアラートは 9/16 夕方のWazuh監査・ブラウザ利用・権限監査に集中している。

---

## 3. 作成済みの中間ファイル

| ファイル | 内容 |
|---|---|
| `C_Data96_Sysmon_flat.csv` | Sysmonを1イベント1行に展開したもの |
| `C_Data96_Sysmon_hourly_summary.csv` | Sysmonを時間帯別に集計したもの |
| `C_Data96_ProcessCreate_hourly.csv` | Sysmon EID 1、つまりプロセス生成を時間帯別に集計したもの |
| `C_Data96_Wazuh_alerts_flat.csv` | Wazuhアラートを1イベント1行に展開したもの |
| `C_Data96_Wazuh_hourly_summary.csv` | Wazuhアラートを時間帯別に集計したもの |
| `C_Data96_起点アラート分類表.csv` | Wazuhルール単位の起点分類表 |

注意: 時刻は基本的にWindows/PowerShellで表示された時刻を使っている。Wazuhの `@timestamp` はUTC由来なので、資料上では時刻の基準をそろえる必要がある。

---

## 4. 時間帯別の全体像

### 4.1 2024-09-08 06:41頃: 初期確認フェーズ

この時間帯はイベント数は少ないが、人間または自動操作による確認っぽい行動が見える。

| 時刻 | 見えた行動 | 根拠 |
|---|---|---|
| 06:41 | WMI Provider起動 | `WmiPrvSE.exe` |
| 06:41 | Sysmon設定ファイルをNotepadで開く | `notepad.exe ... sysmon.xml` |
| 06:41 | タスクマネージャ起動 | `Taskmgr.exe` |
| 06:41 | タスクスケジューラ管理画面を開く | `mmc.exe taskschd.msc` |
| 06:42 | グループポリシーエディタを開く | `mmc.exe gpedit.msc` |

解釈:

この時点では、通常のユーザー作業というより、環境確認・監査設定確認に見える。  
`taskschd.msc` や `gpedit.msc` が出ているため、後の「TaskScheduler / Persistence類似」系アラートを見るときの背景になる。

未確認:

- これがGhost NPCによる操作なのか、環境セットアップなのか
- Securityログ上のログオン情報

---

### 4.2 2024-09-16 04:15〜04:59: 更新・インストーラ開始フェーズ

この時間帯からログが急に濃くなる。主にEdge Update、DISM、一部JetBrains製品のインストールが見える。

| 時刻 | 見えた行動 | 根拠 |
|---|---|---|
| 04:15 | Microsoft Edge Update実行 | `MicrosoftEdgeUpdate.exe` |
| 04:15 | DISM Host起動 | `DismHost.exe` |
| 04:22 | PyCharmインストーラ起動 | `pycharm-professional-2024.2.1.exe` |
| 04:42 | Windows Update関連処理 | `wuauclt.exe` |
| 04:49 | RubyMineインストーラ起動 | `RubyMine-2024.2.1.exe`, parent=`choco.exe` |

解釈:

この時間帯は、開発環境の構築が始まっている。  
`Description.yml` にも PyCharm、RubyMine、GoLand、Git、Python などがあるため、インストール済みソフト一覧と整合する。

アラート化しやすいポイント:

- インストーラが一時フォルダから起動する
- `DismHost.exe` が動く
- 更新系プロセスが大量のファイル/レジストリ変更を行う

---

### 4.3 2024-09-16 05:00〜05:59: Chocolatey大量インストールフェーズ

この時間帯はかなり重要。Sysmonのイベント数が多く、正常行動の大部分はここに集中している。

| 見えた行動 | 具体例 |
|---|---|
| Chocolateyによるソフト導入 | `choco.exe install firefox -y`, `choco.exe install goland -y`, `choco.exe install 7zip -y`, `choco.exe install notepadplusplus -y` |
| Chrome/Google Updater | `GoogleUpdater`, `Chrome setup.exe`, `crashpad-handler` |
| Firefoxインストール | `Firefox Setup 130.0.exe` |
| Notepad++インストール | `npp.8.6.9.Installer.x64.exe`, `regsvr32 NppShell.dll` |
| .NET/Chocolatey shim生成 | `shimgen.exe -> csc.exe` |
| Windows Installer | `msiexec.exe` |
| Windows Updateタスク操作 | `schtasks.exe -delete`, `schtasks.exe -create` |

解釈:

この時間帯は「開発者端末のソフトウェア導入」と考えるのが自然。  
一時フォルダ、PowerShell、`choco.exe`, `msiexec.exe`, `regsvr32.exe`, `csc.exe`, `schtasks.exe` が出るため、攻撃っぽいログが大量に出やすい。

正常行動として説明できそうなもの:

- Chocolateyによるソフト導入
- インストーラによるファイル作成
- `regsvr32` によるシェル拡張登録
- `csc.exe` によるChocolatey shim生成
- `schtasks.exe` によるWindows Update関連タスクの更新

アラート化しやすいポイント:

- PowerShell実行
- 一時フォルダ配下のEXE起動
- スクリプト/ファイル生成
- `schtasks.exe`
- `regsvr32.exe`

この時間帯を復元するなら:

> 「Chocolateyによる開発環境構築」という正常行動を大きな単位として復元する。

ただし、イベント数が多いので最初の1ケースには重い。

---

### 4.4 2024-09-16 06:00〜06:59: Defender更新 + Git/GIMP/.NET導入フェーズ

この時間帯は、Defender更新と開発系ソフト導入が混ざっている。

| 時刻 | 見えた行動 | 根拠 |
|---|---|---|
| 06:02〜06:09 | Defender更新 | `MpSigStub.exe`, `MpRecovery.exe`, `MsMpEng.exe` |
| 06:09 | Defender関連イベントマニフェスト再登録 | `MsMpEng.exe -> wevtutil.exe install/uninstall-manifest` |
| 06:20 | GIMPインストール | `gimp-2.10.38-setup.exe` |
| 06:21 | Git Extensions導入 | `choco.exe install gitextensions -y` |
| 06:25〜06:26 | Gitインストール・設定 | `Git-2.46.0-64-bit.tmp`, `git.exe config --system ...` |
| 06:29〜06:35 | Visual C++/.NET導入 | `VC_redist.x86.exe`, `VC_redist.x64.exe`, `windowsdesktop-runtime` |

解釈:

ここも正常な環境構築・更新処理が中心。  
特にDefenderは `wevtutil.exe` を大量に呼ぶため、攻撃っぽく見えやすいが、親プロセスが `MsMpEng.exe` である点が正常説明の根拠になる。

正常行動として説明できそうなもの:

- Defender定義/プラットフォーム更新
- Git導入時の `git.exe config --system`
- GIMP/.NET/VC++ランタイム導入

アラート化しやすいポイント:

- `wevtutil.exe`
- `taskkill.exe`
- `git.exe config`
- 一時フォルダ配下のインストーラ
- VC++/MSI系の大量ファイル生成

---

### 4.5 2024-09-16 07:00〜07:06: Defender/Google/印刷系の後処理フェーズ

この時間帯は、06時台の続きとして、Defender・Google Updater・印刷系DLL登録などが見える。

| 見えた行動 | 根拠 |
|---|---|
| Defenderイベントマニフェスト再登録 | `MsMpEng.exe -> wevtutil.exe` |
| Google Updater | `GoogleUpdater` |
| WinHTTP AutoProxy | `svchost.exe -s WinHttpAutoProxySvc` |
| 印刷設定DLL登録 | `spoolsv.exe -> regsvr32.exe PrintConfig.dll` |

解釈:

インストールや更新の後処理に見える。  
復元対象としては、単独で扱うより「更新・環境構築フェーズの一部」としてまとめるのがよい。

---

### 4.6 2024-09-16 17:13〜17:31: ユーザーログオン後の初期化フェーズ

夕方にもう一度ログが濃くなる。ここはユーザーセッション開始後の初期化に見える。

| 時刻 | 見えた行動 | 根拠 |
|---|---|---|
| 17:13 | Google Updater / Defender関連処理 | `GoogleUpdater`, `MsMpEng.exe -> wevtutil.exe` |
| 17:16 | Windows Updateサービス起動 | `sc.exe start wuauserv` |
| 17:22 | Chromeユーザー設定 | `chrmstp.exe --configure-user-settings` |
| 17:22 | AppX/Edge関連初期化 | `rundll32.exe AppXDeployment...`, `EDGEHTML.dll` |
| 17:23 | Security Health起動 | `SecurityHealthSystray.exe` |
| 17:23 | OneDrive起動・旧ファイル削除 | `OneDrive.exe`, `cmd.exe del/rmdir OneDriveSetup.exe` |

解釈:

これは「ユーザーがログオンした後、ブラウザ・OneDrive・Windows関連サービスが初期化された」時間帯に見える。

この直後にWazuh監査が始まるため、Wazuhアラートの前後文脈として重要。

---

### 4.7 2024-09-16 17:31〜17:32: Wazuh監査フェーズ

ここが、最初に復元すべきアラート群。

| 時刻 | 見えた行動 | 根拠 |
|---|---|---|
| 17:31 | Wazuh停止/起動 | `restart-wazuh.exe -> cmd.exe -> net.exe stop/start Wazuh` |
| 17:31 | アカウントポリシー確認 | `wazuh-agent.exe -> net.exe accounts -> net1.exe accounts` |
| 17:31 | 管理者/Guest確認 | `net user administrator`, `net user guest` |
| 17:31 | レジストリ確認 | `reg query ... legalnoticecaption`, `legalnoticetext` |
| 17:31 | セキュリティ設定エクスポート | `wazuh-agent.exe -> powershell.exe -> SecEdit.exe /export` |

解釈:

これは攻撃ではなく、Wazuhエージェントによる設定監査・SCAの正常動作と考えるのが自然。  
ただし、アラート名だけ見ると `Discovery activity executed` や `account discovery` に見える。

研究上の価値:

> 「攻撃のDiscoveryに見えるが、親プロセスと周辺文脈からWazuh監査の正常行動と復元できる」

最初の復元ケースはこれがよい。

---

### 4.8 2024-09-16 17:35〜17:57: ブラウザ・更新・権限監査フェーズ

この時間帯は、Wazuhアラート上では `Failed attempt to perform a privileged operation` が多く出る。

主なプロセス:

- `msedge.exe`
- `firefox.exe`
- `dllhost.exe`
- `explorer.exe`
- `svchost.exe`

見えている行動:

- ブラウザ起動・設定ファイル更新
- Firefoxプロファイル配下の `prefs.js` / `prefs-1.js` 生成
- Edge/Chrome/Google Updater関連処理
- COM/Windowsサービス系の権限要求失敗

解釈:

この時間帯は、「ユーザーがブラウザを使い始め、Windows/ブラウザ/サービスが初期化され、Security監査で特権操作失敗が大量に出た」と見るのが自然。

研究対象としては、`Failed attempt to perform a privileged operation` は件数が多すぎるので初手には重い。  
代わりに `firefox.exe -> prefs.js` の方が、正常説明しやすい。

---

## 5. 今わかっていること

### わかっていること

| 項目 | 内容 |
|---|---|
| ホストの性格 | Windows 10 Pro の開発者寄り端末 |
| 導入ソフト | Git, Python, PyCharm, GoLand, RubyMine, SoapUI, Azure Data Studio, Firefox, Chrome など |
| 濃い行動の中心 | 2024-09-16 のソフト導入、更新、Wazuh監査、ブラウザ初期化 |
| 最初に復元しやすい行動 | Wazuh監査による `net.exe` / `SecEdit.exe` 実行 |
| 攻撃っぽく見える正常行動 | account discovery、PowerShell、SecEdit、taskschd.dll、DefenderのLSASS参照、Windows Update DLL配置 |

### まだ確定していないこと

| 未確定事項 | 何を見ればよいか |
|---|---|
| 9/16 04〜07時台のソフト導入を誰が開始したか | 親プロセス、ログオン情報、Security 4624 |
| Chocolatey実行の最初の親プロセス | `powershell.exe` の親プロセス、起動元 |
| Wazuh監査がSCAとして開始された根拠 | WazuhアラートのSCA時刻、Wazuh agentログがあれば確認 |
| Firefoxの `prefs.js` 作成がブラウザ起動に伴うものか | 前後のFirefoxプロセス起動、ファイル作成時系列 |
| `taskschd.dll` 読み込みがどのタスクと対応するか | TaskScheduler.evtx の同時刻イベント |
| Securityの特権操作失敗が何に由来するか | Security EID 4673 の processName別代表例、同時刻Sysmon |

---

## 6. 次に取得すべき情報

混乱を避けるため、次に取得する情報は3つに絞る。

### 6.1 最優先: Wazuh監査ケースの前後30分

対象:

- `2024-09-16 17:31` 前後
- `wazuh-agent.exe`
- `net.exe`
- `net1.exe`
- `reg.exe`
- `powershell.exe`
- `SecEdit.exe`

取得するもの:

| ログ | 見る内容 |
|---|---|
| Sysmon EID 1 | プロセス親子関係とコマンドライン |
| Sysmon EID 11 | `secexport.cfg` やPowerShell一時ファイル |
| Security EID 4624 | SYSTEMログオン/サービスログオンの文脈 |
| Wazuhアラート | SCA/CISチェックが同時刻に出ているか |

目的:

> `Discovery activity executed` を「Wazuh監査による正常Discovery」として復元する。

---

### 6.2 次点: Firefox prefs.js ケースの前後30分

対象:

- `2024-09-16 17:01〜18:03` 付近
- `firefox.exe`
- `prefs.js`
- `prefs-1.js`

取得するもの:

| ログ | 見る内容 |
|---|---|
| Sysmon EID 1 | Firefox起動時刻、親プロセス |
| Sysmon EID 11 | Firefoxプロファイル配下のファイル作成 |
| Security EID 4673 | Firefox由来の特権操作失敗 |

目的:

> `Scripting file created` を「ブラウザ設定ファイル更新」として復元する。

---

### 6.3 余裕があれば: Chocolatey環境構築フェーズ

対象:

- `2024-09-16 05:00〜06:35`
- `choco.exe`
- `powershell.exe`
- `msiexec.exe`
- `regsvr32.exe`
- `csc.exe`
- `git.exe`

取得するもの:

| ログ | 見る内容 |
|---|---|
| Sysmon EID 1 | インストールの親子関係 |
| Sysmon EID 11 | インストーラ・一時ファイル作成 |
| Sysmon EID 13 | レジストリ変更 |
| Description.yml | 導入済みソフトとの照合 |

目的:

> 「開発者端末の環境構築」という大きな正常行動を復元する。

注意:

これはログ量が多いので、最初のケースにすると重い。まずWazuh監査ケースを終えてから扱う。

---

## 7. 研究としての優先順位

| 優先度 | ケース | 理由 |
|---:|---|---|
| 1 | Wazuh監査による `net.exe` / `SecEdit.exe` | 親子関係が明確で、攻撃っぽい正常行動として説明しやすい |
| 2 | Firefox `prefs.js` 作成 | アラート名と実態のズレを説明しやすい |
| 3 | taskschd.dll 読み込み | Persistence研究テーマに近いが、TaskSchedulerとの突合が必要 |
| 4 | Defender/Windows Update | 正常説明はできそうだが、システム内部処理が多い |
| 5 | Chocolatey大量導入 | 重要だがイベント数が多く、分析が重い |

---

## 8. 迷ったときの判断ルール

今後このホストを見るときは、以下の順で考える。

1. まず時間帯を見る
2. その時間帯がどのフェーズかを決める
3. 起点アラートを1つだけ選ぶ
4. 前後30分だけ見る
5. 主体、行為、対象、連鎖、根拠に分ける
6. 正常 / 正常寄り / 判断不能 にする

一度に全部のアラートを理解しようとしない。  
このホストは、まず「Wazuh監査フェーズ」と「ブラウザ設定更新フェーズ」だけ理解できれば、研究の第一段階として十分に進む。

---

## 9. 一言でいうと

C_Data/96 は、開発者向けソフトを大量に導入した後、Windows/Defender/Google/OneDriveの更新・初期化が走り、最後にWazuh監査とブラウザ利用が行われた正常ホストである。

この中で最初に復元すべきなのは、`2024-09-16 17:31` 頃の Wazuh監査である。  
理由は、`Discovery activity executed` という攻撃っぽいアラートが出ているが、親プロセスが `wazuh-agent.exe` であり、正常な設定監査として説明できる可能性が高いからである。
