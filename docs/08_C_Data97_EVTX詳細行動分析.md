# C_Data/97 EVTX詳細行動分析
> 作成日: 2026-04-16  
> 対象: `apt-persistence/Datasets/C_Data/97`  
> 目的: C_Data/97 にどのような正常行動データが含まれているかを具体的に把握し、偽陽性復元ケースとして使える行動を整理する。

---

## 1. 結論

C_Data/97 は、完全な日常業務ログというより、**ソフトウェア導入・ユーザーアプリ初期化・Wazuh監査・Windows/Defender更新が混ざった正常ホスト** である。

ただし、C_Data/96と比べると以下のようなユーザー寄り行動が見える。

- Dropbox のインストール・更新・一時EXE作成
- OneDrive の起動と Explorer 連携
- Discord の起動
- PDF24 の起動と一時ファイル作成
- Microsoft/Windows系のタスク実行
- Wazuh agent によるアカウント/セキュリティ設定監査
- Defender による LSASS 参照

この中で、偽陽性復元ケースとして最も使いやすいのは **Dropbox Update が `C:\Windows\Temp` にEXEを作成し、Wazuhで `Executable dropped in Windows root folder` と検知されたケース** である。

---

## 2. データ全体

### 2.1 EVTX構成

| ログ | サイズ | レコード数 | 役割 |
|---|---:|---:|---|
| Security.evtx | 21,041,152 bytes | 30,179 | ログオン、特権付与、プロセス作成など |
| Sysmon.evtx | 32,575,488 bytes | 25,947 | プロセス、ファイル、レジストリ、DLL、通信など |
| TaskScheduler.evtx | 2,166,784 bytes | 3,348 | タスク実行、ログオン時タスク、UpdateOrchestratorなど |
| System.evtx | 1,118,208 bytes | 1,290 | サービス、DCOM、HTTP予約、時刻同期など |
| Application.evtx | 1,118,208 bytes | 603 | アプリケーションエラー、MSI、アプリイベントなど |

### 2.2 Sysmonの範囲

| 項目 | 内容 |
|---|---|
| 最初のSysmonイベント | 2024-09-06 02:35:44 |
| 最後のSysmonイベント | 2024-09-16 17:54:19 |
| Sysmon総件数 | 25,947 |
| プロセス作成 Event ID 1 | 409 |
| ファイル作成 Event ID 11 | 9,664 |
| レジストリキー作成 Event ID 12 | 5,592 |
| レジストリ値設定 Event ID 13 | 3,701 |
| プロセスアクセス Event ID 10 | 2,686 |
| イメージロード Event ID 7 | 2,660 |

### 2.3 Wazuhアラートの概要

C_Data/97 のWazuhアラートは611件。

上位ルールは以下。

| 件数 | ルール |
|---:|---|
| 78 | Windows logon success. |
| 40 | Discovery activity executed |
| 27 | Process loaded taskschd.dll module. May be used to create delayed malware execution |
| 16 | A net.exe account discovery command was initiated |
| 9 | Summary event of the report's signatures. |
| 6 | Powershell process created an executable file in Windows root folder |
| 5 | Windows User Logoff. |
| 4 | Software protection service scheduled successfully. |
| 4 | Lsass process was accessed by MsMpEng.exe with read permissions |
| 4 | Executable dropped in Windows root folder |

---

## 3. ホストのソフトウェア構成

Description.yml と `install_choco_software.ps1` から、このホストは以下のような「一般ユーザー/クリエイティブ/コミュニケーション寄り」構成である。

| 種別 | ソフト |
|---|---|
| ブラウザ/閲覧 | Firefox, Microsoft Edge |
| 文書/PDF | LibreOffice, Adobe Acrobat, SumatraPDF, PDF24 Creator |
| メディア/制作 | VLC, Audacity, GIMP, Krita, OBS Studio |
| コミュニケーション | Zoom, Discord, Teams, Skype |
| クラウド/同期 | Dropbox, OneDrive |
| 管理/監視 | Wazuh Agent |

`install_choco_software.ps1` では、`libreoffice`, `microsoft-word`, `adobereader`, `teams`, `zoom`, `skype`, `notepadplusplus`, `firefox`, `chrome`, `vlc`, `obs-studio`, `audacity`, `7zip`, `dropbox`, `sumatrapdf`, `pdf24`, `gimp`, `krita`, `discord` などをChocolateyで導入する設定になっている。

したがって、早朝の `choco.exe`, `msiexec.exe`, `setup.exe` 系ログは、ホストプロファイル構築のための正常なセットアップ行動と考える。

---

## 4. 時間帯別の行動

### 4.1 2024-09-06 02:35頃: 初期設定フェーズ

見える行動:

- `setx.exe`
- `mmc.exe`
- `choco.exe`
- `regsvr32.exe`
- `WmiPrvSE.exe`
- `powershell.exe`
- `msedge.exe`

解釈:

環境の初期設定、Chocolatey準備、Windows管理ツール操作に見える。  
Wazuhアラートは目立たないため、復元ケースとしての優先度は低い。

---

### 4.2 2024-09-16 04:00台: MSI/Office系初期化フェーズ

プロセス作成は43件。

主なプロセス:

- `WmiPrvSE.exe`
- `msiexec.exe`
- `regsvr32.exe`
- `FileCoAuth.exe`
- `WerFault.exe`
- `WinSAT.exe`

解釈:

MSIインストール、Office/OneDrive系の共同編集コンポーネント、Windows評価/初期化処理が混ざっている。  
日常行動というより、セットアップ後処理に近い。

---

### 4.3 2024-09-16 05:00台: 大量導入・更新フェーズ

プロセス作成は138件。  
C_Data/97の中で、セットアップ色が最も強い時間帯である。

主なプロセス:

- `wevtutil.exe`
- `WmiPrvSE.exe`
- `regsvr32.exe`
- `choco.exe`
- `rundll32.exe`
- `msiexec.exe`
- `sc.exe`
- `powershell.exe`

この時間帯に見える具体行動:

| 行動 | 根拠 |
|---|---|
| Dropboxインストール | `Dropbox 207.4.5821 Offline Installer.x64.exe` |
| Dropbox Update配置 | `DropboxUpdate.exe`, `DropboxCrashHandler.exe`, `DropboxUpdateOnDemand.exe` |
| Dropboxタスク作成 | `C:\Windows\Tasks\DropboxUpdateTaskMachineUA.job`, `DropboxUpdateTaskMachineCore.job` |
| Chocolateyによるソフト導入 | `choco.exe`, install script上のソフト一覧 |
| .NET/VC++/MSI処理 | `msiexec.exe`, `mscorsvw.exe`, VC++ Runtime |
| Windows/イベントログ処理 | `wevtutil.exe` |

解釈:

この時間帯は、日常利用ではなく、**ホスト構築の正常ログ** である。  
ただし、偽陽性ケースとしては使える。特にDropbox Updateは、後続の17時台にも同じような挙動が出る。

---

### 4.4 2024-09-16 06:00台: Discord導入・更新フェーズ

プロセス作成は37件。

主なプロセス:

- `Discord.exe`
- `Update.exe`
- `DiscordSetup.exe`
- `reg.exe`
- `msiexec.exe`
- `choco.exe`

解釈:

Discordの導入・更新・初期起動が見える。  
この時間帯ではWazuhの強い対応アラートは目立たないが、後続の17時台にユーザーアプリとしてDiscordが起動している。

---

### 4.5 2024-09-16 17:00台: ユーザーログオン後のアプリ初期化・監査フェーズ

プロセス作成は177件。  
C_Data/97で最も研究対象にしやすい時間帯である。

主なプロセス:

- `Dropbox.exe`
- `DropboxUpdate.exe`
- `OneDrive.exe`
- `FileCoAuth.exe`
- `Discord.exe`
- `PDF24.exe`
- `net.exe`
- `net1.exe`
- `SecEdit.exe`
- `wevtutil.exe`
- `MsMpEng.exe`

この時間帯は、以下の複数の正常行動が重なっている。

| 行動 | 主体 | 具体例 |
|---|---|---|
| ユーザーアプリ起動 | user `win11\win11` | PDF24, Discord, OneDrive, Dropbox |
| クラウド同期/更新 | Dropbox, OneDrive | DropboxUpdate, FileCoAuth |
| Wazuh監査 | `wazuh-agent.exe` / SYSTEM | `net.exe accounts`, `net user administrator`, `SecEdit.exe /export` |
| Defender/Windows Security | `MsMpEng.exe` | LSASS参照、証明書/ネットワーク関連レジストリ参照 |
| タスクスケジューラ | Windows scheduled tasks | UpdateOrchestrator, DeviceDirectoryClient, WDI |
| ログ収集 | PowerShell / wevtutil | EVTXのエクスポート |

研究上は、この17時台を中心にケースを作るのがよい。

---

## 5. 行動別の詳細

### 5.1 Dropbox Update

#### 見えた行動

05時台にDropboxがインストールされ、17時台にもDropbox Updateが動いている。

代表的なSysmon:

| 時刻 | Event ID | 内容 |
|---|---:|---|
| 05:40:50 | 11 | Dropbox Offline Installer が `DropboxUpdate.exe` を配置 |
| 05:40:52 | 1 | `DropboxUpdate.exe` 起動 |
| 05:40:55 | 11 | `DropboxUpdateTaskMachineUA.job`, `DropboxUpdateTaskMachineCore.job` 作成 |
| 17:35:50 | 11 | `C:\Windows\Temp\GURC786.tmp` 作成 |
| 17:35:56 | 11 | `C:\Windows\Temp\GURC786.exe` 作成 |
| 17:37:51 | 11 | `C:\Windows\Temp\GUR9FB1.exe` 作成 |

#### 対応するWazuhアラート

| Wazuh時刻 | アラート | 対象 |
|---|---|---|
| 2024-09-16T07:35:57Z | `Executable dropped in Windows root folder` | `C:\Windows\Temp\GURC786.exe` |
| 2024-09-16T07:37:52Z | `Executable dropped in Windows root folder` | `C:\Windows\Temp\GUR9FB1.exe` |

#### 解釈

アラート名だけ見ると、Windows配下に実行ファイルが落とされたように見えるため攻撃っぽい。  
しかし、Sysmonでは作成元が `C:\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe` であり、Dropboxの更新処理と説明できる。

#### 偽陽性ケースとしての価値

非常に高い。

理由:

- 起点アラートが明確
- 対象ファイルが明確
- 作成元プロセスが明確
- 正常アプリの更新処理として説明しやすい

最初の復元ケースはこれがよい。

---

### 5.2 OneDrive / Explorer連携

#### 見えた行動

17時台にOneDriveとFileCoAuthが起動している。

代表的なSysmon:

| 時刻 | Event ID | 内容 |
|---|---:|---|
| 17:36:16 | 1 | `OneDrive.exe /background` が `explorer.exe` から起動 |
| 17:38:46 | 1 | `FileCoAuth.exe -Embedding` が `svchost.exe` から起動 |
| 17:38〜17:40 | 7 | `FileCoAuth.exe` が複数DLLをロード |

#### 対応するWazuhアラート

| Wazuh時刻 | アラート |
|---|---|
| 2024-09-16T07:36:21Z | `Explorer process was accessed by OneDrive.exe, possible process injection` |
| 2024-09-16T07:36:22Z | `Process loaded taskschd.dll module...` |
| 2024-09-16T07:38:48Z | `Explorer process was accessed by OneDrive.exe, possible process injection` |

#### 解釈

OneDriveはExplorerと密接に連携するため、Explorerへのアクセスが発生しても自然である。  
Wazuhはこれを「process injectionの可能性」として拾っている。

#### 偽陽性ケースとしての価値

高い。

ただし、プロセスアクセスの詳細フィールドを追加確認し、アクセス元・アクセス先・権限を明確にする必要がある。

---

### 5.3 Discord起動

#### 見えた行動

17:36頃にDiscordがユーザー文脈で起動している。

代表的なSysmon:

| 時刻 | Event ID | 内容 |
|---|---:|---|
| 17:36:40 | 1 | `Discord\Update.exe --processStart Discord.exe` が `explorer.exe` から起動 |
| 17:36:48 | 1 | `Discord.exe` 起動 |
| 17:36:50〜17:36:53 | 1 | crashpad / gpu / renderer / utility プロセスが派生 |
| 17:38:39 | 13 | BAM配下にDiscord実行痕跡 |

#### 対応するWazuhアラート

C_Data/97では、Discord単体に強く紐づくWazuhアラートは目立たない。

#### 解釈

ユーザーアプリの起動としては非常に分かりやすいが、起点アラートが弱いため、今回の主ケースにはしにくい。

#### 偽陽性ケースとしての価値

中。

C_Data/45ではDiscord由来のExplorerアクセスアラートが多いため、DiscordケースはC_Data/45で扱う方がよい。

---

### 5.4 PDF24起動

#### 見えた行動

PDF24がExplorerから起動し、一時ファイルやログを作成している。

代表的なSysmon:

| 時刻 | Event ID | 内容 |
|---|---:|---|
| 17:23:00 | 1 | `PDF24\pdf24.exe` が `explorer.exe` から起動 |
| 17:35:25 | 11 | `C:\Windows\Temp\pdf24.exe.stdout...log` 作成 |
| 17:35:25 | 11 | `C:\Windows\Temp\pdf24_write_test...` 作成 |
| 17:36:15 | 1 | `PDF24\pdf24.exe` 再起動 |

#### 対応するWazuhアラート

PDF24単体に強く紐づくWazuhアラートは未確認。

#### 解釈

日常アプリ起動としては良いが、起点アラートが弱い。  
復元ケースではなく、C_Data/97が日常アプリを含む根拠として使う。

---

### 5.5 Wazuh監査

#### 見えた行動

17時台にWazuh agentがアカウント・セキュリティ設定を確認している。

代表的なSysmon:

| 時刻 | Event ID | 内容 |
|---|---:|---|
| 17:36:07 | 1 | `wazuh-agent.exe -> net.exe user administrator` |
| 17:36:07 | 1 | `wazuh-agent.exe -> net.exe user guest` |
| 17:36:08 | 1 | `wazuh-agent.exe -> net.exe accounts` |
| 17:36:08 | 1 | `wazuh-agent.exe -> powershell.exe` |
| 17:36:10 | 1 | `powershell.exe -> SecEdit.exe /export /cfg C:\Windows\TEMP/secexport.cfg` |

#### 対応するWazuhアラート

| アラート | 内容 |
|---|---|
| `Discovery activity executed` | `net.exe accounts` |
| `A net.exe account discovery command was initiated` | `net user administrator`, `net user guest` |
| `SecEdit.exe binary in a suspicious location...` | `SecEdit.exe /export` |
| CIS benchmark/SCA系 | セキュリティ設定の監査結果 |

#### 解釈

攻撃者のDiscoveryに見えるが、親プロセスが `wazuh-agent.exe` であり、SYSTEM権限で動くWazuhの監査処理である。

#### 偽陽性ケースとしての価値

高い。

ただし、C_Data/96と同型であり、C_Data/97の主ケースとしてはDropbox/OneDriveの方が日常行動寄りでよい。

---

### 5.6 Defender / LSASSアクセス

#### 見えた行動

Defender (`MsMpEng.exe`) がLSASSやシステム証明書、ネットワーク関連レジストリにアクセスしている。

#### 対応するWazuhアラート

| Wazuh時刻 | アラート |
|---|---|
| 2024-09-16T07:35:40Z | `Lsass process was accessed by MsMpEng.exe with read permissions, possible credential dump` |
| 2024-09-16T08:04:05Z | 同種アラート |

#### 解釈

LSASSアクセスは攻撃では credential dumping として重要だが、アクセス元がMicrosoft Defenderであるため、正常なセキュリティ製品の動作として説明できる可能性が高い。

#### 偽陽性ケースとしての価値

高い。

ただし、Defender内部動作は説明がやや難しいため、Dropboxケースの次に扱うのがよい。

---

## 6. Securityログから見える文脈

抽出対象イベント:

- 4624: ログオン成功
- 4634: ログオフ
- 4647: ユーザー開始ログオフ
- 4672: 特権ログオン
- 4688: プロセス作成

件数:

| Event ID | 件数 | 意味 |
|---:|---:|---|
| 4624 | 522 | ログオン成功 |
| 4672 | 492 | 特権ログオン |
| 4688 | 66 | プロセス作成 |
| 4634 | 18 | ログオフ |
| 4647 | 5 | ユーザー開始ログオフ |

時間帯別では、17時台に以下が集中している。

| 時間帯 | 4624 | 4672 | 4688 |
|---|---:|---:|---:|
| 2024-09-16 17:00 | 202 | 191 | 22 |

解釈:

17時台はユーザーログオン後の初期化・サービスログオン・監査処理が集中している。  
Dropbox/OneDrive/Discord/PDF24のユーザーアプリ行動と、Wazuh/Defender/TaskSchedulerのシステム行動が同じ時間帯に重なる。

---

## 7. TaskScheduler / Systemログから見える文脈

TaskSchedulerでは、17:50頃に以下のようなタスク実行が見える。

| タスク | 内容 |
|---|---|
| `\Microsoft\Windows\WlanSvc\CDSSync` | ユーザー `win11\win11` のタスク完了 |
| `\Microsoft\Windows\DeviceDirectoryClient\RegisterUserDevice` | ユーザーログオン起因の登録タスク、失敗あり |
| `\Microsoft\Windows\WDI\ResolutionHost` | 診断基盤タスク |
| `\Microsoft\Windows\UpdateOrchestrator\Schedule Work` | `usoclient.exe` 実行、Windows Update関連 |
| `\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker` | 起動失敗あり |

Systemログでは、17時台に以下が見える。

- Service Control Manager: BITSの起動種別変更
- DistributedCOM 10016: Windows Security系COM権限エラー
- Time-Service: `time.windows.com` のDNS解決失敗
- Kernel-Power: SessionUnlock
- Winlogon: ユーザーログオン通知
- HTTP Service: URL予約

解釈:

17時台は、ユーザーログオン後にWindowsのタスク、更新、セキュリティ、クラウド同期、アプリ初期化が一斉に動いた時間帯である。  
そのため、攻撃っぽいアラートが出ても、周辺文脈は正常初期化として説明できる可能性がある。

---

## 8. C_Data/97に含まれる行動イメージ

C_Data/97の行動は、次のようにイメージできる。

1. まず、Chocolateyで一般ユーザー向けソフトが導入される。
2. Dropbox、Adobe、PDF24、LibreOffice、Zoom、Discordなどのインストーラ/更新処理が動く。
3. その後、ユーザー `win11` がログオンする。
4. ログオン後、PDF24、OneDrive、Dropbox、Discordなどが起動する。
5. 同じ時間帯に、Wazuh agent が設定監査を行い、`net.exe` や `SecEdit.exe` を実行する。
6. DefenderやWindows Update、TaskSchedulerも後処理・更新・診断を行う。
7. Wazuhはこれらの一部を、Discovery、process injection、credential dump、executable drop、taskschd.dll としてアラート化する。

つまり、このホストは **ユーザーアプリの初期化とセキュリティ/管理系の監査が同じ時間帯に重なる正常ホスト** である。

---

## 9. 偽陽性復元ケース候補

| 優先度 | ケース | 起点アラート | 正常行動仮説 | 採用判断 |
|---:|---|---|---|---|
| 1 | Dropbox Update | `Executable dropped in Windows root folder` | Dropbox更新が `C:\Windows\Temp` に一時EXEを作成 | 最優先 |
| 2 | OneDrive / Explorer | `Explorer process was accessed by OneDrive.exe` | OneDriveのExplorer連携 | 採用候補 |
| 3 | Wazuh監査 | `Discovery activity executed`, `net.exe account discovery`, `SecEdit.exe` | Wazuh agent の設定監査 | 採用候補 |
| 4 | Defender / LSASS | `Lsass process was accessed by MsMpEng.exe` | Defenderの正常監視 | 採用候補 |
| 5 | PDF24起動 | 直接対応アラート弱め | PDFアプリの通常起動 | 背景説明用 |
| 6 | Discord起動 | 直接対応アラート弱め | コミュニケーションアプリ起動 | 背景説明用 |

---

## 10. 次に作るべきケース

最初に作るべきケースは以下。

### C97-CASE-001: Dropbox UpdateによるWindows TempへのEXE作成

起点:

- Wazuh: `Executable dropped in Windows root folder`
- 対象ファイル: `C:\Windows\Temp\GURC786.exe`, `C:\Windows\Temp\GUR9FB1.exe`
- 作成元: `C:\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe`

前後で見るべきログ:

| ログ | 見る内容 |
|---|---|
| Sysmon EID 1 | Dropbox/DropboxUpdateの起動親子関係 |
| Sysmon EID 11 | Temp配下EXE作成 |
| Sysmon EID 12/13 | DropboxUpdateによるレジストリ参照/更新 |
| Sysmon EID 22 | DropboxUpdateのDNS通信 |
| Wazuh | `Executable dropped` アラート |
| Security | 同時刻のログオン主体 |

判定仮説:

> 攻撃ではなく、Dropboxの正常な更新処理である。  
> ただし、Windows Temp配下にEXEを作成するため、検知ルール上は攻撃的な挙動に見える。

