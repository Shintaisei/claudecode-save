# APT-Persistence データセット 正常行動分析レポート

**対象マシン**: C_Data/25, C_Data/27, C_Data/28, C_Data/30（記録期間が長い4台）  
**分析目的**: 正常行動の洗い出し・タイムライン復元・誤検知パターンの特定  
**分析者**: 自動分析スクリプト（PowerShell + Sysmon/Security/Wazuh解析）  
**作成日**: 2026-04-14

---

## 1. 分析対象マシン概要

| マシン | OS | 記録期間 | Sysmonイベント総数 | ユーザー名 |
|--------|-----|----------|--------------------|------------|
| C_Data/25 | Windows 10 | 2024/09/06 02:35 〜 09/09 04:19 (**~2.7日**) | 35,323 | 不明 |
| C_Data/27 | Windows 10/11 | 2024/09/06 02:35 〜 09/09 20:05 (**~3.7日**) | 39,898 | 不明 |
| C_Data/28 | Windows 10/11 | 2024/09/06 00:27 〜 09/09 19:59 (**~3.8日**) | 31,565 | 不明 |
| C_Data/30 | Windows 10 Home | 2024/09/05 23:33 〜 09/09 22:59 (**~4.0日**) | ※詳細分析対象 | win10 |

**C_Data/30** を主対象として詳細分析を実施。OS: Windows 10 Home 10.0.19045（64bit）

---

## 2. C_Data/30 インストール済みソフトウェア（Description.yml）

すべてChocolateyパッケージマネージャー経由でインストール。

| ソフトウェア | バージョン | インストール日 |
|--------------|------------|----------------|
| Firefox (x64) | 129.0.2 | 起動時から |
| Notepad++ (64bit) | 8.6.9 | 起動時から |
| VLC media player | 3.0.21 | 起動時から |
| Wireshark | 4.4.0 | 起動時から |
| Zotero | 7.0.3 | 起動時から |
| 7-Zip | 24.08 | 起動時から |
| WinMerge | 2.16.42.1 | **2024-09-09** |
| VeraCrypt | 1.26.14 | **2024-09-09** |
| Google Chrome | 128.0.6613.120 | **2024-09-09** |
| Zoom Workplace | 6.1.45504 | **2024-09-09** |
| Microsoft VSCode | 1.93.0 | **2024-09-09** |
| WinSCP | 6.3.4 | **2024-09-09** |
| Microsoft Edge | 128.0.2739.67 | **2024-09-09** |
| Wazuh Agent | 4.8.1 | **2024-09-09** |

> **観察**: 09/09に大量のソフトウェアがインストールされている。これはGHOSTSフレームワークが`install_choco_software.ps1`を実行したタイミング（データ収集前の環境構築最終フェーズ）。

---

## 3. C_Data/30 タイムライン（実データから復元）

### フェーズ1: OOBE/初期セットアップ（09/05 夜）

```
2024-09-05 23:33  defaultuser0 ログオン (Type=2) — Windows OOBE セットアップ
2024-09-05 23:43  win10 ログオン (Type=2) — 最初のユーザーアカウントログオン
2024-09-06 00:09  win10 ログオン (Type=2) — デスクトップセッション開始
2024-09-06 00:27  WmiPrvSE.exe 起動 — WMIプロバイダ初期化
2024-09-06 00:28  Microsoft Edge recovery service 起動
2024-09-06 00:28  MicrosoftEdgeUpdate.exe — Edgeアップデーター初期化
```

### フェーズ2: 安定稼働期（09/06 〜 09/09 朝）

主に自動バックグラウンドタスクのみ。Sysmonログに目立った人間操作なし。

```
【繰り返し発生する自動タスク（3日間）】
- svchost.exe → WmiPrvSE.exe     WMIプロバイダ (14回/4日)
- wazuh-agent.exe → net.exe      Wazuhエージェントヘルスチェック (29回)
- net.exe → net1.exe             net コマンド内部実行 (28回)
- MicrosoftEdgeUpdate             Edge自動アップデート確認 (複数回/日)
- Windows Defender スキャン       定期スキャン (2回)
- sppsvc.exe                     ソフトウェア保護サービス (ライセンス確認)
```

### フェーズ3: ソフトウェア大量インストール（09/09 20:23〜）

```
2024-09-09 20:22  システム再起動 (DWM-1/UMFD-1 再ログオン)
2024-09-09 20:23  win10 ログオン (Type=2)
2024-09-09 20:23  explorer.exe → cmd.exe (2回) — GHOSTSコマンド実行
2024-09-09 20:24  powershell.exe 起動 (無名親プロセス) — install_choco_software.ps1
2024-09-09 20:24  rundll32.exe — DLL実行
2024-09-09 20:24  msedge.exe — Edge起動 (GHOSTS Web閲覧シミュレーション)
2024-09-09 20:25  OneDriveSetup.exe — OneDriveアップデート
2024-09-09 20:26  notepad.exe (2回) — ファイル閲覧 (GHOSTS)
2024-09-09 20:27  csc.exe (PowerShell経由) — .NET コンパイル
2024-09-09 20:30〜 OneDrive更新、EdgeWebView2セットアップ
      ↓
2024-09-09 ~21:00 Chocolatey大量インストール開始:
  powershell.exe → choco.exe (15回)
  choco.exe → msiexec.exe → VC_redist、VLC、WinMerge、VeraCrypt...
  shimgen.exe → csc.exe (4回) — Chocoシム生成
  mscorsvw.exe (431件のFileCreate) — .NETネイティブ最適化
2024-09-09 21:48  win10 再ログオン (再起動後)
2024-09-09 22:59  最終イベント (記録終了)
```

---

## 4. 正常行動カタログ

### 4.1 Windowsシステム自動行動

| 行動パターン | プロセスチェーン | EventID | 頻度 | 説明 |
|--------------|-----------------|---------|------|------|
| WMIプロバイダ | `svchost.exe → WmiPrvSE.exe` | EID 1 | 14回/4日 | WMIクエリ処理 |
| Windowsアップデート確認 | `svchost.exe → sihclient.exe` | EID 1, 3(port 3128) | 毎日 | Windows Update インテリジェンス |
| .NET最適化 | `svchost.exe → mscorsvw.exe → ngen.exe` | EID 1, 11(431件) | インストール後 | .NETアセンブリ最適化 |
| Edgeアップデート | `svchost.exe → MicrosoftEdgeUpdate.exe` | EID 1, 3(port 3128) | 定期 | Edge自動更新 |
| Defender定期スキャン | `MsMpEng.exe → wevtutil.exe` (C_Data/27) | EID 1 | 52回/4日 | Defenderがイベントログ参照 |
| ソフトウェア保護 | `sppsvc.exe` | EID 11(30件) | 4〜6時間毎 | Windows ライセンス確認 |
| レジストリ自動設定 | `services.exe → (レジストリ)` | EID 13 (469件) | サービス起動時 | サービス設定記録 |
| OneDrive同期 | `OneDrive.exe → OneDriveSetup.exe` | EID 1, 13(47件) | ログオン時 | クラウド同期 |
| WFPフィルター変更 | `svchost.exe` | Security EID 5447 | サービス起動時 | ネットワークフィルター更新 |

### 4.2 GHOSTSフレームワーク（ユーザー模擬）行動

| 行動パターン | プロセスチェーン | 説明 |
|--------------|-----------------|------|
| Web閲覧シミュレーション | `explorer.exe → msedge.exe → proxy:3128` | Edge経由でランダムWebアクセス |
| ファイル閲覧 | `explorer.exe → notepad.exe` | テキストファイルを開く |
| スクリプト実行 | `explorer.exe → cmd.exe → powershell.exe` | バッチ・PowerShellスクリプト |
| DNSランダムクエリ | `Vysor.exe → DNS(ランダム文字列)` | GHOSTS生成ランダムDNSクエリ（例: `dazdsogdobuaxhd`, `pzjeurasebxh`） |
| Android操作模擬 | `Vysor.exe → adb.exe:5037` | Android画面ミラーリング (GHOSTS) |
| ログ収集 | `powershell.exe → Compress-Archive → logs.zip` | GHOSTS収集スクリプト |
| ソフトインストール | `explorer.exe → cmd.exe → powershell.exe → choco.exe` | GHOSTS環境構築 |

### 4.3 スケジュールタスク（正常）

C_Data/30 TaskScheduler.evtx - 1107イベント（EID 200=起動154回）

| タスク名 | 起動回数 | 説明 |
|---------|--------|------|
| `\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures` | 6 | Windows機能フラグ同期 |
| `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` | 6 | Windows設定キャッシュ更新 |
| `\Microsoft\Windows\Windows Error Reporting\QueueReporting` | 5 | エラーレポート送信 |
| `\MicrosoftEdgeUpdateTaskMachineUA` | 5 | Edge更新確認 |
| `\Microsoft\Windows\LanguageComponentsInstaller\Installation` | 5 | 言語パックインストール |
| `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork` | 4 | ライセンスサービス再起動 |
| `\MicrosoftEdgeUpdateTaskMachineCore` | 4 | Edgeコアアップデート |
| `\Microsoft\Windows\CertificateServicesClient\UserTask-Roam` | 4 | 証明書ローミング更新 |
| `\Microsoft\Windows\.NET Framework\.NET Framework NGEN` | 3 | .NET最適化 |
| `\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance` | 2 | Defenderキャッシュ整理 |
| `\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan` | 2 | Defender定期スキャン |
| `\GoogleSystem\GoogleUpdater\...` | 3 | Google Updater |

### 4.4 ネットワーク正常通信パターン

| プロセス | 宛先 | ポート | 件数 | 説明 |
|----------|------|-------|------|------|
| svchost.exe | proxy.intra.rma.ac.be | 3128 | 3177 | Windows自動更新・テレメトリがITプロキシ経由 |
| choco.exe | proxy.intra.rma.ac.be | 3128 | 71 | Chocolateyパッケージダウンロード |
| msedge.exe | proxy.intra.rma.ac.be | 3128 | 59 | Edge Web閲覧 |
| SearchApp.exe | proxy.intra.rma.ac.be | 3128 | 48 | Windows検索クラウド機能 |
| adb.exe | localhost | 5037 | 6 | Android Debug Bridge (Vysor) |
| Vysor.exe | DNS | 53 | 5 | DNS解決 |

**DNS クエリパターン**（EID 22 - 153件）:
- `proxy.intra.rma.ac.be` (108件) — 機関プロキシ
- `wpad` / `wpad.intra.rma.ac.be` (13件) — プロキシ自動検出
- GHOSTS生成ランダム文字列: `dazdsogdobuaxhd`, `pzjeurasebxh`, `qtedcexeyqqdrrg`, `txgrboyj` 等
- `winscp.net` — WinSCP公式サイト（GHOSTSが開いた）

### 4.5 ファイル生成パターン（EID 11 - 4145件）

| プロセス | 件数 | 生成ファイルの種類 |
|----------|------|--------------------|
| svchost.exe | 2128 | `C:\Windows\ServiceProfiles\`, ログファイル, 一時ファイル |
| mscorsvw.exe | 431 | `C:\Windows\Microsoft.NET\` .NETアセンブリ |
| msiexec.exe | 278 | `C:\Program Files\` インストールファイル |
| choco.exe | 177 | `C:\ProgramData\chocolatey\` パッケージファイル |
| ngen.exe | 152 | `C:\Windows\assembly\NativeImages\` |
| SearchApp.exe | 136 | `C:\Users\win10\AppData\Local\Packages\` 検索インデックス |
| powershell.exe | 126 | スクリプト、一時ファイル |
| System | 82 | デバイスドライバ関連 |

### 4.6 レジストリ変更パターン（EID 13 - 1507件）

| プロセス | 件数 | 主な対象ハイブ |
|----------|------|--------------------|
| services.exe | 469 | `HKLM\System\CurrentControlSet\Services\` |
| svchost.exe | 291 | `HKLM\System\CurrentControlSet\` |
| VSCodeSetup.tmp | 148 | `HKLM\SOFTWARE\Microsoft\VSCode` |
| vlc-3.0.21.exe | 134 | `HKLM\SOFTWARE\VideoLAN\VLC` |
| msedge.exe | 58 | ユーザーハイブ |
| OneDrive.exe | 47 | `HKU\...\Software\Microsoft\OneDrive` |

---

## 5. 比較分析：C_Data/25, 27, 28

### C_Data/27 特有のプロセスパターン

| パターン | 件数 | 特記事項 |
|---------|------|---------|
| `MsMpEng.exe → wevtutil.exe` | 52 | Defender Antivirusが積極的にイベントログを読み取り |
| `updater.exe → updater.exe` | 28 | GHOSTS updaterプロセスの自己更新 |
| `Git-2.46.0-64-bit.tmp → git.exe` | 14 | **Git** インストール (C_Data/30にはない) |
| `gitkraken.exe → reg.exe` | 6 | **GitKraken** GUIツール使用 |
| `explorer.exe → LogiOptions.exe` | 6 | **Logitech** マウス設定ソフト |

### C_Data/28 特有のプロセスパターン

| パターン | 件数 | 特記事項 |
|---------|------|---------|
| `powershell.exe → choco.exe` | 34 | 最多 (C_Data/30の2倍以上のインストール) |
| `shimgen.exe → csc.exe` | 16 | Chocoシム大量生成 |
| `MicrosoftEdgeUpdate.exe → MicrosoftEdgeUpdateComRegisterShell64.exe` | 6 | Edge COM登録 |

### 共通正常行動（全マシン共通）

```
全マシンで確認された正常行動パターン：
1. wazuh-agent.exe → net.exe → net1.exe   (Wazuhヘルスチェック)
2. powershell.exe → choco.exe             (Chocolateyパッケージ管理)
3. svchost.exe → WmiPrvSE.exe             (WMIプロバイダ)
4. updater.exe → updater.exe              (GHOSTSアップデーター)
5. msiexec.exe → msiexec.exe             (Windows Installer)
6. shimgen.exe → csc.exe                  (Chocoシム生成)
7. svchost.exe → rundll32.exe            (DLL実行サービス)
8. svchost.exe → sc.exe                  (サービス制御)
9. services.exe → svchost.exe            (サービスプロセス起動)
```

---

## 6. Wazuh アラート分析（C_Data/30）

**アラート総数: 681件**（正常マシンにもかかわらず）

### 6.1 レベル別内訳

| レベル | 件数 | セキュリティ意味 |
|--------|------|-----------------|
| **3** | 239 | 情報 (Informational) |
| **4** | 42 | 低リスク (Low) |
| **5** | 5 | 低リスク |
| **6** | 127 | 注意 (Notice) |
| **7** | 264 | 中リスク (Medium) |
| **9** | 2 | 高リスク (High) |
| **14** | 1 | 重大 (Critical) |
| **15** | 1 | 重大 (Critical) |

### 6.2 誤検知パターン（FalsePositive）上位

| アラート内容 | 件数 | Level | 実際の正体 |
|-------------|------|-------|------------|
| Process loaded taskschd.dll module (遅延実行マルウェアの可能性) | 40 | 7 | 正常なWindowsプロセスがタスクスケジューラAPIを使用 |
| Discovery activity executed | 37 | 7 | `wazuh-agent.exe → net.exe`によるWazuhヘルスチェック |
| Scripting file created under Windows Temp or User folder | 28 | 6 | GHOSTS/PowerShellの正常スクリプト作成 |
| Windows logon success | 24 | 3 | 正常ログオン (win10ユーザー) |
| A net.exe account discovery command was initiated | 16 | 7 | Wazuhエージェントの`net user`コマンド |
| Possible DLL search order hijack (SoftwareDistribution\Download) | ~56 | 7 | Windows Updateの一時DLL（正常なステージング） |
| Software protection service scheduled successfully | 4 | 3 | Windowsライセンス管理 |
| C:\Windows\SysWOW64\powershell.exe created a new script file | 2 | 9 | GHOSTS PowerShellスクリプト作成 |

### 6.3 高レベルアラートの真相

**Level 15** (Rule 92213) — "Executable file dropped in folder commonly used by malware"
```
時刻: 2024-09-09T12:57:02 UTC
プロセス: powershell.exe
ファイル: C:\Users\win10\AppData\Local\Temp\__PSScriptPolicyTest_y1no5kad.oed.ps1
実態: PowerShellが実行ポリシー確認のために一時的に作成する標準ファイル
      (実行後すぐ削除される — 攻撃ではない)
```

**Level 14** (Rule 92212) — "Suspicious file compression activity by powershell"
```
時刻: 2024-09-09T13:03:48 UTC
プロセス: powershell.exe (同一ProcessGuid {30f6f5d4-f09c-66de-2d01-000000000400})
ファイル: C:\Users\win10\Downloads\Scripts\Scripts\Collector\logs.zip
実態: GHOSTSフレームワークの "Collector" スクリプトがログを収集・圧縮
      (install_choco_software.ps1 と同一セッション)
```

**Level 9** (Rule 92201) — "PowerShell created a new script file"
```
時刻: 2024-09-09T13:47, 13:51
実態: GHOSTSのinstall_choco_software.ps1実行中に
      PowerShellが中間スクリプトを生成 (正常なChoco処理フロー)
```

---

## 7. プロセスチェーン復元例（研究活用）

### 例1: Wazuhヘルスチェックチェーン（全マシン共通）

```
wazuh-agent.exe
  └→ net.exe "net user"        [EID 1, 毎約2〜3時間]
      └→ net1.exe              [EID 1, net.exeの内部コマンド実行]
         └→ (終了)             [EID 5]
         
関連アラート: Level 7 "A net.exe account discovery command was initiated"
判定: FALSE POSITIVE (Wazuhエージェントの正常ヘルスチェック)
```

### 例2: Chocolateyソフトウェアインストールチェーン

```
explorer.exe (ユーザー/GHOSTS操作)
  └→ cmd.exe /q /c install.bat          [EID 1]
      └→ powershell.exe -File install_choco_software.ps1  [EID 1]
          └→ choco.exe install firefox   [EID 1 ×15回]
              └→ msiexec.exe /i firefox.msi  [EID 1]
                  └→ (FileCreate: C:\Program Files\Mozilla Firefox\)  [EID 11]
                     (Registry: HKLM\SOFTWARE\Mozilla\Firefox)        [EID 13]
              └→ shimgen.exe             [EID 1]
                  └→ csc.exe (シム生成)  [EID 1]
          └→ Compress-Archive logs.zip  [EID 11: logs.zip] ← Level 14 Alert!
          
関連アラート: Level 14/15, Level 9 (全てFP)
判定: FALSE POSITIVE (GHOSTS環境構築スクリプト)
```

### 例3: Windows自動更新経由のDLL読み込み

```
svchost.exe -k wuauserv (Windows Update)
  └→ (FileCreate: C:\Windows\SoftwareDistribution\Download\2908...\Module.dll)  [EID 11]
  └→ (ImageLoad: 同DLLをロード)  [EID 7]
  
関連アラート: Level 7 "Possible DLL search order hijack by C:\Windows\SoftwareDistribution\..."
判定: FALSE POSITIVE (Windows Updateの正常DLLステージング)
```

---

## 8. 正常/異常の判別基準（分析から導出）

### 正常と判断できる特徴

| 特徴 | 正常のサイン |
|------|------------|
| 親プロセス | `services.exe`, `svchost.exe`, `explorer.exe`, `wazuh-agent.exe` が起点 |
| ネットワーク先 | `proxy.intra.rma.ac.be:3128`（機関プロキシ）のみ |
| ファイル作成先 | `C:\Windows\`, `C:\Program Files\`, `C:\ProgramData\chocolatey\` |
| レジストリ操作 | `HKLM\System\CurrentControlSet\Services\`（サービス設定） |
| TaskScheduler | `\Microsoft\Windows\` 配下の既知タスク |
| DNS | 機関ドメイン `*.rma.ac.be`、既知ソフトウェアドメイン |

### 異常を示す可能性がある特徴（参考）

| 特徴 | 要調査のサイン |
|------|--------------|
| 親プロセス | `cmd.exe → powershell.exe → net.exe` (ユーザー直接実行) |
| ネットワーク先 | プロキシ外への直接接続、非標準ポート |
| ファイル作成先 | `C:\Users\...\AppData\Roaming\`, スタートアップフォルダ |
| レジストリ操作 | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| TaskScheduler | ユーザー定義タスク（`\Microsoft\Windows\` 以外） |
| DNS | ランダム文字列 DGA パターン（ただしGHOSTS生成FPに注意） |

---

## 9. 研究への示唆

### 正常行動復元の可否

**結論: 可能（ただし条件付き）**

✅ **可能なこと:**
- Sysmon EID 1 の `ProcessGuid` / `ParentProcessGuid` により完全な親子チェーンを復元できる
- 機関プロキシ（`proxy.intra.rma.ac.be:3128`）への通信は全て正常として分類可能
- TaskScheduler の `\Microsoft\Windows\` 配下タスクは全て正常
- Wazuh-agent によるnet.exeは誤検知として分類可能

❌ **困難な点:**
- Security.evtx EID 4688 の CommandLine が空 → プロセス引数不明
- GHOSTSのランダムDNSクエリは表面上DGAマルウェアと区別困難
- PowerShellスクリプト内容はSysmonに記録されない (EID 1のCmdLineのみ)
- 記録期間の大部分はバックグラウンドタスクのみ（人間の操作は極めて少ない）

### Wazuh アラートの誤検知率（C_Data/30正常マシン）

```
総アラート: 681件
Level 14以上: 2件 (全てFP: PowerShellポリシーテスト + GHOSTS Collector)
Level 9以上: 4件 (全てFP)
Level 7: 264件 (大部分FP: Wazuhnet.exe、DLLステージング、taskschd.dll)
Level 6: 127件 (FP: スクリプトファイル作成)
→ 正常マシンでLevel 14/15アラートが発生する = 高誤検知率を裏付ける
```

---

## 10. データファイル一覧

| ファイル | 内容 |
|---------|------|
| `analysis_raw.csv` | C_Data/30 Sysmon EID 1 全275行（ProcessCreate） |
| `apt-persistence/Datasets/C_Data/30/Description/Description.yml` | C_Data/30 ソフトウェア構成 |
| `apt-persistence/Datasets/C_Data/30/Wazuh-Alerts/alerts.json` | Wazuhアラート681件 |

---

*このドキュメントはPowerShellによるEvtx/JSON自動解析結果を元に作成。データソース: APT-Persistence Dataset (cylab.be)*
