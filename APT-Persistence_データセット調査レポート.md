# APT Persistence データセット 調査レポート

> 作成日: 2026-04-11  
> 調査者: Claude Code (自動調査)  
> リポジトリ: https://gitlab.cylab.be/cylab/datasets/apt-persistence  
> 論文: Rahal, Riahi, Debatty — "Dataset of APT Persistence Techniques on Windows Platforms Mapped to the MITRE ATT&CK Framework", ICIN 2025  
> DOI: 10.1109/ICIN64016.2025.10943025  
> 著者機関: Cyber Defence Lab, Royal Military Academy (Belgium) / cylab.be

---

## 1. データセット概要

このデータセットは、**APTが使用するWindowsの永続化（Persistence）テクニック**を収集することを目的に、ベルギー王立軍事アカデミーのCyber Defence Labが構築した研究用データセット。  
構成は「**正常環境（C_Data）**」と「**攻撃注入済み環境（I_Data）**」の2種類に分かれており、各マシンのWindowsイベントログをEVTX形式で収録している。

### 基本スペック

| 項目 | 値 |
|------|-----|
| 正常マシン数 | **112台**（C_Data） |
| 感染マシン数 | **26台**（I_Data） |
| 合計 | **138台** |
| 正常/感染比率 | 約 **81% / 19%** |
| 配布形式 | ZIPアーカイブ（PowerShell で展開可能） |
| C_Data.zip サイズ | **546 MB**（圧縮後） |
| I_Data.zip サイズ | **278 MB**（圧縮後） |
| 論文発表年 | 2025年（ICIN 2025） |

---

## 2. ログソース

各マシンに以下の5種類のEVTXが収録されている。

| ログ名 | ファイル名 | benign合計サイズ | 用途 |
|--------|-----------|----------------|------|
| Windowsセキュリティ | `Security.evtx` | **約 2,140 MB** | 認証・プロセス・オブジェクトアクセス等 |
| Sysmon | `Sysmon.evtx` | **約 5,144 MB** | プロセス生成・ネットワーク接続・ファイル操作 |
| Windowsシステム | `System.evtx` | 約 143 MB (×112) | システムイベント全般 |
| アプリケーション | `Application.evtx` | 約 143 MB (×112) | アプリ起動・エラー等 |
| タスクスケジューラ | `TaskScheduler.evtx` | 可変（感染マシンで増大） | スケジュールタスク実行ログ |

> **重要**: 収集スクリプト (`windows-log-collector.ps1`) では上記に加えて WinRM, PowerShell Operational, Windows Defender, TerminalServices-LocalSessionManager も対象としているが、今回の配布ZIPには5種類のみ含まれている。

### 有効化された監査ポリシー（Security.evtxで取得される内容）

- Logon（ログオン成功・失敗）
- Object Access（ファイル・レジストリ・フォルダアクセス）
- System Events（起動・シャットダウン）
- Account Logon Events（アカウントログオン）
- Process Tracking（プロセス生成・終了）
- Policy Change（監査ポリシー変更）
- Privilege Use（特権使用）
- Directory Service Access
- Account Management（アカウント変更・グループ変更）

---

## 3. 正常行動の記録期間

**重要な特徴**: このデータセットはリアルタイム連続収録ではなく、**「ある時点でのイベントログバッファをまるごとスナップショット」する方式**で収集されている（`wevtutil epl` コマンドによるエクスポート）。そのためマシンごとに記録期間が大きく異なる。

### 実測タイムスタンプ

| マシン | 種別 | 期間（実測） | 開始日時 | 終了日時 | Securityイベント数 |
|--------|------|------------|---------|---------|-----------------|
| C_Data/3 | 正常（Windows Server 2016） | **約1時間** | 2024-08-17 | 2024-08-17 | 少 |
| C_Data/5 | 正常 | **1日2時間** | 2024-09-03 | 2024-09-04 | — |
| C_Data/6 | 正常 | **21時間** | 2024-09-04 | 2024-09-05 | — |
| C_Data/30 | 正常 | **3日22時間** | 2024-09-06 | 2024-09-09 | 1,477件 |
| I_Data/1 | 感染 | **1時間26分** | 2024-09-03 18:01 | 2024-09-03 19:27 | — |

**まとめ**: 正常マシンは概ね **1時間〜4日程度**のログが収録。感染マシンは攻撃実施分のみなので短い（1〜2時間が多い模様）。全マシン合計では2024年8月〜9月の期間に収集されたデータ。

---

## 4. マシン構成（ソフトウェアプロファイル）

各マシンには **7つのユーザーカテゴリ** に応じた **10〜15個のソフトウェア** がChocolateyでインストールされている。

### ユーザーカテゴリ

| カテゴリ | 想定職種・用途 |
|--------|------------|
| Developers | 開発者（PyCharm, VS Code, Node.js, Git等） |
| Students | 学生（Firefox, Notepad++, Python等） |
| Teachers | 教師・教育者 |
| Administrators | システム管理者（PowerShell, OpenVPN等） |
| Normal Users | 一般ユーザー（Chrome, Slack, OBS等） |
| Researchers | 研究者（R, Jupyter, Wireshark等） |
| Others | その他 |

### インストール可能ソフトウェアプール（150種以上から選択）

代表的なもの（Chocolateyパッケージから抜粋）:

- **ブラウザ**: Firefox, Chrome, Edge, Opera, Vivaldi, Brave, Waterfox, Tor Browser
- **開発ツール**: VS Code, PyCharm, IntelliJ, CLion, Android Studio, GoLand
- **言語**: Python, Node.js, Java (JDK8/11), Go, Rust, Ruby, PHP, Perl, Haskell, Julia
- **データベース**: MySQL, PostgreSQL, MongoDB, MariaDB, Redis, SQLite, MSSQL
- **コミュニケーション**: Slack, Teams, Skype, Zoom, Webex, Signal, Thunderbird
- **クラウド/DevOps**: Docker Desktop, Kubernetes CLI, Terraform, Ansible, Azure CLI, GCloud
- **クリエイティブ**: GIMP, Inkscape, Krita, Blender, OBS Studio, Audacity, Handbrake
- **セキュリティ**: VeraCrypt, KeePass, Wireshark, Sysinternals
- **仮想化**: VirtualBox, VMware Player, Vagrant
- **その他**: 7-Zip, WinRAR, VLC, Dropbox, Evernote, Joplin, Steam

### OSバリエーション

READMEによれば複数バージョンのWindowsを使用（実測から確認したもの）:

- Windows 10 Home (10.0.19045)
- Windows Server 2016 Standard Evaluation (10.0.14393)
- 他のWindows 10/11バリエーションも含まれる模様

---

## 5. 攻撃シナリオ（I_Data）

### 使用ツール

| ツール | 役割 |
|--------|------|
| **Atomic Red Team** | MITREマッピング済みのテスト用攻撃コマンド集 |
| **Caldera** | 自動化された敵性エミュレーションフレームワーク |
| **Metasploit** | エクスプロイト・ペネトレーションテストフレームワーク |
| **Ghost NPC (GHOSTS)** | 現実的なバックグラウンドノイズ生成（正常行動の模倣） |

> **GHOSTS** は正常マシンに対してリアルなユーザー操作（ブラウジング・ファイル操作等）をシミュレートするためのフレームワーク。これが「背景ノイズ」を生成し、単純な正常環境より実環境に近くなっている。

### カバーする永続化テクニック数

- **19の持続化テクニック、67のサブテクニック**

### 確認されたMITRE ATT&CK テクニック

| テクニックID | テクニック名 | 手法例 |
|------------|------------|-------|
| **T1053.005** | Scheduled Task/Job: Scheduled Task | schtasks による定期実行、PowerShell New-ScheduledTask |
| **T1547** | Boot or Logon Autostart Execution | レジストリ RunOnceEx, BootVerificationProgram |
| **T1543** | Create or Modify System Process: Windows Service | sc.exe create でサービス登録 |
| **T1137** | Office Application Startup | Outlook VbaProject.OTM への悪性コード注入 |
| その他 | registry key modifications, DLL hijacking, startup folder manipulation, COM hijacking など | |

### 攻撃シナリオの流れ（例）

```
1. Host && Remote System Discovery
   → 対象システムの識別
   
2. Scheduled Task（schtasks）
   → schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
   
3. Office Application Startup
   → reg add + mkdir Outlook + VbaProject.OTM 作成
   
4. Ghost Task（隠しスケジュールタスク）
   → GhostTask.exe localhost add updats ...
   
5. Boot or Logon Autostart Execution
   → レジストリ RunOnceEx に DLL を登録
   
6. Windows Service Creation
   → sc.exe create でバックグラウンドサービス登録
```

### Ground Truth（GT.yml）の形式

感染マシンごとに `Description/GT.yml` が付属し、実際に実施された攻撃コマンドが記録されている：

```yaml
attack_technique: T1053.005
display_name: 'Scheduled Task/Job: Scheduled Task'
atomic_tests:
  - name: Scheduled Task Startup Script
    executor:
      command: |
        schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
        schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```

---

## 6. フォルダ構成

### ZIPを展開後のフォルダ構造

```
C_Data/
└── {マシン番号}/          ← 112台分
    ├── Description/
    │   ├── Description.yml     ← OSバージョン + インストール済みソフト一覧
    │   └── install_choco_software.ps1  ← Chocolateyインストールスクリプト
    ├── Evtx_Logs/
    │   ├── Application.evtx
    │   ├── Security.evtx       ← 認証・プロセス追跡（重要）
    │   ├── Sysmon.evtx         ← プロセス生成・NW・ファイル操作（重要）
    │   ├── System.evtx
    │   └── TaskScheduler.evtx
    └── Wazuh-Alerts/
        └── alerts.json         ← Wazuh SIEMが生成した補助アラート

I_Data/
└── {マシン番号}/          ← 26台分
    ├── Description/
    │   ├── Description.yml
    │   ├── GT.yml              ← 攻撃の詳細（MITRE ID + Atomic Red Teamコマンド）
    │   └── install_choco_software.ps1
    ├── Evtx_Logs/
    │   ├── Application.evtx
    │   ├── Security.evtx
    │   ├── Sysmon.evtx
    │   ├── System.evtx
    │   └── TaskScheduler.evtx
    └── Wazuh-Alerts/
        └── alerts.json
```

### リポジトリ付属スクリプト

| スクリプト | 内容 |
|-----------|------|
| `Scripts/windows-log-collector.ps1` | マシン上でログをEVTX+CSV両形式で収集するスクリプト |
| `Scripts/install_choco_software.ps1` | Chocolateyでソフトをインストール |
| `Scripts/Evtx_To_Json.py` | EVTX → JSON変換スクリプト |
| `Scripts/os-version.py` | データセット内のOSバージョン分布を表示 |
| `config/sysmon-config.xml` | Sysmon設定ファイル（ルール込み） |
| `activate-win-log.md` | Windowsの監査ポリシー有効化手順書 |

---

## 7. 研究への適合性評価

### 本研究（正常行動起点の関連ログ探索）との対応

| 評価軸 | 評価 | 根拠 |
|--------|------|------|
| Security.evtx あり | ✅ 高 | 全マシンに収録、benign合計2140MB |
| Sysmon.evtx あり | ✅ 高 | 全マシンに収録、benign合計5144MB |
| 正常行動の規模 | ✅ 高 | 112台 × 1時間〜4日分 |
| 正常行動の多様性 | ✅ 高 | 7職種×10〜15ソフト、150種プールから選択 |
| Ground Truth | ✅ 高 | GT.yml（MITRE ID + 実コマンド）付き |
| Hayabusa適合性 | ✅ 高 | EVTX形式、Security+Sysmon両対応 |
| 正常行動の現実性 | ✅ 中〜高 | Ghost NPC (GHOSTS) でバックグラウンドノイズあり |
| ストレージ要件 | ⚠️ 注意 | 展開後は Security+Sysmon だけで 10GB 超 |

### 注意点

- **記録期間がマシンによって大きく異なる**（1時間〜4日）。長期の行動パターン分析には向かない機ある。
- **感染マシスのログは短時間**（攻撃実施分のみ）。正常前後のログ比較には正常期間が短い。
- **GHOSTSフレームワーク**による正常行動が「機械的」である可能性（あくまでシミュレーション）。
- 記録方式が「スナップショット」のため、**同一マシンの時系列変化**を追うことはできない。

---

## 8. 論文について

### 論文情報

- **タイトル**: Dataset of APT Persistence Techniques on Windows Platforms Mapped to the MITRE ATT&CK Framework
- **著者**: Khaled Rahal, Arbia Riahi, Thibault Debatty
- **発表**: 28th Conference on Innovation in Clouds, Internet and Networks (ICIN 2025)
- **DOI**: 10.1109/ICIN64016.2025.10943025
- **機関**: Cyber Defence Lab, Royal Military Academy, Belgium

### 論文PDF取得状況

- cylab.be の直接配信URL → **500エラー（サーバー障害）**
- ResearchGate → **403エラー**
- IEEE Xplore → **アクセス制限**

**論文本文の手動取得先**（優先順）:

1. IEEE Xplore: https://ieeexplore.ieee.org/document/10943025/ （機関ログイン推奨）
2. cylab.be: https://cylab.be/publications/76/ （復旧待ち）
3. ResearchGate: https://www.researchgate.net/publication/390502365

---

## 9. 利用手順（Hayabusaで流す場合）

### ステップ1: 展開

```powershell
# PowerShell で展開（GUI または以下コマンド）
Expand-Archive -Path "C_Data.zip" -DestinationPath ".\C_Data_extracted\" -Force
```

> **注意**: 全台展開するとSecurity+Sysmonだけで10GB超。最初は数台だけ展開推奨。

```powershell
# 小さいマシンのみ先に展開する場合（PowerShell）
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead("C_Data.zip")
$target = $zip.Entries | Where-Object { $_.FullName -match "^C_Data/30/" }
foreach ($entry in $target) {
    $outPath = Join-Path ".\C_Data_30\" ($entry.FullName -replace "^C_Data/30/", "")
    if ($entry.FullName.EndsWith("/")) { mkdir $outPath -Force } 
    else { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $outPath, $true) }
}
$zip.Dispose()
```

### ステップ2: Hayabusaを実行

```bash
# Hayabusa でSecurity.evtxを解析
hayabusa csv-timeline -f "C_Data_30\Evtx_Logs\Security.evtx" -o security_result.csv

# Sysmon も
hayabusa csv-timeline -f "C_Data_30\Evtx_Logs\Sysmon.evtx" -o sysmon_result.csv

# フォルダ全体
hayabusa csv-timeline -d "C_Data_30\Evtx_Logs\" -o all_result.csv
```

---

*調査日: 2026-04-11 | ローカルパス: `ATLAS以外のデータセット/apt-persistence/`*
