# apt-persistence 研究方針まとめ

> 集約日: 2026-04-15  
> 集約元: データセット調査レポート / 実データ内容と研究適合性分析 / データ構造詳細 / 発表用まとめ / 正常行動分析レポート / ホスト選定レポート

---

## 1. 研究背景と目的

### 研究背景

**サイバー攻撃の高度化により、エンドポイントの監視が重要になっている。その中でもインシデント分析はコストが高く属人化している。**

- サイバー攻撃の実態は端末上に現れる
- 異常検知・トリアージは見逃し回避を優先するため、インシデント分析に回りやすい
- インシデント分析は熟練者の暗黙知に依存している

### 先行研究

**マルチエージェントの登場により、攻撃を前提とした攻撃の再現は可能になっている。**

- マルチエージェント登場以前は、攻撃再現に必要なログが揃った状態からの再現が中心
- マルチエージェントの登場により、攻撃の再現に必要なログの調達から行えるようになった

### 研究目的

**インシデント分析を運用可能な形で自動化したい。そのために正常行動に着目し、正常行動の復元分析を可能にする。**

- 実務では攻撃の再現に加えて、偽陽性を正常と判断する必要もある。しかし従来は攻撃が存在する前提での再現に焦点が当たりやすい
- 偽陽性を「攻撃ではない」と結論付ける分析は十分に検討されていない

---

## 2. 現在の進捗方向性

### マイルストーン

| 段階 | 内容 |
|------|------|
| 最終目的 | インシデント分析を運用可能な形で自動化する |
| **第一段階** | 起点ログから正常行動の関連ログを調達し、行動復元ができるようにする |
| 第二段階 | 復元した行動から「攻撃 / 正常 / 判断不能」の判定ができるようにする |

### 現在の取り組み

**第一段階のユースケース作成**

- オープンソースの正常データを網屋の異常検知システムにかけ、異常と判定されたログを集める
- そのログを「正常行動の復元対象」として、起点アラートから関連ログを探索・行動復元を行う

### 実験フロー概要

```
Step 1: 正常ホストのEVTXにHayabusaをかける
         ↓（C_Dataは正常のみ → 出るアラートはすべて偽陽性と確定）
Step 2: アラートから起点を1つ選ぶ
         例：「FirefoxがTempフォルダにファイル作成」
         ↓
Step 3: 起点のEVTXイベントを特定し、Sysmon.evtxで関連イベントを探索
         ProcessGuidを使って前後のプロセス連鎖を追跡
         ↓
Step 4: 主体・行為・対象・連鎖を文章で説明できるか評価
         「Firefox（主体）がキャッシュファイルを（行為）Tempフォルダに（対象）保存した。
          FirefoxはExplorer.exeから起動されており（連鎖）...」
         ↓
Step 5: 復元できた → 成立。できなかった → どこで詰まったかを記録
```

---

## 3. データセット選定経緯

### Hayabusaの入力形式制限

**Hayabusaは EVTX形式（Windowsイベントログ）を直接入力とする。** EVTX以外だとログ情報が欠落し、Hayabusa内部のSigmaルールが機能しない。

### データセット選定基準

| 基準 | 内容 | 理由 |
|------|------|------|
| EVTX形式 | `.evtx` 形式で配布されていること | Hayabusaに直接投入できる必須条件 |
| 正常データを含む | 攻撃データだけでなく正常データが含まれること | 研究の第一段階が「正常行動の復元」であるため |
| 攻撃/正常の区別 | どちらのログかが判別できること | 偽陽性の判定根拠として必要 |
| 起点ログからの追跡 | 起点から関連ログを辿れる構造 | 行動復元フローに必要 |

### データセット比較表

| データセット | EVTX形式 | 攻撃/正常の区別 | 正常データあり | 起点ログ追跡 | コメント |
|------------|---------|--------------|-------------|-----------|---------|
| **ATLAS / ATLAS v2** | △ | ○ | ○ | △ | txt/json配布でEVTXへの置換が困難。Sigmaルールが機能しない |
| **COMISET** | △ | ○ | ○ | △ | 正常（REAL）と攻撃（LAB）が分かれているがJSON配布 |
| **apt-persistence** | **○** | △ | ○ | △〜○ | EVTX/Sysmon/監査ログを扱え、Hayabusaに最もかけやすい |

**ATLASを不採用とした理由**: ログがtxt/json形式での配布でEVTX形式でなく、Hayabusaに直接投入できない。アプリケーションログ・DNSログもWindowsイベントログ由来ではなくSigmaルールが機能しない。

---

## 4. apt-persistence データセット詳細

### 4-1. 概要

> **「Windows VM 138台分のイベントログを、正常環境（112台）と攻撃が注入された環境（26台）に分けて収録した、EVTX形式の公開データセット」**

| 項目 | 内容 |
|------|------|
| 配布元 | cylab.be（ベルギー王立軍事アカデミー Cyber Defence Lab）|
| 論文 | Rahal, Riahi, Debatty — "Dataset of APT Persistence Techniques on Windows Platforms Mapped to the MITRE ATT&CK Framework", ICIN 2025 |
| DOI | 10.1109/ICIN64016.2025.10943025 |
| 正常マシン数 | **112台**（C_Data） |
| 攻撃注入済みマシン数 | **26台**（I_Data） |
| 合計 | **138台** |
| 攻撃カバー範囲 | MITRE ATT&CK Persistence（TA0003）：19テクニック・67サブテクニック |

### 4-2. フォルダ構造

```
apt-persistence/Datasets/
├── C_Data.zip  （546 MB）  ← 正常マシン 112台
└── I_Data.zip  （278 MB）  ← 攻撃注入済みマシン 26台
```

展開後の1マシンフォルダ：

```
{マシン番号}/
├── Description/
│   ├── Description.yml           ← OSバージョン＋インストール済みソフト一覧
│   ├── install_choco_software.ps1
│   └── GT.yml                    ← 【I_Dataのみ】実施した攻撃の詳細（MITRE ID + コマンド）
├── Evtx_Logs/
│   ├── Security.evtx             ← 認証・プロセス・権限（メイン）
│   ├── Sysmon.evtx               ← プロセス連鎖・NW・ファイル・レジストリ（メイン）
│   ├── TaskScheduler.evtx        ← スケジュールタスク実行
│   ├── Application.evtx          ← アプリエラー等
│   └── System.evtx               ← システムイベント
└── Wazuh-Alerts/
    └── alerts.json               ← Wazuh SIEMが自動生成したアラート
```

### 4-3. ログソース詳細

| ファイル | 内容 | 研究上の役割 |
|---------|------|------------|
| `Security.evtx` | 認証・プロセス追跡・オブジェクトアクセス | 基本ログ。C_Data全112台で合計約2,140MB |
| `Sysmon.evtx` | プロセス生成・NW接続・ファイル操作・レジストリ | **主力データ**。ProcessGuidによる連鎖追跡。C_Data合計約5,144MB |
| `TaskScheduler.evtx` | スケジュールタスクの実行ログ | Persistence痕跡として重要。感染マシンで増大 |
| `Application.evtx` | アプリケーション層のイベント | 補助情報 |
| `System.evtx` | システムレベルのイベント | 補助情報 |
| `Wazuh-Alerts/alerts.json` | WazuhがEVTXを解析して生成したアラート | **起点アラートの供給源**（正常マシンのアラートは全て偽陽性と確定できる）|
| `Description.yml` | OSバージョン + インストール済みソフト | プロセスの出所特定に使う辞書 |
| `GT.yml`（I_Dataのみ） | 実施した攻撃手法（MITRE ID）+ コマンド | 攻撃との照合・正解データ |

#### ⚠️ 重要制約：Security EID 4688 の CommandLine が空

Security.evtxのEID 4688（プロセス起動）には**CommandLineが記録されていない**。  
プロセスの詳細追跡は **Sysmon EID 1（ProcessCreate）** を使うこと。

```
Security 4688:
  NewProcessName: C:\Windows\System32\lsass.exe
  CommandLine:    []  ← 空
```

#### Sysmonで「主体・行為・対象・連鎖」が復元できる仕組み

| 研究の概念 | 対応Sysmonフィールド | 具体例 |
|----------|-------------------|--------|
| **主体**（誰が） | `Image` + `User` | `C:\...\powershell.exe` / `win10` |
| **行為**（何をした） | EventID（種別） | EID 11 = ファイル作成、EID 3 = ネットワーク接続 |
| **対象**（何に対して） | `TargetFilename` / `DestinationIp` / `TargetObject` | `C:\Users\...\script.csv` |
| **連鎖**（誰が呼んだか） | `ProcessGuid` + `ParentProcessGuid` | explorer.exe → powershell.exe → ... |

### 4-4. C_Data マシン一覧（正常 112台）

展開後サイズ（MB）の一覧。Security + Sysmonの合計が「このマシンのログ量」の目安。

| ID | Security | Sysmon | TaskSched | Description.yml |
|----|----------|--------|-----------|----------------|
| 1 | 20.1 | 47.1 | 2.1 | あり |
| 2 | 20.1 | 63.1 | 2.1 | あり |
| 3 | 50.1 | 25.1 | 1.1 | あり |
| 4 | 20.1 | 50.1 | 1.1 | あり |
| 5 | 2.1 | 63.1 | 1.1 | あり |
| 6 | 20.1 | 63.1 | 1.1 | あり |
| 7 | 13.1 | 43.1 | 1.1 | あり |
| 8 | 10.1 | 8.1 | 1.1 | あり |
| 9 | 2.1 | 6.1 | 1.1 | あり |
| 10 | 19.1 | 63.1 | 1.1 | あり |
| 11 | 16.1 | 23.1 | 1.1 | あり |
| 12 | 123.1 | 27.1 | 1.1 | あり |
| 13 | 9.1 | 52.1 | 2.1 | あり |
| 14 | 20.1 | 64.1 | 1.1 | あり |
| 15 | 20.1 | 47.1 | 1.1 | あり |
| 16 | 20.1 | 4.1 | 1.1 | あり |
| 17 | 20.1 | 63.1 | 1.1 | あり |
| 18 | 20.1 | 29.1 | 1.1 | あり |
| 19 | 1.1 | 41.1 | 1.1 | あり |
| 20 | 20.1 | 37.1 | 2.1 | あり |
| 21 | 19.1 | 17.1 | 1.1 | あり |
| 22 | 19.1 | 31.1 | 1.1 | あり |
| 23 | 20.1 | 17.1 | 1.1 | あり |
| 24 | 19.1 | 26.1 | 1.1 | あり |
| 25 | 20.1 | 37.1 | 1.1 | あり |
| 26 | 19.1 | 21.1 | 1.1 | あり |
| 27 | 20.1 | 45.1 | 1.1 | あり |
| 28 | 2.1 | 39.1 | 1.1 | あり |
| 29 | 19.1 | 29.1 | 1.1 | あり |
| 30 | 2.1 | 29.1 | 1.1 | あり |
| 31〜50 | ※ | ※ | ※ | あり（全て） |
| 51〜101 | ※ | ※ | ※ | あり（全て） |
| 102〜112 | 20〜28 | 35〜398 | 2〜5 | **なし（11台）** |

※ 31〜101は概ね Security: 2〜20MB / Sysmon: 13〜64MB の範囲。

**注目マシン（サイズ）**:
- C108: Sysmon **398MB**（群を抜いて最大）
- C106: Sysmon 150MB / C105: Sysmon 141MB

**C_Data 合計サイズ（展開後）**

| ログ種別 | 合計 |
|---------|------|
| Security.evtx | 約 2,140 MB |
| Sysmon.evtx | 約 5,144 MB |
| 合計 | 約 **7.6 GB** |

### 4-5. I_Data マシン一覧（攻撃注入済み 26台）

| ID | Security | Sysmon | TaskSched | GT.yml |
|----|----------|--------|-----------|--------|
| 1 | 20.1 | 29.1 | 3.1 | あり |
| 2〜20 | 8〜125MB | 29〜64MB | 1〜4MB | あり |
| **21** | **261.1** | **159.1** | **6.1** | あり（Pythonリスト形式・7バリアント）|
| 22 | 20.1 | 132.1 | 3.1 | あり |
| 23〜26 | 20〜21MB | 43〜76MB | 2〜4MB | あり |

**I_Data 合計**: 約 3.0 GB（Security 1,294MB + Sysmon 1,657MB）

### 4-6. OSバージョン分布（C_Data 101台）

| OS | 台数 |
|----|------|
| Windows 10 Pro | 23 |
| Windows 11 Pro | 23 |
| Windows 10 Home | 13 |
| Windows 11 Home | 13 |
| Windows Server 2019 | 6 |
| Windows 8.1 Pro | 4 |
| Windows Server 2016 | 4 |
| Windows Server 2022 | 3 |
| その他（Win7/Win8/Server 2012等）| 15 |

### 4-7. 攻撃シナリオ（I_Data）

#### 使用ツール

| ツール | 役割 |
|--------|------|
| **Atomic Red Team** | MITREマッピング済みのテスト用攻撃コマンド集 |
| **Caldera** | 自動化された敵性エミュレーションフレームワーク |
| **Metasploit** | エクスプロイト・ペネトレーションテスト |
| **Ghost NPC (GHOSTS)** | 正常マシン用のユーザー操作シミュレーター（CMU SEI製） |

#### カバーされる主な MITRE ATT&CK テクニック

| テクニックID | テクニック名 | カテゴリ |
|------------|------------|---------|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |
| T1547.003 | Time Providers | Persistence |
| T1547.004 | Winlogon Helper DLL | Persistence |
| T1543.003 | Windows Service | Persistence |
| T1505.004 | IIS Components | Persistence |
| T1562.001 | Impair Defenses: Disable Tools | Defense Evasion |
| T1574.001 | DLL Search Order Hijacking | Persistence |
| T1574.008 | Path Interception | Persistence |
| T1112 | Modify Registry | Defense Evasion |
| T1546.008 | Accessibility Features | Persistence |

論文記載: 合計 **19テクニック・67サブテクニック**

#### GT.yml のフォーマット（4〜5種類が混在）

| スタイル | 特徴 | 代表マシン |
|---------|------|----------|
| A: YAML・単一手法 | `attack_technique: T1053.005` | I_Data/1 |
| B: YAML・複数手法リスト | `attack_techniques: [{id: T1562.001}, ...]` | I_Data/2 |
| C: YAML・シンプルIDリスト | `Atomic_red_team_techniques: [T1574.001, ...]` | I_Data/14 |
| D: Pythonリスト形式 | `GT_21 = [r'"cmd.exe" /c schtasks...']` | I_Data/21 |

⚠️ 機械処理にはマシンごとの個別パーサーが必要。人間が読む分には問題ない。

### 4-8. 記録期間の分布

**収集方式**: `wevtutil epl`コマンドによるスナップショット（VMのログバッファをまるごと取り出す）。そのためマシンごとに期間が大きく異なる。

#### C_Data 記録期間分布

| 記録期間 | 台数（C_Data） | 代表ホスト |
|---------|--------------|----------|
| 10日超 | 1台 | C3（291.6h, Server 2016）|
| 1〜2日 | 1台 | C2（45.5h, Win11 Pro）|
| 17〜27時間 | 5台 | C10/C12/C13/C14/C15 |
| 4〜17時間 | 約10台 | C11, C22, C39, C40等 |
| **4時間未満** | **約95台** | 大半が1〜2時間 |
| Wazuh未処理（EVTXのみ） | 11台 | C102〜C112 |

> **クライアントOS（Win10/11）かつ記録期間4時間超の正常ホストは実質 C2・C10・C13 の3台のみ**

#### I_Data 記録期間

| ホスト | 記録期間 | 備考 |
|-------|--------|------|
| 大半（約18台） | 数分〜数時間 | 攻撃実施の時間帯のみ |
| **I1** | **282時間（11.75日）** | 長期。C10との比較に最適 |
| **I18** | **44.3時間** | GhostTask使用（TaskScheduler.evtxに痕跡なし）|
| I22〜I24 | 141〜142日 | 古いイベント混入の可能性あり |

---

## 5. 実データ分析：C_Data/30

**C_Data/30**: Security 2MB・Sysmon 29MB・期間**約4日**・OS: Windows 10 Home 10.0.19045・Description.ymlあり（最初に試すのに最適なマシン）

### 5-1. インストール済みソフトウェア

| ソフトウェア | バージョン | インストール日 |
|-------------|-----------|-------------|
| Firefox, Notepad++, VLC, Wireshark, Zotero, 7-Zip | — | 起動時から |
| WinMerge, VeraCrypt, Chrome, Zoom, VSCode, WinSCP, Edge, Wazuh Agent | — | **2024-09-09**（GHOSTSが環境構築）|

### 5-2. タイムライン（実データから復元）

```
フェーズ1: OOBE/初期セットアップ（09/05 夜）
2024-09-05 23:33  defaultuser0 ログオン — Windows OOBEセットアップ
2024-09-05 23:43  win10 ログオン — 最初のユーザーアカウント
2024-09-06 00:09  win10 ログオン — デスクトップセッション開始

フェーズ2: 安定稼働期（09/06〜09/09 朝）
【繰り返し発生する自動タスク（3日間）】
- svchost.exe → WmiPrvSE.exe     WMIプロバイダ (14回/4日)
- wazuh-agent.exe → net.exe      Wazuhヘルスチェック (29回)
- MicrosoftEdgeUpdate             Edge自動アップデート確認
- Windows Defender スキャン       定期スキャン (2回)

フェーズ3: ソフトウェア大量インストール（09/09 20:23〜）
2024-09-09 20:23  explorer.exe → cmd.exe → GHOSTSコマンド実行
2024-09-09 20:24  powershell.exe → install_choco_software.ps1
2024-09-09 21:00〜 choco.exe(15回) → msiexec.exe → VLC, WinMerge, VeraCrypt...
2024-09-09 22:59  最終イベント（記録終了）
```

### 5-3. 正常行動カタログ

#### Windowsシステム自動行動

| 行動パターン | プロセスチェーン | 頻度 |
|------------|---------------|------|
| WMIプロバイダ | `svchost.exe → WmiPrvSE.exe` | 14回/4日 |
| Windowsアップデート確認 | `svchost.exe → sihclient.exe` | 毎日 |
| .NET最適化 | `svchost.exe → mscorsvw.exe → ngen.exe` | インストール後 |
| Edgeアップデート | `svchost.exe → MicrosoftEdgeUpdate.exe` | 定期 |
| Defender定期スキャン | `MsMpEng.exe → wevtutil.exe` | 2回/4日 |
| ソフトウェア保護 | `sppsvc.exe` | 4〜6時間毎 |
| OneDrive同期 | `OneDrive.exe → OneDriveSetup.exe` | ログオン時 |
| WFPフィルター変更 | `svchost.exe` | サービス起動時（Security EID 5447）|

#### GHOSTSフレームワーク（ユーザー模擬）行動

| 行動パターン | プロセスチェーン |
|------------|---------------|
| Web閲覧シミュレーション | `explorer.exe → msedge.exe → proxy:3128` |
| ファイル閲覧 | `explorer.exe → notepad.exe` |
| スクリプト実行 | `explorer.exe → cmd.exe → powershell.exe` |
| DNSランダムクエリ | `Vysor.exe → DNS(ランダム文字列)` |
| ログ収集 | `powershell.exe → Compress-Archive → logs.zip` |
| ソフトインストール | `explorer.exe → cmd.exe → powershell.exe → choco.exe` |

#### ネットワーク正常通信パターン

| プロセス | 宛先 | ポート | 説明 |
|----------|------|-------|------|
| svchost.exe | proxy.intra.rma.ac.be | 3128 | Windows自動更新・テレメトリがITプロキシ経由 |
| choco.exe | proxy.intra.rma.ac.be | 3128 | Chocolateyパッケージダウンロード |
| msedge.exe | proxy.intra.rma.ac.be | 3128 | Edge Web閲覧 |

### 5-4. Sysmon イベント分布（C_Data/30 / 約4日間 / 約16,800件）

| EID | イベント名 | 件数 |
|-----|-----------|------|
| 10 | ProcessAccess | 4,708 |
| 11 | FileCreate | 4,145 |
| 3 | NetworkConnect | 3,496 |
| 12/13 | RegistryCreate/Set | 4,362 |
| 7 | ImageLoad | 1,975 |
| **1** | **ProcessCreate** | **275** |
| 22 | DnsQuery | 153 |

### 5-5. Wazuh アラート分析（C_Data/30・681件）

**正常マシンでもLevel 14・15のアラートが発生することを確認。誤検知率が高い。**

| レベル | 件数 | セキュリティ意味 |
|--------|------|---------------|
| 3 | 239 | 情報 |
| 4 | 42 | 低リスク |
| 6 | 127 | 注意 |
| 7 | 264 | 中リスク |
| 9 | 2 | 高リスク |
| **14** | **1** | **重大** |
| **15** | **1** | **重大** |

#### 誤検知パターン（FalsePositive）上位

| アラート内容 | 件数 | Level | 実際の正体 |
|------------|------|-------|----------|
| Process loaded taskschd.dll | 40 | 7 | 正常なWindowsプロセスがタスクスケジューラAPIを使用 |
| Discovery activity executed | 37 | 7 | `wazuh-agent → net.exe` によるWazuhヘルスチェック |
| Scripting file created under Temp | 28 | 6 | GHOSTS/PowerShellの正常スクリプト作成 |
| Possible DLL search order hijack | ~56 | 7 | Windows Updateの一時DLL（正常なステージング）|
| **Executable file dropped (malware path)** | 1 | **15** | PowerShellが実行ポリシー確認のために一時作成する標準ファイル |
| **Suspicious file compression by PS** | 1 | **14** | GHOSTSの "Collector" スクリプトがログを収集・圧縮 |
| PowerShell created new script file | 2 | **9** | GHOSTSのinstall_choco_software.ps1実行中の中間スクリプト生成 |

### 5-6. プロセスチェーン復元例（研究活用）

#### 例1: Wazuhヘルスチェックチェーン（全マシン共通）

```
wazuh-agent.exe
  └→ net.exe "net user"        [EID 1, 毎約2〜3時間]
      └→ net1.exe              [EID 1]
         └→ (終了)             [EID 5]
         
関連アラート: Level 7 "A net.exe account discovery command was initiated"
判定: FALSE POSITIVE（Wazuhエージェントの正常ヘルスチェック）
```

#### 例2: Chocolateyソフトインストールチェーン

```
explorer.exe (GHOSTS操作)
  └→ cmd.exe → powershell.exe -File install_choco_software.ps1  [EID 1]
      └→ choco.exe install firefox × 15回  [EID 1]
          └→ msiexec.exe → FileCreate: C:\Program Files\...\  [EID 11]
                         → Registry: HKLM\SOFTWARE\Mozilla  [EID 13]
      └→ Compress-Archive logs.zip  [EID 11] ← Level 14 Alert!

関連アラート: Level 14/15, Level 9（全てFP）
判定: FALSE POSITIVE（GHOSTS環境構築スクリプト）
```

#### 例3: Windows Update経由のDLL読み込み

```
svchost.exe -k wuauserv (Windows Update)
  └→ FileCreate: C:\Windows\SoftwareDistribution\Download\...\Module.dll  [EID 11]
  └→ ImageLoad: 同DLLをロード  [EID 7]
  
関連アラート: Level 7 "Possible DLL search order hijack"
判定: FALSE POSITIVE（Windows Updateの正常DLLステージング）
```

### 5-7. 正常/異常の判別基準（実データから導出）

| 特徴 | 正常のサイン |
|------|------------|
| 親プロセス | `services.exe`, `svchost.exe`, `explorer.exe`, `wazuh-agent.exe` が起点 |
| ネットワーク先 | `proxy.intra.rma.ac.be:3128`（機関プロキシ）のみ |
| ファイル作成先 | `C:\Windows\`, `C:\Program Files\`, `C:\ProgramData\chocolatey\` |
| レジストリ操作 | `HKLM\System\CurrentControlSet\Services\`（サービス設定）|
| TaskScheduler | `\Microsoft\Windows\` 配下の既知タスク |
| DNS | 機関ドメイン `*.rma.ac.be`、既知ソフトウェアドメイン |

| 特徴 | 要調査のサイン |
|------|--------------|
| 親プロセス | `cmd.exe → powershell.exe → net.exe`（ユーザー直接実行）|
| ネットワーク先 | プロキシ外への直接接続、非標準ポート |
| ファイル作成先 | `C:\Users\...\AppData\Roaming\`、スタートアップフォルダ |
| レジストリ操作 | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| TaskScheduler | ユーザー定義タスク（`\Microsoft\Windows\` 以外）|

---

## 6. 研究ホスト選定

### 6-1. 選定基準

| 基準 | 内容 |
|------|------|
| A | クライアントOS（Win10/11）— サーバOSはユーザ行動モデルに当てはめられない |
| B | 記録期間 ≥ 4時間 — 起点→探索→連鎖復元のサイクルを確認できる最低限 |
| C | Sysmon.evtx ≥ 30MB — ProcessCreate/NetworkConnect/Registryが実用量あること |
| D | Wazuhアラートに複数種類のMITREタグ付きルールがある |
| E | インストールソフトが多様かつ具体的 |
| F | 特定プロセスパスやタスク名を含むアラートが存在する（高特異性起点） |

### 6-2. C_Data 候補ランキング

#### C10 ★★★★★（主ホスト・第一推奨）

| 項目 | 内容 |
|------|------|
| 記録期間 | **18.8時間**（2024-09-04〜09-05）|
| OS | Windows 10 Pro |
| 主要ソフト | Firefox, Opera, Notepad++, **Avast Antivirus**, PhotoDirector, Adobe Reader |
| Wazuhアラート件数 | **657件** |
| Sysmon.evtx | **66MB** |
| 主要MITREタグ | T1078(82) / T1087(54) / T1055(54) / T1053.005(29) |
| 主要アラートルール | CIS Benchmark(255), Logon Success(80), Explorer accessed by AppData process(54), Discovery(38), taskschd.dll(29) |
| 採用理由 | クライアントOS・十分な記録期間・Avastによる高特異性偽陽性（ルール92910 = 具体パス付き）・ソフト多様性の全条件を満たす |

#### C13 ★★★★☆（予備A・手続型専用）

| 項目 | 内容 |
|------|------|
| 記録期間 | **17.6時間**（2024-09-06〜09-07）|
| OS | Windows 10 Home |
| 主要ソフト | **PyCharm**, **Zoom**, Git, Firefox, Chrome, Notepad++, BleachBit |
| Wazuhアラート件数 | **1039件** |
| 主要MITREタグ | T1087(56) / T1570(42) / T1053.005(38) / T1105(15) |
| 採用理由 | C10と異なる「開発者行動」プロファイル。PyCharm→Git→pushの手続型行動連鎖が明示的 |

#### C2 ★★★☆☆（予備B・長期記録用）

| 項目 | 内容 |
|------|------|
| 記録期間 | **45.5時間**（2024-07-31〜08-02）|
| OS | Windows 11 Pro |
| 主要ソフト | Firefox, VMware Workstation, WampServer, Notepad++, AVG Antivirus |
| Wazuhアラート件数 | **9,000件（上限到達・打ち切りあり）** |
| 主要MITREタグ | T1078(8816)（大半はAVG/WampServerが起こす認証失敗）|
| 懸念点 | Wazuhアラートが9000件上限で打ち切られている。高特異性起点がほぼない |

#### C3 ★★★☆☆（背景動作観察用・別枠）

| 項目 | 内容 |
|------|------|
| 記録期間 | **291.6時間（12日間）**（2024-08-04〜08-16）|
| OS | **Windows Server 2016 Standard Evaluation** |
| Wazuhアラート件数 | 4690件 |
| 主要MITREタグ | T1543.003(237) = サービス作成が正常でも大量発生する好例 |
| 位置づけ | サーバOSのためユーザ行動モデルには使えない。「背景動作型」専用、復元が成立しないケースの代表 |

### 6-3. I_Data 攻撃比較用候補

#### I1 ★★★★★（攻撃比較・第一推奨）

| 項目 | 内容 |
|------|------|
| 記録期間 | **282時間（11.75日）**（2024-08-22〜09-03）|
| OS | Windows 10 Pro |
| 主要ソフト | Firefox, Notepad++, FileZilla |
| MITREテクニック | **T1053.005のみ（7種のAtomicテスト）** |
| GT.ymlの特徴 | schtasks・PowerShell Register-ScheduledTask・WMI・Base64エンコードなど7パターンが完全コマンドで記録 |
| 採用理由 | C10と同じWin10 Pro・Firefox環境。正常タスクスケジューラ vs 攻撃タスクスケジューラの直接対比が可能 |

#### I18 ★★★★☆（攻撃比較・ステルス系）

| 項目 | 内容 |
|------|------|
| 記録期間 | **44.3時間**（2024-12-02〜12-04）|
| OS | Windows 11 Pro |
| MITREテクニック | T1053.005（**GhostTask**）+ T1078.003（net user add）|
| GT.ymlの特徴 | GhostTask.exeでTaskScheduler APIを通らず直接レジストリを書き換え → **TaskScheduler.evtxに痕跡が残らない** |
| 採用理由 | 「ログが見えないから安全とは言えない」という復元限界を示す実験に適する |

### 6-4. 最終ホスト構成

```
主ホスト（最初に詳細分析する正常ホスト）
  → C10（Win10 Pro, 18.8h, Avast起点, 657アラート）

予備ホストA（手続型行動用）
  → C13（Win10 Home, 17.6h, PyCharm+Git, 1039アラート）

予備ホストB（長期記録・低特異性起点用）
  → C2（Win11 Pro, 45.5h, WampServer, 9000アラート上限）

背景動作・復元破綻観測用（別枠）
  → C3（Server 2016, 12日間, サービス常駐型）

攻撃比較用メイン
  → I1（Win10 Pro, 11日, T1053.005×7パターン）

攻撃比較用サブ（ステルス・TaskScheduler回避型）
  → I18（Win11 Pro, 44h, GhostTask+T1078.003）
```

### 6-5. C10 実験開始手順

```
Step 1: C_Data/10/Wazuh-Alerts/alerts.json から
        ルール92910（"Explorer process was accessed by..."）を全件抽出
        → 高特異性起点アラートの確定

Step 2: 92910アラートのうち最も具体的なパスを起点として選定
        プロセス名・タイムスタンプをメモ

Step 3: C_Data/10/Evtx_Logs/Sysmon.evtx をHayabusaで解析
        EID=10（ProcessAccess）を起点プロセス名でフィルタ
        → SourceProcessGuid を取得

Step 4: SourceProcessGuid → EID=1（ProcessCreate）で
        「そのプロセスがいつ誰から生まれたか」を確認
        ParentProcessGuid → 親を2段辿る
        同時に EID=3（NetworkConnect）で同Guidのネットワーク通信を確認

Step 5: Security.evtx で起点時刻 ±30秒の
        EID=4688（Process Create）および EID=4624（Logon）を確認

Step 6: TaskScheduler.evtx で起点時刻前後に
        EID=106/200/201 がないか確認

Step 7: 行動を「主体・行為・対象・連鎖」で整理し評価
        主体:  user1セッション（EID=4624で確認）
        行為:  Avastプロセスがexplorer.exeのメモリにアクセス
        対象:  explorer.exe
        連鎖:  Wazuh Alert(92910)
                 ← Sysmon EID=10 (ProcessAccess)
                 ← Sysmon EID=1  (AvastSvc 起動)
                 ← Sysmon EID=1  (親: svchost.exe)

Step 8: 4要素が揃ったか判定 → 成立 / 部分成立 / 不成立

Step 9: 次の起点を選定
        - ルール92154（taskschd.dll loaded, 29件）→ 高特異性起点 × 手続型/背景動作型
        - ルール92031（Discovery, 38件）→ 中特異性起点 × 単発操作型

Step 10: C13へ横展開（PyCharm+Git シナリオ）
```

---

## 7. データセットの限界と注意点

| 項目 | 内容 |
|------|------|
| **イベント単位のラベルがない** | GT.ymlには「T1053.005を実行した」しか書いておらず、どのSysmonイベントが攻撃に対応するかはタイムスタンプで自分で突き合わせが必要 |
| **Security EID 4688のCommandLineが空** | プロセス起動のコマンドライン追跡はSysmon EID 1を使うこと |
| **過半数のマシンが記録1時間未満** | 長期パターン分析には4時間超のマシンに絞る |
| **感染マシンに「攻撃前の正常期間」がない** | 同一マシス内で「正常→攻撃の変化」を見ることはできない。C_Dataと横並び比較になる |
| **GT.ymlの書式がマシンごとに統一されていない** | 機械処理には個別対応が必要 |
| **Description.ymlがないマシンが11台** | C_Data/102〜112（後から追加されたバッチ）|
| **GHOSTSの操作とWindowsシステム処理の区別がつかない** | どのログがユーザー模擬操作でどれがOS自動処理かの区別がない |
| **展開後の総サイズ** | 約**10.7 GB**（C_Data 7.6GB + I_Data 3.0GB）。最初は1台ずつ展開推奨 |

---

## 8. 次のアクション（次回MTGまで）

- [ ] 研究対象ホストの選定確定（C10を主ホストとして確定するか）
- [ ] apt-persistenceの正常ログ（C10）をHayabusaにかけてもらう
- [ ] Hayabusa結果を分析し、正常行動なのに偽陽性と判定されたアラートを洗い出す
- [ ] 起点アラートを1件選定し、Sysmon ProcessGuidを使った連鎖追跡を試行する

---

## 参考：Hayabusaでの実行コマンド

```bash
# 正常マシン（C10）のSysmonを解析
hayabusa csv-timeline -f "C_Data/10/Evtx_Logs/Sysmon.evtx" -o sysmon_c10.csv

# Security.evtxも合わせて
hayabusa csv-timeline -f "C_Data/10/Evtx_Logs/Security.evtx" -o security_c10.csv

# フォルダ全体（5種類のEVTXまとめて）
hayabusa csv-timeline -d "C_Data/10/Evtx_Logs/" -o all_c10.csv
```

```powershell
# 特定マシン（C10）だけをZIPから展開するPowerShell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead("C_Data.zip")
$target = $zip.Entries | Where-Object { $_.FullName -match "^C_Data/10/" }
foreach ($entry in $target) {
    $outPath = Join-Path ".\C_Data_10\" ($entry.FullName -replace "^C_Data/10/", "")
    if ($entry.FullName.EndsWith("/")) { mkdir $outPath -Force }
    else { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $outPath, $true) }
}
$zip.Dispose()
```

---

*集約日: 2026-04-15 | 集約元5ファイル: データセット調査レポート・実データ内容と研究適合性分析・データ構造詳細・発表用まとめ・正常行動分析レポート*
