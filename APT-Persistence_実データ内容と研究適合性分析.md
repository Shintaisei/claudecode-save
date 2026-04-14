# APT Persistence — 実データ内容・研究適合性・不足点 分析

> 作成日: 2026-04-11  
> 分析対象: C_Data/30（正常）・I_Data/1（感染）を代表例として実際のEVTXを解析

---

## 1. 各ファイルに実際に何が入っているか

### 1-1. Security.evtx

Windowsの「セキュリティ」イベントログ。認証・プロセス・オブジェクトアクセスが中心。

#### 実測：イベントID分布（C_Data/30、正常マシン、約4日間 / 総1,477件）

| EventID | 件数 | 意味 | 研究上の価値 |
|---------|------|------|------------|
| **5379** | 454 | Credential Manager の読み取り | 認証情報アクセスの正常パターン |
| **4624** | 297 | ログオン成功 | ユーザー・サービスのセッション開始 |
| **4672** | 276 | 特権ログオン（管理者相当） | 権限利用の正常ベースライン |
| 4799 | 61 | ローカルグループメンバー列挙 | グループ照会の正常パターン |
| 4798 | 50 | ユーザーのグループ照会 | 同上 |
| **4688** | 45 | プロセス起動 | ※CommandLineは**空**（後述） |
| 5061 | 37 | 暗号化操作 | TLS/証明書利用の正常パターン |
| 4648 | 22 | 明示的資格情報でのログオン | RunAs相当 |
| 4738 | 22 | ユーザーアカウント変更 | アカウント管理の正常パターン |

#### 実測：イベントID分布（I_Data/1、感染マシン / 総約8,500件）

| EventID | 件数 | 意味 | 攻撃との関係 |
|---------|------|------|------------|
| 5447 | 5,689 | WFP（Windowsファイアウォール）フィルタ変更 | **攻撃によるFW操作の痕跡** |
| 5156 | 1,377 | WFP 接続許可 | ネットワーク活動の急増 |
| 5158 | 742 | WFP バインド許可 | 同上 |
| 4957 | 202 | FW例外の適用失敗 | 攻撃ツールのFW操作 |
| **4702** | 68 | **スケジュールタスク更新** | **Persistence（T1053）の直接証跡** |
| 4624 | 25 | ログオン | 攻撃時の認証 |

**→ 攻撃マシンは正常マシンと比べてイベント種別の分布が全く異なる。特に EID 4702（スケジュールタスク更新）が顕著。**

---

#### ⚠️ 重大な注意：Security 4688 の CommandLine は空

```
Process: C:\Windows\System32\lsass.exe
CommandLine: []   ← 空

Process: C:\Windows\System32\services.exe
CommandLine: []   ← 空
```

Security.evtx の EID 4688（プロセス起動）には **CommandLine が記録されていない**。  
「プロセスのコマンドライン引数付きトラッキング」には **Sysmon.evtx を使う必要がある**。

---

### 1-2. Sysmon.evtx

Sysmon（System Monitor）によるWindowsの詳細監視ログ。Security より圧倒的に情報量が多い。

#### 実測：イベントID分布（C_Data/30、正常マシン / 総約16,800件）

| EventID | Sysmonイベント名 | 件数 | 何が記録されるか |
|---------|----------------|------|---------------|
| **10** | ProcessAccess | 4,708 | プロセスが別プロセスにアクセス（OpenProcess等） |
| **11** | FileCreate | 4,145 | ファイル作成（Image・TargetFilename） |
| **3** | NetworkConnect | 3,496 | ネットワーク接続（Image・DestinationIp・Port） |
| **12** | RegistryCreate/Delete | 2,855 | レジストリキーの作成/削除 |
| **7** | ImageLoad | 1,975 | DLL等のロード |
| **13** | RegistrySet | 1,507 | レジストリ値の書き込み |
| **1** | ProcessCreate | 275 | プロセス生成（CommandLine・GUID付き） |
| 26 | FileDeleteDetected | 237 | ファイル削除 |
| 17 | PipeCreated | 196 | 名前付きパイプ作成 |
| 22 | DnsQuery | 153 | DNS照会 |
| 2 | FileCreateTime | 116 | ファイルタイムスタンプ変更 |
| 5 | ProcessTerminated | 73 | プロセス終了 |

#### 実測：Sysmon Event 1（プロセス生成）の具体的なフィールド

```
時刻: 2024-09-09 21:57:00
  Image:             C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  CommandLine:       "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
  ParentImage:       C:\Windows\explorer.exe
  User:              DESKTOP-0B7RNLE\win10
  ProcessGuid:       {30f6f5d4-f09c-66de-2d01-000000000400}
  ParentProcessGuid: {30f6f5d4-ee99-66de-4a00-000000000400}
```

**→ ProcessGuid / ParentProcessGuid でプロセスの親子関係（連鎖）が完全に追跡可能。**

#### Sysmon Event 3（ネットワーク接続）の具体例

```
時刻: 2024-09-09 21:48:49
  Image:               C:\Windows\system32\svchost.exe
  DestinationIp:       224.0.0.252
  DestinationPort:     5355
  DestinationHostname: -
```

#### Sysmon Event 11（ファイル作成）の具体例

```
時刻: 2024-09-09 22:03:12
  Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetFilename: C:\Users\win10\Downloads\Scripts\...\wineventlog\Powershell_Operational.csv
```

#### Sysmon Event 13（レジストリ値セット）の具体例

```
時刻: 2024-09-09 21:57:00
  Image:        C:\Windows\system32\svchost.exe
  TargetObject: HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\...\powershell.exe
  Details:      Binary Data
```

---

### 1-3. TaskScheduler.evtx

スケジュールタスクの実行ログ。Persistenceの証跡として特に重要。

#### 実測：イベントID分布（C_Data/30、正常マシン / 総約1,100件）

| EventID | 意味 |
|---------|------|
| 140 | タスクが起動されなかった（条件不一致等） |
| 200/201 | タスクのアクション開始・完了 |
| 100/102 | タスクエンジン開始・停止 |
| 129 | タスクプロセス生成 |
| 119 | タスクのトリガー |

**→ 正常マシンでもWindowsの定期メンテタスクが多数実行されており、正常なスケジュールタスク活動のベースラインが確認できる。**

---

### 1-4. Wazuh-Alerts/alerts.json

Wazuh SIEM が自動解析して生成したアラート。EVTX の補助情報として使える。

#### 構造

```json
{
  "_index": "wazuh-alerts-4.x-2024.09.09",
  "_id": "2Sve1pEB9BZutGSNsc4H",
  "_source": {
    "timestamp": "2024-09-09T15:00:01.145+0200",
    "agent": { "name": "VM34" },
    "rule": {
      "id": "92200",
      "level": 6,
      "description": "Scripting file created under Windows Temp or User folder"
    },
    "data": {
      "win": {
        "eventdata": {
          "image": "C:\\Windows\\Explorer.EXE"
        }
      }
    }
  }
}
```

#### 実測：C_Data/30（正常）に発生したアラートの例（全681件）

| Wazuh rule | 件数 | 説明 |
|------------|------|------|
| 19007 | 262 | （Sysmon系ルール） |
| 19008 | 125 | （Sysmon系ルール） |
| 92219 | 98 | — |
| 92154 | 40 | — |
| 92031 | 37 | — |
| **92200** | 多数 | **Scripting file created under Temp or User folder** |

実際のアラート例（正常マシンで発生）：
```
rule 92200 [level 6] Scripting file created under Windows Temp or User folder
  time:  2024-09-09T15:00:27
  image: C:\Program Files\Mozilla Firefox\firefox.exe
```

**→「正常マシン」でも level 6 のアラートが681件発生している。  
Firefoxがスクリプトファイルを作成するだけでアラートになる → 誤検知が多い環境。**

---

### 1-5. Description/Description.yml

そのVMのOS・インストール済みソフト一覧。

```yaml
OSInfo:
  OSName: Microsoft Windows 10 Home
  OSVersion: 10.0.19045

InstalledSoftware:
  - Name: Mozilla Firefox (x64 en-GB)    Version: 129.0.2
  - Name: Notepad++ (64-bit x64)         Version: 8.6.9
  - Name: Python 3.12.6                   Version: 3.12.6150.0
  - Name: Slack (Machine)                 Version: 4.40.126
  - Name: OBS Studio                      Version: 30.2.3
  - Name: PyCharm Community Edition       Version: 242.21829.153
  - Name: Google Chrome                   Version: 128.0.6613.120
  ...（計30本以上）
```

**→ 「このマシンで発生しているプロセス/ネットワーク接続が、どのソフトから来たか」を特定する辞書として機能する。**

---

### 1-6. Description/GT.yml（I_Data のみ）

感染マシンで実際に実施した攻撃の詳細。フォーマットは統一されていないが、以下の情報が含まれる。

```yaml
attack_techniques:
  - id: T1053.005
    name: Scheduled Task/Job: Scheduled Task
    tests:
      - executor:
          command: schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
  - id: T1562.001
    name: Impair Defenses: Disable or Modify Tools
    tests:
      - executor:
          command: schtasks /delete /tn "Windows Defender Scheduled Scan" /f
```

---

## 2. Sysmonで「主体・行為・対象・連鎖」がどこまで復元できるか

研究の核心である「正常行動の連鎖復元」に直接対応する部分を整理する。

| 研究の概念 | 対応するSysmonフィールド | 具体例 |
|----------|----------------------|-------|
| **主体**（誰が） | `Image` + `User` | `C:\...\powershell.exe` / `DESKTOP-0B7RNLE\win10` |
| **行為**（何をした） | EventID（種別） | EID 11 = ファイル作成、EID 3 = ネットワーク接続 |
| **対象**（何に対して） | `TargetFilename` / `DestinationIp` / `TargetObject` | `C:\Users\win10\...\script.csv` / `224.0.0.252:5355` |
| **連鎖**（誰が呼んだか） | `ProcessGuid` + `ParentProcessGuid` | explorer.exe → powershell.exe → ... |

### 連鎖追跡の具体例（C_Data/30から実測）

```
explorer.exe（ParentProcessGuid: {30f6f5d4-ee99...}）
  └─ powershell.exe（ProcessGuid: {30f6f5d4-f09c...}）  [EID 1: ProcessCreate]
       └─ ファイル作成: C:\Users\win10\Downloads\...\wineventlog\Powershell_Operational.csv  [EID 11]
       └─ レジストリ書き込み: HKLM\...\bam\State\...\powershell.exe  [EID 13]
```

**→ ProcessGuid を使えば「どのプロセスが何を作った/接続した/書き込んだ」という完全な連鎖が復元できる。**

---

## 3. 研究への活用マッピング

研究の第1〜第3段階それぞれについて、このデータセットで何ができるかを示す。

### 第1段階：「高特異性起点 × 単発操作型」の正常行動探索

**使えるデータ**: Sysmon.evtx（EID 1, 3, 11）+ Wazuh alerts.json

| やること | 使うファイル | 具体的な操作 |
|---------|------------|------------|
| Hayabusaで正常マシンのSysmonを流してアラートを確認 | `Sysmon.evtx` | `hayabusa csv-timeline -f Sysmon.evtx` |
| Wazuhアラートを「起点」として関連イベントを追う | `alerts.json` + `Sysmon.evtx` | alertのtimestampでSysmonを前後検索 |
| プロセス連鎖の復元 | `Sysmon.evtx` EID 1 | ProcessGuid/ParentProcessGuid でグラフ構築 |

### 第2段階：「手続型正常行動」の連鎖復元

**使えるデータ**: Sysmon.evtx の EID 1→3→11→13 の組み合わせ

```
典型的な手続型正常行動の例（C_Data/30より）:
1. explorer.exe が powershell.exe を起動（EID 1）
2. powershell.exe が スクリプトファイルを作成（EID 11）
3. powershell.exe がレジストリ書き込み（EID 13）
4. svchost.exe が ネットワーク接続（EID 3）
```

### 第3段階：正常 vs 攻撃の比較

**使えるデータ**: C_Data の Sysmon/Security vs I_Data の Sysmon/Security + GT.yml

| 正常マシン（C_Data/30）の特徴 | 感染マシン（I_Data/1）の特徴 |
|-----------------------------|--------------------------|
| Security EID 4688: 45件（CommandLine空） | Security EID 4702: 68件（スケジュールタスク更新） |
| Security EID 5447: なし | Security EID 5447: 5,689件（FWフィルタ変更） |
| Sysmon EID 1: 275件 | Sysmon EID 1: 492件（プロセス生成が倍以上） |
| Sysmon EID 12: 2,855件 | Sysmon EID 12: 8,270件（レジストリ3倍増） |

---

## 4. 不足していること・研究上の限界

### ❌ 不足点 1：「何が正常ユーザー操作か」のラベルがない

GHOSTSフレームワークが自動生成したイベント（NPCユーザー操作）と、Windowsシステムの自動処理（Windows Update, Prefetch, Defender等）が **区別されていない**。

```
例：C_Data/30 の Sysmon EID 11（ファイル作成）
  → svchost.exe が Windows Update の Prefetchファイルを作成
  → svchost.exe が Windows SoftwareDistribution のメタデータを作成
  → powershell.exe が ログ収集スクリプトのCSVを作成
  
どれがGHOSTS生成でどれがWindowsシステムかの区別なし
```

**影響**: 「正常ユーザー操作の典型パターン」を抽出しようとすると、Windowsのシステム動作と混在して分離が難しい。

---

### ❌ 不足点 2：Security 4688 の CommandLine が空

Windowsの監査ポリシー「プロセス作成の詳細な追跡」でCommandLine記録が**有効化されていない**。

```
Security 4688:
  NewProcessName: C:\Windows\System32\lsass.exe
  CommandLine: []  ← 空
```

→ **Sysmon Event 1 に頼ることになる**が、このデータセットではSysmonのプロセス生成（EID 1）が正常マシンで約275件と少ない（4日間で275件 = 1日70件程度）。

---

### ❌ 不足点 3：記録期間がマシンによって大きくバラバラ

| マシン | 期間 |
|--------|------|
| C_Data/3 | 約1時間 |
| C_Data/30 | 約4日 |

→ 「どのくらいの期間の正常行動が観察できるか」がマシンによって大きく異なる。  
**短期間（1〜2時間）のマシンでは、定常的な正常行動パターンの抽出が困難。**

---

### ❌ 不足点 4：マシン間のネットワーク連携が不明

各VMが同一ネットワーク上で実際に互いに通信していたかが不明。  
Sysmon EID 3 のDestinationIpを見ると `224.0.0.252`（LLMNR）や `192.168.1.x` が出てくるが、どのVMがどのIPかのマッピングがない。

→ **横展開（Lateral Movement）の正常・異常比較には向かない**（PeXの方が適している）。

---

### ❌ 不足点 5：GT.yml のフォーマットが統一されていない

26台の感染マシンで GT.yml の書き方が4〜5種類混在している。  
機械処理（自動解析スクリプト）には個別対応が必要。

---

### ❌ 不足点 6：「攻撃前の正常期間」が感染マシンにない

I_Data の各マシンは **攻撃実施時のログのみ**（1〜2時間程度）。  
同じマシンの「攻撃前の正常状態」のログが存在しない。

→ 「同一マシンで正常→攻撃の変化を追う」ことはできない。  
正常との比較は **C_Data（別マシン）との横比較** になる。

---

### △ 補助的な注意点

- **Description.ymlがないマシンが11台**（102〜112番）: ソフトウェア構成不明
- **Wazuh alertsは正常マシンにも多数発生**（C_Data/30で681件・level 6含む）: 単純な「アラート数」での正常/異常判定は困難
- **GHOSTS（Ghost NPC）の行動ログが含まれない**: GHOSTSがどんな操作をシミュレートしたか追えない

---

## 5. 研究フェーズ別の使い方まとめ

| フェーズ | 使えるデータ | 使い方 | 注意点 |
|---------|------------|-------|-------|
| **Hayabusa PoC** | C_Data 任意1台のSysmon.evtx | Hayabusaに流してアラート確認 | EID 1が少ないのでProcessCreateに注目 |
| **正常連鎖復元** | C_Data/30〜/49（4日間あるマシン群）のSysmon.evtx | ProcessGuid で連鎖グラフ構築 | システム自動処理との分離に工夫が必要 |
| **起点アラート設計** | Wazuh alerts.json（C_Data）| 正常マシンでのアラート種別・頻度を把握 | 正常でもlevel 6が多発する |
| **攻撃との比較** | I_Data（任意）Security + Sysmon vs C_Data | EID 4702・5447・EID 1増加パターンを見る | 感染マシスは正常前期間がない |
| **手法別分析** | I_Data GT.yml + 対応するEvtx_Logs | T1053.005なら Security 4702 + TaskScheduler.evtx を追う | GT.ymlのフォーマット差異に注意 |

---

## 6. 最も使いやすいマシンの推薦

### 最初に試すなら：**C_Data/30**

- Security.evtx: 2MB（軽い）・1,477件
- Sysmon.evtx: 29MB・約16,800件
- 期間: **4日間**（2024-09-06〜09-09）
- OS: Windows 10 Home
- Description.yml: あり（Firefox, Notepad++, Python, Slack, OBS, PyCharm等）

### 正常行動の多様性を見るなら：**C_Data/100〜112**

- Sysmon.evtx が 43〜398MB と大きい
- Description.yml なし（ソフト不明）だが量は豊富

### 攻撃の証跡を追うなら：**I_Data/21**

- Security.evtx: 261MB（最大）・T1053.005の詳細なコマンドリストあり（GT.yml にPythonリスト形式で数十件の実行コマンド）
- スケジュールタスク操作の証跡が最も豊富

---

*分析日: 2026-04-11 | 実データをPowerShell/Get-WinEventで直接解析した結果に基づく*
