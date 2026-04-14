# データセット評価レポート
作成日：2026-04-11

## 研究要件（前提）

- Hayabusa でのルール適用 → **EVTX形式必須**
- WindowsイベントログからのSysmonログ（ネットワーク・プロセス・アプリケーション）が主対象
- **正常行動データ**が確実に含まれること
- 9マスフレーム（起点アラート特異性 × 正常行動種別）に対応するユースケースを抽出できること

---

## 1. Python_Evtx_Analyzer（LMD: Lateral Movement Dataset）

### 出典論文
Smiliotopoulos, C.; Barmpatsalou, K.; Kambourakis, G.  
"Revisiting the Detection of Lateral Movement through Sysmon"  
*Applied Sciences*, 2022, 12, 7746. DOI: 10.3390/app12157746  
GitHub: https://github.com/ChristosSmiliotopoulos/Python_Evtx_Analyzer  
Dataset: https://github.com/ChristosSmiliotopoulos/Lateral-Movement-Dataset--LMD_Collections

### ログ形式・種類

| 項目 | 内容 |
|---|---|
| 形式 | **Sysmon .evtx（および .xml / CSV変換版）** |
| ログソース | **Sysmonのみ**（Security EventログやDNSログは含まない） |
| Sysmon Event IDカバレッジ | 16種類（全27中） |

**含まれる主要イベントID：**
| ID | 内容 |
|---|---|
| 1 | プロセス生成 |
| 3 | **ネットワーク接続（ネットワーク・アプリケーション通信）** |
| 7 | イメージロード（DLL） |
| 10 | プロセスアクセス |
| 11 | ファイル作成 |
| 12/13 | レジストリイベント |
| その他 | DNSクエリ（Sysmon ID 22）、パイプイベント等 |

### 正常行動データ

| サブセット | 規模 |
|---|---|
| Normal（正常のみ） | **80,000サンプル** |
| NormalVsMalicious01 | 290,000サンプル |
| NormalVsMalicious02 | 415,000サンプル |
| FullSet | **870,000サンプル**（LMD-2022） |
| LMD-2023 | 最大**2,310,000サンプル**（ラベル付き版あり） |

正常行動の内容：SOHOネットワーク上での10日間の通常業務ログ（内容の詳細種別は論文参照）

### 攻撃種別

**ラテラルムーブメント（横移動）攻撃に特化：**

| カテゴリ | 具体的手法 |
|---|---|
| 認証悪用（EoHT） | Pass the Hash, Pass the Ticket, Golden Ticket, Silver Ticket |
| リモートサービス悪用（EoRS） | ms17-010, EternalBlue, BlueKeep, Log4Shell, Follina, Zerologon |

### Hayabusa互換性
**○**：Sysmon EVTXをそのまま入力可能。Sigmaルールの中でSysmon向けルールが多数存在。

### 研究9マスとの対応

| 観点 | 評価 |
|---|---|
| 起点アラートの特異性 | **中特異性**が中心（不審IP・端末）。高特異性（特定ファイル）は一部のみ |
| 正常行動種別カバレッジ | 単発操作型○、手続型△、**背景動作型△**（Sysmon単体では文脈が切れやすい） |
| クロスログ探索 | **✗**：ログソースが1種のみで横断探索が難しい |

### 総合評価
**適合度：中**  
Hayabusa互換・正常データあり・大容量という点は優れる。  
ただしSysmonのみのため、複数ログソース間の探索（CLOUSEAUが想定する構造）には制約あり。  
LMD-2023はCSV形式でも提供されており特徴量エンジニアリングには使いやすいが、EVTXのまま使うのが本研究に合う。

---

## 2. apt-persistence（APT Persistence Techniques Dataset）

### 出典論文
Rahal, K.; Riahi, A.; Debatty, T.  
"Dataset of APT Persistence Techniques on Windows Platforms Mapped to the MITRE ATT&CK Framework"  
*28th Conference on Innovation in Clouds, Internet and Networks (ICIN)*, 2025.  
DOI: 10.1109/ICIN64016.2025.10943025  
GitLab: https://gitlab.cylab.be/cylab/datasets/apt-persistence  
機関: Cyber Defence Lab, Royal Military Academy（ベルギー）

### ログ形式・種類

| 項目 | 内容 |
|---|---|
| 形式 | **Windows EVTX（5種）** |
| ログソース | Application / Security / System / **Sysmon** / **Task Scheduler** |

**各ログの役割：**
| ログ種別 | 主な情報 |
|---|---|
| Security | 認証・ログオン（4624/4625/4688等）|
| Sysmon | プロセス・ネットワーク・ファイル・レジストリ（ID 1,3,11,12,13等）|
| Task Scheduler | スケジュールタスク作成・実行イベント |
| Application | アプリケーション動作イベント |
| System | システム起動・サービス状態 |

### 正常行動データ

| 区分 | 内容 |
|---|---|
| Clean Data | 攻撃なし環境の正常ログ（7種ユーザープロファイル） |
| Ghost NPC | 現実的な背景ノイズを自動生成（合成正常行動） |

**ユーザープロファイル（7種）：**
Developer / Student / Teacher / Administrator / Normal User / Researcher / Others

各OSには10〜15種のアプリがChocolateyでインストールされており、ユーザー種別ごとに異なる正常行動パターンが存在する。

**注意：** Ghost NPCによる正常行動は合成ノイズのため、「どこまでが意図的な正常行動か」の境界が明示されていない部分がある。

### 攻撃種別（MITRE ATT&CK Persistence: TA0003）

**シミュレーションツール：** Caldera / Atomic Red Team / Metasploit

| テクニック | 具体的手法 |
|---|---|
| T1053.005 | スケジュールタスク作成（schtasks, GhostTask）|
| T1547 | Boot/Logon Autostart（レジストリRunOnceEx, BootVerificationProgram）|
| T1137 | Officeアプリ起動時スクリプト（Outlook VbaProject）|
| T1543.003 | Windowsサービス作成・偽装（sc.exe）|

### Hayabusa互換性
**○**：SecurityログとSysmon EVTXが揃っており、Hayabusaの主要Sigmaルールが広くカバーされる。  
また `Evtx_To_Json.py` による変換スクリプトも付属。

### 研究9マスとの対応

| 観点 | 評価 |
|---|---|
| 起点アラートの特異性 | **高特異性が豊富**（特定タスク名・特定レジストリキー・特定サービス名）|
| 正常行動種別カバレッジ | 単発操作型○、手続型○、**背景動作型○**（Task Schedulerログが直接対応）|
| クロスログ探索 | **○**：5種のEVTXソースで横断探索が可能 |

### 総合評価
**適合度：高**  
Hayabusa互換・複数EVTXソース・高特異性起点・背景動作型カバーと、研究フレームワークの9マスに最も広く対応できる。  
Task Schedulerログの存在は背景動作型ユースケースに直接使える。  
課題はGhost NPCノイズの解釈と、論文がまだ2025年の新しいもののためデータ量の詳細が公開情報では確認しきれない点。

---

## 統合判断

### 要件対応マトリクス

| 要件 | Python_Evtx_Analyzer | apt-persistence |
|---|---|---|
| EVTX形式 | ○ Sysmon | ○ 5種類 |
| WindowsセキュリティログからのEVTX | △ Sysmonのみ | ○ Security+Sysmon+他 |
| Hayabusa対応 | ○ | ○ |
| 正常行動データ | ○ 80,000件（Normal subset）| ○ Clean Data + Ghost NPC |
| クロスログ探索 | ✗ 単一ソース | ○ 5ソース |
| 高特異性起点の確保 | △ | ○ タスク名・レジストリキー |
| 背景動作型のカバー | △ | ○ Task Schedulerログ |
| データ量 | ○ 大（2.3Mまで）| △ 要確認 |

### 推奨方針

**メインデータセット：apt-persistence**  
- 5種EVTXによるクロスログ探索が可能
- 9マスの大部分をカバーできる起点・行動パターンの多様性
- Hayabusaでの偽陽性分析に適したログ構成

**サブ／比較用：Python_Evtx_Analyzer（LMD-2023）**  
- 正常データが大量（2.3M）で統計的な分析に有効
- LMの攻撃文脈でのユースケース（中特異性起点 × 単発操作型）の補完に使える
- Sysmon単体のため探索範囲は限定的

### 残課題
1. apt-persistenceのClean Dataの実際のデータ量（公開情報では未確認）→ GitLabリポジトリを直接確認要
2. Ghost NPCが生成する正常行動の種別が研究の「正常行動タクソノミー」に対応しているか確認
3. LMD-2023のEVTXファイルが単体のSysmon EVTXとして入手できるか確認（CSVへの変換前のraw EVTX）
