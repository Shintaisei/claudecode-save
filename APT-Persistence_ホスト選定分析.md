# APT-Persistence ホスト選定分析
> 作成日: 2026-04-15  
> 目的: apt-persistence の正常ホストから、Hayabusa/異常検知の起点アラートを使った正常行動復元に適した研究対象ホストを選定する。

---

## 1. 結論

研究対象の第一候補は **C_Data/96** とする。

C_Data/96 は、Sysmon の記録期間が約 203 時間あり、Sysmon/Security/TaskScheduler がそろっている。さらに Wazuh アラートが 1,458 件と多すぎず少なすぎないため、正常ホストでありながら「調査対象になりうる起点ログ」を十分に確保できる。ソフトウェア構成も Git、Python、SoapUI、Firefox、Notepad++ などを含み、開発者・技術者寄りの正常行動を復元する題材として使いやすい。

比較候補として **C_Data/80** と **C_Data/42** を残す。C_Data/80 は Windows Server 2019 で管理・開発系ソフトが多く、サーバ系の正常行動を比較できる。C_Data/42 は Windows 11 Home で、クライアント端末としてログ量・アラート量・ソフトウェア多様性のバランスがよい。

補助候補として **C_Data/63** を残す。Security ログ量はやや弱いが、Docker/Git/Python などの正常行動が多く、Wazuh アラートの種類も比較的分散しているため、偽陽性分析の例として使いやすい。

---

## 2. 選定方針

今回の研究では、単にログ量が多いホストではなく、以下の条件を満たすホストを優先した。

| 評価軸 | 見る内容 | 理由 |
|---|---|---|
| ログ期間 | Sysmon の最古・最新イベント間の時間 | 行動復元には前後文脈が必要なため |
| ログ種別の充実度 | Sysmon / Security / TaskScheduler のサイズ | プロセス、認証、タスク実行を横断して追跡するため |
| 正常行動の多様性 | インストール済みソフト数、開発・管理系ソフトの有無 | 正常だが攻撃に見えやすい行動を含むホストを選ぶため |
| 起点アラートの有用性 | Wazuh アラート件数 | Hayabusa投入前の代理指標として、調査起点の多さを見るため |
| 関連ログ追跡可能性 | Sysmon/Security量、Wazuh有無、技術系ソフト有無 | 起点ログから関連ログへたどれる可能性を見るため |

注意点として、全ログの最古・最新時刻を使うと、Security/System に古いイベントが残っているホストで期間が過大に見積もられる。そのため、実験対象の時系列評価では **Sysmon の期間** を主指標にした。

### 2.1 選定基準

選定基準は、足切り条件と優先条件に分けた。

#### 足切り条件

| 条件 | 基準 | 理由 |
|---|---:|---|
| Sysmon期間 | 原則 96 時間以上 | 起点アラート前後の文脈を復元するため、最低4日分を目安にする |
| Sysmonログ量 | 20MB以上を目安 | プロセス生成、通信、ファイル、レジストリなどの追跡材料が必要 |
| Securityログ量 | 15MB以上を目安 | ログオン、権限、監査失敗などを補助的に確認するため |
| TaskSchedulerログ | 1MB以上を目安 | 永続化類似の正常タスク実行を説明するため |
| アラート有無 | Wazuhアラートが存在すること | Hayabusa投入前の代理指標として、調査起点が存在するかを見る |

#### 優先条件

| 条件 | 高評価にした状態 | 理由 |
|---|---|---|
| アラート件数 | 500〜5000件 | 少なすぎると起点候補が不足し、多すぎるとノイズが支配的になる |
| ソフトウェア構成 | 開発・管理系ソフトが多い | 正常でも攻撃に見えやすい行動が出やすい |
| OS | Windows 10/11 Pro または実務に近い構成 | エンドポイント運用のユースケースに説明しやすい |
| アラートの種類 | Discovery、script、task、privilege、logon が含まれる | 行動復元の起点として分類しやすい |

### 2.2 C_Data/30 の位置づけ

C_Data/30 は、以前の分析で正常行動の復元例を作るために見ていたホストであり、**予備分析対象としては有用**である。

ただし、今回の目的は「apt-persistence の正常ホスト112台を同じ基準で横断評価し、主実験対象を選ぶこと」である。その基準で見ると、C_Data/30 は次の理由で主対象から外した。

| 観点 | C_Data/30 | 評価 |
|---|---:|---|
| Sysmon期間 | 93.59時間 | 4日、つまり96時間にわずかに届かない |
| Sysmonログ量 | 29.07MB | プロセス追跡には使える |
| Securityログ量 | 2.07MB | 認証・権限・監査文脈が薄い |
| TaskSchedulerログ量 | 1.07MB | 最低限はある |
| Wazuhアラート | 681件 | 起点候補としては扱いやすい |
| ソフトウェア構成 | 23件、技術系ヒット8 | C_Data/96 や C_Data/42 より弱い |

つまり C_Data/30 は「使えない」わけではなく、**既に見えている正常行動を説明する予備ケース**として残す。一方で、主実験としては、期間・Securityログ・ソフトウェア多様性の面で C_Data/96 の方が強い。

---

## 3. 集計方法

対象は `apt-persistence/Datasets/C_Data` 配下の正常ホスト 112 台。

集計した内容は以下。

- `Security.evtx`, `Sysmon.evtx`, `TaskScheduler.evtx`, `Application.evtx`, `System.evtx` のサイズ
- 各 EVTX の最古・最新イベント時刻
- Sysmon の記録期間
- Wazuh アラート件数
- `Description.yml` または `installed_software.yml` から取得した OS とインストール済みソフト
- 開発・管理系ソフトの該当数

生成した中間ファイル:

- `apt_persistence_host_inventory.csv`
- `apt_persistence_host_scores_top25.csv`

---

## 4. スコアリング

100 点満点で以下のように評価した。

| 項目 | 配点 | 評価内容 |
|---|---:|---|
| ログ期間 | 20 | Sysmon が 7 日以上なら高評価、4 日以上も候補化 |
| ログ種別の充実度 | 20 | Sysmon/Security/TaskScheduler が十分にあるか |
| 正常行動の多様性 | 20 | ソフト数と開発・管理系ソフトの多さ |
| 起点アラートの有用性 | 20 | Wazuh アラートが 500〜5000 件なら最も扱いやすい |
| 関連ログ追跡可能性 | 20 | 起点からプロセス・認証・タスク・ソフト構成に結びつくか |

Wazuh アラートについては、多すぎるホストはノイズが支配的になりやすいため、500〜5000 件を最も扱いやすい範囲とした。

---

## 5. 段階的な絞り込み

全112台をいきなり比較するのではなく、以下の順に絞り込んだ。

| 段階 | 条件 | 残ったホスト数 | 判断 |
|---:|---|---:|---|
| 0 | 正常ホスト全体 | 112 | C_Data 全体を母集団にする |
| 1 | Sysmon が存在する | 112 | 全ホストに Sysmon は存在するため除外なし |
| 2 | Sysmon期間が96時間以上 | 55 | 4日以上の時系列文脈を持つホストに絞る |
| 3 | Sysmon 20MB以上、Security 15MB以上、TaskScheduler 1MB以上 | 47 | 行動復元に必要な主要ログがそろうホストに絞る |
| 4 | Wazuhアラートが1件以上 | 40 | 調査起点候補があるホストに絞る |
| 5 | Wazuhアラートが500〜5000件 | 21 | 初回分析で扱いやすいアラート量のホストに絞る |
| 6 | ソフトウェア構成とスコアで比較 | 上位候補8台 | 正常行動の多様性と追跡可能性で比較する |

この段階で、以前候補として見ていた C_Data/25、C_Data/27、C_Data/28、C_Data/30 は主対象から外れた。いずれも正常行動の題材としては悪くないが、4日以上の Sysmon 期間または Security ログ量の基準を満たさない。

| ホスト | Sysmon期間 | Sysmon | Security | Wazuh | 判断 |
|---|---:|---:|---:|---:|---|
| C_Data/25 | 73.73h | 37.07MB | 20.07MB | 772 | 期間不足 |
| C_Data/27 | 89.50h | 45.07MB | 20.07MB | 884 | 期間不足 |
| C_Data/28 | 91.52h | 39.07MB | 2.07MB | 699 | 期間不足、Security薄い |
| C_Data/30 | 93.59h | 29.07MB | 2.07MB | 681 | 期間がわずかに不足、Security薄い |

このため、C_Data/30 は「以前の探索で見つけた有望ホスト」から「予備分析・説明用ホスト」に位置づけを変更した。

---

## 6. 上位候補

| 順位 | ホスト | 総合点 | Sysmon期間 | Sysmon | Security | TaskScheduler | Wazuh | OS | ソフト数 | 技術系ヒット |
|---:|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 1 | **C_Data/96** | **99** | 203.26h | 58.07MB | 19.07MB | 2.07MB | 1,458 | Windows 10 Pro | 50 | 17 |
| 2 | **C_Data/80** | **93** | 217.33h | 22.07MB | 20.07MB | 1.07MB | 1,083 | Windows Server 2019 | 28 | 18 |
| 3 | **C_Data/42** | **93** | 121.89h | 60.07MB | 20.07MB | 3.07MB | 1,510 | Windows 11 Home | 42 | 16 |
| 4 | C_Data/25 | 91 | 73.73h | 37.07MB | 20.07MB | 1.07MB | 772 | Windows 11 Home | 51 | 15 |
| 5 | C_Data/89 | 91 | 184.34h | 50.07MB | 19.07MB | 2.07MB | 7,657 | Windows 11 Pro | 31 | 16 |
| 6 | C_Data/27 | 90 | 89.50h | 45.07MB | 20.07MB | 1.07MB | 884 | Windows 11 Home | 48 | 15 |
| 7 | C_Data/92 | 90 | 187.15h | 36.07MB | 20.07MB | 1.07MB | 9,229 | Windows 10 Pro | 36 | 12 |
| 8 | **C_Data/63** | **90** | 174.37h | 48.07MB | 9.07MB | 2.07MB | 1,121 | Windows 10 Home | 43 | 16 |

C_Data/25 と C_Data/27 はスコア上は高いが、Sysmon 期間が 4 日未満であるため、主対象からは外す。C_Data/89 と C_Data/92 は期間・ログ量はよいが、Wazuh アラートが多く、特権操作失敗の大量発生に寄りやすいため、初回の正常行動復元ユースケースにはやや重い。

---

## 7. Wazuh アラートの傾向

Hayabusa の実行結果はこの時点では未確認のため、Wazuh アラートを「起点ログ候補の代理指標」として見た。

### C_Data/96

- アラート総数: 1,458
- 主な内容:
  - `Failed attempt to perform a privileged operation.`: 854 件
  - `Discovery activity executed`: 37 件
  - `Process loaded taskschd.dll module. May be used to create delayed malware execution`: 31 件
  - `Scripting file created under Windows Temp or User folder`: 27 件
  - `Windows logon success.`: 22 件

C_Data/96 は特権操作失敗が多いが、Discovery、TaskScheduler DLL、スクリプト作成など、行動復元の起点にしやすいアラートも含まれている。件数が 1,458 件に収まっているため、分析対象として扱いやすい。

### C_Data/80

- アラート総数: 1,083
- 主な内容:
  - `Failed attempt to perform a privileged operation.`: 714 件
  - `Binary loaded PowerShell automation library`: 29 件
  - `Windows logon success.`: 15 件
  - `Windows audit failure event.`: 13 件
  - `Process loaded taskschd.dll module`: 12 件

サーバ OS で、PowerShell、TeamViewer、Vagrant、Python などが含まれる。管理系の正常行動を扱う比較対象として有用。

### C_Data/42

- アラート総数: 1,510
- 主な内容:
  - `Discovery activity executed`: 120 件
  - `Windows logon success.`: 114 件
  - `Process loaded taskschd.dll module`: 87 件
  - `A net.exe account discovery command was initiated`: 48 件
  - `Scripting file created under Windows Temp or User folder`: 36 件

C_Data/42 は特権操作失敗に偏りすぎず、Discovery、ログオン、net.exe、スクリプト作成などが見える。正常行動復元の題材としてかなり素直で、C_Data/96 の次点候補として強い。

### C_Data/63

- アラート総数: 1,121
- 主な内容:
  - `Scripting file created under Windows Temp or User folder`: 41 件
  - `Executable dropped in Windows root folder`: 37 件
  - `Discovery activity executed`: 35 件
  - `Windows logon success.`: 26 件
  - `Process loaded taskschd.dll module`: 23 件

C_Data/63 は Security ログ量がやや少ないが、アラート内容が分散している。Docker/Git/Python などの正常行動が多いため、偽陽性として説明できる行動を探しやすい可能性がある。

---

## 8. 最終選定

### 主対象: C_Data/96

主対象は **C_Data/96** とする。

理由:

- Sysmon 期間が約 203 時間あり、4 日以上の条件を十分に満たす
- Sysmon 58.07MB、Security 19.07MB、TaskScheduler 2.07MB でログ種別がそろっている
- Wazuh アラートが 1,458 件で、調査起点として多すぎず少なすぎない
- Git、Python、SoapUI、Firefox、Notepad++ などがあり、正常でも攻撃に見えやすい技術系行動が期待できる
- Windows 10 Pro で、実務のエンドポイント想定にも近い

想定ユースケース:

> 技術者・開発者寄りの正常端末において、Discovery、スクリプト作成、TaskScheduler DLL 読み込み、特権操作失敗などのアラートを起点に、Sysmon/Security/TaskScheduler を横断して正常行動を復元する。

### 比較候補A: C_Data/42

C_Data/42 はクライアント端末としてバランスがよい。特に `Discovery activity executed`、`net.exe account discovery`、スクリプト作成などが含まれており、Hayabusa に投入した際にも起点ログとして扱いやすい可能性が高い。

C_Data/96 の分析後、同じクライアント系正常行動の別例として使う。

### 比較候補B: C_Data/80

C_Data/80 は Windows Server 2019 で、管理者・サーバ運用寄りの正常行動を比較するために残す。

主対象をクライアント端末にする場合、サーバ OS は最初のユースケースには混ぜない方がよい。ただし、研究の発展として「サーバ管理操作は正常でも攻撃に見えやすい」という説明に使える。

### 補助候補: C_Data/63

C_Data/63 は Security ログ量が少ないため主対象からは外すが、Docker/Git/Python などの開発系ソフトが多く、Wazuh アラートの内訳も分散している。C_Data/96 で起点アラートが特権操作失敗に偏りすぎる場合の代替候補として残す。

---

## 9. 今回は主対象から外すホスト

| ホスト | 理由 |
|---|---|
| C_Data/25 | ソフト構成は非常によいが、Sysmon期間が約73.7時間で4日未満 |
| C_Data/27 | ソフト構成はよいが、Sysmon期間が約89.5時間で4日未満 |
| C_Data/30 | 既存分析は進んでいるが、Sysmon期間が約93.6時間で4日未満、Securityも2.07MBと薄い |
| C_Data/89 | ログ期間・ログ量はよいが、Wazuh 7,657件で特権操作失敗が6,920件と偏りが強い |
| C_Data/92 | ログ期間・ログ量はよいが、Wazuh 9,229件で特権操作失敗が8,060件と偏りが強い |

C_Data/30 は既に正常行動分析が進んでいるため、発表では「予備分析済みホスト」として使える。ただし、今後の主実験対象としては C_Data/96 の方が適している。

---

## 10. 次の作業

1. C_Data/96 の EVTX を Hayabusa に投入する
2. Hayabusa の出力から起点アラート候補を抽出する
3. 起点候補を以下の観点で分類する
   - Discovery 系
   - PowerShell / script 系
   - TaskScheduler / persistence 類似系
   - privilege / logon 系
   - file / registry 系
4. 各起点アラートについて、Sysmon の `ProcessGuid` / `ParentProcessGuid`、Security のユーザー・ログオン情報、TaskScheduler の実行履歴を使って関連ログを追跡する
5. 復元できたものを「正常行動として説明可能」「説明不足」「判断不能」に分ける

Hayabusa 実行後に C_Data/96 のアラートが偏りすぎる場合は、C_Data/42 を第二候補として同じ手順にかける。

---

## 11. 発表での言い方

今回のホスト選定は、単なるログ量ではなく、正常行動復元に必要な条件から段階的に絞り込んだ。

まず正常ホスト112台を対象に、Sysmon の記録期間、EVTX の充実度、Wazuh アラート件数、ソフトウェア構成を集計した。そこから、Sysmon期間が4日以上の55台、主要ログがそろう47台、Wazuhアラートが存在する40台、アラート量が分析しやすい21台へ段階的に絞り込んだ。

以前候補として見ていた C_Data/30 は、Wazuhアラート数やSysmonログ量の点では使えるが、Sysmon期間が96時間に届かず、Securityログも薄い。そのため、主実験対象ではなく予備分析済みホストとして扱うことにした。

その結果、Windows 10 Pro の C_Data/96 が最も研究目的に合うと判断した。C_Data/96 は開発・技術系の正常行動が含まれ、アラート件数も分析可能な範囲に収まっているため、起点アラートから正常行動を復元するユースケース作成に適している。
