# ATLASv2 5シナリオ FP行動解析（S3 / S4 / M4 / M5 / M6）

作成日: 2026-04-21  
対象: ATLASv2 h1 `S3`, `S4`, `M4`, `M5`, `M6`  
入力: Hayabusa `msft-security` CSV, ATLASv2 ground truth, 一部 Firefox sidecar  
目的: 偽陽性アラートの中身を確認し、それを追跡したときに

- 正常行動の seed になるのか
- 攻撃隣接ログが混ざるのか
- 実験環境由来なのか

を切り分ける。

---

## 1. 先に結論

この5シナリオで **Hayabusa non-info の FP** を見ると、かなり傾向が揃っている。

1. **clean な正常行動 seed は non-info FP にはあまり出ない**
2. non-info FP の大半は
   - **環境由来** (`Log Cleared`, Windows Defender task deletion)
   - **攻撃隣接** (`powershell.exe` の 4673, `winword.exe` の 8080通信)
   に分かれる
3. 一方で **all-level の FP** には
   - `firefox.exe`
   - `svchost.exe`
   - `repmgr.exe`
   - `RepWmiUtils.exe`
   など、正常行動復元に使いやすい候補が大量に含まれる

つまり、

> **「偽陽性なら non-info からそのまま正常行動復元に使える」わけではない。**  
> **正常行動の seed は info 側に豊富で、non-info は環境由来や攻撃隣接の比率が高い。**

---

## 2. 判定基準

本メモでは、Hayabusa `msft-security` の **non-info alert** を ground truth と突き合わせ、GTに含まれないものを FP とした。

その上で FP を次の3種に分けた。

### A. 正常行動 seed
- 利用者操作または定常動作として説明しやすい
- その後の関連ログを辿ることで正常行動復元に使えそう

### B. 攻撃隣接
- GT EventRecordID には含まれない
- しかし時刻・プロセス・通信先から見ると攻撃チェーンの近傍
- 「GT漏れ」「粒度差」で FP 扱いされている可能性が高い

### C. 環境由来 / 監視由来
- VM起動アーティファクト
- Windows Defender / Sysmon / EDR の定常動作
- 攻撃でも正常業務でもなく、実験環境や監視基盤の副作用

---

## 3. 全体サマリー

| Scenario | non-info alerts | non-info FP | 主なFP rule | 主判定 |
|---|---:|---:|---|---|
| `S3` | 11 | 5 | `Process Ran With High Privilege` ×4, `Log Cleared` ×1 | 攻撃隣接 + 環境由来 |
| `S4` | 14 | 7 | `Process Ran With High Privilege` ×6, `Log Cleared` ×1 | 攻撃隣接 + 環境由来 |
| `M4` | 9 | 2 | `Scheduled Task Deletion` ×1, `Log Cleared` ×1 | 環境由来 |
| `M5` | 18 | 13 | `Process Ran With High Privilege` ×6, `Office ... Uncommon Ports` ×3, `LSASS` ×2, `Scheduled Task Deletion` ×1, `Log Cleared` ×1 | 攻撃隣接 + 監視由来 + 環境由来 |
| `M6` | 10 | 5 | `Process Ran With High Privilege` ×4, `Log Cleared` ×1 | 攻撃隣接 + 環境由来 |

---

## 4. シナリオ別解析

## 4.1 `S3`

### non-info FP の中身

| 時刻 (UTC) | Rule | EID | RecordID | プロセス / 対象 | 判定 |
|---|---|---:|---:|---|---|
| 14:36:17–14:36:18 | `Process Ran With High Privilege` ×4 | 4673 | 3276685, 3276686, 3278729, 3278924 | `powershell.exe`, `SeCreateGlobalPrivilege` | 攻撃隣接 |
| 14:22:16 | `Log Cleared` | 1102 | 3162456 | Security log clear | 環境由来 |

### 解釈

- `4673` 4件は **`powershell.exe` が特権呼び出しを行った記録**
- 時刻が攻撃チェーン本体の `powershell.exe` 通信・起動に重なっており、**実態としてはかなり攻撃寄り**
- ただし GT が `4673` を含んでいないため FP になっている

`Log Cleared` は VM スナップショット起動直後の既知アーティファクトで、正常行動 seed ではない。

### all-level 側で見える正常行動候補

`S3` の info FP は 9,051件あり、上位プロセスは次の通り。

- `svchost.exe`: 6,720
- `firefox.exe`: 1,548
- `repmgr.exe`: 331
- `RepWmiUtils.exe`: 251

特に `firefox.exe` は Firefox sidecar と結ぶと、

- `tiles.services.mozilla.com`
- `tiles-cloudfront.cdn.mozilla.net`
- `google.com` -> `www.google.com`

が確認でき、**通常ブラウザ利用の seed** としてかなり強い。

### 小結

`S3` の non-info FP は **正常行動そのものではなく、攻撃隣接 + 環境由来**。  
正常行動復元の seed は主に **info の Firefox / svchost / EDR** 側にある。

---

## 4.2 `S4`

### non-info FP の中身

| 時刻 (UTC) | Rule | EID | RecordID | プロセス / 対象 | 判定 |
|---|---|---:|---:|---|---|
| 00:53:47–00:53:49 | `Process Ran With High Privilege` ×6 | 4673 | 3570733, 3570740, 3571568, 3571782, 3572441, 3572442 | `powershell.exe`, `SeCreateGlobalPrivilege` | 攻撃隣接 |
| 00:33:07 | `Log Cleared` | 1102 | 3425370 | Security log clear | 環境由来 |

### 解釈

`S4` も `S3` と同型で、**PowerShell の 4673 が GT未記載の攻撃隣接ログ**として大量に FP に落ちている。  
clean な正常行動 seed は non-info 側には無い。

### all-level 側で見える正常行動候補

`S4` の info FP は 4,885件。上位は

- `svchost.exe`: 3,390
- `firefox.exe`: 774
- `repmgr.exe`: 304
- `RepWmiUtils.exe`: 225

で、構図は `S3` とほぼ同じ。  
正常行動の材料はやはり info 側に多い。

### 小結

`S4` でも non-info FP は **攻撃隣接 + 環境由来** に寄る。  
normal seed を探すなら Firefox / background 通信は info 側から拾う方が自然。

---

## 4.3 `M4`

### non-info FP の中身

| 時刻 (UTC) | Rule | EID | RecordID | プロセス / 対象 | 判定 |
|---|---|---:|---:|---|---|
| 22:37:59 | `Scheduled Task Deletion` | 4699 | 4596545 | `\Microsoft\Windows Defender\MP Scheduled Scan` | 環境由来 |
| 22:35:36 | `Log Cleared` | 1102 | 4567974 | Security log clear | 環境由来 |

### 解釈

`Scheduled Task Deletion` の中身は **Windows Defender の定期スキャンタスク**。

- `TaskName: \Microsoft\Windows Defender\MP Scheduled Scan`
- `MpCmdRun.exe Scan -ScheduleJob -WinTask -RestrictPrivilegesScan`

これは **攻撃よりというより環境由来**。  
`M4` は今回の5シナリオの中で、non-info FP が最も clean に「環境側」へ寄っている。

### all-level 側で見える正常行動候補

`M4` の info FP は 4,583件。上位は

- `svchost.exe`: 3,098
- `firefox.exe`: 858
- `repmgr.exe`: 271
- `RepWmiUtils.exe`: 202

で、正常行動 seed はやはり info 側に豊富。

### 小結

`M4` の non-info FP は **ほぼ環境由来**。  
このシナリオでは「攻撃隣接FPが多い」というより、「non-info では正常 seed が痩せる」ことの例になっている。

---

## 4.4 `M5`

### non-info FP の中身

| 時刻 (UTC) | Rule | EID | 件数 | 主なRecordID | プロセス / 対象 | 判定 |
|---|---|---:|---:|---|---|---|
| 23:39:34–23:39:35 | `Process Ran With High Privilege` | 4673 | 6 | 4985376, 4985377, 4986287, 4986552, 4987221, 4987222 | `powershell.exe`, `SeCreateGlobalPrivilege` | 攻撃隣接 |
| 23:25:52 / 23:31:06 / 23:35:44 | `Office Application Initiated Network Connection Over Uncommon Ports` | 5156 | 3 | 4813371, 4858050, 4960280 | `winword.exe` -> `10.193.66.115:8080` | 攻撃隣接 |
| 23:34:14 | `Potentially Suspicious AccessMask Requested From LSASS` | 4663 | 2 | 4895777, 4895780 | `C:\Windows\Sysmon.exe` -> `C:\Windows\System32\lsass.exe` | 監視由来 |
| 23:39:58 | `Scheduled Task Deletion` | 4699 | 1 | 4989874 | `\Microsoft\Windows Defender\MP Scheduled Scan` | 環境由来 |
| 23:15:24 | `Log Cleared` | 1102 | 1 | 4752384 | Security log clear | 環境由来 |

### 解釈

`M5` は今回の5シナリオで **一番混ざり方が複雑**。

#### A. `powershell.exe` の 4673
`S3/S4/M6` と同じで、**GT未記載の攻撃隣接ログ**。

#### B. `winword.exe` -> `10.193.66.115:8080`
これはかなり重要で、**正常FPというより attack-adjacent の典型**。

- Office 由来
- 宛先が `10.193.66.115:8080`
- uncommon port 通信

なので、`S3` の `winword.exe` GT漏れと同じく、**「正常業務っぽく見えるが実態は攻撃側」** の可能性が高い。

#### C. `Sysmon.exe` による LSASS access
これは

- ProcessName: `C:\Windows\Sysmon.exe`
- ObjectName: `C:\Windows\System32\lsass.exe`

なので、攻撃というより **監視基盤由来** と見るのが自然。  
少なくとも「利用者正常行動」ではない。

### all-level 側で見える正常行動候補

`M5` の info FP は 3,337件。上位は

- `svchost.exe`: 2,127
- `repmgr.exe`: 334
- `firefox.exe`: 334
- `RepWmiUtils.exe`: 228

ここでも normal seed は info 側に存在するが、`M5` は non-info 側の attack-adjacent がかなり濃い。

### 小結

`M5` は

- 攻撃隣接 (`powershell`, `winword->8080`)
- 監視由来 (`Sysmon -> lsass`)
- 環境由来 (`Log Cleared`, Defender task)

が混在しており、**non-info FP をそのまま正常行動扱いするのが最も危険なシナリオ**。

---

## 4.5 `M6`

### non-info FP の中身

| 時刻 (UTC) | Rule | EID | RecordID | プロセス / 対象 | 判定 |
|---|---|---:|---:|---|---|
| 00:10:09–00:10:10 | `Process Ran With High Privilege` ×4 | 4673 | 4932274, 4932275, 4932748, 4932939 | `powershell.exe`, `SeCreateGlobalPrivilege` | 攻撃隣接 |
| 23:55:04 | `Log Cleared` | 1102 | 4811087 | Security log clear | 環境由来 |

### 解釈

構図は `S3 / S4` と同じ。  
clean な正常行動 seed は non-info 側にはほぼ見えない。

### all-level 側で見える正常行動候補

`M6` の info FP は 6,527件。上位は

- `svchost.exe`: 4,552
- `firefox.exe`: 1,267
- `repmgr.exe`: 300
- `RepWmiUtils.exe`: 224

で、やはり Firefox や背景通信は info 側に集まる。

### 小結

`M6` の non-info FP は **攻撃隣接 + 環境由来**。  
正常行動の材料は info に多い。

---

## 5. 横断考察

## 5.1 non-info FP は「正常行動の宝庫」ではない

今回の5シナリオで、non-info FP を追ってみると、

- `4673 powershell.exe` (`SeCreateGlobalPrivilege`)
- `1102 Log Cleared`
- `4699 Scheduled Task Deletion`
- `winword.exe -> 10.193.66.115:8080`
- `Sysmon.exe -> lsass.exe`

が中心で、**利用者の clean な正常行動**はほとんど出てこなかった。

## 5.2 正常行動復元の seed は info 側に多い

一方、all-level FP では各シナリオとも

- `firefox.exe`
- `svchost.exe`
- `repmgr.exe`
- `RepWmiUtils.exe`

が上位に出ており、**正常行動復元に使いやすい対象はむしろ info 側に豊富**だった。

## 5.3 研究的な含意

この結果から、次のことが言える。

1. **non-info FP をそのまま「正常行動の seed」とみなすのは危険**
2. FP は少なくとも
   - 正常行動 seed
   - 攻撃隣接
   - 環境由来 / 監視由来
   に分ける必要がある
3. 正常行動復元を第一段階の目的にするなら、
   **seed 候補を non-info に限定せず info まで広げる** 方が現実的

---

## 6. 今の時点の一番自然な言い方

> `S3`, `S4`, `M4`, `M5`, `M6` の5シナリオで Hayabusa の non-info FP を精査したところ、clean な正常行動 seed は少なく、環境由来または攻撃隣接のログが支配的であった。  
> 一方で、Firefox などの正常行動復元に使いやすい候補は info 側の FP に豊富に含まれていた。  
> このため、偽陽性ログを正常行動復元に使う研究では、FP を一律に normal とみなさず、その性質を分類した上で seed を選ぶ必要がある。

---

## 7. 関連ファイル

- [analysis_data/atlas_fp_noninfo_selected.json](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/atlas_fp_noninfo_selected.json)
- [analysis_data/atlas_fp_info_summary.json](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/atlas_fp_info_summary.json)
- [msft-security-h1-s3.csv](/c:/Users/komat/OneDrive/Desktop/ATLAS系データセット取得/hayabusa/atlasv2_runs/csv/msft-security-h1-s3.csv)
- [msft-security-h1-s4.csv](/c:/Users/komat/OneDrive/Desktop/ATLAS系データセット取得/hayabusa/atlasv2_runs/csv/msft-security-h1-s4.csv)
- [msft-security-h1-m4.csv](/c:/Users/komat/OneDrive/Desktop/ATLAS系データセット取得/hayabusa/atlasv2_runs/csv/msft-security-h1-m4.csv)
- [msft-security-h1-m5.csv](/c:/Users/komat/OneDrive/Desktop/ATLAS系データセット取得/hayabusa/atlasv2_runs/csv/msft-security-h1-m5.csv)
- [msft-security-h1-m6.csv](/c:/Users/komat/OneDrive/Desktop/ATLAS系データセット取得/hayabusa/atlasv2_runs/csv/msft-security-h1-m6.csv)
