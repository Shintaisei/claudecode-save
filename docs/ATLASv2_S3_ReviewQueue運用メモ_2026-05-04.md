# ATLAS v2 S3 Review Queue 運用メモ

更新日: 2026-05-04

## 1. 何を作ったか

`Security first pass -> Security second pass -> Sysmon補助` を、そのまま読む順へ落とした review queue を作成した。

参照:
- [security_sysmon_review_queue_s3/results.json](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/security_sysmon_review_queue_s3/results.json:1)
- [security_sysmon_review_queue_s3/review_queue.md](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/analysis_data/model_runs/security_sysmon_review_queue_s3/review_queue.md:1)

## 2. まず見る数字

- first-pass 陽性 sequence: `3`
- その内訳: `真陽性2 / 偽陽性1`
- first-pass 合計: `118,495 event`
- second-pass review windows: `10`
- second-pass 合計: `5,400 event`
- second-pass に残った attack event: `195`

つまり、attack day を直接読む代わりに、まず `3 sequence` へ絞り、その中でも読む候補を `5,400 event` まで落とせている。

## 3. 読む順

### 3.1 最優先

`win-32-h1|aalsahee|20220719T1430Z`

この sequence は真陽性で、Security second pass と Sysmon の両方で裏が取れている。

特に優先度が高い起点は次である。

- Security: `payload.exe`, `chunk 323-329`, `700 event`, `attack 155`
- Security: `payload.exe`, `chunk 331-340`, `1000 event`, `attack 34`
- Security: `powershell.exe`, `chunk 271-274`, `400 event`, `attack 3`
- Security: `regsvr32.exe`, `chunk 181-183`, `300 event`, `attack 1`
- Sysmon: `20220719T1436Z`
- Sysmon: `20220719T1437Z`, top image=`payload.exe`

したがって、この sequence は「攻撃近傍の正常行動を取る起点」として最も信頼しやすい。

### 3.2 次点

`win-32-h1|win-32-h1$|20220719T1430Z`

この sequence も真陽性だが、Security second pass は `osppsvc.exe` を出しており、まだ局所化が弱い。  
一方で same-host Sysmon では `1433Z`, `1436Z`, `1437Z` が上がっており、特に `1437Z` では `payload.exe` が見える。

したがって、この sequence は

- Security chunk 単独で読むより
- same-host Sysmon minute を横に置いて読む

方がよい。

### 3.3 後回し

`win-32-h1|win-32-h1$|20220719T1420Z`

これは現時点では偽陽性である可能性が高い。  
Security 側は `wmiapsrv.exe`、Sysmon 側も `pseudo_anomaly=0` の minute が中心で、真陽性 sequence ほどの裏づけがない。

したがって、現段階では「比較用の偽陽性サンプル」として扱うのがよい。

## 4. 今の運用ルール

今は次の順で見ればよい。

1. first pass で陽性になった sequence を確認する
2. その中で `aalsahee|20220719T1430Z` を最優先で読む
3. Security second pass の `payload.exe / powershell.exe / regsvr32.exe` 帯を先に読む
4. 同じ coarse bucket にある Sysmon minute `1436Z / 1437Z` を補助的に見る
5. `1420Z` 側は偽陽性比較のため最後に回す

## 5. 今の限界

- 小さい attack sequence の局所化はまだ弱い
- Sysmon は補助起点としては有効だが、単純 fusion で一本化はできていない
- second pass 上位がすべて良い seed とは限らず、`werfault.exe` などの偽陽性帯も混ざる

そのため、現時点では

- `Security` を主軸
- `Sysmon` を補助
- 真陽性と偽陽性の比較読解を並行

で進めるのが一番安全である。
