# Normal / attack observable-component v3 最終独立監査

## 判定

**PASS**

採点に参加していないCodexがread-onlyで再計算した。run、Gold、queue、review、
adopted ledger、aggregate、正式comparison、contract、synthesisは変更していない。
OpenAI judge APIは使用せず、採点判断も変更していない。

## 実行品質

| 群 | run | Stage | valid output JSON | error-free | unbounded | token | cost | code steps |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 正常 | 24/24 | 8/8/8 | 24/24 | 24/24 | 24/24 | 322,015 | USD 0.4800675 | 52 |
| 攻撃 | 24/24 | 8/8/8 | 24/24 | 24/24 | 24/24 | 353,063 | USD 0.5832585 | 74 |

両群とも`max_investigations`、`max_questions`、`max_queries`は`null`、
`agent_call_limit_policy`は`unbounded_by_experiment`、stderrは0 byteである。

## 採点完全性と分母

| 群 | 正式採用 | exact | review3 | unresolved / stale / rejected / excluded | alert mapping item |
|---|---:|---:|---:|---:|---:|
| 正常 | 24/24 | 19 | 5 | 0 / 0 / 0 / 0 | 0 |
| 攻撃 | 24/24 | 7 | 17 | 0 / 0 / 0 / 0 | 0 |

正常のStage別分母はGold step 23、action 69、critical evidence 23、order 15、
candidate slot 33/63/60である。攻撃はGold step 59、action 177、
critical evidence 59、order 51、candidate slot 86/75/60である。
各群8 Gold fileは3 Stageで同じhashを持ち、run/Goldのstale hashは0だった。

## adopted ledgerからの独立再計算

### 正常

| Stage | Action recall | Candidate precision | Behavior-step recall | Order recall | Critical evidence recall |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 11/69 = 0.1594 | 11/33 = 0.3333 | 5/23 = 0.2174 | 0/15 = 0.0000 | 0/23 = 0.0000 |
| Stage 2 | 25/69 = 0.3623 | 25/63 = 0.3968 | 12/23 = 0.5217 | 5/15 = 0.3333 | 8/23 = 0.3478 |
| Stage 3 | 17/69 = 0.2464 | 17/60 = 0.2833 | 10/23 = 0.4348 | 3/15 = 0.2000 | 2/23 = 0.0870 |
| **Overall** | **53/207 = 0.2560** | **53/156 = 0.3397** | **27/69 = 0.3913** | **8/45 = 0.1778** | **10/69 = 0.1449** |

component別はsubject 13/69、operation 26/69、object 14/69。
candidate TP 53、unique matched Gold 53、duplicate TP 0である。

### 攻撃

| Stage | Action recall | Candidate precision | Behavior-step recall | Order recall | Critical evidence recall |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 15/177 = 0.0847 | 15/86 = 0.1744 | 8/59 = 0.1356 | 3/51 = 0.0588 | 4/59 = 0.0678 |
| Stage 2 | 23/177 = 0.1299 | 22/75 = 0.2933 | 12/59 = 0.2034 | 3/51 = 0.0588 | 8/59 = 0.1356 |
| Stage 3 | 15/177 = 0.0847 | 16/60 = 0.2667 | 9/59 = 0.1525 | 3/51 = 0.0588 | 8/59 = 0.1356 |
| **Overall** | **53/531 = 0.0998** | **53/221 = 0.2398** | **29/177 = 0.1638** | **9/153 = 0.0588** | **20/177 = 0.1130** |

component別はsubject 13/177、operation 25/177、object 15/177。
candidate TP 53、unique matched Gold 52、duplicate TP 1である。
全Stage・overallで独立再計算値と正式aggregateの不一致は0だった。

## comparison再計算

| 指標 | 正常−攻撃 | 正常 / 攻撃 |
|---|---:|---:|
| Action recall | +0.156227 | 2.565217 |
| Candidate precision | +0.099925 | 1.416667 |
| Behavior-step recall | +0.227463 | 2.388306 |
| Order recall | +0.118954 | 3.022222 |
| Critical evidence recall | +0.031933 | 1.282609 |

Stage別を含む20組の差分・ratioを再計算し、
`normal_attack_observable_component_v3_formal_comparison_20260726.json`との不一致は0だった。

## hash

文書に記載された主要8値を実ファイルから直接再計算し、すべて一致した。

| artifact | SHA-256 |
|---|---|
| normal queue | `ed5e4177e37eaac549ab8fe80582c5e3ef798af0109c07431f88c8e46b585413` |
| normal adopted ledger | `f9524e50881b2d60510d3a07895066e664956b93c28cecc6c450e7bd07502d16` |
| normal aggregate | `746705a52c080ca8fceb535327ff49763dbcf2a7d8c63ecc4c0007bdb4a323ba` |
| normal run audit | `5920cd67bd64e81f48a864c3af5aaa1b0587441e512229aa78935a1bba67bc77` |
| attack queue | `bbe862ad318595889f8fcf1e4a7e7695bb7f84e29d0313ec2f4d62964e189869` |
| attack adopted ledger | `c5732f151147f87c8463f396e2d0263985c737ae758bef90b449b0f4c1273910` |
| attack aggregate | `42cac9ea7d6697125c74b5816ad09bcce23aef86d673a66d1e5b515f3ed29770` |
| attack run audit | `832c7c35cf96860ee748343403ef2e82b5011808c6d92e5febe56aa8458f80bc` |

normal review1/2/3、queue audit v2、comparisonの記載hashも一致した。

## 初回FAILと正式PASS

- attack `run_audit_v3.json`の初回FAILは1件だけで、Stage 1の表示clueに
  neutral anchor自体を要求した監査契約の誤りだった。Stage 1は代表alert anchorを
  表示し、neutral 5分scopeを探索範囲として保持する契約である。
  既存runを変更せず、契約準拠の`run_audit_v3_contract_v2.json`はPASSした。
- normal queue監査v1は`critical_evidence_signature`を正式採点値と誤認した。
  正式値は`evidence_basis`であり、source dataを変更せず、prepare実装を直接使った
  queue audit v2で24/24 contract一致、PASSを確認した。

この履歴は正式結果と矛盾しない。

## 比較可能性と限界

モデル、8ケース×3 Stage、5分窓、focus processへ接続するneutral anchor、
Stage入力方針、S/A/O・order・critical evidence・candidate precision、
PID strict、上限なしAgent設定、Codex二重review＋不一致第三reviewは、
比較に必要な範囲で同一である。与えられていないalert-to-Gold対応は両群とも
採点item 0である。

残る限界は、各群1反復で分散・有意差を評価できないことと、正常23 step、
攻撃59 stepでGold長・行動構成が異なることである。したがって、比較は正式pilot
として有効だが、同一長系列の統制実験や母集団性能の推定ではない。

非致命warningは、正常run 1件に同値`ppid=null`の重複JSON memberがあることだけで、
queue slot、分母、採点値への影響はない。
