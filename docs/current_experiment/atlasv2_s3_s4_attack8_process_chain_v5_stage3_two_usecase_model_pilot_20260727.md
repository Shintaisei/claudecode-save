# ATLAS v2 攻撃行動復元 v5 Stage 3・2ユースケースモデルpilot

作成日: 2026-07-27  
判定: **採点完了・監査PASS・全実験への移行はGO**

## 1. 目的

正常23ユースケースと同じprocess-chain粒度・component rubricで、攻撃由来のプロセス行動列を一次テレメトリだけからどの程度復元できるかを小規模に確認した。全24 runへ進む前に、次を検証するpilotである。

- v5正式Goldが実際のモデル出力を採点できること
- Stage 3でCBC alert summaryがモデルから見えないこと
- Agent呼出し回数を実験側で制限していないこと
- 低スコアがGoldや時間窓の不備ではなく、モデル／Agentシステムの調査・統合行動として説明できること

## 2. 実験条件

| 項目 | 設定 |
|---|---|
| モデル | `gpt-4.1-mini`, `gpt-5.4-mini` |
| Stage | Stage 3のみ |
| 初期入力 | host、focus process、timestamp |
| CBC alert summary | SQL一時viewで非表示。各runで可視行0件を確認 |
| 時間窓 | v5で固定したcase別確定窓。本pilotの2 caseはいずれも5分 |
| Agent上限 | `max_investigations/max_questions/max_queries=null`、`agent_call_limit_policy=unbounded_by_experiment` |
| 採点 | Codexによるitem単位採点。OpenAI judge API不使用 |
| rubric | subject/action/object、critical evidence別診断、隣接order pair、candidate precision |
| 非採点 | PID一致、hidden alert mapping、ATT&CK label、意図推定 |

対象は短い境界ケースと長い多段ケースを1件ずつ選んだ。

| case | 内容 | Gold step |
|---|---|---:|
| `s3_pt_01_word_document_processing_stage3` | Wordの文書openと子Word processの短い系列 | 2 |
| `s4_pt_03_mshta_c1_stage3` | mshtaからPowerShell、cmd、payload、通信へ続く多段系列 | 9 |

4 runはすべてerrorなし、`output_text` valid JSON、Stage 3 filter有効、unbounded設定で完了した。

## 3. 採点方法と監査

本pilotは、Codexが4 runをGold item、order pair、candidate slot単位で採点し、別工程でschema、固定分母、candidate slot、totals、run/Gold hash、Stage 3 filter、token/costを機械的に再計算した。pilotのため独立二重レビューではなく、**単一Codexレビュー＋決定論的監査**である。正式な全実験では独立Codex二重レビューを用いる。

- scoring status: `pass`
- review validation: 4/4 pass
- unresolved conflict: 0
- audit failure: 0
- judge API: 不使用
- queue SHA-256: `5205fd6327681972e897cfcb68ec2cc9d36fc927876f1d72017d60b4a4614b68`
- validated review SHA-256: `c8a98b568858f24c8fb191175f10aac9d55d854c5f94b1e2d200605fcc3f8fa4`

ここで「再現率」はGoldのsubject/action/objectのうち復元できた割合、「適合率」はモデルが出力したcandidate subject/action/objectのうちGoldに一致した割合である。

## 4. 結果

### 4.1 モデル別

| モデル | 再現率（Action recall） | 適合率（Candidate precision） | Behavior-step recall | Order recall | Critical evidence recall |
|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 2/33 = **0.0606** | 2/17 = **0.1176** | 1/11 = **0.0909** | 0/9 = **0.0000** | 1/11 = **0.0909** |
| `gpt-5.4-mini` | 10/33 = **0.3030** | 10/30 = **0.3333** | 4/11 = **0.3636** | 2/9 = **0.2222** | 4/11 = **0.3636** |
| **全体** | **12/66 = 0.1818** | **12/47 = 0.2553** | **5/22 = 0.2273** | **2/18 = 0.1111** | **5/22 = 0.2273** |

`gpt-5.4-mini`は本pilotの全指標で`gpt-4.1-mini`を上回った。ただし各モデル2 caseだけなので、母集団性能や有意差を示す結果ではない。

### 4.2 ケース別

| モデル | case | 再現率 | 適合率 | Step recall | Order recall | Critical evidence |
|---|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | S3-1 Word | 0/6 = **0.0000** | 0/9 = **0.0000** | 0/2 = **0.0000** | 0/1 = **0.0000** | 0/2 = **0.0000** |
| `gpt-4.1-mini` | S4-3 mshta | 2/27 = **0.0741** | 2/8 = **0.2500** | 1/9 = **0.1111** | 0/8 = **0.0000** | 1/9 = **0.1111** |
| `gpt-5.4-mini` | S3-1 Word | 3/6 = **0.5000** | 3/18 = **0.1667** | 1/2 = **0.5000** | 0/1 = **0.0000** | 1/2 = **0.5000** |
| `gpt-5.4-mini` | S4-3 mshta | 7/27 = **0.2593** | 7/12 = **0.5833** | 3/9 = **0.3333** | 2/8 = **0.2500** | 3/9 = **0.3333** |

### 4.3 token・cost

| モデル | input token | output token | total token | cost (USD) |
|---|---:|---:|---:|---:|
| `gpt-4.1-mini` | 65,801 | 5,520 | 71,321 | 0.0351524 |
| `gpt-5.4-mini` | 18,706 | 7,103 | 25,809 | 0.0459930 |
| **全体** | **84,507** | **12,623** | **97,130** | **0.0811454** |

`gpt-4.1-mini`のinput tokenが多いのは、S3-1で調査を反復した一方、最終行動列へ統合できなかったためである。呼出し上限で打ち切られた結果ではない。

## 5. 調査行動と失敗原因

### 5.1 `gpt-4.1-mini`

- S3-1では24回の`investigate_lead`を反復し、親、子process、一時ファイル、DLLを繰り返し検索した。調査結果中には文書と子processへ到達可能な手掛かりがあったが、最終出力はExplorer起動、temp file、DLL loadを選び、「子processは観測されない」と結論した。
- S4-3ではmshtaからPowerShellへの関係を部分的に復元したが、mshta通信と後続のPowerShell、cmd、payload、9999番通信へ進めなかった。一部の調査応答が実在する通信を「なし」と報告したことも失敗へ寄与した。
- 主因は、検索回数不足ではなく、反復検索の停止判断、調査結果の選別、因果edgeへの統合、後段pivotである。

### 5.2 `gpt-5.4-mini`

- S3-1では調査応答がWord、子Word、文書readを提示した。最終出力は文書openを復元したが、Word→子Word edgeを落とし、Zone.Identifier、Recent LNK、lock file、module等の近傍行動を過剰接続した。
- S4-3ではmshta通信、mshta→PowerShell、PowerShell→PowerShellまで復元したが、調査応答が後続PIDを調べるよう明示したにもかかわらず1回のinvestigationで停止し、cmd、payload、後続通信を落とした。
- さらに実在しないPowerShell PID 4994とedgeを出力した。原DBではPID 4994の`process_pid`、`childproc_pid`はいずれも0件で、実際の系列は4724→2976→3820→2168である。これはGold漏れではなく調査応答／モデルの幻覚である。

## 6. Gold・実験設定の妥当性

v5正式Goldは事前レビューでsemantic step 43/43、原DBとの742 field比較mismatch 0、Stage 3一次証拠43/43を確認済みである。本pilotでも次を確認した。

- S3-1の正解となる文書openと子Wordの手掛かりは、モデルの調査結果へ到達していた。
- S4-3のGold process chainは原DBに存在する。
- モデルが追加したPID 4994は原DBに存在しない。
- 2 caseのGold chainはいずれも固定5分窓に収まり、30分窓による系列混在はない。
- hidden alert mappingは採点していない。

したがって低スコアの主因は、Gold不備、時間窓、Agent回数制限ではない。現行マルチAgentシステムの検索品質、追跡継続、証拠統合、過剰接続抑制、およびモデル推論性能である。

## 7. Gate判断

**全実験への移行はGO**とする。理由は、4/4 valid run、固定Gold分母、Stage 3非アラート条件、unbounded設定、Codex採点、hash・totals監査がすべて成立し、低スコアを実験設定不備ではなく観測可能なモデル／Agent行動として説明できたためである。

全実験では次を固定する。

1. v5正式Gold、case別確定窓、現行promptをbaselineとして変更しない。
2. 8ユースケース×3 Stageを各モデルで実行する。
3. Codex独立二重レビューと、不一致時のitem単位第三レビューを用いる。
4. 反復検索、早期停止、因果edge欠落、近傍行動の過剰接続、存在しないprocessの追加を失敗分類として記録する。
5. prompt／orchestration改善はbaseline完了後の別実験とし、baseline途中で条件を変えない。

pilotの数値はモデル選定の参考にはできるが、2 caseのみのため正式な性能値としては採用しない。

## 8. 成果物

- run・score root: `docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v5_formal/stage3_two_usecase_model_pilot_01`
- machine-readable aggregate: `pilot_scores/pilot_aggregate.json`
- Codex decision ledger: `pilot_scores/single_codex_reviews.jsonl`
- raw Codex review: `scores_codex_pilot_single_review_v1/raw_reviews/review1_raw.jsonl`
- validated Codex review: `scores_codex_pilot_single_review_v1/validated_reviews/review1.jsonl`
- 本報告のmachine-readable summary: `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_stage3_two_usecase_model_pilot_20260727.json`
