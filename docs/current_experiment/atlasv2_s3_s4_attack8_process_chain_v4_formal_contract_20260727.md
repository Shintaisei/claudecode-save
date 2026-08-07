# ATLASv2 attack8 process-chain v4 正式実験契約

## 1. 修正理由

`observable-component v3`は、一次テレメトリ上で個別に観測できるプロセス、
通信、ファイル操作をそれぞれ独立Gold stepとして扱った。この単位は、元の
正常23ユースケースで用いた「因果関係でまとまる主要なプロセス行動チェーン」
より細かい。

この差により、攻撃側だけが次の追加要求を受けていた。

- PIDを含むプロセスインスタンス同一性
- 一時ファイルやキャッシュ生成を含む観測componentの網羅
- 同じダウンロード・実行行動を表す通信、ファイル生成、プロセス生成の個別再現
- モデル入力へのneutral event anchorとtarget component ruleの追加

したがって、v3の正常・攻撃比較値は診断結果として保持するが、元の正常23ケースと
比較する正式な攻撃復元性能には採用しない。

## 2. 評価単位

v4の評価単位は、正常23ケースと同じく、プロセスを主体とした因果的なbehavior
chainである。各Gold stepは次の3要素で表す。

1. subject：行動主体のプロセス名
2. action：プロセスが行った意味的な行動
3. object：起動対象、文書・スクリプト、通信先など

PIDは一次証拠のprovenanceとして保存するが、subject/objectの正解要素には含めず、
完全一致を要求しない。

## 3. Gold粒度

独立stepとして含める。

- 文書・スクリプトなど、行動系列の中心となる入力
- 明示的な子プロセス生成またはプログラム実行
- remote SCT、payload取得、C2など、異なる意味段階を表す外部通信

独立stepとして含めない。

- Office一時ファイルの生成・削除
- Internet cacheへのSCT/HTA保存を、同じremote実行行動とは別に数えること
- payload取得と同じ意味段階に属するファイルmaterializationの重複計上
- module load、MRU、registry/cache housekeeping
- PIDの再現
- 時刻または同じプロセス名だけで隣接componentを接続すること

除外した一次テレメトリは削除せず、各Gold stepのsupporting evidenceまたは
`gold_granularity_audit`へ保存する。

## 4. ユースケースとGold step

| ID | chain_id | focus process | 対象行動 | Gold step |
|---|---|---|---|---:|
| S3-1 | `s3_pt_01_word_document_processing` | `winword.exe` | 文書入力とWord子プロセス | 2 |
| S3-2 | `s3_pt_02_regsvr32_remote_sct` | `regsvr32.exe` | Equation Editorからremote SCTまで | 3 |
| S3-3 | `s3_pt_03_regsvr32_long_chain` | `regsvr32.exe` | remote SCT、PowerShell、payload、C2 | 8 |
| S3-4 | `s3_pt_04_powershell_mid_chain` | `powershell.exe` | PowerShell起点の後段系列 | 7 |
| S4-1 | `s4_pt_01_word_w1` | `winword.exe` | explorer起点Word、文書、通信 | 4 |
| S4-2 | `s4_pt_02_word_w2` | `winword.exe` | WerFault起点の単一Word component | 4 |
| S4-3 | `s4_pt_03_mshta_c1` | `mshta.exe` | mshta、PowerShell、payload、C2 | 9 |
| S4-4 | `s4_pt_04_powershell_c1` | `powershell.exe` | PowerShell起点の後段系列 | 7 |
| **合計** | **8 chains** |  |  | **44** |

S4-2では、因果的に接続されていない別のWord PID clusterを同一chainへ結合しない。
S3-4とS4-4では、focus processから見て上流にある無関係な開始部分をGoldへ強制せず、
直近の親によるfocus process起動から後段の因果系列を評価する。

## 5. Stage入力条件

時間窓は正常23ケースと同じ5分である。3 Stageでhost、focus process、時間窓、
Goldを固定する。

| Stage | モデルへ提示する情報 | Alert summary |
|---|---|---|
| Stage 1 | host、focus process、5分窓、代表CBC alert | 初期入力として1件提示 |
| Stage 2 | host、focus process、5分窓 | 初期入力には含めない。調査中の検索は可能 |
| Stage 3 | host、focus process、5分窓 | 検索結果からも除外 |

モデル入力へneutral event anchor、target component rule、Gold境界、PID正解値を
追加しない。Stage 1の`anchor_event`はCBC alert、Stage 2/3は正常23ケースと同じ
scope startである。

## 6. 評価方法

正常23ケースのcomponent rubricを使用する。

- Action recall：Gold stepごとのsubject/action/object、分母は`Gold step × 3`
- Critical evidence recall：各Gold stepの非alert一次証拠、Action分母とは別診断
- Order recall：隣接Gold pair
- Candidate precision：モデルが出力した候補action slotのうち正しいslot
- Overclaim：Gold外、根拠なし、誤接続したcandidate slot

content inclusionで判定し、同義表現を許容する。PID完全一致、hidden alert対応、
ATT&CK technique名、攻撃意図は採点しない。command lineはaction/evidence属性であり、
独立candidate slotにはしない。

## 7. Agent実行条件

Chief、Investigator、SQL Agentの呼出し回数に、実験側の上限を設定しない。

- `max_investigations = null`
- `max_questions = null`
- `max_queries = null`
- `agent_call_limit_policy = unbounded_by_experiment`

モデルの最大出力tokenは安全上のAPI設定であり、Agent呼出し回数制限とは区別する。

## 8. 固定成果物

- builder：
  `src/clouseau_process_time/build_atlasv2_s3_s4_attack8_process_chain_v4_suite.py`
- cases：
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v4_stage_cases_20260727.jsonl`
- Gold：
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_process_chain_v4_gold_20260727`
- manifest：
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v4_manifest_20260727.json`
- build validation：
  `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v4_build_validation_20260727.json`
- Stage 3 validation：
  `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v4_stage3_validation_steps_20260727.csv`
- APIなしpreflight：
  `docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v4/preflight_v2/preflight.json`

## 9. 検証結果

- case：24/24
- Stage：8/8/8
- chain：8
- unique Gold step：44
- Stage別Action分母：132
- Stage別Critical evidence分母：44
- Stage別Order pair分母：36
- Stage 3 validation row：44
- source DB field mismatch：0
- Gold evidenceの5分窓外：0
- scored subject/objectのPID token：0
- raw file lifecycleの独立Gold step：0
- hidden alert mapping：非採点
- preflight：pass
- APIなしdry-run：24/24 valid JSON、Stage別8/8/8
- dry-run model：`gpt-5.4-mini`
- `max_investigations/max_questions/max_queries`：24/24 `null`
- `agent_call_limit_policy`：24/24 `unbounded_by_experiment`

dry-run rootは
`docs/current_experiment/results_2026-07-27/atlasv2_s3_s4_attack8_process_chain_v4/dryrun_01`
である。

## 10. 再実験の扱い

既存のpaired、neutral5、normal-parity v2、observable-component v3のrun、score、
監査成果物は削除・上書きしない。v4は新しいresult rootで1反復を実行し、
Codex component-rubric二重レビューで採点する。

正式比較では、正常側は元の23ユースケースの既存component-rubric結果を使用し、
攻撃側は本v4で再取得した結果を使用する。observable-component v3に合わせて作った
normal8 pilotは、粒度感度を確認する補助実験としてのみ扱う。
