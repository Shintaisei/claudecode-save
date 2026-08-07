# ATLASv2 attack8 process-chain v5 正式Goldレビュー

## 判定

`process_behavior_chain_normal23_parity_v5_formal`を、攻撃再実験の正式な正解データとして採用する。
旧v4候補は上書きせず保持するが、正式実験には使用しない。

決定論的な原DB・実験契約レビューは`PASS`である。

- 8 chain、24 case（Stage別8/8/8）
- unique Gold step：43
- semantic stepレビュー：43/43 pass
- 原`cbc_events`とのfield比較：742、mismatch 0
- focus processと時間窓で対象系列を識別可能：8/8 pass
- Stage 1 alert provenance：8/8 pass
- Stage 2/3へのalert入力漏洩：0
- scored subject/object内のPID：0
- hidden alert-to-Gold対応の採点：なし
- 攻撃意図、ATT&CK label、未観測の目的推定の採点：なし

機械可読な全stepレビュー、原DB行番号、supporting evidence、hashは
`docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_review_20260727.json`
を正本とする。

## 正常23ケースとの条件対応

正常側の参照正本は次の2点である。

- cases：`data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl`
- Gold：`data/current_experiment/gold/cbc_alert_behavior_chain_gold`

共通化したのは、固定のイベント列数ではなく、次の実験方法である。

1. 評価単位を、processをsubjectとする意味的な因果行動列とする。
2. 各stepを`subject / action / object`で採点する。
3. critical evidenceはAction分母から分離して診断する。
4. 隣接Gold pairのorder recallとcandidate precisionを採点する。
5. PIDは一次証拠のprovenanceに保持するが、正解要素にはしない。
6. 一時ファイル、cache、重複sensor rowは独立行動にしない。
7. 同じcaseのGoldと時間窓をStage 1/2/3で固定し、初期情報だけを段階的に減らす。
8. Agent呼出し回数に実験側の上限を置かない。

正常23ケースの時間窓は、21 chainが5分、1 chainが10分、1 chainが15分である。
したがって共通規則は「全caseを固定5分にすること」ではなく、
「対象行動列を含むcase別の確定窓を全Stageで固定すること」である。
攻撃8 chainはすべて完全な対象系列を5分以内に収められるため、全caseを5分とした。

## v4からの修正

v4は正式採用前の再レビューで次の2点を修正対象とした。

- `payload取得先`、`C2候補`など、一次テレメトリだけでは確定しない目的語を除去した。
- S4のW2 Word系列は、process名と5分窓だけでは近接するW1/W3との境界が曖昧だったため、
  独立した文書open・子process・通信と対応CBC alertを持つW3系列へ置換した。

W3窓内に残る`~$msf.doc`処理と`werfault.exe`由来のWord再生成は、それぞれ
一時ロックファイルのライフサイクルとクラッシュ回復である。対象W3の因果系列へは
接続せず、Goldにも採点分母にも含めない。

## 正式Gold

| ID | chain | focus process | Gold step |
|---|---|---|---:|
| S3-1 | `s3_pt_01_word_document_processing` | `winword.exe` | 2 |
| S3-2 | `s3_pt_02_regsvr32_remote_sct` | `regsvr32.exe` | 3 |
| S3-3 | `s3_pt_03_regsvr32_long_chain` | `regsvr32.exe` | 8 |
| S3-4 | `s3_pt_04_powershell_mid_chain` | `powershell.exe` | 7 |
| S4-1 | `s4_pt_01_word_w1` | `winword.exe` | 4 |
| S4-2 | `s4_pt_02_word_w3` | `winword.exe` | 3 |
| S4-3 | `s4_pt_03_mshta_c1` | `mshta.exe` | 9 |
| S4-4 | `s4_pt_04_powershell_c1` | `powershell.exe` | 7 |
| **合計** | **8 chain** |  | **43** |

Stageごとの固定分母はAction component 129、critical evidence 43、order pair 35である。

## 固定成果物

- builder：
  `src/clouseau_process_time/build_atlasv2_s3_s4_attack8_process_chain_v5_formal_suite.py`
- cases：
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl`
- Gold：
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727`
- manifest：
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_manifest_20260727.json`
- build validation：
  `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_build_validation_20260727.json`
- formal review：
  `docs/current_experiment/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_review_20260727.json`

case file SHA-256は
`85b9251cfc2ed2fb45e2ed53fd2bf8fb18821134a5cf215c959fa5dc3c888576`
である。各Gold fileのSHA-256はformal review JSONに固定した。

