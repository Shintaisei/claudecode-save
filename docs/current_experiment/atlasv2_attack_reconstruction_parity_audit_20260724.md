# ATLASv2 攻撃行動復元実験の設計監査と修正版

> **更新注記（2026-07-26）**  
> `attack8_paired`実行後の独立監査で、Stage 2/3のtimestampが30分窓開始時刻へ
> 置換され、正常系の局所chain anchorと意味が揃っていないこと、および
> 非提示アラートとGoldの対応が一部で一意に定まらないことを確認した。
> 本書の修正版契約は次の統合成果物により更新されている。  
> `docs/current_experiment/normal_attack_evidence_constrained_behavior_reconstruction_research_synthesis_20260726.md`

## 結論

2026-07-23 の `attack24` 結果は、正常行動復元実験の Stage 1/2/3 と直接比較できない。
モデルの良し悪しを判断する前に、評価単位、Gold、時間スコープ、集計指標が段階間・実験間で一致していなかった。

既存の40出力は削除しない。ただし位置付けを「個別 CBC アラートを起点にした感度調査」に変更し、
Stage 間の性能差を示す正式結果には使わない。

正式な比較用として、同じ8行動チェーンを Stage 1/2/3 で固定する
`attack8_paired` を新たに作成した。

## 旧 attack24 で確認した不一致

### 1. Stage 間で評価単位が変わる

| 実験 | Stage 1 | Stage 2 | Stage 3 |
|---|---:|---:|---:|
| 正常行動復元 | 27行動チェーン | 同じ27行動チェーン | 同じ27行動チェーン |
| 旧 attack24 | 24個別アラート | 8統合プロセス時間窓 | 8統合プロセス時間窓 |
| 修正 attack8_paired | 8行動チェーン | 同じ8行動チェーン | 同じ8行動チェーン |

旧 attack24 の Stage 1 は、同じ攻撃クラスタに属する別アラートを別ケースとして反復計上する。
一方、Stage 2/3 は重複するアラートを統合している。
したがって Stage 1 と Stage 2/3 の平均は、入力情報量だけでなくケース構成の差も含む。

### 2. Stage 間で Gold が変わる

正常行動復元は、同じ `chain_gold.json` を3条件で採点する。
旧 attack24 は Stage 1 の個別アラート用 Gold と、Stage 2/3 の統合チェーン Gold が異なる。
このため、再現率の分母と要求される行動境界が同一ではない。

### 3. 時間スコープの実装が異なる

正常行動復元では、宣言したチェーン時間窓を探索・報告の中心にするが、
adapter DB をその時間だけに物理切断しない。
旧 attack24 は `enforce_time_scope=true` により、アラート時刻±15分へ物理切断していた。

さらに旧 attack24 の Stage 2/3 は代表アラート時刻を clue の timestamp に使うが、
正常側はチェーン時間窓の開始時刻を scope anchor に使う。

### 4. 手作業スコアを正常側の正式指標と比較できない

旧 attack24 の手作業集計は、各 Gold step を
`subject / operation / object / command_line / critical_evidence`
の5要素として一つの総分母にした。

現行の正式 scorer は次のように分離する。

- `action_step_recall` / `action_step_precision`: `critical_evidence` を除く行動要素
- `critical_evidence_recall`: canonical evidence の独立診断指標
- `behavior_step_recall`: Gold step の粗い回収
- `behavior_sequence_order`: 回収できた step 間の順序

旧手作業集計では全ケースで canonical event ID が出力されず、
`critical_evidence` が一律0になった。その0を総分母へ混ぜた値は、
正常側の `action_step_recall` より機械的に低くなる。

また、自動 scorer の完了結果は40ケース中2ケースだけで、
残りは S3/S4 ごとに異なる手作業ファイルで採点されている。
この状態は正式な同一プロトコル採点ではない。

## 旧結果から言える範囲

旧出力は無効ではない。次の分析には使える。

- 同一攻撃クラスタで、どの CBC alert title が探索を誘導しやすいか
- 個別アラート起点で周辺チェーンを混入する傾向
- PID、親子関係、command line、canonical event ID の欠落傾向
- alert-target triage の感度分析

一方、次には使わない。

- Stage 1 > Stage 2 > Stage 3 の性能差
- 正常行動復元との再現率の直接比較
- 「攻撃は正常より難しい／易しい」という結論

## 修正 attack8_paired の契約

評価単位は次の8行動チェーンで固定する。

- S3: Word document processing
- S3: regsvr32 remote SCT
- S3: regsvr32 long chain
- S3: PowerShell mid chain
- S4: Word W1
- S4: Word W2/W3
- S4: mshta C1
- S4: PowerShell C1

各チェーンで、host、focus process、時間窓、Gold を3段階すべて同一にする。

- Stage 1: 代表 CBC alert 1件 + host/process/time
- Stage 2: host/process/time のみ。DB内の alert summary は調査で発見可能
- Stage 3: Stage 2 と同じ入力。alert summary rows のみ SQL tool から非表示、`cbc_events` は保持

正常側と同様に、時間窓は探索・主チェーン報告のスコープであり、
adapter DB の物理切断には使わない。

## 検証結果

ビルドおよび scorer preflight は pass。

| 項目 | Stage 1 | Stage 2 | Stage 3 |
|---|---:|---:|---:|
| ケース数 | 8 | 8 | 8 |
| Gold step | 45 | 45 | 45 |
| action required item | 135 | 135 | 135 |
| critical evidence item | 45 | 45 | 45 |
| order pair | 36 | 36 | 36 |

Stage 1/2/3 を各1件 dry-run し、次を確認した。

- Stage 1 の clue のみに alert ID/name/severity がある
- Stage 2 の clue は host/process/timestamp のみ
- Stage 3 の clue は Stage 2 と同じで、alert summary hidden が明記される
- 3条件ともモデル API は未呼び出し

## 成果物

- ケース生成:
  `src/clouseau_process_time/build_atlasv2_s3_s4_attack8_paired_suite.py`
- 実行・採点:
  `src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py`
- 24入力:
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_paired_stage_cases_20260724.jsonl`
- 8 Gold:
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_paired_gold_20260724/`
- build validation:
  `docs/current_experiment/atlasv2_s3_s4_attack8_paired_build_validation_20260724.json`
- run preflight:
  `docs/current_experiment/results_2026-07-24/atlasv2_s3_s4_attack8_paired/preflight.json`

## 実行コマンド

モデルを呼ばない再検証:

```powershell
python src/clouseau_process_time/build_atlasv2_s3_s4_attack8_paired_suite.py
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py --preflight
```

モデル実行:

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py `
  --run --models gpt-5.4-mini --log-cost
```

既存 run の正式 scorer 採点:

```powershell
python src/clouseau_process_time/run_atlasv2_s3_s4_attack8_paired_experiment.py `
  --score --models gpt-5.4-mini
```

正式報告では、同一 scorer を独立2回実行し、不一致を第三レビューまたは保守的規則で解消する。
単一の手作業スコアと混在させない。

## 実行費用の目安

旧40 run は合計 407,987 input tokens / 133,515 output tokens、
記録費用は約0.88 USD だった。
同程度の出力長なら修正版24 run は概算約0.53 USD。
scorer のモデル呼び出し費用は別に発生する。

## 正式実験への移行

この監査を受け、正式な実験条件は
`atlasv2_attack8_paired_formal_experiment_contract_20260724.md`
に固定した。Agent呼び出し回数による打ち切りは使用せず、
最初の試行は `gpt-4.1-mini`、1反復で実施する。
