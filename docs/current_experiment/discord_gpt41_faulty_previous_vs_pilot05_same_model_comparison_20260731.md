# Discord Run-key：gpt-4.1-mini 同一モデル比較

## 比較対象

- 前回：
  - `formal_23_chain_experiment_2rep_20260612/replicate_02`
  - model: `gpt-4.1-mini`
  - case: `chain_10_e07_discord_run_key_registry_chain`
- 今回：
  - `normal_attack_full_ledger_pilot_05/normal_chain10_gpt41`
  - model: `gpt-4.1-mini`
  - case: `chain_10_e07_discord_run_key_registry_chain`

前回の出力を、今回と同じ2-step observable component Goldとv5 atomic rubricでread-only再評価した。前回の旧3-step採点値は使用していない。

## 条件差

- 前回Stage 2/3の検索窓は概ね `15:05:00–15:10:00` で、Gold eventの `15:03:54–15:03:55` を外していた。
- 今回は全Stageを `15:03:54.731041–15:08:54.731041` に統一した。
- 前回は各Stageとも実質1 Chief lead。
- 今回はStage 1/2/3でそれぞれ5、7、1 Chief lead。
- 今回Stage 3にはlegacy TEMP VIEW guard bypassの既知交絡がある。

## Stage別精度

| Stage | 指標 | 前回 | 今回 | 増減 |
|---|---|---:|---:|---:|
| Stage 1 | Action recall | 4/6 = 66.67% | 0/6 = 0.00% | -66.67 pp |
|  | Candidate precision | 4/12 = 33.33% | 0/18 = 0.00% | -33.33 pp |
|  | Behavior-step recall | 0/2 = 0.00% | 0/2 = 0.00% | 0.00 pp |
|  | Critical evidence | 0/2 = 0.00% | 0/2 = 0.00% | 0.00 pp |
|  | Order recall | 1/1 = 100.00% | 0/1 = 0.00% | -100.00 pp |
| Stage 2 | Action recall | 0/6 = 0.00% | 3/6 = 50.00% | +50.00 pp |
|  | Candidate precision | 0/0 = N/A | 3/6 = 50.00% | N/A |
|  | Behavior-step recall | 0/2 = 0.00% | 1/2 = 50.00% | +50.00 pp |
|  | Critical evidence | 0/2 = 0.00% | 0/2 = 0.00% | 0.00 pp |
|  | Order recall | 0/1 = 0.00% | 0/1 = 0.00% | 0.00 pp |
| Stage 3 | Action recall | 3/6 = 50.00% | 6/6 = 100.00% | +50.00 pp |
|  | Candidate precision | 3/6 = 50.00% | 6/15 = 40.00% | -10.00 pp |
|  | Behavior-step recall | 1/2 = 50.00% | 2/2 = 100.00% | +50.00 pp |
|  | Critical evidence | 0/2 = 0.00% | 0/2 = 0.00% | 0.00 pp |
|  | Order recall | 0/1 = 0.00% | 0/1 = 0.00% | 0.00 pp |

## 3 Stage合計

| 指標 | 前回 | 今回 | 増減 |
|---|---:|---:|---:|
| Action recall | 7/18 = 38.89% | 9/18 = 50.00% | +11.11 pp |
| Candidate precision | 7/18 = 38.89% | 9/39 = 23.08% | -15.81 pp |
| Behavior-step recall | 1/6 = 16.67% | 3/6 = 50.00% | +33.33 pp |
| Critical evidence | 0/6 = 0.00% | 0/6 = 0.00% | 0.00 pp |
| Order recall | 1/3 = 33.33% | 0/3 = 0.00% | -33.33 pp |

## 取得内容の差

### 前回

- Stage 1:
  - `Discord.exe -> reg.exe`についてsubjectとoperationを部分取得。
  - `reg.exe -> Run key write`についてsubjectとoperationを部分取得。
  - 両部分claimは正順だったためorderを取得。
  - objectは別PID、generic Run key、CbDefense keyなどにずれ、完全stepは0。
- Stage 2:
  - Gold eventが検索窓外となり、`code_steps=[]`。
- Stage 3:
  - `reg.exe -> Run\Discord modification`を完全取得。
  - `Discord.exe -> reg.exe`はexecution contextに留まり、独立stepとして未取得。

### 今回

- Stage 1:
  - 6 candidate claimsを出したが、近傍Discord housekeepingと別registry instanceに寄り、Gold hit 0。
- Stage 2:
  - `reg.exe -> Run\Discord write`を完全取得。
- Stage 3:
  - `Discord.exe -> reg.exe`と`reg.exe -> Run\Discord write`を両方完全取得。
  - ただし出力順が逆でorderは0。
  - Gold外の上流installer chainも候補化し、precisionは40%。

## 解釈

- 同一モデルでAction recallは38.89%から50.00%、完全step recallは16.67%から50.00%へ改善した。
- 一方、候補claim数は6から13、candidate slotは18から39へ増加し、precisionは38.89%から23.08%へ低下した。
- 改善の大部分は、正しい5分窓への修正によるStage 2の復旧と、Stage 3でprocess-create stepを独立表現できたことによる。
- 複数lead化だけの因果効果とは分離できない。
- Stage 1では5 leadを使っても前回より悪化しているため、lead数増加だけでは精度は上がらない。
- Critical evidenceは両実験とも0%。canonical row、時刻、actor/target、operationを一体で提示する課題は未改善。
- Orderは33.33%から0%へ低下。取得したstepの時系列ソート／因果方向の最終検証が必要。
