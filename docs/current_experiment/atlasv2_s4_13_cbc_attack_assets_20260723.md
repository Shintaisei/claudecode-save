# ATLASv2 S4・13件 CBCアラート起点攻撃復元：実行前成果物

作成日: 2026-07-23  
選定根拠: [S4・13件の選定根拠](atlasv2_s4_13_cbc_attack_alert_selection_20260723.md)

## 1. 作成したもの

| 成果物 | 内容 |
|---|---|
| `data/current_experiment/gold/atlasv2_s4_13_cbc_attack_gold_20260723/` | Stage 1の13 alert-target Goldと、Stage 2/3の4 process-time Gold、計17件。各ステップは `cbc_events` の一次テレメトリに対応する。 |
| `data/current_experiment/cases/atlasv2_s4_13_cbc_attack_stage_cases_20260723.jsonl` | Stage 1は13入力、Stage 2/3は各4入力、計21モデル入力。 |
| `data/current_experiment/cases/atlasv2_s4_13_cbc_attack_stage_cases_20260723_manifest.json` | 件数、時間窓、実行状態を固定するmanifest。 |
| `docs/current_experiment/atlasv2_s4_13_cbc_attack_assets_validation_20260723.json` | アラート同一性・時刻・PID/親子/通信・Stage入力可視性の自動検証。 |
| `docs/current_experiment/atlasv2_s4_13_cbc_attack_stage3_answerability_20260723.json` | Stage 3でのGold可答性台帳。 |

生成器は `src/clouseau_process_time/build_atlasv2_s4_13_attack_assets.py` である。再生成は次で行う。

```powershell
python src\clouseau_process_time\build_atlasv2_s4_13_attack_assets.py
```

実モデルはまだ実行していない。

## 2. 固定した実験条件

全入力について、CBCアラートの `create_time_utc` を基準に **前後15分（計30分）** の調査範囲を固定した。Stage 1では13 alert-target入力を維持する。一方、Stage 2/3ではアラート要約を落とすと同一系列への複数アラートを区別できないため、4つのユニークprocess-time入力へ縮約する。W2とW3はrunnerの秒精度では同じ`winword.exe`・時刻入力になるため、1入力とし、Gold内で二つの局所系列を分離して採点する。`mshta.exe`と`powershell.exe`は同じC1主系列に属していても、モデルに可視なprocess入力が異なるため別入力として保持する。

| Stage | 初期入力 | `cbc_alerts` summary |
|---|---|---|
| Stage 1 | host・process・時間範囲・当該CBCアラート要約 | 初期入力として可視 |
| Stage 2 | host・process・時間範囲 | 初期入力から除外。ただしDB上は探索可能 |
| Stage 3 | host・process・時間範囲 | SQL探索対象から隠蔽。`cbc_events`テレメトリは残す |

Stage 2/3のcase JSONLでは `input_alert_rows` を空にしている。そのため、runnerがStage 1のアラート入力分岐に入らない。起点アラート行は評価用の非可視provenanceとしてだけ保持する。

| 条件 | 入力数 | 独立性の単位 |
|---|---:|---|
| Stage 1 | 13 | CBC alert target row。8つの一意な`alert_id`に属する。 |
| Stage 2 | 4 | S4-W1、S4-W2+W3、S4-C1の`mshta.exe`起点、S4-C1の`powershell.exe`起点。 |
| Stage 3 | 4 | Stage 2と同じ4入力。 |

Stage 1のWord6件は、攻撃関連の境界入力である。全件をprocess-level GT上の`attack`という意味の「真陽性」とは呼ばない。

## 3. Goldの境界

- S4-W1〜W3（Word起点）では、観測されたWord親子関係と`:8080`通信だけをGoldに含める。
- Wordと後続の`mshta.exe`主系列を、同じホスト・近い時刻であっても一本の因果系列として結ばない。
- S4-C1では、`svchost PID644 → mshta PID4724 → PowerShell PID2976 → PowerShell PID3820 → cmd PID2168 → payload PID4184/3652 → ortrta.net:9999`を、親子または通信の一次証跡で構成する。
- すべてのGoldステップは `cbc_events` のみを証跡とする。CBC alert名・reason・GTラベル・ATLASシナリオ記述はStage 3のGold証跡として使わない。

## 4. 自動検証

生成時の結果は **17 Gold、21入力、284/284 checks pass** である。各Goldについて次を検証する。

- 起点の`cbc_alerts` rowが選定したアラートと一致すること
- `create_time_utc ±15分`の固定窓であること
- 各Gold行が実在する`cbc_events` rowで、時刻範囲内であること
- プロセス生成では主体PID・子PID、通信では主体PID・remote IP・portがGold記述と一致すること
- Word境界ケースに、`mshta`以降の主系列PIDが混入していないこと
- Stage 1だけがアラート要約を初期入力に持ち、Stage 2/3は持たないこと
- 全case rowで`enforce_time_scope: true`を指定すること

## 5. 既知の注意点

Stage 1の13件は「攻撃関連のCBCアラート起点」であり、alert targetのATLAS process-level GTラベルを全件で`attack`と仮定しない。例えば子Wordの一部はGT上`contaminated`または`benign`であり、PID 2608は該当GT行を確認できない。これはモデル入力には渡さず、Gold内の評価メタデータとしてのみ保持する。

また、30分という範囲を真に実験条件とするには、runner／SQLアダプタ側で窓外ログを読めないハード制約を有効にする必要がある。この成果物は入力範囲とGoldを固定しているが、実行時のハード制限はrunner統合側の責務である。
