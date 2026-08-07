# ATLASv2 S3: CBCアラート起点・攻撃復元実験の実行前資産

作成日: 2026-07-23  
対象DB: `Clouseau/artifact/scenarios/atlasv2/attack/h1/s3/incident.db`

## 実験単位

S3のCBCアラート対象行は11件あるが、同一のprocess-time範囲に対するアラート種別違いが含まれる。そこで、Stageごとの評価単位を次のように分けた。

| Stage | 入力数 | 評価単位 | 重複の扱い |
|---|---:|---|---|
| Stage 1 | 11 | alert-target入力 | 選定したCBCアラート要約が異なるため、11件を保持する |
| Stage 2 | 4 | unique process-time入力 | 同じprocess-time範囲のalert variantは1件に統合する |
| Stage 3 | 4 | unique process-time入力 | Stage 2と同じ4件。CBCアラート要約を隠す |

したがって、Stage 2/3で11件を平均して同一行動列を重複採点しない。最終報告では、Stage 1の「11 alert-target入力」と、Stage 2/3の「4 unique process-time入力」を分けて示す。

## 固定条件

- 全件の調査範囲は `[CBC alert create_time - 15分, create_time + 15分]`（計30分）。
- ランナーは、`enforce_time_scope` が指定されたケースについて、adapter DBの`audit_logs`、`dns_requests`、`browser_history`から範囲外の行を物理的に除去する。
- Stage 1は、`input_alert_rows[0]`の選定CBCアラートだけを可視入力とする。Gold先頭イベントは入力手掛かりに使わない。
- Stage 2/3の時刻手掛かりは、Gold先頭イベントではなく、選定アラート（または代表アラート）の`create_time`である。
- Stage 3は`--exclude-cbc-alert-summary`なしでは実行を中止する。CBCイベントテレメトリは残し、CBCアラート要約はSQLから隠す。

## Goldの範囲

| unit | 起点process | 観測クラスタ | Goldステップ | 採点対象 |
|---|---|---|---:|---|
| S3-01 / PT-01 | Word PID 5592 | S3-C1 | 3 | `msf.rtf`の読込と一時RTFの作成／削除 |
| S3-02〜04 / PT-02 | regsvr32 PID 6124 | S3-C2 | 3 | DcomLaunch → Equation Editor → regsvr32 → `:8080`接続作成 |
| S3-05〜07 / PT-03 | regsvr32 PID 3992 | S3-C3 | 8 | Equation Editor → regsvr32 → PowerShell → cmd → payload → `:9999`接続作成 |
| S3-08〜11 / PT-04 | PowerShell PID 2340 | S3-C3 | 7 | regsvr32 → PowerShell → cmd → payload → `:9999`接続作成 |

各Goldステップは、範囲内の1件の正規化済み`cbc_events`行に固定する。CBCアラート要約、ATLASシナリオ文、GTラベルをStage 3の採点根拠に使わない。

S3-01は境界ケースであり、Wordから後続Equation Editor・regsvr32・PowerShell・payloadへの未観測の因果接続をGoldに含めない。外部通信も`ACTION_CONNECTION_CREATE`としてのみ記述し、接続成功、C2、情報流出、payloadの目的を主張しない。

## 成果物

- 生成器: `src/clouseau_process_time/build_atlasv2_s3_11_cbc_attack_stage_cases.py`
- ランナー: `src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py`
- Stage 1 Gold（11件）: `data/current_experiment/gold/atlasv2_s3_11_cbc_attack_gold_20260723/`
- Stage 2/3 Gold（4件）: `data/current_experiment/gold/atlasv2_s3_4_process_time_gold_20260723/`
- Stage 1入力（11件）: `data/current_experiment/cases/atlasv2_s3_11_cbc_alert_stage1_cases_20260723.jsonl`
- Stage 2入力（4件）: `data/current_experiment/cases/atlasv2_s3_4_process_time_stage2_cases_20260723.jsonl`
- Stage 3入力（4件）: `data/current_experiment/cases/atlasv2_s3_4_process_time_stage3_cases_20260723.jsonl`
- マニフェスト: `data/current_experiment/cases/atlasv2_s3_11_cbc_attack_stage_cases_20260723_manifest.json`
- 実行前検証: `docs/current_experiment/atlasv2_s3_11_cbc_attack_preflight_validation_20260723.json`

## 検証範囲

生成器は、CBCアラート／代表アラートの同一性、30分窓、全Gold証跡の行ID・時刻・不変フィールド、Word境界、Stage別件数、入力可視性、選定alert時刻基準を検証する。モデル実行はまだ行っていない。
