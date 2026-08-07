# Chain Gold Validation 2026-06-09

## 結論

27 behavior chains / 75 gold steps について、ATLASv2 benign h1 の source DB を照合した。

```text
DB: Clouseau/artifact/scenarios/atlasv2/benign/h1/benign-1/incident.db
status: passed_with_stage3_partial_support
chain_count: 27
gold_step_count: 75
step_pass_count: 75
step_fail_count: 0
stage1_input_pass_count: 27
stage1_input_fail_count: 0
stage3_supported_step_count: 65
stage3_unsupported_step_count: 10
```

raw DB 上の gold correctness は 75/75 で確認済み。pass 判定は、抽出した material terms が同一DB行にすべて含まれる場合だけに限定した。`any_term` 一致は pass に使わない。

best evidence の内訳は `cbc_events` が 65 step、`cbc_alerts` が 10 step。`cbc_alerts` の検索対象には `process_path` も含めるため、C08 の `python.exe` / `hello.py` 行は `cbc_alerts.id=126` で支持される。

2026-06-09の厳格レビューで、DNS packet capture chain に混入していた `python.exe` child-process step 3件 (`C01-S04`, `C13-S04`, `C25-S04`) は削除した。これらは同一episode内の out-of-scope SimpleHTTPServer chain と一致しており、`start_dns_logs.bat` lineage のDB証跡では支持されなかった。

## 入力条件

全27チェーンで、入力条件は次の3 stageに固定する。

| Stage | 入力として渡す | 入力に含めない |
|---|---|---|
| Stage 1 | `host`, `focus_processes`, `chain_window_start_utc`, `chain_window_end_utc`, chain-specific CBC alert triage fields (`alert_time`, `alert_id`, `alert_name`, `alert_reason`, `alert_process`, `alert_pid`, `alert_source_stream`, `alert_severity`) | `gold_steps`, `chain_type`, `expected_behavior_label`, parent process, command line, child process, registry/file/network object |
| Stage 2 | `host`, `focus_processes`, `chain_window_start_utc`, `chain_window_end_utc` | CBC alert id/name/reason, command line, parent process, target object, gold steps |
| Stage 3 | Stage 2 と同じ | Stage 2 と同じ。DB検索では `cbc_alerts` / `cbc-edr-alerts` / `cbc-ngav-alerts` summary rows を除外し、`cbc_events` telemetry は残す |

Stage 1 の alert rows は、単純な「時間窓内の全アラート」ではなく、gold supporting evidence に出ている `alert_id` から特定した chain-specific alert triage rows とする。alert_id が取れない場合に時間窓内の全アラートへフォールバックしない。

`gold_alert_count` は過去の5分窓/chain整理時の参考値として残す。正式な Stage 1 入力行数は `db_stage1_alert_row_count` を使う。監査用に、時間窓内の全アラート数は `db_raw_window_alert_row_count` として別に保存する。

`chain_input_conditions_2026-06-09.json/csv` は監査用manifestなので、`chain_id`, `chain_type`, `gold_sample_alert_ids` などの追跡メタデータを含む。実験でモデルへ渡す入力は `chain_stage_inputs_model_ready_2026-06-09.json` を使う。このmodel-ready fileは `input_id`, `stage`, `input`, `db_filter` だけを持ち、`chain_type`, `gold_steps`, `gold_alert_count`, `gold_sample_alert_ids`, command line, parent process, target object は含まない。`input_id` と chain の対応は `chain_stage_input_audit_map_2026-06-09.csv` に分離する。

## Stage 3 の扱い

Stage 3 は alert summary rows を取り除く条件なので、raw DB gold と同じ75 stepすべてが観測可能とは限らない。今回のDB照合では 65/75 step が `cbc_events` または `sysmon_logs` で支持され、次の10 stepは alert summary 除去後には未支持として扱う。

```text
C03-S01, C03-S02,
C08-S01, C08-S02, C08-S03, C08-S04,
C20-S01, C20-S02,
C27-S01, C27-S02
```

したがって、Stage 3評価では `stage3_status=pass` の65 stepを answerable gold とし、`unsupported_after_alert_summary_removal` の10 stepは alert-only gold として別扱いにする。

## 生成物

- `chain_input_conditions_2026-06-09.json`
  - 全27チェーンの Stage 1/2/3 入力条件。
  - Stage 1 の chain-specific alert rows を含む。
- `chain_input_conditions_2026-06-09.csv`
  - 入力条件の一覧表。
- `chain_stage_inputs_model_ready_2026-06-09.json`
  - 実験でモデルへ渡すための Stage 1/2/3 入力。監査メタデータとgold情報は含まない。
- `chain_stage_input_audit_map_2026-06-09.csv`
  - `input_id` と chain の対応表。モデル入力には使わない。
- `chain_gold_db_validation_steps_2026-06-09.json`
  - 75 gold steps それぞれのDB照合結果。
  - `status` は raw DB support、`stage3_status` は alert summary 除去後の support を表す。
- `chain_gold_db_validation_steps_2026-06-09.csv`
  - step検証の一覧表。
- `chain_gold_db_validation_summary_2026-06-09.json`
  - 検証サマリ。

## 再実行

```powershell
python src\clouseau_process_time\validate_chain_gold_against_db.py
```

このスクリプトはDBをコピー・変更しない。検索窓は各 chain window の前後5分で、chain window外に出る実行証跡も監査対象に含める。
