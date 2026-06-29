# 本実験後の置換メモ

作成日: 2026-06-09

この原稿は6ページ構成を先に作るため、本文中では「プレ実験」として Discord Run key の単一ケースを扱っている。本実験後は以下を置換する。

## 置換必須

- `main.tex` の abstract:
  - 「プレ実験」「単一ケース」の表現を、本実験の対象ケース数に合わせて更新する。
- `main.tex` の `プレ実験設計`:
  - 単一ケース説明を、正式なケース集合・選定基準・除外基準へ置換する。
- `main.tex` の `プレ実験結果`:
  - 表 `tab:result` を複数ケース集計表へ置換する。
  - 現在の canonical single-case values は削除または補助例へ降格する。
- `main.tex` の `考察`:
  - Stage 3低下が再現した場合のみ、alert summary rowsの有無が到達性に影響したという主張を維持する。
  - 再現しない場合は Discord Run key 固有の観察として弱める。
- `main.tex` の `本実験への拡張計画`:
  - 本実験完了後は削除し、実験結果・失敗分析・妥当性への脅威へ置換する。

## 現在の重要な sentinel

- canonical source:
  - `docs/current_experiment/results_2026-06-04/formal_gpt41mini_gpt54mini_action_claim_eval_20260605/canonical_from_rerun_20260606/formal_step_score_summary_canonical_20260606.md`
- gold source:
  - `data/current_experiment/gold/discord_reg_runkey/gold_behavior_node.json`
- score source:
  - `docs/current_experiment/results_2026-06-04/formal_gpt41mini_gpt54mini_action_claim_eval_20260605/scores_gpt55_raw_rerun_14denom_20260605/*/score_result.json`
- validation source:
  - `docs/current_experiment/results_2026-06-04/formal_gpt41mini_gpt54mini_action_claim_eval_20260605/canonical_from_rerun_20260606/validation_report_20260606.json`
- single-case Stage 3 run evidence:
  - `docs/current_experiment/results_2026-06-04/formal_gpt41mini_gpt54mini_action_claim_eval_20260605/runs/gpt54mini_stage3_alert_summary_removed_run.json`
- formal chain DB validation:
  - `docs/current_experiment/chain_gold_validation_2026-06-09/chain_gold_db_validation_steps_2026-06-09.json`
  - `docs/current_experiment/chain_gold_validation_2026-06-09/README.md`
- `gpt-5.4-mini Stage 2`:
  - recall/precision: `14/14`
  - order: `1/2`
  - このため「完全な行動列復元」「順序2/2」と書かない。
- Stage 3:
  - alert summary rowsだけ除外。
  - CBC EDR/NGAV telemetryとOS側ログは残っている。

## PDF作成時に確認すること

- FIT2026要件:
  - A4
  - 上30mm、下25mm、左右20mm、コラム間7mm目安
  - ページ番号なし
  - 3MB以内
  - フォント埋め込み
- 現環境では `pdflatex` / `latexmk` が未検出のため、ページ数とPDF条件は未検証。
