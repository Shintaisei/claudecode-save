# Scoring Ledgers

このフォルダは採点の監査用。最終集計の数字だけでなく、どのレビュー結果から採用したかを追うために使う。

## Files

| file/folder | role |
| --- | --- |
| `REVIEW_RUBRIC.md` | 今回の component rubric。内容が含まれていれば hit とする採点方針。 |
| `component_rubric_20260614/codex_component_double_reviews.jsonl` | Codex 上で行った2重レビューの採用元 ledger。 |
| `component_rubric_20260614/review_conflicts.jsonl` | 2レビューで割れた項目の一覧。 |
| `component_rubric_20260614/codex_component_third_review_adoptions.jsonl` | 割れた項目への第三レビュー・採用結果。 |
| `component_rubric_20260614/review_queue_status.json` | 採点キューの完了状況。 |
| `legacy27_filtered_scores_20260611/non_alert_per_case_scores.csv` | 旧27チェーンから現在の23チェーン範囲を抜いて3セット目に使った採点表。 |

## Scoring Policy

- `action_step_recall`: 正解行動ステップの内容が候補出力に含まれている割合。
- `critical_evidence_recall`: 重要証跡の内容が候補出力に含まれている割合。
- `behavior_sequence_order`: 正解行動の順序関係を候補出力が保てている割合。
- `candidate_claim_precision`: 候補出力の主張のうち、正解内容に対応するものの割合。
- `overclaim_slot_count`: 正解にない余計な主張・過剰な証跡・過剰な行動の数。

採点は「内容が入っていればOK」の方針。出力形式が崩れていても、内容が読める場合は salvage して採点した。ただし alert-only evidence を non-alert evidence の代わりとしては数えない。

## Review Process

1. Reviewer A と Reviewer B が独立に Codex 上で採点。
2. A/B が一致したものは採用。
3. 割れたものは第三レビューで採用値を決定。
4. GPT-5.5 は出力契約が崩れたため、形式準拠結果ではなく raw text salvage 結果として別扱い。
