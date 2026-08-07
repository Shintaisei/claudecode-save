# Final Per-Item Review Rubric for gpt-5.4-mini Codex Scores

Scope:
- Target model: `gpt-5.4-mini`
- Target final scores: `final/gpt-5.4-mini/<stage>/<instance_id>/codex_score_result.json`
- Target count: 81 final score artifacts.
- Each final score must receive two independent item-level reviews:
  - `final_item_review1/<stage>/<instance_id>/review_result.json`
  - `final_item_review2/<stage>/<instance_id>/review_result.json`

Review question:
- Is the final score artifact correct under `RUBRIC.md`, based only on the corresponding `run_json` `output_text.code_steps` / `output_text.code_sequence`, the referenced `gold_file`, and the Stage3 validation filter?

Required checks per item:
- The final score JSON is readable and has correct `model`, `stage`, `instance_id`.
- The final score references the expected `run_json` and `gold_file`.
- `gold_required_item_scores` are consistent with the recovered behavior claim in `code_steps` / `code_sequence`.
- `order_pair_scores` are consistent with the recovered behavior order.
- `totals` agree with the item-level scores and order scores.
- `candidate_claims_review` and overclaim counts are plausible under the rubric.
- Stage3 only: `stage3_answerable_filter_applied=true`, and scored gold steps are limited to validation CSV rows with `stage3_status=pass`.
- No OpenAI judge/API, no `--score`, and no `score_element_order_with_gpt.py`.

Review result JSON shape:
```json
{
  "reviewer": "final_item_review1",
  "model": "gpt-5.4-mini",
  "stage": "stage1",
  "instance_id": "...",
  "final_score_path": "...",
  "run_json": "...",
  "gold_file": "...",
  "review_pass": true,
  "checks": {
    "json_schema_ok": true,
    "required_item_scores_ok": true,
    "order_pair_scores_ok": true,
    "totals_ok": true,
    "candidate_claim_counts_ok": true,
    "stage3_filter_ok": true
  },
  "issues": [],
  "recommended_action": "accept",
  "review_summary_ja": "..."
}
```

PASS criteria:
- `review_pass=true`
- all `checks` values are true
- `issues=[]`
- `recommended_action="accept"`

FAIL criteria:
- Any material scoring disagreement, denominator/filter error, item-total mismatch, missing artifact, or evidence that the artifact was not scored under the rubric.
