# Codex Manual Double Review Rubric for gpt-5.4-mini

Scope:
- Target model: `gpt-5.4-mini`
- Target runs: `runs/gpt-5.4-mini/<stage>/*_run.json`
- Gold: `data/current_experiment/gold/cbc_alert_behavior_chain_gold/by_chain/<chain_id>/chain_gold.json`
- Stage3 denominator: only gold steps with `stage3_status=pass` in `docs/current_experiment/chain_gold_validation_2026-06-09/chain_gold_db_validation_steps_2026-06-09.csv`
- Do not use GPT judge/API scoring.

Per run output:
- Write one JSON file:
  - `review1/gpt-5.4-mini/<stage>/<instance_id>/codex_score_result.json`, or
  - `review2/gpt-5.4-mini/<stage>/<instance_id>/codex_score_result.json`
- Each review pass must be independent. Do not copy the other review's result.

Required scoring:
- For each answerable gold step, score four required items as `0` or `1`:
  - `subject`
  - `operation`
  - `object`
  - `critical_evidence`
- Credit only behavior recovered in `output_text.code_steps` or `output_text.code_sequence`.
- Alert titles, input hints, nearby excluded evidence, and limitations do not count as recovered behavior unless the candidate makes the behavior claim in the chain.
- Partial generic matches can receive credit only for the exact required item. Example: `cmd.exe` as subject can score `subject=1` even if the object is wrong.
- Critical evidence requires the candidate to cite or use the relevant evidence class/field, such as parent path, process command line, child process/object, file/reg mod field, or telemetry source. A bare alert name is not enough.
- Score each adjacent gold order pair as `1` only when the candidate orders the corresponding recovered behavior in the correct sequence.

Also record:
- candidate claim count
- overclaim / nearby / hallucinated claim count
- short Japanese rationale for important misses and overclaims

Recommended JSON shape:
```json
{
  "reviewer": "codex_manual_review1",
  "scoring_mode": "manual_strict_0_1_no_api",
  "model": "gpt-5.4-mini",
  "stage": "stage1",
  "instance_id": "...",
  "run_json": "...",
  "gold_file": "...",
  "stage3_answerable_filter_applied": false,
  "gold_required_item_scores": [
    {
      "item_id": "<chain_id>:<step_id>:subject",
      "step_id": "<step_id>",
      "kind": "subject",
      "gold_value": "...",
      "matched_candidate_excerpt": "... or null",
      "score": 0,
      "reason_ja": "..."
    }
  ],
  "order_pair_scores": [
    {
      "before_step_id": "...",
      "after_step_id": "...",
      "score": 0,
      "reason_ja": "..."
    }
  ],
  "candidate_claims_review": {
    "candidate_action_claim_count": 0,
    "overclaim_slot_count": 0,
    "nearby_action_fp_count": 0,
    "hallucinated_claim_count": 0,
    "notes_ja": "..."
  },
  "totals": {
    "action_step_recall_hits": 0,
    "action_step_recall_total": 0,
    "action_step_recall": null,
    "critical_evidence_recall_hits": 0,
    "critical_evidence_recall_total": 0,
    "critical_evidence_recall": null,
    "behavior_sequence_order_hits": 0,
    "behavior_sequence_order_total": 0,
    "behavior_sequence_order": null,
    "candidate_claim_precision_hits": 0,
    "candidate_claim_precision_total": 0,
    "candidate_claim_precision": null,
    "overclaim_slot_count": 0
  },
  "judge_summary_ja": "..."
}
```

