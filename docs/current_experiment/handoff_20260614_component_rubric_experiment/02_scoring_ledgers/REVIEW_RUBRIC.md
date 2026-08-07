# Component Rubric Review Instructions

Use this rubric for the component-rubric rescoring only. Do not use the stricter behavior-plus-evidence step metric here.

## Unit

Score each run against the non-alert gold chain steps.

- `action_step_recall`: subject/action/object component recall. Denominator is `gold_step_count * 3`.
- `critical_evidence_recall`: whether each gold step has its critical non-alert evidence recovered. Denominator is `gold_step_count`.
- `behavior_sequence_order`: whether adjacent gold behavior order is recovered. Denominator is `max(gold_step_count - 1, 0)`.
- `candidate_claim_precision`: correct candidate claim slots divided by all candidate claim slots.
- `overclaim_slot_count`: candidate claim slots that are unsupported, wrong, or outside the gold behavior.

## Matching Policy

Use content inclusion, not strict wording or exact JSON shape. If the candidate output contains the same substantive subject, action, object, or evidence content as the gold data, count that component as a hit even when phrasing, field names, order of explanation, or Japanese/English wording differs.

Do not require the candidate to reproduce every raw-log field. A critical evidence hit is valid when the candidate recovers the essential non-alert evidence content that supports the gold step, such as process/command/object/network/registry evidence. However, alert-only content still must not be counted as non-alert evidence.

## Evidence Policy

Use the non-alert gold as ground truth. CBC alert fields may explain why the run started, but alert-only evidence must not create a correct non-alert evidence hit.

## GPT-5.5 Raw Text Salvage

GPT-5.5 violated the formal JSON/code_steps contract. For those runs:

1. First normalize the raw prose/table output into candidate behavior/evidence claim slots.
2. Then score the normalized slots with the same component rubric.
3. Report these rows separately with `contract=raw_text_contract_failed`.

## Reviewer Output Schema

Each reviewer JSONL row must contain:

```json
{
  "dataset_label": "...",
  "replicate": "...",
  "model": "...",
  "stage": "...",
  "instance_id": "...",
  "chain_id": "...",
  "chain_type": "...",
  "run_json": "...",
  "gold_steps_jsonl": "...",
  "contract": "formal_json_code_steps | raw_text_contract_failed",
  "review_pass": true,
  "action_step_recall_hits": 0,
  "action_step_recall_total": 0,
  "critical_evidence_recall_hits": 0,
  "critical_evidence_recall_total": 0,
  "behavior_sequence_order_hits": 0,
  "behavior_sequence_order_total": 0,
  "candidate_claim_precision_hits": 0,
  "candidate_claim_precision_total": 0,
  "overclaim_slot_count": 0,
  "candidate_step_count": 0,
  "normalized_candidate_step_count": 0,
  "review_summary_ja": "..."
}
```
