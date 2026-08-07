# Codex-only attack8 paired scoring

`codex_manual_attack8_scoring.py` is an offline scoring route. It does not call
OpenAI or another model API. Codex tasks fill the generated JSONL templates,
and the script performs deterministic validation, adjudication, and aggregation.

## 1. Prepare the 24-case queue

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py prepare `
  --result-root <gpt54mini_replicate_01> `
  --score-root <gpt54mini_replicate_01>/scores_codex_manual_double_review `
  --expected-count 24
```

Preparation accepts only completed run JSONs with valid `output_text` JSON and
the experiment's unbounded-agent configuration. It binds each queue item to
SHA-256 hashes of the run, gold, Stage 3 validation CSV, and fixed scoring
contract. Potential candidate slots are frozen from `code_steps` before review.
Each reviewer explicitly decides whether a potential slot is a substantive,
non-null scoring slot using `include_in_denominator`. That extraction decision
is itself subject to independent agreement and third-review adjudication.

The review policy explicitly sets `alert_mapping_scored=false`. Reviewers must
not score whether the model inferred an unavailable CBC alert ID, title,
reason, or alert-to-Gold correspondence. Only the fixed Gold behavior
components, order pairs, evidence diagnostic, and output candidate slots are
scored. This exclusion does not turn an alert title into a valid behavior:
when the submitted `code_steps` themselves use an alert row/title as an action,
that candidate is judged by the ordinary normal-reconstruction precision rule.

### Preparing later batches safely

`--exclude-queue` is repeatable. It excludes an already queued case only when
its model, Stage, instance ID, and run SHA-256 exactly match the current
completed run. A changed run under the same case key stops preparation instead
of silently reusing the old review.

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py prepare `
  --result-root <gpt54mini_replicate_01> `
  --score-root <gpt54mini_replicate_01>/scores_codex_manual_double_review/batch_02 `
  --exclude-queue <score-root>/batch_01/review_queue.jsonl `
  --expected-count <newly-completed-count>
```

Additional prior batches can be supplied with more `--exclude-queue` options.
`--expected-count` always refers to the number of new queue rows remaining
after exclusions. The manifest records completed count before exclusion,
excluded rows, every exclusion queue SHA-256, new eligible count, and rejected
runs. Existing queues and outputs are never modified.

Give separate copies of `review_template.jsonl` and `review_queue.jsonl` to two
independent Codex tasks. Reviewers must use different `reviewer_id` values and
must not see one another's decisions.

For three smaller immutable batches, `prepare` also accepts repeatable
`--stage`. For example, `--stage stage1 --expected-count 8` creates the eight
Stage-1 cases only. Prepare Stage 2 and Stage 3 into different score roots,
complete each independent review/adjudication cycle, then merge the three
adopted ledgers with `merge-batches`.

## 2. Validate both independent reviews

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py validate-review `
  --queue <score-root>/review_queue.jsonl `
  --reviewer-jsonl <raw-review1.jsonl> `
  --review-name review1 `
  --score-root <score-root>

python src/clouseau_process_time/codex_manual_attack8_scoring.py validate-review `
  --queue <score-root>/review_queue.jsonl `
  --reviewer-jsonl <raw-review2.jsonl> `
  --review-name review2 `
  --score-root <score-root>
```

Validation checks the complete gold-item, order-pair, and candidate-slot ID
sets; binary decisions; immutable candidate fields; gold references; kind
compatibility; and contract provenance. No submitted totals are trusted.

## 3. Adopt exact matches and create the conflict queue

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py finalize `
  --queue <score-root>/review_queue.jsonl `
  --review1 <score-root>/validated_reviews/review1.jsonl `
  --review2 <score-root>/validated_reviews/review2.jsonl `
  --score-root <score-root>
```

Exact item-level decision matches are adopted. Conflicts are written to
`formal_outputs/review_conflicts.jsonl`; the corresponding full cases and
templates are written to `review3_conflict_queue.jsonl` and
`review3_template.jsonl`.

## 4. Validate review 3 and finalize

Have a third independent Codex task score only the conflict queue, then run:

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py validate-review `
  --queue <score-root>/formal_outputs/review3_conflict_queue.jsonl `
  --reviewer-jsonl <raw-review3.jsonl> `
  --review-name review3 `
  --score-root <score-root>
```

Because formal output artifacts are immutable, perform the final three-review
aggregation in a new child output root:

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py finalize `
  --queue <score-root>/review_queue.jsonl `
  --review1 <score-root>/validated_reviews/review1.jsonl `
  --review2 <score-root>/validated_reviews/review2.jsonl `
  --review3 <score-root>/validated_reviews/review3.jsonl `
  --score-root <score-root>/final_with_review3
```

The rule is exact double-review agreement, otherwise 2-of-3 per item. A
candidate-slot tuple with no majority is conservatively scored as false
positive with no gold match. The final aggregate reports Stage 1/2/3 and
overall behavior recall, action recall, action precision, sequence order,
critical-evidence recall, and candidate precision.

## 5. Merge completed batches for the final 24-case report

After each batch has completed any required third review, merge its final
`adopted_reviews.jsonl` ledgers offline:

```powershell
python src/clouseau_process_time/codex_manual_attack8_scoring.py merge-batches `
  --adopted-ledger <batch_01>/final_with_review3/formal_outputs/adopted_reviews.jsonl `
  --adopted-ledger <batch_02>/final_with_review3/formal_outputs/adopted_reviews.jsonl `
  --score-root <score-root>/merged_final_24
```

The production defaults require exactly 24 adopted cases and exactly 8 cases
in each of Stage 1, Stage 2, and Stage 3. The merger rejects duplicate queue
IDs and duplicate `(model, stage, instance_id)` keys. For current ledgers it
recomputes and verifies the full queue-contract SHA-256, run/gold provenance,
adopted-decision SHA-256, and every formal metric total before aggregation.
It writes immutable
`formal_outputs/adopted_reviews.jsonl` and
`formal_outputs/formal_aggregate_adopted_only.json`.

`--expected-count` and `--expected-stage-count` exist for synthetic tests or a
separately declared non-production suite; the attack8 final report uses their
defaults of 24 and 8.

Every writer refuses to overwrite an existing artifact.
