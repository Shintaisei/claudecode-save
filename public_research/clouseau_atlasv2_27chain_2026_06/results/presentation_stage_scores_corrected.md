# Presentation Stage Scores, Corrected

This table is for slides. `Action recall` is normalized to the same definition for both models: subject, operation, and object only. `Critical evidence` is reported separately.

The correction matters because the archived `gpt-4.1-mini` aggregate encoded action recall with four slots per answerable step, while `gpt-5.4-mini` encoded action recall with three slots per answerable step. For comparability, the critical-evidence slot is removed from `gpt-4.1-mini` action recall and kept only in the `Critical evidence` column.

| Model | Stage | Runs | Answerable steps | Action recall (S/O/O) | Critical evidence | Sequence order | Candidate precision | Overclaims |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | Stage 1 | 27 | 75 | 64.0% (144/225) | 17.3% (13/75) | 33.3% (16/48) | 40.2% (151/376) | 225 |
| `gpt-4.1-mini` | Stage 2 | 27 | 75 | 44.0% (99/225) | 0.0% (0/75) | 8.3% (4/48) | 26.5% (91/344) | 253 |
| `gpt-4.1-mini` | Stage 3 | 27 | 65 | 33.3% (65/195) | 0.0% (0/65) | 11.9% (5/42) | 35.5% (61/172) | 111 |
| `gpt-5.4-mini` | Stage 1 | 27 | 75 | 88.9% (200/225) | 85.3% (64/75) | 81.2% (39/48) | 59.0% (49/83) | 34 |
| `gpt-5.4-mini` | Stage 2 | 27 | 75 | 80.4% (181/225) | 76.0% (57/75) | 45.8% (22/48) | 53.2% (41/77) | 36 |
| `gpt-5.4-mini` | Stage 3 | 27 | 65 | 82.1% (160/195) | 81.5% (53/65) | 59.5% (25/42) | 41.4% (36/87) | 51 |

## Notes For Speaking

- Stage 3 has fewer answerable steps because alert-summary-dependent gold steps are excluded from the denominator.
- Candidate precision uses the number of candidate action claims as its denominator, so it naturally differs by model and stage.
- The strongest slide-level claim is that `gpt-5.4-mini` keeps high action and critical-evidence recall even in Stage 3, while precision and order remain the main weaknesses.
