# Results summary

## Overall

| Model | Runs | Action recall | Critical evidence recall | Sequence order | Candidate precision | Overclaims |
|---|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 81 | 37.3% (321/860) | 6.0% (13/215) | 18.1% (25/138) | 34.0% (303/892) | 589 |
| `gpt-5.4-mini` | 81 | 83.9% (541/645) | 80.9% (174/215) | 62.3% (86/138) | 51.0% (126/247) | 121 |

## By stage

| Model | Stage | Action recall | Critical evidence recall | Sequence order | Candidate precision | Overclaims |
|---|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | stage1 | 52.3% (157/300) | 17.3% (13/75) | 33.3% (16/48) | 40.2% (151/376) | 225 |
| `gpt-4.1-mini` | stage2 | 33.0% (99/300) | 0.0% (0/75) | 8.3% (4/48) | 26.5% (91/344) | 253 |
| `gpt-4.1-mini` | stage3 | 25.0% (65/260) | 0.0% (0/65) | 11.9% (5/42) | 35.5% (61/172) | 111 |
| `gpt-5.4-mini` | stage1 | 88.9% (200/225) | 85.3% (64/75) | 81.3% (39/48) | 59.0% (49/83) | 34 |
| `gpt-5.4-mini` | stage2 | 80.4% (181/225) | 76.0% (57/75) | 45.8% (22/48) | 53.2% (41/77) | 36 |
| `gpt-5.4-mini` | stage3 | 82.1% (160/195) | 81.5% (53/65) | 59.5% (25/42) | 41.4% (36/87) | 51 |

## Interpretation

`gpt-5.4-mini` keeps high action and critical evidence recall even in `stage3`, where alert summary rows are hidden. This suggests that the stronger model can reconstruct much of the chain from remaining telemetry rather than only from alert summaries.

`gpt-4.1-mini` drops sharply in `stage2` and `stage3`, especially on critical evidence recall. This points to a failure mode where the model can produce plausible behavior descriptions but cannot anchor them to the required evidence.

Scenario structure matters. Explicit execution chains are easiest, multi-step tool chains increase order and overclaim errors, and the registry/app semantic chain is the hardest class, though that class currently has only three runs.
