# Normal / attack observable-component v3 formal comparison

## Contract

- Model: `gpt-5.4-mini`
- Replicates: one formal pilot replicate per class
- Cases: 8 normal and 8 attack use cases × 3 stages = 24 runs per class
- Scope: neutral focus-process anchor and ±5-minute window
- Scoring unit: observable semantic step components (subject/action/object)
- Alert mapping: hidden or unavailable alert-to-Gold correspondence is not scored
- Agent calls: unbounded by the experiment in all 48 runs
- Review: offline Codex independent double review, third review for conflicts

## Overall

| Metric | Normal | Attack | Normal − attack | Ratio |
|---|---:|---:|---:|---:|
| action_step_recall | 53/207 = 0.2560 | 53/531 = 0.0998 | +0.1562 | 2.57× |
| candidate_claim_precision | 53/156 = 0.3397 | 53/221 = 0.2398 | +0.0999 | 1.42× |
| behavior_step_recall | 27/69 = 0.3913 | 29/177 = 0.1638 | +0.2275 | 2.39× |
| behavior_sequence_order | 8/45 = 0.1778 | 9/153 = 0.0588 | +0.1190 | 3.02× |
| critical_evidence_recall | 10/69 = 0.1449 | 20/177 = 0.1130 | +0.0319 | 1.28× |

## By stage

### stage1

| Metric | Normal | Attack | Normal − attack |
|---|---:|---:|---:|
| action_step_recall | 11/69 = 0.1594 | 15/177 = 0.0847 | +0.0747 |
| candidate_claim_precision | 11/33 = 0.3333 | 15/86 = 0.1744 | +0.1589 |
| behavior_step_recall | 5/23 = 0.2174 | 8/59 = 0.1356 | +0.0818 |
| behavior_sequence_order | 0/15 = 0.0000 | 3/51 = 0.0588 | -0.0588 |
| critical_evidence_recall | 0/23 = 0.0000 | 4/59 = 0.0678 | -0.0678 |

### stage2

| Metric | Normal | Attack | Normal − attack |
|---|---:|---:|---:|
| action_step_recall | 25/69 = 0.3623 | 23/177 = 0.1299 | +0.2324 |
| candidate_claim_precision | 25/63 = 0.3968 | 22/75 = 0.2933 | +0.1035 |
| behavior_step_recall | 12/23 = 0.5217 | 12/59 = 0.2034 | +0.3183 |
| behavior_sequence_order | 5/15 = 0.3333 | 3/51 = 0.0588 | +0.2745 |
| critical_evidence_recall | 8/23 = 0.3478 | 8/59 = 0.1356 | +0.2122 |

### stage3

| Metric | Normal | Attack | Normal − attack |
|---|---:|---:|---:|
| action_step_recall | 17/69 = 0.2464 | 15/177 = 0.0847 | +0.1616 |
| candidate_claim_precision | 17/60 = 0.2833 | 16/60 = 0.2667 | +0.0167 |
| behavior_step_recall | 10/23 = 0.4348 | 9/59 = 0.1525 | +0.2822 |
| behavior_sequence_order | 3/15 = 0.2000 | 3/51 = 0.0588 | +0.1412 |
| critical_evidence_recall | 2/23 = 0.0870 | 8/59 = 0.1356 | -0.0486 |

## Interpretation boundary

This is a one-replicate paired-condition pilot, not an estimate of population-level model variance. The comparison is authorized because the run window, stage inputs, call-limit policy, scoring units, and review process are aligned. Differences in Gold sequence length and behavior composition remain part of the use-case difficulty and must be discussed rather than normalized away after observing the results.
