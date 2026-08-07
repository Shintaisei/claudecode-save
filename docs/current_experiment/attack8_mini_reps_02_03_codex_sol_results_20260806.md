# Attack8 replicate_02/03 Codex v5 atomic scoring (2026-08-06)

OpenAI judge API/API scorer was not used. An experiment-nonparticipant Codex gpt-5.6-sol reviewer froze the semantic alignments, after which every score, fixed denominator, hash, and aggregate was derived deterministically.

## Headline metrics

| Slice | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 96 | 396/1548 = 25.58% | 396/996 = 39.76% | 120/516 = 23.26% | 50/516 = 9.69% | 32/420 = 7.62% |
| replicate_02 | 48 | 207/774 = 26.74% | 207/528 = 39.20% | 63/258 = 24.42% | 33/258 = 12.79% | 20/210 = 9.52% |
| replicate_03 | 48 | 189/774 = 24.42% | 189/468 = 40.38% | 57/258 = 22.09% | 17/258 = 6.59% | 12/210 = 5.71% |
| gpt-4.1-mini | 48 | 282/774 = 36.43% | 282/666 = 42.34% | 84/258 = 32.56% | 34/258 = 13.18% | 25/210 = 11.90% |
| gpt-5.4-mini | 48 | 114/774 = 14.73% | 114/330 = 34.55% | 36/258 = 13.95% | 16/258 = 6.20% | 7/210 = 3.33% |
| stage1 | 32 | 133/516 = 25.78% | 133/312 = 42.63% | 41/172 = 23.84% | 18/172 = 10.47% | 9/140 = 6.43% |
| stage2 | 32 | 138/516 = 26.74% | 138/318 = 43.40% | 42/172 = 24.42% | 18/172 = 10.47% | 13/140 = 9.29% |
| stage3 | 32 | 125/516 = 24.22% | 125/366 = 34.15% | 37/172 = 21.51% | 14/172 = 8.14% | 10/140 = 7.14% |

## Model x Stage

| Model / Stage | Runs | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini/stage1 | 16 | 95/258 = 36.82% | 95/213 = 44.60% | 29/86 = 33.72% | 11/86 = 12.79% | 6/70 = 8.57% |
| gpt-4.1-mini/stage2 | 16 | 94/258 = 36.43% | 94/216 = 43.52% | 28/86 = 32.56% | 13/86 = 15.12% | 11/70 = 15.71% |
| gpt-4.1-mini/stage3 | 16 | 93/258 = 36.05% | 93/237 = 39.24% | 27/86 = 31.40% | 10/86 = 11.63% | 8/70 = 11.43% |
| gpt-5.4-mini/stage1 | 16 | 38/258 = 14.73% | 38/99 = 38.38% | 12/86 = 13.95% | 7/86 = 8.14% | 3/70 = 4.29% |
| gpt-5.4-mini/stage2 | 16 | 44/258 = 17.05% | 44/102 = 43.14% | 14/86 = 16.28% | 5/86 = 5.81% | 2/70 = 2.86% |
| gpt-5.4-mini/stage3 | 16 | 32/258 = 12.40% | 32/129 = 24.81% | 10/86 = 11.63% | 4/86 = 4.65% | 2/70 = 2.86% |

## Deterministic audit

- Status: **PASS**
- Source runs/audits/output JSON: 96/96/96 (all source audits PASS)
- Checked: 1548 Gold action items, 996 candidate slots, 516 behavior steps, 516 critical items, 420 adjacent order pairs.
- Cross-field mismatches: Gold=1 without TP 0; TP without Gold=1 0; duplicate TP 0.
- PID and hidden alert mapping are excluded from scoring. Critical evidence is diagnosed separately from action recall.

## Failure pattern

- Unrecovered Gold steps across runs: 378
- Missing adjacent causal edges: 388
- Nearby/unsupported candidate slots: 582
- Wrong-component candidate slots: 18
- Primary failures are truncated causal chains, nearby process/file activity substituted for the canonical chain, and over-connected pivots that skip an intermediate process. Partial subject/operation credit is retained only when the emitted claim itself identifies the corresponding Gold behavior; PID and hidden alert mapping are never scored.

The score root contains every run/case/Gold hash, Gold item, candidate slot, order pair, fixed denominator, per-run total, semantic alignment decision, and cross-field consistency audit.
