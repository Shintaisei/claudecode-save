# Formal Experiment Slide Text: 2026-06-09 27-Chain Version

The old 2026-06-05 single-case slide text has been superseded. Use the 2026-06-09 formal experiment below.

## Experiment Overview

CLOUSEAU is evaluated on 27 behavior chains under three input/database conditions. The comparison tests whether the system can reconstruct observed code behavior sequences from CBC dense endpoint logs as alert-derived support is reduced.

Matrix:

- 27 chains x 3 stages = 81 cases.
- Models: `gpt-4.1-mini` and `gpt-5.4-mini`.
- Full default run matrix: 162 runs.

## Stage Conditions

| Stage | Input | Database condition | Purpose |
|---|---|---|---|
| Stage 1 | process-time clue plus CBC alert summary fields | CBC alert summary and CBC EDR/NGAV telemetry available | alert-assisted baseline |
| Stage 2 | process-time clue only | CBC alert summary and CBC EDR/NGAV telemetry available | discover alert-derived evidence from logs |
| Stage 3 | process-time clue only | CBC alert summary hidden by `audit_logs_stage3`; CBC EDR/NGAV telemetry retained | reconstruct behavior without high-density alert summaries |

Stage 3 is not a full CBC removal condition.

## Evaluation

The scorer expands each chain gold file into required items from `scoring_template`.

| Stage | Aggregate behavior steps | Aggregate required items |
|---|---:|---:|
| Stage 1 | 75 | 300 |
| Stage 2 | 75 | 300 |
| Stage 3 | 65 validation-supported steps | 260 |

Stage 3 excludes 10 unsupported steps through the validation CSV before scoring.

## Commands

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run
python src\clouseau_process_time\run_formal_27_chain_experiment.py --score
```
