# Archived Design Note: Superseded

This file is retained only to prevent stale links from silently pointing to the old single-case design.

The current formal experiment is documented here:

- `docs/current_experiment/formal_experiment_pipeline_2026-06-09.md`

Do not use legacy single-case denominators or legacy metric names for the formal experiment.

Current formal facts:

- 27 chains x 3 stages = 81 cases.
- Default two-model matrix = 162 run commands.
- Stage 1 and Stage 2 aggregate denominator = 75 behavior steps / 300 required items.
- Stage 3 aggregate denominator = 65 validation-supported behavior steps / 260 required items.
- Stage 3 hides CBC alert summary from SQL via `audit_logs_stage3`; CBC EDR/NGAV telemetry remains available.

Current command:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run
```
