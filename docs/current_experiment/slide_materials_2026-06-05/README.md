# Slide Materials: 2026-06-09 Formal 27-Chain Experiment

These slide notes were originally drafted on 2026-06-05 for a legacy single-case run. They have been updated so this folder no longer serves stale single-case instructions.

Current source of truth:

- `../formal_experiment_pipeline_2026-06-09.md`

Use these current facts in slides:

- Formal experiment: 27 chains x 3 stages = 81 cases.
- Default model matrix: `gpt-4.1-mini` and `gpt-5.4-mini`, 162 runs total.
- Stage 1: process-time input plus CBC alert summary clue; CBC alert summary and CBC telemetry available in DB.
- Stage 2: process-time input only; CBC alert summary and CBC telemetry still available in DB.
- Stage 3: process-time input only; CBC alert summary hidden through `audit_logs_stage3`; CBC EDR/NGAV telemetry retained.
- Stage 1/2 aggregate evaluation: 75 behavior steps / 300 required items.
- Stage 3 aggregate evaluation: 65 validation-supported behavior steps / 260 required items.

Historical single-case examples and old denominators are not the formal experiment.
