# Superseded Prompt Fulltext

The old full prompt dump for the 2026-06-05 single-case experiment has been removed from the active slide-material path to avoid confusing it with the 2026-06-09 formal 27-chain experiment.

Current source of truth:

- `../formal_experiment_pipeline_2026-06-09.md`
- `../../src/clouseau_process_time/run_formal_27_chain_experiment.py`
- `../../src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py`
- `../../src/clouseau_process_time/score_element_order_with_gpt.py`

Current conditions:

- Stage 1: process-time input plus CBC alert summary fields.
- Stage 2: process-time input only; CBC alert summary and CBC telemetry available in DB.
- Stage 3: process-time input only; CBC alert summary hidden through `audit_logs_stage3`; CBC telemetry retained.
- Stage 1/2 aggregate scoring: 75 behavior steps / 300 required items.
- Stage 3 aggregate scoring: 65 validation-supported behavior steps / 260 required items.
