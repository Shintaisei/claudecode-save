# Archived Design Note: Superseded By 2026-06-09 Formal Pipeline

This file used to describe an earlier legacy single-case experiment. That design is no longer the formal experiment and must not be used as the runbook, scoring definition, or source of denominators.

Current source of truth:

- `docs/current_experiment/formal_experiment_pipeline_2026-06-09.md`

## Current Formal Experiment

- Scope: 27 behavior chains x 3 stages = 81 cases.
- Default models: `gpt-4.1-mini` and `gpt-5.4-mini`.
- Full matrix: 162 run commands.
- Case file: `data/current_experiment/cases/cbc_27_chain_stage_cases_2026-06-09.jsonl`.
- Manifest: `docs/current_experiment/results_2026-06-09/formal_27_chain_experiment_20260609/manifest.json`.
- Entry point: `src/clouseau_process_time/run_formal_27_chain_experiment.py`.
- Scorer: `src/clouseau_process_time/score_element_order_with_gpt.py`.

## Current Stage Definitions

Stage 1 includes process-time input plus CBC alert summary fields, with all CBC/OS/browser logs available in the database.

Stage 2 uses process-time input only, while CBC alert summary and CBC telemetry remain available in the database.

Stage 3 uses process-time input only and hides CBC alert summary rows from the SQL tool through the `audit_logs_stage3` temporary view. CBC EDR/NGAV event telemetry remains available. The Stage3 adapter database uses a hardlink to the cache DB and fails fast instead of making a large copy unless `CLOUSEAU_ALLOW_ADAPTER_COPY=1` is explicitly set.

## Current Evaluation Denominators

- Stage 1 and Stage 2: 75 behavior steps / 300 required items.
- Stage 3: 65 validation-supported behavior steps / 260 required items.
- Stage 3 unsupported: 10 steps.

Legacy single-case denominators and legacy metric names are historical only.

## Current Commands

Generate or refresh the canonical manifest:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py
```

Run the full formal experiment:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run
```

Score completed runs:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --score
```
