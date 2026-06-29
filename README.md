# CLOUSEAU Process-Time 27-Chain Experiment

This workspace contains the current non-ATLAS CLOUSEAU process-time experiment for CBC dense logs.

## Current Source Of Truth

Use the formal pipeline document for the active experiment:

- `docs/current_experiment/formal_experiment_pipeline_2026-06-09.md`

Do not use the old Discord single-case runner or old single-case gold files for the formal experiment.

## Active Formal Experiment

- Scope: 27 behavior chains x 3 stages = 81 cases.
- Default models: `gpt-4.1-mini` and `gpt-5.4-mini`.
- Full run matrix: 81 cases x 2 models = 162 run commands.
- Case file: `data/current_experiment/cases/cbc_27_chain_stage_cases_2026-06-09.jsonl`.
- Canonical manifest: `docs/current_experiment/results_2026-06-09/formal_27_chain_experiment_20260609/manifest.json`.
- Runner: `src/clouseau_process_time/run_formal_27_chain_experiment.py`.
- Scorer: `src/clouseau_process_time/score_element_order_with_gpt.py`.

## Stage Definitions

Stage 1:

- Input clue includes process-time fields plus CBC alert summary fields.
- Database includes CBC alert summary, CBC EDR/NGAV telemetry, and the OS/browser logs.

Stage 2:

- Input clue is process-time only: host, process, timestamp, and related canonical model-ready fields.
- Database still includes CBC alert summary and CBC telemetry.

Stage 3:

- Input clue is process-time only.
- CBC alert summary is hidden from the SQL tool by a temporary `audit_logs_stage3` view.
- CBC EDR/NGAV event telemetry remains available.
- The Stage3 adapter database uses a hardlink to the cache DB. If hardlinking fails, the runner fails fast unless `CLOUSEAU_ALLOW_ADAPTER_COPY=1` is explicitly set.

## Evaluation Denominators

- Stage 1 and Stage 2: 75 behavior steps / 300 required items.
- Stage 3: validation-filtered answerable steps only, 65 behavior steps / 260 required items.
- Stage 3 unsupported items: 10 steps.

The scorer expands `chain_gold_index.json` into each per-chain `by_chain/*/chain_gold.json` and applies the Stage3 validation CSV before scoring Stage3.

## Commands

Prepare API keys:

```powershell
copy .env.clouseau.example .env.clouseau
# Edit .env.clouseau and set ANTHROPIC_API_KEY for Claude runs.
```

Regenerate the canonical manifest:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py
```

Run the full formal matrix:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run
```

Run one Stage3 dry-run probe:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --dry-run --stage stage3 --limit 1 --models gpt-5.4-mini
```

Run one Claude Sonnet dry-run probe:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --dry-run --stage stage3 --limit 1 --models claude-sonnet-4-6
```

Run one Claude Opus dry-run probe:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --dry-run --stage stage3 --limit 1 --models claude-opus-4-8
```

Run one Claude full-matrix run-only replicate with guards:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_formal_27_chain_claude_runonly_20260617.ps1 -Models claude-sonnet-4-6 -Replicates 1 -Workers 2 -CostCheckUsd 120
```

Score completed runs:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --score
```
