# 2026-06-09 Formal 27-Chain Experiment Pipeline

Created: 2026-06-09

This is the official pipeline for the finalized CBC alert behavior-chain experiment. The old `run_formal_discord_experiment.py` is a legacy single-case Discord Run-key wrapper and must not be used for the 27-chain experiment.

## Final Data

- Gold root: `data/current_experiment/gold/cbc_alert_behavior_chain_gold`
- Chain index: `data/current_experiment/gold/cbc_alert_behavior_chain_gold/chain_gold_index.json`
- Per-chain gold: `data/current_experiment/gold/cbc_alert_behavior_chain_gold/by_chain/*/chain_gold.json`
- Model-ready inputs: `docs/current_experiment/chain_gold_validation_2026-06-09/chain_stage_inputs_model_ready_2026-06-09.json`
- Input audit map: `docs/current_experiment/chain_gold_validation_2026-06-09/chain_stage_input_audit_map_2026-06-09.csv`
- DB validation: `docs/current_experiment/chain_gold_validation_2026-06-09/chain_gold_db_validation_steps_2026-06-09.csv`

Final counts:

- Chains: 27
- Active gold steps: 75
- Stage 1 cases: 27, with CBC alert rows plus host/focus process/window
- Stage 2 cases: 27, with host/focus process/window only and full DB available
- Stage 3 cases: 27, with host/focus process/window only and CBC alert summary rows hidden
- Stage 3 answerable gold: 65 steps
- Stage 3 alert-only unsupported gold: 10 steps

## Case Generation

Build the runner-ready JSONL by joining model-ready inputs, the input audit map, and chain summary.

```powershell
python src\clouseau_process_time\build_chain_experiment_cases.py
```

Expected output:

```text
data/current_experiment/cases/cbc_27_chain_stage_cases_2026-06-09.jsonl
```

Expected count: 81 cases = 27 chains x 3 stages.

## Formal Entry Point

Use this wrapper for the official experiment:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py
```

With no run flags, it does not call the model API. It writes a manifest with selected cases, stage counts, models, and sample commands.

Manifest:

```text
docs/current_experiment/results_2026-06-09/formal_27_chain_experiment_20260609/manifest.json
```

## Preflight

Run one Stage 1 dry-run before the full matrix:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --dry-run --limit 1 --models gpt-5.4-mini
```

Run one Stage 3 dry-run:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --dry-run --stage stage3 --limit 1 --models gpt-5.4-mini
```

Run one Claude Stage 3 dry-run:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --dry-run --stage stage3 --limit 1 --models claude-sonnet-4-6
```

Storage behavior:

- Stage 1/2 use hard links to the adapter cache DB, so each run does not create another 4.7GB copy.
- Stage 3 also uses a hard link to the adapter cache DB.
- During Stage 3, CBC alert summary rows are hidden logically by replacing SQL-tool references to `audit_logs` with the temporary view `audit_logs_stage3`.
- `audit_logs_stage3` excludes rows where `source_stream in ('cbc-edr-alerts', 'cbc-ngav-alerts')`, `access = 'cbc_alert'`, or `original_table = 'cbc_alerts'`.
- If hard links are unavailable, the runner fails instead of silently copying the multi-GB DB. Set `CLOUSEAU_ALLOW_ADAPTER_COPY=1` only when enough disk space is available.

## Full Run

Default formal matrix: 2 models x 3 stages x 27 chains = 162 runs.

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run
```

Restrict to one model:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run --models gpt-5.4-mini
```

Restrict to one stage:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run --stage stage1 --models gpt-5.4-mini
```

Run a guarded Claude run-only replicate:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_formal_27_chain_claude_runonly_20260617.ps1 -Models claude-sonnet-4-6 -Replicates 1 -Workers 2 -CostCheckUsd 120
```

Claude model IDs supported by the same runner include `claude-sonnet-4-6`, `claude-opus-4-8`, `claude-fable-5`, and `claude-haiku-4-5`. The provider is inferred automatically for model names beginning with `claude-`; set `ANTHROPIC_API_KEY` in `.env.clouseau` before real runs.

Run output:

```text
docs/current_experiment/results_2026-06-09/formal_27_chain_experiment_20260609/runs/<model>/<stage>/<instance_id>_run.json
```

## Evaluation

Use `score_element_order_with_gpt.py` through the formal wrapper.

Metrics:

- `behavior_step_recall`: step-level metric. Stage 1/2 denominator is 75 gold steps. Stage 3 denominator is 65 answerable gold steps.
- `action_step_recall` / `action_step_precision`: required-item metrics. Each gold step expands `subject`, `action`, `object`, and `evidence` from `scoring_template`. Stage 1/2 denominator is 300 required items. Stage 3 denominator is 260 required items.
- `behavior_sequence_order`: order metric over gold order pairs after Stage 3 filtering.
- `candidate_claim_precision`: diagnostic candidate-side precision for overclaiming and false positives.

Rules:

- Stage 1/2 score every per-chain gold file as-is.
- Stage 3 scores only validation rows with `stage3_status=pass`.
- Stage 3 chains with zero answerable steps are written as skipped with zero denominator.
- `alert_name` and `alert_reason` are evidence, not operations. If emitted as behavior operations, they are false positives.
- Evidence verbosity must not increase denominators. Evidence is one `critical_evidence` slot per action claim.

Score existing runs:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --score
```

Run and score in one call:

```powershell
python src\clouseau_process_time\run_formal_27_chain_experiment.py --run --score
```

Score output:

```text
docs/current_experiment/results_2026-06-09/formal_27_chain_experiment_20260609/scores/<model>/<stage>/<instance_id>/score_result.json
```

## Start Criteria

Before starting the full matrix, confirm:

- `build_chain_experiment_cases.py` generates 81 cases.
- `run_formal_27_chain_experiment.py` generates a manifest.
- Manifest stage counts are `stage1=27`, `stage2=27`, `stage3=27`.
- The scorer derives required-item denominators from per-step `scoring_template`.
- Per-chain score outputs expose per-chain denominators.
- Aggregate reporting over all selected chains should sum to step denominators: 75 for Stage 1/2 and 65 for Stage 3.
- Aggregate reporting over all selected chains should sum to required-item denominators: 300 for Stage 1/2 and 260 for Stage 3.
- Stage 3 reflects the 65 answerable / 10 unsupported split.
- The legacy Discord wrapper is not used for this formal 27-chain experiment.
