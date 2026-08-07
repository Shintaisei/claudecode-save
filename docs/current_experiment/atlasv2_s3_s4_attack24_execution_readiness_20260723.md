# ATLASv2 S3/S4 attack24: Execution Readiness

## Decision

The suite is ready for model execution and scoring. No model API call has been made by this preparation check.

## Verified conditions

| Check | Result |
| --- | --- |
| Input structure | Stage 1: 24; Stage 2: 8; Stage 3: 8; total: 40 |
| Gold resolution | 40 of 40 Gold files resolve through `formal_gold_root` and `gold_chain_file` |
| Stage 3 Gold | Eight cases and 45 steps are scoreable from canonical `cbc_events` evidence; zero steps depend on `cbc_alerts` summaries |
| Stage 3 scoring precondition | A CSV with 45 `stage3_status=pass` rows was generated; scorer filtering succeeds for all 8 Stage 3 cases |
| Order scoring | Legacy two-item list pairs and mapping pairs are normalized compatibly before filtering |
| Stage 3 isolation | The dedicated driver always adds `--exclude-cbc-alert-summary` to Stage 3 runner commands |
| Runner dry-run | 40 of 40 inputs completed with model `gpt-5.4-mini`; no model API call |

## Artifacts

- Driver: `src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py`
- Stage 3 validation CSV: `docs/current_experiment/atlasv2_s3_s4_attack24_stage3_validation_steps_20260723.csv`
- Preflight result: `docs/current_experiment/results_2026-07-23/atlasv2_s3_s4_attack24_preflight/preflight.json`
- Dry-run outputs: `docs/current_experiment/results_2026-07-23/atlasv2_s3_s4_attack24_preflight/dry_runs/gpt-5.4-mini/`

## Commands

```powershell
# Preflight only
python src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py --preflight

# Model execution (requires explicit --run)
python src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py --run --models gpt-5.4-mini

# Score existing model-run outputs
python src/clouseau_process_time/run_atlasv2_s3_s4_attack24_experiment.py --score --models gpt-5.4-mini
```

Stage 1 alert-target inputs and Stage 2/3 process-time inputs are separate aggregation units. Report Word boundary cases separately from main attack-reconstruction success. `triage_decision` is stored as a reference output but is not scored.
