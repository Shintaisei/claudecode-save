# ATLASv2 S3/S4 CBC Attack Reconstruction: Execution and Scoring Contract

## Evaluation units

- Stage 1 evaluates 24 inputs. Each input is a CBC alert target.
- Stages 2 and 3 each evaluate 8 inputs. These are unique combinations of host, process, and a 30-minute time window after alert-summary information is removed.
- The Stage 1 aggregate (24 alert-target inputs) and the Stage 2/3 aggregates (8 process-time inputs) are not paired one-to-one comparisons. Report each aggregate separately and state the different input units when comparing stages.

## Gold and scoring

- Every case resolves its dedicated Gold file from `formal_gold_root` and `gold_chain_file`.
- Stage 3 scores only Gold steps with canonical `cbc_events` evidence. CBC alert-summary rows (`cbc_alerts`), ground-truth labels, and scenario descriptions are not valid evidence.
- Stage 3 scores only rows marked `stage3_status=pass` in `atlasv2_s3_s4_attack24_stage3_validation_steps_20260723.csv`.
- Gold order pairs may use either the legacy list form `[before_step_id, after_step_id]` or mapping form. The scorer normalizes both forms before Stage 3 filtering.

## Success and boundary reporting

- Word boundary cases do not claim an unobserved causal edge to a later loader. Report them separately from the main attack-reconstruction success aggregate.
- `triage_decision` is retained in the agent output as a reference field, but it is not a scored metric in this suite. The primary evaluation target is evidence-backed behavior reconstruction.

## Execution gate

The dedicated driver `run_atlasv2_s3_s4_attack24_experiment.py` fails fast before execution unless all of the following conditions hold:

1. The case file has 40 inputs with the required 24 / 8 / 8 Stage split and unique IDs.
2. Every Gold path resolves.
3. Every selected Gold file has scoreable steps and required action items.
4. Stage 3 Gold does not require CBC alert summaries.
5. The generated Stage 3 validation CSV filters successfully for all eight Stage 3 cases.
6. Every Stage 3 runner command includes `--exclude-cbc-alert-summary`.

The model is called only when `--run` is explicitly supplied. `--dry-run` verifies runner setup and output creation without a model API call.
