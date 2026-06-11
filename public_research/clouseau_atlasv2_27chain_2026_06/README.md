# CLOUSEAU ATLASv2 27-chain experiment package

This folder is a cleaned public package for the current CLOUSEAU / ATLASv2 behavior reconstruction experiment.

It contains the research purpose, experiment design, current LaTeX manuscript, scoring rubrics, sanitized metadata, and aggregate result files needed to discuss and reproduce the reported tables. It intentionally excludes raw databases, EVTX files, external datasets, and full run outputs.

## Folder layout

- `paper/`: current LaTeX manuscript files.
- `docs/`: research direction, experiment design, scenario taxonomy, data scope, result summary, cost estimates, and incident notes.
- `experiment_metadata/`: sanitized case metadata, chain summary, chain index, run settings, and token/cost summary.
- `results/`: final score CSV/JSON files and aggregate tables.
- `rubrics/`: scoring rubrics used for double review / final review.
- `scripts/`: selected scripts used to build cases, run the 27-chain experiment, validate gold chains, and score outputs.

## Current experiment

- Dataset context: ATLASv2 benign H1 / benign-1, reconstructed through CLOUSEAU.
- Evaluation unit: 27 behavior chains.
- Stage design: 27 chains x 3 input conditions = 81 runs per model.
- Models in the completed result set: `gpt-4.1-mini`, `gpt-5.4-mini`.
- Raw model runs completed: 162 / 162.
- Final scored results included here: 81 / 81 for each model.

## Main result files

- `results/score_summary_overall.csv`
- `results/score_summary_by_stage.csv`
- `results/score_summary_by_scenario_group.csv`
- `results/score_summary_by_stage_and_scenario_group.csv`
- `results/gpt-4.1-mini/final_scores.csv`
- `results/gpt-5.4-mini/final_scores.csv`

## Data exclusion policy

The package does not include source DB files, raw logs, EVTX files, scenario databases, or full per-run model outputs. See `docs/data_scope.md`.

## Notes

The aggregate tables report both percentages and numerator/denominator fractions. Use the fractions when checking metric definitions or comparing score pipelines.
