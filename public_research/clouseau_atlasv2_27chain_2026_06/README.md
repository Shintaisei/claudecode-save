# CLOUSEAU ATLASv2 / FIT2026 experiment package

This folder is a cleaned public package for the CLOUSEAU / ATLASv2 behavior reconstruction experiment and the FIT2026 manuscript draft.

It contains the research purpose, experiment design, current LaTeX manuscript, scoring rubrics, sanitized metadata, aggregate result files, per-run model outputs, and the latest discussion materials. It intentionally excludes raw databases, EVTX files, external datasets, local virtual environments, and API keys.

## Folder layout

- `paper/`: earlier public LaTeX manuscript copy.
- `fit2026_manuscript/`: current FIT2026 manuscript workspace, including the working LaTeX draft and draft notes.
- `docs/`: research direction, experiment design, scenario taxonomy, data scope, result summary, cost estimates, and incident notes.
- `experiment_metadata/`: sanitized case metadata, chain summary, chain index, run settings, and token/cost summary.
- `results/`: final score CSV/JSON files and aggregate tables.
- `results_23chain_20260614/`: current final 23-chain experiment result tables and definitions. Use this first for paper writing.
- `raw_runs/`: per-run raw CLOUSEAU output JSON files for all 162 model/stage runs.
- `exp_20260614/`: latest component-rubric experiment handoff package. This includes 23-chain filtered outputs, scoring ledgers, aggregate tables, cost audit, and discussion/deep-dive materials.
- `rubrics/`: scoring rubrics used for double review / final review.
- `scripts/`: selected scripts used to build cases, run experiments, validate gold chains, score outputs, and generate the 2026-06-14 component-rubric discussion assets.

## Current experiment

- Dataset context: ATLASv2 benign H1 / benign-1, reconstructed through CLOUSEAU.
- Earlier public package: 27 behavior chains x 3 input conditions = 81 runs per model.
- Latest analysis package: 23 behavior chains x 3 stages, component-level scoring, 3-run average for `gpt-4.1-mini` and `gpt-5.4-mini`, and one available `gpt-5.5` low-effort run.
- Models in the completed structured result set: `gpt-4.1-mini`, `gpt-5.4-mini`.
- GPT-5.5 status: included as raw/salvaged one-run evidence because the output contract differed from the structured runs.

## Main result files

- `results_23chain_20260614/README.md`
- `results_23chain_20260614/RESULT_DEFINITIONS_23CHAIN.md`
- `results_23chain_20260614/overall.csv`
- `results_23chain_20260614/by_stage.csv`
- `results_23chain_20260614/ledgers/final_comparison_per_run_component_scores.csv`
- `docs/method_changes_for_paper_20260615.md`
- `docs/method_section_points_ja_20260615.md`
- `docs/gpt55_remaining_budget_request_20260615.md`
- `results/score_summary_overall.csv`
- `results/score_summary_by_stage.csv`
- `results/score_summary_by_scenario_group.csv`
- `results/score_summary_by_stage_and_scenario_group.csv`
- `results/gpt-4.1-mini/final_scores.csv`
- `results/gpt-5.4-mini/final_scores.csv`
- `exp_20260614/03_aggregated_results/summary.md`
- `exp_20260614/03_aggregated_results/overall.csv`
- `exp_20260614/03_aggregated_results/by_stage.csv`
- `exp_20260614/UPLOAD_AUDIT_20260615.md`
- `exp_20260614/04_discussion_base/detailed_discussion_20260614.md`
- `exp_20260614/04_discussion_base/usecase_deep_dive_20260614/usecase_deep_dive.md`
- `exp_20260614/04_discussion_base/model_argument_deep_dive_20260614/model_argument_deep_dive.md`
- `exp_20260614/04_discussion_base/investigator_sql_deep_dive_20260614/investigator_sql_deep_dive.md`

## Data exclusion policy

The package includes per-run model output JSON files and scoring/discussion artifacts, but does not include source DB files, EVTX files, scenario databases, external dataset archives, virtual environments, or `.env` files. See `docs/data_scope.md`.

## Notes

The aggregate tables report both percentages and numerator/denominator fractions. Use the fractions when checking metric definitions or comparing score pipelines.

For the latest paper discussion, start with `results_23chain_20260614/README.md`, `docs/method_changes_for_paper_20260615.md`, `docs/method_section_points_ja_20260615.md`, `fit2026_manuscript/paper/main.tex`, and `exp_20260614/04_discussion_base/detailed_discussion_20260614.md`.
