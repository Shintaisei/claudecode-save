# Data scope and exclusion policy

## Included

This public package includes:

- current LaTeX manuscript files,
- experiment design notes,
- scenario taxonomy,
- sanitized 81-run case metadata,
- chain summary and chain index,
- aggregate score CSV/JSON files,
- per-run raw CLOUSEAU output JSON files under `raw_runs/`,
- sanitized token/cost summary,
- scoring rubrics,
- selected experiment scripts.

## Excluded

The package intentionally excludes:

- `incident.db`,
- `scenario.db`,
- EVTX files,
- raw external datasets,
- local absolute paths,
- API keys or environment files.

## Reason

The goal is to publish enough information to inspect the experiment design, reported results, and run-level model behavior without uploading source databases, EVTX files, external archives, or machine-local artifacts.

## Reproducibility boundary

The files here are enough to review the paper, inspect the case/stage structure, verify aggregate result tables, inspect run-level model outputs, and understand the scoring policy. Full reruns still require the private/local ATLASv2/CLOUSEAU database environment.
