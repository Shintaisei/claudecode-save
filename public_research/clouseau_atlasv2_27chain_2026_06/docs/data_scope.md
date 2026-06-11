# Data scope and exclusion policy

## Included

This public package includes:

- current LaTeX manuscript files,
- experiment design notes,
- scenario taxonomy,
- sanitized 81-run case metadata,
- chain summary and chain index,
- aggregate score CSV/JSON files,
- sanitized token/cost summary,
- scoring rubrics,
- selected experiment scripts.

## Excluded

The package intentionally excludes:

- `incident.db`,
- `scenario.db`,
- EVTX files,
- raw external datasets,
- full per-run model output JSON files,
- raw alert row inputs,
- local absolute paths,
- API keys or environment files.

## Reason

The goal is to publish enough information to inspect the experiment design and reported results without uploading raw security telemetry or machine-local artifacts.

## Reproducibility boundary

The files here are enough to review the paper, inspect the case/stage structure, verify aggregate result tables, and understand the scoring policy. Full reruns still require the private/local ATLASv2/CLOUSEAU database environment.
