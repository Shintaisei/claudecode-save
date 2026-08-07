# Proposal Method Slide Text: CLOUSEAU Behavior Reconstruction Pipeline

Note: the active formal experiment is the 2026-06-09 27-chain experiment. Use `../formal_experiment_pipeline_2026-06-09.md` as the runbook.

## Pipeline Overview

CLOUSEAU starts from a small SOC investigation clue and searches Windows endpoint logs to reconstruct observed process, command, registry, file, and network behavior as evidence-backed `code_steps` and `code_sequence`.

```text
SOC clue / process-time clue
  -> Chief agent: generate investigation leads
  -> Investigation agent: turn leads into verifiable questions
  -> QAAgent / SQL expert: retrieve observed rows from SQLite
  -> Final synthesis: separate nearby behavior and merge the main chain
  -> code_steps + code_sequence
  -> judge scoring + review
```

## Stage Inputs

| Stage | Input | DB condition | Meaning |
|---|---|---|---|
| Stage 1 | process-time clue plus CBC alert summary fields | alert summary and telemetry available | alert-assisted baseline |
| Stage 2 | process-time clue only | alert summary and telemetry available | can the pipeline discover alert-related evidence from logs |
| Stage 3 | process-time clue only | alert summary hidden via `audit_logs_stage3`; CBC EDR/NGAV telemetry retained | can the pipeline reconstruct behavior without high-density alert summary rows |

## Internal Roles

| Component | Role |
|---|---|
| Chief agent | decide what to investigate |
| Investigation agent | convert leads into concrete questions |
| QAAgent / SQL expert | retrieve observed rows and source fields |
| Final synthesis | produce the main behavior chain and exclude nearby non-target behavior |
| Judge | score required items and order over the 27-chain aggregate |

## Output

`code_steps` are evidence-backed behavior steps. `code_sequence` is the compact behavior sequence derived from observed commands or target operations. Alert names and reasons may be evidence, but they are not behavior operations.

## Evaluation Facts

- Stage 1/2 aggregate denominator: 75 behavior steps / 300 required items.
- Stage 3 aggregate denominator: 65 validation-supported behavior steps / 260 required items.
- Evidence verbosity does not increase denominators; each action claim has one critical evidence slot.
