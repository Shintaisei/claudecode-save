# Current CLOUSEAU Process-Time Prompt Conditions

This file summarizes the active prompt-side conditions for the 2026-06-09 formal 27-chain experiment. The complete runbook remains:

- `docs/current_experiment/formal_experiment_pipeline_2026-06-09.md`

## Shared Task

Recover the code behavior sequence from Windows endpoint logs. The final answer must describe observed behavior steps and supporting evidence, not copy alert labels as behavior.

Raw observed values such as paths, command lines, process names, timestamps, PIDs, row ids, and source streams should be preserved exactly when reported.

## Stage Input Conditions

Stage 1 input:

- process-time fields: host, process, timestamp, and canonical model-ready context
- CBC alert summary fields available as the starting clue

Stage 2 input:

- process-time fields only
- CBC alert title, reason, alert id, command line, parent process, child process, registry object, file object, network object, and behavior category are not supplied as input hints

Stage 3 input:

- same process-time-only input policy as Stage 2

## Stage Database Conditions

Stage 1 database:

- CBC alert summary available
- CBC EDR/NGAV telemetry available
- Security, Sysmon, DNS, browser, and related OS evidence available

Stage 2 database:

- CBC alert summary still available
- CBC EDR/NGAV telemetry still available
- Security, Sysmon, DNS, browser, and related OS evidence available

Stage 3 database:

- CBC alert summary hidden from the SQL tool through the `audit_logs_stage3` temporary view
- CBC EDR/NGAV telemetry remains available
- Security, Sysmon, DNS, browser, and related OS evidence remains available

Stage 3 is not a full CBC database removal condition.

## Evaluation

The current scorer is `src/clouseau_process_time/score_element_order_with_gpt.py`.

- Stage 1 and Stage 2 aggregate over all 27 chains: 75 behavior steps / 300 required items.
- Stage 3 applies the validation CSV first: 65 supported behavior steps / 260 required items.
- Legacy single-case examples, denominators, and metric names are historical only.
