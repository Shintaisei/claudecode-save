# full-ledger pilot03 first-run diagnostic score

This score is diagnostic only and is not formally adoptable. The run completed
without a runtime error, but process-instance scope drift changed the evidence
used by the final synthesis.

| Metric | Score |
|---|---:|
| Action recall | 4/21 = 19.05% |
| Candidate precision | 4/12 = 33.33% |
| Complete behavior-step recall | 0/7 = 0.00% |
| Critical evidence recall | 0/7 = 0.00% |
| Order recall | 1/6 = 16.67% |

## Internal processing

- PASS: Chief generated 10 leads (9 unique), so the earlier one-lead failure is
  not present.
- PASS: full-pipeline usage/cost accounting is internally consistent across
  208 LLM calls.
- PASS: the per-lead expansion guard stopped one lead after 20 Investigator
  questions and returned its unresolved frontier.
- PARTIAL PASS: the first lead retrieved the target process chain
  `explorer.exe -> cmd.exe PID 3652 -> tshark.exe PID 2496 ->
  dumpcap.exe PIDs 2164/2384/3288`.
- FAIL: later SQL queries omitted the supplied case window, searched every
  `start_dns_logs.bat` occurrence, and introduced other process instances.
- FAIL: PID 2496 at 13:08:26 was resolved as a Confer
  `RepWmiUtils.exe`/`RepMgr.exe` instance and was incorrectly propagated as the
  parent of the target `tshark.exe`.
- FAIL: final synthesis omitted the Gold explorer-to-cmd edge, the two distinct
  dumpcap behaviors, and the materialized `.pcapng` file.

The orchestration, multi-lead behavior, accounting, and expansion guard work.
The run is nevertheless unsafe to use as evidence that the pipeline is
operating as intended. Process-identity queries must be deterministically
bound to the case window before the pilot is expanded.

Detailed item-level decisions are in
`normal_attack_full_ledger_pilot03_first_run_diagnostic_score_20260730.json`.
