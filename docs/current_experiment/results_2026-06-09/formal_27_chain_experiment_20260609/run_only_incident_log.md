# Run-only Incident Log

## 2026-06-11 JST - Interrupted During Formal Run

- Impact: The formal run-only process was no longer running after the PC was interrupted.
- Last confirmed completed run before interruption:
  - model: `gpt-4.1-mini`
  - instance: `chain_19_e13_python_simplehttpserver_network_chain_stage1`
  - completed run files: `55/162`
  - cumulative estimated run-only API cost: `$0.9377492000000001`
- Failed/interrupted active run:
  - model: `gpt-4.1-mini`
  - instance: `chain_19_e13_python_simplehttpserver_network_chain_stage2`
  - command had no `--score`
  - exit code: `1073807364`
  - captured stdout/stderr from the child runner were empty
- Interpretation: Treat as an external interruption / process termination, not a model-quality or validation failure.
- Recovery plan: Resume with the same run-only guard script and the same formal limits. Existing valid run files should be skipped by the guard, and execution should continue from the first missing run.

## 2026-06-11 JST - Resume Started

- Resume process started with the same run-only guard configuration:
  - models: `gpt-4.1-mini,gpt-5.4-mini`
  - max investigations/questions/queries/tokens: `300/800/1600/24576`
  - cost check: `$10`
  - no `--score`
- Resume stdout/stderr logs:
  - `run_only_guard_stdout_resume_20260611_081621.log`
  - `run_only_guard_stderr_resume_20260611_081621.log`
- Observed active run after resume:
  - parent PID: `20348`
  - child PID: `24432`
  - model: `gpt-4.1-mini`
  - instance: `chain_19_e13_python_simplehttpserver_network_chain_stage2`
- Resume behavior: Existing completed runs were retained; execution continued from the first missing run.

## 2026-06-11 JST - Second Interruption And Clean Restart Of Active Run

- Impact: The resumed process was interrupted again while running the same missing run:
  - model: `gpt-4.1-mini`
  - instance: `chain_19_e13_python_simplehttpserver_network_chain_stage2`
  - exit code: `1073807364`
  - captured stdout/stderr from the child runner were empty
- Formal result status after interruption:
  - completed formal run files remained `55/162`
  - no formal `run.json` existed for `chain_19_e13_python_simplehttpserver_network_chain_stage2`
- User instruction: Restart the interrupted run from the beginning.
- Cleanup performed before restart:
  - removed partial non-formal output directory `data/current_experiment/runs/clouseau_reconstruction_outputs/20260610T123744Z_chain_19_e13_python_simplehttpserver_network_chain_stage2_gpt-4.1-mini_official`
  - removed partial non-formal output directory `data/current_experiment/runs/clouseau_reconstruction_outputs/20260610T231626Z_chain_19_e13_python_simplehttpserver_network_chain_stage2_gpt-4.1-mini_official`
- Formal completed run files were not deleted.

## 2026-06-11 JST - Clean Restart Launched

- Restart process launched after deleting partial output directories.
- Active run after restart:
  - parent PID: `38820`
  - child PID: `23812`
  - model: `gpt-4.1-mini`
  - instance: `chain_19_e13_python_simplehttpserver_network_chain_stage2`
- New resume logs:
  - `run_only_guard_stdout_resume_20260611_085610.log`
  - `run_only_guard_stderr_resume_20260611_085610.log`
- New non-formal partial output directory:
  - `data/current_experiment/runs/clouseau_reconstruction_outputs/20260610T235624Z_chain_19_e13_python_simplehttpserver_network_chain_stage2_gpt-4.1-mini_official`

## 2026-06-11 JST - Clean Restart Confirmed Successful

- The clean restart completed the previously interrupted run:
  - `gpt-4.1-mini / chain_19_e13_python_simplehttpserver_network_chain_stage2`
- Subsequent runs also completed:
  - `gpt-4.1-mini / chain_19_e13_python_simplehttpserver_network_chain_stage3`
  - `gpt-4.1-mini / chain_20_e14_dns_packet_capture_batch_chain_stage1`
- Formal run status after recovery:
  - completed formal run files: `58/162`
  - validation errors across completed formal run files: `0`
  - cumulative estimated run-only API cost: `$0.9786136000000001`
- Active run after recovery:
  - `gpt-4.1-mini / chain_20_e14_dns_packet_capture_batch_chain_stage2`

## 2026-06-11 JST - Long-running Chain 25 Stage2 Watch

- Active run under observation:
  - model: `gpt-4.1-mini`
  - instance: `chain_25_e18_dns_packet_capture_batch_chain_stage2`
  - child PID observed: `18808`
- Status at review:
  - completed formal run files: `73/162`
  - latest completed formal run: `gpt-4.1-mini / chain_25_e18_dns_packet_capture_batch_chain_stage1`
  - resume stderr log: `0` bytes
  - no `--score` in the active command
  - no formal `run.json` yet for the active run
- Review decision:
  - local review agent returned `PASS`
  - no immediate stop condition was found
  - continue monitoring
- Caution:
  - active run had been long-running with no formal output yet
  - a short CPU sample showed no CPU increase, so this is being watched as a possible long API/wait state rather than treated as a completed or failed run

## 2026-06-11 JST - Chain 25 Stage2 Aborted For Parallel Restart

- Active long-running run was stopped after it continued for more than two hours without producing a formal `run.json`:
  - model: `gpt-4.1-mini`
  - instance: `chain_25_e18_dns_packet_capture_batch_chain_stage2`
  - parent PID stopped: `38820`
  - child PID stopped: `18808`
- Interpretation:
  - This was not accepted as a completed or failed formal run.
  - The run had no formal result artifact, so it will be restarted from scratch.
- Cleanup performed:
  - removed partial non-formal output directory `data/current_experiment/runs/clouseau_reconstruction_outputs/20260611T012332Z_chain_25_e18_dns_packet_capture_batch_chain_stage2_gpt-4.1-mini_official`
- Formal result status before parallel restart:
  - completed formal run files: `73/162`
  - completed formal run validation errors: `0`
- Next action:
  - switch from sequential resume to a guarded parallel resume runner to reduce wall-clock time
  - keep GPT judge / `--score` disabled

## 2026-06-11 JST - Parallel Runner Started

- Parallel run-only guard script added:
  - `src/clouseau_process_time/run_formal_27_chain_run_only_parallel_guarded.py`
- Parallel runner launched with:
  - workers: `3`
  - models: `gpt-4.1-mini,gpt-5.4-mini`
  - max investigations/questions/queries/tokens: `300/800/1600/24576`
  - cost check: `$10`
  - no `--score`
- Parallel logs:
  - `run_only_parallel_stdout_20260611_131433.log`
  - `run_only_parallel_stderr_20260611_131433.log`
  - `run_only_parallel_guard_log.jsonl`
- Initial active child runs:
  - `gpt-4.1-mini / chain_25_e18_dns_packet_capture_batch_chain_stage2`
  - `gpt-4.1-mini / chain_25_e18_dns_packet_capture_batch_chain_stage3`
  - `gpt-4.1-mini / chain_26_e18_python_simplehttpserver_network_chain_stage1`

## 2026-06-11 JST - Parallel Runner Review

- Review decision: `PASS`
- Major issues: none
- Confirmed:
  - no GPT judge / `--score` path in the parallel runner
  - Stage3 still receives `--exclude-cbc-alert-summary`
  - existing valid runs are skipped before task creation
  - parallel plan started with `89` missing tasks after `73/162` formal run files existed
  - limits remain `300/800/1600/24576`
  - cost check remains `$10`
- Caution:
  - on failure or cost threshold, the parallel runner stops submitting new tasks, but already-running child processes may continue until they naturally exit
  - this is acceptable for the current run because the cost threshold is not a hard cap and current estimated run-only cost is still far below `$10`

## 2026-06-11 JST - Chain 25 Stage2 Completed After Parallel Restart

- The previously long-running run completed successfully after parallel restart:
  - `gpt-4.1-mini / chain_25_e18_dns_packet_capture_batch_chain_stage2`
- Formal run status:
  - completed formal run files: `77/162`
  - completed formal run validation errors: `0`
  - cumulative estimated run-only API cost: `$1.218968`
- Active runs after completion:
  - `gpt-4.1-mini / chain_26_e18_python_simplehttpserver_network_chain_stage3`
  - `gpt-4.1-mini / chain_27_e19_dns_packet_capture_batch_chain_stage1`
  - `gpt-4.1-mini / chain_27_e19_dns_packet_capture_batch_chain_stage2`

## 2026-06-11 JST - First Model Completed

- `gpt-4.1-mini` formal run-only set completed:
  - stage1: `27/27`
  - stage2: `27/27`
  - stage3: `27/27`
- Total formal run files at checkpoint:
  - `126/162`, then `127/162` during validation
- Validation result at checkpoint:
  - completed formal run validation errors: `0`
- Estimated cumulative run-only API cost at checkpoint:
  - about `$2.26`
- Parallel runner remained active for the remaining `gpt-5.4-mini` runs.

## 2026-06-11 JST - Run-only Execution Completed

- Formal run-only execution completed.
- Final formal run status:
  - completed formal run files: `162/162`
  - `gpt-4.1-mini`: `27/27` stage1, `27/27` stage2, `27/27` stage3
  - `gpt-5.4-mini`: `27/27` stage1, `27/27` stage2, `27/27` stage3
  - Stage3 total: `54/54`
- Final validation:
  - completed formal run validation errors: `0`
  - Stage3 alert summary hidden / telemetry retained checks passed for all `54` Stage3 runs
- Final estimated run-only API cost:
  - `$2.9870929499999983`
- GPT judge / scoring:
  - no `--score` was used
  - GPT judge API was not used
- Process status:
  - no formal run-only runner or child runner processes remained after completion check

## 2026-06-11 JST - Codex Scoring Long Path Verification Issue

- During gpt-5.4-mini Codex-side manual scoring, review artifact paths under `scores_codex_manual_double_review_gpt54/.../<instance_id>/codex_score_result.json` exceeded the normal Windows 260-character path limit.
- Symptom:
  - `cmd dir` showed files such as `codex_score_result.json`.
  - standard PowerShell/Python path checks sometimes reported the same file as missing.
  - Python access succeeded with the Windows long-path prefix `\\?\`.
- Action:
  - added `scores_codex_manual_double_review_gpt54/aggregate_gpt54_double_review.py`
  - all aggregate/read/write checks in that script use long-path handling.
- Classification:
  - verification I/O issue only; not a formal run failure and not evidence that scoring JSON content is invalid.
