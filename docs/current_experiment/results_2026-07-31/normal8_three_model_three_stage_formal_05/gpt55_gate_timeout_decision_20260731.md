# GPT-5.5 sentinel timeout decision

- Status: **FAIL — not accepted as a formal run**
- Case: `chain_10_e07_discord_run_key_registry_chain_stage3`
- Policy: `material_causal_frontier_review_v2`
- Total-run limit: **1,800 seconds (30 minutes)**
- Observed stop: **1,800.063 seconds**
- Reason: `total_run_wall`
- Single-call timeout: not triggered
- Formal `run.json`: not created
- Full 72-run phase: not started

The API calls themselves continued to complete; the run failed to converge within the bounded sentinel period. This is therefore an investigation-convergence failure rather than a single API-call hang. The valid gpt-4.1-mini and gpt-5.4-mini sentinel runs remain unchanged and are not rerun.

The stop log also exposed two transient Windows `PermissionError` events while replacing the active-call watchdog JSON. A bounded retry was added to the atomic writer, and the relevant test suite passes 25 tests. The incomplete GPT-5.5 attempt has no final usage/cost ledger and is neither scored nor counted.
