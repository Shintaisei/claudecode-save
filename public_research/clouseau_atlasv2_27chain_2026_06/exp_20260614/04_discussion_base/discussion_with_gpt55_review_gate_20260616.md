# GPT-5.5 Discussion Review Gate 2026-06-16

## Accepted Document

`detailed_discussion_with_gpt55_20260616.md`

This document is accepted as the current discussion base for the 23-chain experiment including GPT-5.5 low raw results.

## Review Outcome

| reviewer | first pass | final pass | final file |
| --- | --- | --- | --- |
| Reviewer A | FIX_REQUIRED | OK | `reviewer_a_discussion_with_gpt55_20260616_final.json` |
| Reviewer B | FIX_REQUIRED | OK | `reviewer_b_discussion_with_gpt55_20260616_final.json` |

Both reviewers independently checked the discussion draft against local result sources and approved the revised version.

## Blocking Fixes Resolved

- Framework-level results now include all five framework groups for all three models.
- The framework section explicitly states chain-count limits: 13 chains for `network_service_behavior`, 5 for `collection_or_tool_invocation`, 2 each for `command_shell_execution` and `script_execution_chain`, and 1 for `persistence_registry_run_key`.
- The cost section now identifies separate local provenance for gpt-4.1-mini/gpt-5.4-mini and GPT-5.5 estimates.

## Remaining Caveats To Preserve In Paper Writing

- GPT-5.5 is a raw-output salvage result, not a structured-output-contract-equivalent result.
- GPT-5.5 cost is reconstructed from token/progress logs because local `call_total_usd` values were zero for GPT-5.5.
- The gpt-4.1-mini and gpt-5.4-mini third source set is the legacy 27-chain run filtered to the current 23-chain scope, not a same-condition formal23 rerun.
- One-chain and two-chain framework groups should be described as concrete cases rather than stable category-level findings.
