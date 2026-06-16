# FIT2026 Manuscript Rewrite Gate 2026-06-16

## Scope

- Manuscript: `paper/main.tex`
- PDF: `paper/main.pdf`
- Source baseline: latest GitHub `origin/master` paper artifact was fetched and used as the clean non-mojibake base.
- Rewrite target: 23-chain experiment results with `gpt-4.1-mini`, `gpt-5.4-mini`, and `gpt-5.5 low raw`.

## Experiment Claims Checked

- Current experiment scope is 23 behavior chains, 3 stages, and 207 scored rows per model.
- `gpt-4.1-mini` and `gpt-5.4-mini` use two completed formal23 sets plus one legacy 27-chain set filtered to the current 23-chain scope.
- `gpt-5.5 low raw` is reported as a raw-output salvage evaluation because the required JSON / `code_steps` output contract was not followed.
- Stage 3 excludes CBC alert-summary rows from SQL search targets, but keeps CBC EDR/NGAV telemetry and other OS/browser logs.
- Cost for `gpt-5.5 low raw` is the conservative reconstructed estimate from `results_23chain_20260614/openai_cost_audit_note_20260614.md`, not a direct `call_total_usd` ledger value.

## Build Checks

- Build command: `tectonic --keep-logs --keep-intermediates main.tex`
- Build result: exit code 0.
- PDF page count: 5 pages.
- PDF media box: A4, 595.28 x 841.89 pt.
- PDF size: 295182 bytes, under 3 MB.
- LaTeX log: no `Overfull`, no fatal error, no LaTeX error, no undefined control sequence; underfull warnings only.
- Page numbering: suppressed in source with `\pagestyle{empty}` and `\thispagestyle{empty}`.

## Review Gate

Round 1:

- `review_gpt55_rewrite_round1_reviewer1.json`: OK.
- `review_gpt55_rewrite_round1_reviewer2.json`: FIX_REQUIRED; requested replicate wording, scenario traceability, cost provenance, and stronger limitations.
- `review_gpt55_rewrite_round1_reviewer3.json`: FIX_REQUIRED; requested author/affiliation cleanup, scoring reproducibility, consistent `gpt-5.5 low raw` wording, and PDF checks.

Round 2:

- `review_gpt55_rewrite_round2_reviewer1.json`: OK.
- `review_gpt55_rewrite_round2_reviewer2.json`: OK.
- `review_gpt55_rewrite_round2_reviewer3.json`: source-level OK, pending PDF/FIT checks.

Round 3:

- `review_gpt55_rewrite_round3_reviewer1.json`: OK.
- `review_gpt55_rewrite_round3_reviewer2.json`: OK.
- `review_gpt55_rewrite_round3_reviewer3.json`: OK.

Post-round3 delta review:

- A final cost-provenance wording change was made after round 3, then PDF was rebuilt.
- `review_gpt55_rewrite_round4_reviewer1.json`: OK.
- `review_gpt55_rewrite_round4_reviewer2.json`: OK.
- `review_gpt55_rewrite_round4_reviewer3.json`: OK.

## Remaining Human Check

- The author name was corrected per user instruction to `小松崎 大世`.
- Confirm the exact affiliation before final submission.
