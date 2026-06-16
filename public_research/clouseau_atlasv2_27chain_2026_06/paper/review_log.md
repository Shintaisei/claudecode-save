# Professor Review Log

Goal: 6ページFIT2026原稿を、全体レビュー3回・局所レビュー3回で通す。

## Round 1 Global

Status: addressed, pending re-review

Findings addressed:

- Added scoring-rule details for required-item score, candidate claim precision denominator, overclaim, and critical evidence.
- Added gold construction criteria and excluded inferred intent/maliciousness from required items.
- Explained D1 as an independent process creation step, not merely supporting evidence.
- Added Stage 2/3 confounding note and future plan to inspect exploration logs.
- Added general gold-construction procedure for future multi-case experiments.

## Round 1 Local

Status: addressed, pending re-review

Findings addressed:

- Removed stale wording around generic recall and major behavior elements.
- Replaced long registry-path inline code with shorter prose to reduce overfull risk.
- Shortened output-field table labels to reduce two-column overfull risk.
- Clarified `cand. prec.` as `claim precision` in the result table.

## Round 2 Global

Status: addressed, pending re-review

Findings addressed:

- Added artifact reference for complete scoring reproducibility.
- Added Stage 3 DB/run evidence references: single-case Stage 3 run artifact and formal chain DB validation artifacts.

## Round 2 Local

Status: passed

## Round 3 Global

Status: passed

Professor-style checks:

- ATLAS position: passed. The manuscript now distinguishes ATLAS as prior attack investigation work, ATLASv2 as the log/data environment, and this paper as a post-alert SOC behavior reconstruction evaluation.
- Incident-analysis scope: passed. The target is clearly limited to endpoint behavior reconstruction after alerts or process/time clues, not malware detection, attribution, or full incident-response automation.
- Formal experiment reflection: passed. The paper now uses the 27-chain, 3-stage, 2-model result set instead of the old single-case pre-experiment.
- Metric consistency: passed with note. `gpt-4.1-mini` legacy action totals are normalized in the paper by separating critical-evidence slots; critical evidence remains reported separately.
- Limitations: passed. The manuscript states the single ATLASv2 benign environment boundary and the Stage 3 alert-summary-only exclusion boundary.

## Round 3 Local

Status: passed

Local checks:

- Removed stale single-case / pre-experiment claims.
- Checked for old fractions such as `14/14`, `8/14`, `321/860`, and old Discord-only result wording; none remain.
- Checked LaTeX brace balance: open and close brace counts match.
- FIT2026 page/margin assumptions checked against the official page: A4, top 30mm, bottom 25mm, left/right 20mm, column gap 7mm, no page numbers are consistent with the manuscript settings.

Remaining risk:

- Local TeX tools (`latexmk`, `pdflatex`, `lualatex`, `tectonic`) are not installed in this environment, so PDF page count and overfull/underfull warnings could not be verified here.

## CLOUSEAU Follow-up Round 1 Global

Status: addressed, pending re-review

Findings addressed:

- Added explicit citation to the CLOUSEAU paper.
- Defined CLOUSEAU as a hierarchical multi-agent framework with Chief Inspector, Investigator, and QA agents.
- Clarified that this manuscript uses CLOUSEAU as the investigation pipeline basis, not as an unnamed generic LLM agent.
- Added the key distinction: CLOUSEAU originally targets attack narrative reconstruction from a POI, while this paper evaluates post-alert SOC behavior-chain reconstruction including benign/normal chains.

## CLOUSEAU Follow-up Round 1 Local

Status: addressed, pending re-review

Findings addressed:

- Added `\bibitem{clouseau}` before other related-work references.
- Added `\cite{clouseau}` in introduction, related work, and method sections.
- Updated the abstract to say "CLOUSEAU-based LLM agent workflow".

## CLOUSEAU Follow-up Round 2 Global

Status: addressed, pending re-review

Findings addressed:

- Checked that CLOUSEAU is not presented as the paper's original invention.
- Checked that the paper's novelty is framed as evaluation/re-scoping: POI-start attack investigation -> SOC post-alert behavior-chain reconstruction.
- Added wording that the work does not replace or re-evaluate CLOUSEAU's original attack narrative task.

## CLOUSEAU Follow-up Round 2 Local

Status: passed

Local checks:

- Verified multiple mentions of CLOUSEAU exist across abstract, introduction, related work, method, experiment setup, discussion, and conclusion.
- Verified brace balance still matches after edits.

## CLOUSEAU Follow-up Round 3 Global

Status: passed

Professor-style checks:

- Citation adequacy: passed. CLOUSEAU is cited where the system concept is introduced, where prior LLM-agent investigation work is discussed, and where the pipeline is described.
- Novelty boundary: passed. The paper states that it does not claim CLOUSEAU itself as original and does not simply re-evaluate CLOUSEAU's attack-narrative task.
- Research positioning: passed. The manuscript now frames the contribution as adapting/evaluating CLOUSEAU-style POI investigation for SOC post-alert behavior-chain reconstruction on ATLASv2 benign logs.
- ATLAS/CLOUSEAU relationship: passed. CLOUSEAU is the investigation pipeline basis; ATLASv2 is the log environment; this paper's target is evidence-backed behavior reconstruction.

## CLOUSEAU Follow-up Round 3 Local

Status: passed

Local checks:

- Confirmed `\cite{clouseau}` appears in introduction, related work, and method sections.
- Confirmed the bibliography contains authors, title, year, and URL for the CLOUSEAU paper.
- Checked LaTeX brace balance again after CLOUSEAU edits: open and close brace counts match.

Remaining risk:

- PDF build/page count remains unverified because local TeX tools are unavailable in this environment.

## GPT-5.5 / 23-Chain Rewrite Round 1

Status: addressed, pending later re-review

Scope:

- Rewrote the manuscript from the latest GitHub paper artifact to reflect the current 23-chain experiment.
- Added `gpt-5.5 low raw` as a raw-output salvage result.
- Replaced old 27-chain / 81-run result claims with 23-chain, 3-stage, 207-row-per-model claims.

Review outcomes:

- Reviewer 1: passed.
- Reviewer 2: requested clearer replicate wording, scenario traceability, cost provenance, and limitations.
- Reviewer 3: requested author/affiliation cleanup, scoring reproducibility, consistent `gpt-5.5 low raw` wording, and PDF/FIT checks.

## GPT-5.5 / 23-Chain Rewrite Round 2

Status: addressed, pending PDF gate

Fixes checked:

- Clarified that `gpt-4.1-mini` and `gpt-5.4-mini` use a legacy 27-chain set filtered to the current 23-chain scope as the third set.
- Defined scenario groups and the single-chain semantic case.
- Clarified that Stage 3 hides only CBC alert-summary rows, not all EDR telemetry.
- Added explicit scoring reproducibility wording: two independent reviews and third adjudication on conflicts.
- Replaced author/affiliation placeholders with inferred local metadata.

Review outcomes:

- Reviewer 1: passed.
- Reviewer 2: passed.
- Reviewer 3: source-level passed, pending PDF/FIT checks.

## GPT-5.5 / 23-Chain Rewrite Round 3

Status: passed, followed by delta review

Local checks:

- Built `main.pdf` successfully with Tectonic/XeLaTeX.
- Confirmed 5 pages, A4 media box, size under 3 MB.
- Removed `Overfull` warnings; remaining warnings are underfull only.

Review outcomes:

- `review_gpt55_rewrite_round3_reviewer1.json`: OK.
- `review_gpt55_rewrite_round3_reviewer2.json`: OK.
- `review_gpt55_rewrite_round3_reviewer3.json`: OK.

## GPT-5.5 / 23-Chain Rewrite Post-Round3 Delta

Status: passed

Delta:

- Updated the cost provenance wording so `gpt-5.5 low raw` clearly refers to the public package cost audit note rather than a direct `call_total_usd` ledger.
- Rebuilt the PDF after the delta; final size is 295182 bytes, 5 pages, A4, with no `Overfull` warnings.

Review outcomes:

- `review_gpt55_rewrite_round4_reviewer1.json`: OK.
- `review_gpt55_rewrite_round4_reviewer2.json`: OK.
- `review_gpt55_rewrite_round4_reviewer3.json`: OK.

Remaining risk:

- Author name was corrected per user instruction to `小松崎 大世`. Affiliation should still be confirmed before final submission.

## User Correction 2026-06-16

Status: passed

Changes:

- Removed the English abstract block from `main.tex`.
- Corrected the author name from `小松崎 慎太郎` to `小松崎 大世`.

## Overleaf Template Conversion 2026-06-16

Status: superseded by single-file `main.tex`

Changes:

- Reworked the paper into the same Overleaf-style structure as `2025_09_FIT_上前諒輔_論文.zip`.
- Added `styles/FITpaper.cls`, `styles/mystyle.sty`, `.latexmkrc`, and `contents/*.tex`.
- Replaced the title with `Windowsエンドポイントログを用いた正常行動の行動列復元による偽陽性判断支援の検討`.
- Added the professor/coauthor block following the senior paper style.
- Revised the introduction and conclusion so the research framing explicitly targets false positive triage through benign/normal behavior sequence reconstruction.
- Removed stale alternative source files and the old PDF to avoid Overleaf confusion.

Review:

- Action-by-action review was recorded in `review_overleaf_template_20260616.md`.
- Active source has no English abstract environment and no old placeholder author.
- Local pLaTeX build was not possible because `platex`, `pbibtex`, `dvipdfmx`, and `latexmk` are not installed in this environment.

## Overleaf Single-File Correction 2026-06-16

Status: passed by static review

Reason:

- The user wants to paste only `main.tex` into Overleaf.
- The previous split-file/FITpaper structure required auxiliary files and engine settings, which is too fragile for copy-paste use.
- The attached Overleaf log showed `fontspec` failing under default `pdflatex`; therefore the active source must not use `fontspec`, `xeCJK`, or a custom class.

Actions:

- Rebuilt `main.tex` as a fully self-contained file.
- Removed dependency on `FITpaper.cls`, `contents/*.tex`, `.latexmkrc`, `fontspec`, and `xeCJK`.
- Kept the user-specified Japanese and English title.
- Kept the coauthor/professor block from the senior-paper style.
- Kept the false-positive-triage framing in the introduction and conclusion.
- Removed the split-file Overleaf template assets to avoid confusion.

Review:

- Active `main.tex` has no `\input{...}`.
- Active `main.tex` has no `fontspec`, `xeCJK`, or `FITpaper` dependency.
- Active `main.tex` has no English abstract environment.
- Active `main.tex` is intended for Overleaf default `pdflatex` using `CJKutf8`.

## Overleaf Single-File CJK Fix 2026-06-16

Status: passed by static review

Reason:

- The Overleaf log showed `job aborted, no legal \end found`.
- The active source had a manual `\begin{CJK}...\end{CJK}` wrapper, so the Japanese wrapper became a possible paste/engine failure point.

Actions:

- Replaced `\usepackage{CJKutf8}` and the manual `CJK` environment with `\usepackage[whole]{bxcjkjatype}`.
- Kept the file as a single self-contained `main.tex`.
- Kept `\maketitle`, `\title`, and `\author` removed.

Review:

- Active `main.tex` has exactly one `\begin{document}` and one `\end{document}`.
- Active `main.tex` has no `\begin{CJK}` or `\end{CJK}`.
- Active `main.tex` has balanced braces and matched table/figure/bibliography environments.
- Tectonic local compile is not representative here because Tectonic uses an unsupported engine for `bxcjkjatype`; Overleaf default `pdflatex` is the intended engine.

## Overleaf Minimal Single-File Fallback 2026-06-16

Status: passed by static review

Reason:

- The Overleaf log still showed `job aborted, no legal \end found`.
- The log also contained many undefined citation and reference warnings, which are not fatal but made debugging noisy.
- To make copy-paste into Overleaf robust, the active `main.tex` was reduced to a shorter self-contained file with no cross-reference system.

Actions:

- Removed all `\cite`, `\ref`, and `\label` usages.
- Removed floating `table` and `figure` environments.
- Replaced the bibliography environment with a plain `\section*{参考文献}` list.
- Kept the essential research framing, method, experiment setup, result tables, and discussion.
- Added `% END OF MAIN.TEX` after `\end{document}` so paste completion is easy to verify.

Review:

- Active `main.tex` has exactly one `\begin{document}` and one `\end{document}`.
- Active `main.tex` has no `\cite`, `\ref`, `\label`, `\begin{table}`, or `\begin{figure}`.
- Active `main.tex` has balanced braces and matched `center` / `tabular` environments.
- Active `main.tex` is 194 lines, making full paste into Overleaf less error-prone.

## Overleaf Title Layout Correction 2026-06-16

Status: passed by static review

Reason:

- The minimal fallback compiled more easily, but its title block did not match the senior-paper sample.
- The title and affiliations were placed like ordinary body content inside the two-column flow.

Actions:

- Moved the title block into `\twocolumn[...]` so it spans the full page width above the two-column body.
- Changed the author area to match the senior-paper pattern: Japanese author row with affiliation marks, English author row below it, affiliations below the author table.
- Narrowed the author table with `\small` and trimmed tabular side padding so the five-author row is less likely to overflow.
- Kept the paper as a single pasteable `main.tex`; no external class or split files were reintroduced.

Review:

- Active `main.tex` still has no `\maketitle`, `\title`, `\author`, `\input`, `\cite`, `\ref`, or external class dependency.
- Active `main.tex` has exactly one `\twocolumn[...]` title block.
- Braces and `center` / `tabular` environments are balanced.
