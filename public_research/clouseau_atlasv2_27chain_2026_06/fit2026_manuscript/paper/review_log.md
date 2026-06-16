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

Status: pending

## Round 3 Local

Status: pending

## Single-File 6-Page Expansion 2026-06-16

Status: passed by static review

Actions:

- Removed `永田　功`, `Isao Nagata`, affiliation mark 3, and the YAMAGATA affiliation from the title block.
- Expanded the single-file `main.tex` from the short 3-page draft toward a 6-page manuscript by adding detailed discussion of scoring interpretation, operational implications, future improvements, scenario-level analysis, and limitations.
- Kept the accepted title layout: full-width Japanese title, English title, Japanese author row, English author row, and affiliations above the two-column body.
- Synchronized the same `main.tex` content to both manuscript and public paper locations.

Review:

- Active `main.tex` contains no `\maketitle`, `\title`, `\author`, `\input`, `\cite`, `\ref`, `\bibliography`, or manual CJK environment.
- Active `main.tex` contains no `永田`, `Isao`, `YAMAGATA`, or affiliation mark 3.
- Active `main.tex` has one `\begin{document}` and one `\end{document}`, with matched `center` and `tabular` environments.
- Local `pdflatex` is not installed, so exact PDF page count must be verified in Overleaf.

## Additional Length Tuning 2026-06-16

Status: passed by static review

Actions:

- Added discussion of run-to-run variability, stage sensitivity, and why repeated runs are needed.
- Added operational discussion of model cost, staged review, confidence estimation, and two-step scoring review.
- Increased active `main.tex` from 15,230 characters to 16,468 characters after the user reported the prior version reached only the beginning of page 5.

Review:

- Active `main.tex` still contains no removed author or affiliation-3 strings.
- Active `main.tex` still has no external file, citation, reference, or BibTeX dependency.

## Sample Format Alignment Review 2026-06-16

Status: passed after 3 reviews

Reason:

- The prior single-file fallback placed affiliations as a visible block directly below the author table.
- The senior sample uses author affiliation marks and emits affiliations as footnotes through `\affmark` / `\afftext`, so the affiliation position was visually different.

Fix:

- Changed `\affmark` to use `\footnotemark[#1]`.
- Removed the visible affiliation block from inside the full-width title area.
- Added `\footnotetext[1]` and `\footnotetext[2]` immediately after the `\twocolumn[...]` title block, matching the senior sample's footnote-style affiliation placement while keeping `main.tex` single-file.

Review 1 - sample format:

- Full-width title block remains in `\twocolumn[...]`.
- Author table remains Japanese author row followed by English author row.
- Affiliations are no longer printed as a title-body block; they are emitted as footnotes.

Review 2 - LaTeX safety:

- No `\maketitle`, `\title`, `\author`, `\input`, `\cite`, `\ref`, `\bibliography`, or manual CJK environment was introduced.
- One `\begin{document}` and one `\end{document}` remain.
- `center` and `tabular` environments are balanced.

Review 3 - content and authors:

- The author list remains four authors: Komatsuzaki, Yokoyama, Yamashita, Kawamura.
- Removed author and affiliation strings remain absent.
- Manuscript and public `main.tex` copies are byte-identical.
- Local TeX engine is not installed, so final visual page check must be done in Overleaf.

## Page Trim and Section Restructure 2026-06-16

Status: passed after 3 reviews

Reason:

- The prior version entered page 7 in Overleaf.
- The manuscript had too many top-level sections, unlike the senior sample where the experiment chapter is organized with subsections such as 5.1--5.4.

Fix:

- Reduced active `main.tex` from 16,485 characters to 15,390 characters.
- Reorganized `結果`, `採点結果の解釈`, `運用上の含意`, `今後の改善`, `個別シナリオの分析`, and `考察` under `\section{実験と考察}` as subsections.
- Compressed duplicated discussion around run variability, cost, review policy, improvement items, and model operational interpretation.

Review 1 - structure:

- Top-level flow is now Introduction, Related Work, Method, Experiment Setup, Experiment and Discussion, Limitations/Future Work, Conclusion.
- Section 5 now contains numbered subsections including `5.4` equivalent content: overclaim and scoring review.

Review 2 - LaTeX and length:

- No external dependency commands, citations, references, or removed-author strings were introduced.
- Document has one `\begin{document}` and one `\end{document}`, with matched `center` and `tabular` environments.

Review 3 - sync and title:

- Manuscript and public `main.tex` copies are byte-identical.
- Four-author title block and footnote-style affiliations remain intact.
- Exact page count still requires Overleaf visual confirmation because no local TeX engine is installed.

## Explicit Subsection Numbering 2026-06-16

Status: passed by static review

Reason:

- The source used `\subsection{...}`, which should normally render as `5.1`, `5.2`, etc., but the user reported that the PDF did not visibly show the intended numbering.

Fix:

- Added explicit numbering controls:
  - `\setcounter{secnumdepth}{2}`
  - `\renewcommand{\thesection}{\arabic{section}}`
  - `\renewcommand{\thesubsection}{\thesection.\arabic{subsection}}`

Review:

- Static section walk now maps `\section{実験と考察}` to section 5.
- Static section walk maps `\subsection{全体結果}` to 5.1, `\subsection{Stage別結果}` to 5.2, and `\subsection{過剰出力と採点レビュー}` to 5.4.
- No external dependency commands, removed-author strings, citations, or references were introduced.

## Sample Major-Section Restructure 2026-06-16

Status: passed after 3 reviews

Reason:

- The sample paper uses the major-section structure `1 はじめに`, `2 関連研究`, `3 提案手法`, `4 データセット`, `5 実験`, `6 おわりに`.
- The prior manuscript still used `4 実験設定`, `5 実験と考察`, and many numbered subsections beyond 5.4.

Fix:

- Renamed section 2 to `関連研究`.
- Changed section 4 to `データセット`.
- Changed section 5 to `実験`.
- Added `5.1 実験目的`, `5.2 実験設定`, `5.3 評価方法`, and `5.4 実験結果`.
- Moved detailed discussion topics inside `5.4 実験結果` as bold paragraph heads instead of numbered subsections, so no `5.5` or later subsections appear.
- Folded limitations into the experiment-result discussion and kept section 6 as `おわりに`, matching the sample's major-section style.

Review 1 - sample structure:

- Static walk now gives exactly: sections 1--6 and subsections 5.1--5.4.

Review 2 - LaTeX safety:

- No `\maketitle`, `\input`, citations, references, removed-author strings, or external dependencies were introduced.
- Document and tabular environments remain balanced.

Review 3 - sync/title:

- Manuscript and public `main.tex` copies are byte-identical.
- Four-author title block and footnote-style affiliations remain intact.

## External Review Response Pass 2026-06-16

Status: passed after action review and 3 final reviews

Action review:

- Baseline concern: added related-work framing that there is little direct prior work on reconstructing evidence-backed benign behavior sequences after detection; existing work is positioned as anomaly detection, log diagnosis, agent investigation, or dataset construction.
- CLOUSEAU novelty concern: clarified that the contribution is not a new agent mechanism, but the task formulation, Stage design, and overclaim-aware evaluation.
- Metric concern: added formal definitions for action recall, critical evidence recall, candidate precision, sequence order, overclaim, and normalized overclaim.
- Overclaim concern: added `Over/inst` to the model and Stage result tables.
- Repetition concern: removed confusing wording around old 27-chain extraction and stated the experiment as 23 chains × 3 stages × 3 evaluations.
- Model handling concern: kept `gpt-5.5 low` in the main tables as a normal comparison model, and removed `raw`, `salvage`, and output-contract-failure framing.
- Reliability concern: added that scoring used two-stage review and adjudication of disagreements.
- External validity concern: strengthened the limitation about ATLASv2-derived chains not fully representing diverse enterprise benign activity.
- Reference concern: added inline numeric references for CLOUSEAU, Sysmon, ReAct, DeepLog, and ATLAS/ATLASv2 without introducing LaTeX citation dependencies.

Final review 1 - user policy:

- No `raw`, `salvage`, output-contract-failure, old-27-chain, or 3-set wording remains.
- The manuscript states 23 chains × 3 stages × 3 evaluations.
- `gpt-5.5 low` remains in the main comparison tables.

Final review 2 - reviewer findings:

- Normalized overclaim, formal metric definitions, CLOUSEAU difference, direct-baseline absence, scoring review, and external validity are all present.

Final review 3 - LaTeX and sync:

- No external dependency commands, removed-author strings, citations, or references were introduced.
- Manuscript and public `main.tex` copies are byte-identical.

## Page-Length Trim Pass 2026-06-16

Status: passed after action review and 3 final checks

Action review:

- Replaced the vertical metric-definition table with compact formal prose while preserving action recall, critical evidence recall, sequence order, candidate precision, overclaim, and Over/inst definitions.
- Merged duplicated model interpretation, operation, and improvement discussion into shorter paragraphs.
- Compressed individual scenario analysis and overall discussion while keeping the explicit/multi-step/semantic distinction, Stage 3 interpretation, and gpt-5.5 overclaim finding.

Final review 1 - content:

- The reviewer-response points remain present after trimming: direct-baseline absence, metric definitions, normalized overclaim, scoring review, and ATLASv2 external-validity limitation.

Final review 2 - structure:

- Major structure remains sections 1--6 with experiment subsections 5.1--5.4.
- The manuscript stays in single-file `main.tex` form.

Final review 3 - size and sync:

- Canonical `main.tex` was reduced from about 15,989 characters to about 12,800 characters.
- Manuscript and public `main.tex` copies are byte-identical.

## Citation And Table Review Response Pass 2026-06-16

Status: passed after action review and 3 final checks

Action review:

- Converted the manual reference list to single-file `thebibliography` with `\bibitem` keys, so `\cite{...}` works without BibTeX.
- Added 13 inline `\cite` usages covering CLOUSEAU, Sysmon, ReAct, DeepLog, ATLAS, and ATLASv2.
- Converted result tabular blocks to numbered `table` / `table*` floats with captions and labels.
- Changed `Over/inst` to clearer `Over/run` wording and kept normalized overclaim values.
- Added a short note that `gpt-5.5 low` is evaluated from freer-form output under the same component rubric and is separated by a rule in the main tables.
- Added a scenario-level numeric table for `gpt-5.4-mini` with chain count, action, critical evidence, order, and Over/run.
- Tightened the order-score definition as adjacent gold-step order slots rather than Kendall's tau or edit distance.
- Added short limitations for missing single-prompt baseline, inter-annotator agreement, and systematic API cost/runtime comparison.

Final review 1 - reviewer findings:

- Inline citation, table caption/label, scenario table, overclaim normalization, and metric-definition requests are reflected.

Final review 2 - LaTeX safety:

- All `\cite{...}` keys have matching `\bibitem{...}` entries.
- All `\ref{...}` targets have matching `\label{...}` entries.
- `main.tex` remains single-file and uses no `\input`, `\bibliography`, or `\maketitle`.

Final review 3 - scope and sync:

- The manuscript still states 23 chains × 3 stages × 3 evaluations.
- The public and manuscript `main.tex` copies are byte-identical after sync.
- Local TeX engines were not available, so final PDF page count must be checked on Overleaf.

## Domain Context Citation Pass 2026-06-16

Status: passed after targeted review

Actions:

- Added Carbon Black Cloud (CBC) as the EDR source context instead of leaving `CBC` unexplained.
- Added MITRE ATT&CK as the attack-technique knowledge-base context.
- Added LOLBAS as the Living-off-the-Land context for benign-looking Windows tool activity.
- Added `cbc`, `attack`, and `lolbas` bibliography entries and inline citations.
- Synced canonical, public, and `docs/fit2026_manuscript/paper/main.tex` copies.

Review:

- All 9 citation keys used in text have matching `\bibitem` entries.
- The added wording keeps the task framed as benign behavior reconstruction for false-positive triage, not attack detection.
- All three `main.tex` copies are byte-identical after sync.

## Reviewer Response And Six-Page Expansion Pass 2026-06-16

Status: passed after 3 review checks

Action review:

- Adjusted FIT geometry to top 30mm, left/right 18mm, bottom 27mm, and removed the negative first-page vertical space that could collide with the lecture-number area.
- Removed the `gpt-5.5 low` freer-form/raw caveat from the result-table note and kept it as a normal model row, per current writing direction.
- Replaced `evaluation instance` wording with `run`, and normalized metric wording to `candidate precision`.
- Added formal aggregation notes: overall scores use micro averages over hit/denominator slots, scenario rows aggregate run/slot counts inside each category, and single-step chains are excluded from the order denominator.
- Split interpretation-heavy text out of Experiment into an independent `考察` section, reducing duplicated recommendations while expanding the discussion to target a 6-page manuscript.
- Added explicit statements that the paper measures reconstruction quality, which is a necessary condition for false-positive triage support but not a direct measurement of analyst speed or final triage accuracy.
- Added 3-run variation ranges for `gpt-4.1-mini` and `gpt-5.4-mini`, strengthened Stage 3 and overclaim as the FP-specific novelty, and fixed ATLASv2 year to 2024.

Final review 1 - LaTeX safety:

- `\begin` / `\end` counts match, brace balance is zero, and underscores appear only in labels or math-safe contexts.
- All `\cite{...}` keys have matching `\bibitem{...}` entries, with 9 cited bibliography items.

Final review 2 - reviewer coverage:

- The title/evaluation gap, gpt-5.5 table treatment, micro aggregation, order denominator, run variation, novelty framing, duplicated discussion, terminology drift, category consistency, and ATLASv2 year issues are all addressed.

Final review 3 - page-length and sync readiness:

- Canonical `main.tex` increased to about 15,819 characters from the prior 5-page version and no longer uses negative top spacing; this should move the Overleaf output back toward 6 pages.
- Local TeX engines were not installed in this environment, so final page count still needs Overleaf confirmation after paste/upload.

## Claim-Focused Prize Review Pass 2026-06-16

Status: passed after 3 review checks

Action review:

- Reframed the title and introduction from "CLOUSEAU application" to an evaluation of evidence-backed benign behavior reconstruction for false-positive triage.
- Added a single central claim: false-positive triage support should be evaluated as evidence-backed benign behavior sequence reconstruction, including both evidence recall and overclaim.
- Promoted the two main findings into the contribution, results, and conclusion: (1) `gpt-5.4-mini` remains stable when alert summary rows are excluded, and (2) high raw reconstruction ability does not equal operational suitability because `gpt-5.5 low` has the highest recall and the highest overclaim.
- Treated `gpt-5.5 low` as a capability upper-bound probe rather than a simple operational model ranking.
- Changed scenario reporting to chain-level macro averages and updated the `gpt-5.4-mini` scenario table accordingly: explicit 0.869/0.826/0.778, multi-step 0.783/0.600/0.543, semantic 0.642/0.481/0.333.
- Added the explicit micro/macro aggregation statement explaining why overall values and scenario-weighted values need not match.

Final review 1 - stale wording and numbers:

- No stale `raw`, `evaluation instance`, `free-form comparability note`, old margin, old title, or old scenario values remain in the active manuscript.

Final review 2 - claim coverage:

- The central claim, Finding 1, Finding 2, Stage 3 evidence numbers, `gpt-5.5 low` upper-bound-probe framing, micro/macro definition, and necessary-condition limitation are all present in the manuscript.

Final review 3 - static LaTeX and page risk:

- `\begin` / `\end` counts match, brace balance is zero, and all citation keys have bibliography entries.
- Canonical `main.tex` is about 16,615 characters. Local TeX engines were unavailable, so exact Overleaf page count remains to be checked, but the manuscript is intentionally expanded from the 5-page version while still avoiding a figure file or extra artifacts.
