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
