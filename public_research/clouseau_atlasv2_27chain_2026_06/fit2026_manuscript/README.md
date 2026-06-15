# FIT2026 manuscript workspace

Purpose: FIT2026 manuscript drafting area for the CLOUSEAU process-time behavior reconstruction experiment.

## Files

- `fit2026_requirements.md`: confirmed FIT2026 requirements and local checklist.
- `draft_body_ja.md`: copy-paste oriented Japanese manuscript draft.
- `paper/main.tex`: LaTeX working draft matching the FIT page settings as closely as possible.
- `official_reference/`: official FIT sample files downloaded from the FIT2026 requirement page.

## Current Draft Stance

- Target category is undecided: general paper or selected paper.
- The default draft is written as a Japanese, two-column FIT-style paper.
- Page target should be decided early:
  - General paper: 2-8 pages.
  - Selected paper: 4-8 pages and requires presenter membership eligibility.
- The LaTeX file intentionally has no page numbers.

## Build Note

The default `main.tex` uses pdfLaTeX + `CJKutf8` because this is the configuration that compiled in the current Overleaf-like setup:

```powershell
cd docs\fit2026_manuscript\paper
pdflatex main.tex
```

If using Overleaf, `main.tex` should compile with the default pdfLaTeX compiler. A prettier LuaLaTeX version is saved as `main_lualatex_pretty.tex`, but it requires `Menu -> Compiler -> LuaLaTeX`.
