# FIT2026 manuscript workspace

Purpose: FIT2026 manuscript drafting area for the CLOUSEAU process-time behavior reconstruction experiment.

## Files

- `FIT2026_論点生成_証跡発見_最終反映_関係構築の段階別分析_20260814.md`: 全1,571 Gold行動を、論点生成、証跡発見、最終反映、関係構築のどこで失敗したかに分解し、モデル別・正常／攻撃別の違いを整理した精密版。

- `FIT2026_調査ミスと結果とりまとめミスの分解_20260814.md`: Gold step・critical evidenceの発見不足を調査時のミス、主体・対象・関係の組立て、逆転、重複、未支持claimを結果とりまとめ時のミスとして分解し、3モデルと正常／攻撃の差を比較した分析。
- `FIT2026_3モデル_復元失敗パターン分析_20260814.md`: 全1,571 Gold stepと1,384 candidate claimを、step欠落、対象・主体・関係誤り、主体対象逆転、Gold非対応の付加、値誤り、重複、順序逆転に分類した考察用分析。
- `FIT2026_3モデル全試行_行動順序_意味クラス再採点_20260814.md`: GPT-4.1-mini・GPT-5.4-mini・GPT-5.5の正式採点可能な全384試行を同一規則で再採点し、意図した432試行に対する取得状況、行動意味クラス、順序coverage、条件付き順序正確性を整理した全体結果。
- `FIT2026_GPT55_行動順序_意味クラス再採点_20260814.md`: 主体・対象・critical evidenceを固定し、行動をログ根拠付き共通クラスで再採点した結果と、順序coverage／条件付き順序正確性を分離した分析。
- `FIT2026_GPT55_既存96PASS_行動分布分析_20260814.md`: Gold 66 stepとGPT-5.5の535 operation候補を行動family別に集計し、process/networkへの実験設計上の偏りと、正常側での過剰出力を整理した分析。
- `FIT2026_GPT55_主体行動対象_ケース別復元分析_20260814.md`: GPT-5.5の取得済み96 PASSを、正常8ケース・攻撃8ケースの各stepについて主体・行動・対象・証拠・完全復元に分解したケース別分析表。

- `FIT2026_資料作成の核_行動復元の成立条件と失敗条件_20260807.md`: current highest-level research stance for the FIT manuscript and presentation. Use this before revising the older body draft.
- `FIT2026_ユースケースの立ち位置と検証範囲_20260807.md`: attack/normal use-case taxonomy, direct coverage, structurally similar scope, and untested scope.
- `FIT2026_導入スライド文章案_20260807.md`: slide text, full speaking script, and transitions for the nine-slide introduction.
- `fit2026_requirements.md`: confirmed FIT2026 requirements and local checklist.
- `draft_body_ja.md`: copy-paste oriented Japanese manuscript draft.
- `paper/main.tex`: LaTeX working draft matching the FIT page settings as closely as possible.
- `official_reference/`: official FIT sample files downloaded from the FIT2026 requirement page.

## Current Draft Stance

- The current research core is to identify which normal and attack behaviors CLOUSEAU could reconstruct, which it could not reconstruct, and the conditions separating those outcomes.
- The success / partial-success / failure classification is provisional and must be finalized through case-level review.
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

## 別PCへの引き継ぎ

最新の研究資料と再採点結果は `codex/package-fit2026-experiment-results` ブランチに保存する。

```powershell
git clone https://github.com/Shintaisei/claudecode-save.git
cd claudecode-save
git switch codex/package-fit2026-experiment-results
```

再開時は、次の順で確認する。

1. `FIT2026_資料作成の核_行動復元の成立条件と失敗条件_20260807.md`
2. `FIT2026_ユースケースの立ち位置と検証範囲_20260807.md`
3. `FIT2026_結果数値再整理_claim単位Precision_20260815.md`
4. `FIT2026_論点生成_証跡発見_最終反映_関係構築の段階別分析_20260814.md`
5. `../current_experiment/results_2026-08-15/failure_analysis_semantic_v3/report.md`

再採点の入力・監査結果は `docs/current_experiment/results_2026-08-14/` と
`docs/current_experiment/results_2026-08-15/`、再計算用コードは `scripts/` に保存している。
APIキーを含む `.env.clouseau` とローカルDB・元データセットはGit管理外のため、別PCで個別に準備する。
