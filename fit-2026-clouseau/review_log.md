# Professor Review Log

Goal: `fit-2025` と同じFITpaper形式で、CLOUSEAU / ATLASv2行動列復元評価の最終版原稿を作る。

## Round 1 Global

Status: addressed

Findings:

- FITpaper形式への移植が必要。`article` + `CJKutf8` ではなく、既存の `FITpaper.cls` と `contents/` 分割構成へ合わせる。
- CLOUSEAUへの言及が不十分だと、既存研究との差分が曖昧になる。
- ATLAS/ATLASv2の立ち位置は、攻撃検知ではなくSOC検知後の行動復元評価として明示する必要がある。

Actions:

- `fit-2025` の `styles/`, `.latexmkrc`, `main.tex` 構成に合わせた新規フォルダを作成。
- 導入、関連研究、手法、考察、結論でCLOUSEAUの役割を明示。
- CLOUSEAUは調査パイプライン基盤、ATLASv2はログ環境、本稿は行動列復元評価と整理。

## Round 1 Local

Status: addressed

Findings:

- ファイル分割形式を `fit-2025` と一致させる必要がある。
- 参考文献はFITpaper/TinyTeX 2026環境で安定してコンパイルできる形式にする必要がある。

Actions:

- `contents/title.tex`, `section1.tex` から `section6.tex`, `bibliography.tex`, `bibliographies.bib` を作成。
- 各content fileは `docmute` 前提で `\begin{document}` / `\end{document}` を持つ形式に統一。
- `FITpaper.cls` の参考文献まわりがTeX Live 2026で失敗したため、この新規フォルダ内だけ互換修正し、本文側は手動番号の参考文献形式へ変更。

## Round 2 Global

Status: addressed

Findings:

- 27 chain正式実験の結果が本文の中心に置かれているか確認が必要。
- `gpt-5.5` は現パッケージ内に正式run/scoreがないため、性能表には載せないのが妥当。
- Stage 3の主張は「alert summary rowsのみ除外」に限定すべき。

Actions:

- 全体結果、Stage別結果、scenario別結果を本文へ配置。
- `gpt-5.5` は未採点のため本文結果表から除外。
- Stage 3の限界を結論に明記。

## Round 2 Local

Status: addressed

Findings:

- 二段組で大きすぎる表は崩れる可能性がある。
- コマンドラインや長いpathを本文に大量に入れるとoverfullになりやすい。

Actions:

- 結果表は二段組内に収まる簡略表へ圧縮。
- 長いログpathやコマンドライン例は本文から削り、評価単位の説明に留めた。

## Round 3 Global

Status: passed

Professor-style checks:

- Research positioning: passed. CLOUSEAU, ATLAS, ATLASv2, and this paper's contribution are separated.
- Incident-analysis scope: passed. The paper targets post-alert endpoint behavior reconstruction, not malware detection or attribution.
- Evidence grounding: passed. Metrics include action item recall, critical evidence recall, sequence order, claim precision, and overclaim.
- Result validity: passed with caveat. Only scored models in the package are reported.
- Page target: passed. The manuscript now compiles to 6 pages in FITpaper format.

追加の厳しめ確認:

- CLOUSEAUに依存している研究なのにCLOUSEAUとの差分が薄い問題を再確認した。本文に「CLOUSEAUとの差分」を独立節として追加し，CLOUSEAUは攻撃narrative復元，本文はSOC post-alert behavior chain復元評価であると分けた。
- ATLAS/ATLASv2を使っているのに攻撃検知評価に見える問題を再確認した。本文に，検知分類・attribution・ATT&CK label推定ではなく，証跡付き行動列復元が対象であると明記した。
- `gpt-5.5` の扱いを再確認した。コスト見積りはあるが同一rubricの81 run採点がないため，性能表から除外し，限界として明記した。

## Round 3 Local

Status: passed

Local checks:

- `fit-2025` と同じ `FITpaper` class, `styles/`, `.latexmkrc`, `contents/` 分割形式にした。
- TinyTeXを `~/Library/TinyTeX` に導入し，`platex`, `dvipdfmx`, `latexmk` を利用可能にした。
- 必要パッケージ（Japanese/latexmk/jlreq/docmute/booktabs/sttools/newtx等）を導入した。
- `\ref{...}` targets used in text are present as labels.
- Build command succeeded:
  `PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk main.tex`
- Output PDF: `out/main.pdf`
- Page count: 6 pages
- Page size: A4
- Undefined references/citations: none
- Overfull warnings: none
- Rendered PNG pages were inspected for title page, result tables, conclusion, and references.

Remaining risk:

- Underfull warnings remain for page balancing and long URL/reference line breaks. These do not block PDF generation.
- `styles/FITpaper.cls` was patched only inside `fit-2026-clouseau`; the original `fit-2025` folder was not modified.

## Round 4 Template / Professor Review

Status: addressed

Template structure analysis:

- `fit-2025` follows a standard FIT research-paper structure: introduction, related work, method, dataset, experiment, conclusion.
- The strongest part of the sample is that the experiment chapter is subdivided into purpose, setting, evaluation method, and results before presenting multiple tables.
- The current paper already matched the file/font/class format, but needed a clearer operational analysis layer because the subject is an SOC support system rather than a pure algorithm proposal.

Professor-style findings:

- `gpt-5.5` was underexplained. Ignoring it looked suspicious because raw/salvage data and cost records exist.
- Putting `gpt-5.5` into the same formal comparison table would be methodologically unsafe because it is raw text salvage, replicate_01 only, and not the same 27-chain formal JSON result.
- Cost, token, and runtime analysis was missing, which weakens the operational SOC argument.

Actions:

- Added a dedicated `gpt-5.5と運用コスト` subsection.
- Reported `gpt-5.5 low raw` as an upper-bound/reference result, separate from the formal comparison.
- Initially added a 23-chain supplemental `gpt-5.5` performance table; this was later removed in Round 6 because it mixed incompatible denominators with the formal comparison.
- Added a table for model-level cost, tokens, and average runtime.
- Updated conclusion/validity discussion so `gpt-5.5` is neither hidden nor overclaimed.

Latest build checks:

- Build command succeeded:
  `PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk main.tex`
- Output PDF: `out/main.pdf`
- Page count: 6 pages
- Page size: A4
- Undefined references/citations: none
- Overfull warnings: none
- Rendered PNG pages 4--6 were inspected after adding the new tables.

## Round 5 Main TeX Consolidation

Status: passed

Actions:

- Replaced the split `\input{contents/...}` structure with a single self-contained `main.tex`.
- Inlined title, all sections, bibliography, citation-number mapping, and local macros into `main.tex`.
- Removed `docmute` and `mystyle` dependencies from `main.tex`.
- Left `contents/` as backup/editing source only; it is no longer used by the build.

Checks:

- `main.tex` has no `\input{...}` references.
- `main.tex` has exactly one `\begin{document}` and one `\end{document}`.
- Build command succeeded:
  `PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk main.tex`
- Output PDF: `out/main.pdf`
- Page count: 6 pages
- Undefined references/citations: none
- Overfull warnings: none

## Round 6 Harsh Reviewer Response

Status: textually addressed; several items require new experiments for full resolution

Reviewer-blocking issues addressed in the manuscript:

- Run accounting was made explicit with a new `評価系列と母数` table: formal comparison is 27 chains x 3 stages x 1 replicate = 81 runs/model; cost support is 23 chains x 3 stages x 3 replicates = 207 runs/model; `gpt-5.5` raw support is 23 chains x 3 stages x 1 replicate = 69 runs.
- Formal comparison text now states that 23-chain/3-replicate cost logs and `gpt-5.5` raw salvage are not mixed into the 81-run formal comparison.
- `gpt-4.1-mini` claims were weakened because its legacy output contract required re-scoring. The paper now treats its critical-evidence gap as a comparison of available saved outputs, not as a clean model-capability conclusion.
- Stage 3 claims now state that the denominator is restricted to 65 answerable steps. The text no longer claims that 82.1% is directly comparable to the 75-step Stage 1/2 denominator.
- Metric definitions were operationalized for action item, critical evidence, sequence order, candidate claim precision, and overclaim count.
- The `gpt-5.5` performance table was removed. `gpt-5.5` remains only in the cost/token/time subsection and is positioned as a next-experiment candidate because no formal JSON 81-run score exists.
- Threats to validity now explicitly include missing baselines, single-author gold construction, limited external validity, incomplete API/protocol metadata, and the non-formal status of `gpt-5.5` raw salvage.
- The conclusion narrows the claim to ATLASv2 benign H1 / benign-1 Windows behavior-chain reconstruction and avoids presenting the result as a broad attack-investigation benchmark.

Items that still require user-provided data or new runs:

- Exact API/model metadata: model version/date, temperature, top-p, seed, max output tokens, prompts, and grading rubric procedure.
- A same-contract rerun of `gpt-4.1-mini` if the paper needs a clean model comparison.
- A baseline run such as single-shot LLM over logs or a simple process/time-window search.
- A fixed-denominator Stage 3 comparison: Stage 1/2 recalculated on the same 65 answerable steps, if the gold index exposes that subset.
- Second annotator agreement or a mechanically specified adjudication rule for gold chain construction.

Checks:

- Clean rebuild command succeeded:
  `PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk -C main.tex && PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk main.tex`
- Output PDF: `out/main.pdf`
- Page count: 6 pages
- Page size: A4
- Undefined references/citations: none
- Overfull warnings: none
- Remaining warnings are Underfull page/URL/reference line breaks only.
- Rendered PNG pages 1--6 were inspected after the revision.

## Round 7 GitHub 23-Chain Scope Correction

Status: passed

Action-by-action review:

- GitHub fetch initially failed because local invalid refs named `master 2` and `package-fit2026-experiment-results 2` existed. Removed only those invalid duplicate refs, then fetched `origin/codex/package-fit2026-experiment-results`.
- Imported the new paper-writing materials and current result folder from GitHub: `method_changes_for_paper_20260615.md`, `method_section_points_ja_20260615.md`, updated `experiment_design.md`, and `results_23chain_20260614/`.
- Corrected the formal result scope from old 27-chain / 81-run tables to the current 23-chain component-rubric result set.
- Rewrote the run accounting: formal comparison is now 23 chains x 3 stages x 3 sets = 207 runs/model. `gpt-5.5 low raw` remains 23 chains x 3 stages x 1 raw-output salvage set = 69 runs.
- Added the usecase-selection logic from the 0612 deck: MITRE ATT&CK and LOLBA were used to choose investigation-relevant processes, CBC false-positive alert windows were extracted from ATLASv2, and the final scope was reduced to 23 finalized behavior chains.
- Added a usecase breakdown table: Python SimpleHTTPServer 13, DNS/communication-log batch 5, Sublime Python execution 2, cmd.exe surrounding operation 2, Discord Run key 1.
- Replaced all main result numbers with `results_23chain_20260614`: overall, stage-wise, claim-quality, scenario-wise, cost/runtime context, conclusion, and limitations.
- Removed manuscript-body wording that referred to `FIT` as the evaluation target. `FITpaper` remains only as the LaTeX class/template name.
- Corrected the Stage 3 denominator story: the current 23-chain final result uses matched denominators across stages, so the manuscript no longer relies on the old 65-vs-75 denominator caveat.
- Added the scoring governance point: content-inclusion matching, double review, conflict queue, and conservative/third-review adoption.

Current key numbers in the manuscript:

- `gpt-5.4-mini`: action 79.8% (1400/1755), critical evidence 70.3% (411/585), order 55.3%.
- `gpt-4.1-mini`: action 46.6% (818/1755), critical evidence 19.5% (114/585), order 20.1%.
- Stage 3 for `gpt-5.4-mini`: action 80.2% (469/585), critical evidence 77.9%.
- Candidate precision / overclaim: `gpt-4.1-mini` 36.6% / 1190, `gpt-5.4-mini` 58.4% / 651.

Checks:

- Build command succeeded:
  `PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk -C main.tex && PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk main.tex`
- Output PDF: `out/main.pdf`
- Page count: 6 pages
- Page size: A4
- Undefined references/citations: none
- Overfull warnings: none
- Rendered PNG pages 1--6 were inspected after the revision.
