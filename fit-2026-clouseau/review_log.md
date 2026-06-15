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
