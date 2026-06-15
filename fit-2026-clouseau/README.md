fit-2026-clouseau

FITpaper形式で作成したCLOUSEAU / ATLASv2行動列復元評価の原稿フォルダです。

## 構成

- `main.tex`: FITpaperクラスを使うメインファイル
- `contents/`: タイトル、本文各章、参考文献の分割版バックアップ
- `styles/`: `fit-2025` と同じ `FITpaper` 用スタイル
- `.latexmkrc`: `fit-2025` と同じ platex + dvipdfmx 設定

現在の `main.tex` は、タイトル、本文、参考文献をすべて含む単体ファイルです。
`contents/` は編集履歴・分割版として残していますが、コンパイル時には参照しません。

## ビルド

この環境では TinyTeX を `~/Library/TinyTeX` に導入済みです。
このフォルダで以下を実行します。

```sh
PATH=/Users/komatsuzakiharutoshi/Library/TinyTeX/bin/universal-darwin:$PATH latexmk main.tex
```

生成物:

- `out/main.pdf`: 最終PDF
- `out/main.dvi`: DVI
- `out/main.log`: ビルドログ

確認結果:

- PDF生成: 成功
- ページ数: 6ページ
- 用紙: A4
- 未定義参照: なし
- Overfull warning: なし
- PNGレンダリング目視確認: 済み
- 残警告: URL/参考文献とページ末由来の Underfull のみ

## 2026-06-15 追記

`fit-2025` の構成を再分析し、実験章の説得力を高めるために以下を追加しました。

- `gpt-5.5 low raw` の補助分析
- コスト、token、平均実行時間の比較表
- `gpt-5.5` を正式比較に混ぜない理由
- 教授レビュー観点の追記

## 2026-06-15 追記 2

提出・移植しやすいように、`contents/*.tex` への `\input` をやめ、本文を `main.tex` へ集約しました。
`main.tex` 単体と `styles/FITpaper.cls` があれば現在の原稿をコンパイルできます。

## 2026-06-15 追記 3

厳しめ査読コメントへの対応として、run/chain/stage/replicateの母数表を追加し、`gpt-4.1-mini` のlegacy再採点、Stage 3の65 answerable step限定、`gpt-5.5` raw salvageの非正式扱いを本文で明記しました。
`gpt-5.5` の性能表は正式比較と混同されるため削除し、コスト・token・時間と次実験候補としてのみ残しています。

## 2026-06-15 追記 4

GitHubに追加された `results_23chain_20260614/` と手法メモを取り込み、本文の正式結果を23 usecase基準へ差し替えました。
現在の正式比較は、23 chain x 3 stage x 3 set = 207 run/modelです。
古い27-chain/81-run結果は本文の主結果から外し、第3 setが旧27-chain実行から現在の23 chainを抽出したものであることだけ注記しています。
ユースケース選定についても、MITRE ATT&CK/LOLBAを参考にプロセスを選び、ATLASv2内のCBC偽陽性アラート時刻窓から23 chainを作った流れを追記しました。
