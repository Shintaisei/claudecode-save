fit-2026-clouseau

FITpaper形式で作成したCLOUSEAU / ATLASv2行動列復元評価の原稿フォルダです。

## 構成

- `main.tex`: FITpaperクラスを使うメインファイル
- `contents/`: タイトル、本文各章、参考文献
- `styles/`: `fit-2025` と同じ `FITpaper` 用スタイル
- `.latexmkrc`: `fit-2025` と同じ platex + dvipdfmx 設定

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
