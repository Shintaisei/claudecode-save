# LMD Collections 調査メモ

作成日: 2026-04-17

## 取得状況

取得元:

- GitHub: https://github.com/ChristosSmiliotopoulos/Lateral-Movement-Dataset--LMD_Collections
- Google Drive: https://drive.google.com/drive/folders/1PkJiGpD0Kn1rV8GC9m2b_eWvqQTSa1eH

保存先:

- `LMD_Collections/`

取得済みファイル:

- `LMD_Collections/LMD-2022/LMD-2022.rar` 約 7.5 MB
- `LMD_Collections/LMD-2023/LMD-2023.rar` 約 345 MB

展開済みCSV:

- LMD-2022: 5 CSV
- LMD-2023: 18 CSV
- 合計: 23 CSV

## データ概要

LMDはWindows Sysmonログ由来のラテラルムーブメント検知用データセット。GitHub READMEでは、LMD-2022は9種類の攻撃、LMD-2023は追加攻撃を含む拡張版として説明されている。

主なラベル:

- `0`: Normal
- `1`: EoRS, Exploitation of Remote Services
- `2`: EoHT, Exploitation of Hashing Techniques / credential exploitation

主な形式:

- 生CSV
- ラベル付きCSV
- Normal/EoRS/EoHT別サブセット
- LMD-2023には前処理済みCSVも含まれる

## 実ファイル集計

代表ファイル:

| ファイル | 行数 | 列数 | ラベル分布 |
|---|---:|---:|---|
| `LMD-2022 [870K Elements][Labelled].csv` | 867,672 | 94 | 0: 853,730 / 1: 565 / 2: 13,377 |
| `LMD-2023 [1.75M Elements][Labelled]checked.csv` | 1,752,836 | 94 | 0: 1,611,619 / 1: 110,710 / 2: 30,507 |
| `LMD-2023 [1.87M Elements][Labelled]checked.csv` | 1,901,979 | 95 | 0: 1,611,619 / 1: 234,813 / 2: 55,547 |
| `LMD-2023 [2.3M Elements][Labelled]checked.csv` | 2,144,008 | 94 | 0: 1,632,903 / 1: 375,239 / 2: 135,866 |
| `LMD-2023 [2.3M Elements][Labelled+Preprocessed]checked.csv` | 2,106,200 | 87 | 0: 1,611,637 / 1: 363,459 / 2: 131,104 |

LMD-2023のファイル名は「2.3M」となっているが、確認できたラベル付きCSVの実行数は約214万行だった。前処理済みCSVは欠損・整形処理のためか、ラベル付きCSVより少ない。

## 研究利用の評価

使えそうな研究テーマ:

- Sysmonログによるラテラルムーブメント検知
- Normal / EoRS / EoHT の3クラス分類
- 正常多数・攻撃少数の不均衡データに対する評価
- 前処理済み特徴量を使った浅い機械学習、DNN、異常検知の比較
- EventIDやプロセス・ネットワーク系特徴の寄与分析

良い点:

- ラテラルムーブメントに特化している。
- ラベル付きCSVがあり、すぐ教師あり学習に使える。
- LMD-2023には前処理済み版があり、初期実験の立ち上げが速い。
- Normal/EoRS/EoHTのサブセットがあるため、二値分類・三値分類・攻撃カテゴリ別評価に分けやすい。
- README上で査読済み論文と対応しており、引用しやすい。

注意点:

- 明示的なLICENSEファイルは確認できない。公開研究で使う場合は引用だけで足りるか、配布・再公開条件を確認する必要がある。
- ラベルが強く不均衡。Accuracyだけでは評価が歪むため、macro F1、balanced accuracy、PR-AUC、クラス別recallを使うべき。
- LMD-2022のフルラベル付きCSVでは `Label=1` が565件のみで極端に少ない。
- 一部列に `Unnamed` や空列がある。前処理前に列整理が必要。
- 同一テストベッド・同一生成手順のログなので、現実環境への外的妥当性は別データで補強した方がよい。
- 時系列分割をしないランダム分割だと、近いイベントがtrain/testに跨り、性能が高く見える可能性がある。

## 結論

LMD Collectionsは、ラテラルムーブメント検知の研究には十分使える。特に「Sysmonログからの教師あり分類」「不均衡データでのLM検知」「EoRS/EoHTの攻撃カテゴリ分類」には相性がよい。

ただし、研究として説得力を出すなら、以下の設計にするのが安全。

- まずLMD-2023の前処理済み2.3M版でベースラインを作る。
- 評価指標はmacro F1、クラス別recall、PR-AUCを中心にする。
- ランダム分割だけでなく、時間順分割または攻撃シナリオ単位分割を試す。
- 論文ではライセンス未明記とデータセット依存の限界を明記する。
- 再配布せず、取得元URLと引用情報を記載する。

