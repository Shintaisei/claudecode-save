# GitHub候補調査 ATLAS v2

作成日: 2026-05-03

## 1. 目的

ATLAS v2 を対象に、シーケンスベースの異常検知モデルを GitHub から導入する。
この文書では、候補の比較、選定理由、導入先、適用方針をまとめる。

## 2. 評価基準

今回の候補評価では、次を重視した。

- GitHub 上での利用実績が比較的あること
- シーケンス入力を直接扱えること
- ログ異常検知に特化していること
- ATLAS v2 の Windows Event Log XML 由来 JSONL に変換しやすいこと
- 学習コードと前処理コードがあること
- 単一モデルではなく、比較しやすい構成を持つこと

## 3. 候補一覧

### 3.1 `logpai/loglizer`

- URL: <https://github.com/logpai/loglizer>
- Stars: 1.4k
- 位置づけ: 最も star が多い古典的なログ異常検知ツールキット
- 長所:
  - 利用実績が大きい
  - ログ異常検知の代表的な基準点として使いやすい
- 弱み:
  - 深層シーケンスモデルの主戦場というより、比較基盤色が強い
  - 今回やりたい「系列全体を見る」流れでは、第一候補としては少し古い

### 3.2 `d0ng1ee/logdeep`

- URL: <https://github.com/d0ng1ee/logdeep>
- Stars: 457
- 位置づけ: DeepLog 系の実装を含むログ深層学習ツールキット
- 長所:
  - star 数が比較的高い
  - 複数特徴を扱える
  - ログ異常検知に特化している
- 弱み:
  - README にある通り log parsing を含まない
  - 今回はこちらで ATLAS v2 用の前処理を厚めに持つ必要がある

### 3.3 `HelenGuohx/logbert`

- URL: <https://github.com/HelenGuohx/logbert>
- Stars: 345
- 位置づけ: BERT 系のログ異常検知
- 長所:
  - Transformer/BERT 系で、今回のシーケンス志向と相性が良い
  - HDFS / BGL / Thunderbird 向けの実験手順が見える
- 弱み:
  - 実験対象データに寄った構成が強い
  - そのまま ATLAS v2 を流し込むには調整箇所が多い

### 3.4 `Thijsvanede/DeepLog`

- URL: <https://github.com/Thijsvanede/DeepLog>
- Stars: 279
- 位置づけ: DeepCASE 論文系統で利用された DeepLog 実装
- 長所:
  - セキュリティイベント系列との距離が近い
  - DeepCASE 文脈に接続しやすい
- 弱み:
  - 単独実装寄りで、比較実験基盤としては広さがやや足りない

### 3.5 `logpai/deep-loglizer`

- URL: <https://github.com/logpai/deep-loglizer>
- Stars: 263
- 位置づけ: deep learning ベースのログ異常検知ツールキット
- 長所:
  - LSTM, LogAnomaly, Transformer, Autoencoder, CNN など複数モデルを一つの枠で試せる
  - `session_train.pkl` / `session_test.pkl` という入力形式が明確
  - `sequentials` と `semantics` の両方を扱える
  - HDFS/BGL 向け前処理コードがあり、ATLAS v2 用に真似しやすい
- 弱み:
  - stars は最大ではない
  - 依存関係が古い
  - Python 3.11 ではそのまま動かない可能性が高い

### 3.6 `LogIntelligence/LogADEmpirical`

- URL: <https://github.com/LogIntelligence/LogADEmpirical>
- 位置づけ: 複数深層モデルの比較実験基盤
- 長所:
  - 比較研究として有用
  - `main_run.py` と dataset 構成があり、実験管理に向く
- 弱み:
  - star 数の観点では最優先ではない
  - まず一本目としては `deep-loglizer` の方が ATLAS v2 への接続が単純

## 4. 今回の選定

最初に導入するリポジトリは **`logpai/deep-loglizer`** とする。

選定理由:

- star 数が十分あり、完全な個人実装ではない
- 1本で複数モデルを比較できる
- ATLAS v2 の JSONL を、`templates` と `label` を持つ session 辞書へ変換すれば流し込める
- まず ATLAS v2 で「系列として食わせる」足場を作るのに向いている

## 5. ATLAS v2 への適用方針

### 5.1 入力データ

ATLAS v2 のうち、まず対象にするのは次の系統。

- `msft-security`
- 必要に応じて `sysmon`

現状の手元資産では、少なくとも Hayabusa 向けに変換した JSONL が一部ある。

### 5.2 変換方針

`deep-loglizer` は内部で、各 session に対して次の形を要求する。

```python
{
  "session_id": {
    "templates": [...],
    "label": 0 or 1 or [0, 1, ...]
  }
}
```

そのため、ATLAS v2 からは次をこちらで作る。

- `templates`: 各イベントを系列モデル向けの簡約テンプレート文字列へ変換
- `label`: ground truth に含まれる EventRecordID を 1、それ以外を 0 とする
- `session_train.pkl`
- `session_test.pkl`
- `data_desc.json`

### 5.3 session の切り方

ATLAS v2 は HDFS のような自然な session ID を持たないため、最初は近似的に切る。

第一候補:

- `Computer + User + 時間バケット`

補助候補:

- `Computer + Process + 時間バケット`
- `all` として1本の長い系列

まずは粗い切り方で載せ、あとで異常検知性能や解釈しやすさを見ながら調整する。

### 5.4 テンプレート化

ATLAS v2 の各イベントは高次元の生ログを持つため、そのままでは template の種類が爆発しやすい。
そのため、最初は次のような低次元化した文字列テンプレートを作る。

- `EventID`
- `Channel`
- `Provider`
- `ProcessName` または `Image` の basename
- 必要に応じて `ObjectType` や `DestPort` などの一部フィールド

狙い:

- まず系列構造を学習させる
- ランダムなパスや一意値に引きずられすぎないようにする

### 5.5 ラベル付け

attack day に対しては、ground truth の EventRecordID 一覧があればイベント単位ラベルを付けられる。

方針:

- train: 基本は正常中心
- test: 正常と異常の混在
- 異常 session の中に正常成分がどれくらい含まれるかを後で観察する

## 6. 実装状況

このリポジトリには、以下を追加する。

- `external/deep-loglizer/`
  - GitHub から clone した元実装
- `scripts/prepare_atlasv2_for_deeploglizer.py`
  - ATLAS v2 JSONL を deep-loglizer 互換 session 形式へ変換する

実施済み:

- `logpai/deep-loglizer` を `external/deep-loglizer/` に clone 済み
- 仮想環境 `.venv-atlas-seq/` を作成済み
- `analysis_data/atlasv2_benign_runs/jsonl/msft-security-h1-benign-1.jsonl` から
  `analysis_data/atlasv2_for_deep-loglizer/benign1_cu30/` を生成済み

生成物:

- `analysis_data/atlasv2_for_deep-loglizer/benign1_cu30/data_desc.json`
- `analysis_data/atlasv2_for_deep-loglizer/benign1_cu30/session_train.pkl`
- `analysis_data/atlasv2_for_deep-loglizer/benign1_cu30/session_test.pkl`

この変換では次の条件を使った。

- input: `msft-security-h1-benign-1.jsonl`
- session mode: `computer_user`
- time bucket: 30分
- train ratio: 0.8
- 確認用に先頭 20,000 events を使用

結果:

- events: 20,000
- sessions total: 4
- train sessions: 3
- test sessions: 1
- anomalies: 0

## 7. 注意点

`deep-loglizer` の依存関係は古い。

- `torch==1.4.0`
- `numpy==1.19.5`
- `pandas==1.1.5`
- `scikit-learn==0.24.2`

現在のローカル Python は 3.11 系なので、そのままでは環境衝突の可能性が高い。
したがって、まずはデータ変換を先に固定し、その後に実行環境を分離する。

実際の状況:

- `numpy`, `pandas`, `scikit-learn`, `tqdm` の導入は完了
- `torch` は通常版・CPU版の両方を試したが、このマシンでは
  `c10.dll` 読み込み時の `WinError 1114` で停止した
- そのため、**ATLAS v2 を deep-loglizer 互換データへ変換するところまでは完了**
- **モデル本体の学習実行だけがローカル DLL 問題で未完了**

この問題は、研究上の前処理設計の破綻ではなく、ローカル実行環境依存の停止である。

## 8. 次の実行順

1. `deep-loglizer` を clone 済みの基盤として保持する
2. ATLAS v2 JSONL から deep-loglizer 用 session データを生成する
3. 生成データを benign / attack で分けられるようにする
4. 実行用 Python 環境を分離する
5. まず LSTM または Transformer を 1 本回す
6. 異常 session 内の正常イベント比率を見る調査へ進む

## 9. 再実行コマンド

### 9.1 ATLAS v2 JSONL から deep-loglizer 用 session を生成

```powershell
python scripts\prepare_atlasv2_for_deeploglizer.py `
  --jsonl analysis_data\atlasv2_benign_runs\jsonl\msft-security-h1-benign-1.jsonl `
  --output-dir analysis_data\atlasv2_for_deep-loglizer\benign1_cu30 `
  --session-mode computer_user `
  --time-window-minutes 30 `
  --train-ratio 0.8 `
  --max-events 20000
```

### 9.2 attack scenario へ適用する時の形

```powershell
python scripts\prepare_atlasv2_for_deeploglizer.py `
  --jsonl <ATLASv2_attack_jsonl> `
  --groundtruth <groundtruth_record_ids.txt> `
  --output-dir <output_dir> `
  --session-mode computer_user `
  --time-window-minutes 30 `
  --train-ratio 0.8
```

### 9.3 deep-loglizer の LSTM 実行例

`torch` 問題が解消した後は、次のように実行できる想定。

```powershell
cd external\deep-loglizer\demo
& ..\..\..\.venv-atlas-seq\Scripts\python.exe lstm_demo.py `
  --data_dir ..\..\analysis_data\atlasv2_for_deep-loglizer\benign1_cu30 `
  --dataset ATLASv2 `
  --feature_type sequentials `
  --label_type next_log `
  --window_size 10 `
  --stride 1 `
  --epoches 1 `
  --batch_size 256 `
  --learning_rate 0.001 `
  --topk 5
```

## 10. 今の到達点

今回の作業で、次までは完了した。

1. GitHub 候補の比較
2. 第一候補の選定
3. リポジトリの取得
4. ATLAS v2 用前処理の作成
5. deep-loglizer 互換データの生成
6. Python 実行環境の分離

未完了なのは次のみ。

1. `torch` の DLL 問題を解消してモデルを実行すること

したがって、現時点の研究作業としては
**「ATLAS v2 を deep-loglizer に載せる入口」は作成済み**
であり、残タスクは主にローカル実行環境の安定化である。

## 11. benign train / attack test パッケージ

同一シナリオ内で train/test をそのまま切ると、異常 session が train 側に寄りやすい。
そのため、研究用途では次の構成を優先する。

- train: benign day
- test: attack scenario

このためのパッケージング用スクリプトも追加した。

- `scripts/package_atlasv2_deeploglizer_dataset.py`

生成済みデータセット:

- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_s3`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_s4`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_m4`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_m5`
- `analysis_data/atlasv2_for_deep-loglizer/exp_benign1_vs_m6`

この構成では、train 側は benign のみ、test 側は attack scenario 側 session を使う。

## 12. 異常シーケンス中の正常成分

ATLAS v2 の attack session について、
「異常 session の中に正常イベントがどれくらい含まれるか」を集計した。

結果ファイル:

- `analysis_data/atlasv2_for_deep-loglizer/attack_session_normality_summary.json`

要点:

- `S3`: 異常 session 内の正常イベント比率は約 `99.829%`
- `S4`: 異常 session 内の正常イベント比率は約 `99.766%`
- `M4`: 異常 session 内の正常イベント比率は約 `99.826%`
- `M5`: 異常 session 内の正常イベント比率は約 `99.854%`
- `M6`: 異常 session 内の正常イベント比率は約 `99.812%`

解釈:

- 異常シーケンスは「異常イベントだけの列」ではない
- 実際には、ほぼすべてが正常イベントで、その中に少量の異常イベントが埋まっている
- したがって、今回の研究課題は単発異常検出よりも
  **正常文脈に埋もれた異常の検出**
  として捉える方が適切

これは、今回の「異常シーケンスの中に正常がどれくらい含まれるかを調べる」という主方針に対して、
かなり直接的な初期根拠になっている。
