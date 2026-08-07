# 実装方針: Security + Sysmon / benign1to4 学習

日付: 2026-05-19

## 1. まず前提を修正する

- 現在の `Security` 実験は `正常4日学習 -> 5日目判別` ではない
- 実際には `benign-1` を学習側、`S3 / S4 / M4 / M6` などの attack scenario を判別側にしている
- したがって、次にやるべきことは `Security + Sysmon` を足すことに加えて、学習データを `benign-1to4` へ切り替えること

## 2. 今あるもの

### Security 側

- `msft-security-h1-benign-1.jsonl`
- `msft-security-h1-benign-1to4.jsonl`
- `msft-security-h1-benign-2to4.jsonl`
- 既存の first pass / second pass / third pass スクリプト

### Sysmon 側

- `scripts/experiment_security_sysmon_fusion_s3.py`
  - `S3` 向けの `Security + Sysmon` minute fusion 実装
- `scripts/build_security_sysmon_review_queue.py`
  - `Security second pass` と `Sysmon minute` を束ねる review queue 実装

## 3. 今回の実装ゴール

- 学習側を `benign-1to4` に統一する
- 判別側は `S3 / M4 / M6 / S4`
- `Security only` ではなく `Security + Sysmon` で比較する
- 少なくとも `top candidate` 段階で、
  - attack がどれだけ前に来るか
  - 正常候補がどのように変わるか
を見られる状態にする

## 4. 実装を 3 段階で進める

### Step 1. benign1to4 ベースの Security 学習データを作る

- `prepare_atlasv2_for_deeploglizer.py` を使って、`msft-security-h1-benign-1to4.jsonl` から `cu10` データを作る
- 既存の `benign1_cu10_200k` と同じ形式で、`benign1to4_cu10_*` 系の学習データを出す
- そのうえで `exp_benign1to4_vs_s3_cu10`, `...vs_m4_cu10`, `...vs_m6_cu10`, `...vs_s4_cu10` を作る

### Step 2. Sysmon 側も benign1to4 にそろえる

- 既存の `experiment_security_sysmon_fusion_s3.py` は `sysmon-h1-benign-1.xml` 前提
- これを scenario 固定から外し、
  - `sysmon benign source`
  - `sysmon attack source`
  - `scenario name`
を引数化する
- 可能なら `sysmon-h1-benign-1to4.xml` 相当を作る
- もし単一 XML がない場合は、`benign-1.xml` から `benign-4.xml` を複数入力で受けて内部で連結する形にする

### Step 3. Security + Sysmon の review queue を各 scenario へ横展開する

- `S3` 専用で使っている review queue を `M4 / M6 / S4` にも流す
- 出力は scenario ごとに
  - first pass の predicted sequence
  - second pass の `100 event` review windows
  - sysmon minute の近傍候補
を持つようにする
- その後に `top10 micro = 100ログ` と同じ粒度まで落として、`attack / normal` の比較をやる

## 5. 実装上の変更点

### 変更 1. `Security` データ準備の切り替え

- 既存: `benign-1`
- 変更後: `benign-1to4`

### 変更 2. `Security + Sysmon` 実験スクリプトの一般化

- 既存: `S3` 固定の命名と入力
- 変更後:
  - scenario 非依存
  - `benign-1to4` 学習対応
  - `S3 / M4 / M6 / S4` 共通実行

### 変更 3. review queue 出力の統一

- `Security only` の比較と `Security + Sysmon` の比較を混ぜない
- `docs_active` では `same_method / benign1to4 / security+sysmon` を明示する

## 6. 期待する確認ポイント

- `S3` では、既存の `Security only` より attack が前に出るか
- `M4 / M6 / S4` では、`normal-only` の反復ノイズだけで埋まる状態が改善するか
- `Sysmon` を足すことで、`tshark.exe` や `tpautoconnect.exe` の単純反復よりも
  - `Image`
  - `ParentImage`
  - `User`
  - `EventID 1 / 5`
の組み合わせが効くか

## 7. いったんの判断

- この方針で進める価値はある
- ただし本質は `Sysmon を足す` だけではなく、`学習側を benign-1 から benign-1to4 へ変える` こと
- 先に `S3` で 1 本通してから `M4 / M6 / S4` に広げるのが安全

## 8. 次に着手する順番

1. `benign-1to4` の Security 学習データを作る
2. `experiment_security_sysmon_fusion_s3.py` を scenario 共通化する
3. `S3` で `Security + Sysmon / benign1to4` をまず 1 回通す
4. 問題なければ `M4 / M6 / S4` へ展開する
