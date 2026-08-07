# usecase_sysmon100 再実行結果（attack_near 含む）

作成日: 2026-05-19

## 1. 何を変えたか

従来の `select_sysmon_usecase_candidates.py` は `attack_near` minute を**スキップ**していた。

```python
# 変更前（旧ロジック）
for minute in candidate_minutes:
    if minute["classification"] == "attack_near":
        continue   # ← 攻撃プロセスを含む minute を完全除外

# 変更後（新ロジック）
priority = {"core_normal": 0, "attack_near": 1, "neutral_context": 2, "background_context": 3}
# attack_near を除外せず、core_normal の次に優先して選ぶ
```

変更点は2箇所：
1. `select_to_max_events` の `attack_near` スキップを削除
2. priority 順を `attack_near` が2番目になるよう変更

出力先：`analysis_data/model_runs/usecase_sysmon100_incl_attack_*/`

---

## 2. なぜこの変更をしたか

**旧ロジックのFPストーリーの弱さ：**

```
旧：検知器が反応したセッション → attack minute を除外 → 残った正常 minute を収集
    → 「なぜ偽陽性になったか」が説明できない（攻撃の文脈を先に取り除いているため）

新：検知器が反応したセッション → attack minute を優先的に含める → 同じ minute の中に
    attack プロセスと normal プロセスが混在
    → 「攻撃と一緒に正常行動も検知された」＝ 真の偽陽性として説明できる
```

これは LOF micro-chunk ルート（ルートA）と同じ構造であり、FP の因果が一貫する。

---

## 3. 選定結果

### 選定された attack_near minute とその中身

| scenario | minute | attack プロセス | normal プロセス（同 minute） | events |
| --- | --- | --- | --- | ---: |
| `m4` | `aalsahee\|20220719T2253Z` | `payload.exe` | `cmd.exe`, `conhost.exe` | `8` |
| `m6` | `aalsahee\|20220720T0009Z` | `eqnedt32.exe`, `regsvr32.exe` | `winword.exe`, `dllhost.exe`, `werfault.exe` | `11` |
| `s4` | `aalsahee\|20220720T0053Z` | `powershell.exe`, `mshta.exe` | `winword.exe`, `dllhost.exe`, `conhost.exe` | `16` |
| `s4` | `aalsahee\|20220720T0054Z` | `payload.exe` | `repux.exe`, `cmd.exe`, `conhost.exe` | `8` |
| `s3` | `aalsahee\|20220719T1437Z` | `payload.exe`, `powershell.exe` | `cmd.exe`, `conhost.exe` | `10` |

### 各シナリオの 100 ログ内訳

| scenario | selected minutes | 内訳 | attack_near 内の normal 候補 |
| --- | ---: | --- | --- |
| `m4` | `9` | core_normal×3, attack_near×1, neutral×2, background×3 | `cmd.exe`, `conhost.exe` |
| `m6` | `6` | core_normal×1, attack_near×1, neutral×3, background×1 | `winword.exe`, `dllhost.exe` |
| `s4` | `6` | core_normal×1, attack_near×2, neutral×2, background×1 | `winword.exe`, `repux.exe`, `cmd.exe` |
| `s3` | `7` | core_normal×0, attack_near×1, neutral×6, background×0 | `cmd.exe`, `conhost.exe` |

---

## 4. 旧バージョンとの比較

| 観点 | 旧（attack 除外） | 新（attack 含む） |
| --- | --- | --- |
| attack_near minute の扱い | スキップ | core_normal の次に優先選択 |
| FP ストーリー | 弱い（攻撃文脈が切れている） | **強い（攻撃と正常が同一 minute で共存）** |
| m4 attack_near | 未選択 | `payload.exe` と同一 minute の `cmd/conhost` を含む |
| m6 attack_near | 未選択 | `eqnedt32+regsvr32` と同一 minute の `winword.exe` を含む |
| s4 attack_near | 未選択 | `powershell+mshta` と同一 minute の `winword.exe` を含む |
| s3 attack_near | 未選択 | `payload+powershell` と同一 minute の `cmd/conhost` を含む |

---

## 5. 各シナリオの読み

### M4

- `core_normal` の mmc/excel/winword に加えて、`payload.exe` と同一 minute の `cmd.exe`, `conhost.exe` が入った
- **FP の読み:** payload 実行時にシェル操作（cmd/conhost）が一緒に検知された
- これは「攻撃のシェル呼び出しに紛れた正常のコンソール処理」として説明できる

### M6

- `eqnedt32.exe`（数式エディタ脆弱性悪用）+ `regsvr32.exe` と同一 minute に `winword.exe` がいた
- **FP の読み:** 攻撃が Word の数式エディタ経由で起動する際、Word 本体の正常終了処理も一緒に検知された
- これは最も説明力が高い FP 例：「Word を使った攻撃」の文脈で「Word の正常動作」が偽陽性になる

### S4

- `powershell.exe + mshta.exe` の minute に `winword.exe` が混在
- さらに `payload.exe` の minute に `repux.exe`（環境固有サービス）が混在
- **FP の読み:** 攻撃スクリプトが動いていた時間帯に、Word 閲覧やサービス処理も並行して動いていた

### S3

- `core_normal = 0` のまま変わらず
- ただし `payload.exe + powershell.exe` の minute に `cmd.exe`, `conhost.exe` が混在するようになった
- **FP の読み:** 攻撃が起動したシェルの中で、正常なコマンド処理も並行して発生した

---

## 6. 採用判断の見直し

旧バージョンの「S3 は見送り」という判断は変わらない。
FP 候補として説明力が高い順に並べると：

| 順位 | scenario | FP の説明のしやすさ | 理由 |
| --- | --- | --- | --- |
| 1 | **M6** | ★★★ | Word 攻撃 → Word 正常動作が FP になる構造が明確 |
| 2 | **S4** | ★★☆ | 攻撃スクリプトと正常サービスの並行動作が見える |
| 3 | **M4** | ★★☆ | payload とシェル処理の混在。業務操作 (excel/mmc) も保持 |
| 4 | **S3** | ★☆☆ | attack 近傍の cmd/conhost のみ。業務主体が依然なし |

---

## 7. 次にやるべきこと

1. M6 の `winword.exe` が同一 minute 内でどのイベントを出しているか詳細確認
   - `selected_events.csv` の `eqnedt32.exe` 前後の `winword.exe` イベントを読む
2. S4 の `winword.exe + powershell/mshta` の並行を可視化
3. 発表では M6 を **「Word 攻撃による偽陽性の最も説明しやすい例」** として前面に出す

## 8. 参照

- スクリプト: `scripts/select_sysmon_usecase_candidates.py`（attack_near 含むよう修正済み）
- 旧結果: `analysis_data/model_runs/usecase_sysmon100_*/`（attack 除外版、保持）
- 新結果: `analysis_data/model_runs/usecase_sysmon100_incl_attack_*/`
