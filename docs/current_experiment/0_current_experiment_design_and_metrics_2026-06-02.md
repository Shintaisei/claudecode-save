# 現行実験計画と評価指標

作成日: 2026-06-02  
更新日: 2026-06-04

## 1. 研究目的

評価対象は、あるプロセスを起点として「誰が、何を起動し、どのコマンドを実行し、どのファイル・レジストリ・通信先に作用し、どのログ根拠で説明できるか」を `code_steps` と `code_sequence` として復元できるかである。

## 2. なぜ CBC alert 内容を入力にしないか
CBC alert は実務上有用な調査起点である。一方で、CBC alert 行には alert name、reason、process、parent process、command line、target object など、復元対象に近い情報がすでに含まれる場合がある。

その内容をそのまま CLOUSEAU の入力に渡すと、モデルが関連ログを探索して行動列を復元したのか、単にアラート文面を整理したのかを切り分けにくい。

また、実務では必ずしもアラートが発報したプロセスだけを調査するわけではない。アラートが出ていないプロセス、周辺プロセス、異常スコア上位のプロセス、SOC analyst が気になったプロセスを起点に調査することもある。

したがって本実験では、CBC alert の内容を入力情報としては与えない。入力は `host + process + timestamp` に限定する。CBC alert は DB 内に存在する観測証跡としては利用可能だが、モデルが探索の過程で発見した場合にのみ根拠として扱う。

## 3. 正解データ

正解データ:

`data/current_experiment/gold/cbc_alert_behavior_chain_gold/`

現在の正解単位:

| 項目 | 件数 |
|---|---:|
| behavior chains | 27 |
| gold steps | 78 |

主なファイル:

| ファイル | 用途 |
|---|---|
| `all_chain_steps.csv` | 全 gold step の一覧 |
| `all_chain_steps.jsonl` | 全 gold step の JSONL |
| `by_chain/<chain_id>/chain_gold.json` | 各 chain の正解データ |
| `data/current_experiment/gold/discord_reg_runkey/gold_behavior_node.json` | Discord Run key の詳細確認用 gold |

重要なデータ方針:

- `process_code_object` / `process_code_sequence` には、プロセス実行、コマンドライン、ファイル、レジストリ、ネットワーク対象など、コード列として扱える観測値だけを入れる。
- CBC alert の `report_name` / `reason` / `alert_id` は `alert_evidence_basis` または `alert_evidence_only` に分離する。
- CBC alert 文面は code sequence ではない。

## 4. 実験全体

本実験は2条件で構成する。

| 条件 | 入力 | DB内容 | 目的 |
|---|---|---|---|
| Stage 1 | `host + process + timestamp` | 全ログ | process-time 起点から code sequence を復元できるか |
| Stage 2 | `host + process + timestamp` | CBC alert summary 行を除外 | alert summary に頼らず、下位ログからどこまで復元できるか |

どちらの条件でも入力は同じである。違いは DB 内に CBC alert summary 行を残すか、除外するかだけである。

## 5. Stage 1: process-time 起点の code sequence 復元

### 入力

各 chain について、CLOUSEAU には次だけを渡す。

| 入力項目 | 内容 |
|---|---|
| host | 対象ホスト |
| process | 調査起点のプロセス名 |
| timestamp | 調査起点時刻 |

入力に含めないもの:

- CBC alert name
- CBC alert reason
- alert_id
- command_line
- parent process
- child process
- file object
- registry object
- network object
- behavior category
- gold step / gold label

### 出力

最終出力は以下を中心にする。

```json
{
  "input_scope": {
    "host": "",
    "process": "",
    "timestamp": "",
    "condition": "stage1_full_logs",
    "input_fields_used": ["host", "process", "timestamp"]
  },
  "code_steps": [],
  "code_sequence": [],
  "supporting_alert_evidence": [],
  "excluded_nearby_evidence": [],
  "global_limitations": [],
  "timeline_ja": []
}
```

`code_sequence` には、CBC alert name や reason を入れない。実行コマンド、プロセス関係、ファイル/レジストリ/通信対象など、ログから観測された code-level の行動だけを入れる。

## 6. Stage 2: CBC alert summary 除去アブレーション

Stage 2 は、時間窓を広げて全行動を出す実験ではない。時間窓を広げると正解作成が大きくなり、実験の意味も曖昧になるため採用しない。

Stage 2 では入力を Stage 1 と同じ `host + process + timestamp` に固定したまま、DB から CBC alert summary 行だけを除外する。

除外対象:

```sql
source_stream IN ('cbc-edr-alerts', 'cbc-ngav-alerts')
OR access = 'cbc_alert'
```

残すもの:

- CBC EDR/NGAV event telemetry
- Sysmon
- Windows Security
- DNS
- browser history

Stage 2 の問いは次である。

> CBC alert summary がなくても、process-time 起点から下位ログを探索し、同じ code sequence を復元できるか。

この条件により、CLOUSEAU が alert 文面に依存しているのか、実際に関連ログを探索しているのかを見やすくする。

## 7. 評価指標

### Step-level 指標

各 gold step に対して、次の要素を 0/1 で採点する。

| 要素 | 1点の条件 |
|---|---|
| subject | 主体プロセスまたは親子関係の主体が正しい |
| operation | 実行、query、add、write、spawn、connect などの行動種別が正しい |
| object | 対象ファイル、レジストリ、ネットワーク、子プロセスが正しい |
| command_line | 必要な場合に実コマンドラインを正しく保持している |
| evidence | source_stream、timestamp、PID/PPID、event_record_id、alert_id などの根拠が観測値に戻れる |

基本スコア:

```text
step_score = sum(subject, operation, object, command_line, evidence)
```

### Sequence-level 指標

| 指標 | 内容 |
|---|---|
| code sequence recall | gold の code sequence 要素をどれだけ復元したか |
| order correctness | 親 -> 子 -> 対象操作の順序が正しいか |
| boundary precision | 同時刻付近の無関係な行動を同じ sequence に混ぜていないか |
| evidence faithfulness | 最終出力の値が実際の tool result / DB result に存在するか |

特に `evidence faithfulness` を重視する。観測されていない PID、event_record_id、パス、command line を作った場合は強く減点する。

### Stage 1 / Stage 2 比較

| 比較項目 | 見たいこと |
|---|---|
| Stage 1 score | 全ログ条件でどこまで復元できるか |
| Stage 2 score | alert summary なしでどこまで落ちるか |
| delta | alert summary 依存度 |
| failure mode | command line 欠落、object 欠落、親子関係欠落、捏造値、近傍混入 |

## 8. 代表プレ実験: Discord Run key
対象:

```text
host=WIN-32-H1
process=reg.exe
timestamp=2022-07-16 15:07:46
model=gpt-4.1-mini
```

gold code sequence:

1. `C:\Windows\System32\reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord`
2. `C:\Windows\System32\reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /d "C:\Users\aalsahee\AppData\Local\Discord\Update.exe --processStart Discord.exe" /f`

### 修正版 scorer での採点単位

正式実験では、`behavior_element_recall` と `behavior_element_precision` を同じ atomic behavior element 単位で採点する。対象 kind は次の 5 種類だけである。

| atomic kind | 採点対象 |
|---|---|
| `subject` | 行動主体の process / parent process |
| `operation` | spawn, query, add, write value などの行動種別 |
| `object` | 対象 process, registry key/value, value data など |
| `command_line` | その step に属する観測 command line |
| `evidence` | source_stream, timestamp, parent relation, regmod/action, alert_id などの証跡 |

Discord Run key gold の再現率母数は 14 atomic elements で固定する。

| gold step | required atomic elements | count |
|---|---|---:|
| D1: `Discord.exe` が `reg.exe` を子プロセスとして起動 | `subject`, `operation`, `object`, `evidence` | 4 |
| D2: `reg.exe query` が Run key の `Discord` 値を照会 | `subject`, `operation`, `object`, `command_line`, `evidence` | 5 |
| D3: `reg.exe add` が Run key の `Discord` 値を追加/更新 | `subject`, `operation`, `object`, `command_line`, `evidence` | 5 |
| 合計 |  | 14 |

再現率:

```text
behavior_element_recall =
  matched_gold_atomic_elements / total_gold_atomic_elements
```

この例では `total_gold_atomic_elements = 14` である。candidate が各 gold atomic element を復元していれば 1、欠落、曖昧、部分的に誤った値、近傍 chain の値は 0 とする。

適合率:

```text
behavior_element_precision =
  true_positive_candidate_atomic_elements / total_candidate_atomic_elements
```

`total_candidate_atomic_elements` は固定値ではない。candidate が出力した非 null の `subject`, `operation`, `object`, `command_line`, `evidence` を Judge が列挙した数である。したがって、candidate が 3 steps を出し、各 step に 5 種類の非 null atomic elements を持つ場合、候補母数は原則 `3 * 5 = 15` になる。`null`, `unknown`, `not observed` は候補 atomic element として数えない。ただし、観測証跡に存在する値について「存在しない」と断定した場合や、観測証跡に反する否定 claim は false positive として数える。

precision numerator と denominator は `matched_gold_element_id` で true positive の重複を畳む。同じ gold atomic element に複数の candidate atomic elements が対応した場合、最初の 1 個だけを true positive 分子と有効分母に入れ、重複分は raw candidate count として監査用に残すが正式な precision 分母には入れない。これにより precision hits も precision denominator も、同一 gold element の言い換えや重複出力で水増しされない。

近傍行動を混入した場合は、step 単位で 1 個の false positive にしない。その step の `subject`, `operation`, `object`, `command_line`, `evidence` に分解し、gold に対応しない atomic element をそれぞれ false positive とする。同じ gold atomic element に対応する重複 true positive は正式分子・正式分母から畳むが、gold に対応しない extra element は false positive として分母に残す。

`command_line` は独立した行動 step ではない。D2 / D3 それぞれの `command_line` atomic element として採点する。

CBC alert の `report_name` / `reason` は行動要素ではなく `evidence` である。`Discovery - Query Registry` や `Persistence - Regmod Run or Runonce Key Modification` を `operation` として出した場合は、`alert_name_as_behavior` の false positive とする。

プレ実験結果:

| 条件 | run | 結果 |
|---|---|---|
| Stage 1 full logs | `20260604T044757Z_gold_reviewed_10_regexe_20220716t150700z_gpt-4.1-mini_official` | `discord.exe -> reg.exe -> Run key add/query` の大枠は復元。exact command line と value data は不十分。最終JSONで一部捏造値あり。 |
| Stage 2 alert summary removed | `20260604T045254Z_gold_reviewed_10_regexe_20220716t150700z_gpt-4.1-mini_official` | `Discord.exe -> reg.exe` とレジストリ変更の大枠は残るが、Run key や query/add の詳細が落ちる。 |

詳細:

`data/current_experiment/gold/discord_reg_runkey/process_time_preexperiment_2026-06-04.md`

## 9. 現時点の結論

この実験設計は、CBC alert 文面の整理ではなく、関連ログ探索に基づく code sequence 復元能力を評価するための設定として妥当である。

プレ実験では、GPT-4.1-mini は粗い行動チェーンを復元できた。一方で、証跡に忠実な `code_steps` / `code_sequence` にはまだ不足がある。特に、最終合成段階で観測されていない値を作る失敗が残る。

したがって、今後の改善対象は次である。

1. 最終合成プロンプトで、tool result に存在する値以外を書かせない。
2. 観測されない値は `null` または limitation にする。
3. code sequence と alert evidence を明確に分離する。
4. Stage 1 / Stage 2 の差分を、alert summary 依存度として評価する。

## 10. 次の作業

1. Discord Run key 以外の代表ケースで Stage 1 / Stage 2 を各1回ずつ回す。
2. `evidence faithfulness` を自動採点できるように、最終出力中の値を tool result / DB result と照合する。
3. 27 chain 全件に対して Stage 1 full logs を回す。
4. 代表カテゴリごとに Stage 2 alert-summary-ablation を回す。
