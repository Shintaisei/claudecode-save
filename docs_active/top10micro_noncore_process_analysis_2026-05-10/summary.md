# LOF top10 micro-chunk の非 payload / 非 tpautoconnect プロセス分析

更新日: 2026-05-10

## 1. 前提

- 対象は `docs_active\lof_top10micro_review_2026-05-10\top10_micro_raw_events.json`
- 母集団は `LOF top10 micro-chunk = 100 event`
- `payload.exe` と `tpautoconnect.exe` を除いた残りのプロセスだけを見る
- 今回ここで出てくるプロセスが、そのままユースケース候補の母集団になる

## 2. 全体像

- 残ったプロセス種別数: `4`
- 残った event 数: `11`
- 出てきたプロセスは `repmgr.exe`, `explorer.exe`, `winword.exe`, `csrss.exe` の4種だけ
- このうちユースケース対象として自然なのは `repmgr.exe`, `explorer.exe`, `winword.exe`
- `csrss.exe` は system-side noise とみなすのが自然

## 3. プロセス別集計

| process | event数 | 出現micro数 | 出現rank | attack label数 | normal label数 | ユースケース対象 | 見え方 |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| `repmgr.exe` | `5` | `2` | `6, 9` | `0` | `5` | `yes` | `document-access chain candidate` |
| `explorer.exe` | `3` | `1` | `7` | `0` | `3` | `yes` | `file-operation candidate` |
| `csrss.exe` | `2` | `2` | `1, 2` | `0` | `2` | `no` | `system-side noise` |
| `winword.exe` | `1` | `1` | `10` | `0` | `1` | `yes` | `document-viewing candidate` |

## 4. micro rank ごとの出現

| micro rank | micro-chunk | 非coreプロセス | event数 | attack / normal |
| --- | --- | --- | ---: | ---: |
| `1` | `chunk330 micro05` | `csrss.exe:1` | `1` | `1 / 9` |
| `2` | `chunk325 micro02` | `csrss.exe:1` | `1` | `0 / 10` |
| `6` | `chunk204 micro02` | `repmgr.exe:4` | `4` | `0 / 10` |
| `7` | `chunk244 micro08` | `explorer.exe:3` | `3` | `0 / 10` |
| `9` | `chunk203 micro05` | `repmgr.exe:1` | `1` | `0 / 10` |
| `10` | `chunk203 micro07` | `winword.exe:1` | `1` | `0 / 10` |

## 5. 解釈

- `repmgr.exe`
  文書関連アクセスの中心候補。`rank 6, 9` に出ていて、今回もっとも手続型ユースケースに近い。
- `explorer.exe`
  `rank 7` にまとまって出ており、単発のファイル操作ユースケースとして扱いやすい。
- `winword.exe`
  出現は `rank 10` の1 eventだけだが、文書閲覧起点として意味が明確。
- `csrss.exe`
  `rank 1, 2` に少量出るだけで、今回のユースケース対象にはしない方が自然。

## 6. 今回のユースケース対象

| 優先度 | process | 主な型 | 根拠 |
| --- | --- | --- | --- |
| `高` | `repmgr.exe` | 手続型 | `rank 6, 9` に計5 event 出現し、文書アクセス連鎖として読める |
| `高` | `explorer.exe` | 単発操作型 | `rank 7` に計3 event 出現し、ファイル操作として説明しやすい |
| `中` | `winword.exe` | 単発操作型 | `rank 10` に1 event だが、文書閲覧の意味が明確 |
| `低` | `csrss.exe` | 対象外 | system-side noise であり、関連ログ調達の起点にしにくい |

## 7. まとめ

- 今回の `100 event` で、ユースケース対象として本当に見るべきプロセスは実質 `3種`
- `repmgr.exe` と `explorer.exe` が主対象、`winword.exe` が補助対象
- 研究上は、この `3種` を起点候補として自動化可否を評価するのがちょうどよい