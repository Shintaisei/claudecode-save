# LOF top10 micro-chunk の非 payload / 非 tpautoconnect プロセス分析

更新日: 2026-05-10

## 1. 前提

- 対象は `docs_active\lof_browser_ranks42_47_review_2026-05-10\top10_micro_raw_events.json`
- 母集団は `LOF top10 micro-chunk = 100 event`
- `payload.exe` と `tpautoconnect.exe` を除いた残りのプロセスだけを見る
- 今回ここで出てくるプロセスが、そのままユースケース候補の母集団になる

## 2. 全体像

- 残ったプロセス種別数: `4`
- 残った event 数: `63`
- 出てきたプロセスは `repmgr.exe`, `explorer.exe`, `winword.exe`, `csrss.exe` の4種だけ
- このうちユースケース対象として自然なのは `repmgr.exe`, `explorer.exe`, `winword.exe`
- `csrss.exe` は system-side noise とみなすのが自然

## 3. プロセス別集計

| process | event数 | 出現micro数 | 出現rank | attack label数 | normal label数 | ユースケース対象 | 見え方 |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| `vmtoolsd.exe` | `40` | `10` | `50, 51, 52, 53, 54, 55, 56, 57, 58, 59` | `0` | `40` | `maybe` | `needs manual interpretation` |
| `firefox.exe` | `11` | `4` | `52, 53, 54, 60` | `0` | `11` | `yes` | `browser candidate` |
| `explorer.exe` | `9` | `2` | `51, 58` | `0` | `9` | `yes` | `file-operation candidate` |
| `taskhost.exe` | `3` | `1` | `58` | `0` | `3` | `maybe` | `needs manual interpretation` |

## 4. micro rank ごとの出現

| micro rank | micro-chunk | 非coreプロセス | event数 | attack / normal |
| --- | --- | --- | ---: | ---: |
| `50` | `chunk231 micro08` | `vmtoolsd.exe:3` | `3` | `0 / 10` |
| `51` | `chunk761 micro08` | `vmtoolsd.exe:6, explorer.exe:4` | `10` | `0 / 10` |
| `52` | `chunk231 micro09` | `vmtoolsd.exe:4, firefox.exe:2` | `6` | `0 / 10` |
| `53` | `chunk234 micro01` | `vmtoolsd.exe:7, firefox.exe:3` | `10` | `0 / 10` |
| `54` | `chunk742 micro09` | `vmtoolsd.exe:4, firefox.exe:2` | `6` | `0 / 10` |
| `55` | `chunk761 micro07` | `vmtoolsd.exe:5` | `5` | `0 / 10` |
| `56` | `chunk761 micro09` | `vmtoolsd.exe:4` | `4` | `0 / 4` |
| `57` | `chunk050 micro07` | `vmtoolsd.exe:3` | `3` | `0 / 10` |
| `58` | `chunk234 micro00` | `explorer.exe:5, taskhost.exe:3, vmtoolsd.exe:2` | `10` | `0 / 10` |
| `59` | `chunk050 micro00` | `vmtoolsd.exe:2` | `2` | `0 / 10` |
| `60` | `chunk005 micro02` | `firefox.exe:4` | `4` | `0 / 10` |

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