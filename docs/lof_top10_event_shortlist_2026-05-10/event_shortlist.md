# LOF top10 chunk からさらに絞った event shortlist

更新日: 2026-05-10

## 1. 目的

- `LOF` の高順位 chunk から、さらに実務の初動で先に見るべき event を `10件` に絞る
- 今回は `top10 chunk` を対象にし、normal seed 候補を優先している

## 2. ルール

- 親の `chunk rank` が高い event を優先
- `winword.exe` / `repmgr.exe` / `explorer.exe` / `firefox.exe` を優先
- `4656` のような起点寄り event をやや優先
- chunk 内で最初に出るプロセス切り替わりを優先
- `tpautoconnect.exe` など反復 background noise は下げる
- 1 chunk あたり最大 `2 event` までに制限

## 3. shortlist

| rank | parent chunk | event offset | process | event_id | category | 理由 |
| --- | --- | ---: | --- | --- | --- | --- |
| `1` | `chunk203 (rank 4)` | `5` | `repmgr.exe` | `4656` | `office-doc` | `chunk rank 4; process repmgr.exe; event 4656; first process appearance in chunk; process transition; early in chunk` |
| `2` | `chunk203 (rank 4)` | `1` | `winword.exe` | `4656` | `office-doc` | `chunk rank 4; process winword.exe; event 4656; first process appearance in chunk; early in chunk` |
| `3` | `chunk204 (rank 5)` | `70` | `winword.exe` | `4656` | `office-doc` | `chunk rank 5; process winword.exe; event 4656; first process appearance in chunk; process transition` |
| `4` | `chunk204 (rank 5)` | `1` | `repmgr.exe` | `4656` | `office-doc` | `chunk rank 5; process repmgr.exe; event 4656; first process appearance in chunk; early in chunk` |
| `5` | `chunk244 (rank 6)` | `88` | `explorer.exe` | `4656` | `user-file` | `chunk rank 6; process explorer.exe; event 4656; first process appearance in chunk; process transition` |
| `6` | `chunk210 (rank 7)` | `1` | `winword.exe` | `4663` | `office-doc` | `chunk rank 7; process winword.exe; event 4663; first process appearance in chunk; early in chunk` |
| `7` | `chunk243 (rank 9)` | `27` | `explorer.exe` | `4656` | `user-file` | `chunk rank 9; process explorer.exe; event 4656; first process appearance in chunk; process transition` |
| `8` | `chunk210 (rank 7)` | `4` | `winword.exe` | `4656` | `office-doc` | `chunk rank 7; process winword.exe; event 4656; early in chunk` |
| `9` | `chunk244 (rank 6)` | `90` | `explorer.exe` | `4656` | `user-file` | `chunk rank 6; process explorer.exe; event 4656` |
| `10` | `chunk243 (rank 9)` | `30` | `explorer.exe` | `4656` | `user-file` | `chunk rank 9; process explorer.exe; event 4656` |

## 4. 読み

- 先頭は `office-doc` と `user-file` の起点 event が中心
- `chunk203`, `chunk204`, `chunk210` からは `winword.exe` / `repmgr.exe` の開始側 event が選ばれている
- `chunk244`, `chunk243` からは `explorer.exe` が現れた切り替わり地点が拾われている
- 今回は `top10 chunk` 限定なので browser 系はまだ入れていない

## 5. 次の広げ方

- browser 系も欲しいなら対象を `rank 43〜47` まで拡張する
- その場合は `firefox.exe` の最初の出現 event を同じロジックで追加するとよい