# third pass: top10 chunk -> 10 event micro-chunk 再ランキング

更新日: 2026-05-10

## 1. 設定

- second pass の `top10` chunk を対象
- 各 `100 event chunk` をさらに `10 event` に分割
- 候補 micro-chunk 数: `100`

## 2. 比較結果

| model | first attack rank | top5 attack event | top5 normal event | top5 normal-only micro-chunk | 読み |
| --- | ---: | ---: | ---: | ---: | --- |
| `lof` | `1` | `10` | `40` | `1` | 起点候補向き |
| `ocsvm` | `2` | `1` | `49` | `4` | attack 近傍を厚めに残す |
| `rarity` | `1` | `15` | `35` | `0` | 珍しさ重視で単純 |

## 3. top10 micro-chunk

### lof

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk330 (rank 1)` | `5` | `1 / 9` | `payload.exe, tpautoconnect.exe, csrss.exe` |
| `2` | `chunk325 (rank 3)` | `2` | `0 / 10` | `tpautoconnect.exe, payload.exe, csrss.exe` |
| `3` | `chunk325 (rank 3)` | `5` | `3 / 7` | `payload.exe, tpautoconnect.exe` |
| `4` | `chunk325 (rank 3)` | `7` | `3 / 7` | `payload.exe, tpautoconnect.exe` |
| `5` | `chunk324 (rank 8)` | `7` | `3 / 7` | `payload.exe, tpautoconnect.exe` |
| `6` | `chunk204 (rank 5)` | `2` | `0 / 10` | `tpautoconnect.exe, repmgr.exe` |
| `7` | `chunk244 (rank 6)` | `8` | `0 / 10` | `tpautoconnect.exe, explorer.exe` |
| `8` | `chunk325 (rank 3)` | `8` | `1 / 9` | `tpautoconnect.exe, payload.exe` |
| `9` | `chunk203 (rank 4)` | `5` | `0 / 10` | `tpautoconnect.exe, repmgr.exe` |
| `10` | `chunk203 (rank 4)` | `7` | `0 / 10` | `tpautoconnect.exe, winword.exe` |

### ocsvm

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk308 (rank 2)` | `6` | `0 / 10` | `cmd.exe` |
| `2` | `chunk308 (rank 2)` | `7` | `1 / 9` | `cmd.exe, csrss.exe` |
| `3` | `chunk308 (rank 2)` | `9` | `0 / 10` | `payload.exe, csrss.exe, cmd.exe` |
| `4` | `chunk330 (rank 1)` | `4` | `0 / 10` | `csrss.exe` |
| `5` | `chunk308 (rank 2)` | `8` | `0 / 10` | `csrss.exe` |
| `6` | `chunk308 (rank 2)` | `5` | `0 / 10` | `cmd.exe, -` |
| `7` | `chunk325 (rank 3)` | `3` | `0 / 10` | `csrss.exe` |
| `8` | `chunk330 (rank 1)` | `8` | `0 / 10` | `csrss.exe, payload.exe` |
| `9` | `chunk330 (rank 1)` | `9` | `0 / 10` | `csrss.exe, payload.exe` |
| `10` | `chunk330 (rank 1)` | `3` | `1 / 9` | `payload.exe, csrss.exe, tpautoconnect.exe` |

### rarity

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk330 (rank 1)` | `6` | `2 / 8` | `payload.exe` |
| `2` | `chunk330 (rank 1)` | `7` | `2 / 8` | `payload.exe` |
| `3` | `chunk325 (rank 3)` | `9` | `3 / 7` | `payload.exe` |
| `4` | `chunk324 (rank 8)` | `0` | `4 / 6` | `payload.exe` |
| `5` | `chunk324 (rank 8)` | `1` | `4 / 6` | `payload.exe, -` |
| `6` | `chunk324 (rank 8)` | `3` | `0 / 10` | `payload.exe` |
| `7` | `chunk324 (rank 8)` | `4` | `1 / 9` | `payload.exe` |
| `8` | `chunk324 (rank 8)` | `5` | `0 / 10` | `payload.exe` |
| `9` | `chunk324 (rank 8)` | `6` | `3 / 7` | `payload.exe` |
| `10` | `chunk308 (rank 2)` | `6` | `0 / 10` | `cmd.exe` |

## 4. 読み

- third pass を入れることで、`100 event` 単位では広すぎた候補を `10 event` 単位まで落とせる
- ここで重要なのは、attack を拾うことだけでなく、normal-only micro-chunk を上位に何個出せるか
- 実務の起点抽出では、`first attack rank` と `top5 normal-only micro-chunk` の両方を見るのがよい