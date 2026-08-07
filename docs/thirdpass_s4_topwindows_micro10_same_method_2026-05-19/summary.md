# third pass: top10 chunk -> 10 event micro-chunk 再ランキング

更新日: 2026-05-19

## 1. 設定

- second pass の `top10` chunk を対象
- 各 `100 event chunk` をさらに `10 event` に分割
- 候補 micro-chunk 数: `400`

## 2. 比較結果

| model | first attack rank | top5 attack event | top5 normal event | top5 normal-only micro-chunk | 読み |
| --- | ---: | ---: | ---: | ---: | --- |
| `lof` | `398` | `0` | `50` | `5` | 起点候補向き |
| `ocsvm` | `73` | `0` | `50` | `5` | attack 近傍を厚めに残す |
| `rarity` | `395` | `0` | `50` | `5` | 珍しさ重視で単純 |

## 3. top10 micro-chunk

### lof

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk199 (rank 6)` | `0` | `0 / 10` | `wmiprvse.exe` |
| `2` | `chunk180 (rank 1)` | `0` | `0 / 10` | `upd.exe` |
| `3` | `chunk180 (rank 1)` | `1` | `0 / 10` | `upd.exe` |
| `4` | `chunk180 (rank 1)` | `2` | `0 / 10` | `upd.exe` |
| `5` | `chunk180 (rank 1)` | `5` | `0 / 10` | `scanhost.exe` |
| `6` | `chunk180 (rank 1)` | `6` | `0 / 10` | `scanhost.exe` |
| `7` | `chunk180 (rank 1)` | `7` | `0 / 10` | `scanhost.exe` |
| `8` | `chunk180 (rank 1)` | `8` | `0 / 10` | `scanhost.exe` |
| `9` | `chunk181 (rank 1)` | `0` | `0 / 10` | `scanhost.exe` |
| `10` | `chunk181 (rank 1)` | `1` | `0 / 10` | `scanhost.exe` |

### ocsvm

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk079 (rank 9)` | `0` | `0 / 10` | `services.exe, -` |
| `2` | `chunk080 (rank 9)` | `8` | `0 / 10` | `services.exe` |
| `3` | `chunk080 (rank 9)` | `4` | `0 / 10` | `services.exe` |
| `4` | `chunk080 (rank 9)` | `3` | `0 / 10` | `services.exe` |
| `5` | `chunk080 (rank 9)` | `9` | `0 / 10` | `services.exe` |
| `6` | `chunk081 (rank 9)` | `4` | `0 / 10` | `services.exe, wsqmcons.exe` |
| `7` | `chunk081 (rank 9)` | `3` | `0 / 10` | `services.exe, wsqmcons.exe` |
| `8` | `chunk080 (rank 9)` | `2` | `0 / 10` | `services.exe, csrss.exe` |
| `9` | `chunk079 (rank 9)` | `6` | `0 / 10` | `services.exe, sysmon.exe` |
| `10` | `chunk080 (rank 9)` | `7` | `0 / 10` | `services.exe, svchost.exe` |

### rarity

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk180 (rank 1)` | `0` | `0 / 10` | `upd.exe` |
| `2` | `chunk180 (rank 1)` | `1` | `0 / 10` | `upd.exe` |
| `3` | `chunk180 (rank 1)` | `2` | `0 / 10` | `upd.exe` |
| `4` | `chunk180 (rank 1)` | `5` | `0 / 10` | `scanhost.exe` |
| `5` | `chunk180 (rank 1)` | `6` | `0 / 10` | `scanhost.exe` |
| `6` | `chunk180 (rank 1)` | `7` | `0 / 10` | `scanhost.exe` |
| `7` | `chunk180 (rank 1)` | `8` | `0 / 10` | `scanhost.exe` |
| `8` | `chunk181 (rank 1)` | `0` | `0 / 10` | `scanhost.exe` |
| `9` | `chunk181 (rank 1)` | `1` | `0 / 10` | `scanhost.exe` |
| `10` | `chunk181 (rank 1)` | `2` | `0 / 10` | `scanhost.exe` |

## 4. 読み

- third pass を入れることで、`100 event` 単位では広すぎた候補を `10 event` 単位まで落とせる
- ここで重要なのは、attack を拾うことだけでなく、normal-only micro-chunk を上位に何個出せるか
- 実務の起点抽出では、`first attack rank` と `top5 normal-only micro-chunk` の両方を見るのがよい