# third pass: top10 chunk -> 10 event micro-chunk 再ランキング

更新日: 2026-05-19

## 1. 設定

- second pass の `top10` chunk を対象
- 各 `100 event chunk` をさらに `10 event` に分割
- 候補 micro-chunk 数: `280`

## 2. 比較結果

| model | first attack rank | top5 attack event | top5 normal event | top5 normal-only micro-chunk | 読み |
| --- | ---: | ---: | ---: | ---: | --- |
| `lof` | `None` | `0` | `50` | `5` | 起点候補向き |
| `ocsvm` | `None` | `0` | `50` | `5` | attack 近傍を厚めに残す |
| `rarity` | `None` | `0` | `50` | `5` | 珍しさ重視で単純 |

## 3. top10 micro-chunk

### lof

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk174 (rank 6)` | `4` | `0 / 10` | `tpautoconnect.exe` |
| `2` | `chunk174 (rank 6)` | `3` | `0 / 10` | `tpautoconnect.exe` |
| `3` | `chunk174 (rank 6)` | `5` | `0 / 10` | `tpautoconnect.exe, svchost.exe, -` |
| `4` | `chunk007 (rank 1)` | `2` | `0 / 10` | `tshark.exe` |
| `5` | `chunk007 (rank 1)` | `5` | `0 / 10` | `tshark.exe` |
| `6` | `chunk007 (rank 1)` | `8` | `0 / 10` | `tshark.exe` |
| `7` | `chunk008 (rank 1)` | `1` | `0 / 10` | `tshark.exe` |
| `8` | `chunk008 (rank 1)` | `4` | `0 / 10` | `tshark.exe` |
| `9` | `chunk008 (rank 1)` | `7` | `0 / 10` | `tshark.exe` |
| `10` | `chunk008 (rank 1)` | `9` | `0 / 10` | `tshark.exe` |

### ocsvm

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk008 (rank 1)` | `8` | `0 / 10` | `tshark.exe` |
| `2` | `chunk009 (rank 1)` | `0` | `0 / 10` | `tshark.exe` |
| `3` | `chunk007 (rank 1)` | `0` | `0 / 10` | `tshark.exe` |
| `4` | `chunk007 (rank 1)` | `3` | `0 / 10` | `tshark.exe` |
| `5` | `chunk007 (rank 1)` | `6` | `0 / 10` | `tshark.exe` |
| `6` | `chunk007 (rank 1)` | `9` | `0 / 10` | `tshark.exe` |
| `7` | `chunk008 (rank 1)` | `2` | `0 / 10` | `tshark.exe` |
| `8` | `chunk008 (rank 1)` | `5` | `0 / 10` | `tshark.exe` |
| `9` | `chunk009 (rank 1)` | `2` | `0 / 10` | `tshark.exe` |
| `10` | `chunk009 (rank 1)` | `5` | `0 / 10` | `tshark.exe` |

### rarity

| rank | parent chunk | micro | attack / normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| `1` | `chunk015 (rank 2)` | `3` | `0 / 10` | `services.exe` |
| `2` | `chunk015 (rank 2)` | `1` | `0 / 10` | `services.exe, dumpcap.exe` |
| `3` | `chunk015 (rank 2)` | `2` | `0 / 10` | `services.exe, dumpcap.exe` |
| `4` | `chunk003 (rank 5)` | `0` | `0 / 10` | `cmd.exe` |
| `5` | `chunk024 (rank 3)` | `1` | `0 / 10` | `cmd.exe` |
| `6` | `chunk024 (rank 3)` | `2` | `0 / 10` | `cmd.exe` |
| `7` | `chunk003 (rank 5)` | `2` | `0 / 10` | `cmd.exe` |
| `8` | `chunk003 (rank 5)` | `3` | `0 / 10` | `cmd.exe` |
| `9` | `chunk003 (rank 5)` | `8` | `0 / 10` | `cmd.exe` |
| `10` | `chunk003 (rank 5)` | `9` | `0 / 10` | `cmd.exe` |

## 4. 読み

- third pass を入れることで、`100 event` 単位では広すぎた候補を `10 event` 単位まで落とせる
- ここで重要なのは、attack を拾うことだけでなく、normal-only micro-chunk を上位に何個出せるか
- 実務の起点抽出では、`first attack rank` と `top5 normal-only micro-chunk` の両方を見るのがよい