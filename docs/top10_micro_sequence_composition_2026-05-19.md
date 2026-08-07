# top10 sequence composition

作成日: 2026-05-19

## 区分
- `attack label`: `label = 1` の event
- `payload.exe`: `label = 0` かつ `process = payload.exe` の event
- `non-payload normal`: `label = 0` かつ `process != payload.exe` の event

この3区分は重ならないように切ってあり、各シーケンスは必ず `10 event` に合計されます。

## 全体合計
- attack label: `11`
- label 0 + payload.exe: `29`
- label 0 + non-payload: `60`

## シーケンス別

| seq rank | attack label | label 0 + payload.exe | label 0 + non-payload |
| --- | ---: | ---: | ---: |
| `1` | `1` | `5` | `4` |
| `2` | `0` | `3` | `7` |
| `3` | `3` | `5` | `2` |
| `4` | `3` | `6` | `1` |
| `5` | `3` | `6` | `1` |
| `6` | `0` | `0` | `10` |
| `7` | `0` | `0` | `10` |
| `8` | `1` | `4` | `5` |
| `9` | `0` | `0` | `10` |
| `10` | `0` | `0` | `10` |

## 読み方
- `seq 4` と `seq 5` は `payload.exe` 近傍がかなり多く、attack label も `3` 件ずつ入る
- `seq 6, 7, 9, 10` は `label 0 + non-payload` だけで構成される
- `seq 2` は attack label はないが `payload.exe` が `3` 件含まれるため、clean normal と言い切りにくい
