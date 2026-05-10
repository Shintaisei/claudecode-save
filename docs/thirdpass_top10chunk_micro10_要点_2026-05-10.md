# third pass top10chunk micro10 要点
更新日: 2026-05-10

## 1. 設定

- second pass の `LOF top10 chunk` を対象
- 各 `100 event chunk` を `10 event micro-chunk` に再分割
- 候補数は `100 micro-chunk`
- 比較モデル:
  - `LOF`
  - `OneClassSVM`
  - `rarity`

## 2. 結果の要点

| model | first attack rank | top5 attack event | top5 normal event | top5 normal-only micro-chunk | 読み |
| --- | ---: | ---: | ---: | ---: | --- |
| `LOF` | `1` | `10` | `40` | `1` | attack 近傍を強く前に出す |
| `OneClassSVM` | `2` | `1` | `49` | `4` | normal-only を多く上に出す |
| `rarity` | `1` | `15` | `35` | `0` | payload / cmd 偏重になりやすい |

## 3. 実務向けの読み

- 「attack に早く触れたい」なら `LOF`
- 「重要な起点を数個出したい」なら、今回の条件では **`OneClassSVM` の方が目的に近い**
- `rarity` は単純で分かりやすいが、珍しいプロセスに引っ張られやすく、起点抽出用途では弱い

## 4. 今回の解釈

- `LOF` は attack-mixed な micro-chunk を前に出しやすい
- `OneClassSVM` は `cmd.exe` / `csrss.exe` なども上がるため、そのままでは起点説明に弱いが、**normal-only micro-chunk を上位に多く出せる**
- つまり third pass を本当に起点抽出に使うなら、
  - `OneClassSVM` をベースにする
  - その上で `cmd.exe` / `csrss.exe` のような説明しにくいものを落とす
  という後段ルールを足すのがよさそう

## 5. 次の一手

1. `OneClassSVM top10 micro-chunk` を対象に、説明しやすいプロセスだけ残す
2. `winword.exe` / `repmgr.exe` / `explorer.exe` / `firefox.exe` を含むものを起点候補として採択する
3. その件数を「実務で出せる重要起点数」として数える

## 6. 参照

- [thirdpass_top10chunk_micro10_2026-05-10/summary.md](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/docs_active/thirdpass_top10chunk_micro10_2026-05-10/summary.md:1)
- [thirdpass_top10chunk_micro10_2026-05-10/results.json](/c:/Users/komat/OneDrive/Desktop/ATLAS以外のデータセット/docs_active/thirdpass_top10chunk_micro10_2026-05-10/results.json:1)
