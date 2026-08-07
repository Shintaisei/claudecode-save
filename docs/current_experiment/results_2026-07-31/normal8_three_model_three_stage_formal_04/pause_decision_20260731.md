# normal8 formal_04 pause decision

`formal_04` はゲート3件の計装監査にはPASSしたが、正式結果としては未採用のまま停止した。既存runは削除・上書きしていない。`full_run_audit.json` は生成されていない。

## 停止理由

gpt-5.5のDiscord Run-key Stage 3 sentinelは、単発APIの固着ではなく探索幅が膨張した。

| 指標 | gpt-5.5 sentinel |
|---|---:|
| Chief lead | 20（unique 20） |
| Investigator question | 124 |
| SQL query | 811 |
| API call | 773 |
| Input tokens | 12,692,655 |
| Output tokens | 1,145,977 |
| Total tokens | 13,838,632 |
| Cost | $62.947353 |
| Wall time | 13,589.266秒（約3時間46分） |
| 最大LLM call | 162.187秒 |
| 最大lead | 1,276.36秒 |

最大LLM callは20分未満であり、API固着ではない。一方、v1のfrontier promptが「直接接続edgeをすべて確認」「各新規edgeを次のleadへ分ける」と要求したため、Discordのroutine sibling、通常通信、Crashpad、loopback等まで追跡対象になった。また、1件のleadが設定上限1,200秒を超えたが、最後のin-flight call後に再チェックされなかったためguard recordは誤って`triggered=false`だった。

## 実施した保全措置

- 後続69件を開始したfull親PID 25924と、未完了の最初のgpt-4.1-mini子PID 16332を停止した。
- 4件目のrun artifactは生成されていない。
- 完了済み3 runとgate auditは保存した。
- 数値的な論点上限ではなく、主行動列へ異なるatomic stepを追加・順序変更・重要なsubject/operation/object証拠を解消するedgeだけを追う`material_causal_frontier_review_v2`を作成した。
- lead完了時にもwall超過を記録する修正とテストを追加した。
- successor `formal_05` のAPIなしpreflightはPASSした。

`formal_04`は運用上の失敗・原因分析資料として保持し、修正版の正式候補は`formal_05`でcreate-only実行する。
