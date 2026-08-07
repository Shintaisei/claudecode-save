# pilot05 研究発表用サマリ

## Slide 1 — 12試行の全体像

**中心メッセージ：全体Action recallは24.31%。費用は$2.89、逐次実行時間は79.83分だった。**

| Runs | API calls | Input | Output | Cached input | Total tokens | Cost | Wall time |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 12 | 1,412 | 6,480,641 | 384,897 | 3,689,600 | 6,865,538 | $2.891690 | 79.83 min |

| Action recall | Candidate precision | Complete step | Critical evidence | Order |
|---:|---:|---:|---:|---:|
| 35/144 (24.31%) | 35/123 (28.46%) | 9/48 (18.75%) | 0/48 (0.00%) | 5/36 (13.89%) |

注：モデルごとに異なる2ケースを担当しているため、モデル値はケース難易度を統制した直接比較ではない。

### モデル別・1ユースケース当たり（Stage 1〜3の1セット）

| Model | API calls | Input | Output | Cached | Total tokens | Cost | Wall min |
|---|---:|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 504.5 | 2,021,898.0 | 102,360.5 | 1,064,896.0 | 2,124,258.5 | $0.653067 | 28.36 |
| gpt-5.4-mini | 201.5 | 1,218,422.5 | 90,088.0 | 779,904.0 | 1,308,510.5 | $0.792778 | 11.56 |

| Model | Action recall | Precision | Complete step | Critical evidence | Order |
|---|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 9.5/49.5 (19.19%) | 9.5/33 (28.79%) | 2.5/16.5 (15.15%) | 0/16.5 (0.00%) | 0.5/13.5 (3.70%) |
| gpt-5.4-mini | 8/22.5 (35.56%) | 8/28.5 (28.07%) | 2/7.5 (26.67%) | 0/7.5 (0.00%) | 2/4.5 (44.44%) |

精度の割合は2ケースのmicro-averageであり、分子・分母だけを2で割って1ケース当たり平均として表示した。

## Slide 2 — SQL QAが処理量と費用の約7割を占める

| Module | API calls | Call share | Total tokens | Token share | LLM sec | Cost | Cost share |
|---|---:|---:|---:|---:|---:|---:|---:|
| chief | 75 | 5.31% | 509,624 | 7.42% | 445.660 | $0.312384 | 10.80% |
| investigator | 294 | 20.82% | 1,622,054 | 23.63% | 1367.185 | $0.618406 | 21.39% |
| sql_qa | 1,043 | 73.87% | 4,733,860 | 68.95% | 2431.077 | $1.960900 | 67.81% |

Cached inputはinput tokenの内数であり、Total tokensへ二重加算していない。ModuleのLLM secはAPI call所要時間の合計で、試行wall timeとは定義が異なる。

## Slide 3 — 未取得の主因は探索回数より「edge化と候補化」

- Gold action miss: 109/144
- 完全step miss: 39/48
- Critical evidence miss: 48/48
- Order miss: 31/36
- Causal edge欠落タグ: 11/12 run
- 近傍行動の過剰接続: 8/12 run
- 幻覚・未裏付け証拠タグ: 8/12 run
- 明確な早期停止: 1/12 run

原因タグは重複する。早期停止は1件だけであり、低精度を単純な回数制限では説明できない。

## Slide 4 — 4ユースケースで異なる失敗パターンが現れた

| Group | Model | Use case | Action recall | Precision | Complete step | Critical | Order |
|---|---|---|---:|---:|---:|---:|---:|
| attack | gpt-5.4-mini | 攻撃: Word document | 12/18 (66.67%) | 12/30 (40.00%) | 3/6 (50.00%) | 0/6 (0.00%) | 3/3 (100.00%) |
| attack | gpt-4.1-mini | 攻撃: mshta C1 | 10/81 (12.35%) | 10/27 (37.04%) | 2/27 (7.41%) | 0/27 (0.00%) | 1/24 (4.17%) |
| normal | gpt-5.4-mini | 正常: Python HTTP | 4/27 (14.81%) | 4/27 (14.81%) | 1/9 (11.11%) | 0/9 (0.00%) | 1/6 (16.67%) |
| normal | gpt-4.1-mini | 正常: Discord Run-key | 9/18 (50.00%) | 9/39 (23.08%) | 3/6 (50.00%) | 0/6 (0.00%) | 0/3 (0.00%) |

- Discord：Stage進行でrecallは回復したが、順序逆転とGold外候補でprecisionが低い。
- mshta：長い後段chainへのrecursive pivot不足。大量探索でもedge coverageが増えない。
- Python HTTP：初回に別process instanceを選ぶと、後続探索が誤系列を精緻化した。
- Word：core 2-stepは安定したが、文書openの誤型付けとGold外候補追加でprecisionが低下。

## Slide 5 — Stage 1が最も安定し、Stage 3はRecallとPrecisionがトレードオフ

| Stage | Action recall | Precision | Complete step | Critical | Order |
|---|---:|---:|---:|---:|---:|
| stage1 | 15/48 (31.25%) | 15/42 (35.71%) | 3/16 (18.75%) | 0/16 (0.00%) | 3/12 (25.00%) |
| stage2 | 7/48 (14.58%) | 7/24 (29.17%) | 2/16 (12.50%) | 0/16 (0.00%) | 1/12 (8.33%) |
| stage3 | 13/48 (27.08%) | 13/57 (22.81%) | 4/16 (25.00%) | 0/16 (0.00%) | 1/12 (8.33%) |

Stage 2はexact-time検索後の早期停止と誤process選択の影響を受けた。Stage 3は完全stepが回復した一方、candidate slotが57まで増え、precisionは22.81%へ低下した。

## Slide 6 — モデル×Stage値はケース割当を含む記述統計

| Model | Stage | Action recall | Precision | Complete step | Critical | Order |
|---|---|---:|---:|---:|---:|---:|
| gpt-4.1-mini | stage1 | 7/33 (21.21%) | 7/30 (23.33%) | 1/11 (9.09%) | 0/11 (0.00%) | 1/9 (11.11%) |
| gpt-4.1-mini | stage2 | 3/33 (9.09%) | 3/6 (50.00%) | 1/11 (9.09%) | 0/11 (0.00%) | 0/9 (0.00%) |
| gpt-4.1-mini | stage3 | 9/33 (27.27%) | 9/30 (30.00%) | 3/11 (27.27%) | 0/11 (0.00%) | 0/9 (0.00%) |
| gpt-5.4-mini | stage1 | 8/15 (53.33%) | 8/12 (66.67%) | 2/5 (40.00%) | 0/5 (0.00%) | 2/3 (66.67%) |
| gpt-5.4-mini | stage2 | 4/15 (26.67%) | 4/18 (22.22%) | 1/5 (20.00%) | 0/5 (0.00%) | 1/3 (33.33%) |
| gpt-5.4-mini | stage3 | 4/15 (26.67%) | 4/27 (14.81%) | 1/5 (20.00%) | 0/5 (0.00%) | 1/3 (33.33%) |

4.1-miniは11 Gold step/Stage、5.4-miniは5 Gold step/Stageを担当する。真のモデル比較には、両モデルを4ケースすべてで実行する24試行が必要である。

## Slide 7 — 原因を6つのモジュール改善軸へ変換する

| 原因 | 観測 | 改善軸 |
|---|---|---|
| Process-instance選択 | Python HTTP Stage 2/3で38秒前の別chainを選択 | anchor再検証・PID+時刻instance gate |
| Downstream pivot | mshtaでPowerShell以降のedgeを失う | typed unresolved-frontier ledger |
| Atomic action化 | 親子edgeや文書openをexecution_contextへ圧縮 | subject/operation/object正規化器 |
| Candidate admission | Gold外file/moduleを主要chainへ昇格 | evidence-backedかつchain-relevant admission gate |
| Critical evidence束縛 | 0/48 | canonical row/action/target binder |
| Stop判定 | exact-time 0件後に1 runだけ早期停止 | 0件時の時間緩和・代替pivot必須化 |

## Slide 8 — 次の実験で切り分けるべきこと

1. 同一4ケースを両モデルで実行し、ケース難易度を統制する。
2. Anchor validation、typed edge ledger、candidate admissionを独立A/Bする。
3. Critical evidence binderはchain reconstructionと別指標で改善する。
4. API回数ではなく、Gold edge到達率・誤instance滞在率・Gold外candidate率を中間KPIにする。

# Appendix A — 試行別 total ledger

| Case | Model | Stage | Input | Output | Cached | Total | Calls | Chief | Inv | SQL | Cost | Wall min |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 正常: Discord Run-key | gpt-4.1-mini | stage1 | 710,887 | 40,115 | 478,720 | 751,002 | 192 | 7 | 37 | 148 | $0.204923 | 10.92 |
| 正常: Discord Run-key | gpt-4.1-mini | stage2 | 171,257 | 12,141 | 86,144 | 183,398 | 63 | 7 | 17 | 39 | $0.062085 | 3.90 |
| 正常: Discord Run-key | gpt-4.1-mini | stage3 | 329,852 | 19,542 | 227,712 | 349,394 | 100 | 4 | 17 | 79 | $0.094894 | 7.54 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage1 | 712,974 | 44,634 | 400,640 | 757,608 | 196 | 7 | 42 | 147 | $0.236412 | 11.31 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage2 | 17,170 | 911 | 7,680 | 18,081 | 8 | 4 | 2 | 2 | $0.006022 | 0.34 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage3 | 2,101,656 | 87,378 | 928,896 | 2,189,034 | 450 | 11 | 103 | 336 | $0.701798 | 22.69 |
| 正常: Python HTTP | gpt-5.4-mini | stage1 | 241,128 | 20,055 | 156,672 | 261,183 | 56 | 7 | 12 | 37 | $0.165340 | 2.96 |
| 正常: Python HTTP | gpt-5.4-mini | stage2 | 492,657 | 27,408 | 357,376 | 520,065 | 70 | 6 | 13 | 51 | $0.251600 | 4.74 |
| 正常: Python HTTP | gpt-5.4-mini | stage3 | 513,380 | 38,255 | 349,440 | 551,635 | 102 | 6 | 18 | 78 | $0.321310 | 5.39 |
| 攻撃: Word document | gpt-5.4-mini | stage1 | 312,370 | 29,114 | 171,648 | 341,484 | 45 | 5 | 10 | 30 | $0.249428 | 3.08 |
| 攻撃: Word document | gpt-5.4-mini | stage2 | 476,169 | 36,727 | 258,944 | 512,896 | 73 | 6 | 12 | 55 | $0.347611 | 3.80 |
| 攻撃: Word document | gpt-5.4-mini | stage3 | 401,141 | 28,617 | 265,728 | 429,758 | 57 | 5 | 11 | 41 | $0.250266 | 3.13 |

# Appendix B — 試行・モジュール別 ledger

| Case | Model | Stage | Module | Calls | Input | Output | Cached | Total | LLM sec | Cost |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| 正常: Discord Run-key | gpt-4.1-mini | stage1 | chief | 7 | 32,367 | 4,741 | 22,144 | 37,108 | 64.126 | $0.013889 |
| 正常: Discord Run-key | gpt-4.1-mini | stage1 | investigator | 37 | 210,324 | 14,164 | 169,344 | 224,488 | 178.781 | $0.055989 |
| 正常: Discord Run-key | gpt-4.1-mini | stage1 | sql_qa | 148 | 468,196 | 21,210 | 287,232 | 489,406 | 311.855 | $0.135045 |
| 正常: Discord Run-key | gpt-4.1-mini | stage2 | chief | 7 | 34,351 | 2,170 | 16,384 | 36,521 | 30.906 | $0.012297 |
| 正常: Discord Run-key | gpt-4.1-mini | stage2 | investigator | 17 | 39,992 | 5,172 | 23,936 | 45,164 | 63.066 | $0.017091 |
| 正常: Discord Run-key | gpt-4.1-mini | stage2 | sql_qa | 39 | 96,914 | 4,799 | 45,824 | 101,713 | 72.502 | $0.032697 |
| 正常: Discord Run-key | gpt-4.1-mini | stage3 | chief | 4 | 13,523 | 3,427 | 6,016 | 16,950 | 43.156 | $0.009088 |
| 正常: Discord Run-key | gpt-4.1-mini | stage3 | investigator | 17 | 111,633 | 6,680 | 90,368 | 118,313 | 106.595 | $0.028231 |
| 正常: Discord Run-key | gpt-4.1-mini | stage3 | sql_qa | 79 | 204,696 | 9,435 | 131,328 | 214,131 | 171.017 | $0.057576 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage1 | chief | 7 | 40,146 | 3,631 | 25,472 | 43,777 | 48.000 | $0.014226 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage1 | investigator | 42 | 234,575 | 15,911 | 173,056 | 250,486 | 224.817 | $0.067371 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage1 | sql_qa | 147 | 438,253 | 25,092 | 202,112 | 463,345 | 376.182 | $0.154815 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage2 | chief | 4 | 9,523 | 608 | 4,096 | 10,131 | 10.985 | $0.003553 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage2 | investigator | 2 | 3,824 | 166 | 1,792 | 3,990 | 3.063 | $0.001258 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage2 | sql_qa | 2 | 3,823 | 137 | 1,792 | 3,960 | 2.781 | $0.001211 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage3 | chief | 11 | 105,167 | 6,093 | 63,104 | 111,260 | 80.516 | $0.032884 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage3 | investigator | 103 | 603,628 | 37,481 | 472,320 | 641,109 | 533.831 | $0.159725 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage3 | sql_qa | 336 | 1,392,861 | 43,804 | 393,472 | 1,436,665 | 728.644 | $0.509189 |
| 正常: Python HTTP | gpt-5.4-mini | stage1 | chief | 7 | 41,969 | 3,831 | 24,192 | 45,800 | 23.203 | $0.032387 |
| 正常: Python HTTP | gpt-5.4-mini | stage1 | investigator | 12 | 34,551 | 5,508 | 16,256 | 40,059 | 38.782 | $0.039726 |
| 正常: Python HTTP | gpt-5.4-mini | stage1 | sql_qa | 37 | 164,608 | 10,716 | 116,224 | 175,324 | 81.702 | $0.093227 |
| 正常: Python HTTP | gpt-5.4-mini | stage2 | chief | 6 | 42,105 | 5,131 | 22,016 | 47,236 | 27.250 | $0.039807 |
| 正常: Python HTTP | gpt-5.4-mini | stage2 | investigator | 13 | 41,920 | 7,055 | 22,144 | 48,975 | 46.641 | $0.048240 |
| 正常: Python HTTP | gpt-5.4-mini | stage2 | sql_qa | 51 | 408,632 | 15,222 | 313,216 | 423,854 | 118.835 | $0.163552 |
| 正常: Python HTTP | gpt-5.4-mini | stage3 | chief | 6 | 42,645 | 4,858 | 22,528 | 47,503 | 30.625 | $0.038638 |
| 正常: Python HTTP | gpt-5.4-mini | stage3 | investigator | 18 | 61,858 | 8,002 | 33,408 | 69,860 | 56.546 | $0.059852 |
| 正常: Python HTTP | gpt-5.4-mini | stage3 | sql_qa | 78 | 408,877 | 25,395 | 293,504 | 434,272 | 192.355 | $0.222820 |
| 攻撃: Word document | gpt-5.4-mini | stage1 | chief | 5 | 37,025 | 4,791 | 16,768 | 41,816 | 24.564 | $0.038010 |
| 攻撃: Word document | gpt-5.4-mini | stage1 | investigator | 10 | 43,395 | 7,085 | 19,200 | 50,480 | 41.143 | $0.051469 |
| 攻撃: Word document | gpt-5.4-mini | stage1 | sql_qa | 30 | 231,950 | 17,238 | 135,680 | 249,188 | 103.419 | $0.159949 |
| 攻撃: Word document | gpt-5.4-mini | stage2 | chief | 6 | 32,588 | 5,096 | 16,384 | 37,684 | 28.095 | $0.036314 |
| 攻撃: Word document | gpt-5.4-mini | stage2 | investigator | 12 | 69,976 | 5,720 | 43,776 | 75,696 | 37.436 | $0.048673 |
| 攻撃: Word document | gpt-5.4-mini | stage2 | sql_qa | 55 | 373,605 | 25,911 | 198,784 | 399,516 | 158.453 | $0.262624 |
| 攻撃: Word document | gpt-5.4-mini | stage3 | chief | 5 | 27,314 | 6,524 | 12,672 | 33,838 | 34.234 | $0.041290 |
| 攻撃: Word document | gpt-5.4-mini | stage3 | investigator | 11 | 48,177 | 5,257 | 28,160 | 53,434 | 36.484 | $0.040781 |
| 攻撃: Word document | gpt-5.4-mini | stage3 | sql_qa | 41 | 325,650 | 16,836 | 224,896 | 342,486 | 113.332 | $0.168195 |

# Appendix C — 試行別の主原因

| Case | Model | Stage | Action recall | Primary cause |
|---|---|---|---:|---|
| 正常: Discord Run-key | gpt-4.1-mini | stage1 | 0/6 (0.00%) | 近傍Discord処理へ漂流し、対象2 edgeを候補化できず |
| 正常: Discord Run-key | gpt-4.1-mini | stage2 | 3/6 (50.00%) | process-create edgeをexecution_contextへ圧縮 |
| 正常: Discord Run-key | gpt-4.1-mini | stage3 | 6/6 (100.00%) | Actionは回収したが順序逆転・Gold外chain追加 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage1 | 7/27 (25.93%) | 前半process edgeのみ、network・後段pivotを欠落 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage2 | 0/27 (0.00%) | exact-time 0件後、時間緩和pivotをせず早期停止 |
| 攻撃: mshta C1 | gpt-4.1-mini | stage3 | 3/27 (11.11%) | 450 callの過剰探索でも最終network edge以外をatomic化できず |
| 正常: Python HTTP | gpt-5.4-mini | stage1 | 4/9 (44.44%) | 親子process-createをexecution_contextへ圧縮 |
| 正常: Python HTTP | gpt-5.4-mini | stage2 | 0/9 (0.00%) | 38秒前の別DNS chainを誤選択 |
| 正常: Python HTTP | gpt-5.4-mini | stage3 | 0/9 (0.00%) | 追加探索が誤ったDNS chainを精緻化 |
| 攻撃: Word document | gpt-5.4-mini | stage1 | 4/6 (66.67%) | msf.rtf openをprocess-startとして誤型付け |
| 攻撃: Word document | gpt-5.4-mini | stage2 | 4/6 (66.67%) | 同じ誤型付け＋Gold外一時file候補 |
| 攻撃: Word document | gpt-5.4-mini | stage3 | 4/6 (66.67%) | 同じ誤型付け＋Gold外file/module候補増加 |

# Method notes

- Costはfull-pipeline per-call ledgerから算出し、Chief・Investigator・SQL QAをすべて含む。
- Total tokensはinput+output。Cached inputはinputの内数。
- Module LLM secは各roleのAPI latency合計。Wall minは試行全体の経過時間。
- Accuracyはv5 atomic rubric。PIDとhidden alert mappingは非採点、critical evidenceとorderは別判定。
- gpt-4.1-mini / Discord Stage 3は修正前TEMP VIEW wrapperの共通guard迂回を含む既知の技術的交絡であり、完了済みthoughtを1回だけ採用して再実行していない。
- OpenAI judge API/API scorerは不使用。
- Operational audit / accuracy audit: PASS。

機械可読JSON：`docs\current_experiment\normal_attack_full_ledger_pilot05_slide_ready_summary_20260731.json`
