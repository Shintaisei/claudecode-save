# Pilot05：各モデル・正常1ユースケース／攻撃1ユースケースの実験結果

## 実験外観

| モデル | 区分 | ユースケース | Gold step | Stage | 試行数 |
|---|---|---|---:|---|---:|
| `gpt-4.1-mini` | 正常 | Discord Run-key registry chain | 2 | 1–3 | 3 |
| `gpt-4.1-mini` | 攻撃 | mshta → PowerShell → payload/network chain | 9 | 1–3 | 3 |
| `gpt-5.4-mini` | 正常 | Python SimpleHTTPServer chain | 3 | 1–3 | 3 |
| `gpt-5.4-mini` | 攻撃 | Word document processing chain | 2 | 1–3 | 3 |

- 全ケース5分窓。
- 各ケースはStage 1、2、3を1回ずつ実行。
- `max_tokens=24576`、実験上のAgent call上限なし。
- Chief、Investigator、SQL QAを含むfull-pipeline ledgerで集計。
- 以下の運用量は、元の「モデル平均」と同じく1試行平均。精度は3 Stageを合算したmicro aggregate。

## 1ユースケース×モデルの全体外観

| モデル | 区分・ケース | API calls | Input | Output | Total tokens | Cost | Wall time |
|---|---|---:|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 正常・Discord | 118.33 | 403,999 | 23,933 | 427,931 | $0.120634 | 7.46分 |
| `gpt-4.1-mini` | 攻撃・mshta | 218.00 | 943,933 | 44,308 | 988,241 | $0.314744 | 11.45分 |
| `gpt-5.4-mini` | 正常・Python HTTP | 76.00 | 415,722 | 28,573 | 444,294 | $0.246083 | 4.37分 |
| `gpt-5.4-mini` | 攻撃・Word | 58.33 | 396,560 | 31,486 | 428,046 | $0.282435 | 3.34分 |

## 1ユースケース×モデルの精度

| モデル | 区分・ケース | Action recall | Precision | 完全step | Critical | Order |
|---|---|---:|---:|---:|---:|---:|
| `gpt-4.1-mini` | 正常・Discord | 9/18 = **50.00%** | 9/39 = **23.08%** | 3/6 = **50.00%** | 0/6 = 0.00% | 0/3 = 0.00% |
| `gpt-4.1-mini` | 攻撃・mshta | 10/81 = **12.35%** | 10/27 = **37.04%** | 2/27 = **7.41%** | 0/27 = 0.00% | 1/24 = **4.17%** |
| `gpt-5.4-mini` | 正常・Python HTTP | 4/27 = **14.81%** | 4/27 = **14.81%** | 1/9 = **11.11%** | 0/9 = 0.00% | 1/6 = **16.67%** |
| `gpt-5.4-mini` | 攻撃・Word | 12/18 = **66.67%** | 12/30 = **40.00%** | 3/6 = **50.00%** | 0/6 = 0.00% | 3/3 = **100.00%** |

## モジュール別：1試行平均

| モデル・ケース | モジュール | API calls | Total tokens | LLM時間 | Cost | 費用構成比 |
|---|---|---:|---:|---:|---:|---:|
| 4.1・正常Discord | Chief | 6.00 | 30,193 | 46.06秒 | $0.011758 | 9.7% |
|  | Investigator | 23.67 | 129,322 | 116.15秒 | $0.033770 | 28.0% |
|  | SQL QA | **88.67** | **268,417** | **185.12秒** | **$0.075106** | **62.3%** |
| 4.1・攻撃mshta | Chief | 7.33 | 55,056 | 46.50秒 | $0.016888 | 5.4% |
|  | Investigator | 49.00 | 298,528 | 253.90秒 | $0.076118 | 24.2% |
|  | SQL QA | **161.67** | **634,657** | **369.20秒** | **$0.221738** | **70.5%** |
| 5.4・正常Python | Chief | 6.33 | 46,846 | 27.03秒 | $0.036944 | 15.0% |
|  | Investigator | 14.33 | 52,965 | 47.32秒 | $0.049273 | 20.0% |
|  | SQL QA | **55.33** | **344,483** | **130.96秒** | **$0.159866** | **65.0%** |
| 5.4・攻撃Word | Chief | 5.33 | 37,779 | 28.96秒 | $0.038538 | 13.6% |
|  | Investigator | 11.00 | 59,870 | 38.35秒 | $0.046974 | 16.6% |
|  | SQL QA | **42.00** | **330,397** | **125.07秒** | **$0.196923** | **69.7%** |

## Stage別

| モデル・ケース | Stage | API calls | Total tokens | Cost | Wall time | Action recall | Precision | 完全step | Order |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4.1・正常Discord | 1 | 192 | 751,002 | $0.204923 | 10.92分 | 0.00% | 0.00% | 0.00% | 0.00% |
|  | 2 | 63 | 183,398 | $0.062085 | 3.90分 | 50.00% | 50.00% | 50.00% | 0.00% |
|  | 3 | 100 | 349,394 | $0.094894 | 7.54分 | 100.00% | 40.00% | 100.00% | 0.00% |
| 4.1・攻撃mshta | 1 | 196 | 757,608 | $0.236412 | 11.31分 | 25.93% | 58.33% | 11.11% | 12.50% |
|  | 2 | 8 | 18,081 | $0.006022 | 0.34分 | 0.00% | 0.00% | 0.00% | 0.00% |
|  | 3 | 450 | 2,189,034 | $0.701798 | 22.69分 | 11.11% | 20.00% | 11.11% | 0.00% |
| 5.4・正常Python | 1 | 56 | 261,183 | $0.165340 | 2.96分 | 44.44% | 66.67% | 33.33% | 50.00% |
|  | 2 | 70 | 520,065 | $0.251600 | 4.74分 | 0.00% | 0.00% | 0.00% | 0.00% |
|  | 3 | 102 | 551,635 | $0.321311 | 5.39分 | 0.00% | 0.00% | 0.00% | 0.00% |
| 5.4・攻撃Word | 1 | 45 | 341,484 | $0.249428 | 3.08分 | 66.67% | 66.67% | 50.00% | 100.00% |
|  | 2 | 73 | 512,896 | $0.347611 | 3.80分 | 66.67% | 44.44% | 50.00% | 100.00% |
|  | 3 | 57 | 429,758 | $0.250266 | 3.13分 | 66.67% | 26.67% | 50.00% | 100.00% |

Critical evidenceは全12試行で0%。

## ケース別の実験結果

### gpt-4.1-mini・正常：Discord Run-key

- Stage 1は近傍Discord housekeepingと別registry instanceへ逸れ、6候補すべて非TP。
- Stage 2はRun-key書込みを完全取得したが、Discord→reg.exe生成はexecution contextに留まった。
- Stage 3は2 Gold stepを完全取得したが、順序を逆転し、上流installer chainも候補化した。
- 3 Stage合計ではAction recall 50%、完全step 50%。一方、Precision 23.08%、Order 0%。
- 正しいchainへ入った場合の回収力は高いが、候補抑制と最終時系列検証が弱い。

### gpt-4.1-mini・攻撃：mshta chain

- Stage 1は前半のprocess chainを部分取得したが、3本のnetwork edgeと後半payload chainを失った。
- Stage 2は最初の時刻完全一致検索が外れ、時間緩和を追跡せず1 leadで早期停止した。
- Stage 3は450 API calls、218.9万tokens、22.69分を使ったが、完全取得は最後のpayload network edgeだけ。
- 関連PowerShell、cmd、payload自体は発見しており、証拠不足ではなく、因果edgeの候補化と探索終端制御が失敗した。
- 4ケース中で最も計算量が大きく、Action recallは12.35%に留まった。

### gpt-5.4-mini・正常：Python SimpleHTTPServer

- Stage 1はrun_http_server.bat実行を完全取得し、Action recall 44.44%、Precision 66.67%。
- Stage 2・3は38秒前のDNS capture chainを選び、対象HTTP chainは0 hit。
- 追加探索は誤ったprocess instanceを詳細化し、正しいinstanceへのpivotにつながらなかった。
- 主要課題は初期process-instance選択と、低確信時の再検証。

### gpt-5.4-mini・攻撃：Word document processing

- 全StageでAction recall 66.67%、完全step 50%、Order 100%と安定。
- WINWORD→子WINWORD生成は完全取得。
- msf.rtf文書オープンは証拠中に存在したが、process creationとしてcandidate化され、operation/objectが欠落した。
- Stageが上がるほどGold外の一時ファイル・module load候補が増え、Precisionは66.67%→44.44%→26.67%へ低下。
- 因果順序は安定しているが、行動タイプ付けとGold外候補の抑制が課題。

## 発表用まとめ

> 各モデルに正常1ケース・攻撃1ケースを割り当てた結果、性能差はモデルよりもケース構造と初期instance選択に強く依存した。gpt-5.4-miniのWord攻撃ケースはAction recall 66.67%、Order 100%で安定した一方、同モデルの正常Pythonケースは誤った近傍chainを追跡しAction recall 14.81%に留まった。gpt-4.1-miniのDiscord正常ケースは正しいchainに入ったStage 3でAction recall 100%を達成したが、mshta攻撃ケースでは探索量が最大でもAction recall 12.35%だった。全ケース共通でCritical evidenceは0%であり、探索量の増加よりもprocess-instance再検証、因果edgeの候補化、時系列整列、Gold外候補抑制が主要改善軸である。
