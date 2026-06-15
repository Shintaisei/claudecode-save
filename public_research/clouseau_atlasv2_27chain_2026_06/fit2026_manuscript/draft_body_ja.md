# FIT2026 原稿本文ドラフト

作成日: 2026-06-09  
用途: FIT原稿へ貼り込むための本文たたき台。数値は `docs/current_experiment/results_2026-06-04/formal_gpt41mini_gpt54mini_action_claim_eval_20260605/canonical_from_rerun_20260606/formal_step_score_summary_canonical_20260606.md` に基づく。

## 仮タイトル

少数のSOC調査起点からの証跡付き行動列復元に向けたエージェント型ログ探索の評価

## 概要

本稿では、少数のSOC調査起点からWindowsエンドポイントログを探索し、観測証跡に基づく行動列を復元するエージェント型パイプラインを評価する。対象手法は、アラート名を分類・要約するのではなく、host、process、timestamp、および必要に応じてEDRアラート情報を起点として、プロセス実行、コマンドライン、レジストリ操作などの観測事実を探索し、`code_steps` と `code_sequence` として出力する。評価では Discord Run key persistence 事例を対象に、入力情報とデータベース条件を段階的に変えた3条件を設定し、gpt-4.1-mini と gpt-5.4-mini の復元性能を比較した。gpt-5.4-mini は、アラートを初期入力に含む条件で13/14、アラートを初期入力に含めないfull DB条件で14/14の主要行動要素を復元した。一方、full DB条件でも行動順序は1/2に留まり、アラート要約行をDBから除外した条件では主要行動要素が8/14に低下した。これにより、alert summary が復元の探索経路と証跡同定に大きく寄与することが示された。

## 1. はじめに

SOCにおけるエンドポイント調査では、アラート名や短い検知理由だけでは、実際に端末上でどの行動が発生したかを十分に説明できない場合がある。特に、永続化や資格情報アクセスのような攻撃行動では、プロセス、コマンドライン、レジストリ、ファイル、通信などの複数ログを横断して、観測可能な行動列として再構成する必要がある。

本研究の目的は、少数の調査起点からログを探索し、アラートの自然文要約ではなく、調査者が検証可能な証跡付き行動列を復元できるかを評価することである。ここでいう行動列とは、主体、操作、対象、コマンドライン、根拠ログを含むステップ列であり、本稿では `code_steps` および `code_sequence` として表現する。

本稿の貢献は次の3点である。第一に、SOC調査起点から行動列を復元するエージェント型パイプラインを、入力情報の強さが異なる複数条件で評価する。第二に、評価単位を単なる自然文一致ではなく、行動ステップを構成する required item 単位に分解し、復元率、順序、証跡、過剰主張を測定する。第三に、EDRアラート情報が初期入力として与えられる場合と、DB内の探索対象としてのみ存在する場合、さらにアラート要約行が除外される場合を比較し、復元に寄与する情報源を分析する。

## 2. 提案手法

提案手法は、Chief agent、Investigation agent、QAAgent / SQL expert、Final synthesis からなる階層型パイプラインである。Chief agent は初期手がかりから調査方針を生成し、Investigation agent は確認すべき事実を質問へ変換する。QAAgent / SQL expert はSQLite化されたWindows endpoint logを検索し、timestamp、source stream、PID/PPID、process tree、command line、registry path、source row id などの観測値を返す。Final synthesis は得られた観測結果を統合し、主行動列と近傍行動を分離して `code_steps` と `code_sequence` を生成する。

本手法では、CBC alert の title や reason を行動そのものとして扱わない。アラート情報は探索の入口または証跡の一部として用いるが、出力される行動は、ログ上で観測できるプロセス実行、レジストリ操作、ファイル操作、通信などに限定する。この制約により、アラート名の言い換えを正解として扱うことを避け、調査者が再確認可能な出力を目指す。

## 3. 評価設計

評価対象は Discord Run key persistence 事例である。起点は `host=WIN-32-H1`、`process=reg.exe`、`timestamp=2022-07-16 15:07:46` であり、正解行動列は、Discord から `reg.exe` が子プロセスとして起動され、`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` の `Discord` 値が照会され、その後 `Update.exe --processStart Discord.exe` を指す値として追加または更新される3ステップで構成される。

比較条件は次の3段階である。Stage 1 はCBC alert triage情報と host/process/timestamp を初期入力に含める。Stage 2 は host/process/timestamp のみを初期入力とし、DB内にはCBC alert summary、CBC EDR/NGAV telemetry、Security、Sysmon、DNS、browser historyを残す。Stage 3 は初期入力をStage 2と同じにしつつ、DBからCBC alert summary rowsのみを除外し、CBC EDR/NGAV telemetryとOS側ログは残す。

評価指標は action-claim metrics を用いる。正解行動列を3つの action step に分け、合計14個の required item に固定する。D1は `Discord.exe` が `reg.exe` を子プロセスとして起動する行動であり、subject、operation、object、critical evidence の4項目を持つ。D2は `reg.exe query` によるRun keyの `Discord` 値照会であり、subject、operation、object、command line、critical evidence の5項目を持つ。D3は `reg.exe add` によるRun keyの `Discord` 値追加または更新であり、同じく5項目を持つ。主指標の recall と precision はどちらもこの14項目を分母とし、候補出力の過剰主張は candidate claim precision と overclaim slot count として別に診断する。

## 4. 結果

gpt-5.4-mini は、Stage 1で recall 13/14、precision 13/14、順序 1/2 を達成した。Stage 2では recall 14/14、precision 14/14 となり、アラートを初期入力に含めなくても、full DB内のアラート要約およびtelemetryへ探索で到達できる場合には、正解行動要素をすべて復元できた。ただし、Stage 2の順序は1/2であり、行動要素の網羅と時系列構成は分けて評価する必要がある。一方で、candidate claim precision は Stage 1 の 13/26 から Stage 2 の 14/32 に変化しており、正解行動は復元できるものの、近傍行動や重複claimも多く出力する傾向が見られた。

Stage 3では、gpt-5.4-mini の recall と precision は 8/14 に低下し、順序は 0/2 となった。特に、CBC alert summary rowsを除外すると、query step と critical evidence の復元が崩れ、Discord Run keyの主行動列に近い周辺レジストリ操作が混入した。これは、alert titleやreasonを最終答えとして使わない場合でも、アラート要約行が探索経路と証跡同定のための重要な足場になっていることを示す。

gpt-4.1-mini は、Stage 1で 4/14 を復元したが、Stage 2およびStage 3では主要行動列を復元できなかった。今回の設定では、少数のprocess-time clueから関連ログを探索し、複数証跡を統合する能力において、gpt-5.4-miniとの差が大きく表れた。

| model | stage | condition | recall | precision | candidate claim precision | order | critical evidence | overclaim slots |
|---|---|---|---:|---:|---:|---:|---:|---:|
| gpt-4.1-mini | Stage 1 | CBC alert input | 4/14 | 4/14 | 4/19 | 0/2 | 1/3 | 15 |
| gpt-4.1-mini | Stage 2 | process-time full DB | 0/14 | 0/14 | 0/10 | 0/2 | 0/3 | 10 |
| gpt-4.1-mini | Stage 3 | process-time alert summary removed | 0/14 | 0/14 | 0/17 | 0/2 | 0/3 | 17 |
| gpt-5.4-mini | Stage 1 | CBC alert input | 13/14 | 13/14 | 13/26 | 1/2 | 2/3 | 13 |
| gpt-5.4-mini | Stage 2 | process-time full DB | 14/14 | 14/14 | 14/32 | 1/2 | 3/3 | 18 |
| gpt-5.4-mini | Stage 3 | process-time alert summary removed | 8/14 | 8/14 | 8/18 | 0/2 | 1/3 | 10 |

## 5. 考察

結果から、強いモデルでは、アラート情報を初期入力として与えなくても、DB内にアラート要約と関連telemetryが残っていれば、process-time clueから主行動列へ到達できることが分かる。これは、SOC調査において最初から完全なアラート文脈が得られない場合でも、ログ探索により関連証跡を発見できる可能性を示している。

一方で、Stage 3の低下は、低レベルtelemetryだけでは復元が難しいことを示している。アラート要約行は、最終的な行動出力としては使わないが、探索空間を絞るインデックスとして機能している可能性が高い。したがって、今後は、アラート要約に依存しない探索戦略、例えばprocess tree、registry path、timestamp window、known persistence pattern を組み合わせたquery planningを強化する必要がある。

また、Stage 2で完全なrecallを得た場合でも candidate claim precision は低く、過剰な周辺行動の混入が課題である。復元パイプラインには、候補行動を広く拾う探索能力だけでなく、主行動列と近傍行動を分離する選別能力が必要である。特に、同一プロセス周辺のSquirrel/Discord関連処理や、Run key以外の近傍レジストリ操作をどのように除外するかが重要となる。

## 6. おわりに

本稿では、少数のSOC調査起点からWindows endpoint logを探索し、証跡付き行動列を復元するエージェント型パイプラインを評価した。Discord Run key persistence 事例では、gpt-5.4-mini がfull DB条件で14/14の主要行動要素を復元したが、順序は1/2に留まった。一方、CBC alert summary rowsを除外すると性能が低下し、アラート要約が探索経路として重要であることが示された。今後は、複数事例への拡張、低レベルtelemetryのみからの探索強化、主行動列と近傍行動の分離精度向上を進める。

## 未記入・要確認

- 著者名、所属、連絡先。
- FITの申込区分: 一般論文か選奨論文か。
- 関連研究節に入れる文献。
- 図: パイプライン全体図、Stage条件図、結果表。
- ページ数: 2ページ狙いか4ページ以上狙いか。
