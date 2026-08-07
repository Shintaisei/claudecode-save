# Detailed Discussion Draft 2026-06-14

この文書は、発表・論文用の考察の土台。数値は `03_aggregated_results/` と `04_discussion_base/deep_dive_20260614/` に基づく。現時点では「考察ドラフト」であり、最終本文では図表番号と文章量を調整する。

## Scope And Caveats

本比較の主対象は、`gpt-4.1-mini`、`gpt-5.4-mini`、`gpt-5.5 low raw` の3系列である。ただし、比較条件は完全には同一ではない。

| model | scope | treatment |
| --- | ---: | --- |
| gpt-4.1-mini | 207 runs | formal23 rep1+rep2 + legacy27 filtered-to-current-23 |
| gpt-5.4-mini | 207 runs | formal23 rep1+rep2 + legacy27 filtered-to-current-23 |
| gpt-5.5 low raw | 69 runs | replicate_01 only; raw text salvage; output contract failed |

したがって、`gpt-4.1-mini` と `gpt-5.4-mini` の比較は比較的強く言える。一方、`gpt-5.5 low raw` は内容回収力の参考値としては重要だが、構造化JSONを守った正式条件の比較ではない。

## M1. Overall Accuracy

**主張。** `gpt-5.4-mini` は `gpt-4.1-mini` より、行動再現・証跡回収・順序・適合率の全指標で明確に高い。`gpt-5.5 low raw` はさらに高いrecall/orderを示すが、raw salvageかつ1反復なので別枠で扱う。

| model | runs | action | evidence | order | precision | overclaim |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 207 | 0.466 | 0.195 | 0.201 | 0.366 | 1190 |
| gpt-5.4-mini | 207 | 0.798 | 0.703 | 0.553 | 0.584 | 651 |
| gpt-5.5 low raw | 69 | 0.940 | 0.928 | 0.889 | 0.667 | 350 |

**解釈。** `gpt-4.1-mini` は行動の断片は拾えるが、証跡と順序が大きく弱い。`gpt-5.4-mini` は証跡recallが0.703まで上がっており、ログ根拠を伴う再構成能力が明確に改善している。過剰主張も1190から651に減っており、高recall化が単に出力量増加だけで起きているわけではない。

**言える範囲。** 23チェーン対象のcomponent rubricでは、`gpt-5.4-mini` は `gpt-4.1-mini` より堅牢。`gpt-5.5 low raw` は内容抽出能力の上限候補を示す。

**言ってはいけない表現。** `gpt-5.5が正式に最良`、`GPT-5.5は実運用可能`、`4.1は使えない`。GPT-5.5は出力契約失敗を分ける必要がある。

## M2. Cost And Runtime

**主張。** `gpt-5.4-mini` は `gpt-4.1-mini` より費用はやや高いが、精度改善に対する費用対効果は良い。`gpt-5.5 low raw` は内容recallは高いが、ローカル価格表推定では費用が大きく跳ねる。

| model | runs | total cost | avg/run | input tokens | output tokens | avg duration | serial sum | 4-parallel est |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 207 | $3.6433 | $0.0176 | 6,830,288 | 569,498 | 6.81 min | 15.66 h | 3.91 h |
| gpt-5.4-mini | 207 | $4.3501 | $0.0210 | 2,042,236 | 626,317 | 2.05 min | 4.65 h | 1.16 h |
| gpt-5.5 low raw | 69 | $30.9974 | $0.4492 | 1,827,906 | 728,595 | 9.32 min | 10.72 h | 2.68 h |

**費用表の注意。** 4.1/5.4のformal23分はcost log実費、legacy27 filtered分はrun tokenとローカル価格表による推定を含む。GPT-5.5はcost log上の費用が0で記録されていたため、全件ローカル価格表による推定である。

**時間表の注意。** runtimeは全runで取得できているわけではない。4.1-miniは138/207 runs、5.4-miniは136/207 runs、GPT-5.5は69/69 runsのみdurationを持つ。したがって、4.1/5.4の時間値はlegacy27 filtered分を含まない観測可能runの集計であり、3セット全体の完全な実測時間ではない。

**費用対効果。**

| model | cost/action hit | cost/evidence hit | cost/order hit | cost/precision hit |
| --- | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | $0.0045 | $0.0320 | $0.0479 | $0.0053 |
| gpt-5.4-mini | $0.0031 | $0.0106 | $0.0208 | $0.0048 |
| gpt-5.5 low raw | $0.0564 | $0.1713 | $0.2768 | $0.0442 |

**解釈。** `gpt-5.4-mini` は1runあたり費用が `gpt-4.1-mini` より約19%高いが、evidence hitあたり費用は約1/3、order hitあたり費用は約1/2以下である。実行時間も平均2.05分/runで、4.1の6.81分/runより短い。`gpt-5.5 low raw` はrecallが高いが、費用対効果では明確に重い。

**言える範囲。** 本条件では、精度・観測可能な実行時間・ローカル価格表を含む推定費用の総合では `gpt-5.4-mini` が最もバランスが良い。ただし、費用はログ実費と推定の混在であり、時間は4.1/5.4でduration欠損を含む。

**言ってはいけない表現。** `GPT-5.5は高いから不要`。高recallの参考値としては重要だが、費用と形式失敗の制約がある、という書き方にする。

## M3. Stage Effects

**主張。** `gpt-5.4-mini` はstage1からstage3まで大きく崩れない。特にstage3でevidence recallが0.779まで上がっている点は、CBC alert summaryがなくてもnon-alert telemetryから必要証跡を拾えている可能性を示す。

| model | stage | runs | action | evidence | order | precision | overclaim |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | stage1 | 69 | 0.639 | 0.292 | 0.341 | 0.433 | 422 |
| gpt-4.1-mini | stage2 | 69 | 0.414 | 0.128 | 0.111 | 0.285 | 506 |
| gpt-4.1-mini | stage3 | 69 | 0.345 | 0.164 | 0.151 | 0.382 | 262 |
| gpt-5.4-mini | stage1 | 69 | 0.791 | 0.574 | 0.579 | 0.559 | 215 |
| gpt-5.4-mini | stage2 | 69 | 0.800 | 0.754 | 0.540 | 0.597 | 213 |
| gpt-5.4-mini | stage3 | 69 | 0.802 | 0.779 | 0.540 | 0.594 | 223 |
| gpt-5.5 low raw | stage1 | 23 | 0.954 | 0.908 | 0.905 | 0.679 | 113 |
| gpt-5.5 low raw | stage2 | 23 | 0.923 | 0.923 | 0.857 | 0.701 | 99 |
| gpt-5.5 low raw | stage3 | 23 | 0.944 | 0.954 | 0.905 | 0.626 | 138 |

**解釈。** `gpt-4.1-mini` はstage1で相対的に高いが、stage2/stage3で落ちる。これはalertや明示的な手がかりがない条件で、ログ探索・因果復元が不安定になることを示す。一方 `gpt-5.4-mini` はstage2/stage3で証跡recallが上がっており、alert文面に頼らずtelemetryを使えている可能性がある。

**言える範囲。** stage3の結果は「alert summaryが常に必要ではない」可能性を示す。ただし、これはgold側もalert-only evidenceを除外した採点である。

**言ってはいけない表現。** `alertは不要`、`stage3の方が一般に良い`。正しくは「この条件ではalert summary除去後も5.4-miniは崩れなかった」。

## M4. Scenario And Framework Effects

**主張。** 場面別では、`explicit_execution_chain` が比較的高く、`multi_step_tool_chain` は順序・証跡で難しい。`semantic_interpretation_chain` は1チェーンしかないため、一般化せず事例扱いにする。

| model | scenario | chains | runs | action | evidence | order | precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | explicit_execution_chain | 15 | 135 | 0.501 | 0.237 | 0.243 | 0.351 |
| gpt-4.1-mini | multi_step_tool_chain | 7 | 63 | 0.428 | 0.158 | 0.176 | 0.382 |
| gpt-5.4-mini | explicit_execution_chain | 15 | 135 | 0.865 | 0.824 | 0.764 | 0.640 |
| gpt-5.4-mini | multi_step_tool_chain | 7 | 63 | 0.746 | 0.602 | 0.431 | 0.469 |
| gpt-5.5 low raw | explicit_execution_chain | 15 | 45 | 0.971 | 0.978 | 0.958 | 0.650 |
| gpt-5.5 low raw | multi_step_tool_chain | 7 | 21 | 0.903 | 0.903 | 0.861 | 0.681 |

**解釈。** explicit executionはコマンド実行やサービス起動など、イベント列と行動の対応が比較的明示的である。multi-step tool chainは複数のツールやプロセスをまたぐため、行動の一部は拾えても、順序と証跡の完全性が落ちやすい。

より細かいframeworkでは、`network_service_behavior` で `gpt-5.4-mini` が action 0.885 / evidence 0.842 / order 0.803 と高い。これは13チェーン117runsで、n数も比較的ある。一方、`persistence_registry_run_key` は1チェーン9runsなので、個別例として扱う。

**言える範囲。** 発表で強く使えるのは explicit vs multi-step、および network_service_behavior。semantic/persistenceは事例紹介に留める。

**言ってはいけない表現。** `semanticに強い/弱い`。1チェーンなので傾向とは言えない。

## M5. Model And Source-Set Variability

**主張。** 4.1/5.4の3セット統合値にはsource-set差が含まれる。特にlegacy27 filteredは、5.4では高く、4.1では証跡が低く、平均に影響している。

| model | action sd | evidence sd | order sd | precision sd | overclaim sd |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.031 | 0.121 | 0.053 | 0.039 | 88.9 |
| gpt-5.4-mini | 0.027 | 0.076 | 0.068 | 0.044 | 113.1 |

source-set別では、`gpt-5.4-mini` の legacy filtered は evidence 0.790、overclaim 90 で、formal23 rep1/rep2より良い。`gpt-4.1-mini` の legacy filtered は evidence 0.056、overclaim 495 で、formal23 rep1/rep2より悪い。

**解釈。** これは単なるモデル乱数の揺れではなく、実験ソース・ランナー条件・採点由来の差を含む。したがって「3セット統合値」または「source-set込み平均」とは書けるが、「同一条件3反復の安定性」とは書けない。

**言える範囲。** 4.1/5.4の平均は、現行23チェーン範囲に対する3セット統合値。揺れはsource-set込みの実験再現性として扱う。

**言ってはいけない表現。** `モデルの確率的揺れは小さい`。source-set差を分離していないため。

## M6. Chain-Level Instability

**主張。** 個別chainではsource-set込み3セット間の揺れが大きいものがある。これは、論文では失敗例・難例の候補として使える。ただし、formal23 rep1/rep2 と legacy27 filtered を含むため、同一条件反復の純粋な確率的ブレではない。

Top examples by mean metric SD:

| model | chain | source-set count | mean metric sd |
| --- | --- | ---: | ---: |
| gpt-4.1-mini | chain_12_e08_python_simplehttpserver_network_chain | 3 | 0.324 |
| gpt-4.1-mini | chain_18_e13_dns_packet_capture_batch_chain | 3 | 0.324 |
| gpt-4.1-mini | chain_05_e03_python_simplehttpserver_network_chain | 3 | 0.288 |
| gpt-4.1-mini | chain_23_e17_python_simplehttpserver_network_chain | 3 | 0.272 |
| gpt-5.4-mini | chain_02_e01_python_simplehttpserver_network_chain | 3 | 0.260 |

**解釈。** Python SimpleHTTPServer系とDNS packet capture系が複数上位に出ている。これらは、実行、ネットワーク待受、ファイル/プロセス証跡の対応付けが複数段になるため、どの証跡を正解成分として拾うかで揺れやすい可能性がある。

**次にやるべき確認。** 上位chainについては、run outputとgoldを並べた定性的分析を追加する。現段階では、揺れの候補抽出まで。

## M7. Reviewer Variability

**主張。** 採点そのものにも揺れがある。2レビューで完全一致して即採用できたのは379/643、第三レビューが必要だったのは264/643で、third review rateは0.411。この643 rowsは広いcomponent review queue由来であり、最終比較の483 rowsそのものとは母集団が一致しない。

| item | value |
| --- | ---: |
| exact adopted rows | 379 |
| third-review conflict rows | 264 |
| total rows with two reviews | 643 |
| exact adoption rate | 0.589 |
| third review rate | 0.411 |

衝突が多いfieldは、`overclaim_slot_count` 205件、`candidate_claim_precision_hits` 152件、`action_step_recall_hits` 112件である。

**解釈。** recallそのものより、余計な主張をどこまで数えるか、候補主張の分母をどう数えるかで揺れやすい。ここでいう「Agentの揺れ」は、モデル出力側のagent behaviorではなく、Codex上で採点したReviewer A/B/Cの判断差を指す。component rubricは内容包含を許すため、実験上この主観性は避けにくい。一方、2レビュー+第三レビューで確定値を作っているため、最終表はレビュー手続きを通した値として扱える。

**言える範囲。** 採点値には主観性が残るが、単独評価ではなく二重レビューと第三レビューを通している。

**言ってはいけない表現。** `完全に客観的な採点`。正しくは「レビュー手続きで一貫性を高めた採点」。

## M8. Contract Compliance And Exclusions

**主張。** 内容回収力と出力契約遵守は分けるべきである。GPT-5.5はraw salvageでは高いが、構造化出力契約に失敗したため、運用上は別のリスクを持つ。

Queue statusでは、adopted review 379、valid unreviewed 0、invalid run 3、missing run 239が記録されている。ただしこれは広いreview queue全体の状態であり、最終比較は483 rowsを対象にしている。

**解釈。** GPT-5.5の69runは、素のテキストから内容を読めば高い。しかし、出力契約に失敗すると自動評価・下流処理・運用統合に弱い。したがって、論文では「raw content recovery」と「structured compliance」を別軸にするのがよい。

**言える範囲。** GPT-5.5は内容抽出能力の上限候補。ただし、この実験の正式出力形式では失敗している。

**言ってはいけない表現。** `GPT-5.5はすべての面で最良`。正しくは「raw salvageでは高recallだが、形式遵守・費用・過剰主張に課題がある」。

## M9. Usecase-Level Interpretation

**主張。** 集計値だけでは見えない差は、個別ユースケースを見るとかなり明確になる。詳細表は `04_discussion_base/usecase_deep_dive_20260614/usecase_deep_dive.md` に置いた。ここでは発表で使いやすい代表例だけを抜く。

| usecase | gold steps | gpt-5.4 action | evidence | order | precision | over/run | 読み取り |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| chain_23 SimpleHTTPServer | 2 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 | `python -m SimpleHTTPServer` と通信先が短い行動列として揃い、再構成しやすい代表例。 |
| chain_06 SimpleHTTPServer | 2 | 0.889 | 0.889 | 0.889 | 0.667 | 2.44 | 同じSimpleHTTPServer系でも、余計な候補は少し残るが、証跡と順序は高い。 |
| chain_10 Discord Run key | 3 | 0.642 | 0.481 | 0.333 | 0.719 | 2.00 | 短い3ステップでも、HKCU Run keyのquery/addを永続化として意味づける必要があり難しい。 |
| chain_07 Sublime Python script | 10 | 0.659 | 0.567 | 0.198 | 0.629 | 2.89 | `plugin_host.exe`、複数の`cmd.exe`、`python.exe`が連なるため、内容は拾えても順序が落ちる。 |
| chain_01 DNS packet capture | 3 | 0.790 | 0.407 | 0.667 | 0.380 | 4.89 | `start_dns_logs.bat`から`tshark.exe`までの境界が広がり、周辺ログを足しすぎてprecisionが落ちる。 |
| chain_24 run_http_server.bat | 3 | 0.741 | 0.778 | 0.556 | 0.398 | 7.56 | bat、cmd、python起動が近接し、証跡は拾えるが候補ステップを広げすぎる。 |

**解釈。** SimpleHTTPServer系のように、プロセス名・コマンド・通信先が短い連鎖で対応するケースは、5.4-miniで高い再現率と順序を出しやすい。一方でDNS/bat系やrun_http_server系は、正解行動の近くに似たcmd/bat/python/tsharkログが多く、モデルが「関係ありそうな周辺ログ」まで行動列に入れやすい。Discord Run keyはステップ数だけ見ると短いが、レジストリ永続化という意味づけが必要なので、単純なコマンド実行より難しい。

**言える範囲。** 今回の23チェーン条件では、5.4-miniは短い明示的実行連鎖を比較的安定して再構成できる。一方で、代表例を見る限り、重複プロセス・ツール連鎖・レジストリ永続化の意味解釈を含む場面では、証跡選択と余計な候補の抑制がボトルネックになりやすい。特にsemantic/persistenceは1チェーンのみなので、一般化せず個別例として扱う。

## M10. Model Argument Patterns

ユースケース別の点数だけでなく、モデルが実際にどの論点を出したかは `04_discussion_base/model_argument_deep_dive_20260614/model_argument_deep_dive.md` に整理した。抽出対象は `code_steps`、`operation`、`object`、`evidence`、`global_limitations`、`excluded_nearby_evidence` で、GPT-5.5 low rawは構造化JSONではないためraw textの見出し・仮説・観測事実から論点だけを拾っている。

主要な読み取りは、5.4-miniがSimpleHTTPServerではプロセス・コマンド・通信先を素直に論点化できる一方、DNS/bat/tshark系では「DNS収集」という大枠は出るが、cmd、bat、tshark、近傍python/http serverを同一行動列に広げやすいこと。Sublime/Python系ではSublime、cmd、python、script fileという論点は出るが、重複cmd/pythonの順序付けが弱い。Discord Run keyではregistry/Run keyという論点は立つが、query/addと永続化設定の意味づけ、親Discordとの接続が揺れる。

## M11. Investigator And SQL Trace

Investigator/QAAgent/SQLの深掘りは `04_discussion_base/investigator_sql_deep_dive_20260614/investigator_sql_deep_dive.md` に分けた。重要な制約として、正式23チェーンrunでは実行SQL文字列とrunner traceが保存されていないため、4.1-mini/5.4-miniのSQL精度は最終 `code_steps` の証跡選択からの間接評価になる。一方、GPT-5.5 low rawは構造化出力に失敗したが、69 run中66 runではraw本文にQA/質問材料が残っている。仮説や結果要約も多くのrunで復元できるが、すべてのrunで3点セットが揃うわけではない。残り3 runではraw QAは可視ではない。

この観点で見ると、5.4-miniはSimpleHTTPServer系では最終出力の証跡選択がプロセス、command_line、通信先に届きやすい。DNS/bat/tshark系では関連ログに届くが、最終証跡選択として近傍ログを広く採用し、別batやpython/http serverを混ぜやすい。Discord Run keyでは、GPT-5.5 rawの質問例から、msft-securityのreg.exe DLL accessを入口にPID 5424/5504へ絞り、CBC EDR/NGAVでcommand_lineと親Discordを確認する探索方針が見える。この方針は有効な可能性があるが、構造化最終出力ではquery/addの切り分けや順序がまだ揺れる。

## Recommended Paper Framing

1. Main result: `gpt-5.4-mini` が `gpt-4.1-mini` より、精度・費用対効果・実行時間のバランスで優れる。
2. Stage result: `gpt-5.4-mini` はalert summaryを除いたstage3でも崩れず、telemetryからの復元能力が示唆される。
3. Scenario result: explicit executionは比較的容易、multi-step tool chainは順序・証跡が難しい。
4. Reliability result: 採点者間の揺れはprecision/overclaimで大きいので、2レビュー+第三レビューが必要。
5. Limitation: 4.1/5.4の3セット目はlegacy27 filtered、GPT-5.5は1反復raw salvage、semanticは小n。

## Review Status

| section | Reviewer A | Reviewer B | status |
| --- | --- | --- | --- |
| M1 Overall accuracy | OK | OK | passed |
| M2 Cost and runtime | fix requested | fix requested | revised: duration coverage and cost-source caveats added |
| M3 Stage effects | OK | OK | passed |
| M4 Scenario effects | OK | OK | passed |
| M5 Model/source-set variability | fix requested | fix requested | revised: 3-set/source-set wording |
| M6 Chain-level instability | fix requested | fix requested | revised: source-set count and non-identical repetition caveat |
| M7 Reviewer variability | fix requested | fix requested | revised: reviewer queue scope and Agent definition added |
| M8 Contract/exclusions | OK | OK | passed |
