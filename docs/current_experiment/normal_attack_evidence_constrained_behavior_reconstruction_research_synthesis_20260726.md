# 正常・攻撃を共通評価する証拠制約付き行動復元研究

## 1. この文書の目的

本書は、正常行動復元実験とATLASv2攻撃行動復元実験を、同一の研究目的、
行動表現、入力契約、評価指標で論理的に接続するための統合成果物である。

本研究で評価する対象は、与えられた中立的なprocess/time起点から、
観測ログに基づく行動列を復元する能力である。モデルに与えていない
「どのCBCアラートに対応するGoldか」を推測する能力は評価対象にしない。

2026-07-26時点の攻撃`attack8_paired`実行は、Goldおよび採点計算の監査には
合格したが、Stage 2/3の時刻anchorとケース識別に問題があった。そのため、
現在の攻撃結果は診断runとして保存し、正常・攻撃の正式比較には修正版を用いる。

## 2. 研究目的

### 2.1 目標

正常・攻撃が混在する環境において、分析者が判断に用いるログ調査と、
証拠付き行動列の構成を自動支援する。

### 2.2 研究目的

正常由来行動と攻撃シナリオ由来行動を、共通の行動表現と評価指標で扱える
証拠制約付き行動復元基盤を構築する。

### 2.3 実験目的

- マルチAgentシステムについて、入力情報を段階的に削減したときの
  行動要素、順序、根拠証跡の復元性能を評価する。
- 観測上つながらない行動を一つの系列へ結合する過剰接続を評価する。
- 正常・攻撃に共通する失敗と、それぞれに固有の失敗傾向を明らかにする。
- CBCアラート要約の有無が行動復元に与える影響を評価する。ただし、
  非提示アラートとGoldの対応関係を当てる能力は採点しない。

### 2.4 研究質問

1. 同一の中立的なprocess/time起点とGoldに対して、アラート要約の提示・発見可能性・
   非表示は、行動要素、順序、証拠の復元にどの程度影響するか。
2. 正常行動と攻撃行動で、再現率、適合率、順序復元、証拠回収にどのような差があるか。
3. 多段攻撃、Living off the Land、同名プロセスの反復出現は、
   取りこぼしや過剰接続をどのように増加させるか。
4. Agentは調査可能範囲を十分に探索してから結論を出しているか。

## 3. 追加実験で使用するユースケース

### 3.1 選定方法

1. 正規ツールを含み、プロセス、コマンド、通信の相関が必要となる
   単一ホスト上の多段攻撃として、ATLASv2 S3、S4を選定した。
2. Living off the Land手法を含む多段階マルウェア実行を対象とした。
3. 同一攻撃シナリオから、異なる調査開始プロセスと証跡構造を持つケースを作成した。
4. 各Gold stepは、元`incident.db`のcanonical一次テレメトリへ直接対応させた。

Living off the Landとは、正規用途でも利用されるプログラムや機能を悪用して
攻撃を進める手法である。正規利用と攻撃利用の双方に現れ得るため、
本研究の正常・攻撃共通評価に適している。

### 3.2 攻撃ユースケース

| ID | シナリオ | 起点プロセス | 対象とする場面 | Gold step |
|---|---|---|---|---:|
| S3-1 | S3 | `winword.exe` | 文書処理のみを復元する境界ケース | 3 |
| S3-2 | S3 | `regsvr32.exe` | Equation Editorからremote SCTまでのローダ系列 | 3 |
| S3-3 | S3 | `regsvr32.exe` | PowerShell・payload・C2までの長い攻撃系列 | 8 |
| S3-4 | S3 | `powershell.exe` | 攻撃途中から後段を追跡するケース | 7 |
| S4-1 | S4 | `winword.exe` | Word親子関係と外部通信を含む文書起点 | 3 |
| S4-2 | S4 | `winword.exe` | 複数のWordローカル処理を分離するケース | 5 |
| S4-3 | S4 | `mshta.exe` | mshtaからpayload・C2までの長い攻撃系列 | 9 |
| S4-4 | S4 | `powershell.exe` | PowerShell中間起点からpayload・C2まで | 7 |
| **合計** | **2シナリオ** | **4種類** |  | **45** |

### 3.3 Goldの意味

Goldは「時間窓内に存在する全イベント」ではなく、観測された親子関係、
command、file、registry、network objectで接続された採点対象行動列である。

別の実在clusterを出力した場合は、次の二つを分離して記録する。

- `observed_but_out_of_target_chain`: ログには存在するが対象chain外
- `unsupported_or_fabricated`: ログで裏づけられない

前者を後者と同じ「幻覚」として扱わない。

## 4. 正常・攻撃共通の実験契約

### 4.1 評価単位

評価単位はCBCアラートではなく、観測証拠で接続されたbehavior chainとする。
Stage 1/2/3で、同じchain、Gold、host、focus process、neutral anchor、
時間窓を使用する。

neutral anchorは、モデルから見える一次テレメトリ上のprocess/time起点とする。
選択アラートの非可視ID、非可視ラベル、非提示アラートとの対応関係は使用しない。

対象chainは次の規則で一意化する。

> focus processについて、neutral anchor時刻に存在する、または最も近い
> 観測イベントを起点とし、観測されたparent/child、command、target-object edgeで
> 接続されたcomponentを復元する。

### 4.2 Stage条件

| 条件 | 初期手掛かり | 調査中に利用可能なデータ | 想定する実務場面 | 評価する能力 |
|---|---|---|---|---|
| Stage 1：明示的アラート起点 | 共通neutral anchor＋代表アラート | アラート要約と一次テレメトリ | EDRアラート直後の一次トリアージ | 検知コンテキストを利用して、対象chainを証拠付きで復元できるか |
| Stage 2：潜在的アラート利用 | Stage 3と同じ共通neutral anchor | アラート要約は検索・発見可能。一次テレメトリも利用可能 | process/timeを引き継いだ統合ログ調査 | 初期提示されない補助情報を探索しつつ、対象chainを復元できるか |
| Stage 3：アラート要約非依存 | 共通neutral anchor | アラート要約は利用不可。一次テレメトリは利用可能 | process pivot、threat hunting、ユーザー申告、事後調査 | アラート名・検知理由に依存せず、一次証拠から対象chainを復元できるか |

Stage 2でアラートを発見したかどうかは調査過程の補助診断として記録できる。
ただし、非提示アラートとGoldの対応関係は得点化しない。Stage 3にも同じGoldを
適用できるのは、対象chainがneutral anchorで既に一意化されているためである。

### 4.3 時間窓

既存の正常23-chain実験は、21件が5分、1件が10分、1件が15分の
finalized chain windowを用いている。Stage 2/3のtimestampはwindow startと一致し、
そのwindowは対象chainの局所行動へ整列している。

攻撃8-chainのGold spanは最大約3分1秒である。したがって、正式主実験では
正常系と同じ選定方法を使い、neutral anchorから始まる5分のchain-complete
local windowを原則とする。5分でGoldが収まらない場合だけ、事前規則に従って
10分、15分へ延長する。

10分固定窓は、時間窓拡大への頑健性を確認する追加分析に使用できるが、
正常系との主比較条件にはしない。30分のアラート中心窓は、同名プロセスの
別clusterを多数含むため主比較から除外する。

### 4.4 調査完了条件

Agent呼び出し回数の上限は設けない。ただし、無制限設定だけでは調査継続を
保証しないため、次を機械的に検証する。

- 宣言window全体に対するfocus process横断検索が実行済みである。
- `process_name`だけでなく、parent、child、command line、object、
  network、file、registryの各関係列を確認済みである。
- `code_steps=[]`を返す場合、window全体のcoverage証跡を必須にする。
- 最終stepは実際のevent timestampとsource rowを保持する。
- 別componentは観測edgeがない限り接続しない。

## 5. 評価方法

### 5.1 行動表現

各Gold stepを次の要素へ分解する。

- subject
- action
- object
- critical evidence

critical evidenceは行動要素の分母へ混ぜず、独立指標とする。

### 5.2 主指標

| 指標 | 評価対象 |
|---|---|
| Action recall | Goldのsubject/action/objectをどれだけ回収したか |
| Candidate precision | 出力したsubject/action/object/evidence claimのうち、対象Goldに対応した割合 |
| Action F1 | Action recallとCandidate precisionの調和平均 |
| Behavior sequence order | Gold order pairを正しい順序で復元した割合 |
| Critical evidence recall | canonical一次証跡をどれだけ保持したか |
| Temporal evidence accuracy | stepの実時刻または対応event identityが正しいか |
| Cross-component overconnection | 観測edgeのない別clusterを因果接続した件数 |

`behavior_step_recall`は少なくとも一要素を回収したstepの粗いcoverageとして
副指標に残すが、主結論にはAction recallを用いる。

### 5.3 採点しない項目

- 非提示アラートとGoldの対応関係
- アラート名の推測
- シナリオラベルや悪性ラベルの推測
- 観測証拠だけでは確定できない攻撃成功、C2、exfiltration、意図

### 5.4 集計

- chain単位のmacro平均と、全Gold itemを合算するmicro集計を併記する。
- 正常・攻撃で同じscorer、同じCodex review手順、同じ分母規則を使用する。
- 正式比較では同じモデル、reasoning effort、replicate数を使用する。
- pilotの1反復は妥当性確認用とし、論文の正式値は原則3反復とする。

## 6. 現在までの結果

### 6.1 正常行動復元

現在の23-chain、3-run component rubric集計における`gpt-5.4-mini`の結果は
次のとおりである。

| Stage | Action recall | Critical evidence | Order | Candidate precision |
|---|---:|---:|---:|---:|
| Stage 1 | 0.791 | 0.574 | 0.579 | 0.559 |
| Stage 2 | 0.800 | 0.754 | 0.540 | 0.597 |
| Stage 3 | 0.802 | 0.779 | 0.540 | 0.594 |
| **全Stage** | **0.798** | **0.703** | **0.553** | **0.584** |

3反復のAction recallは0.822、0.802、0.769、Candidate precisionは
0.563、0.545、0.629だった。

### 6.2 攻撃行動復元の診断run

2026-07-26の`gpt-5.4-mini attack8_paired replicate_01`は24/24 run、
Codex正式採点24/24、Gold 45行の元DB照合不一致0である。

| Stage | Action recall | Order | Critical evidence | Candidate precision |
|---|---:|---:|---:|---:|
| Stage 1 | 0.207407 | 0.055556 | 0.088889 | 0.241758 |
| Stage 2 | 0.037037 | 0.000000 | 0.000000 | 0.028369 |
| Stage 3 | 0.088889 | 0.027778 | 0.066667 | 0.218182 |
| **全Stage** | **0.111111** | **0.027778** | **0.051852** | **0.132404** |

ただし、Stage 2/3ではpaired builderが元のアラート時刻anchorを削除し、
30分window startをtimestampへ設定した。Gold先頭はその9.30–12.74分後にあり、
Agentはwindow全体を検索せず早期停止した。また、S4 Wordでは同じ入力窓内の
別の実在clusterを採用した。

したがって、この表は現行実装の診断結果であり、正常行動復元との性能差や
攻撃行動の難しさを示す正式比較値として使用しない。

### 6.3 現時点で言えること

- Goldのログ転記誤りは低得点の原因ではない。
- 無制限Agent callは、十分な時間範囲探索を保証しない。
- 広い窓と同名プロセスの反復は、別の実在clusterの選択を増やす。
- 現scorerは、実在する対象外clusterと未観測claimを十分に分離していない。
- timestamp非採点は、誤った時刻の行動に部分得点を与え得る。

## 7. 考察

### 7.1 正常・攻撃に共通する失敗

- subject/action/objectの一部だけを回収し、完全なstepを構成できない。
- canonical event ID、source row、実timestampを最終出力へ保持できない。
- 同時間帯の実在イベントを過剰に列挙し、対象chainのprecisionを下げる。
- 観測された親子・object edgeより、プロセス名や時間的近接を優先する。
- Agentが検索可能範囲を使い切らず、早期に調査を終了する。

### 7.2 正常行動に固有または強く現れる失敗

- 正常な管理操作、ブラウザ、ネットワークサービスの定型行動を過小評価する。
- 一見重要性の低いfile、registry、service操作を省略する。
- アラート要約がないと、日常的な複数操作から対象chainを選ぶ優先度が下がる。

### 7.3 攻撃行動に固有または強く現れる失敗

- `winword.exe`、`regsvr32.exe`、`mshta.exe`、`powershell.exe`など
  正規ツールを含む長い親子系列を途中で切る。
- loader、PowerShell、payload、network connectionを別々に発見しても、
  一つの観測chainとして統合できない。
- 同名プロセスが短時間に反復すると、別clusterを対象chainとして選択する。
- 近傍のDNS logging、packet capture、Office初期化など、実在する別行動を混入する。
- connection creationから、攻撃成功、C2、download完了等を過剰推論し得る。

### 7.4 攻撃と正常を通した考察

本研究の中心的な比較は、「正常か攻撃かを分類できるか」ではなく、
同じ証拠制約下で行動構造をどれだけ復元できるかである。

正常・攻撃の双方で、単一イベントの抽出よりも、複数ログをsubject/action/objectへ
正規化し、観測edgeだけで順序付ける部分が主要なボトルネックになると考えられる。
攻撃では多段性、Living off the Land、同名プロセス反復によって、
探索深度とcomponent分離の負荷が増える。一方、正常では重要度の低そうな操作を
省略する傾向がGold回収率を下げる可能性がある。

この主張を定量的に確定するには、修正版attack runを正常系と同じ入力・採点条件で
実行する必要がある。現時点では仮説および診断所見として扱う。

## 8. 正式比較へ向けたロードマップ

### Phase 1: 契約修正

1. 非提示アラートとGoldの対応関係を採点対象から除外する。
2. 8 chainすべてに一次テレメトリ由来のneutral anchorを固定する。
3. 5分のchain-complete local windowを作成する。
4. Stage 1/2/3でchain、Gold、anchor、windowを完全一致させる。
5. S4 Wordはanchor近傍のconnected component規則でW1とW2/W3を識別する。

### Phase 2: 機械的preflight

1. 全45 Gold行が各Stage adapterから取得可能であることを確認する。
2. 各Gold行がwindow内にあることを確認する。
3. neutral anchorが各chainを一意に識別することを確認する。
4. 別chainの実在イベントがGoldへ混入していないことを確認する。
5. 空回答前のwindow coverage gateをテストする。
6. alert ID、alert名、非可視selection provenanceがStage 2/3入力へ漏れていないことを確認する。

### Phase 3: pilot

1. `gpt-5.4-mini`、reasoning指定なし（正常系と同じrunner既定値）、
   1反復、24 runを実行する。
2. Agent call上限は設けない。
3. Codex二重レビューと第三レビューを実施する。
4. 正常23-chainの既存結果と同じcomponent rubricで採点する。
5. target-chain識別、時間coverage、candidate分類の品質ゲートを監査する。

### Phase 4: 正式比較

pilotが全gateを通過した後、攻撃側も3反復へ拡張する。
同じモデル・反復数・scorerで正常と攻撃を比較し、Stage、chain長、
起点プロセス、証跡種別ごとに分析する。

### Phase 5: 論文成果物

- 実験目的
- ユースケース選定
- 共通実験契約
- 評価方法
- 正常結果
- 攻撃結果
- 正常・攻撃の比較
- 失敗事例
- 妥当性への脅威
- 再現手順と監査証跡

を本書の構成に沿って論文本文へ反映する。

## 9. 正式比較の採用基準

次をすべて満たすrunだけを正式比較へ採用する。

- Stage別ケース数が同一
- 同じchain Goldを全Stageで使用
- neutral anchorとwindowが全Stageで同一
- 非提示アラート対応関係を採点していない
- Gold全行がadapterに存在
- 全runがvalid JSON
- Agent call上限なし
- window coverage gate通過
- timestamp/event identityを監査可能
- Codex二重レビュー、第三レビュー、独立監査完了
- 正常・攻撃で同じ指標定義とscorerを使用

この条件を満たすまで、現在の攻撃診断runと正常行動復元結果を
「攻撃は正常より難しい」という結論へ直接使用しない。

## 10. neutral-anchor・5分窓pilotの実装状況

2026-07-26に、旧30分paired suiteを上書きせず、次のversioned suiteを作成した。

- case:
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_neutral5_stage_cases_20260726.jsonl`
- Gold:
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_neutral5_gold_20260726`
- manifest:
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_neutral5_manifest_20260726.json`
- build validation:
  `docs/current_experiment/atlasv2_s3_s4_attack8_neutral5_build_validation_20260726.json`

本suiteの復元対象は、focus processを含み、neutral anchorから観測された
parent/child、process identity、command、target-object edgeで接続できる
behavior componentである。提示されていないalert ID、alert名、alert理由、
alert-to-Gold対応関係の推測は採点しない。

preflightでは次を確認した。

- 24 case、Stage別8/8/8、全Stageで同じ8 chain
- unique Gold step 45、Stage横断135
- 各chainのneutral anchor、focus process、5分window、Goldが全Stageで同一
- 全45 canonical evidenceが各5分window内
- `(scenario, host, focus process, anchor秒)`の衝突0
- 原本`incident.db`の45行について13 field、計585比較で不一致0
- Stage 2/3入力へのalert field漏洩0
- `alert_mapping_scored=false`
- `max_investigations/max_questions/max_queries=null`
- `agent_call_limit_policy=unbounded_by_experiment`

実行時promptでは、5分範囲を参考情報ではなく主評価範囲とし、最終化前に
範囲全体を列挙すること、同名プロセスの近傍componentを観測edgeなしに
結合しないことを明示した。Stage 1の代表alertは追加の観測手掛かりであり、
主timestampはStage 2/3と同じneutral anchorである。alert発行時刻が
behavior windowより遅れる場合も、alert対応推測を評価しない。

第1反復は次の結果先で実行を開始した。

`docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_neutral5/gpt54mini_replicate_01`

本反復の結果は24 run完了、JSON妥当性、Codex component-rubric二重レビュー、
必要な第三レビュー、独立監査が完了するまで正式結果として採用しない。

## 11. neutral5第1反復の品質ゲートとnormal-parity v2

neutral5第1反復は24/24 runを生成し、Stage別件数は8/8/8、run-level errorは
0件だった。しかし、厳格監査では`S4-4 / Stage 2`の最終`output_text`が
JSON文字列の途中で切れており、valid JSONは23/24だった。対象runの総output
tokenは11,856であり、複数Agent応答のうち最終統合応答が
`max_tokens=8192`へ到達したことによる切断である。

また、先に完了したS3の12 runをCodex独立review1/2とblind review3で採点した
診断値は次のとおりだった。

| Stage | Runs | Action recall | Order | Critical evidence | Candidate precision |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 4 | 0.381 | 0.118 | 0.143 | 0.351 |
| Stage 2 | 4 | 0.365 | 0.118 | 0.286 | 0.329 |
| Stage 3 | 4 | 0.476 | 0.176 | 0.333 | 0.226 |
| **S3合計** | **12** | **0.407** | **0.137** | **0.254** | **0.287** |

この値は攻撃側の正式性能値として採用しない。原因はモデル能力だけではなく、
第1反復の契約に正常系との不一致が二つ残っていたためである。

1. 正常23-chain runは`max_tokens=24576`だったが、攻撃第1反復は8192だった。
2. 攻撃promptは5分窓全体の列挙を要求し、さらにprocess identityをcomponent
   edgeに含めた。この組合せにより、同じprocessが実行したroutine file、
   registry、module操作まで主行動列へ入り、Gold外candidateとして数えられた。
   正常系の評価単位は全audit rowではなく、実行・コマンド・対象オブジェクトで
   進む意味的behavior chainである。

そこでGold 45行、neutral anchor、5分windowを変更せず、境界定義だけを
versioned contractとして次へ修正した。

- case:
  `data/current_experiment/cases/atlasv2_s3_s4_attack8_neutral5_parity_v2_stage_cases_20260726.jsonl`
- Gold:
  `data/current_experiment/gold/atlasv2_s3_s4_attack8_neutral5_parity_v2_gold_20260726`
- validation:
  `docs/current_experiment/atlasv2_s3_s4_attack8_neutral5_parity_v2_build_validation_20260726.json`
- result:
  `docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_neutral5_parity_v2/gpt54mini_replicate_01_v2`

normal-parity v2では、5分windowを正常系と同じ探索補助情報として扱い、
全rowの出力を要求しない。主行動鎖はobserved parent/child、command、
target-object edgeで展開する。同じprocess名/PIDは同一意味操作を裏付ける
複数rowの統合には使えるが、それだけで付随操作を独立stepへしない。
付随する観測済みrowは`excluded_nearby_evidence`へ分離する。

v2 preflightは24 case、Stage別8/8/8、neutral anchor一意8、Gold 45、
全Goldの5分window内包含、Stage 2/3 alert漏洩0、原本DBとの585 field比較
不一致0でpassした。実行条件は`gpt-5.4-mini`、reasoning指定なし、
`max_tokens=24576`、Agent call上限なしである。Agent call上限だけは
ユーザー指定により正常履歴runの数値上限を継承せず、実験側では無制限とする。
## 12. Observable-component v3：正式比較へ移行するための確定契約（2026-07-26）

### 12.1 旧45-step Goldを正式値に使わない理由

旧Goldの各値は原DB行と一致していたが、意味的成分の網羅性監査では8ケース中7ケースに行動欠落があった。また、旧S4-2は観測上接続していないW2とW3を、非公開の旧ケース設計だけで一つに束ねていた。これはStage 3の入力から一意に決定できない。

したがって、旧run・旧Gold・旧スコアは診断履歴として保持するが、正常系との正式比較値には採用しない。時間窓を10分へ広げるだけでは、別成分の混入を増やすため解決にならない。

### 12.2 v3で固定した評価単位

評価単位は、neutral anchorが触れる一次テレメトリ上の「観測可能な意味的成分」である。parent/child、command target、network target、後続実行物のmaterializationを辿る。同一PID・同一プロセス名・時間的近接だけでは接続しない。センサ重複行と同一ファイルの連続lifecycle行は一つの意味的stepへ畳み、module load、MRU、一般的なregistry/cache housekeepingは付随証跡として主系列から除外する。

同じ攻撃成分へ異なるfocus processから入るS3-3/S3-4およびS4-3/S4-4は、Gold行動列を同一にした。これにより、モデルへ与えていない「どこで系列を打ち切るか」を推測させない。旧S4-2は、anchorが実際に選ぶW2だけのケースへ改め、独立したW3は接続しない。

### 12.3 v3ユースケース

| ID | focus process | 観測可能な対象成分 | Gold step |
|---|---|---|---:|
| S3-1 | `winword.exe` | 文書open、一時RTF処理、子Word生成 | 4 |
| S3-2 | `regsvr32.exe` | DCOM/Equation Editor、regsvr32、remote SCT通信 | 3 |
| S3-3 | `regsvr32.exe` | regsvr32からSCT、PowerShell、payload、C2まで | 11 |
| S3-4 | `powershell.exe` | S3-3と同じ成分をPowerShellから調査 | 11 |
| S4-1 | `winword.exe` | Word親子、文書open、外部通信 | 4 |
| S4-2 | `winword.exe` | WerFault起点のW2 Word成分 | 4 |
| S4-3 | `mshta.exe` | mshta、HTA、PowerShell、payload、C2まで | 11 |
| S4-4 | `powershell.exe` | S4-3と同じ成分をPowerShellから調査 | 11 |
| **合計** |  |  | **59** |

### 12.4 Stage条件と採点除外

- Stage 1は、正常系の過去実験と同様に、見えている代表アラートを探索開始情報として表示する。
- Stage 2はhost、focus process、neutral anchor、5分scopeを初期情報とし、アラート要約は検索可能である。
- Stage 3は同じprocess/time scopeを使うが、アラート要約を利用不可にする。
- すべてのStageでGold、5分scope、評価単位は同一である。
- 与えられていないCBC alert ID、title、reason、Goldとの対応関係を推測する能力は、hitにもmissにも数えない。
- アラート要約は行動stepの代替証拠にしない。

### 12.5 共通評価指標

- Action recall：Goldのsubject/action/objectの回収数 ÷ Goldのsubject/action/object数。
- Candidate precision：出力されたsubject/action/object slotのうち正しいslot数 ÷ 出力subject/action/object slot数。
- Order recall：隣接Gold pairを、別々のGold-aligned candidate claimとして正順に復元した割合。
- Critical evidence recall：固定したCBC一次テレメトリfingerprintの回収率。Action分母とは分離する。
- Duplicate TP rate：正しいが同一Gold itemを重複して述べたcandidate slotの割合。
- Cross-component overconnection：観測edgeのない別成分を主系列へ接続した件数。

command lineは行動claimの属性であり、独立candidate slotにはしない。candidate claimはactor instance、operation family、target path/endpoint、orderにより最大一つのGold stepへalignする。GoldがPIDを指定する場合、プロセス名だけではsubject hitにしない。`false_positive_type`は診断ラベルであり、review多数決の成否には使わない。

### 12.6 preflight結果と本番1反復

- case：`data/current_experiment/cases/atlasv2_s3_s4_attack8_observable_component_v3_stage_cases_20260726.jsonl`
- Gold：`data/current_experiment/gold/atlasv2_s3_s4_attack8_observable_component_v3_gold_20260726`
- build validation：`docs/current_experiment/atlasv2_s3_s4_attack8_observable_component_v3_build_validation_20260726.json`
- result root：`docs/current_experiment/results_2026-07-26/atlasv2_s3_s4_attack8_observable_component_v3/gpt54mini_replicate_01_v3`

preflightは24ケース、Stage別8/8/8、Gold 59 step、Stage別action分母177、critical evidence分母59、order分母51、DB 826 field比較不一致0、Stage 3一意性8/8、同一成分別anchorのGold同一性2/2でpassした。`max_tokens=24576`、三つのAgent呼出し上限はすべて`null`、`agent_call_limit_policy=unbounded_by_experiment`である。

この契約はモデル出力を見る前に固定した。精度が正常系へ近づくまでGoldやpromptを事後調整するのではなく、まずこの1反復を正式pilotとして完了し、差が残る場合は事前登録した別version・別replicateで原因仮説を検証する。

### 12.7 v3第1反復のrun完了

`gpt-5.4-mini`の第1反復は24/24件、Stage別8/8/8で完了した。
output JSONは24/24件が妥当、run errorは0、stderrは0 byte、
Agent呼出し上限なし設定は24/24件で確認した。input/output tokenは
268,140/84,923、合計353,063 token、費用はUSD 0.5832585である。

モデルが出力したcode stepはStage 1/2/3で29/25/20、合計74であり、
0 stepはStage 2で1件、Stage 3で2件あった。この値は採点値ではなく、
出力規模の診断である。正式な再現率・適合率・順序・critical evidenceは、
固定queueに対するCodex二重reviewと不一致裁定の完了後に記載する。

上限なしであっても、Agentが必要なだけ調査するとは限らない。
本反復でChief Agentが実際に呼んだ`investigate_lead`はStage 1/2/3で
8/12/11回であった。0 stepの一例では、存在しない`host`列を使ったSQLと
広すぎる検索を再構成せず終了した。したがって、今後の考察では時間窓だけでなく、
queryのschema遵守、失敗後の再試行、長系列の後段pivot完了を独立に扱う。

採点queueのSHA-256は
`bbe862ad318595889f8fcf1e4a7e7695bb7f84e29d0313ec2f4d62964e189869`
であり、未提示アラート対応推測を全件で採点外に固定した。

## 13. Observable-component v3第1反復の正式結果

Codex sub-Agent 2名が24件を独立reviewし、item-level完全一致7件を直接採用、
差を含む17件を第三Codexが独立reviewした。項目単位2-of-3により24/24件を
採用し、未解消conflict、stale、rejectedは0である。3者のcandidate alignmentが
すべて異なった7 itemは、事前規則どおりhitを保守的に0とした。

| Stage | Action recall | Candidate precision | Critical evidence recall | Order recall |
|---|---:|---:|---:|---:|
| Stage 1 | 15/177 = **0.0847** | 15/86 = **0.1744** | 4/59 = **0.0678** | 3/51 = **0.0588** |
| Stage 2 | 23/177 = **0.1299** | 22/75 = **0.2933** | 8/59 = **0.1356** | 3/51 = **0.0588** |
| Stage 3 | 15/177 = **0.0847** | 16/60 = **0.2667** | 8/59 = **0.1356** | 3/51 = **0.0588** |
| **Overall** | **53/531 = 0.0998** | **53/221 = 0.2398** | **20/177 = 0.1130** | **9/153 = 0.0588** |

component別Action recallはsubject 13/177 = 0.0734、operation 25/177 =
0.1412、object 15/177 = 0.0847であった。candidate TP 53のうちunique Gold
itemは52、duplicate TPは1である。

### 13.1 具体例：S3-2 Stage 2

Goldは、(1) DcomLaunch PID 648からEQNEDT32 PID 6032、
(2) EQNEDT32 PID 6032からregsvr32 PID 6124、
(3) regsvr32 PID 6124からremote SCTの
`ortrta.net / 10.193.66.115:8080`接続、の3 stepである。

モデルは(2)をPID付きで復元し、(3)のprocess、URL、domain/IP/portも取得した。
しかし(1)を落とし、(3)のoperationをnetwork connectionではなく
「URLを指定して実行」と表現し、さらにroutineな`counters.dat`を主系列へ
追加した。結果はAction recall 5/9 = 0.5556、Critical evidence 2/3 =
0.6667、Order 1/2 = 0.5、Candidate precision 5/9 = 0.5556である。

## 14. 考察

### 14.1 Stage差

Stage 2がAction recallとCandidate precisionで最良だった。Stage 1の
アラート要約は今回の平均性能を上げず、Stage 3はアラートを利用できなくても
Stage 1と同じAction recall、より高いcritical evidence recallを示した。
したがって、主な失敗原因は「アラート要約がないこと」だけではない。

Stage 1では、特にWord周辺でtemporary file、Recent link、Office cacheを
主系列へ混ぜた。アラートが調査開始の助けになる一方、同時刻近傍を広く
関連付けるバイアスも生じたと解釈できる。

### 14.2 系列長と失敗の型

3–4 stepの短系列12 runはAction recall 0.1185、Candidate precision 0.1280、
11 stepの長系列12 runはAction recall 0.0934、Candidate precision 0.3854
であった。長系列では後段pivot前に調査を終えるためrecallが低いが、
少数の比較的確かなstepだけを出すためprecisionは高い。短いWord系列では
出力step数は多いが、housekeeping混入によってprecisionが低い。

S3/S4別のAction recallは0.1149/0.0852、Candidate precisionは
0.2952/0.1897である。S4ではWord、WerFault、Office一時ファイルが近接し、
親子edge・document object・network targetを同時に満たす成分だけを
切り出すことが難しかった。

### 14.3 なぜ「30分与えたのに調べない」ように見えたか

旧30分窓の問題は、時間が足りないことではなく、同名processと別成分が増えて
境界が曖昧になることだった。v3は5分窓に縮め、全Goldが窓内にあることを
事前検証した。それでも低性能だった。

Agent呼出し上限は全件`null`で、実際の`investigate_lead`はStage別8/12/11回
である。ところが、存在しない`host`列を使ったSQL、広すぎる検索を絞り直さない、
上流または後段のedgeを消費する前に終了する、といった失敗が残った。
これは「時間窓が大きい」「Agent回数を制限した」ことではなく、query生成、
失敗後の再試行、完了条件の問題である。10分へ広げるだけでは改善せず、
別成分の混入を増やす可能性が高い。

## 15. 正常と攻撃を通した考察

正常・攻撃に共通する難所は、process名の発見ではなく、
観測edgeに基づいてactor/action/objectを同じstepへ束ね、余計な近傍rowを
切ることである。攻撃固有には、Living off the Landにより
`winword.exe`、`regsvr32.exe`、`powershell.exe`等の正規processが使われ、
正規housekeepingと攻撃成分の境界がさらに曖昧になる。また長い攻撃系列では、
一つの正しいpivotを見つけても、payload materializationとC2まで追い切れない。

一方、今回の値を公表済み正常系overall
（Action 0.798、evidence 0.703、order 0.553、precision 0.584）と
そのまま差分検定してはならない。入力Stageと主指標の構造は揃えたが、
attack v3 scorerはGold PID指定時のname-onlyを不一致とし、candidate slotを
subject/action/objectだけに固定した。正常系の過去reviewはcontent-inclusion型で、
完全なitem-level provenanceも207件中69件に限られる。

したがって、本反復から正式に言えるのは、attack v3内でStage 2が最良であり、
全Stageで系列境界、actor instance、後段pivotが弱いことまでである。
正常と攻撃の正式な数値比較には、正常系の少なくとも1反復を同じv2 rubricで
再reviewするか、正常・攻撃の両方を同じ新共通rubricで再reviewする必要がある。
攻撃側のGoldやpromptを正常の精度へ近づけるために事後調整するのではなく、
比較rubricを両側へ適用する。

採点に参加していないCodex sub-Agentによるread-only最終再計算監査はpassした。
正式採用24/24、未解消0、alert mapping採点item 0であり、正式aggregateの
SHA-256は`42cac9ea7d6697125c74b5816ad09bcce23aef86d673a66d1e5b515f3ed29770`
である。

## 16. 正常・攻撃を同一条件にした正式pilot

### 16.1 実験目的と実験の接続

本研究の目標は、正常・攻撃が混在する環境で、分析者が判断に用いるログ調査と
証拠付き行動列の構成を自動支援することである。そのため、正常由来行動と
攻撃シナリオ由来行動を共通の行動表現と評価指標で扱う必要がある。

この目的に対し、observable-component v3では、両群を次の共通契約で実行した。

- モデルは`gpt-5.4-mini`
- 8ユースケース×3 Stage、各群24 run、各群1反復
- focus processに実際に触れる中立anchorから5分窓
- Goldは一次テレメトリから一意に確認できる意味行動
- 行動はsubject/action/object、順序、critical evidence、candidate precisionで評価
- 与えられていないCBC alert ID・title・reasonとGoldの対応推測は採点外
- Stage 1だけ代表alertを初期提示し、Stage 2は検索可能、Stage 3は利用不可
- `max_investigations`、`max_questions`、`max_queries`は`null`
- Agent呼出しは`unbounded_by_experiment`
- 採点は外部judge APIを使わず、Codex独立二重reviewと不一致時の第三review

したがって、本実験は攻撃分類の正しさではなく、同じ証拠制約下で正常行動と
攻撃行動をどの程度復元できるかを比較する。

### 16.2 正常側の追加ユースケース

正常側は過去23-chainから、プロセス起動、script、file、network、registryを含み、
一次テレメトリだけで5分窓内の対象成分を固定できる8件を事前選定した。

| ID | 対象成分 | Gold step |
|---|---|---:|
| N1 | HTTP batch起動 | 3 |
| N2 | DNS packet capture | 7 |
| N3 | HTTP listener | 2 |
| N4 | persistent HTTP connection | 1 |
| N5 | Discord rendererから`cmd.exe` | 1 |
| N6 | Discord Run key | 2 |
| N7 | Sublimeから`hello.py`実行 | 3 |
| N8 | HTTP batchとlistener | 4 |
| **合計** |  | **23** |

攻撃側はATLAS v2 S3/S4の8件、Gold 59 stepである。両群とも、module load、
MRU、一般的なcache/housekeeping、同時刻に近いだけの別component、センサ重複を
主行動列から除外した。Gold step数の差はユースケース難度の一部であり、結果を
見た後に同数へ調整していない。

## 17. 正常observable-component v3の実行と採点

### 17.1 run品質

正常側の第1反復は24/24件、Stage別8/8/8で完了した。output JSONは24/24件で
妥当、run error 0、stderr 0、Agent上限なし設定24/24である。入力258,400、
出力63,615、合計322,015 token、費用USD 0.4800675、code step 52、
code step 0件のrunは3件であった。

Codex review1/review2は24/24件を独立採点し、19件は完全一致、5件をblindな
第三reviewで項目単位2-of-3裁定した。正式採用24/24、未解消0、保守fallback 0、
duplicate TP 0、alert mapping採点item 0である。

### 17.2 正常側の正式結果

| Stage | Action recall | Candidate precision | Behavior-step recall | Order recall | Critical evidence recall |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 11/69 = **0.1594** | 11/33 = **0.3333** | 5/23 = **0.2174** | 0/15 = **0.0000** | 0/23 = **0.0000** |
| Stage 2 | 25/69 = **0.3623** | 25/63 = **0.3968** | 12/23 = **0.5217** | 5/15 = **0.3333** | 8/23 = **0.3478** |
| Stage 3 | 17/69 = **0.2464** | 17/60 = **0.2833** | 10/23 = **0.4348** | 3/15 = **0.2000** | 2/23 = **0.0870** |
| **Overall** | **53/207 = 0.2560** | **53/156 = 0.3397** | **27/69 = 0.3913** | **8/45 = 0.1778** | **10/69 = 0.1449** |

component別Action recallはsubject 13/69 = 0.1884、operation 26/69 =
0.3768、object 14/69 = 0.2029である。正常側でもactor instanceとobjectの
同定がoperationより弱い。

### 17.3 正常側の具体例

N2 Stage 2のGoldは、`explorer.exe`→`cmd.exe`、batch script実行、DNS log
directory作成、`cmd.exe`→`tshark.exe`、interface-discovery用`dumpcap.exe`、
DNS capture worker、pcapng生成の7 stepである。

モデルはbatch実行、directory作成、DNS capture、pcapng生成を4 candidateに
まとめ、Action recall 10/21 = 0.4762、Candidate precision 10/12 = 0.8333、
Critical evidence 5/7 = 0.7143、Order 2/6 = 0.3333となった。一方、
`explorer.exe`→`cmd.exe`と`cmd.exe`→`tshark.exe`を独立stepにせず、
短命なinterface-discovery workerも落とした。これは、行動の概要は合っていても、
親子edgeとPID単位の系列が欠落する失敗である。

## 18. 正常・攻撃の同条件比較

| 指標 | 正常 | 攻撃 | 正常−攻撃 |
|---|---:|---:|---:|
| Action recall | 53/207 = **0.2560** | 53/531 = **0.0998** | **+0.1562** |
| Candidate precision | 53/156 = **0.3397** | 53/221 = **0.2398** | **+0.0999** |
| Behavior-step recall | 27/69 = **0.3913** | 29/177 = **0.1638** | **+0.2275** |
| Order recall | 8/45 = **0.1778** | 9/153 = **0.0588** | **+0.1190** |
| Critical evidence recall | 10/69 = **0.1449** | 20/177 = **0.1130** | **+0.0319** |

正常は攻撃よりAction recallで2.57倍、Behavior-step recallで2.39倍、
Order recallで3.02倍であった。両群のTP action slotは偶然同じ53だが、
攻撃Goldは531 componentと長く、後段pivotとPID edgeを多数落としたため
recallが低い。Candidate precisionも正常0.3397、攻撃0.2398であり、攻撃では
Living off the Landに使われる正規process周辺のhousekeepingを主系列へ接続する
誤りが増えた。

ただしcritical evidenceの差は小さい。Stage 1とStage 3では攻撃が正常を上回る
ため、根拠行の提示能力だけで「正常の方が容易」とは言えない。主な差は、根拠を
発見した後に正しいactor/objectへ束ね、長い系列として最後まで接続する能力にある。

Stage 2は両群で最良であった。アラートを初期答えとして与えず、必要なら検索できる
条件が、過剰なalertアンカリングを抑えながら調査の補助情報を残した可能性がある。
ただし1反復であり、Stage差の統計的有意性は主張しない。

## 19. 結論と次のロードマップ

本pilotから、共通表現による正常・攻撃の比較基盤は構築できた。一方、
`gpt-5.4-mini`の復元性能は正常でも十分高くなく、攻撃ではさらに低下した。
原因は30分窓やAgent呼出し上限ではない。5分窓・上限なしでも、query schema誤り、
失敗後の再試行不足、系列途中での終了、PID省略、近接rowの過剰接続が残った。

次の追加実験は、Goldやpromptを観測結果へ合わせて調整するのではなく、
事前登録した別versionで次を切り分ける。

1. query schemaを固定して失敗時retryを要求する条件
2. 観測edge frontierが空になるまで調査完了を許さない条件
3. actor PID、parent/child PID、targetを必須出力にする条件
4. 同一契約の複数反復による分散評価

時間窓を10分へ広げることは第一選択ではない。現行5分窓には全Goldが含まれており、
拡大すると別component混入を増やす可能性が高い。10分窓は、5分窓でGoldが欠ける
別ユースケースに対する事前登録済み感度分析としてのみ扱う。

正式比較成果物は
`docs/current_experiment/normal_attack_observable_component_v3_formal_comparison_20260726.json`
および同名`.md`である。比較JSONのSHA-256は
`70e6e10a9a725dd813250ac1fcbf13c32199a6ee530d24665d399180387a878b`である。
