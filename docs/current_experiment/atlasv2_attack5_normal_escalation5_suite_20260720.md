# ATLASv2 攻撃・正常境界 10ユースケース（Stage 3）

## 目的

既存の正常行動23ユースケースを補完し、次の二つを同じ Stage 3 条件で評価する。

1. アラート起点から、観測ログだけで攻撃に関係する行動列を復元できるか。
2. 一見通常操作に見える局所文脈を復元した後、同じ host・時間窓にある別系列の要確認証拠を示し、「通常として閉じるには不十分」と報告できるか。

モデルに渡す情報は host・focus process・5分窓のみである。CBC alert の要約・理由・ラベル、および ATLAS シナリオ説明は渡さない。

## 構成

| 群 | 件数 | 対象 | 評価すること |
|---|---:|---|---|
| Attack reconstruction | 5 | ATLASv2 S3 | 直接のアラート起点から攻撃関連の証跡付き行動列を復元できるか |
| Normal-context to escalation | 5 | S3 1件、S4 4件 | 通常に見える文脈と、別系列の同時観測証拠を分けて示せるか |
| 合計 | 10 | 4つのインシデントエピソード | 23件の正常行動セットと結合すると33入力 |

「10件」は10個のモデル入力であり、10個の独立した攻撃ではない。S3の複数入力と、S4の N2A02--N2A05 は同じインシデントの異なる調査起点で重複する。結果は入力単位に加え、重複をまとめたエピソード単位でも報告する。

## Attack reconstruction（5件）

| ID | 起点（host / process / UTC） | 復元対象 |
|---|---|---|
| AO01 | WIN-32-H1 / winword.exe / 2022-07-19 14:33:20 | RTFを開く、テンポラリRTFの作成・削除 |
| AO02 | WIN-32-H1 / regsvr32.exe / 2022-07-19 14:33:24 | Equation Editor → regsvr32 → リモートSCT・8080接続 |
| AO03 | WIN-32-H1 / regsvr32.exe / 2022-07-19 14:36:16 | Equation Editor → regsvr32 → PowerShell、8080/8443接続 |
| AO04 | WIN-32-H1 / powershell.exe / 2022-07-19 14:36:16 | regsvr32 → PowerShell → cmd / 子payload、9999接続 |
| AO05 | WIN-32-H1 / winword.exe / 2022-07-19 14:33:20 | 親Word → 埋込みWord、テンポラリWMFの作成・削除 |

AO06（payload系統からの起点）は補助6件セットには残すが、分析者が選んだpayload系統起点であり、直接アラート起点の5件とは性質が異なるため、この主10件セットからは除外した。

## Normal-context to escalation（5件）

| ID | 最初に復元する局所文脈 | 別系列として報告すべき同時観測証拠 | 重複クラスタ |
|---|---|---|---|
| N2A01 | S3のWordによる文書操作 | EqnEdt32 → regsvr32 → リモート接続 | s3_word_regsvr32 |
| N2A02 | S4のWordによるテンプレート・文書操作と接続 | svchost → mshta → PowerShell → payload | s4_word_mshta_payload |
| N2A03 | S4で再起動したWordによる文書操作と接続 | svchost → mshta → PowerShell → payload | s4_word_mshta_payload |
| N2A04 | S4のWerFault → Wordとテンプレート操作 | svchost → mshta → PowerShell → payload | s4_word_mshta_payload |
| N2A05 | S4の後続Wordによる文書操作と接続 | svchost → mshta → PowerShell → payload | s4_word_mshta_payload |

この5件の「通常に見える」起点は、評価オーケストレーションが既知アラートの近傍から選んだものであり、モデルが正常ログだけから自律的に攻撃を発見する条件ではない。アラート内容は隠す。したがって主張は「局所的な通常説明だけではクローズ不十分であることを、ログ上の別系列証拠とともに示せるか」であり、「正常ログから自律的に攻撃を発見した」ではない。

さらに、局所文脈と要確認証拠の間には明示的な親子・コマンドライン・対象オブジェクトの接続がない場合がある。goldでは両者を別segmentとして保持し、segmentをまたぐ順序正解は置かない。モデル入力にも、因果を推論せず co-observed escalation evidence として報告するよう明記する。

## 正解データと検証

- 10 chain、68 evidence step。
- 各stepは元DBの行IDだけでなく、時刻・表・canonical evidence fieldsを照合して検証済み（68/68 pass）。
- Stage 3では CBC alert summary rowsをSQLから除外し、CBC EDR/NGAV telemetryは利用可能。
- N2Aの5入力について、実際のdry-run clueに「別系列として報告」「因果を推論しない」が含まれること、および期待行動・攻撃プロセス名等がclueに漏れていないことを確認済み。

## 実行単位

- 10件のみ: `atlasv2_attack5_normal_escalation5_stage3_cases_20260720.jsonl`
- 正常23件との結合: `cbc_23_plus_atlasv2_attack5_normal_escalation5_stage3_cases_20260720.jsonl`
- 採点時は `suite_group`（attack_reconstruction / normal_to_escalation）と `overlap_cluster_id` を必ず分けて集計する。

この文書はユースケース定義と検証状態の記録であり、モデル性能の結果ではない。実モデル実行・採点は未実施である。
