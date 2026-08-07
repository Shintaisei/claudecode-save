# ATLASv2: 真陽性5・偽陽性5 CBCアラート起点ユースケース

## 設計目的

実際のCBCアラートを入力として調査を開始し、次を分けて評価する。

1. 真陽性アラートでは、攻撃に対応する証跡付き行動列を復元し、調査をエスカレーションできるか。
2. 偽陽性アラートでは、アラートの検知対象を通常行動として説明し、アラートを閉じられるか。
3. 偽陽性アラートを閉じる場合でも、同じホストの後続攻撃証跡があれば、ホスト調査を閉じずに分離して報告できるか。

真陽性・偽陽性のラベルは、CBC規則名の印象ではなく、**CBCアラート対象プロセスのATLASv2 process-level ground truth**で決めた。

## 入力

各入力には一つの実在する `cbc_alerts` 行を渡す。入力項目は、アラート時刻・名前・理由・対象プロセス・PID・severity・hostと、定義済みの調査時間範囲である。ground truth、正解行動列、ATLASシナリオ説明は渡さない。

全10入力・全エージェントには同一のシステムプロンプト方針を適用する。入力アラートに対応する行動を復元した上で、指定host・時間範囲内にアラート判断またはホスト判断へ影響する別系列の行動があるかを確認する。ただし、攻撃の存在や悪性を仮定せず、明示的な接続証拠がない系列間の因果も主張しない。

## 真陽性アラート起点（5入力）

| ID | CBC alert row | アラート | 根拠となる攻撃行動 | cluster |
|---|---:|---|---|---|
| TP01 | 21 | regsvr32 / suspicious LOLBin | Equation Editor → regsvr32 → remote SCT/connection | s3_regsvr32_6124 |
| TP02 | 4 | regsvr32 loading scrobj.dll | Equation Editor → regsvr32 → PowerShell | s3_regsvr32_3992_powershell |
| TP03 | 7 | PowerShell Invoke-Expression | regsvr32 → PowerShell → cmd/payload | s3_regsvr32_3992_powershell |
| TP04 | 18 | mshta launching script interpreters | mshta → PowerShell → connection → cmd | s4_mshta_powershell |
| TP05 | 16 | hidden/encoded PowerShell | mshta → PowerShell → connection → cmd | s4_mshta_powershell |

TP02/TP03、TP04/TP05は同一攻撃エピソード内のネストした異なるアラート起点である。5件を独立した5攻撃とは数えない。

## 偽陽性アラート起点（5入力）

| ID | CBC alert row | アラート | アラート対象の通常行動 | cluster |
|---|---:|---|---|---|
| FP01 | 2 | LLMNR/NBT-NS poisoning traffic | svchostによるLLMNR multicast通信 | s3_benign_llmnr |
| FP02 | 3 | command/scripting interpreter | `start_dns_logs.bat` によるtshark起動 | s3_dns_capture_startup |
| FP03 | 10 | packet capture tools | tsharkによるdumpcap起動 | s3_dns_capture_startup |
| FP04 | 13 | packet capture tools | DNSログ取得のためのtshark起動 | s3_dns_capture_startup |
| FP05 | 14 | packet capture tools | tsharkによるdumpcapのインタフェース列挙 | s3_dns_capture_startup |

FP02--FP05は同じDNSログ取得系列であり、FP03--FP05は同じpacket-capture CBC alert identityに属する。したがって、偽陽性群は5つのalert-target-row入力だが、一意なCBC alert identityは3件であり、独立行動エピソードは主に2クラスタである。

## 偽陽性群における「攻撃近傍」の扱い

全10入力で、偽陽性・真陽性を問わず、CBCアラート作成時刻の6分前〜10分後の16分を調査範囲とする。これは、アラート生成がテレメトリより遅れるためアラート対象行動を遡って確認しつつ、同じS3ホストで後続する悪性文書の攻撃を確認できるようにするためである。この16分条件は、既存の5分Stage 3実験とは時間・コストを直接比較しない探索的なStage 1条件である。

正解では次を明確に分離する。

- **alert-level disposition:** 偽陽性アラートは `close_alert`
- **host-level disposition:** 後続の `EqnEdt32 → regsvr32 → remote connection` は別系列として `escalate_host_investigation`

この二つの行動列に親子・コマンドライン・対象オブジェクトの接続がない限り、因果関係は主張しない。つまり「偽陽性アラートを閉じる」と「ホスト全体のインシデントを閉じる」を区別する実験である。

全Stage 1入力のモデル出力には `triage_decision.alert_disposition` と `triage_decision.host_disposition` を必須とし、各1点、計2点で別々に採点する。これにより、行動列の復元だけでなく、閉鎖判断とホスト調査判断を混同していないかを評価する。

## 検証状態

- 10 alert-origin inputs、全入力で実CBCアラートを入力に含める Stage 1条件。
- 各アラートは、CBCの時刻・ID・名前・stream・severity・対象process/PID等の不変フィールドと、ATLASv2 CSV上の `scenario + PID + path` ラベルを照合する。
- 各行動証跡は、DBの時刻・表・canonical evidence fieldsまで照合する。
- 上記に判断rubricと時間窓の整合を加え、84/84項目が検証済み。
- 10件の公式runner dry-runを完了。
- 実際のモデル入力で、各アラートの名前が見えること、GTラベルが漏れないこと、FP5件ではアラート判断とホスト判断を分ける指示が入ることを確認済み。

これはユースケース定義・入力監査までの状態であり、モデル性能の本実験・採点は未実施である。
