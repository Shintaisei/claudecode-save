# 正常ケース：修正前 v3 と修正後 pilot05 の同一ケース比較

## 比較条件

- 修正前：`results_2026-07-26/normal8_observable_component_v3/gpt54mini_replicate_01_v3`
- 修正後：`normal_attack_full_ledger_pilot05_formal_results_20260730`
- Gold は同じ v3 observable component Gold。
- Python HTTP ケースは、修正前・修正後とも `gpt-5.4-mini` であり、同一モデル比較が可能。
- Discord Run-key ケースは、修正前が `gpt-5.4-mini`、修正後が `gpt-4.1-mini`。モデル差が混入するため参考比較。
- 修正前の「完全 step」は Gold action coverage と独立に入力された旧方式であり、修正後の atomic な完全 step と厳密には比較できない。Action recall、Candidate precision、Critical evidence、Order を主指標とする。

## 1. Python HTTP：同一モデルでの正式比較

対象：`chain_06_e01_python_http_server_chain`、両方とも `gpt-5.4-mini`

### Stage 別

| Stage | 指標 | 修正前 | 修正後 | 増減 |
|---|---|---:|---:|---:|
| Stage 1 | Action recall | 2/9 = 22.22% | 4/9 = 44.44% | **+22.22 pp** |
|  | Candidate precision | 2/6 = 33.33% | 4/6 = 66.67% | **+33.34 pp** |
|  | 完全 step（参考） | 1/3 = 33.33% | 1/3 = 33.33% | 0.00 pp |
|  | Critical evidence | 0/3 = 0.00% | 0/3 = 0.00% | 0.00 pp |
|  | Order recall | 0/2 = 0.00% | 1/2 = 50.00% | **+50.00 pp** |
| Stage 2 | Action recall | 3/9 = 33.33% | 0/9 = 0.00% | **-33.33 pp** |
|  | Candidate precision | 3/6 = 50.00% | 0/9 = 0.00% | **-50.00 pp** |
|  | 完全 step（参考） | 2/3 = 66.67% | 0/3 = 0.00% | -66.67 pp |
|  | Critical evidence | 0/3 = 0.00% | 0/3 = 0.00% | 0.00 pp |
|  | Order recall | 1/2 = 50.00% | 0/2 = 0.00% | **-50.00 pp** |
| Stage 3 | Action recall | 2/9 = 22.22% | 0/9 = 0.00% | **-22.22 pp** |
|  | Candidate precision | 2/9 = 22.22% | 0/12 = 0.00% | **-22.22 pp** |
|  | 完全 step（参考） | 1/3 = 33.33% | 0/3 = 0.00% | -33.33 pp |
|  | Critical evidence | 1/3 = 33.33% | 0/3 = 0.00% | **-33.33 pp** |
|  | Order recall | 0/2 = 0.00% | 0/2 = 0.00% | 0.00 pp |

### 3 Stage 合計

| 指標 | 修正前 | 修正後 | 増減 |
|---|---:|---:|---:|
| Action recall | 7/27 = 25.93% | 4/27 = 14.81% | **-11.11 pp** |
| Candidate precision | 7/21 = 33.33% | 4/27 = 14.81% | **-18.52 pp** |
| 完全 step（参考） | 4/9 = 44.44% | 1/9 = 11.11% | -33.33 pp |
| Critical evidence | 1/9 = 11.11% | 0/9 = 0.00% | **-11.11 pp** |
| Order recall | 1/6 = 16.67% | 1/6 = 16.67% | 0.00 pp |

### 何が起きたか

- Stage 1 は明確に改善した。修正前は Python 実行 chain の一部だけだったが、修正後は対象 step の完全取得と次 step の object まで進み、隣接 order も1組取得した。
- Stage 2・3 は逆に全項目を失った。修正後 run は、対象の `cmd PID 336 → run_http_server.bat → python PID 720` ではなく、約38秒前の近傍 DNS capture chainである `cmd PID 3344 → start_dns_logs.bat → tshark → dumpcap` を選択した。
- Chief の複数 lead と frontier closure は機能していたが、最初に選んだ誤った process instance を深掘りした。したがって、今回の修正は「探索を継続できない問題」を解消した一方、「初期 anchor／instance 選択の誤りを途中で再検証して戻る問題」は解消していない。
- 結論として、同一モデル比較では全体精度は上がっていない。Stage 1 の改善より、Stage 2・3 の instance-selection failure の影響が大きい。

## 2. Discord Run-key：モデル差を含む参考比較

対象：`chain_04_e02_discord_runkey_chain`

- 修正前：`gpt-5.4-mini`
- 修正後：`gpt-4.1-mini`

### Stage 別

| Stage | 指標 | 修正前 | 修正後 | 増減 |
|---|---|---:|---:|---:|
| Stage 1 | Action recall | 3/6 = 50.00% | 0/6 = 0.00% | **-50.00 pp** |
|  | Candidate precision | 3/3 = 100.00% | 0/18 = 0.00% | **-100.00 pp** |
|  | 完全 step（参考） | 1/2 = 50.00% | 0/2 = 0.00% | -50.00 pp |
| Stage 2 | Action recall | 0/6 = 0.00% | 3/6 = 50.00% | **+50.00 pp** |
|  | Candidate precision | 0/6 = 0.00% | 3/6 = 50.00% | **+50.00 pp** |
|  | 完全 step（参考） | 0/2 = 0.00% | 1/2 = 50.00% | +50.00 pp |
| Stage 3 | Action recall | 1/6 = 16.67% | 6/6 = 100.00% | **+83.33 pp** |
|  | Candidate precision | 1/15 = 6.67% | 6/15 = 40.00% | **+33.33 pp** |
|  | 完全 step（参考） | 1/2 = 50.00% | 2/2 = 100.00% | +50.00 pp |

Critical evidence と Order recall は、修正前・修正後とも全 Stage で 0%。

### 3 Stage 合計

| 指標 | 修正前 | 修正後 | 増減 |
|---|---:|---:|---:|
| Action recall | 4/18 = 22.22% | 9/18 = 50.00% | **+27.78 pp** |
| Candidate precision | 4/24 = 16.67% | 9/39 = 23.08% | **+6.41 pp** |
| 完全 step（参考） | 2/6 = 33.33% | 3/6 = 50.00% | +16.67 pp |
| Critical evidence | 0/6 = 0.00% | 0/6 = 0.00% | 0.00 pp |
| Order recall | 0/3 = 0.00% | 0/3 = 0.00% | 0.00 pp |

### 解釈

- 修正後 Stage 3 は両 Gold step の全 action component を取得し、Action recall 100%に達した。
- 一方、近傍行動も多く候補化したため precision は40%。さらに2 step の順序を逆に接続し、Order recall は0%だった。
- Stage 1 は修正前より悪化しており、正しい Run-key chain ではなく近傍の Discord housekeeping／別時刻の registry instance に寄った。
- 大幅改善は確認できるが、モデルが異なるため、frontier-closure 修正だけの効果とは断定できない。

## 3. 研究発表向けの結論

1. **探索継続性は改善した。** Chief が複数 lead を生成し、1論点だけで終了する旧障害は解消している。
2. **精度向上は一様ではない。** 同一モデル・同一ケースの Python では Action recall が25.93%から14.81%へ低下した。
3. **主な残課題は初期 instance selection。** 誤った近傍 chain を選ぶと、追加の lead と SQL query がその誤りを深く掘るため、探索量の増加が recall 改善につながらない。
4. **正しい chain に入れた場合の回収能力は高い。** Discord Stage 3 では Action recall 100%まで回復した。ただし precision 40%、Order 0%で、過剰接続と因果順序が残る。
5. **次の改善軸は探索数の増加ではない。** anchor 時刻、process instance、親子関係を複数候補間で再検証し、低確信時に別 instance へ pivot する制御が必要。

## 4. 比較上の注意

- 1ケース・1 replicate の Stage 比較なので、差分にはモデルの確率的変動が含まれる。
- Discord はモデル差を含むため、architecture ablation としては扱わない。
- 修正前の完全 step は、現在の `subject / operation / object` の unique candidate-TP coverage から決定論的に導出する方式ではない。スライドの主比較には Action recall と Candidate precision を使用する。
- 修正前の不具合実験は無駄ではなく、「探索停止」と「誤 instance を継続探索する失敗」が異なる障害であることを示す比較対照として利用できる。
