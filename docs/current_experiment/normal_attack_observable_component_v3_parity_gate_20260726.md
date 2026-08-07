# 正常・攻撃 observable-component v3 比較可能性監査

- 判定: **FAIL_REQUIRES_NEW_NORMAL_V3_RUN**
- 作成時刻: `2026-07-26T08:50:23.469075+00:00`
- 目的: 旧正常 gpt-5.4-mini 結果を攻撃 observable-component v3 と正式比較できるかを判定する。

## 結論

旧正常スコアは参考値として保持するが、攻撃v3との正式な精度差には使わない。正常側を同じGold構築規則、同じneutral anchor、同じ5分窓、同じ出力schema、同じ無制限Agent契約、同じCodex item-level採点で新規に実行する必要がある。

## 機械監査結果

- 正常ケース: 69件、Stage別 {'stage1': 23, 'stage2': 23, 'stage3': 23}、5分窓 {'5.0': 63, '10.0': 3, '15.0': 3}
- 正常Gold: 65 step、平均 2.826 step/chain
- 正常Gold代表証跡の窓内: 34/65、窓外: 31
- 正常Goldのmodule-load代理証跡: 18 step
- 正常run: 69件、output JSON valid 68/69、error 0
- 正常runのAgent上限: unbounded=False; policy={'not_recorded': 69}
- 攻撃v3: 8 chain、59 Gold step、DB照合 mismatch=0、exhaustiveness pass=8/8

## parity gate

- FAIL: all Gold canonical evidence must be inside the declared five-minute window
- FAIL: every scored action must use its own canonical primary-action row
- FAIL: every Gold step must carry canonical_evidence and PID identity
- FAIL: every Gold component must pass an independent exhaustiveness audit
- FAIL: all model runs must use agent_call_limit_policy=unbounded_by_experiment
- FAIL: all adopted runs must have valid output_text JSON

## 次の正式実験

1. 正常ユースケースを observable-component v3 で再構築し、各stepを窓内のcanonical CBC primary rowとPIDに固定する。
2. Stage 1/2/3で同一Gold・neutral anchor・5分窓を使い、alert対応関係の推測は採点しない。
3. gpt-5.4-miniを `unbounded_by_experiment`、`max_tokens=24576` で新規1反復する。
4. 攻撃v3と同じCodex item-level二重レビュー＋不一致第三レビューで採点する。
5. 同一契約で得た正常と攻撃のみを主比較に採用し、旧正常値はhistorical referenceと明記する。

精度を正常値へ合わせるための事後的なGold・prompt調整は行わない。揃えるのは測定条件であり、精度は観測結果として報告する。
