# Raw Experiment Outputs

このフォルダには、今回の最終比較に関係する実験生出力をコピーしている。パス長エラーを避けるため、元フォルダ名より短い階層名にしている。

## Contents

| folder | contents | count used in final comparison |
| --- | --- | ---: |
| `f23_2rep/` | formal23 の replicate_01 / replicate_02。対象は gpt-4.1-mini と gpt-5.4-mini。 | 276 run JSON |
| `legacy27_raw/` | 旧27チェーン実験の raw_runs 一式。最終比較では現在の23チェーンにフィルタした138 run相当を3セット目として使う。 | 138 filtered from 162 raw run JSON |
| `gpt55_r1/` | GPT-5.5 low reasoning effort の replicate_01。 | 69 run JSON |
| `filtered_3run_input_manifest.json` | 4.1/5.4 の3セット集計に使った入力の manifest。 | - |

## Original Sources

| copied folder | original source |
| --- | --- |
| `f23_2rep/` | `docs/current_experiment/results_2026-06-09/formal_23_chain_experiment_2rep_20260612/` |
| `legacy27_raw/` | `public_research/clouseau_atlasv2_27chain_2026_06/raw_runs/` |
| `gpt55_r1/` | `docs/current_experiment/results_2026-06-09/formal_23_chain_gpt55_low_3rep_20260613/replicate_01/` |

## Important Scope Notes

- `gpt-4.1-mini` / `gpt-5.4-mini`: final comparison uses 3セット平均。内訳は formal23 replicate_01、formal23 replicate_02、legacy27 filtered-to-23。
- `gpt-5.5 low raw`: final comparison uses replicate_01 only。replicate_02 以降の部分実行や quota error はこの最終比較から除外。
- GPT-5.5 は出力契約に失敗しているため、raw text salvage として採点している。JSON契約を守れたという意味ではない。
