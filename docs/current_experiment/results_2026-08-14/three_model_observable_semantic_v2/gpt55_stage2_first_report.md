# GPT-5.5 Stage 2 再採点結果

| 対象 | 試行数 | Gold step | Action | Precision | Complete step | Evidence | Order |
|---|---:|---:|---:|---:|---:|---:|---:|
| 正常行動 | 8 | 23 | 92.75% | 47.41% | 86.96% | 82.61% | 86.67% |
| 攻撃行動 | 8 | 43 | 79.07% | 57.89% | 79.07% | 74.42% | 65.71% |

## ユースケース別

| 対象 | ユースケース | Gold step | Action | Precision | Complete step | Evidence | Order |
|---|---|---:|---:|---:|---:|---:|---:|
| 攻撃 | s3_pt_01_word_document_processing | 2 | 100.00% | 25.00% | 100.00% | 50.00% | 100.00% |
| 攻撃 | s3_pt_02_regsvr32_remote_sct | 3 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| 攻撃 | s3_pt_03_regsvr32_long_chain | 8 | 87.50% | 63.64% | 87.50% | 87.50% | 71.43% |
| 攻撃 | s3_pt_04_powershell_mid_chain | 7 | 85.71% | 60.00% | 85.71% | 85.71% | 66.67% |
| 攻撃 | s4_pt_01_word_w1 | 4 | 75.00% | 37.50% | 75.00% | 75.00% | 33.33% |
| 攻撃 | s4_pt_02_word_w3 | 3 | 66.67% | 33.33% | 66.67% | 33.33% | 50.00% |
| 攻撃 | s4_pt_03_mshta_c1 | 9 | 88.89% | 72.73% | 88.89% | 88.89% | 87.50% |
| 攻撃 | s4_pt_04_powershell_c1 | 7 | 42.86% | 75.00% | 42.86% | 42.86% | 33.33% |
| 正常 | chain_02_e01_python_simplehttpserver_network_chain | 3 | 100.00% | 75.00% | 100.00% | 100.00% | 100.00% |
| 正常 | chain_04_e03_dns_packet_capture_batch_chain | 7 | 80.95% | 80.95% | 71.43% | 71.43% | 66.67% |
| 正常 | chain_05_e03_python_simplehttpserver_network_chain | 2 | 100.00% | 50.00% | 100.00% | 100.00% | 100.00% |
| 正常 | chain_06_e04_python_simplehttpserver_network_chain | 1 | 100.00% | 50.00% | 100.00% | 100.00% | - |
| 正常 | chain_09_e07_cmdexe_other_chain | 1 | 100.00% | 9.09% | 100.00% | 100.00% | - |
| 正常 | chain_10_e07_discord_run_key_registry_chain | 2 | 100.00% | 22.22% | 100.00% | 50.00% | 100.00% |
| 正常 | chain_11_e07_sublime_python_script_execution_chain | 3 | 88.89% | 66.67% | 66.67% | 66.67% | 100.00% |
| 正常 | chain_24_e18_cmdexe_other_chain | 4 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
