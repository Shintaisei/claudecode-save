# Official 23-Chain Use Case Index

This file defines the formal FIT2026 evaluation scope. The official set is 23 behavior chains, not the legacy 27-chain candidate set.

## Scope

| item | value |
| --- | ---: |
| official behavior chains | 23 |
| official gold steps | 65 |
| stages per chain | 3 |
| official stage cases | 69 |

## Scenario Groups

| scenario group | count | chain types |
| --- | ---: | --- |
| explicit_execution_chain | 15 | python_simplehttpserver_network_chain; cmdexe_other_chain |
| multi_step_chain | 7 | dns_packet_capture_batch_chain; sublime_python_script_execution_chain |
| semantic_interpretation_chain | 1 | discord_run_key_registry_chain |

## Excluded Legacy Chains

- `chain_03_e02_dns_packet_capture_batch_chain`
- `chain_08_e06_sublime_python_script_execution_chain`
- `chain_20_e14_dns_packet_capture_batch_chain`
- `chain_27_e19_dns_packet_capture_batch_chain`

## Official Chain List

| chain_id | group | chain_type | window_utc | focus | steps |
| --- | --- | --- | --- | --- | ---: |
| `chain_01_e01_dns_packet_capture_batch_chain` | multi_step_chain | dns_packet_capture_batch_chain | 2022-07-15T13:15:00Z - 2022-07-15T13:20:00Z | cmd.exe | 3 |
| `chain_02_e01_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-15T13:15:00Z - 2022-07-15T13:20:00Z | python.exe | 2 |
| `chain_04_e03_dns_packet_capture_batch_chain` | multi_step_chain | dns_packet_capture_batch_chain | 2022-07-15T20:55:00Z - 2022-07-15T21:00:00Z | cmd.exe | 2 |
| `chain_05_e03_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-15T20:50:00Z - 2022-07-15T20:55:00Z | python.exe | 2 |
| `chain_06_e04_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-16T13:05:00Z - 2022-07-16T13:10:00Z | python.exe | 2 |
| `chain_07_e05_sublime_python_script_execution_chain` | multi_step_chain | sublime_python_script_execution_chain | 2022-07-16T13:25:00Z - 2022-07-16T13:35:00Z | cmd.exe; python.exe | 10 |
| `chain_09_e07_cmdexe_other_chain` | explicit_execution_chain | cmdexe_other_chain | 2022-07-16T15:05:00Z - 2022-07-16T15:10:00Z | cmd.exe | 2 |
| `chain_10_e07_discord_run_key_registry_chain` | semantic_interpretation_chain | discord_run_key_registry_chain | 2022-07-16T15:05:00Z - 2022-07-16T15:10:00Z | reg.exe | 3 |
| `chain_11_e07_sublime_python_script_execution_chain` | multi_step_chain | sublime_python_script_execution_chain | 2022-07-16T14:55:00Z - 2022-07-16T15:00:00Z | cmd.exe; python.exe | 6 |
| `chain_12_e08_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-16T18:35:00Z - 2022-07-16T18:40:00Z | python.exe | 2 |
| `chain_13_e09_dns_packet_capture_batch_chain` | multi_step_chain | dns_packet_capture_batch_chain | 2022-07-16T21:10:00Z - 2022-07-16T21:25:00Z | cmd.exe | 5 |
| `chain_14_e09_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-16T21:15:00Z - 2022-07-16T21:20:00Z | python.exe | 2 |
| `chain_15_e10_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-17T13:30:00Z - 2022-07-17T13:35:00Z | python.exe | 2 |
| `chain_16_e11_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-17T14:35:00Z - 2022-07-17T14:40:00Z | python.exe | 2 |
| `chain_17_e12_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-17T17:50:00Z - 2022-07-17T17:55:00Z | python.exe | 2 |
| `chain_18_e13_dns_packet_capture_batch_chain` | multi_step_chain | dns_packet_capture_batch_chain | 2022-07-17T21:00:00Z - 2022-07-17T21:05:00Z | cmd.exe | 2 |
| `chain_19_e13_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-17T20:55:00Z - 2022-07-17T21:00:00Z | python.exe | 2 |
| `chain_21_e15_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-18T13:25:00Z - 2022-07-18T13:30:00Z | python.exe | 2 |
| `chain_22_e16_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-18T17:45:00Z - 2022-07-18T17:50:00Z | python.exe | 2 |
| `chain_23_e17_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-18T18:50:00Z - 2022-07-18T18:55:00Z | python.exe | 2 |
| `chain_24_e18_cmdexe_other_chain` | explicit_execution_chain | cmdexe_other_chain | 2022-07-18T21:05:00Z - 2022-07-18T21:10:00Z | cmd.exe | 3 |
| `chain_25_e18_dns_packet_capture_batch_chain` | multi_step_chain | dns_packet_capture_batch_chain | 2022-07-18T21:00:00Z - 2022-07-18T21:05:00Z | cmd.exe | 3 |
| `chain_26_e18_python_simplehttpserver_network_chain` | explicit_execution_chain | python_simplehttpserver_network_chain | 2022-07-18T21:00:00Z - 2022-07-18T21:05:00Z | python.exe | 2 |

## Gold Step Files

- `official_23_chain_gold_steps.csv`: one row per official gold behavior step.
- `official_23_chain_gold_steps.json`: JSON form of the same step index.
- `chain_summary.csv`: canonical official 23-chain summary.
- `chain_gold_index.json`: canonical official 23-chain index.
- `legacy_27_chain_summary.csv` and `legacy_27_chain_gold_index.json`: retained only for traceability.
