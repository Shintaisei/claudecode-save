# Scenario taxonomy

## Raw chain types

The experiment starts from five raw chain types:

| Raw chain type | Meaning |
|---|---|
| `dns_packet_capture_batch_chain` | cmd/batch starts packet capture related tools such as tshark/dumpcap |
| `python_simplehttpserver_network_chain` | Python SimpleHTTPServer behavior and network serving evidence |
| `sublime_python_script_execution_chain` | Sublime/editor-driven Python script execution chain |
| `cmdexe_other_chain` | cmd.exe-centered miscellaneous command behavior |
| `discord_run_key_registry_chain` | Discord/Update.exe and registry Run key behavior |

## Analysis grouping

For interpretation, the five raw types are grouped into three higher-level classes:

| Analysis group | Raw chain types | Reason |
|---|---|---|
| Explicit execution chain | `python_simplehttpserver_network_chain`, `cmdexe_other_chain` | command line and parent-child process evidence are relatively direct |
| Multi-step tool chain | `dns_packet_capture_batch_chain`, `sublime_python_script_execution_chain` | multiple tools, scripts, files, and process steps must be connected |
| Semantic interpretation chain | `discord_run_key_registry_chain` | registry/app-specific semantics must be interpreted |

## Stage is not scenario type

`stage1`, `stage2`, and `stage3` are input/start-condition settings. They are separate from scenario type.
