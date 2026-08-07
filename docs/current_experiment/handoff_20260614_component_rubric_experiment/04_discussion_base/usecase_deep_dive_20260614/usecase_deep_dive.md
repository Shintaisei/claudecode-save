# ユースケース別詳細考察 2026-06-14

集計単位は1ユースケース単位。gpt-4.1-mini / gpt-5.4-miniは各ユースケースにつき3ステージ x 3 source set = 9行平均。gpt-5.5 low rawは3ステージ x 1周 = 3行平均で、構造化出力に失敗した素の出力を救済採点した参考値。

## 読み方

- `action`: 主体・行動・対象の内容再現率。
- `evidence`: 重要証跡の再現率。
- `order`: 行動列の順序再現率。
- `precision`: 候補として出した主張の適合率。
- `over/run`: 1 runあたりの余計な主張数。

## 難度ラベル別の件数

- `easy_or_well_reconstructed`: 8ユースケース
- `hard_or_unstable`: 3ユースケース
- `mixed`: 1ユースケース
- `moderate_reconstructable`: 10ユースケース
- `overclaim_prone`: 1ユースケース

## 代表的な読み取り

- SimpleHTTPServer系は、IP/portなど通信先まで証跡として拾えるケースでは5.4-miniが高く、再構成しやすい場面の代表。
- DNS packet capture系は、`start_dns_logs.bat` と `tshark.exe` の境界を広げすぎやすく、actionは上がってもprecisionが伸びにくい。
- Sublime/Python script系は、cmd/pythonの重複ステップが多く、証跡は拾えても順序スコアが低くなりやすい。
- Discord Run keyは、レジストリ永続化という意味づけが必要で、短い3ステップでも難ケースとして残る。

## ユースケース別メモ

### 1. chain_01_e01_dns_packet_capture_batch_chain

- 場面: DNS packet capture batch execution
- 分類: `multi_step_tool_chain` / `collection_or_tool_invocation`
- 正解ステップ数: 3
- 正解の骨子: `explorer.exe -> cmd.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\start_dns_logs.bat" " | start_dns_logs.bat | tshark.exe`
- 難度ラベル: `hard_or_unstable`
- 何を見る場面か: Explorer/cmd起点で `start_dns_logs.bat` を起動し、DNSログ取得のためのバッチ実行を追うユースケース。tshark実行まで含むため、`cmd.exe`、bat、`tshark.exe` のどこまでを同一行動として切るかで過剰出力が出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.370 | 0.222 | 0.167 | 0.270 | 8.11 |
| gpt-5.4-mini | 0.790 | 0.407 | 0.667 | 0.380 | 4.89 |
| gpt-5.5 low raw | 0.667 | 0.667 | 0.667 | 0.400 | 12.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。証跡または順序が弱く、単に行動名を当てるだけでは正解にならない難ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 1.000 | 0.333 | 1.000 | 0.667 | 2.00 |
| stage2 | 0.630 | 0.222 | 0.333 | 0.400 | 4.00 |
| stage3 | 0.741 | 0.667 | 0.667 | 0.212 | 8.67 |

### 2. chain_02_e01_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 待受/通信先詳細は限定的`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、通信先詳細はgold側で明示しにくいケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.370 | 0.222 | 0.111 | 0.171 | 10.78 |
| gpt-5.4-mini | 0.889 | 0.722 | 0.556 | 0.534 | 3.78 |
| gpt-5.5 low raw | 0.889 | 1.000 | 0.667 | 0.615 | 6.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.889 | 0.500 | 0.333 | 0.286 | 6.67 |
| stage2 | 0.889 | 0.833 | 0.667 | 0.607 | 3.67 |
| stage3 | 0.889 | 0.833 | 0.667 | 0.824 | 1.00 |

### 3. chain_04_e03_dns_packet_capture_batch_chain

- 場面: DNS packet capture batch execution
- 分類: `multi_step_tool_chain` / `collection_or_tool_invocation`
- 正解ステップ数: 2
- 正解の骨子: `explorer.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\start_dns_logs.bat" " | start_dns_logs.bat`
- 難度ラベル: `overclaim_prone`
- 何を見る場面か: Explorer/cmd起点で `start_dns_logs.bat` を起動し、DNSログ取得のためのバッチ実行を追うユースケース。バッチ起動部分が中心ため、`cmd.exe`、bat、`tshark.exe` のどこまでを同一行動として切るかで過剰出力が出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.630 | 0.389 | 0.333 | 0.236 | 10.44 |
| gpt-5.4-mini | 0.870 | 0.500 | 0.444 | 0.347 | 5.44 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.435 | 8.67 |

考察: 5.4-miniの改善はあるが、全指標で安定して伸びるケースではない。証跡または順序が弱く、単に行動名を当てるだけでは正解にならない難ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 1.000 | 0.333 | 1.000 | 0.346 | 5.67 |
| stage2 | 1.000 | 0.667 | 0.333 | 0.538 | 2.00 |
| stage3 | 0.611 | 0.500 | 0.000 | 0.278 | 8.67 |

### 4. chain_05_e03_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 待受/通信先詳細は限定的`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、通信先詳細はgold側で明示しにくいケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.463 | 0.333 | 0.333 | 0.309 | 6.22 |
| gpt-5.4-mini | 0.907 | 0.889 | 0.778 | 0.562 | 3.89 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.667 | 4.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.833 | 0.833 | 0.667 | 0.545 | 5.00 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.583 | 3.33 |
| stage3 | 0.889 | 0.833 | 0.667 | 0.565 | 3.33 |

### 5. chain_06_e04_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:58199`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:58199` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.444 | 0.222 | 0.111 | 0.247 | 6.44 |
| gpt-5.4-mini | 0.889 | 0.889 | 0.889 | 0.667 | 2.44 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.659 | 5.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.889 | 0.833 | 1.000 | 0.583 | 3.33 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.704 | 2.67 |
| stage3 | 0.778 | 0.833 | 0.667 | 0.733 | 1.33 |

### 6. chain_07_e05_sublime_python_script_execution_chain

- 場面: Sublime-triggered Python script execution
- 分類: `multi_step_tool_chain` / `script_execution_chain`
- 正解ステップ数: 10
- 正解の骨子: `plugin_host.exe -> cmd.exe -> cmd.exe -> cmd.exe -> python.exe` -> `C:\Windows\system32\cmd.exe /c "python -u "C:\Program Files\Sublime Text 3\helloworld.py"" | C:\Windows\system32\cmd.exe /c "python -u "C:\Program Files\Sublime Text 3\helloworld.py"" | C:\Program Files\Sublime Text 3\helloworld.py | C:\Program Files\Sublime Text 3\helloworld.py | C:\Program Files\Sublime Text 3\helloworld.py`
- 難度ラベル: `hard_or_unstable`
- 何を見る場面か: Sublime Textの `plugin_host.exe` から `cmd.exe` を経由し、Pythonスクリプト `helloworld.py` を実行する連鎖。cmdやpythonの重複ステップが多く、正解ステップ数も10なので、内容想起より順序評価が厳しく出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.293 | 0.056 | 0.123 | 0.635 | 3.00 |
| gpt-5.4-mini | 0.659 | 0.567 | 0.198 | 0.629 | 2.89 |
| gpt-5.5 low raw | 0.833 | 0.833 | 0.815 | 0.852 | 5.33 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。証跡または順序が弱く、単に行動名を当てるだけでは正解にならない難ケース。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.822 | 0.600 | 0.333 | 0.842 | 1.00 |
| stage2 | 0.567 | 0.533 | 0.111 | 0.423 | 5.00 |
| stage3 | 0.589 | 0.567 | 0.148 | 0.680 | 2.67 |

### 7. chain_09_e07_cmdexe_other_chain

- 場面: cmd.exe alert behavior chain
- 分類: `explicit_execution_chain` / `command_shell_execution`
- 正解ステップ数: 2
- 正解の骨子: `discord.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /q /d /s /c "undefined\NVIDIA^ Corporation\NVSMI\nvidia-smi.exe" | C:\Windows\system32\cmd.exe /q /d /s /c "undefined\NVIDIA^ Corporation\NVSMI\nvidia-smi.exe"`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: Discord起点で `cmd.exe` が `nvidia-smi.exe` 実行コマンドを呼ぶユースケース。コマンド列自体は短いが、親プロセスDiscordとの関係とコマンド本文の保持が必要になる。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.278 | 0.000 | 0.111 | 0.197 | 5.44 |
| gpt-5.4-mini | 0.796 | 0.667 | 0.667 | 0.500 | 2.78 |
| gpt-5.5 low raw | 0.667 | 0.667 | 0.667 | 0.538 | 4.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.556 | 0.333 | 0.333 | 0.250 | 5.00 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.647 | 2.00 |
| stage3 | 0.833 | 0.667 | 0.667 | 0.692 | 1.33 |

### 8. chain_10_e07_discord_run_key_registry_chain

- 場面: Discord Run key registry chain
- 分類: `semantic_interpretation_chain` / `persistence_registry_run_key`
- 正解ステップ数: 3
- 正解の骨子: `discord.exe -> reg.exe -> reg.exe` -> `C:\Windows\System32\reg.exe (query/add reg.exe child processes) | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Discord | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Discord = "C:\Users\aalsahee\AppData\Local\Discord\Update.exe --processStart Discord.exe"`
- 難度ラベル: `hard_or_unstable`
- 何を見る場面か: `discord.exe` から `reg.exe` を呼び、HKCU Runキーのquery/addを通じてDiscord自動起動設定を確認・登録する永続化系ユースケース。単なるプロセス実行ではなく、レジストリキーの意味づけまで必要なので、証跡と順序の両方が難しい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.506 | 0.148 | 0.167 | 0.444 | 4.44 |
| gpt-5.4-mini | 0.642 | 0.481 | 0.333 | 0.719 | 2.00 |
| gpt-5.5 low raw | 1.000 | 0.667 | 0.667 | 0.750 | 3.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。証跡または順序が弱く、単に行動名を当てるだけでは正解にならない難ケース。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.667 | 0.333 | 0.500 | 0.824 | 1.00 |
| stage2 | 0.593 | 0.556 | 0.333 | 0.692 | 2.67 |
| stage3 | 0.667 | 0.556 | 0.167 | 0.667 | 2.33 |

### 9. chain_11_e07_sublime_python_script_execution_chain

- 場面: Sublime-triggered Python script execution
- 分類: `multi_step_tool_chain` / `script_execution_chain`
- 正解ステップ数: 6
- 正解の骨子: `plugin_host.exe -> cmd.exe -> cmd.exe -> cmd.exe -> python.exe` -> `C:\Windows\system32\cmd.exe /c "python -u "C:\Users\aalsahee\Documents\hello.py"" | C:\Windows\system32\cmd.exe /c "python -u "C:\Users\aalsahee\Documents\hello.py"" | C:\Users\aalsahee\Documents\hello.py | C:\Users\aalsahee\Documents\hello.py | C:\Users\aalsahee\Documents\hello.py`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: Sublime Textの `plugin_host.exe` から `cmd.exe` を経由し、Pythonスクリプト `hello.py` を実行する連鎖。cmdやpythonの重複ステップが多く、正解ステップ数も6なので、内容想起より順序評価が厳しく出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.549 | 0.204 | 0.200 | 0.520 | 5.33 |
| gpt-5.4-mini | 0.809 | 0.704 | 0.600 | 0.655 | 3.33 |
| gpt-5.5 low raw | 0.944 | 0.944 | 0.800 | 0.806 | 4.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.796 | 0.500 | 0.533 | 0.724 | 2.67 |
| stage2 | 0.815 | 0.778 | 0.667 | 0.857 | 1.00 |
| stage3 | 0.815 | 0.833 | 0.600 | 0.486 | 6.33 |

### 10. chain_12_e08_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:39277`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:39277` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.593 | 0.333 | 0.556 | 0.493 | 3.89 |
| gpt-5.4-mini | 0.963 | 0.944 | 0.889 | 0.558 | 4.22 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.700 | 4.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 1.000 | 1.000 | 1.000 | 0.419 | 8.33 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.643 | 3.33 |
| stage3 | 0.889 | 0.833 | 0.667 | 0.800 | 1.00 |

### 11. chain_13_e09_dns_packet_capture_batch_chain

- 場面: DNS packet capture batch execution
- 分類: `multi_step_tool_chain` / `collection_or_tool_invocation`
- 正解ステップ数: 5
- 正解の骨子: `explorer.exe -> cmd.exe -> cmd.exe -> explorer.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\start_dns_logs.bat" " | start_dns_logs.bat | tshark.exe | C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\start_dns_logs.bat" " | start_dns_logs.bat`
- 難度ラベル: `mixed`
- 何を見る場面か: Explorer/cmd起点で `start_dns_logs.bat` を起動し、DNSログ取得のためのバッチ実行を追うユースケース。tshark実行まで含むため、`cmd.exe`、bat、`tshark.exe` のどこまでを同一行動として切るかで過剰出力が出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.289 | 0.067 | 0.083 | 0.403 | 4.44 |
| gpt-5.4-mini | 0.674 | 0.578 | 0.389 | 0.629 | 2.56 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.717 | 5.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。証跡または順序が弱く、単に行動名を当てるだけでは正解にならない難ケース。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.600 | 0.200 | 0.250 | 0.714 | 1.33 |
| stage2 | 0.689 | 0.800 | 0.417 | 0.591 | 3.00 |
| stage3 | 0.733 | 0.733 | 0.500 | 0.615 | 3.33 |

### 12. chain_14_e09_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 待受/通信先詳細は限定的`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、通信先詳細はgold側で明示しにくいケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.444 | 0.167 | 0.000 | 0.301 | 5.67 |
| gpt-5.4-mini | 0.704 | 0.667 | 0.667 | 0.543 | 4.78 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.667 | 4.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 1.000 | 1.000 | 1.000 | 0.514 | 5.67 |
| stage2 | 0.278 | 0.167 | 0.333 | 0.562 | 2.33 |
| stage3 | 0.833 | 0.833 | 0.667 | 0.558 | 6.33 |

### 13. chain_15_e10_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:54869`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:54869` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.519 | 0.278 | 0.222 | 0.352 | 5.11 |
| gpt-5.4-mini | 0.833 | 0.833 | 0.778 | 0.815 | 1.11 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.750 | 2.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.556 | 0.500 | 0.333 | 0.778 | 0.67 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.708 | 2.33 |
| stage3 | 0.944 | 1.000 | 1.000 | 0.952 | 0.33 |

### 14. chain_16_e11_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:51647`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:51647` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.463 | 0.278 | 0.333 | 0.366 | 5.00 |
| gpt-5.4-mini | 0.889 | 0.889 | 0.889 | 0.719 | 1.78 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.706 | 3.33 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.667 | 0.667 | 0.667 | 0.647 | 2.00 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.810 | 1.33 |
| stage3 | 1.000 | 1.000 | 1.000 | 0.684 | 2.00 |

### 15. chain_17_e12_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:48503`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:48503` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.611 | 0.222 | 0.556 | 0.440 | 4.67 |
| gpt-5.4-mini | 0.926 | 0.833 | 0.889 | 0.833 | 0.89 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.710 | 3.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.778 | 0.500 | 0.667 | 0.733 | 1.33 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.800 | 1.33 |
| stage3 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |

### 16. chain_18_e13_dns_packet_capture_batch_chain

- 場面: DNS packet capture batch execution
- 分類: `multi_step_tool_chain` / `collection_or_tool_invocation`
- 正解ステップ数: 2
- 正解の骨子: `explorer.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\start_dns_logs.bat" " | start_dns_logs.bat`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: Explorer/cmd起点で `start_dns_logs.bat` を起動し、DNSログ取得のためのバッチ実行を追うユースケース。バッチ起動部分が中心ため、`cmd.exe`、bat、`tshark.exe` のどこまでを同一行動として切るかで過剰出力が出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.722 | 0.278 | 0.444 | 0.264 | 9.89 |
| gpt-5.4-mini | 0.852 | 0.667 | 0.778 | 0.333 | 5.33 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.647 | 4.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.944 | 0.667 | 1.000 | 0.412 | 3.33 |
| stage2 | 0.722 | 0.500 | 0.333 | 0.259 | 6.67 |
| stage3 | 0.889 | 0.833 | 1.000 | 0.357 | 6.00 |

### 17. chain_19_e13_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:59277`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:59277` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.537 | 0.222 | 0.333 | 0.324 | 5.56 |
| gpt-5.4-mini | 0.852 | 0.833 | 0.778 | 0.879 | 0.44 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.667 | 4.00 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.667 | 0.667 | 0.667 | 0.750 | 1.33 |
| stage2 | 0.889 | 0.833 | 0.667 | 1.000 | 0.00 |
| stage3 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |

### 18. chain_21_e15_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:49187`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:49187` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.481 | 0.167 | 0.111 | 0.622 | 1.56 |
| gpt-5.4-mini | 0.833 | 0.833 | 0.778 | 0.905 | 0.44 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.686 | 3.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.667 | 0.667 | 0.667 | 0.667 | 1.33 |
| stage2 | 0.833 | 0.833 | 0.667 | 1.000 | 0.00 |
| stage3 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |

### 19. chain_22_e16_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:58211`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:58211` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.630 | 0.278 | 0.556 | 0.708 | 1.56 |
| gpt-5.4-mini | 0.963 | 0.944 | 0.889 | 0.870 | 0.78 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.774 | 2.33 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 1.000 | 1.000 | 1.000 | 0.850 | 1.00 |
| stage2 | 1.000 | 1.000 | 1.000 | 0.826 | 1.33 |
| stage3 | 0.889 | 0.833 | 0.667 | 1.000 | 0.00 |

### 20. chain_23_e17_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 10.193.66.115:41345`
- 難度ラベル: `easy_or_well_reconstructed`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、接続先/通信先として `10.193.66.115:41345` まで拾えるケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.611 | 0.389 | 0.222 | 0.475 | 3.56 |
| gpt-5.4-mini | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.706 | 3.33 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |
| stage2 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |
| stage3 | 1.000 | 1.000 | 1.000 | 1.000 | 0.00 |

### 21. chain_24_e18_cmdexe_other_chain

- 場面: cmd.exe alert behavior chain
- 分類: `explicit_execution_chain` / `command_shell_execution`
- 正解ステップ数: 3
- 正解の骨子: `explorer.exe -> cmd.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\run_http_server.bat" " | run_http_server.bat | python.exe`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: Explorer/cmdから `run_http_server.bat` を起動し、最終的にPython HTTPサーバ実行へつながるユースケース。bat名、cmd起動、python起動が近接しているため、候補ステップを広く取りすぎると適合率が落ちる。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.543 | 0.222 | 0.167 | 0.390 | 8.33 |
| gpt-5.4-mini | 0.741 | 0.778 | 0.556 | 0.398 | 7.56 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.471 | 12.33 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.444 | 0.444 | 0.333 | 0.400 | 3.00 |
| stage2 | 0.926 | 1.000 | 0.667 | 0.367 | 12.67 |
| stage3 | 0.852 | 0.889 | 0.667 | 0.447 | 7.00 |

### 22. chain_25_e18_dns_packet_capture_batch_chain

- 場面: DNS packet capture batch execution
- 分類: `multi_step_tool_chain` / `collection_or_tool_invocation`
- 正解ステップ数: 3
- 正解の骨子: `explorer.exe -> cmd.exe -> cmd.exe` -> `C:\Windows\system32\cmd.exe /c ""C:\Users\aalsahee\Desktop\start_dns_logs.bat" " | start_dns_logs.bat | tshark.exe`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: Explorer/cmd起点で `start_dns_logs.bat` を起動し、DNSログ取得のためのバッチ実行を追うユースケース。tshark実行まで含むため、`cmd.exe`、bat、`tshark.exe` のどこまでを同一行動として切るかで過剰出力が出やすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.593 | 0.259 | 0.333 | 0.489 | 5.00 |
| gpt-5.4-mini | 0.827 | 0.778 | 0.722 | 0.352 | 7.56 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.679 | 5.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.852 | 0.667 | 1.000 | 0.345 | 6.33 |
| stage2 | 0.889 | 0.889 | 0.667 | 0.400 | 7.00 |
| stage3 | 0.741 | 0.778 | 0.500 | 0.317 | 9.33 |

### 23. chain_26_e18_python_simplehttpserver_network_chain

- 場面: Python SimpleHTTPServer network behavior
- 分類: `explicit_execution_chain` / `network_service_behavior`
- 正解ステップ数: 2
- 正解の骨子: `python.exe -> python.exe` -> `python  -m SimpleHTTPServer | 待受/通信先詳細は限定的`
- 難度ラベル: `moderate_reconstructable`
- 何を見る場面か: `python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース、通信先詳細はgold側で明示しにくいケース。プロセス名とコマンドが短く、正解ステップも2なので、証跡が揃うと比較的再構成しやすい。

| model | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt-4.1-mini | 0.500 | 0.222 | 0.000 | 0.247 | 7.78 |
| gpt-5.4-mini | 0.852 | 0.667 | 0.667 | 0.557 | 3.44 |
| gpt-5.5 low raw | 1.000 | 1.000 | 1.000 | 0.632 | 4.67 |

考察: 5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。

gpt-5.4-miniのステージ別パターン:

| stage | action | evidence | order | precision | over/run |
| --- | ---: | ---: | ---: | ---: | ---: |
| stage1 | 0.833 | 0.500 | 0.667 | 0.476 | 3.67 |
| stage2 | 0.833 | 0.667 | 0.667 | 0.444 | 3.33 |
| stage3 | 0.889 | 0.833 | 0.667 | 0.677 | 3.33 |
