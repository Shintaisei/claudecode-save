# normal8 formal_10 gate abort decision

`formal_10` は正式採用せず、gpt-4.1-mini の最初の Stage 3 gate 中に停止した。gpt-5.4-mini とgpt-5.5は開始していない。

v7は許可anchor、汎用object、構成フィールド、malformed key、完全一致重複を正しく拒否し、最終的に次の具体的な2行動へ到達した。

- `reg.exe|write|registry_key\Software\Microsoft\Windows\CurrentVersion\Run\Discord`
- `discord.exe|create|reg.exe`

しかしモデルは、後者を `discord.exe|create|reg.exe process with command line` と言い換え、別keyとして再調査した。これは同じprocess creation stepの意味的重複である。

停止時点ではChief 17件、Investigator 41件、SQL QA 62件が完了し、`run.json` は未生成だった。次は実行ファイル名を抽出し、create/start/launch/execute等の同義operationを統合したsemantic fingerprintで重複判定する。
