# normal8 formal_09 gate abort decision

`formal_09` は正式採用せず、gpt-4.1-mini の最初の Stage 3 gate 中に停止した。gpt-5.4-mini とgpt-5.5は開始していない。

許可anchor `reg.exe@2022-07-16 15:03:54` の完全一致は機能し、汎用objectを使った最初の3件も拒否した。しかし `reg.exe|execute|command_line` は、構成フィールド名をoperationではなくobjectに置くことでvalidatorをすり抜け、実調査を開始した。その後も `command_line@2022-07-16 15:03:54` という派生表現が出ている。

停止時点ではChief 4件、Investigator 5件、SQL QA 25件が完了し、`run.json` は生成されていない。全プロセスを停止し、孤児プロセスは残していない。

次はcommand line、parent/child、PID、timestamp、evidence、order等の構成フィールド名をbehavior keyの全位置で拒否し、`@`や`:`で値を付けた派生表現も同じく拒否する。
