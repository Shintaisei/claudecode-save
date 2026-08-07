# normal8 formal_08 gate abort decision

`formal_08` は正式採用せず、gpt-4.1-mini の最初の Stage 3 gate 中に停止した。gpt-5.4-mini と gpt-5.5 は開始していない。

Chief は `reg.exe|create|registry_key` を `new_step` とし、`evidence_anchor` に `2022-07-16 15:03:54 PID=1234` を指定した。しかし入力で与えられたのは `reg.exe` と時刻だけであり、PID 1234 は未観測の作成値である。また `registry_key` は具体的なレジストリパスではなくobject型名にすぎない。

したがって、非空anchorと単純なunknown判定だけでは不十分と判断した。停止時点ではInvestigator 2件、SQL QA 14件が完了し、`run.json` は生成されていない。全プロセスを停止し、孤児プロセスは残していない。

次は、各runの入力から許可anchorを決定論的に生成してtool callに完全一致させ、`process`、`file`、`registry_key`、`network`などの型名を具体的なnew step objectとして拒否する。
