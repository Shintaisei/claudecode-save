# normal8 formal_07 gate abort decision

`formal_07` は正式採用せず、gpt-4.1-mini の最初の Stage 3 gate 中に停止した。gpt-5.4-mini と gpt-5.5 は開始していない。

停止理由は、v4 の exact behavior-key deduplication だけでは atomic behavior の意味的分割を防げなかったためである。同じ未解決の `reg.exe` 行動に対して、Chief は次の4論点を別々の `new_step` として開始した。

- `reg.exe|process_start|unknown`
- `reg.exe|command_line|unknown`
- `reg.exe|registry_access|unknown`
- `reg.exe|process_child|unknown`

`command_line` と `process_child` は独立した行動stepではなく、process start／execution stepを確定する構成要素である。したがって、これはモデル精度として許容する誤認ではなく、実験アーキテクチャが許してはいけない論点分割である。

停止時点では Chief 3件、Investigator 22件、SQL QA 55件が完了し、4件目のChief論点が進行中だった。`run.json` は生成されておらず、成果物は診断用として保存した。親・子プロセスは停止し、孤児プロセスは残っていない。

次は固定の論点数上限ではなく、component-only pseudo-operation を決定論的に拒否し、atomic stepの探索段階と確定段階を区別するsemantic validatorを追加して、別のcreate-only rootで再ゲートする。
