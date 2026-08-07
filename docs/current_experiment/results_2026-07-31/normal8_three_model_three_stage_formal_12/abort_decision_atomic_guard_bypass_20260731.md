# formal_12 abort decision

`formal_12` was stopped before any additional completed run after the first
`gpt-4.1-mini` Stage-1 run.

The Stage-2 live ledger showed that the v9 atomic-key guard accepted
`cmd.exe|access|file_or_registry`. The object `file_or_registry` is a compound
generic label rather than one observed file path or registry path/value. This is
an architecture guard vocabulary gap, not a model-quality result that can be
carried into the formal comparison.

Four completed run JSON files and the incomplete Stage-2 activity ledger are
preserved read-only. They must not be deleted, overwritten, resumed under a new
policy, or included in the corrected formal aggregate. The correction must use
a new policy version and a new create-only result root after tests and a fresh
three-model gate pass.
