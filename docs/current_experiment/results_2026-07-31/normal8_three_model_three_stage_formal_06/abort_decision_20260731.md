# v3 core-gate abort decision

The gpt-4.1-mini Discord Stage-3 sentinel was stopped before creating a formal run. The completed live ledger had **7 Chief leads, 52 Investigator questions, 88 SQL queries, and 152 completed tool events**. GPT-5.4-mini and GPT-5.5 were not started.

The v3 instruction “one lead per edge” was too narrow. It divided one atomic behavior into separate parent, command-line, registry-object, and child investigations. The successor v4 contract uses one complete atomic step per lead and requires a canonical `subject|operation|object` behavior key, allowing deterministic duplicate-step rejection without imposing a fixed lead count.
