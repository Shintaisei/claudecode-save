# Method Changes For Paper 2026-06-15

This note is the method-writing source for the FIT2026 paper. It separates the unchanged CLOUSEAU agent architecture from the parts that were newly designed or substantially changed in this experiment.

## Main Message

The experiment is not only an architecture evaluation. The important method contribution is the evaluation protocol around the architecture:

- staged input weakening,
- alert-summary exclusion in the hardest condition,
- non-alert gold behavior chains,
- component-level scoring,
- double-review scoring governance,
- scenario/framework-level analysis,
- and explicit handling of raw-output contract failure for GPT-5.5.

These changes make the experiment evaluate whether an agent can reconstruct evidence-backed endpoint behavior from logs, rather than whether it can restate an alert label.

## What Stayed Mostly The Same

The high-level CLOUSEAU pipeline stayed mostly unchanged:

1. A chief/planning agent receives an investigation clue.
2. An investigator converts the clue into concrete questions.
3. QA/SQL components retrieve evidence from endpoint log tables.
4. A final synthesis step emits behavior steps and supporting evidence.

This is the architecture side. The paper should not frame the work as a new agent architecture unless the manuscript explicitly limits that claim. The stronger claim is that the evaluation design, gold construction, and scoring policy were rebuilt.

## What Changed Beyond Architecture

| area | previous/simple framing | current method |
| --- | --- | --- |
| Evaluation target | Single alert or one-off case reconstruction | 23 behavior chains, each evaluated under 3 stages |
| Starting information | Alert-centered clue | Stage-controlled clue: alert-assisted, process-time only, and process-time with alert summary hidden |
| Retrieval environment | Alert and telemetry often available together | Stage3 hides CBC alert summary from SQL retrieval while keeping CBC EDR/NGAV telemetry and OS/browser logs |
| Gold data | Alert-derived or partially alert-dependent references were allowed during early trials | Current gold is non-alert behavior/evidence oriented; CBC alert summary is not counted as non-alert evidence |
| Metric unit | Whole-step or behavior+evidence combined matching | Component-level rubric: subject/action/object, critical evidence, order, precision proxy, and overclaim slots |
| Matching policy | Stricter shape/field matching in earlier scoring attempts | Content-inclusion matching: score as correct when the required substantive content is present |
| Review process | Single-pass or API-judge-style scoring was insufficient for final tables | Codex-based double review, conflict queue, and third-review adoption for contested items |
| Model comparison | Earlier 27-chain structured comparison only | 4.1-mini and 5.4-mini use 23 chains x 3 stages x 3 sets; GPT-5.5 is included as one raw-output salvage set |
| Analysis layer | Aggregate score only | Stage, scenario group, behavior framework, usecase, model-argument, and Investigator/SQL-trace deep dives |
| Cost/runtime handling | Initial cost logs undercounted GPT-5.5 | Cost audit added token/cost reconstruction and explicitly marks GPT-5.5 local estimate / logging caveat |

## Stage Design

The same chain is run under three information conditions.

| stage | input clue | database visibility | purpose |
| --- | --- | --- | --- |
| `stage1` | Process-time fields plus CBC alert summary fields | CBC alert summary, CBC EDR/NGAV telemetry, OS/browser logs | Alert-assisted reconstruction |
| `stage2` | Process-time fields only | CBC alert summary still retrievable in the DB | Tests whether the model can find the alert context rather than being handed it |
| `stage3` | Process-time fields only | CBC alert summary hidden from SQL retrieval; CBC EDR/NGAV telemetry remains available | Tests reconstruction without the alert-summary shortcut |

The paper should emphasize that Stage3 does not remove endpoint telemetry. It removes the alert-summary shortcut. This distinction matters because Stage3 asks whether the behavior is recoverable from telemetry evidence, not whether all CBC data is absent.

## Chain Scope

The current final comparison uses 23 chains.

| model | scope | interpretation |
| --- | ---: | --- |
| `gpt-4.1-mini` | 207 runs | 23 chains x 3 stages x 3 sets |
| `gpt-5.4-mini` | 207 runs | 23 chains x 3 stages x 3 sets |
| `gpt-5.5 low raw` | 69 runs | 23 chains x 3 stages x 1 raw-output salvage set |

For `gpt-4.1-mini` and `gpt-5.4-mini`, the third set is the current 23-chain subset filtered from the older 27-chain run, not a newly executed formal23 replicate. This should be stated clearly in the method or limitation section.

For GPT-5.5, the result is useful for qualitative and component-level ability analysis, but it should not be described as fully contract-equivalent because the model did not follow the structured output contract.

## Gold Construction

The gold target is a behavior chain, not an alert explanation. Each gold step is decomposed into:

- subject,
- action,
- object,
- critical non-alert evidence,
- and expected local order relation.

Important policy:

- CBC alert summary can explain why the investigation started.
- CBC alert summary must not be counted as non-alert evidence.
- Stage3 gold remains based on the same behavior target, but evidence hits are validated against evidence that should be recoverable without relying on alert-summary rows.

This is the central reason the experiment differs from simply asking a model to explain an alert.

## Component Rubric

The final scoring rubric is component-level.

| metric | denominator | meaning |
| --- | --- | --- |
| `action_step_recall` | `gold_step_count * 3` | subject/action/object component recovery |
| `critical_evidence_recall` | `gold_step_count` | recovery of the essential non-alert evidence for each gold step |
| `behavior_sequence_order` | `max(gold_step_count - 1, 0)` | adjacent gold step order recovery |
| `candidate_claim_precision` | candidate claim slots | proportion of candidate claim slots that are supported/correct |
| `overclaim_slot_count` | count only | unsupported, wrong, or outside-gold claim slots |

The matching policy is content inclusion. A candidate can use different wording or a different output shape and still receive credit if it contains the required substantive content.

## Review Governance

The final tables are not based on a single automatic judge pass. The review process is:

1. Prepare candidate/gold review rows.
2. Run two independent Codex-based reviews.
3. Accept rows when both reviews agree.
4. Put conflicts into a conflict queue.
5. Resolve conflicts with third-review adoption or conservative adjudication.

This should be described as a scoring governance method, not merely as implementation detail. It supports the claim that the final component scores were not produced by one unchecked judge call.

## Scenario And Framework Analysis

The paper can say that chains were analyzed at multiple levels:

- stage level: effect of input weakening,
- scenario group level: broad task structure,
- behavior framework level: more detailed behavior category,
- usecase level: individual chain difficulty,
- model argument level: what each model tended to claim,
- Investigator/SQL proxy level: what evidence-selection behavior was visible.

The recommended paper framing is:

- explicit execution / network service behavior is easier,
- multi-step tool chains are harder because order and evidence separation matter,
- registry/app semantic chains need more interpretation and should be discussed as individual cases when counts are small.

## Investigator And SQL Trace Caveat

Formal 23-chain runs do not preserve actual SQL strings or full runner traces. Therefore, SQL precision cannot be directly evaluated for 4.1/5.4. The current analysis evaluates final evidence selection as an indirect proxy.

For GPT-5.5, raw text often exposes QA-style questions and investigation hypotheses, but this is still a raw-output salvage observation, not a structured SQL trace.

Paper wording should use:

- "final evidence-selection proxy",
- "raw-output hypothesis/QA observation",
- "actual SQL statements were not logged for direct SQL correctness analysis".

Avoid wording such as:

- "SQL accuracy was measured directly",
- "the model generated correct SQL",
- "GPT-5.5 is directly comparable as a structured run".

## Paper Method Section Skeleton

1. Task definition: evidence-backed endpoint behavior-chain reconstruction from SOC/process-time clues.
2. Dataset/cases: ATLASv2/CBC-derived endpoint logs, 23 final chains, 3 stages.
3. Agent pipeline: CLOUSEAU planner/investigator/QA-SQL/final synthesis, kept mostly fixed.
4. Stage manipulation: stage1/stage2/stage3 and alert-summary hiding.
5. Gold construction: non-alert behavior steps and critical evidence.
6. Scoring rubric: component recall, evidence recall, order, precision proxy, overclaims.
7. Review process: double review, conflict resolution, third-review adoption.
8. Model setup: 4.1-mini/5.4-mini 3-set comparison and GPT-5.5 raw salvage caveat.
9. Analysis axes: stage, scenario/framework, usecase, model argument, cost/runtime.

## Suggested Wording For Contribution

The architecture of the agent workflow is not the only contribution. The experiment introduces a controlled evaluation protocol for log-investigation agents: the initial clue is progressively weakened, alert-summary shortcuts are explicitly removed in the hardest condition, gold behavior chains are scored at component level against non-alert evidence, and final scores are produced through double review and conflict resolution. This makes the evaluation closer to SOC investigation practice, where the goal is not only to explain an alert label but to reconstruct which observable endpoint behaviors are supported by logs.

