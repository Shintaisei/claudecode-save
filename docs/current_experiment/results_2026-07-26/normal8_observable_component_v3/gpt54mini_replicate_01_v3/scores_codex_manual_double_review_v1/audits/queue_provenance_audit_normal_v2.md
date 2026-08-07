# Normal observable-component v3 queue provenance audit v2

- Status: **PASS**
- Queue SHA-256: `ed5e4177e37eaac549ab8fe80582c5e3ef798af0109c07431f88c8e46b585413`
- Review outcomes accessed: **No**
- OpenAI/API judge used: **No**

## v1 correction

This v2 audit supersedes `queue_provenance_audit_normal_v1.json`. The v1 auditor incorrectly treated `gold_steps[].critical_evidence_signature`, a structured provenance signature, as the scored critical-evidence value. The queue preparation path uses `normalize_gold` and `gold_required_items`, whose formal value is `gold_steps[].evidence_basis`.

The correction was verified by directly executing these preparation-side functions against all 24 rows:

- `validate_queue_rows`: 24/24
- `gold_contract`: 24/24 exact contract matches
- `completed_run`: 24/24 eligible
- `candidate_slots`: 24/24 exact slot matches

No source run, case, Gold, validation, queue, manifest, or score artifact was modified.

## Recomputed counts

| Item | Count |
| --- | ---: |
| Cases / runs / queue rows | 24 / 24 / 24 |
| Stage 1 / 2 / 3 | 8 / 8 / 8 |
| Unique Gold chains / steps | 8 / 23 |
| Gold S/A/O items across stages | 207 |
| Critical-evidence items across stages | 69 |
| All Gold items across stages | 276 |
| Order pairs across stages | 45 |
| Candidate claims / fixed slots | 52 / 156 |
| Valid run JSON / output JSON | 24 / 24 |
| Error-free / unbounded configs | 24 / 24 |
| Stale / rejected / excluded | 0 / 0 / 0 |
| Hidden alert-mapping scoring items | 0 |

## Provenance result

Run, Gold, validation, queue, and contract hashes all match current files. All candidate outputs and fixed S/A/O slots match their run outputs. `alert_mapping_scored=false` is present in all case, Gold, and queue contracts, and hidden alert ID/title/reason/mapping scoring items are 0.

## Non-blocking warning

One Stage 1 output contains a duplicate `ppid` member inside one nested evidence object; both values are `null`. The standard JSON parser accepts it, parsed output matches the queue, and no candidate slot or contract hash changes. It is a serialization-quality warning only.

## Checks

- Passed: 42
- Failed: 0
- Machine-readable audit: `queue_provenance_audit_normal_v2.json`
