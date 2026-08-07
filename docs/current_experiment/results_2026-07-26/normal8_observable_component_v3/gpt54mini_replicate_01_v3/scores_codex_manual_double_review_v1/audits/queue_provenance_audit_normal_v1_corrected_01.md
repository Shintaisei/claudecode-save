# Normal observable-component v3 queue provenance audit — corrected 01

- Status: **PASS**
- Queue SHA-256: `ed5e4177e37eaac549ab8fe80582c5e3ef798af0109c07431f88c8e46b585413`
- Review outcomes accessed: **No**
- OpenAI/API judge used: **No**

## Correction provenance

This file supersedes `queue_provenance_audit_normal_v1.json`. The preliminary auditor incorrectly treated `gold_steps[].critical_evidence_signature`, a structured provenance signature, as the scored critical-evidence value. The formal contract uses `gold_steps[].evidence_basis`. Recalculation with `evidence_basis` matches all 24 queue rows. No source run, case, Gold, validation, queue, manifest, or score artifact was modified.

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

All 24 queue contracts were reconstructed from the current run JSON, Gold JSON, and validation CSV. Run, Gold, validation, contract, and queue-ID hashes matched. Candidate outputs and all fixed S/A/O slots matched the run outputs. Gold S/A/O, separate critical-evidence items from `evidence_basis`, and order pairs matched the eight source Gold files.

`alert_mapping_scored=false` was confirmed in all cases, Gold contracts, and queue review policies. No Gold scoring item asks the reviewer to infer an unavailable CBC alert ID, title, reason, or alert-to-Gold mapping.

## Non-blocking warning

One Stage 1 output contains a duplicate `ppid` member inside one nested evidence object; both values are `null`. The standard JSON parser accepts the output, the parsed candidate output matches the queue, and the duplicate does not affect candidate slots or contract hashes. This is a serialization-quality warning, not a provenance failure.

## Checks

- Passed: 42
- Failed: 0
- Machine-readable audit: `queue_provenance_audit_normal_v1_corrected_01.json`
