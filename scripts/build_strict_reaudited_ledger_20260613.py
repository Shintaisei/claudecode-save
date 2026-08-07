from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCORE_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612"
AUDIT_ROOT = SCORE_ROOT / "strict_reaudit_20260613"
LEDGER = SCORE_ROOT / "codex_double_reviews.jsonl"
OUT_LEDGER = AUDIT_ROOT / "codex_double_reviews.strict_reaudited.jsonl"
OUT_CHANGES = AUDIT_ROOT / "strict_reaudit_consensus_changes.jsonl"
OUT_UNRESOLVED = AUDIT_ROOT / "strict_reaudit_unresolved_disagreements.jsonl"
OUT_SUMMARY = AUDIT_ROOT / "strict_reaudit_final_summary.json"


KEY_FIELDS = ("replicate", "model", "stage", "instance_id")

CONSENSUS_CHANGES: dict[tuple[str, str, str, str], dict[str, Any]] = {
    (
        "replicate_02",
        "gpt-5.4-mini",
        "stage1",
        "chain_22_e16_python_simplehttpserver_network_chain_stage1",
    ): {
        "recall_hits": 2,
        "precision_hits": 2,
        "behavior_sequence_order_hits": 2,
        "reason": "J1/J2 consensus: S1 has cbc-ngav source_row_id/event 1002140 with command, PID/PPID, and cmd parent for launch; S3 has the same source row's endpoint 10.193.66.115:58211. S2 remains alert-only.",
    },
    (
        "replicate_02",
        "gpt-5.4-mini",
        "stage2",
        "chain_13_e09_dns_packet_capture_batch_chain_stage2",
    ): {
        "recall_hits": 2,
        "precision_hits": 2,
        "behavior_sequence_order_hits": 2,
        "reason": "J1/J2 consensus: S1 supports explorer-to-cmd/start_dns_logs.bat, and S2 separately supports tshark udp port 53 under that cmd. Duplicate gold rows are not double-counted.",
    },
}

UNRESOLVED_DISAGREEMENTS = [
    {
        "key": {
            "replicate": "replicate_01",
            "model": "gpt-4.1-mini",
            "stage": "stage2",
            "instance_id": "chain_05_e03_python_simplehttpserver_network_chain_stage2",
        },
        "current_score": {
            "gold_step_count": 2,
            "candidate_step_count": 5,
            "recall_hits": 2,
            "recall_total": 2,
            "precision_hits": 2,
            "precision_total": 5,
            "behavior_sequence_order_hits": 2,
            "behavior_sequence_order_total": 2,
        },
        "j1_decision": "keep_current",
        "j2_decision": "change_score_to_1_of_2",
        "handling": "not_applied_without_two-auditor_consensus",
        "reason": "J2 judged the network endpoint evidence too weak because it lacked port/parent endpoint alignment; J1 accepted S3 as same-PID non-alert connection to 10.193.66.115. Requires manual policy decision if stricter remote-port evidence is mandatory.",
    }
]


def key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row[field]) for field in KEY_FIELDS)  # type: ignore[return-value]


def ratio(hit: int | None, total: int | None) -> float | None:
    if total is None or total == 0 or hit is None:
        return None
    return hit / total


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    rows = read_jsonl(LEDGER)
    out_rows: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for row in rows:
        out = deepcopy(row)
        row_key = key(row)
        change = CONSENSUS_CHANGES.get(row_key)
        if change:
            before = {
                "recall_hits": row.get("recall_hits"),
                "recall": row.get("recall"),
                "precision_hits": row.get("precision_hits"),
                "precision": row.get("precision"),
                "behavior_sequence_order_hits": row.get("behavior_sequence_order_hits"),
                "behavior_sequence_order": row.get("behavior_sequence_order"),
            }
            out["recall_hits"] = int(change["recall_hits"])
            out["precision_hits"] = int(change["precision_hits"])
            out["behavior_sequence_order_hits"] = int(change["behavior_sequence_order_hits"])
            out["recall"] = ratio(int(out["recall_hits"]), int(out["recall_total"]))
            out["precision"] = ratio(int(out["precision_hits"]), int(out["precision_total"]))
            out["behavior_sequence_order"] = ratio(
                int(out["behavior_sequence_order_hits"]),
                int(out["behavior_sequence_order_total"]),
            )
            out["strict_reaudit_adjusted"] = True
            out["strict_reaudit_adjusted_at_utc"] = now
            out["strict_reaudit_reason"] = change["reason"]
            after = {
                "recall_hits": out.get("recall_hits"),
                "recall": out.get("recall"),
                "precision_hits": out.get("precision_hits"),
                "precision": out.get("precision"),
                "behavior_sequence_order_hits": out.get("behavior_sequence_order_hits"),
                "behavior_sequence_order": out.get("behavior_sequence_order"),
            }
            changes.append(
                {
                    "key": {field: row[field] for field in KEY_FIELDS},
                    "chain_id": row.get("chain_id"),
                    "before": before,
                    "after": after,
                    "reason": change["reason"],
                }
            )
        out_rows.append(out)

    write_jsonl(OUT_LEDGER, out_rows)
    write_jsonl(OUT_CHANGES, changes)
    write_jsonl(OUT_UNRESOLVED, UNRESOLVED_DISAGREEMENTS)

    summary = {
        "created_at_utc": now,
        "source_ledger": str(LEDGER.relative_to(ROOT).as_posix()),
        "strict_reaudited_ledger": str(OUT_LEDGER.relative_to(ROOT).as_posix()),
        "rows": len(out_rows),
        "consensus_change_count": len(changes),
        "unresolved_disagreement_count": len(UNRESOLVED_DISAGREEMENTS),
        "mechanical_audit": {
            "expected_rows": 276,
            "ledger_rows": 276,
            "missing_expected_rows": 0,
            "unexpected_rows": 0,
            "duplicate_keys": 0,
            "mechanical_issue_rows": 2,
            "mechanical_issues_handling": "Both are output_text JSON parse errors already scored as candidate_step_count=0 and score=0.",
        },
        "two_pass_reaudit": {
            "full_partition_double_check_rows": 276,
            "candidate_discrepancy_union_rows": 27,
            "final_adjudication_double_check_rows": 27,
            "applied_policy": "Only score changes agreed by both final adjudicators are applied to the strict reaudited ledger.",
        },
        "consensus_changes": changes,
        "unresolved_disagreements": UNRESOLVED_DISAGREEMENTS,
    }
    OUT_SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
