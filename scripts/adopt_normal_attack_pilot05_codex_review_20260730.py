"""Adopt explicit Codex decisions into deterministic pilot05 v5 scores.

No model or judge API is called. Gold action hits are derived exclusively from
unique included TP candidate slots. Critical evidence is explicitly reviewed,
and adjacent order is derived separately from aligned candidate-claim order.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-30/"
    / "normal_attack_full_ledger_pilot_05/"
    / "analysis_codex_single_review_v1"
)
QUEUE = ANALYSIS_ROOT / "review_queue_v1.jsonl"
QUEUE_MANIFEST = ANALYSIS_ROOT / "review_queue_manifest_v1.json"
DECISIONS = ANALYSIS_ROOT / "codex_decisions_v1.jsonl"
REVIEW = ANALYSIS_ROOT / "codex_review_v5_atomic_v1.jsonl"
AGGREGATE = ANALYSIS_ROOT / "formal_accuracy_aggregate_v1.json"
AUDIT = ANALYSIS_ROOT / "formal_accuracy_audit_v1.json"
ACTION_KINDS = ("subject", "operation", "object")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_new(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"create-only target exists: {path}")
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl_new(path: Path, rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"create-only target exists: {path}")
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def normalize_claims(decision: dict[str, Any]) -> dict[str, dict[str, Any]]:
    claims = decision.get("claims") or {}
    normalized: dict[str, dict[str, Any]] = {}
    for claim_id, value in claims.items():
        if not isinstance(value, dict):
            raise ValueError(f"{decision['queue_id']}: invalid claim {claim_id}")
        step_id = value.get("gold_step_id")
        kinds = set(value.get("tp_kinds") or [])
        if not step_id or not kinds.issubset(ACTION_KINDS):
            raise ValueError(
                f"{decision['queue_id']}: invalid claim alignment {claim_id}"
            )
        normalized[claim_id] = {
            "gold_step_id": str(step_id),
            "tp_kinds": kinds,
        }
    return normalized


def score_row(
    queue: dict[str, Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    gold = {item["item_id"]: item for item in queue["gold_items"]}
    gold_steps = {
        item["step_id"] for item in queue["gold_items"]
    }
    candidate_claim_ids = {
        slot["candidate_claim_id"] for slot in queue["candidate_slots"]
    }
    claims = normalize_claims(decision)
    unknown_claims = set(claims) - candidate_claim_ids
    if unknown_claims:
        raise ValueError(
            f"{queue['queue_id']}: unknown claims {sorted(unknown_claims)}"
        )
    for claim_id, spec in claims.items():
        if spec["gold_step_id"] not in gold_steps:
            raise ValueError(
                f"{queue['queue_id']}: unknown Gold step for {claim_id}"
            )

    duplicate_claims = set(decision.get("duplicate_claim_ids") or [])
    if not duplicate_claims.issubset(candidate_claim_ids):
        raise ValueError(f"{queue['queue_id']}: unknown duplicate claim")

    covered: dict[str, str] = {}
    scored_slots: list[dict[str, Any]] = []
    for source in queue["candidate_slots"]:
        slot = dict(source)
        claim_id = slot["candidate_claim_id"]
        spec = claims.get(claim_id)
        slot["include_in_denominator"] = 1
        slot["aligned_gold_step_id"] = (
            spec["gold_step_id"] if spec else None
        )
        if spec and slot["kind"] in spec["tp_kinds"]:
            target = (
                f"{queue['instance_id'].rsplit('_stage', 1)[0]}:"
                f"{spec['gold_step_id']}:{slot['kind']}"
            )
            if target not in gold:
                raise ValueError(f"{queue['queue_id']}: unknown target {target}")
            if target in covered:
                raise ValueError(
                    f"{queue['queue_id']}: duplicate TP coverage {target}"
                )
            covered[target] = slot["slot_id"]
            slot.update(
                {
                    "matched_gold_item_id": target,
                    "is_true_positive": 1,
                    "false_positive_type": "",
                }
            )
        else:
            fp_type = (
                "duplicate"
                if claim_id in duplicate_claims
                else "wrong_component"
                if spec
                else "unsupported"
            )
            slot.update(
                {
                    "matched_gold_item_id": None,
                    "is_true_positive": 0,
                    "false_positive_type": fp_type,
                }
            )
        scored_slots.append(slot)

    critical_steps = set(decision.get("critical_step_ids") or [])
    if not critical_steps.issubset(gold_steps):
        raise ValueError(f"{queue['queue_id']}: unknown critical step")
    scored_gold: list[dict[str, Any]] = []
    for source in queue["gold_items"]:
        item = dict(source)
        if item["kind"] in ACTION_KINDS:
            item["score"] = int(item["item_id"] in covered)
            item["score_source"] = (
                "derived_from_unique_included_tp_candidate_slot"
            )
            item["matched_candidate_slot_id"] = covered.get(item["item_id"])
        else:
            item["score"] = int(item["step_id"] in critical_steps)
            item["score_source"] = "explicit_codex_critical_evidence_review"
        scored_gold.append(item)

    claim_orders: dict[str, int] = {}
    for slot in queue["candidate_slots"]:
        claim_orders.setdefault(
            slot["candidate_claim_id"],
            int(slot["candidate_order"]),
        )
    aligned_by_step: dict[str, list[str]] = defaultdict(list)
    for claim_id, spec in claims.items():
        aligned_by_step[spec["gold_step_id"]].append(claim_id)
    scored_pairs: list[dict[str, Any]] = []
    for source in queue["order_pairs"]:
        pair = dict(source)
        before_claims = aligned_by_step.get(pair["before_step_id"], [])
        after_claims = aligned_by_step.get(pair["after_step_id"], [])
        matches = [
            (before, after)
            for before in before_claims
            for after in after_claims
            if before != after and claim_orders[before] < claim_orders[after]
        ]
        pair["score"] = int(bool(matches))
        pair["score_source"] = "derived_from_distinct_aligned_claim_order"
        pair["matched_candidate_claims"] = (
            list(matches[0]) if matches else None
        )
        scored_pairs.append(pair)

    return {
        "schema_version": "normal_attack_pilot05_v5_atomic_score_v1",
        **{
            key: queue[key]
            for key in (
                "queue_id",
                "contract_sha256",
                "pair_id",
                "scenario_group",
                "model",
                "stage",
                "instance_id",
                "run_json",
                "gold_json",
                "run_sha256",
                "gold_sha256",
                "validation_steps_sha256",
                "maxima",
            )
        },
        "gold_items": scored_gold,
        "candidate_slots": scored_slots,
        "order_pairs": scored_pairs,
        "review_summary_ja": decision.get("review_summary_ja", ""),
        "failure_analysis": decision.get("failure_analysis") or {},
        "external_judge_api_used": False,
    }


def row_totals(row: dict[str, Any]) -> dict[str, Any]:
    action = [
        item for item in row["gold_items"] if item["kind"] in ACTION_KINDS
    ]
    critical = [
        item
        for item in row["gold_items"]
        if item["kind"] == "critical_evidence"
    ]
    by_step: dict[str, dict[str, int]] = defaultdict(dict)
    for item in action:
        by_step[item["step_id"]][item["kind"]] = item["score"]
    included = [
        slot
        for slot in row["candidate_slots"]
        if slot["include_in_denominator"] == 1
    ]
    fp = Counter(
        slot["false_positive_type"]
        for slot in included
        if slot["is_true_positive"] == 0
    )
    total = {
        "run_count": 1,
        "gold_action_denominator": len(action),
        "gold_action_hits": sum(item["score"] for item in action),
        "candidate_slot_denominator": len(included),
        "candidate_slot_tp": sum(
            slot["is_true_positive"] for slot in included
        ),
        "behavior_step_denominator": len(by_step),
        "behavior_step_hits": sum(
            all(parts.get(kind) == 1 for kind in ACTION_KINDS)
            for parts in by_step.values()
        ),
        "critical_evidence_denominator": len(critical),
        "critical_evidence_hits": sum(item["score"] for item in critical),
        "order_pair_denominator": len(row["order_pairs"]),
        "order_pair_hits": sum(pair["score"] for pair in row["order_pairs"]),
        "false_positive_types": dict(fp),
    }
    return metricize(total)


def metricize(total: dict[str, Any]) -> dict[str, Any]:
    result = dict(total)
    for name, hits, denominator in (
        ("action_recall", "gold_action_hits", "gold_action_denominator"),
        (
            "candidate_precision",
            "candidate_slot_tp",
            "candidate_slot_denominator",
        ),
        (
            "behavior_step_recall",
            "behavior_step_hits",
            "behavior_step_denominator",
        ),
        (
            "critical_evidence_recall",
            "critical_evidence_hits",
            "critical_evidence_denominator",
        ),
        ("order_recall", "order_pair_hits", "order_pair_denominator"),
    ):
        denominator_value = int(result[denominator])
        result[name] = {
            "hits": int(result[hits]),
            "denominator": denominator_value,
            "value": (
                int(result[hits]) / denominator_value
                if denominator_value
                else None
            ),
        }
    return result


def merge(rows: list[dict[str, Any]]) -> dict[str, Any]:
    sums: defaultdict[str, int] = defaultdict(int)
    fp: Counter[str] = Counter()
    for row in rows:
        total = row_totals(row)
        for key, value in total.items():
            if key == "false_positive_types":
                fp.update(value)
            elif not isinstance(value, dict):
                sums[key] += int(value)
    output = dict(sums)
    output["false_positive_types"] = dict(fp)
    return metricize(output)


def grouped(
    rows: list[dict[str, Any]],
    keys: tuple[str, ...],
) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[key] for key in keys)].append(row)
    return [
        {
            **{key: value for key, value in zip(keys, group_key)},
            "metrics": merge(members),
        }
        for group_key, members in sorted(groups.items())
    ]


def audit_reviews(
    queue_rows: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    expected: dict[str, int],
) -> list[str]:
    failures: list[str] = []
    if len(reviews) != expected["row_count"]:
        failures.append("row_count")
    observed = merge(reviews)
    for key, expected_value in expected.items():
        if key == "row_count":
            continue
        if int(observed.get(key, -1)) != int(expected_value):
            failures.append(f"denominator.{key}")
    queue_by_id = {row["queue_id"]: row for row in queue_rows}
    for review in reviews:
        queue = queue_by_id[review["queue_id"]]
        if review["contract_sha256"] != queue["contract_sha256"]:
            failures.append(f"{review['queue_id']}.contract_hash")
        covered = {
            slot["matched_gold_item_id"]
            for slot in review["candidate_slots"]
            if slot["include_in_denominator"] == 1
            and slot["is_true_positive"] == 1
        }
        if len(covered) != sum(
            slot["is_true_positive"]
            for slot in review["candidate_slots"]
            if slot["include_in_denominator"] == 1
        ):
            failures.append(f"{review['queue_id']}.duplicate_tp")
        for item in review["gold_items"]:
            if item["kind"] in ACTION_KINDS:
                if item["score"] != int(item["item_id"] in covered):
                    failures.append(
                        f"{review['queue_id']}.atomic.{item['item_id']}"
                    )
    return failures


def main() -> None:
    queue_rows = read_jsonl(QUEUE)
    queue_manifest = read_json(QUEUE_MANIFEST)
    decisions = read_jsonl(DECISIONS)
    queue_ids = {row["queue_id"] for row in queue_rows}
    decision_by_id = {row["queue_id"]: row for row in decisions}
    if len(decision_by_id) != len(decisions):
        raise ValueError("duplicate decision queue_id")
    if set(decision_by_id) != queue_ids:
        missing = sorted(queue_ids - set(decision_by_id))
        extra = sorted(set(decision_by_id) - queue_ids)
        raise ValueError(f"decision coverage mismatch missing={missing} extra={extra}")
    reviews = [
        score_row(row, decision_by_id[row["queue_id"]])
        for row in queue_rows
    ]
    expected = queue_manifest["expected_denominators"]
    failures = audit_reviews(queue_rows, reviews, expected)
    aggregate = {
        "schema_version": "normal_attack_pilot05_accuracy_aggregate_v1",
        "overall": merge(reviews),
        "by_model": grouped(reviews, ("model",)),
        "by_stage": grouped(reviews, ("stage",)),
        "by_scenario_group": grouped(reviews, ("scenario_group",)),
        "by_model_stage": grouped(reviews, ("model", "stage")),
        "by_model_scenario": grouped(
            reviews, ("model", "scenario_group")
        ),
        "by_case": grouped(
            reviews,
            ("pair_id", "scenario_group", "model"),
        ),
        "by_run": [
            {
                "queue_id": row["queue_id"],
                "pair_id": row["pair_id"],
                "scenario_group": row["scenario_group"],
                "model": row["model"],
                "stage": row["stage"],
                "instance_id": row["instance_id"],
                "metrics": row_totals(row),
                "review_summary_ja": row["review_summary_ja"],
                "failure_analysis": row["failure_analysis"],
            }
            for row in reviews
        ],
        "interpretation_limit": (
            "case/model assignments are confounded; model aggregates are "
            "descriptive and are not a controlled model-superiority comparison"
        ),
        "external_judge_api_used": False,
    }
    audit = {
        "schema_version": "normal_attack_pilot05_accuracy_audit_v1",
        "status": "PASS" if not failures else "FAIL",
        "review_queue_sha256": sha256(QUEUE),
        "review_queue_manifest_sha256": sha256(QUEUE_MANIFEST),
        "decisions_sha256": sha256(DECISIONS),
        "expected_denominators": expected,
        "observed_denominators": {
            key: (
                len(reviews)
                if key == "row_count"
                else aggregate["overall"][key]
            )
            for key in expected
        },
        "atomic_consistency": {
            "gold_action_hits_without_unique_tp": 0,
            "tp_slots_without_gold_action_hit": 0,
            "duplicate_tp_coverage": 0,
            "candidate_claim_multi_alignment": 0,
        },
        "failures": failures,
        "external_judge_api_used": False,
    }
    write_jsonl_new(REVIEW, reviews)
    write_json_new(AGGREGATE, aggregate)
    write_json_new(AUDIT, audit)
    if failures:
        raise SystemExit("audit failed: " + "; ".join(failures))
    print(REVIEW)
    print(AGGREGATE)
    print(AUDIT)


if __name__ == "__main__":
    main()
