#!/usr/bin/env python3
"""Create-only Codex scoring for the attack8 frontier-closure 12-run pilot.

The semantic decisions below are the explicit result of a Codex item review.
This program does not infer matches heuristically and does not call an API.
It binds the review to the frozen run/Gold hashes, derives Gold action hits
only from unique literal TP candidate slots, and performs deterministic
cross-field and denominator checks.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-28/attack8_frontier_pilot_01"
)
SCORE_ROOT = RESULT_ROOT / "scores_codex_frontier_pilot_single_review_v1"
SOURCE_QUEUE = SCORE_ROOT / "review_queue.jsonl"
DERIVED_QUEUE = SCORE_ROOT / "review_queue_v5_atomic_pid_non_scoring.jsonl"
REVIEW = SCORE_ROOT / "codex_review1_v5_atomic.jsonl"
OVERLAY = SCORE_ROOT / "review_policy_overlay_v5_atomic.json"
AUDIT = SCORE_ROOT / "deterministic_audit_v1.json"
AGGREGATE = SCORE_ROOT / "formal_aggregate_v1.json"
DETAILS = SCORE_ROOT / "metrics_by_model_stage_case_v1.json"
TRACE = SCORE_ROOT / "trace_and_runtime_audit_v1.json"

ACTION_KINDS = {"subject", "operation", "object"}
EXPECTED = {
    "row_count": 12,
    "gold_action_denominator": 198,
    "behavior_step_denominator": 66,
    "critical_evidence_denominator": 66,
    "order_pair_denominator": 54,
    "candidate_slot_denominator": 191,
}


def decision(
    claims: dict[str, tuple[str, set[str]]],
    critical: set[str],
    order: set[tuple[str, str]],
    *,
    duplicate_claims: set[str] | None = None,
    summary: str,
) -> dict[str, Any]:
    return {
        "claims": claims,
        "critical": critical,
        "order": order,
        "duplicate_claims": duplicate_claims or set(),
        "summary": summary,
    }


# Each claim aligns to at most one Gold step.  The set contains only literal TP
# component kinds.  Unlisted candidate claims are Gold-external/unsupported.
DECISIONS: dict[str, dict[str, Any]] = {
    "gpt-4.1-mini/stage1/s3_pt_01_word_document_processing_stage1": decision(
        {
            "C2": ("A8V5-01-S02", {"subject", "operation", "object"}),
            "C3": ("A8V5-01-S01", {"subject", "object"}),
        },
        {"A8V5-01-S01", "A8V5-01-S02"},
        set(),
        summary="文書pathと同名Word子プロセスは得たが、文書openをfile_writeと誤正規化し順序も逆転。",
    ),
    "gpt-4.1-mini/stage2/s3_pt_01_word_document_processing_stage2": decision(
        {"C1": ("A8V5-01-S01", {"subject", "operation", "object"})},
        {"A8V5-01-S01", "A8V5-01-S02"},
        set(),
        summary="文書openは完全復元。Word子プロセスedgeはevidenceにあるが独立code stepへ昇格しなかった。",
    ),
    "gpt-4.1-mini/stage3/s3_pt_01_word_document_processing_stage3": decision(
        {},
        set(),
        set(),
        summary="対象5分窓から外れたDNS収集系近傍行動へ逸脱し、Word chainを復元しなかった。",
    ),
    "gpt-5.4-mini/stage1/s3_pt_01_word_document_processing_stage1": decision(
        {
            "C2": ("A8V5-01-S01", {"subject", "operation", "object"}),
            "C6": ("A8V5-01-S02", {"subject", "operation"}),
        },
        {"A8V5-01-S01", "A8V5-01-S02"},
        {("A8V5-01-S01", "A8V5-01-S02")},
        summary="文書openは完全、同名Word子プロセスはsubject/actionまで。object slotが欠落。",
    ),
    "gpt-5.4-mini/stage2/s3_pt_01_word_document_processing_stage2": decision(
        {
            "C1": ("A8V5-01-S02", {"subject", "operation", "object"}),
            "C3": ("A8V5-01-S01", {"subject", "operation", "object"}),
        },
        {"A8V5-01-S01", "A8V5-01-S02"},
        set(),
        duplicate_claims={"C7"},
        summary="両Gold stepは完全復元したが、融合したprocess stepを先に置きGold順序を逆転。supporting fileを多数列挙。",
    ),
    "gpt-5.4-mini/stage3/s3_pt_01_word_document_processing_stage3": decision(
        {
            "C1": ("A8V5-01-S02", {"subject", "operation", "object"}),
            "C3": ("A8V5-01-S01", {"subject", "operation", "object"}),
        },
        {"A8V5-01-S01", "A8V5-01-S02"},
        set(),
        duplicate_claims={"C2"},
        summary="両stepの要素は完全だが、子プロセスstepを文書openより先に出してorderを落とした。",
    ),
    "gpt-4.1-mini/stage1/s4_pt_03_mshta_c1_stage1": decision(
        {
            "C1": ("A8V5-07-S03", {"subject", "operation", "object"}),
            "C3": ("A8V5-07-S06", {"subject", "operation", "object"}),
            "C5": ("A8V5-07-S05", {"operation", "object"}),
        },
        {"A8V5-07-S01", "A8V5-07-S03", "A8V5-07-S06"},
        set(),
        summary="mshta→PowerShellとPowerShell→cmdは復元。8443 endpointのactorをpayloadへ誤接続し、前段8080と後段payload chainを欠落。",
    ),
    "gpt-4.1-mini/stage2/s4_pt_03_mshta_c1_stage2": decision(
        {
            "C1": ("A8V5-07-S03", {"subject", "operation", "object"}),
            "C2": ("A8V5-07-S04", {"subject", "operation"}),
            "C3": ("A8V5-07-S07", {"subject", "operation", "object"}),
        },
        {"A8V5-07-S03", "A8V5-07-S04", "A8V5-07-S07"},
        {("A8V5-07-S03", "A8V5-07-S04")},
        summary="離れた3 edgeを拾ったがPowerShell→cmdをcode step化せず、連続chainが分断。近傍のDLL/registryを過剰接続。",
    ),
    "gpt-4.1-mini/stage3/s4_pt_03_mshta_c1_stage3": decision(
        {
            "C1": ("A8V5-07-S01", {"operation", "object"}),
            "C2": ("A8V5-07-S04", {"subject", "operation", "object"}),
            "C3": ("A8V5-07-S05", {"subject", "operation", "object"}),
            "C5": ("A8V5-07-S07", {"subject", "operation", "object"}),
            "C6": ("A8V5-07-S08", {"subject", "operation", "object"}),
        },
        {
            "A8V5-07-S01",
            "A8V5-07-S03",
            "A8V5-07-S04",
            "A8V5-07-S05",
            "A8V5-07-S07",
        },
        {
            ("A8V5-07-S04", "A8V5-07-S05"),
            ("A8V5-07-S07", "A8V5-07-S08"),
        },
        summary="frontier追跡で8443とpayload実行まで到達。mshta→PowerShell、PowerShell→cmd、payload→9999の明示stepが欠落。",
    ),
    "gpt-5.4-mini/stage1/s4_pt_03_mshta_c1_stage1": decision(
        {
            "C1": ("A8V5-07-S03", {"subject", "operation", "object"}),
            "C2": ("A8V5-07-S04", {"subject", "operation", "object"}),
            "C3": ("A8V5-07-S06", {"subject", "operation", "object"}),
            "C4": ("A8V5-07-S07", {"subject", "operation", "object"}),
        },
        {
            "A8V5-07-S01",
            "A8V5-07-S03",
            "A8V5-07-S04",
            "A8V5-07-S06",
            "A8V5-07-S07",
        },
        {
            ("A8V5-07-S03", "A8V5-07-S04"),
            ("A8V5-07-S06", "A8V5-07-S07"),
        },
        summary="中央のprocess chainは4 step完全。8080/8443/9999 networkとpayload self-spawnを追跡できず前後が欠落。",
    ),
    "gpt-5.4-mini/stage2/s4_pt_03_mshta_c1_stage2": decision(
        {
            "C1": ("A8V5-07-S01", {"operation", "object"}),
            "C2": ("A8V5-07-S04", {"subject", "operation", "object"}),
        },
        {"A8V5-07-S01", "A8V5-07-S03", "A8V5-07-S04"},
        set(),
        summary="起動周辺の証拠は得たが主語正規化に失敗し、mshta→PowerShellを独立claim化せず2 stepで早期停止。",
    ),
    "gpt-5.4-mini/stage3/s4_pt_03_mshta_c1_stage3": decision(
        {
            "C1": ("A8V5-07-S01", {"operation", "object"}),
            "C3": ("A8V5-07-S02", {"subject", "operation", "object"}),
            "C4": ("A8V5-07-S03", {"operation", "object"}),
            "C7": ("A8V5-07-S06", {"subject", "operation", "object"}),
            "C8": ("A8V5-07-S04", {"subject", "operation", "object"}),
        },
        {
            "A8V5-07-S01",
            "A8V5-07-S02",
            "A8V5-07-S03",
            "A8V5-07-S04",
            "A8V5-07-S06",
        },
        {
            ("A8V5-07-S01", "A8V5-07-S02"),
            ("A8V5-07-S02", "A8V5-07-S03"),
            ("A8V5-07-S03", "A8V5-07-S04"),
        },
        summary="8080と前半process frontierは改善。8443以降、cmd→payload、payload self-spawn、9999を取れず後半chainが途切れた。",
    ),
}


def canon(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json_new(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def write_jsonl_new(path: Path, rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"create-only refusal: {path}")
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def chain_id(instance_id: str) -> str:
    return instance_id.rsplit("_stage", 1)[0]


def full_step_id(instance_id: str, short_step: str) -> str:
    return f"{chain_id(instance_id)}:{short_step}"


def group_key(row: dict[str, Any]) -> str:
    return f"{row['model']}/{row['stage']}/{row['instance_id']}"


def metricize(total: dict[str, Any]) -> dict[str, Any]:
    result = dict(total)
    for name, numerator, denominator in (
        ("action_recall", "gold_action_hits", "gold_action_denominator"),
        ("candidate_precision", "candidate_slot_tp", "candidate_slot_denominator"),
        ("behavior_step_recall", "behavior_step_hits", "behavior_step_denominator"),
        (
            "critical_evidence_recall",
            "critical_evidence_hits",
            "critical_evidence_denominator",
        ),
        ("order_recall", "order_pair_hits", "order_pair_denominator"),
    ):
        den = result[denominator]
        result[name] = {
            "hits": result[numerator],
            "denominator": den,
            "value": result[numerator] / den if den else None,
        }
    return result


def totals(row: dict[str, Any]) -> dict[str, Any]:
    action = [x for x in row["gold_items"] if x["kind"] in ACTION_KINDS]
    critical = [x for x in row["gold_items"] if x["kind"] == "critical_evidence"]
    by_step: dict[str, dict[str, int]] = defaultdict(dict)
    for item in action:
        by_step[item["item_id"].rsplit(":", 1)[0]][item["kind"]] = item["score"]
    tp_targets = [
        x["matched_gold_item_id"]
        for x in row["candidate_slots"]
        if x["include_in_denominator"] == 1 and x["is_true_positive"] == 1
    ]
    fp = [
        x["false_positive_type"]
        for x in row["candidate_slots"]
        if x["include_in_denominator"] == 1 and x["is_true_positive"] == 0
    ]
    return {
        "case_count": 1,
        "gold_action_denominator": len(action),
        "gold_action_hits": sum(x["score"] for x in action),
        "candidate_slot_denominator": sum(
            x["include_in_denominator"] for x in row["candidate_slots"]
        ),
        "candidate_slot_tp": len(tp_targets),
        "candidate_slot_fp": len(fp),
        "behavior_step_denominator": len(by_step),
        "behavior_step_hits": sum(
            all(parts.get(kind) == 1 for kind in ACTION_KINDS)
            for parts in by_step.values()
        ),
        "critical_evidence_denominator": len(critical),
        "critical_evidence_hits": sum(x["score"] for x in critical),
        "order_pair_denominator": len(row["order_pairs"]),
        "order_pair_hits": sum(x["score"] for x in row["order_pairs"]),
        "duplicate_tp_slot_count": len(tp_targets) - len(set(tp_targets)),
        "false_positive_types": dict(Counter(fp)),
    }


def merge_totals(parts: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = defaultdict(int)
    fp: Counter[str] = Counter()
    for part in parts:
        for key, value in part.items():
            if key == "false_positive_types":
                fp.update(value)
            else:
                result[key] += value
    result["false_positive_types"] = dict(fp)
    return metricize(dict(result))


def create_overlay() -> dict[str, Any]:
    return {
        "schema_version": "attack8_v5_atomic_pid_non_scoring_overlay_v1",
        "authority": "frozen v5 Gold and normal23 component-rubric parity",
        "action_components": ["subject", "operation", "object"],
        "action_aliases_operation": True,
        "pid_identity_scored": False,
        "hidden_alert_mapping_scored": False,
        "critical_evidence_separate": True,
        "candidate_claim_alignment": (
            "one candidate claim aligns to at most one Gold step; TP slots in the "
            "claim must share that step; duplicate Gold-component coverage is FP"
        ),
        "action_hit_derivation": (
            "Gold action hit iff exactly one included literal TP candidate slot "
            "matches its item_id"
        ),
        "order_rule": (
            "two distinct aligned candidate claims must express the adjacent "
            "Gold steps in the Gold order"
        ),
        "external_judge_api_used": False,
    }


def derive_queue(
    source_rows: list[dict[str, Any]], overlay_sha256: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in source_rows:
        row = copy.deepcopy(source)
        row["schema_version"] = "codex_manual_action_claim_review_v5_atomic_queue"
        row["source_queue_id"] = source["queue_id"]
        row["source_contract_sha256"] = source["contract_sha256"]
        row["review_policy_overlay_sha256"] = overlay_sha256
        row["review_policy"] = {
            **source["review_policy"],
            "pid_identity_scored": False,
            "hidden_alert_mapping_scored": False,
            "match_semantics": (
                "Judge semantic equivalence from observed claims only. PID is "
                "provenance and is not independently scored. Align each candidate "
                "claim to at most one Gold step; do not backfill an unexpressed "
                "subject, operation, object, evidence, or causal edge."
            ),
        }
        contract = {
            key: row[key]
            for key in (
                "model",
                "stage",
                "instance_id",
                "run_sha256",
                "gold_sha256",
                "validation_steps_sha256",
                "maxima",
                "gold_items",
                "order_pairs",
                "candidate_slots",
            )
        }
        contract["review_policy_overlay_sha256"] = overlay_sha256
        row["contract_sha256"] = sha_bytes(canon(contract))
        row["queue_id"] = (
            f"{row['model']}/{row['stage']}/{row['instance_id']}/"
            f"{row['contract_sha256'][:16]}"
        )
        rows.append(row)
    return rows


def score_row(queue: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    prefix = chain_id(queue["instance_id"])
    gold = {x["item_id"]: x for x in queue["gold_items"]}
    target_to_slot: dict[str, dict[str, Any]] = {}
    claim_specs = spec["claims"]
    slots: list[dict[str, Any]] = []
    for source in queue["candidate_slots"]:
        slot = copy.deepcopy(source)
        claim_id = slot["candidate_claim_id"]
        claim_spec = claim_specs.get(claim_id)
        if claim_spec:
            short_step, tp_kinds = claim_spec
            aligned = full_step_id(queue["instance_id"], short_step)
            slot["aligned_gold_step_id"] = aligned
            if slot["kind"] in tp_kinds:
                target = f"{aligned}:{slot['kind']}"
                if target not in gold:
                    raise ValueError(f"unknown TP target: {target}")
                if target in target_to_slot:
                    raise ValueError(
                        f"duplicate TP coverage: {queue['queue_id']} {target}"
                    )
                slot["matched_gold_item_id"] = target
                slot["is_true_positive"] = 1
                slot["false_positive_type"] = ""
                slot["reason_ja"] = (
                    f"{claim_id}の{slot['kind']}は{short_step}の同種要素を"
                    "意味的に明示している。PID一致は採点していない。"
                )
                target_to_slot[target] = slot
            else:
                slot["matched_gold_item_id"] = None
                slot["is_true_positive"] = 0
                slot["false_positive_type"] = "wrong_component"
                slot["reason_ja"] = (
                    f"{claim_id}は{short_step}へ整列するが、この"
                    f"{slot['kind']}要素はGold値/関係を満たさない。"
                )
        else:
            slot["aligned_gold_step_id"] = None
            slot["matched_gold_item_id"] = None
            slot["is_true_positive"] = 0
            slot["false_positive_type"] = (
                "duplicate"
                if claim_id in spec["duplicate_claims"]
                else "unsupported"
            )
            slot["reason_ja"] = (
                "既採用Gold要素の重複claim。"
                if claim_id in spec["duplicate_claims"]
                else "Gold chain外のsupporting/近傍行動、または対応Gold stepなし。"
            )
        slot["include_in_denominator"] = 1
        slots.append(slot)

    critical_steps = {
        full_step_id(queue["instance_id"], value) for value in spec["critical"]
    }
    gold_items: list[dict[str, Any]] = []
    for source in queue["gold_items"]:
        item = copy.deepcopy(source)
        if item["kind"] in ACTION_KINDS:
            item["score"] = int(item["item_id"] in target_to_slot)
            match = target_to_slot.get(item["item_id"])
            item["matched_candidate_excerpt"] = (
                match["candidate_slot_excerpt"] if match else None
            )
            item["reason_ja"] = (
                "included TP candidate slotの一意matched_gold_item_idから導出。"
            )
            item["score_source"] = "derived_from_unique_included_tp_candidate_slot"
        else:
            step = item["item_id"].rsplit(":", 1)[0]
            item["score"] = int(step in critical_steps)
            item["matched_candidate_excerpt"] = None
            item["reason_ja"] = (
                "Goldのprocess/operation/target/timing/causal supportを"
                + ("実質的に回収。" if item["score"] else "十分には回収していない。")
            )
        gold_items.append(item)

    correct_pairs = {
        (
            full_step_id(queue["instance_id"], left),
            full_step_id(queue["instance_id"], right),
        )
        for left, right in spec["order"]
    }
    pairs: list[dict[str, Any]] = []
    for source in queue["order_pairs"]:
        pair = copy.deepcopy(source)
        raw = pair["pair_id"].split(":", 1)[1]
        left, right = raw.split("->", 1)
        full_pair = (f"{prefix}:{left}", f"{prefix}:{right}")
        pair["score"] = int(full_pair in correct_pairs)
        pair["reason_ja"] = (
            "異なるcandidate claimが隣接Gold stepをこの順で表現。"
            if pair["score"]
            else "片方のstep欠落、融合、または順序逆転。"
        )
        pairs.append(pair)

    row = {
        "schema_version": "codex_manual_action_claim_review_v5_atomic_single_pilot",
        "queue_id": queue["queue_id"],
        "source_queue_id": queue["source_queue_id"],
        "contract_sha256": queue["contract_sha256"],
        "review_policy_overlay_sha256": queue[
            "review_policy_overlay_sha256"
        ],
        "reviewer_id": "/root/codex_frontier_pilot_single_review_20260729",
        "model": queue["model"],
        "stage": queue["stage"],
        "instance_id": queue["instance_id"],
        "run_sha256": queue["run_sha256"],
        "gold_sha256": queue["gold_sha256"],
        "gold_items": gold_items,
        "order_pairs": pairs,
        "candidate_slots": slots,
        "review_summary_ja": spec["summary"],
        "external_judge_api_used": False,
    }
    row["decision_sha256"] = sha_bytes(canon(row))
    return row


def trace_audit(queue_rows: list[dict[str, Any]]) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    totals = Counter()
    for queue in queue_rows:
        run_path = Path(queue["run_json"])
        run = json.loads(run_path.read_text(encoding="utf-8"))
        lead_calls = 0
        lead_returns = 0
        unresolved_mentions = 0
        question_count = 0
        for message in run.get("official_messages") or []:
            for call in message.get("tool_calls") or []:
                if call.get("name") == "investigate_lead":
                    lead_calls += 1
            if message.get("type") == "ToolMessage" and message.get(
                "name"
            ) == "investigate_lead":
                lead_returns += 1
                content = str(message.get("content") or "")
                unresolved_mentions += content.count("## unresolved_frontier")
                question_count += len(
                    re.findall(r"(?m)^\s*\d+\.\s+", content)
                )
        configs = run.get("configs") or {}
        guard = configs.get("sql_execution_guard")
        raw_text = run_path.read_text(encoding="utf-8").lower()
        guard_events = sum(
            raw_text.count(token)
            for token in (
                "sql query aborted",
                "sql vm step limit",
                "unsafe recursive",
                "sql wall timeout",
            )
        )
        output = json.loads(run["output_text"])
        alert_rows = 0
        if queue["stage"] == "stage3":
            alert_rows = len(output.get("supporting_alert_evidence") or [])
        usage = run.get("usage") or {}
        item = {
            "model": queue["model"],
            "stage": queue["stage"],
            "instance_id": queue["instance_id"],
            "run_sha256": queue["run_sha256"],
            "investigate_lead_calls": lead_calls,
            "investigate_lead_returns": lead_returns,
            "unresolved_frontier_sections": unresolved_mentions,
            "investigator_numbered_questions": question_count,
            "sql_guard_config_recorded": guard is not None,
            "sql_guard_events": guard_events,
            "frontier_closure_policy": configs.get("frontier_closure_policy"),
            "max_investigations": configs.get("max_investigations"),
            "max_questions": configs.get("max_questions"),
            "max_queries": configs.get("max_queries"),
            "agent_call_limit_policy": configs.get("agent_call_limit_policy"),
            "stage3_supporting_alert_rows": alert_rows,
            "usage": {
                "input_tokens": int(usage.get("input_tokens") or 0),
                "output_tokens": int(usage.get("output_tokens") or 0),
                "cached_input_tokens": int(
                    usage.get("cached_input_tokens") or 0
                ),
            },
        }
        runs.append(item)
        totals.update(
            {
                "investigate_lead_calls": lead_calls,
                "investigate_lead_returns": lead_returns,
                "unresolved_frontier_sections": unresolved_mentions,
                "investigator_numbered_questions": question_count,
                "sql_guard_config_recorded": int(guard is not None),
                "sql_guard_events": guard_events,
                "stage3_supporting_alert_rows": alert_rows,
                "input_tokens": item["usage"]["input_tokens"],
                "output_tokens": item["usage"]["output_tokens"],
                "cached_input_tokens": item["usage"]["cached_input_tokens"],
            }
        )
    return {
        "schema_version": "attack8_frontier_pilot_trace_runtime_audit_v1",
        "run_count": len(runs),
        "totals": dict(totals),
        "runs": runs,
        "notes": {
            "sql_guard_provenance": (
                "The first four preserved gpt-4.1-mini completions predate "
                "sql_execution_guard provenance; completed runs were not rerun."
            ),
            "stage3_alert_check": (
                "Counts only final output supporting_alert_evidence rows; "
                "hidden alert mapping is not scored."
            ),
        },
    }


def main() -> None:
    source_rows = load_jsonl(SOURCE_QUEUE)
    if len(source_rows) != EXPECTED["row_count"]:
        raise SystemExit(
            f"source queue rows={len(source_rows)}, expected={EXPECTED['row_count']}"
        )
    overlay = create_overlay()
    overlay_sha256 = sha_bytes(canon(overlay))
    overlay["decision_sha256"] = overlay_sha256
    derived = derive_queue(source_rows, overlay_sha256)
    if set(group_key(row) for row in derived) != set(DECISIONS):
        missing = set(group_key(row) for row in derived) ^ set(DECISIONS)
        raise SystemExit(f"decision/queue key mismatch: {sorted(missing)}")
    reviews = [score_row(row, DECISIONS[group_key(row)]) for row in derived]

    failures: list[str] = []
    for queue, review in zip(derived, reviews):
        gold = {x["item_id"]: x for x in review["gold_items"]}
        targets = [
            x["matched_gold_item_id"]
            for x in review["candidate_slots"]
            if x["include_in_denominator"] == 1 and x["is_true_positive"] == 1
        ]
        if len(targets) != len(set(targets)):
            failures.append(f"duplicate TP target: {review['queue_id']}")
        aligned_by_claim: dict[str, set[str]] = defaultdict(set)
        for slot in review["candidate_slots"]:
            if slot["aligned_gold_step_id"]:
                aligned_by_claim[slot["candidate_claim_id"]].add(
                    slot["aligned_gold_step_id"]
                )
            if slot["is_true_positive"] == 1:
                target = slot["matched_gold_item_id"]
                if target not in gold:
                    failures.append(f"unknown target: {review['queue_id']} {target}")
                elif gold[target]["kind"] != slot["kind"]:
                    failures.append(f"kind mismatch: {review['queue_id']} {target}")
        if any(len(values) > 1 for values in aligned_by_claim.values()):
            failures.append(f"claim multi-align: {review['queue_id']}")
        for item in review["gold_items"]:
            if item["kind"] in ACTION_KINDS:
                expected = int(item["item_id"] in targets)
                if item["score"] != expected:
                    failures.append(
                        f"Gold/TP inconsistency: {review['queue_id']} "
                        f"{item['item_id']}"
                    )
        if review["run_sha256"] != queue["run_sha256"]:
            failures.append(f"run hash mismatch: {review['queue_id']}")
        if review["gold_sha256"] != queue["gold_sha256"]:
            failures.append(f"gold hash mismatch: {review['queue_id']}")

    row_totals = {
        review["queue_id"]: totals(review) for review in reviews
    }

    def grouped(field_names: tuple[str, ...]) -> dict[str, Any]:
        buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for review in reviews:
            key = "/".join(str(review[name]) for name in field_names)
            buckets[key].append(row_totals[review["queue_id"]])
        return {
            key: merge_totals(parts) for key, parts in sorted(buckets.items())
        }

    overall = merge_totals(list(row_totals.values()))
    for key, expected in EXPECTED.items():
        actual = (
            len(reviews) if key == "row_count" else overall.get(key)
        )
        if actual != expected:
            failures.append(f"denominator mismatch {key}: {actual} != {expected}")
    if overall["duplicate_tp_slot_count"] != 0:
        failures.append("duplicate TP slots are nonzero")

    aggregate = {
        "schema_version": "attack8_frontier_pilot_v5_atomic_aggregate_v1",
        "review_mode": "single Codex item review plus deterministic audit",
        "external_judge_api_used": False,
        "overall": overall,
        "by_model": grouped(("model",)),
        "by_stage": grouped(("stage",)),
        "by_model_stage": grouped(("model", "stage")),
        "by_use_case": grouped(("instance_id",)),
        "by_model_use_case": grouped(("model", "instance_id")),
    }
    detail = {
        "schema_version": "attack8_frontier_pilot_metrics_by_model_stage_case_v1",
        "rows": [
            {
                "model": review["model"],
                "stage": review["stage"],
                "instance_id": review["instance_id"],
                "queue_id": review["queue_id"],
                "metrics": metricize(row_totals[review["queue_id"]]),
                "review_summary_ja": review["review_summary_ja"],
            }
            for review in reviews
        ],
        **{key: aggregate[key] for key in aggregate if key.startswith("by_")},
        "overall": overall,
    }
    trace = trace_audit(derived)
    audit = {
        "schema_version": "attack8_frontier_pilot_v5_atomic_audit_v1",
        "status": "PASS" if not failures else "FAIL",
        "row_count": len(reviews),
        "expected_denominators": EXPECTED,
        "observed_denominators": {
            key: len(reviews) if key == "row_count" else overall.get(key)
            for key in EXPECTED
        },
        "atomic_consistency": {
            "gold1_without_tp": 0,
            "tp_gold0": 0,
            "duplicate_tp_slot_count": overall["duplicate_tp_slot_count"],
            "candidate_claim_multi_alignment_count": 0,
        },
        "source_hashes": {
            "source_queue_sha256": sha_file(SOURCE_QUEUE),
            "review_policy_overlay_sha256": overlay_sha256,
            "run_sha256": {
                row["queue_id"]: row["run_sha256"] for row in derived
            },
            "gold_sha256": {
                row["queue_id"]: row["gold_sha256"] for row in derived
            },
        },
        "failures": failures,
        "external_judge_api_used": False,
    }
    write_json_new(OVERLAY, overlay)
    write_jsonl_new(DERIVED_QUEUE, derived)
    write_jsonl_new(REVIEW, reviews)
    write_json_new(AGGREGATE, aggregate)
    write_json_new(DETAILS, detail)
    write_json_new(TRACE, trace)
    write_json_new(AUDIT, audit)
    if failures:
        raise SystemExit("audit failed: " + "; ".join(failures))
    print(
        json.dumps(
            {
                "status": audit["status"],
                "rows": len(reviews),
                "overall": overall,
                "trace_totals": trace["totals"],
                "artifacts": {
                    path.name: sha_file(path)
                    for path in (
                        OVERLAY,
                        DERIVED_QUEUE,
                        REVIEW,
                        AGGREGATE,
                        DETAILS,
                        TRACE,
                        AUDIT,
                    )
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
