#!/usr/bin/env python3
"""Aggregate GPT-5.5 Stage 2 reconstruction by maximum process-pivot depth.

The script uses only existing Gold, formal scores, and the semantic action
overlay.  It does not rerun CLOUSEAU.  Maximum depth is the undirected
shortest-path distance on Gold PROCESS_CREATE edges from the Stage 2 focus
process instance.  When the focus executable occurs more than once, the
earliest instance in the Gold timeline is used as the anchor.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path

from analyze_gpt55_stage2_structural_axes_20260814 import (
    FORMAL,
    OVERLAY,
    first_exe,
    label_steps,
    load_step_metadata,
    read_jsonl,
    resolve_path,
)


ROOT = Path(__file__).resolve().parents[1]


def load_rows() -> tuple[list[dict], list[dict]]:
    formal = [
        row
        for row in read_jsonl(FORMAL)
        if row.get("model") == "gpt-5.5" and row.get("stage") == "stage2"
    ]
    overlay = [
        row
        for row in read_jsonl(OVERLAY)
        if row.get("model") == "gpt-5.5" and row.get("stage") == "stage2"
    ]
    return formal, overlay


def action_meta(overlay_rows: list[dict]) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in overlay_rows:
        for decision in row["action_decisions"]:
            result.setdefault(decision["step_id"], decision["gold_action_class"])
    return result


def case_structure(row: dict, classes: dict[str, str]) -> dict:
    gold_path = resolve_path(row.get("gold_json") or row.get("gold_path"))
    run_path = resolve_path(row.get("run_json") or row.get("run_path"))
    if gold_path is None or run_path is None:
        raise RuntimeError(f"Missing Gold/run path: {row['chain_id']}")
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    run = json.loads(run_path.read_text(encoding="utf-8"))
    focus = run["gold_reference"]["model_ready_input"]["input"]["focus_processes"]
    if isinstance(focus, str):
        focus = [focus]
    focus = {item.lower() for item in focus}

    graph: dict[int, set[int]] = defaultdict(set)
    pid_name: dict[int, str] = {}
    first_seen: dict[int, str] = {}
    process_pids: set[int] = set()

    for step in gold["gold_steps"]:
        signature = step.get("critical_evidence_signature") or {}
        timestamp = str(signature.get("timestamp_utc") or "9999")
        subject_pid = signature.get("process_pid")
        subject_name = first_exe(step.get("subject"))
        if isinstance(subject_pid, int):
            process_pids.add(subject_pid)
            if subject_name:
                pid_name.setdefault(subject_pid, subject_name)
            first_seen[subject_pid] = min(first_seen.get(subject_pid, timestamp), timestamp)

        if classes.get(step["step_id"]) != "PROCESS_CREATE":
            continue
        child_pid = signature.get("target_key")
        child_name = first_exe(step.get("object"))
        if not isinstance(subject_pid, int) or not isinstance(child_pid, int):
            continue
        process_pids.add(child_pid)
        if child_name:
            pid_name.setdefault(child_pid, child_name)
        first_seen[child_pid] = min(first_seen.get(child_pid, timestamp), timestamp)
        graph[subject_pid].add(child_pid)
        graph[child_pid].add(subject_pid)

    anchors = [pid for pid, name in pid_name.items() if name in focus]
    if not anchors:
        # A relation may have no PROCESS_CREATE edge; its subject is the focus.
        anchors = [pid for pid in process_pids if pid_name.get(pid) in focus]
    if not anchors:
        raise RuntimeError(f"No focus process instance found: {row['chain_id']} focus={focus}")
    anchor = min(anchors, key=lambda pid: (first_seen.get(pid, "9999"), pid))

    distance = {anchor: 0}
    queue = deque([anchor])
    while queue:
        current = queue.popleft()
        for neighbor in graph[current]:
            if neighbor not in distance:
                distance[neighbor] = distance[current] + 1
                queue.append(neighbor)

    reachable = [distance[pid] for pid in process_pids if pid in distance]
    max_depth = max(reachable, default=0)
    return {
        "phase": row["phase"],
        "chain_id": row["chain_id"],
        "gold_steps": len(gold["gold_steps"]),
        "anchor_pid": anchor,
        "anchor_name": pid_name.get(anchor, ""),
        "max_depth": max_depth,
        "process_instances": len(process_pids),
    }


def region(depth: int) -> str:
    if depth <= 1:
        return "local (D=0-1)"
    if depth == 2:
        return "shallow chain (D=2)"
    return "deep chain (D>=3)"


def structural_region(has_pivot: bool, has_multiple: bool) -> str:
    difficulty = int(has_pivot) + int(has_multiple)
    if difficulty == 0:
        return "R1 local + unique"
    if difficulty == 1:
        return "R2 one structural burden"
    return "R3 pivot + multiple"


def main() -> None:
    formal_rows, overlay_rows = load_rows()
    classes = action_meta(overlay_rows)
    chains, _ = load_step_metadata(formal_rows, overlay_rows)
    step_labels = label_steps(chains)
    case_flags: dict[str, dict[str, bool]] = {}
    for chain_id in chains:
        labels = [item for item in step_labels.values() if item["chain_id"] == chain_id]
        case_flags[chain_id] = {
            "has_pivot": any(item["pivot"] == "pivot必要" for item in labels),
            "has_multiple": any(item["instance"] == "候補複数" for item in labels),
        }
    overlay_by_key = {
        (row["phase"], row["replicate"], row["chain_id"]): row
        for row in overlay_rows
    }

    structures: dict[str, dict] = {}
    observations: list[dict] = []
    for formal in formal_rows:
        chain_id = formal["chain_id"]
        structures.setdefault(chain_id, case_structure(formal, classes))
        overlay = overlay_by_key[(formal["phase"], formal["replicate"], chain_id)]
        semantic = {
            item["step_id"]: item["semantic_score"]
            for item in overlay["action_decisions"]
        }
        item_score = {
            (item["step_id"], item["kind"]): item["score"]
            for item in formal["gold_items"]
        }
        step_ids = sorted(semantic)
        complete = {
            step_id: int(
                semantic[step_id] == 1
                and item_score[(step_id, "subject")] == 1
                and item_score[(step_id, "object")] == 1
            )
            for step_id in step_ids
        }
        evidence = {
            step_id: int(item_score[(step_id, "critical_evidence")] == 1)
            for step_id in step_ids
        }
        order_scores = [int(item["score"]) for item in formal["order_pairs"]]
        observations.append(
            {
                **structures[chain_id],
                "replicate": formal["replicate"],
                "region": region(structures[chain_id]["max_depth"]),
                "structural_region": structural_region(**case_flags[chain_id]),
                "complete_hits": sum(complete.values()),
                "complete_n": len(complete),
                "evidence_hits": sum(evidence.values()),
                "evidence_n": len(evidence),
                "order_hits": sum(order_scores),
                "order_n": len(order_scores),
                "full_chain": int(all(complete.values())),
                "full_order": int(all(order_scores)) if order_scores else 1,
            }
        )

    print("[CASE STRUCTURE AND OBSERVED STAGE 2 RESULTS]")
    by_case: dict[str, list[dict]] = defaultdict(list)
    for row in observations:
        by_case[row["chain_id"]].append(row)
    for chain_id in sorted(by_case):
        rows = by_case[chain_id]
        c_hits = sum(item["complete_hits"] for item in rows)
        c_n = sum(item["complete_n"] for item in rows)
        full = sum(item["full_chain"] for item in rows)
        print(
            f"{rows[0]['phase']} | {chain_id} | D={rows[0]['max_depth']} "
            f"| Gold={rows[0]['gold_steps']} | runs={len(rows)} "
            f"| complete={c_hits}/{c_n} ({c_hits/c_n:.1%}) "
            f"| full_chain={full}/{len(rows)} ({full/len(rows):.1%})"
        )

    print("\n[STRUCTURAL REGIONS: CASE-LEVEL GROUPING]")
    by_structural: dict[str, list[dict]] = defaultdict(list)
    for row in observations:
        by_structural[row["structural_region"]].append(row)
    for label in (
        "R1 local + unique",
        "R2 one structural burden",
        "R3 pivot + multiple",
    ):
        rows = by_structural[label]
        cases = sorted({row["chain_id"] for row in rows})
        c_hits = sum(row["complete_hits"] for row in rows)
        c_n = sum(row["complete_n"] for row in rows)
        e_hits = sum(row["evidence_hits"] for row in rows)
        e_n = sum(row["evidence_n"] for row in rows)
        o_hits = sum(row["order_hits"] for row in rows)
        o_n = sum(row["order_n"] for row in rows)
        full = sum(row["full_chain"] for row in rows)
        print(
            f"{label} | cases={len(cases)} runs={len(rows)} "
            f"| complete={c_hits}/{c_n} ({c_hits/c_n:.1%}) "
            f"| evidence={e_hits}/{e_n} ({e_hits/e_n:.1%}) "
            f"| order={o_hits}/{o_n} ({o_hits/o_n:.1%}) "
            f"| full_chain={full}/{len(rows)} ({full/len(rows):.1%})"
        )
        print("  cases=" + ", ".join(cases))

    print("\n[DEPTH REGIONS: MICRO AVERAGE OVER OBSERVED RUNS]")
    by_region: dict[str, list[dict]] = defaultdict(list)
    for row in observations:
        by_region[row["region"]].append(row)
    for label in ("local (D=0-1)", "shallow chain (D=2)", "deep chain (D>=3)"):
        rows = by_region[label]
        cases = {row["chain_id"] for row in rows}
        c_hits = sum(row["complete_hits"] for row in rows)
        c_n = sum(row["complete_n"] for row in rows)
        e_hits = sum(row["evidence_hits"] for row in rows)
        e_n = sum(row["evidence_n"] for row in rows)
        o_hits = sum(row["order_hits"] for row in rows)
        o_n = sum(row["order_n"] for row in rows)
        full = sum(row["full_chain"] for row in rows)
        full_order = sum(row["full_order"] for row in rows)
        print(
            f"{label} | cases={len(cases)} runs={len(rows)} "
            f"| complete={c_hits}/{c_n} ({c_hits/c_n:.1%}) "
            f"| evidence={e_hits}/{e_n} ({e_hits/e_n:.1%}) "
            f"| order={o_hits}/{o_n} ({o_hits/o_n:.1%}) "
            f"| full_chain={full}/{len(rows)} ({full/len(rows):.1%}) "
            f"| full_order={full_order}/{len(rows)} ({full_order/len(rows):.1%})"
        )


if __name__ == "__main__":
    main()
