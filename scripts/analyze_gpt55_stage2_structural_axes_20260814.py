#!/usr/bin/env python3
"""Classify GPT-5.5 Stage 2 Gold steps on three structural axes.

The analysis is deliberately based only on existing Gold, formal scores, and
the semantic action-score overlay. It does not rerun CLOUSEAU.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "docs/current_experiment/results_2026-08-07/gpt55_three_replicate_96pass_scores_codex_sol_provisional_v2/formal_scores_96pass.jsonl"
OVERLAY = ROOT / "docs/current_experiment/results_2026-08-14/three_model_all_trials_action_order_semantic_v1/semantic_rescore_overlay_all_scored.jsonl"

SEMANTIC_EVIDENCE_KINDS = {
    "command_script",
    "command_network",
    "command_process_creation",
    "parent_child_command",
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def resolve_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def first_exe(value: object) -> str | None:
    match = re.search(r"(?i)([a-z0-9_.-]+\.exe)", str(value or ""))
    return match.group(1).lower() if match else None


def explicit_pids(value: object) -> set[int]:
    return {int(item) for item in re.findall(r"(?i)PID\s*[:=]?\s*(\d+)", str(value or ""))}


def canonical_row(step: dict) -> dict:
    rows = step.get("canonical_evidence") or []
    return rows[0] if rows else {}


def step_pids(step: dict, action_class: str) -> tuple[set[int], set[int]]:
    signature = step.get("critical_evidence_signature") or {}
    canonical = canonical_row(step)

    subject = explicit_pids(step.get("subject"))
    if not subject:
        pid = canonical.get("process_pid", signature.get("process_pid"))
        if isinstance(pid, int):
            subject.add(pid)

    obj = explicit_pids(step.get("object"))
    if action_class == "PROCESS_CREATE" and not obj:
        pid = canonical.get("childproc_pid")
        if not isinstance(pid, int):
            target = signature.get("target_key")
            pid = target if isinstance(target, int) else None
        if isinstance(pid, int):
            obj.add(pid)
    return subject, obj


def load_step_metadata(formal_rows: list[dict], overlay_rows: list[dict]) -> tuple[dict, dict]:
    action_meta: dict[str, dict] = {}
    for row in overlay_rows:
        for decision in row["action_decisions"]:
            action_meta.setdefault(
                decision["step_id"],
                {
                    "action_class": decision["gold_action_class"],
                    "evidence_kind": decision["gold_evidence_kind"],
                },
            )

    chains: dict[str, dict] = {}
    for row in formal_rows:
        chain_id = row["chain_id"]
        if chain_id in chains:
            continue

        gold_path = resolve_path(row.get("gold_json") or row.get("gold_path"))
        run_path = resolve_path(row.get("run_json") or row.get("run_path"))
        if gold_path is None or run_path is None:
            raise RuntimeError(f"Missing Gold/run path for {chain_id}")

        gold = json.loads(gold_path.read_text(encoding="utf-8"))
        run = json.loads(run_path.read_text(encoding="utf-8"))
        focus = run["gold_reference"]["model_ready_input"]["input"]["focus_processes"]
        if isinstance(focus, str):
            focus = [focus]

        steps = gold["gold_steps"]
        for step in steps:
            meta = action_meta[step["step_id"]]
            step["_action_class"] = meta["action_class"]
            step["_evidence_kind"] = step.get("evidence_kind") or meta["evidence_kind"]
            step["_subject_name"] = first_exe(step.get("subject"))
            step["_object_name"] = first_exe(step.get("object"))
            step["_subject_pids"], step["_object_pids"] = step_pids(step, meta["action_class"])

        chains[chain_id] = {
            "phase": row["phase"],
            "focus": {name.lower() for name in focus},
            "steps": steps,
        }

    return chains, action_meta


def label_steps(chains: dict[str, dict]) -> dict[str, dict]:
    labels: dict[str, dict] = {}

    for chain_id, chain in chains.items():
        name_to_pids: dict[str, set[int]] = defaultdict(set)
        network_targets: dict[tuple[str, str], set[str]] = defaultdict(set)

        for step in chain["steps"]:
            if step["_subject_name"]:
                name_to_pids[step["_subject_name"]].update(step["_subject_pids"])
            if step["_object_name"]:
                name_to_pids[step["_object_name"]].update(step["_object_pids"])

            if step["_action_class"] in {"NETWORK_CONNECT", "NETWORK_LISTEN"}:
                subject_key = ",".join(map(str, sorted(step["_subject_pids"]))) or (step["_subject_name"] or "")
                target = str((step.get("critical_evidence_signature") or {}).get("target_key") or step.get("object"))
                network_targets[(subject_key, step["_action_class"])].add(target.lower())

        for step in chain["steps"]:
            evidence_kind = step["_evidence_kind"]
            directness = "意味解釈が必要" if evidence_kind in SEMANTIC_EVIDENCE_KINDS else "直接観測"

            process_names = {name for name in (step["_subject_name"], step["_object_name"]) if name}
            multiple = any(len(name_to_pids[name]) > 1 for name in process_names)
            multiple = multiple or len(explicit_pids(step.get("object"))) > 1
            if step["_action_class"] in {"NETWORK_CONNECT", "NETWORK_LISTEN"}:
                subject_key = ",".join(map(str, sorted(step["_subject_pids"]))) or (step["_subject_name"] or "")
                multiple = multiple or len(network_targets[(subject_key, step["_action_class"])]) > 1
            instance = "候補複数" if multiple else "候補一意"

            touches_focus = bool(process_names & chain["focus"])
            pivot = "pivot不要" if touches_focus else "pivot必要"

            labels[step["step_id"]] = {
                "phase": chain["phase"],
                "chain_id": chain_id,
                "step_id": step["step_id"],
                "subject": step.get("subject"),
                "action": step.get("action"),
                "object": step.get("object"),
                "action_class": step["_action_class"],
                "evidence_kind": evidence_kind,
                "directness": directness,
                "instance": instance,
                "pivot": pivot,
            }

    return labels


def scored_observations(formal_rows: list[dict], overlay_rows: list[dict], labels: dict[str, dict]) -> list[dict]:
    formal_by_run = {
        (row["phase"], row["replicate"], row["chain_id"]): row
        for row in formal_rows
    }
    observations: list[dict] = []

    for overlay in overlay_rows:
        key = (overlay["phase"], overlay["replicate"], overlay["chain_id"])
        formal = formal_by_run[key]
        scores = {
            (item["step_id"], item["kind"]): item["score"]
            for item in formal["gold_items"]
        }
        for decision in overlay["action_decisions"]:
            step_id = decision["step_id"]
            complete = int(
                decision["semantic_score"] == 1
                and scores[(step_id, "subject")] == 1
                and scores[(step_id, "object")] == 1
            )
            observations.append(
                {
                    **labels[step_id],
                    "replicate": overlay["replicate"],
                    "complete": complete,
                }
            )
    return observations


def aggregate(observations: list[dict], fields: tuple[str, ...]) -> list[dict]:
    groups: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for row in observations:
        groups[tuple(row[field] for field in fields)].append(row["complete"])
    result = []
    for key, values in sorted(groups.items()):
        hits = sum(values)
        result.append(
            {
                **dict(zip(fields, key)),
                "hits": hits,
                "n": len(values),
                "rate": hits / len(values),
            }
        )
    return result


def print_table(rows: list[dict], fields: tuple[str, ...]) -> None:
    for row in rows:
        labels = " | ".join(str(row[field]) for field in fields)
        print(f"{labels} | {row['hits']}/{row['n']} | {row['rate']:.1%}")


def main() -> None:
    formal_rows = [
        row for row in read_jsonl(FORMAL)
        if row.get("model") == "gpt-5.5" and row.get("stage") == "stage2"
    ]
    overlay_rows = [
        row for row in read_jsonl(OVERLAY)
        if row.get("model") == "gpt-5.5" and row.get("stage") == "stage2"
    ]
    chains, _ = load_step_metadata(formal_rows, overlay_rows)
    labels = label_steps(chains)
    observations = scored_observations(formal_rows, overlay_rows, labels)

    print(f"runs={len(overlay_rows)} unique_steps={len(labels)} scored_step_observations={len(observations)}")
    print("\n[OVERALL BY AXIS]")
    for field in ("directness", "instance", "pivot"):
        print(f"\n{field}")
        print_table(aggregate(observations, (field,)), (field,))

    print("\n[ATTACK/NORMAL BY AXIS]")
    for field in ("directness", "instance", "pivot"):
        print(f"\nphase x {field}")
        print_table(aggregate(observations, ("phase", field)), ("phase", field))

    print("\n[8 COMBINATIONS]")
    print_table(
        aggregate(observations, ("directness", "instance", "pivot")),
        ("directness", "instance", "pivot"),
    )

    print("\n[UNIQUE GOLD STEP COUNTS]")
    unique_rows = [{**row, "complete": 1} for row in labels.values()]
    print_table(
        aggregate(unique_rows, ("directness", "instance", "pivot")),
        ("directness", "instance", "pivot"),
    )

    print("\n[CASE PROFILES]")
    by_chain: dict[str, list[dict]] = defaultdict(list)
    for row in observations:
        by_chain[row["chain_id"]].append(row)
    for chain_id in sorted(by_chain):
        rows = by_chain[chain_id]
        unique = {row["step_id"]: row for row in rows}.values()
        unique = list(unique)
        semantic = sum(row["directness"] == "意味解釈が必要" for row in unique)
        multiple = sum(row["instance"] == "候補複数" for row in unique)
        pivot = sum(row["pivot"] == "pivot必要" for row in unique)
        hits = sum(row["complete"] for row in rows)
        runs = len({row["replicate"] for row in rows})
        print(
            f"{rows[0]['phase']} | {chain_id} | runs={runs} | gold={len(unique)} "
            f"| semantic={semantic} | multiple={multiple} | pivot={pivot} "
            f"| complete={hits}/{len(rows)} ({hits / len(rows):.1%})"
        )


if __name__ == "__main__":
    main()
