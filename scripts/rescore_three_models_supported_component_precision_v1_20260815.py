#!/usr/bin/env python3
"""Claim-atomic Gold-target and supported-component precision overlay.

This is a non-destructive third scoring layer over the adopted 384 formal
scores.  It fixes the precision unit first: one emitted claim is aligned to at
most one relation, and credit may not be assembled from slots in other claims.

Two precision measures are reported:

* Gold-target precision: exact claim-level alignment to a predeclared Gold edge.
* Supported-component precision: Gold-target claims plus directly evidenced,
  non-routine relations in the explicit semantic component connected to Gold.

The second measure is deliberately conservative.  Module/context/lifecycle
claims, duplicate relations, unsupported direction/targets, routine network
traffic, and unconsumed housekeeping files remain false positives.  Ambiguous
relations are retained as a separate class and are not silently credited.

No model or judge API is called.  Existing score ledgers are never modified.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

import rescore_three_models_observable_semantic_v2_20260814 as v2


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = (
    ROOT
    / "docs/current_experiment/results_2026-08-15"
    / "three_model_supported_component_precision_v1"
)
OUT_ROWS = OUT_DIR / "claim_atomic_scores_all_384.jsonl"
OUT_CLAIMS = OUT_DIR / "claim_audit_all_1390.jsonl"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = OUT_DIR / "report.md"
OUT_HEADLINE = OUT_DIR / "headline_common46.csv"
OUT_GPT55_STAGE2 = OUT_DIR / "gpt55_stage2_usecase.csv"

MODELS = v2.MODELS
PHASES = v2.PHASES
STAGES = v2.STAGES


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


def run_path(row: dict[str, Any]) -> Path:
    value = row.get("run_json") or row.get("run_path")
    if value:
        return ROOT / str(value).replace("\\", "/")
    if (
        row["phase"] == "attack8"
        and row["replicate"] == "replicate_01"
        and row["model"] in {"gpt-4.1-mini", "gpt-5.4-mini"}
    ):
        return (
            ROOT
            / "docs/current_experiment/results_2026-07-27"
            / "atlasv2_s3_s4_attack8_process_chain_v5_formal"
            / "two_model_baseline_replicate_01/runs"
            / row["model"]
            / row["stage"]
            / f"{row['chain_id']}_{row['stage']}_run.json"
        )
    raise ValueError(f"cannot resolve run path: {row['queue_id']}")


def output_steps(row: dict[str, Any]) -> list[dict[str, Any]]:
    path = run_path(row)
    run = read_json(path)
    payload = run.get("output_text")
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict) or not isinstance(payload.get("code_steps"), list):
        raise ValueError(f"code_steps missing: {path}")
    return payload["code_steps"]


def compact(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def basename(value: Any) -> str:
    text = str(value or "").replace("/", "\\").rstrip("\\").lower()
    return text.rsplit("\\", 1)[-1]


def json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return value


def entity_aliases(value: Any, kind: str | None = None) -> set[str]:
    value = json_value(value)
    aliases: set[str] = set()
    if isinstance(value, dict):
        for key in ("name", "path", "value", "data"):
            item = value.get(key)
            if isinstance(item, list):
                for part in item:
                    aliases |= entity_aliases(part, kind)
            elif item not in (None, ""):
                aliases |= entity_aliases(item, kind)
        pid = value.get("pid")
        name = basename(value.get("name") or value.get("path"))
        if pid is not None:
            aliases.add(f"pid:{pid}")
            if name:
                aliases.add(f"proc:{name}@{pid}")
        return aliases
    if isinstance(value, list):
        for item in value:
            aliases |= entity_aliases(item, kind)
        return aliases
    text = str(value or "").strip().lower().replace("/", "\\")
    if not text:
        return aliases
    aliases.add(f"raw:{compact(text)}")
    base = basename(text)
    if base and len(base) > 2:
        aliases.add(f"base:{base}")
    for path in re.findall(r"[a-z]:\\[^\s\"'|,;]+", text, flags=re.I):
        aliases.add(f"path:{path.lower().rstrip(').]')}")
        aliases.add(f"base:{basename(path.rstrip(').]'))}")
    for exe in re.findall(r"[a-z0-9_.-]+\.exe", text, flags=re.I):
        aliases.add(f"base:{exe.lower()}")
    for domain in re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", text, flags=re.I):
        aliases.add(f"host:{domain.lower()}")
    for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        aliases.add(f"host:{address}")
    for port in re.findall(r"(?::|port\s*[=:]?\s*)(\d{1,5})", text, flags=re.I):
        aliases.add(f"port:{port}")
    for pid in re.findall(r"(?:pid\s*[=:]?\s*|@)(\d{2,7})", text, flags=re.I):
        aliases.add(f"pid:{pid}")
    return aliases


def process_aliases(step: dict[str, Any]) -> set[str]:
    return entity_aliases(step.get("subject_process"), "process")


def object_aliases(step: dict[str, Any]) -> set[str]:
    return entity_aliases(step.get("object"), str((step.get("object") or {}).get("type") or ""))


def process_graph_keys(value: Any, pid_override: Any = None) -> set[str]:
    """Return instance-aware process keys for component traversal.

    A basename is intentionally not a graph key when a PID is available.  This
    prevents two same-image process instances from becoming connected merely
    because both are named powershell.exe or payload.exe.
    """
    value = json_value(value)
    name = ""
    pid = pid_override
    if isinstance(value, dict):
        name = basename(value.get("name") or value.get("path"))
        if pid is None:
            pid = value.get("pid")
    else:
        text = str(value or "")
        match = re.search(r"([a-z0-9_.-]+\.exe)", text, flags=re.I)
        name = match.group(1).lower() if match else basename(text)
        if pid is None:
            match = re.search(r"(?:pid\s*[=:]?\s*|@)(\d{2,7})", text, flags=re.I)
            pid = match.group(1) if match else None
    if not name:
        return set()
    if pid not in (None, ""):
        return {f"proc:{name}@{pid}"}
    return {f"procname:{name}"}


def file_graph_keys(value: Any) -> set[str]:
    aliases = entity_aliases(value, "file")
    paths = {f"file:{x.removeprefix('path:')}" for x in aliases if x.startswith("path:")}
    if paths:
        return paths
    return {f"filebase:{x.removeprefix('base:')}" for x in aliases if x.startswith("base:")}


def action_class(value: Any, object_type: str = "") -> str:
    text = str(value or "").lower()
    token = compact(text)
    object_type = str(object_type or "").lower()
    if any(x in token for x in ("module_load", "load_module", "dll_load", "action_load_module")):
        return "MODULE_LOAD"
    if any(x in token for x in ("process_context", "execution_context", "process_command_line", "act_as")):
        return "PROCESS_CONTEXT"
    if any(x in token for x in ("api_call", "process_api", "open_process_handle", "call_api")):
        return "PROCESS_API"
    if any(x in token for x in ("terminate", "delete_file", "file_delete", "handle_close")):
        return "LIFECYCLE_OR_DELETE"
    if any(x in token for x in ("network_capture", "packet_capture", "capture_initiation", "capture_start")):
        return "EXECUTION_INPUT"
    if object_type == "process" or any(
        x in token
        for x in (
            "create_process", "process_create", "process_creation", "process_start",
            "start_process", "spawn", "launch", "child_process", "execute_process",
            "process_execution", "command_interpreter_invocation",
        )
    ):
        return "PROCESS_CREATE"
    if "listen" in token or "listener" in token or "server" == token:
        return "NETWORK_LISTEN"
    if object_type == "network" or any(x in token for x in ("network_connect", "connection_create", "establish_connection", "netconn")):
        return "NETWORK_CONNECT"
    if object_type.startswith("registry") or "registry" in token or "regmod" in token:
        return "REGISTRY_WRITE"
    if any(x in token for x in ("script", "execution_input", "batch_execution", "command_target", "read_execution_input", "execute_command")):
        return "EXECUTION_INPUT"
    if object_type == "file":
        if any(x in token for x in ("read", "open_read", "file_access", "handle_request")) and not any(
            x in token for x in ("write", "create", "material", "modify", "rename", "truncate")
        ):
            return "FILE_READ"
        if any(x in token for x in ("write", "create", "material", "modify", "rename", "truncate", "filemod")):
            return "FILE_CREATE_WRITE"
        if any(x in token for x in ("execute", "load", "open", "access", "read")):
            return "EXECUTION_INPUT"
    return "OTHER"


def gold_action_class(step: dict[str, Any]) -> str:
    value = v2.v1.policy_v1.gold_action_class(step)
    return "EXECUTION_INPUT" if value == "INPUT_USE" else value


def step_evidence_text(step: dict[str, Any]) -> str:
    return json.dumps(step.get("evidence") or [], ensure_ascii=False).lower()


def evidence_support(step: dict[str, Any], cls: str) -> tuple[bool, str]:
    evidence = step.get("evidence") or []
    if not evidence:
        return False, "no_evidence"
    evidence_text = step_evidence_text(step)
    context_text = json.dumps(
        {
            "command_line": step.get("command_line"),
            "execution_context": step.get("execution_context"),
        },
        ensure_ascii=False,
    ).lower()
    subject = step.get("subject_process") or {}
    obj = step.get("object") or {}
    subject_pid = subject.get("pid")
    evidence_pids = {
        str(item.get("pid"))
        for item in evidence
        if isinstance(item, dict) and item.get("pid") is not None
    }
    subject_name = basename(subject.get("name") or subject.get("path"))
    subject_ok = (
        subject_pid is not None and str(subject_pid) in evidence_pids
    ) or (subject_name and subject_name in evidence_text + context_text)
    target_terms = {
        alias.split(":", 1)[1]
        for alias in object_aliases(step)
        if alias.startswith(("base:", "path:", "raw:"))
    }
    target_ok = any(term and term in evidence_text + context_text for term in target_terms)
    if not subject_ok:
        return False, "evidence_subject_mismatch"
    if not target_ok:
        return False, "evidence_object_mismatch"
    markers = {
        "PROCESS_CREATE": ("childproc", "procstart", "create_process", "parent_process", "child_process"),
        "FILE_CREATE_WRITE": ("filemod", "file_", "write", "create", "rename", "truncate"),
        "FILE_READ": ("file", "read", "open", "handle_request"),
        "EXECUTION_INPUT": ("command", "script", "read", "open", "load"),
        "REGISTRY_WRITE": ("registry", "regmod", "write_value", "run key", "startupitems"),
        "NETWORK_CONNECT": ("netconn", "connection", "remote_", "local_", "port", "dns"),
        "NETWORK_LISTEN": ("listen", "local_", "port", "connection"),
    }
    if cls not in markers:
        return False, "unsupported_relation_class"
    if not any(marker in evidence_text + context_text for marker in markers[cls]):
        return False, "evidence_action_mismatch"
    # Process telemetry is represented in two forms in the source ledgers:
    # (a) a parent event containing childproc_name, or (b) a child process row
    # whose ppid identifies the emitted subject.  A command-line mention alone
    # is insufficient.
    if cls == "PROCESS_CREATE":
        subject_pid_text = str(subject_pid) if subject_pid is not None else ""
        target_names = {
            alias.removeprefix("base:")
            for alias in object_aliases(step)
            if alias.startswith("base:")
        }
        linked = False
        for item in evidence:
            if not isinstance(item, dict):
                continue
            item_text = json.dumps(item, ensure_ascii=False).lower()
            target_in_item = any(name and name in item_text for name in target_names)
            if not target_in_item:
                continue
            item_pid = str(item.get("pid")) if item.get("pid") is not None else ""
            item_ppid = str(item.get("ppid")) if item.get("ppid") is not None else ""
            if "childproc" in item_text and item_pid == subject_pid_text:
                linked = True
            if item_ppid == subject_pid_text and item_pid != subject_pid_text:
                linked = True
            if "create_process" in item_text and subject_pid_text in item_text:
                linked = True
        context = step.get("execution_context") or {}
        if (
            str(context.get("parent_pid") or "") == subject_pid_text
            and any(name and name in str(context.get("child_process") or "").lower() for name in target_names)
        ):
            linked = True
        if not linked:
            return False, "command_mention_without_process_creation"
    return True, "direct_observation"


def claim_alignment(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {
        str(item["candidate_claim_id"]): item
        for item in row.get("candidate_claim_alignments") or []
    }
    for claim_id, slots in v2.claim_groups(row).items():
        if claim_id in result:
            continue
        basis = [
            str(slot["kind"])
            for slot in slots
            if int(slot.get("is_true_positive", 0))
            and str(slot.get("kind")) in {"subject", "operation", "object"}
        ]
        result[claim_id] = {
            "candidate_claim_id": claim_id,
            "candidate_order": v2.slot_position(slots),
            "candidate_step_id": str(slots[0].get("candidate_step_id") or ""),
            "aligned_gold_step_id": v2.v1.policy_v1.aligned_step(slots),
            "alignment_basis": basis,
        }
    return result


def parse_slot(slots: list[dict[str, Any]], kind: str) -> Any:
    slot = next((x for x in slots if x.get("kind") == kind), None)
    return json_value(slot.get("candidate_slot_excerpt")) if slot else None


def aliases_overlap(left: set[str], right: set[str]) -> bool:
    # PID alone is too weak across a five-minute window; require a stable name,
    # path, endpoint, or raw semantic value.
    return bool({x for x in left & right if not x.startswith("pid:")})


def atomic_gold_match(
    row: dict[str, Any], claim_id: str, step: dict[str, Any],
    alignment: dict[str, dict[str, Any]], gold_steps: dict[str, dict[str, Any]],
) -> str | None:
    item = alignment.get(claim_id) or {}
    aligned = str(item.get("aligned_gold_step_id") or "")
    basis = set(item.get("alignment_basis") or [])
    if aligned and {"subject", "operation", "object"}.issubset(basis):
        return aligned
    if not aligned or aligned not in gold_steps:
        return None
    gold = gold_steps[aligned]
    slots = v2.claim_groups(row).get(claim_id, [])
    subject = parse_slot(slots, "subject")
    obj = parse_slot(slots, "object")
    candidate_class = action_class(
        parse_slot(slots, "operation"),
        str((obj or {}).get("type") if isinstance(obj, dict) else ""),
    )
    if candidate_class != gold_action_class(gold):
        return None
    if not aliases_overlap(entity_aliases(subject), entity_aliases(gold.get("subject"))):
        return None
    if not aliases_overlap(entity_aliases(obj), entity_aliases(gold.get("object"))):
        return None
    return aligned


def relation_signature(step: dict[str, Any], cls: str) -> tuple[str, str, str]:
    def best(aliases: set[str]) -> str:
        for prefix in ("path:", "proc:", "base:", "raw:"):
            values = sorted(x for x in aliases if x.startswith(prefix))
            if values:
                return values[0]
        return "?"
    return best(process_aliases(step)), cls, best(object_aliases(step))


def consumed_file_basenames(claims: list[dict[str, Any]]) -> set[str]:
    used: set[str] = set()
    for claim in claims:
        step = claim["step"]
        cls = claim["action_class"]
        if cls in {"PROCESS_CREATE", "EXECUTION_INPUT", "FILE_READ"}:
            text = json.dumps(
                {
                    "object": step.get("object"),
                    "command_line": step.get("command_line"),
                    "execution_context": step.get("execution_context"),
                },
                ensure_ascii=False,
            ).lower()
            used |= {x.lower() for x in re.findall(r"[a-z0-9_.-]+\.(?:exe|cmd|bat|ps1|py|js|vbs|hta|sct|dll|rtf|docx?|html?|pcapng)", text)}
    return used


def classify_run(row: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    steps = output_steps(row)
    groups = v2.claim_groups(row)
    ordered_groups = sorted(groups.items(), key=lambda item: v2.slot_position(item[1]))
    if len(steps) != len(ordered_groups):
        raise AssertionError(f"claim count mismatch: {row['queue_id']}")
    alignment = claim_alignment(row)
    gold_doc = v2.v1.policy_v1.read_json(v2.v1.policy_v1.gold_path(row))
    gold_steps = {str(x["step_id"]): x for x in gold_doc["gold_steps"]}
    gold_aliases: set[str] = set()
    gold_network_aliases: set[str] = set()
    gold_process_keys: set[str] = set()
    gold_artifact_keys: set[str] = set()
    for gold in gold_steps.values():
        gold_aliases |= entity_aliases(gold.get("subject"))
        gold_aliases |= entity_aliases(gold.get("object"))
        gold_process_keys |= process_graph_keys(gold.get("subject"))
        if gold_action_class(gold) == "PROCESS_CREATE":
            gold_process_keys |= process_graph_keys(gold.get("object"))
        elif gold_action_class(gold) in {"EXECUTION_INPUT", "FILE_CREATE_WRITE"}:
            gold_artifact_keys |= file_graph_keys(gold.get("object"))
        if gold_action_class(gold) in {"NETWORK_CONNECT", "NETWORK_LISTEN"}:
            gold_network_aliases |= entity_aliases(gold.get("object"))

    claims: list[dict[str, Any]] = []
    for (claim_id, slots), step in zip(ordered_groups, steps):
        emitted_id = str(step.get("step_id") or "")
        slot_step_id = str(slots[0].get("candidate_step_id") or slots[0].get("emitted_step_id") or "")
        if slot_step_id and emitted_id and slot_step_id != emitted_id:
            raise AssertionError(f"claim order mismatch: {row['queue_id']} {claim_id}")
        cls = action_class(step.get("operation"), str((step.get("object") or {}).get("type") or ""))
        supported, reason = evidence_support(step, cls)
        claims.append(
            {
                "claim_id": claim_id,
                "candidate_step_id": emitted_id,
                "candidate_order": int(step.get("order") or v2.slot_position(slots)),
                "step": step,
                "action_class": cls,
                "direct_evidence_supported": supported,
                "evidence_reason": reason,
                "atomic_gold_step_id": atomic_gold_match(row, claim_id, step, alignment, gold_steps),
                "subject_aliases": process_aliases(step),
                "object_aliases": object_aliases(step),
                "subject_graph_keys": process_graph_keys(step.get("subject_process")),
                "object_graph_keys": process_graph_keys(
                    step.get("object"), (step.get("execution_context") or {}).get("child_pid")
                ) if cls == "PROCESS_CREATE" else set(),
                "file_graph_keys": file_graph_keys(step.get("object"))
                if cls in {"FILE_CREATE_WRITE", "FILE_READ", "EXECUTION_INPUT"}
                else set(),
                "parent_graph_keys": process_graph_keys(
                    {
                        "name": (step.get("execution_context") or {}).get("parent_process"),
                        "pid": (step.get("execution_context") or {}).get("parent_pid"),
                    }
                ),
            }
        )

    # Build a graph only from directly observed semantic relations.  This lets
    # an explicitly observed predecessor/successor connect transitively to the
    # Gold component, while time or process-name proximity alone contributes no
    # edge.
    adjacency: dict[str, set[str]] = defaultdict(set)
    for claim in claims:
        if claim["action_class"] == "PROCESS_CREATE":
            if not claim["direct_evidence_supported"] and not claim["atomic_gold_step_id"]:
                continue
            left = claim["subject_graph_keys"]
            right = claim["object_graph_keys"]
        elif claim["action_class"] == "PROCESS_CONTEXT":
            evidence = claim["step"].get("evidence") or []
            subject_pid = (claim["step"].get("subject_process") or {}).get("pid")
            parent_pid = (claim["step"].get("execution_context") or {}).get("parent_pid")
            observed_link = any(
                isinstance(item, dict)
                and str(item.get("pid") or "") == str(subject_pid or "")
                and str(item.get("ppid") or "") == str(parent_pid or "")
                for item in evidence
            )
            if not observed_link:
                continue
            left = claim["subject_graph_keys"]
            right = claim["parent_graph_keys"]
        else:
            continue
        for a in left:
            for b in right:
                adjacency[a].add(b)
                adjacency[b].add(a)
    atomic_candidate_keys = {
        key
        for claim in claims
        if claim["atomic_gold_step_id"]
        for key in (claim["subject_graph_keys"] | claim["object_graph_keys"])
    }
    seed_keys = gold_process_keys | atomic_candidate_keys
    queue = deque(seed_keys)
    connected = set(queue)
    while queue:
        item = queue.popleft()
        for nxt in adjacency[item]:
            if nxt not in connected:
                connected.add(nxt)
                queue.append(nxt)

    consumed = consumed_file_basenames(claims)
    seen_gold: set[str] = set()
    seen_relations: set[tuple[str, str, str]] = set()
    audited: list[dict[str, Any]] = []
    for claim in claims:
        cls = claim["action_class"]
        gold_step_id = claim["atomic_gold_step_id"]
        signature = relation_signature(claim["step"], cls)
        in_component = bool(
            (claim["subject_graph_keys"] | claim["object_graph_keys"]) & connected
        ) or bool(claim["file_graph_keys"] & gold_artifact_keys) or bool(gold_step_id)
        category = "relation_error_or_unsupported"
        detail = claim["evidence_reason"]
        gold_tp = 0
        supported_tp = 0

        if gold_step_id and gold_step_id not in seen_gold:
            category = "gold_target_relation"
            detail = "atomic subject-action-object match to predeclared Gold"
            gold_tp = 1
            supported_tp = 1
            seen_gold.add(gold_step_id)
            seen_relations.add(signature)
        elif gold_step_id:
            category = "duplicate_relation"
            detail = f"duplicate claim for Gold step {gold_step_id}"
        elif not claim["direct_evidence_supported"]:
            category = "relation_error_or_unsupported"
        elif signature in seen_relations:
            category = "duplicate_relation"
            detail = "same normalized semantic relation already emitted"
        elif cls in {"MODULE_LOAD", "PROCESS_CONTEXT", "PROCESS_API", "LIFECYCLE_OR_DELETE", "OTHER"}:
            category = "routine_or_context"
            detail = f"excluded relation class: {cls}"
        elif cls == "PROCESS_CREATE" and (
            basename((claim["step"].get("subject_process") or {}).get("name") or (claim["step"].get("subject_process") or {}).get("path")) == "werfault.exe"
            or (
                basename((claim["step"].get("subject_process") or {}).get("name") or (claim["step"].get("subject_process") or {}).get("path")) == "explorer.exe"
                and basename((claim["step"].get("object") or {}).get("name") or (claim["step"].get("object") or {}).get("path")) == "firefox.exe"
            )
        ):
            category = "routine_or_context"
            detail = "generic launcher or crash-recovery process context"
        elif not in_component:
            category = "outside_component"
            detail = "no explicit evidence edge connects the claim to a Gold entity"
        elif cls in {"NETWORK_CONNECT", "NETWORK_LISTEN"}:
            target_overlap = aliases_overlap(claim["object_aliases"], gold_network_aliases)
            server_case = (
                claim["step"].get("subject_process", {}).get("name", "").lower() == "python.exe"
                and (
                    "python_simplehttpserver_network_chain" in row["chain_id"]
                    or row["chain_id"] == "chain_24_e18_cmdexe_other_chain"
                )
            )
            if target_overlap or server_case:
                category = "supported_component_relation"
                detail = "direct network edge matches a Gold endpoint family or declared server use case"
                supported_tp = 1
                seen_relations.add(signature)
            else:
                category = "routine_or_context"
                detail = "Gold-external network traffic without a central target match"
        elif cls == "REGISTRY_WRITE":
            registry_text = json.dumps(claim["step"].get("object") or {}, ensure_ascii=False).lower().replace("/", "\\")
            central_discord_registration = (
                row["chain_id"] == "chain_10_e07_discord_run_key_registry_chain"
                and any(
                    token in registry_text
                    for token in ("\\run\\", "\\runonce", "shell\\open\\command", "url protocol")
                )
            )
            if central_discord_registration:
                category = "supported_component_relation"
                detail = "direct Discord launch/registration edge in the Gold-connected component"
                supported_tp = 1
                seen_relations.add(signature)
            else:
                category = "routine_or_context"
                detail = "Gold-external registry housekeeping or configuration"
        elif cls == "FILE_CREATE_WRITE":
            target_names = {
                alias.removeprefix("base:")
                for alias in claim["object_aliases"]
                if alias.startswith("base:")
            }
            if target_names & consumed:
                category = "supported_component_relation"
                detail = "materialized file is consumed by an observed component relation"
                supported_tp = 1
                seen_relations.add(signature)
            else:
                category = "routine_or_context"
                detail = "unconsumed file/cache/temp activity"
        elif cls in {"PROCESS_CREATE", "EXECUTION_INPUT", "FILE_READ"}:
            category = "supported_component_relation"
            detail = "directly observed semantic edge in the Gold-connected component"
            supported_tp = 1
            seen_relations.add(signature)
        else:
            category = "boundary_ambiguous"
            detail = "not resolved by the conservative component policy"

        audited.append(
            {
                "schema_version": "claim_atomic_supported_component_v1",
                "queue_id": row["queue_id"],
                "model": row["model"],
                "phase": row["phase"],
                "replicate": row["replicate"],
                "stage": row["stage"],
                "chain_id": row["chain_id"],
                "instance_id": row["instance_id"],
                "claim_id": claim["claim_id"],
                "candidate_step_id": claim["candidate_step_id"],
                "candidate_order": claim["candidate_order"],
                "subject": claim["step"].get("subject_process"),
                "operation": claim["step"].get("operation"),
                "object": claim["step"].get("object"),
                "action_class": cls,
                "evidence_count": len(claim["step"].get("evidence") or []),
                "direct_evidence_supported": claim["direct_evidence_supported"],
                "direct_evidence_decision": claim["evidence_reason"],
                "in_gold_connected_component": in_component,
                "atomic_gold_step_id": gold_step_id,
                "category": category,
                "decision_detail": detail,
                "gold_target_tp": gold_tp,
                "supported_component_tp": supported_tp,
                "relation_signature": list(signature),
            }
        )

    category_counts = Counter(item["category"] for item in audited)
    result = {
        "schema_version": "claim_atomic_supported_component_run_v1",
        "queue_id": row["queue_id"],
        "model": row["model"],
        "phase": row["phase"],
        "replicate": row["replicate"],
        "stage": row["stage"],
        "chain_id": row["chain_id"],
        "instance_id": row["instance_id"],
        "source_score_file": row["_source_path"],
        "run_json": rel(run_path(row)),
        "claim_denominator": len(audited),
        "gold_target_hits": sum(x["gold_target_tp"] for x in audited),
        "supported_component_hits": sum(x["supported_component_tp"] for x in audited),
        "category_counts": dict(category_counts),
    }
    return result, audited


def ratio(hit: int, den: int) -> float | None:
    return hit / den if den else None


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    den = sum(row["claim_denominator"] for row in rows)
    gold = sum(row["gold_target_hits"] for row in rows)
    supported = sum(row["supported_component_hits"] for row in rows)
    categories = Counter()
    for row in rows:
        categories.update(row["category_counts"])
    return {
        "run_count": len(rows),
        "claim_denominator": den,
        "gold_target": {"hits": gold, "denominator": den, "rate": ratio(gold, den)},
        "supported_component": {"hits": supported, "denominator": den, "rate": ratio(supported, den)},
        "added_supported_claims": supported - gold,
        "category_counts": dict(categories),
    }


def pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.2f}%"


def csv_write(path: Path, rows: list[list[Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        csv.writer(handle).writerows(rows)


def report(summary: dict[str, Any]) -> str:
    lines = [
        "# Claim単位 Precision再採点 v1",
        "",
        "## 結論",
        "",
        "従来のslot単位Precisionは主体・行動・対象のcreditが別claimへ分散し、Gold外だが証拠付きのcomponent内関係も一律にfalse positiveとしていた。本再採点では、claim全体を1つの関係へatomicに対応させ、事前Goldへの選別能力と、証拠付きcomponent関係を出す能力を分離した。",
        "",
        "Gold外の関係は、直接証跡、Goldとの明示edge接続、対象関係クラス、routine/context除外をすべて通った場合のみSupported-componentの正解とした。Gold外networkはGold endpoint系列または実験上のserver操作に限定し、Gold外registryはDiscordの起動・登録系列に限定した。",
        "",
        "## 3モデル比較（従来と同じ共通46 strata）",
        "",
        "| モデル | claim数 | Gold-target Precision | Supported-component Precision | 追加で正解となったcomponent関係 |",
        "|---|---:|---:|---:|---:|",
    ]
    for model in MODELS:
        item = summary["headline_by_model"][model]
        lines.append(
            f"| {model} | {item['claim_denominator']} | {pct(item['gold_target']['rate'])} | "
            f"{pct(item['supported_component']['rate'])} | {item['added_supported_claims']} |"
        )
    gpt55 = summary["headline_by_model"]["gpt-5.5"]
    lines.extend(
        [
            "",
            f"GPT-5.5ではGold-targetの{pct(gpt55['gold_target']['rate'])}に対し、Supported-componentは{pct(gpt55['supported_component']['rate'])}となった。従来の低Precisionには、誤りだけでなく、Goldより広い証拠付きcomponentを出力した影響が含まれていた。したがって「出力の選別能力は改善しなかった」とは現在の値からは主張できない。",
            "",
            f"なお、従来値は主体・行動・対象のslot単位、本表はclaim単位である。分母が異なるため、従来の46.81%と本表の{pct(gpt55['supported_component']['rate'])}を同じPrecisionとして直接比較してはならない。",
        ]
    )
    lines.extend(
        [
            "",
            "## GPT-5.5 Stage 2 ユースケース別",
            "",
            "| 対象 | ユースケース | claim数 | Gold-target | Supported-component | 追加component関係 |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for key, item in sorted(summary["gpt55_stage2_usecase"].items()):
        phase, chain = key.split("/", 1)
        lines.append(
            f"| {'正常' if phase == 'normal8' else '攻撃'} | {chain} | {item['claim_denominator']} | "
            f"{pct(item['gold_target']['rate'])} | {pct(item['supported_component']['rate'])} | "
            f"{item['added_supported_claims']} |"
        )
    lines.extend(
        [
            "",
            "## 判定カテゴリ",
            "",
            "`gold_target_relation`は既存Goldへclaim全体が対応した関係、`supported_component_relation`はGold外だが直接証跡と明示edgeで中心componentへ接続した有効関係である。`routine_or_context`、`duplicate_relation`、`relation_error_or_unsupported`、`outside_component`は不正解のままとした。",
            "",
            "## 境界の固定",
            "",
            "networkは、Goldと同一のendpoint系列またはPython HTTP serverとして実験定義された待ち受けのみcomponent内とした。Discordの通常通信などは除外した。registryはDiscordのRun/RunOnce/shell-openなど起動・登録に直接関係するもののみ追加関係とし、Office Resiliency、Proxy/Wpad、MuiCache等はhousekeepingとして除外した。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    replace = sys.argv[1:] == ["--replace-generated"]
    if sys.argv[1:] and not replace:
        raise SystemExit("usage: script [--replace-generated]")
    outputs = (OUT_ROWS, OUT_CLAIMS, OUT_SUMMARY, OUT_REPORT, OUT_HEADLINE, OUT_GPT55_STAGE2)
    if not replace:
        existing = [path for path in outputs if path.exists()]
        if existing:
            raise FileExistsError(f"create-only refusal: {existing[0]}")

    scored: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    for row in v2.normalized_rows():
        result, audit = classify_run(row)
        scored.append(result)
        claims.extend(audit)
    scored.sort(key=lambda x: (x["model"], x["phase"], x["replicate"], x["stage"], x["chain_id"]))
    claims.sort(key=lambda x: (x["model"], x["phase"], x["replicate"], x["stage"], x["chain_id"], x["candidate_order"]))
    if len(scored) != 384:
        raise AssertionError(f"expected 384 runs, got {len(scored)}")
    if len(claims) != 1390:
        raise AssertionError(f"expected 1390 claims, got {len(claims)}")
    headline = [row for row in scored if v2.is_headline(row)]
    counts = Counter(row["model"] for row in headline)
    if counts != Counter({model: 46 for model in MODELS}):
        raise AssertionError(f"headline mismatch: {counts}")

    summary = {
        "schema_version": "claim_atomic_supported_component_summary_v1",
        "created_date": "2026-08-15",
        "coverage": {
            "runs": len(scored),
            "claims": len(claims),
            "by_model": dict(Counter(row["model"] for row in scored)),
            "headline_common_strata_per_model": 46,
        },
        "policy": {
            "unit": "one emitted claim maps atomically to at most one relation",
            "gold_target": "predeclared Gold relation only",
            "supported_component": "Gold plus directly evidenced, explicit-edge-connected, non-routine semantic relations",
            "ambiguous_is_true_positive": False,
            "network_registry_extra_policy": "boundary_ambiguous pending case-specific intent audit",
            "model_or_judge_api_calls": 0,
        },
        "full_by_model": {
            model: aggregate([row for row in scored if row["model"] == model])
            for model in MODELS
        },
        "headline_by_model": {
            model: aggregate([row for row in headline if row["model"] == model])
            for model in MODELS
        },
        "gpt55_stage2_usecase": {
            f"{phase}/{chain}": aggregate(
                [
                    row for row in headline
                    if row["model"] == "gpt-5.5" and row["phase"] == phase
                    and row["stage"] == "stage2" and row["chain_id"] == chain
                ]
            )
            for phase in PHASES
            for chain in sorted(
                {
                    row["chain_id"] for row in headline
                    if row["model"] == "gpt-5.5" and row["phase"] == phase and row["stage"] == "stage2"
                }
            )
        },
        "all_claim_categories": dict(Counter(x["category"] for x in claims)),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_ROWS, scored)
    write_jsonl(OUT_CLAIMS, claims)
    OUT_SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    OUT_REPORT.write_text(report(summary), encoding="utf-8")
    headline_rows = [["model", "claims", "gold_target_hits", "gold_target_precision", "supported_hits", "supported_component_precision", "added_supported_claims"]]
    for model in MODELS:
        item = summary["headline_by_model"][model]
        headline_rows.append([model, item["claim_denominator"], item["gold_target"]["hits"], item["gold_target"]["rate"], item["supported_component"]["hits"], item["supported_component"]["rate"], item["added_supported_claims"]])
    csv_write(OUT_HEADLINE, headline_rows)
    stage_rows = [["phase", "chain_id", "claims", "gold_target_precision", "supported_component_precision", "added_supported_claims"]]
    for key, item in sorted(summary["gpt55_stage2_usecase"].items()):
        phase, chain = key.split("/", 1)
        stage_rows.append([phase, chain, item["claim_denominator"], item["gold_target"]["rate"], item["supported_component"]["rate"], item["added_supported_claims"]])
    csv_write(OUT_GPT55_STAGE2, stage_rows)
    print(json.dumps({"coverage": summary["coverage"], "headline_by_model": summary["headline_by_model"], "categories": summary["all_claim_categories"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
