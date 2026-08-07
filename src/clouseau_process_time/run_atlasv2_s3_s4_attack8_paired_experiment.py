#!/usr/bin/env python3
"""Preflight, run, and score the paired eight-chain attack experiment."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ROOT
    / "data/current_experiment/cases"
    / "atlasv2_s3_s4_attack8_paired_stage_cases_20260724.jsonl"
)
RUNNER = ROOT / "src/clouseau_process_time/run_clouseau_official_cbc_dense_eval.py"
SCORER = ROOT / "src/clouseau_process_time/score_element_order_with_gpt.py"
DOUBLE_REVIEW_SCORER = (
    ROOT
    / "src/clouseau_process_time"
    / "score_attack8_paired_completed_double_review.py"
)
DEFAULT_VALIDATION = (
    ROOT
    / "docs/current_experiment"
    / "atlasv2_s3_s4_attack8_paired_stage3_validation_steps_20260724.csv"
)
DEFAULT_RESULTS = (
    ROOT
    / "docs/current_experiment/results_2026-07-24"
    / "atlasv2_s3_s4_attack8_paired"
)
DEFAULT_MODELS = "gpt-5.4-mini"
STAGES = ("stage1", "stage2", "stage3")
NEUTRAL_CONTRACT_VERSIONS = {
    "neutral_anchor_local_window_v1",
    "neutral_anchor_semantic_chain_normal_parity_v2",
    "observable_component_normal_parity_v3",
    "process_behavior_chain_normal23_parity_v4",
    "process_behavior_chain_normal23_parity_v5_formal",
}
PROCESS_CHAIN_CONTRACT_VERSIONS = {
    "process_behavior_chain_normal23_parity_v4",
    "process_behavior_chain_normal23_parity_v5_formal",
}
PID_TOKEN = re.compile(r"\(\s*PID\s+\d+\s*\)", re.IGNORECASE)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def split_csv(value: str) -> list[str]:
    values = [item.strip() for item in value.split(",") if item.strip()]
    if not values:
        raise ValueError("at least one model is required")
    return values


def resolve_gold(case: dict[str, Any]) -> Path:
    root_text = str(case.get("formal_gold_root") or "").replace("\\", "/")
    file_text = str(case.get("gold_chain_file") or "").replace("\\", "/")
    gold = ROOT / Path(root_text) / Path(file_text)
    if not root_text or not file_text or not gold.is_file():
        raise FileNotFoundError(f"{case.get('instance_id')}: Gold not found: {gold}")
    return gold


def load_scorer_module() -> Any:
    spec = importlib.util.spec_from_file_location("attack8_paired_scorer", SCORER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scorer: {SCORER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select_cases(
    cases: list[dict[str, Any]],
    stages: list[str],
    limit: int | None,
    instance_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    selected = [case for case in cases if case.get("stage") in stages]
    if instance_ids:
        requested = set(instance_ids)
        selected = [
            case for case in selected if str(case.get("instance_id")) in requested
        ]
        found = {str(case.get("instance_id")) for case in selected}
        missing = requested - found
        if missing:
            raise ValueError(f"requested instance_id not found: {sorted(missing)}")
    if limit is not None:
        selected = selected[:limit]
    if not selected:
        raise ValueError("selection contains no cases")
    return selected


def stage3_rows(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for case in cases:
        if case["stage"] != "stage3":
            continue
        gold = json.loads(resolve_gold(case).read_text(encoding="utf-8"))
        chain_id = str(gold.get("chain_id") or case["chain_id"])
        for step in gold.get("gold_steps") or gold.get("behavior_timeline") or []:
            step_id = str(step.get("step_id") or "")
            evidence = step.get("canonical_evidence") or []
            if not step_id or not evidence:
                raise ValueError(
                    f"{case['instance_id']}: Stage-3 Gold step/evidence is missing"
                )
            if any(
                not isinstance(item, dict)
                or item.get("source_table") != "cbc_events"
                for item in evidence
            ):
                raise ValueError(
                    f"{case['instance_id']} {step_id}: Stage-3 Gold must use "
                    "canonical cbc_events evidence only"
                )
            key = (chain_id, step_id)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "chain_id": chain_id,
                    "step_id": step_id,
                    "stage3_status": "pass",
                    "validation_basis": (
                        "canonical cbc_events evidence; CBC alert summary excluded"
                    ),
                    "source_case": case["instance_id"],
                }
            )
    if not rows:
        raise ValueError("no Stage-3 validation rows generated")
    return rows


def write_stage3_validation(
    path: Path,
    cases: list[dict[str, Any]],
) -> list[dict[str, str]]:
    rows = stage3_rows(cases)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def compact_time(value: str) -> str:
    return value.replace("T", " ").replace("Z", "")[:19]


def normalize_process(value: Any) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def preflight(
    cases: list[dict[str, Any]],
    validation_steps: Path,
) -> dict[str, Any]:
    stage_counts = Counter(case.get("stage") for case in cases)
    expected_counts = {stage: 8 for stage in STAGES}
    if dict(stage_counts) != expected_counts:
        raise ValueError(f"unexpected stage counts: {dict(stage_counts)}")
    ids = [str(case.get("instance_id")) for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate instance_id")

    chain_sets = {
        stage: {case["chain_id"] for case in cases if case["stage"] == stage}
        for stage in STAGES
    }
    if not (chain_sets["stage1"] == chain_sets["stage2"] == chain_sets["stage3"]):
        raise ValueError("the chain set changes between stages")

    neutral_anchor_keys: dict[tuple[str, str, str, str], str] = {}
    neutral_contract_chain_count = 0
    neutral_gold_steps = 0
    neutral_all_gold_inside_window = True
    for chain_id in sorted(chain_sets["stage1"]):
        paired = [case for case in cases if case["chain_id"] == chain_id]
        gold_paths = {resolve_gold(case) for case in paired}
        scopes = {
            (
                case["host"],
                case["process_name"],
                case["time_window_utc"]["episode_start"],
                case["time_window_utc"]["episode_end"],
            )
            for case in paired
        }
        if len(paired) != 3 or len(gold_paths) != 1 or len(scopes) != 1:
            raise ValueError(f"{chain_id}: broken paired-stage contract")
        contract = paired[0].get("paired_stage_contract") or {}
        is_neutral_contract = (
            contract.get("contract_version") in NEUTRAL_CONTRACT_VERSIONS
        )
        if is_neutral_contract:
            neutral_contract_chain_count += 1
            neutral_signatures = {
                (
                    case.get("investigation_time_anchor_utc"),
                    (case.get("paired_stage_contract") or {}).get(
                        "target_component_rule"
                    ),
                    (case.get("paired_stage_contract") or {}).get(
                        "alert_mapping_scored"
                    ),
                )
                for case in paired
            }
            if len(neutral_signatures) != 1:
                raise ValueError(
                    f"{chain_id}: neutral anchor/target/scoring contract changes by stage"
                )
            neutral_anchor, target_rule, alert_mapping_scored = next(
                iter(neutral_signatures)
            )
            if not neutral_anchor or not target_rule:
                raise ValueError(f"{chain_id}: neutral anchor or target rule is missing")
            if alert_mapping_scored is not False:
                raise ValueError(f"{chain_id}: alert mapping must not be scored")
            if (
                contract.get("contract_version")
                == "observable_component_normal_parity_v3"
            ):
                provenance = paired[0].get("neutral_anchor_provenance") or {}
                if provenance.get("touches_declared_focus_process") is not True:
                    raise ValueError(
                        f"{chain_id}: v3 anchor is not verified against focus process"
                    )
                gold_preview = json.loads(
                    next(iter(gold_paths)).read_text(encoding="utf-8")
                )
                if (
                    (gold_preview.get("gold_exhaustiveness_audit") or {}).get(
                        "status"
                    )
                    != "pass"
                ):
                    raise ValueError(
                        f"{chain_id}: v3 Gold exhaustiveness audit is not pass"
                    )
                scoring = gold_preview.get("case_scoring") or {}
                if (
                    scoring.get("critical_evidence_in_action_denominator")
                    is not False
                    or scoring.get("action_components")
                    != ["subject", "action", "object"]
                ):
                    raise ValueError(
                        f"{chain_id}: v3 action/evidence scoring split is invalid"
                    )
            if contract.get("contract_version") in PROCESS_CHAIN_CONTRACT_VERSIONS:
                gold_preview = json.loads(
                    next(iter(gold_paths)).read_text(encoding="utf-8")
                )
                if (
                    (gold_preview.get("gold_granularity_audit") or {}).get(
                        "status"
                    )
                    != "pass"
                ):
                    raise ValueError(
                        f"{chain_id}: process-chain Gold granularity audit is not pass"
                    )
                scoring = gold_preview.get("case_scoring") or {}
                if (
                    scoring.get("critical_evidence_in_action_denominator")
                    is not False
                    or scoring.get("action_components")
                    != ["subject", "action", "object"]
                    or scoring.get("pid_identity_required_for_match") is not False
                ):
                    raise ValueError(
                        f"{chain_id}: process-chain normal-23 scoring parity is invalid"
                    )
                steps_preview = (
                    gold_preview.get("gold_steps")
                    or gold_preview.get("behavior_timeline")
                    or []
                )
                if any(
                    PID_TOKEN.search(str(step.get(field) or ""))
                    for step in steps_preview
                    for field in ("subject", "object")
                ):
                    raise ValueError(
                        f"{chain_id}: process-chain PID identity leaked into scored components"
                    )
            start = parse_utc(paired[0]["time_window_utc"]["episode_start"])
            end = parse_utc(paired[0]["time_window_utc"]["episode_end"])
            anchor_time = parse_utc(str(neutral_anchor))
            if end - start != timedelta(minutes=5):
                raise ValueError(f"{chain_id}: neutral contract requires a 5-minute window")
            if not start <= anchor_time <= end:
                raise ValueError(f"{chain_id}: neutral anchor is outside the window")
            key = (
                str(paired[0]["scenario"]),
                str(paired[0]["host"]),
                normalize_process(paired[0]["process_name"]),
                compact_time(str(neutral_anchor)),
            )
            if key in neutral_anchor_keys:
                raise ValueError(
                    f"{chain_id}: neutral anchor key collides with "
                    f"{neutral_anchor_keys[key]}: {key}"
                )
            neutral_anchor_keys[key] = chain_id
            gold = json.loads(next(iter(gold_paths)).read_text(encoding="utf-8"))
            steps = gold.get("gold_steps") or gold.get("behavior_timeline") or []
            neutral_gold_steps += len(steps)
            timestamps = [
                parse_utc(str(evidence["timestamp_utc"]))
                for step in steps
                for evidence in step.get("canonical_evidence") or []
            ]
            if not timestamps or min(timestamps) < start or max(timestamps) > end:
                neutral_all_gold_inside_window = False
                raise ValueError(f"{chain_id}: Gold evidence is outside the 5-minute window")
        for case in paired:
            if case.get("enforce_time_scope"):
                raise ValueError(
                    f"{case['instance_id']}: normal-suite parity forbids hard "
                    "adapter time truncation"
                )
            alerts = case.get("input_alert_rows") or []
            if case["stage"] == "stage1" and len(alerts) != 1:
                raise ValueError(
                    f"{case['instance_id']}: Stage 1 requires one representative alert"
                )
            if case["stage"] != "stage1" and alerts:
                raise ValueError(
                    f"{case['instance_id']}: Stage 2/3 must not expose alert input"
                )
            model_input = ((case.get("model_ready_input") or {}).get("input") or {})
            if contract.get("contract_version") in PROCESS_CHAIN_CONTRACT_VERSIONS:
                expected_input_keys = {
                    "host",
                    "focus_processes",
                    "chain_window_start_utc",
                    "chain_window_end_utc",
                }
                if case["stage"] == "stage1":
                    expected_input_keys.add("alerts")
                if set(model_input) != expected_input_keys:
                    raise ValueError(
                        f"{case['instance_id']}: process-chain input does not match the "
                        f"normal-23 field shape: {sorted(model_input)}"
                    )
            if (
                is_neutral_contract
                and case["stage"] != "stage1"
                and any(
                    key in model_input
                    for key in ("alerts", "cbc_alert", "alert_id", "alert_name")
                )
            ):
                raise ValueError(
                    f"{case['instance_id']}: Stage 2/3 leaks alert input fields"
                )

    rows = write_stage3_validation(validation_steps, cases)
    scorer = load_scorer_module()
    maxima_by_stage: dict[str, dict[str, int]] = {}
    for stage in STAGES:
        totals = Counter()
        for case in [item for item in cases if item["stage"] == stage]:
            gold_path = resolve_gold(case)
            chains = scorer.normalize_gold(
                json.loads(gold_path.read_text(encoding="utf-8")),
                gold_path,
            )
            filtered = scorer.filter_chains_for_stage(
                chains, stage, validation_steps
            )
            maxima = scorer.gold_maxima(filtered)
            if not maxima["gold_step_count"]:
                raise ValueError(f"{case['instance_id']}: no scoreable Gold steps")
            totals.update(maxima)
        maxima_by_stage[stage] = dict(totals)

    return {
        "status": "pass",
        "case_count": len(cases),
        "stage_counts": dict(stage_counts),
        "paired_chain_count": len(chain_sets["stage1"]),
        "same_chain_set_all_stages": True,
        "same_gold_and_scope_within_each_chain": True,
        "hard_time_scope": False,
        "neutral_contract_chain_count": neutral_contract_chain_count,
        "neutral_anchor_unique_count": len(neutral_anchor_keys),
        "neutral_gold_step_count": neutral_gold_steps,
        "neutral_all_gold_inside_window": neutral_all_gold_inside_window,
        "alert_mapping_scored": (
            False if neutral_contract_chain_count else "legacy_contract"
        ),
        "stage3_validation_rows": len(rows),
        "gold_maxima_by_stage": maxima_by_stage,
        "metric_contract": (
            "action_step_recall/action_step_precision exclude critical_evidence; "
            "critical_evidence_recall is reported separately"
        ),
    }


def build_run_command(
    case: dict[str, Any],
    model: str,
    args: argparse.Namespace,
    dry_run: bool,
) -> list[str]:
    command = [
        sys.executable,
        str(RUNNER),
        "--cases",
        str(args.cases),
        "--instance-id",
        case["instance_id"],
        "--model",
        model,
        "--difficulty",
        case["difficulty"],
        "--unbounded-agent-calls",
        "--max-tokens",
        str(args.max_tokens),
        "--sql-playbook",
        args.sql_playbook,
    ]
    if case["stage"] == "stage3":
        command.append("--exclude-cbc-alert-summary")
    if dry_run:
        command.append("--dry-run")
    if args.log_cost:
        command.append("--log-cost")
    return command


def command_text(command: list[str]) -> str:
    return " ".join(
        json.dumps(part) if any(char.isspace() for char in part) else part
        for part in command
    )


def overdue_active_llm_call(
    payload: dict[str, Any],
    now_utc: datetime,
    timeout_seconds: float,
) -> dict[str, Any] | None:
    """Return the oldest active call once its total wall time exceeds the cap."""
    overdue: list[dict[str, Any]] = []
    for call in payload.get("active_calls") or []:
        started_raw = call.get("started_at_utc")
        if not started_raw:
            continue
        started = datetime.fromisoformat(
            str(started_raw).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        elapsed = (now_utc.astimezone(timezone.utc) - started).total_seconds()
        if elapsed >= timeout_seconds:
            overdue.append(
                {
                    "run_id": call.get("run_id"),
                    "started_at_utc": started.isoformat(),
                    "elapsed_seconds": round(elapsed, 3),
                }
            )
    if not overdue:
        return None
    return max(overdue, key=lambda item: item["elapsed_seconds"])


def overdue_post_llm_idle(
    payload: dict[str, Any],
    now_utc: datetime,
    timeout_seconds: float,
) -> dict[str, Any] | None:
    """Detect a child that stopped progressing after its last LLM callback.

    The active-call watchdog cannot see a hang that occurs after ``on_llm_end``
    has fired (for example while a streaming connection or runner teardown is
    waiting forever).  Treat an unchanged, inactive callback state as progress
    starvation once it reaches the same 20-minute wall cap.  Legitimate SQL
    work already has an independent 20-minute wall guard, so this does not add
    a shorter experimental limit.
    """
    if payload.get("active_calls") or payload.get("active_call_count"):
        return None
    if payload.get("event") not in {"llm_end", "llm_error"}:
        return None
    updated_raw = payload.get("updated_at_utc")
    if not updated_raw:
        return None
    updated = datetime.fromisoformat(
        str(updated_raw).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    elapsed = (
        now_utc.astimezone(timezone.utc) - updated
    ).total_seconds()
    if elapsed < timeout_seconds:
        return None
    return {
        "event": payload.get("event"),
        "last_progress_at_utc": updated.isoformat(),
        "elapsed_seconds": round(elapsed, 3),
    }


def overdue_total_run(
    started_monotonic: float,
    now_monotonic: float,
    timeout_seconds: float,
) -> dict[str, Any] | None:
    """Return total-run overrun details when the opt-in cap is enabled."""
    if timeout_seconds <= 0:
        return None
    elapsed = now_monotonic - started_monotonic
    if elapsed < timeout_seconds:
        return None
    return {
        "elapsed_seconds": round(elapsed, 3),
        "timeout_seconds": timeout_seconds,
    }


def run_runner(
    case: dict[str, Any],
    model: str,
    args: argparse.Namespace,
    dry_run: bool,
) -> Path:
    command = build_run_command(case, model, args, dry_run)
    hard_wall_timeout_seconds = float(
        os.getenv("CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS", "1200")
    )
    total_run_timeout_seconds = float(
        os.getenv("CLOUSEAU_RUN_HARD_WALL_TIMEOUT_SECONDS", "0")
    )
    invocation_stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )
    runtime_dir = args.result_root / "_runtime" / "llm_call_watchdog"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    state_path = runtime_dir / (
        f"{invocation_stamp}_{model}_active.json"
    )
    timeout_report_path = state_path.with_name(
        state_path.name.replace("_active.json", "_timeout.json")
    )
    activity_ledger_path = state_path.with_name(
        state_path.name.replace("_active.json", "_activity.jsonl")
    )
    child_env = os.environ.copy()
    child_env["CLOUSEAU_LLM_ACTIVE_CALL_STATE_FILE"] = str(state_path)
    child_env["CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS"] = str(
        hard_wall_timeout_seconds
    )
    child_env["CLOUSEAU_ACTIVITY_LEDGER_FILE"] = str(
        activity_ledger_path
    )
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_env,
    )
    process_started_monotonic = time.monotonic()
    timed_out_call: dict[str, Any] | None = None
    timed_out_idle: dict[str, Any] | None = None
    timed_out_run: dict[str, Any] | None = None
    while process.poll() is None:
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                timed_out_call = overdue_active_llm_call(
                    state,
                    datetime.now(timezone.utc),
                    hard_wall_timeout_seconds,
                )
                timed_out_idle = overdue_post_llm_idle(
                    state,
                    datetime.now(timezone.utc),
                    hard_wall_timeout_seconds,
                )
            except (OSError, ValueError, TypeError):
                # The callback updates atomically, but a transient read error
                # must not terminate an otherwise valid experiment.
                timed_out_call = None
                timed_out_idle = None
        timed_out_run = overdue_total_run(
            process_started_monotonic,
            time.monotonic(),
            total_run_timeout_seconds,
        )
        if (
            timed_out_call is not None
            or timed_out_idle is not None
            or timed_out_run is not None
        ):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            break
        time.sleep(0.5)
    stdout, stderr = process.communicate()
    if (
        timed_out_call is not None
        or timed_out_idle is not None
        or timed_out_run is not None
    ):
        if timed_out_call is not None:
            timeout_reason = "active_llm_call"
            effective_timeout_seconds = hard_wall_timeout_seconds
        elif timed_out_idle is not None:
            timeout_reason = "post_llm_no_progress"
            effective_timeout_seconds = hard_wall_timeout_seconds
        else:
            timeout_reason = "total_run_wall"
            effective_timeout_seconds = total_run_timeout_seconds
        activity_events: list[dict[str, Any]] = []
        if activity_ledger_path.is_file():
            for line in activity_ledger_path.read_text(
                encoding="utf-8"
            ).splitlines():
                if not line.strip():
                    continue
                try:
                    activity_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        completed_activity_events = [
            event
            for event in activity_events
            if event.get("event_status") in {None, "completed"}
        ]
        timeout_payload = {
            "schema_version": "clouseau_runner_hard_wall_timeout_v3",
            "detected_at_utc": datetime.now(timezone.utc).isoformat(),
            "model": model,
            "instance_id": case["instance_id"],
            "timeout_seconds": effective_timeout_seconds,
            "llm_call_timeout_seconds": hard_wall_timeout_seconds,
            "total_run_timeout_seconds": total_run_timeout_seconds,
            "timeout_reason": timeout_reason,
            "timed_out_call": timed_out_call,
            "timed_out_idle": timed_out_idle,
            "timed_out_run": timed_out_run,
            "command": command,
            "state_file": str(state_path),
            "activity_ledger_file": str(activity_ledger_path),
            "activity_ledger_record_count": len(activity_events),
            "completed_activity_event_count": len(
                completed_activity_events
            ),
            "activity_event_count_by_role": dict(
                Counter(
                    str(event.get("role") or "unknown")
                    for event in completed_activity_events
                )
            ),
            "activity_event_count_by_tool": dict(
                Counter(
                    str(event.get("tool_name") or "unknown")
                    for event in completed_activity_events
                )
            ),
            "activity_tail": activity_events[-10:],
            "child_returncode": process.returncode,
            "stdout_tail": stdout[-4000:],
            "stderr_tail": stderr[-4000:],
        }
        timeout_report_path.write_text(
            json.dumps(timeout_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        raise RuntimeError(
            f"runner hard-wall timeout for {case['instance_id']} {model}: "
            f"{timeout_reason} exceeded {effective_timeout_seconds:.0f}s; "
            f"report={timeout_report_path}"
        )
    if process.returncode != 0:
        raise RuntimeError(
            f"runner failed for {case['instance_id']} {model} "
            f"(exit {process.returncode})\n"
            f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        )
    paths = [
        Path(line.strip())
        for line in stdout.splitlines()
        if line.strip().endswith("run.json")
    ]
    if not paths:
        raise RuntimeError(
            f"runner did not print run.json for {case['instance_id']} {model}"
        )
    source = paths[-1]
    if not source.is_absolute():
        source = ROOT / source
    bucket = "dry_runs" if dry_run else "runs"
    destination = (
        args.result_root
        / bucket
        / model
        / case["stage"]
        / f"{case['instance_id']}_run.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    payload["atlasv2_s3_s4_attack8_paired_experiment"] = {
        "suite_group": case.get("suite_group"),
        "contract_version": (
            (case.get("paired_stage_contract") or {}).get("contract_version")
        ),
        "case_file": str(args.cases),
        "chain_id": case["chain_id"],
        "stage": case["stage"],
        "gold": str(resolve_gold(case)),
        "copied_from": str(source),
    }
    write_json(destination, payload)
    return destination


def existing_output(
    case: dict[str, Any],
    model: str,
    args: argparse.Namespace,
    dry_run: bool,
) -> Path | None:
    bucket = "dry_runs" if dry_run else "runs"
    path = (
        args.result_root
        / bucket
        / model
        / case["stage"]
        / f"{case['instance_id']}_run.json"
    )
    if not path.is_file():
        return None
    json.loads(path.read_text(encoding="utf-8"))
    return path


def build_double_review_command(args: argparse.Namespace) -> list[str]:
    score_root = (
        args.score_root
        if args.score_root is not None
        else args.result_root / "scores_normal_parity_double_review"
    )
    command = [
        sys.executable,
        str(DOUBLE_REVIEW_SCORER),
        "--cases",
        str(args.cases),
        "--result-root",
        str(args.result_root),
        "--score-root",
        str(score_root),
        "--validation-steps",
        str(args.validation_steps),
        "--judge-model",
        "gpt-5",
        "--reasoning-effort",
        "high",
    ]
    if args.score_list_only:
        command.append("--list-only")
    if args.score_audit_only:
        command.append("--audit-only")
    if args.score_bootstrap_provenance:
        command.append("--bootstrap-provenance")
    return command


def run_double_review(args: argparse.Namespace) -> dict[str, Any]:
    command = build_double_review_command(args)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "formal double-review scoring failed "
            f"(exit {completed.returncode})\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    return {
        "wrapper": str(DOUBLE_REVIEW_SCORER),
        "command": command_text(command),
        "score_root": str(
            args.score_root
            if args.score_root is not None
            else args.result_root / "scores_normal_parity_double_review"
        ),
        "judge_model": "gpt-5",
        "reasoning_effort": "high",
        "list_only": args.score_list_only,
        "audit_only": args.score_audit_only,
        "bootstrap_provenance": args.score_bootstrap_provenance,
    }


def build_manifest(
    cases: list[dict[str, Any]],
    models: list[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    suite_groups = sorted(
        {str(case.get("suite_group") or "") for case in cases}
    )
    if len(suite_groups) != 1 or not suite_groups[0]:
        raise ValueError(f"cases do not declare one suite_group: {suite_groups}")
    evaluation_units = sorted(
        {
            str(
                (case.get("paired_stage_contract") or {}).get("evaluation_unit")
                or ""
            )
            for case in cases
        }
    )
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "suite": suite_groups[0],
        "case_file": str(args.cases),
        "case_count": len(cases),
        "stage_counts": dict(Counter(case["stage"] for case in cases)),
        "models": models,
        "result_root": str(args.result_root),
        "validation_steps": str(args.validation_steps),
        "evaluation_unit": (
            evaluation_units[0]
            if len(evaluation_units) == 1 and evaluation_units[0]
            else "same eight behavior chains in Stage 1/2/3"
        ),
        "normal_suite_parity": {
            "same_chain_and_gold_all_stages": True,
            "stage1_representative_alert_input": True,
            "stage2_process_time_input": True,
            "stage3_process_time_with_alert_summaries_hidden": True,
            "hard_adapter_time_scope": False,
            "same_scorer": str(SCORER),
            "agent_call_limit_policy": (
                "unbounded: no Chief, Investigator, or SQL Agent call-count ceiling"
            ),
        },
        "metric_contract": {
            "primary": [
                "behavior_step_recall",
                "action_step_recall",
                "action_step_precision",
                "behavior_sequence_order",
            ],
            "separate_diagnostic": "critical_evidence_recall",
        },
        "execution_commands": [
            command_text(build_run_command(case, model, args, False))
            for model in models
            for case in cases
        ],
        "dry_run_commands": [
            command_text(build_run_command(case, model, args, True))
            for model in models
            for case in cases
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--result-root", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--validation-steps", type=Path, default=DEFAULT_VALIDATION)
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument("--stage", action="append", choices=STAGES)
    parser.add_argument(
        "--instance-id",
        action="append",
        help="Run only this exact instance_id; repeat for multiple cases.",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--score", action="store_true")
    parser.add_argument(
        "--score-root",
        type=Path,
        help=(
            "Double-review output root; defaults to "
            "<result-root>/scores_normal_parity_double_review."
        ),
    )
    parser.add_argument(
        "--score-list-only",
        action="store_true",
        help="With --score, discover eligible completed runs without judge API calls.",
    )
    parser.add_argument(
        "--score-audit-only",
        action="store_true",
        help="With --score, rebuild double-review ledgers without judge API calls.",
    )
    parser.add_argument(
        "--score-bootstrap-provenance",
        action="store_true",
        help=(
            "With --score, attach provenance sidecars to known matching scores; "
            "normally combine with --score-audit-only."
        ),
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-tokens", type=int, default=24576)
    parser.add_argument("--sql-playbook", choices=["none", "generic"], default="none")
    parser.add_argument("--log-cost", action="store_true")
    args = parser.parse_args()

    if (
        args.score_list_only
        or args.score_audit_only
        or args.score_bootstrap_provenance
    ) and not args.score:
        parser.error(
            "--score-list-only, --score-audit-only, and "
            "--score-bootstrap-provenance require --score"
        )
    if args.score_list_only and args.score_audit_only:
        parser.error("--score-list-only and --score-audit-only are mutually exclusive")

    # A scoring-only invocation must not rewrite run/preflight manifests.  The
    # dedicated wrapper discovers every currently completed run under result_root.
    if args.score and not args.run and not args.dry_run and not args.preflight:
        formal_scoring = run_double_review(args)
        print(
            json.dumps(
                {
                    "formal_double_review": formal_scoring,
                    "run_outputs_written": 0,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    all_cases = read_jsonl(args.cases)
    selected = select_cases(
        all_cases,
        args.stage or list(STAGES),
        args.limit,
        args.instance_id,
    )
    models = split_csv(args.models)
    args.result_root.mkdir(parents=True, exist_ok=True)
    preflight_result = preflight(all_cases, args.validation_steps)
    write_json(args.result_root / "preflight.json", preflight_result)
    write_json(
        args.result_root / "manifest.json",
        build_manifest(all_cases, models, args),
    )
    write_json(
        args.result_root / "selection_manifest.json",
        build_manifest(selected, models, args),
    )

    outputs: list[tuple[Path, dict[str, Any], str]] = []
    if args.dry_run:
        for model in models:
            for case in selected:
                output = (
                    existing_output(case, model, args, True) if args.resume else None
                )
                outputs.append(
                    (output or run_runner(case, model, args, True), case, model)
                )
    if args.run:
        for model in models:
            for case in selected:
                output = (
                    existing_output(case, model, args, False) if args.resume else None
                )
                outputs.append(
                    (output or run_runner(case, model, args, False), case, model)
                )

    formal_scoring: dict[str, Any] | None = None
    if args.score:
        formal_scoring = run_double_review(args)

    print(
        json.dumps(
            {
                "preflight": str(args.result_root / "preflight.json"),
                "selected_cases": len(selected),
                "models": models,
                "dry_run_outputs": sum(
                    "dry_runs" in path.parts for path, _, _ in outputs
                ),
                "run_outputs": sum(
                    "runs" in path.parts and "dry_runs" not in path.parts
                    for path, _, _ in outputs
                ),
                "formal_double_review": formal_scoring,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
