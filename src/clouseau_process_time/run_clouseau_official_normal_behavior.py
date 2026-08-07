#!/usr/bin/env python3
"""Run the official CLOUSEAU pipeline on ATLASv2 normal-behavior instances.

This script uses the CLOUSEAU implementation under external/Clouseau/artifact.
It builds an adapter SQLite database with the table/column names expected by
official CLOUSEAU, then calls chief_inspector.investigate_atlas.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from langchain_core.callbacks import UsageMetadataCallbackHandler


ROOT = Path(__file__).resolve().parents[2]
OFFICIAL_ARTIFACT = ROOT / "external" / "Clouseau" / "artifact"
GOLD_PATH = ROOT / "Clouseau" / "artifact" / "scenarios" / "atlasv2" / "behavior_gold.jsonl"
RUNS_DIR = ROOT / "Clouseau" / "artifact" / "runs" / "atlasv2_official_clouseau"
ENV_PATH = ROOT / ".env.clouseau"
DEFAULT_MAX_INVESTIGATIONS = 8
DEFAULT_MAX_QUESTIONS = 12
DEFAULT_MAX_QUERIES = 20
DEFAULT_MAX_TOKENS = 8192


class InvestigationActivityTracker:
    """Capture every cross-agent tool call as a deterministic run artifact."""

    def __init__(self, live_ledger_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._next_sequence = 1
        self._events: List[Dict[str, Any]] = []
        self._live_ledger_path = live_ledger_path
        if self._live_ledger_path is not None:
            self._live_ledger_path.parent.mkdir(parents=True, exist_ok=True)
            # Every runner invocation supplies a unique timestamped path.  A
            # collision must fail instead of overwriting prior diagnostics.
            self._live_ledger_path.touch(exist_ok=False)

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            return {
                str(key): InvestigationActivityTracker._json_safe(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [
                InvestigationActivityTracker._json_safe(item)
                for item in value
            ]
        return str(value)

    def begin(
        self,
        role: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
        event = {
            "sequence": sequence,
            "role": str(role),
            "tool_name": str(tool_name),
            "arguments": self._json_safe(arguments),
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "_started_monotonic": time.monotonic(),
        }
        if self._live_ledger_path is not None:
            live_event = {
                key: value
                for key, value in event.items()
                if key != "_started_monotonic"
            }
            live_event["event_status"] = "started"
            with self._lock:
                with self._live_ledger_path.open(
                    "a",
                    encoding="utf-8",
                ) as handle:
                    handle.write(
                        json.dumps(live_event, ensure_ascii=False) + "\n"
                    )
                    handle.flush()
        return event

    @staticmethod
    def _outcome(tool_name: str, result_text: str, error: str | None) -> str:
        if error:
            return "tool_exception"
        lowered = result_text.lower()
        if tool_name == "run_sql_query":
            if "query rejected by the sql scale guard" in lowered:
                return "sql_guard_rejected"
            if "query aborted by the sql execution guard" in lowered:
                return "sql_guard_aborted"
            if "no results found" in lowered:
                return "sql_no_results"
            if "was truncated" in lowered:
                return "sql_result_truncated"
            if "an error occurred" in lowered:
                return "sql_error"
            return "sql_success"
        if "bad tool name" in lowered:
            return "bad_tool_name"
        if "tool_validation_recovery:" in lowered:
            return "tool_validation_recovered"
        return "success"

    def finish(
        self,
        event: Dict[str, Any],
        *,
        result: Any = None,
        error: BaseException | None = None,
    ) -> None:
        payload = dict(event)
        started = float(payload.pop("_started_monotonic"))
        result_text = "" if result is None else str(result)
        error_text = (
            None
            if error is None
            else f"{type(error).__name__}: {error}"
        )
        payload.update(
            {
                "finished_at_utc": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - started, 6),
                "outcome": self._outcome(
                    str(payload["tool_name"]),
                    result_text,
                    error_text,
                ),
                "result_length_chars": len(result_text),
                "result_preview": result_text[:500],
                "error": error_text,
            }
        )
        live_payload = dict(payload)
        live_payload["event_status"] = "completed"
        with self._lock:
            self._events.append(payload)
            if self._live_ledger_path is not None:
                with self._live_ledger_path.open(
                    "a",
                    encoding="utf-8",
                ) as handle:
                    handle.write(
                        json.dumps(live_payload, ensure_ascii=False) + "\n"
                    )
                    handle.flush()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            events = sorted(
                (dict(event) for event in self._events),
                key=lambda event: int(event["sequence"]),
            )

        role_counts: Dict[str, int] = {}
        tool_counts: Dict[str, int] = {}
        outcome_counts: Dict[str, int] = {}
        for event in events:
            role = str(event["role"])
            tool_name = str(event["tool_name"])
            outcome = str(event["outcome"])
            role_counts[role] = role_counts.get(role, 0) + 1
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

        def unique_argument(tool_names: set[str], argument_name: str) -> int:
            values = {
                str((event.get("arguments") or {}).get(argument_name) or "").strip()
                for event in events
                if str(event.get("tool_name")) in tool_names
            }
            values.discard("")
            return len(values)

        lead_count = tool_counts.get("investigate_lead", 0)
        investigator_tools = {
            name for name in tool_counts if name.startswith("ask_")
        }
        investigator_count = sum(
            tool_counts[name] for name in investigator_tools
        )
        sql_count = tool_counts.get("run_sql_query", 0)
        unique_leads = unique_argument({"investigate_lead"}, "lead")
        unique_behavior_keys = unique_argument(
            {"investigate_lead"},
            "behavior_key",
        )
        unique_questions = unique_argument(investigator_tools, "question")
        unique_queries = unique_argument({"run_sql_query"}, "query")
        durations = [
            float(event.get("duration_seconds") or 0.0)
            for event in events
        ]

        return {
            "schema_version": "cross_agent_activity_v1",
            "summary": {
                "total_tool_call_count": len(events),
                "tool_call_count_by_role": role_counts,
                "tool_call_count_by_name": tool_counts,
                "outcome_count": outcome_counts,
                "lead_call_count": lead_count,
                "unique_lead_count": unique_leads,
                "repeated_lead_count": lead_count - unique_leads,
                "unique_behavior_key_count": unique_behavior_keys,
                "repeated_behavior_key_count": (
                    lead_count - unique_behavior_keys
                ),
                "investigator_question_count": investigator_count,
                "unique_investigator_question_count": unique_questions,
                "repeated_investigator_question_count": (
                    investigator_count - unique_questions
                ),
                "sql_query_count": sql_count,
                "unique_sql_query_count": unique_queries,
                "repeated_sql_query_count": sql_count - unique_queries,
                "total_tool_duration_seconds": round(sum(durations), 6),
                "max_tool_duration_seconds": round(max(durations, default=0.0), 6),
            },
            "events": events,
        }


def configure_utf8_stdio() -> None:
    """Keep Japanese CLI output readable on Windows and captured logs."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


configure_utf8_stdio()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, default=GOLD_PATH)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--instance-id", action="append", help="Gold instance ID. May be repeated.")
    parser.add_argument("--run-all", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--max-investigations",
        type=int,
        default=DEFAULT_MAX_INVESTIGATIONS,
        help="Safety cap for Chief investigation rounds. Default is intentionally high enough for autonomous exploration.",
    )
    parser.add_argument("--max-questions", type=int, default=DEFAULT_MAX_QUESTIONS)
    parser.add_argument("--max-queries", type=int, default=DEFAULT_MAX_QUERIES)
    parser.add_argument(
        "--unbounded-agent-calls",
        action="store_true",
        help=(
            "Disable CLOUSEAU Chief, Investigator, and SQL Agent call-count "
            "ceilings. The agents stop only when they return a final answer."
        ),
    )
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default=None,
        help="OpenAI reasoning effort to request for GPT-5-class models.",
    )
    parser.add_argument("--log-cost", action="store_true")
    parser.add_argument(
        "--difficulty",
        choices=["exact", "actor_time", "behavior_time", "behavior_only"],
        default="exact",
        help="How much clue information to give official CLOUSEAU.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def load_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def infer_llm_provider(model: str, env: Dict[str, str]) -> str:
    provider = (
        env.get("CLOUSEAU_LLM_PROVIDER")
        or env.get("CLOUSEAU_PROVIDER")
        or os.environ.get("CLOUSEAU_LLM_PROVIDER")
        or os.environ.get("CLOUSEAU_PROVIDER")
        or ""
    ).strip().lower()
    if provider:
        if provider not in {"openai", "anthropic"}:
            raise ValueError(f"Unsupported CLOUSEAU_LLM_PROVIDER={provider!r}")
        return provider
    if model.startswith("claude-"):
        return "anthropic"
    return "openai"


def default_model_for_provider(provider_hint: str | None, env: Dict[str, str]) -> str:
    provider = (provider_hint or "").strip().lower()
    if provider == "anthropic":
        return env.get("ANTHROPIC_MODEL") or env.get("CLAUDE_MODEL") or "claude-sonnet-4-6"
    return env.get("OPENAI_MODEL") or "gpt-5-mini"


def api_key_for_provider(provider: str, env: Dict[str, str]) -> str | None:
    if provider == "anthropic":
        return (
            env.get("ANTHROPIC_API_KEY")
            or env.get("CLAUDE_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("CLAUDE_API_KEY")
        )
    return env.get("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY")


def build_chat_model(
    provider: str,
    model: str,
    api_key: str,
    max_tokens: int,
    reasoning_effort: str | None = None,
    callbacks: Optional[List[Any]] = None,
):
    if provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as exc:
            raise RuntimeError(
                "Claude runs require langchain-anthropic. Install it in the active Python environment."
            ) from exc
        return ChatAnthropic(
            model=model,
            api_key=api_key,
            max_tokens=max_tokens,
            callbacks=callbacks,
        )

    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError("OpenAI runs require langchain-openai in the active Python environment.") from exc
    llm_kwargs: Dict[str, Any] = {
        "model": model,
        "api_key": api_key,
        "callbacks": callbacks,
        # Bind the declared experiment output cap to the actual API request.
        # Previously this value was only persisted in run metadata.
        "max_completion_tokens": max_tokens,
        # A lead wall guard cannot interrupt an already-blocked network call.
        "timeout": float(
            os.getenv("CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS", "1200")
        ),
        # Do not let the SDK silently multiply the wall-clock guard by
        # retrying a timed-out long generation.
        "max_retries": 0,
    }
    if not model.startswith("gpt-5"):
        llm_kwargs["temperature"] = 0
    if reasoning_effort:
        llm_kwargs["reasoning_effort"] = reasoning_effort
        llm_kwargs["use_responses_api"] = True
    return ChatOpenAI(**llm_kwargs)


def empty_usage() -> Dict[str, int]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_input_tokens": 0,
        "total_tokens": 0,
    }


def normalize_usage(usage: Any) -> Dict[str, int]:
    """Normalize LangChain usage metadata without losing cached-token detail."""
    raw = dict(usage or {})
    input_details = dict(raw.get("input_token_details") or {})
    cached_input = int(
        input_details.get("cache_read", raw.get("cached_input_tokens", 0)) or 0
    )
    input_tokens = int(raw.get("input_tokens", 0) or 0)
    output_tokens = int(raw.get("output_tokens", 0) or 0)
    total_tokens = int(
        raw.get("total_tokens", input_tokens + output_tokens)
        or (input_tokens + output_tokens)
    )
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_input_tokens": cached_input,
        "total_tokens": total_tokens,
    }


def add_usage(*items: Dict[str, int]) -> Dict[str, int]:
    total = empty_usage()
    for item in items:
        normalized = normalize_usage(item)
        for key in total:
            total[key] += normalized[key]
    return total


def subtract_usage(total: Dict[str, int], parts: Dict[str, int]) -> Dict[str, int]:
    total_normalized = normalize_usage(total)
    parts_normalized = normalize_usage(parts)
    return {
        key: max(total_normalized[key] - parts_normalized[key], 0)
        for key in total_normalized
    }


def usage_from_callback(handler: Any) -> Dict[str, Any]:
    """Return totals and per-model usage collected across every model invoke."""
    by_model: Dict[str, Dict[str, int]] = {}
    for model_name, usage in dict(
        getattr(handler, "usage_metadata", {}) or {}
    ).items():
        by_model[str(model_name)] = normalize_usage(usage)
    calls = [
        {
            "run_id": call.get("run_id"),
            "model": call.get("model"),
            "usage": normalize_usage(call.get("usage") or {}),
            "started_at_utc": call.get("started_at_utc"),
            "finished_at_utc": call.get("finished_at_utc"),
            "duration_seconds": call.get("duration_seconds"),
        }
        for call in list(getattr(handler, "calls", []) or [])
    ]
    total = add_usage(*by_model.values())
    if not total["total_tokens"] and calls:
        total = add_usage(*[call["usage"] for call in calls])
    return {
        "total": total,
        "by_model": by_model,
        "calls": calls,
    }


def usage_from_serialized_messages(
    serialized: Iterable[Dict[str, Any]],
) -> Dict[str, int]:
    return add_usage(
        *[
            normalize_usage(item.get("usage_metadata") or {})
            for item in serialized
        ]
    )


class PipelineUsageCallbackHandler(UsageMetadataCallbackHandler):
    """Collect aggregate and per-call usage for the complete nested pipeline."""

    def __init__(
        self,
        active_call_state_path: Optional[Path] = None,
        hard_wall_timeout_seconds: Optional[float] = None,
        budget_state: Any = None,
        budget_role: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.calls: List[Dict[str, Any]] = []
        self._calls_lock = threading.Lock()
        self._call_starts: Dict[str, Dict[str, Any]] = {}
        self._active_call_state_path = active_call_state_path
        self._hard_wall_timeout_seconds = hard_wall_timeout_seconds
        self._budget_state = budget_state
        self._budget_role = budget_role
        if self._active_call_state_path is not None:
            with self._calls_lock:
                self._persist_active_calls_locked("initialized")

    def _persist_active_calls_locked(self, event: str) -> None:
        """Publish active calls atomically for the external hard-wall watchdog."""
        path = self._active_call_state_path
        if path is None:
            return
        payload = {
            "schema_version": "clouseau_active_llm_calls_v1",
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "hard_wall_timeout_seconds": self._hard_wall_timeout_seconds,
            "active_call_count": len(self._call_starts),
            "active_calls": [
                {
                    "run_id": run_id,
                    "started_at_utc": started["started_at_utc"],
                }
                for run_id, started in sorted(self._call_starts.items())
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        # On Windows, a concurrent read by the external watchdog can briefly
        # prevent replacing the destination.  Do not lose callback state for
        # this transient sharing violation; retry for a small bounded window.
        for attempt in range(5):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))

    def _record_start(self, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id") or "")
        if not run_id:
            return
        started = {
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "started_monotonic": time.monotonic(),
        }
        with self._calls_lock:
            self._call_starts.setdefault(run_id, started)
            self._persist_active_calls_locked("llm_start")

    def on_llm_start(self, *args: Any, **kwargs: Any) -> None:
        self._record_start(**kwargs)

    def on_chat_model_start(self, *args: Any, **kwargs: Any) -> None:
        self._record_start(**kwargs)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        super().on_llm_end(response, **kwargs)
        run_id = str(kwargs.get("run_id") or "")
        finished_at_utc = datetime.now(timezone.utc).isoformat()
        finished_monotonic = time.monotonic()
        with self._calls_lock:
            started = self._call_starts.pop(run_id, None)
            self._persist_active_calls_locked("llm_end")
        calls: List[Dict[str, Any]] = []
        for generations in getattr(response, "generations", []) or []:
            for generation in generations or []:
                message = getattr(generation, "message", None)
                usage = getattr(message, "usage_metadata", None)
                if not usage:
                    continue
                response_metadata = dict(
                    getattr(message, "response_metadata", {}) or {}
                )
                calls.append(
                    {
                        "run_id": run_id,
                        "model": (
                            response_metadata.get("model_name")
                            or response_metadata.get("model")
                            or "unknown_model"
                        ),
                        "usage": dict(usage),
                        "started_at_utc": (
                            started.get("started_at_utc")
                            if started is not None
                            else None
                        ),
                        "finished_at_utc": finished_at_utc,
                        "duration_seconds": (
                            round(
                                finished_monotonic
                                - float(started["started_monotonic"]),
                                3,
                            )
                            if started is not None
                            else None
                        ),
                    }
                )
        if calls:
            with self._calls_lock:
                self.calls.extend(calls)
            if self._budget_state is not None:
                for call in calls:
                    self._budget_state.record_call(
                        role=str(self._budget_role or "unattributed"),
                        model=str(call.get("model") or "unknown_model"),
                        usage=normalize_usage(call.get("usage") or {}),
                    )

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        super().on_llm_error(error, **kwargs)
        run_id = str(kwargs.get("run_id") or "")
        if run_id:
            with self._calls_lock:
                self._call_starts.pop(run_id, None)
                self._persist_active_calls_locked("llm_error")


GPT55_LONG_CONTEXT_INPUT_THRESHOLD = 272_000


def estimate_usage_cost(
    requested_model: str,
    calls: Iterable[Dict[str, Any]],
    fallback_total: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Estimate standard API token cost from a per-call usage ledger."""
    call_list = list(calls)
    pricing_source = "per_call_ledger"
    if not call_list and fallback_total:
        call_list = [
            {
                "model": requested_model,
                "usage": normalize_usage(fallback_total),
            }
        ]
        pricing_source = "aggregate_fallback"

    prices = model_prices(requested_model)
    input_cost = 0.0
    cached_input_cost = 0.0
    output_cost = 0.0
    long_context_calls = 0
    priced_calls: List[Dict[str, Any]] = []
    is_gpt55 = requested_model == "gpt-5.5" or requested_model.startswith(
        "gpt-5.5-"
    )

    for index, call in enumerate(call_list, start=1):
        usage = normalize_usage(call.get("usage") or {})
        cached_tokens = min(
            usage["cached_input_tokens"],
            usage["input_tokens"],
        )
        uncached_tokens = usage["input_tokens"] - cached_tokens
        is_long_context = (
            is_gpt55
            and usage["input_tokens"] > GPT55_LONG_CONTEXT_INPUT_THRESHOLD
        )
        input_multiplier = 2.0 if is_long_context else 1.0
        output_multiplier = 1.5 if is_long_context else 1.0
        if is_long_context:
            long_context_calls += 1

        call_input_cost = (
            uncached_tokens
            / 1_000_000.0
            * prices["input"]
            * input_multiplier
        )
        call_cached_cost = (
            cached_tokens
            / 1_000_000.0
            * prices["cached_input"]
            * input_multiplier
        )
        call_output_cost = (
            usage["output_tokens"]
            / 1_000_000.0
            * prices["output"]
            * output_multiplier
        )
        input_cost += call_input_cost
        cached_input_cost += call_cached_cost
        output_cost += call_output_cost
        priced_calls.append(
            {
                "index": index,
                "model": call.get("model") or requested_model,
                "usage": usage,
                "long_context_pricing": is_long_context,
                "input_multiplier": input_multiplier,
                "output_multiplier": output_multiplier,
                "estimated_cost_usd": round(
                    call_input_cost
                    + call_cached_cost
                    + call_output_cost,
                    12,
                ),
            }
        )

    total_cost = input_cost + cached_input_cost + output_cost
    return {
        "currency": "USD",
        "pricing_scope": "standard_api_text_tokens",
        "pricing_source": pricing_source,
        "price_card_version": (
            "openai_public_model_pages_checked_2026-07-29"
            if requested_model.startswith("gpt-")
            else "local_static_price_table"
        ),
        "requested_model": requested_model,
        "base_rates_per_1m_tokens": prices,
        "call_count": len(priced_calls),
        "long_context_call_count": long_context_calls,
        "gpt55_long_context_input_threshold": (
            GPT55_LONG_CONTEXT_INPUT_THRESHOLD if is_gpt55 else None
        ),
        "input_cost_usd": round(input_cost, 12),
        "cached_input_cost_usd": round(cached_input_cost, 12),
        "output_cost_usd": round(output_cost, 12),
        "total_cost_usd": round(total_cost, 12),
        "regional_processing_uplift_applied": False,
        "batch_discount_applied": False,
        "local_function_tool_fees_usd": 0.0,
        "calls": priced_calls,
    }


class RunBudgetGuard:
    """Thread-safe, opt-in full-run token/call/cost/lead circuit breaker."""

    def __init__(self, requested_model: str, config: Dict[str, Any]) -> None:
        self.requested_model = requested_model
        self.config = dict(config)
        self.enabled = bool(self.config.get("enabled"))
        self._lock = threading.Lock()
        self._calls = 0
        self._usage = empty_usage()
        self._cost_usd = 0.0
        self._chief_leads_started = 0
        self._chief_leads_completed = 0
        self._active_chief_leads = 0
        self._events: List[Dict[str, Any]] = []
        self._event_keys: set[str] = set()
        self._role_call_counts: Dict[str, int] = {}

    def _threshold_reason_locked(self, level: str) -> Optional[str]:
        if not self.enabled:
            return None
        values = {
            "api_calls": float(self._calls),
            "total_tokens": float(self._usage["total_tokens"]),
            "cost_usd": float(self._cost_usd),
            "chief_leads": float(self._chief_leads_completed),
        }
        labels = {
            "api_calls": "full-run API call",
            "total_tokens": "full-run total-token",
            "cost_usd": "full-run estimated-cost",
            "chief_leads": "full-run Chief lead",
        }
        for name in ("cost_usd", "total_tokens", "api_calls", "chief_leads"):
            limit = self.config.get(f"{level}_{name}")
            if limit is None:
                continue
            if values[name] >= float(limit):
                suffix = " USD" if name == "cost_usd" else ""
                return (
                    f"{labels[name]} {level} limit reached "
                    f"({values[name]:g}/{float(limit):g}{suffix})"
                )
        return None

    def _record_thresholds_locked(self) -> None:
        for level in ("soft", "hard"):
            reason = self._threshold_reason_locked(level)
            if reason is None:
                continue
            key = f"{level}:{reason.split(' limit reached', 1)[0]}"
            if key in self._event_keys:
                continue
            self._event_keys.add(key)
            self._events.append(
                {
                    "at_utc": datetime.now(timezone.utc).isoformat(),
                    "level": level,
                    "reason": reason,
                    "api_calls": self._calls,
                    "total_tokens": self._usage["total_tokens"],
                    "cost_usd": round(self._cost_usd, 12),
                    "chief_leads_completed": self._chief_leads_completed,
                }
            )

    def record_call(
        self,
        role: str,
        model: str,
        usage: Dict[str, int],
    ) -> None:
        if not self.enabled:
            return
        normalized = normalize_usage(usage)
        call_cost = float(
            estimate_usage_cost(
                self.requested_model,
                [{"model": model, "usage": normalized}],
            )["total_cost_usd"]
        )
        with self._lock:
            self._calls += 1
            self._usage = add_usage(self._usage, normalized)
            self._cost_usd += call_cost
            self._role_call_counts[role] = (
                self._role_call_counts.get(role, 0) + 1
            )
            self._record_thresholds_locked()

    def expansion_stop_reason(self) -> Optional[str]:
        with self._lock:
            return self._threshold_reason_locked("hard") or (
                self._threshold_reason_locked("soft")
            )

    def hard_stop_reason(self) -> Optional[str]:
        with self._lock:
            return self._threshold_reason_locked("hard")

    def begin_chief_lead(self, lead: str) -> Optional[str]:
        if not self.enabled:
            return None
        with self._lock:
            reason = self._threshold_reason_locked("hard") or (
                self._threshold_reason_locked("soft")
            )
            if reason is not None:
                return reason
            self._chief_leads_started += 1
            self._active_chief_leads += 1
            self._record_thresholds_locked()
            return None

    def finish_chief_lead(self, lead: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._active_chief_leads = max(
                self._active_chief_leads - 1,
                0,
            )
            self._chief_leads_completed += 1
            self._record_thresholds_locked()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            soft_reason = self._threshold_reason_locked("soft")
            hard_reason = self._threshold_reason_locked("hard")
            return {
                "enabled": self.enabled,
                "api_calls": self._calls,
                "usage": dict(self._usage),
                "estimated_cost_usd": round(self._cost_usd, 12),
                "chief_leads_started": self._chief_leads_started,
                "chief_leads_completed": self._chief_leads_completed,
                "active_chief_leads": self._active_chief_leads,
                "role_call_counts": dict(self._role_call_counts),
                "soft_triggered": soft_reason is not None,
                "hard_triggered": hard_reason is not None,
                "soft_stop_reason": soft_reason,
                "hard_stop_reason": hard_reason,
                "budget_limited": soft_reason is not None,
                "budget_censored": hard_reason is not None,
                "events": list(self._events),
            }


def load_gold(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def select_rows(rows: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.instance_id:
        wanted = set(args.instance_id)
        selected = [row for row in rows if row["instance_id"] in wanted]
        missing = sorted(wanted - {row["instance_id"] for row in selected})
        if missing:
            raise SystemExit(f"Unknown instance_id: {', '.join(missing)}")
        return selected
    if args.run_all:
        return rows
    raise SystemExit("Use --list, --instance-id, or --run-all.")


def process_id_as_int(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def simple_name(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1]


def second_level_domain(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    parts = str(host).strip(".").split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def compact_time(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = str(value)
    if "T" in text:
        text = text.replace("T", " ").replace("Z", "")
    if "." in text:
        head, tail = text.split(".", 1)
        return head
    return text.replace(" UTC", "")


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
    )


def create_adapter_db(source_db: Path, adapter_db: Path) -> Dict[str, int]:
    if adapter_db.exists():
        adapter_db.unlink()
    adapter_db.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(source_db))
    dst = sqlite3.connect(str(adapter_db))
    try:
        adapter_version = "v3_evidence_preserving_parent_context"
        audit_columns = [
            "time",
            "pid",
            "ppid",
            "pname",
            "process_name",
            "access",
            "object",
            "event_record_id",
            "event_id",
            "subject_user_name",
            "access_mask",
            "access_list",
            "source_stream",
            "source_object_type",
            "command_line",
            "hashes",
            "parent_process_name",
            "parent_process_path",
            "parent_command_line",
            "process_guid",
            "parent_process_guid",
            "alert_name",
            "alert_reason",
            "alert_category",
            "raw_event_type",
            "filemod_name",
            "regmod_name",
            "modload_name",
            "childproc_name",
            "netconn_domain",
            "remote_ip",
            "remote_port",
            "original_table",
            "source_row_id",
            "adapter_version",
        ]

        def insert_audit(**values: Any) -> None:
            row = {column: None for column in audit_columns}
            row.update(values)
            row["adapter_version"] = adapter_version
            placeholders = ", ".join("?" for _ in audit_columns)
            dst.execute(
                f"INSERT INTO audit_logs ({', '.join(audit_columns)}) VALUES ({placeholders})",
                tuple(row[column] for column in audit_columns),
            )

        dst.executescript(
            """
            CREATE TABLE audit_logs (
                time TEXT,
                pid INTEGER,
                ppid INTEGER,
                pname TEXT,
                process_name TEXT,
                access TEXT,
                object TEXT,
                event_record_id INTEGER,
                event_id INTEGER,
                subject_user_name TEXT,
                access_mask TEXT,
                access_list TEXT,
                source_stream TEXT,
                source_object_type TEXT,
                command_line TEXT,
                hashes TEXT,
                parent_process_name TEXT,
                parent_process_path TEXT,
                parent_command_line TEXT,
                process_guid TEXT,
                parent_process_guid TEXT,
                alert_name TEXT,
                alert_reason TEXT,
                alert_category TEXT,
                raw_event_type TEXT,
                filemod_name TEXT,
                regmod_name TEXT,
                modload_name TEXT,
                childproc_name TEXT,
                netconn_domain TEXT,
                remote_ip TEXT,
                remote_port TEXT,
                original_table TEXT,
                source_row_id TEXT,
                adapter_version TEXT
            );
            CREATE TABLE dns_requests (
                time TEXT,
                domain TEXT,
                sld TEXT,
                response TEXT,
                query_type TEXT,
                is_response INTEGER
            );
            CREATE TABLE browser_history (
                time TEXT,
                host TEXT,
                sld TEXT,
                method TEXT,
                headers TEXT,
                url TEXT,
                status_code INTEGER
            );
            """
        )
        audit_rows = src.execute(
            """
            SELECT timestamp_utc, process_id, process_name, action, object_name,
                   event_record_id, event_id, subject_user_name, access_mask, access_list
            FROM audit_logs
            """
        )
        audit_count = 0
        for row in audit_rows:
            ts, pid_raw, process_name, action, obj, event_record_id, event_id, user, mask, access_list = row
            insert_audit(
                time=compact_time(ts),
                pid=process_id_as_int(pid_raw),
                ppid=None,
                pname=simple_name(process_name),
                process_name=process_name,
                access=action,
                object=obj,
                event_record_id=event_record_id,
                event_id=event_id,
                subject_user_name=user,
                access_mask=mask,
                access_list=access_list,
                source_stream="msft-security",
                original_table="audit_logs",
                source_row_id=str(event_record_id) if event_record_id is not None else None,
            )
            audit_count += 1

        sysmon_count = 0
        if table_exists(src, "sysmon_logs"):
            sysmon_rows = src.execute(
                """
                SELECT timestamp_utc, process_id, parent_process_id, image, action, object_name,
                       event_record_id, event_id, user, object_type, command_line, hashes,
                       process_guid, parent_process_guid, parent_image, parent_command_line,
                       target_filename, destination_ip, destination_port, query_name
                FROM sysmon_logs
                """
            )
            for row in sysmon_rows:
                (
                    ts,
                    pid_raw,
                    ppid_raw,
                    image,
                    action,
                    obj,
                    event_record_id,
                    event_id,
                    user,
                    object_type,
                    command_line,
                    hashes,
                    process_guid,
                    parent_process_guid,
                    parent_image,
                    parent_command_line,
                    target_filename,
                    destination_ip,
                    destination_port,
                    query_name,
                ) = row
                object_parts = [
                    obj,
                    f"target_filename={target_filename}" if target_filename else None,
                    f"destination_ip={destination_ip}" if destination_ip else None,
                    f"destination_port={destination_port}" if destination_port else None,
                    f"query_name={query_name}" if query_name else None,
                ]
                insert_audit(
                    time=compact_time(ts),
                    pid=process_id_as_int(pid_raw),
                    ppid=process_id_as_int(ppid_raw),
                    pname=simple_name(image),
                    process_name=image,
                    access=action,
                    object=" | ".join(str(part) for part in object_parts if part),
                    event_record_id=event_record_id,
                    event_id=event_id,
                    subject_user_name=user,
                    source_stream="sysmon",
                    source_object_type=object_type,
                    command_line=command_line,
                    hashes=hashes,
                    parent_process_name=simple_name(parent_image),
                    parent_process_path=parent_image,
                    parent_command_line=parent_command_line,
                    process_guid=process_guid,
                    parent_process_guid=parent_process_guid,
                    filemod_name=target_filename,
                    netconn_domain=query_name,
                    remote_ip=destination_ip,
                    remote_port=str(destination_port) if destination_port is not None else None,
                    original_table="sysmon_logs",
                    source_row_id=str(event_record_id) if event_record_id is not None else None,
                )
                audit_count += 1
                sysmon_count += 1

        cbc_event_count = 0
        if table_exists(src, "cbc_events"):
            cbc_rows = src.execute(
                """
                SELECT timestamp_utc, process_pid, parent_pid, process_path, action, object_name,
                       id, process_username, object_type, process_cmdline, stream_name,
                       parent_path, parent_cmdline, type, filemod_name, regmod_name,
                       modload_name, childproc_name, netconn_domain, remote_ip, remote_port
                FROM cbc_events
                """
            )
            for row in cbc_rows:
                (
                    ts,
                    pid,
                    ppid,
                    process_path,
                    action,
                    obj,
                    event_id,
                    user,
                    object_type,
                    cmdline,
                    stream_name,
                    parent_path,
                    parent_cmdline,
                    event_type,
                    filemod_name,
                    regmod_name,
                    modload_name,
                    childproc_name,
                    netconn_domain,
                    remote_ip,
                    remote_port,
                ) = row
                object_parts = [
                    obj,
                    f"event_type={event_type}" if event_type else None,
                    f"parent_path={parent_path}" if parent_path else None,
                    f"parent_cmdline={parent_cmdline}" if parent_cmdline else None,
                    f"filemod_name={filemod_name}" if filemod_name else None,
                    f"regmod_name={regmod_name}" if regmod_name else None,
                    f"modload_name={modload_name}" if modload_name else None,
                    f"childproc_name={childproc_name}" if childproc_name else None,
                    f"netconn_domain={netconn_domain}" if netconn_domain else None,
                    f"remote_ip={remote_ip}" if remote_ip else None,
                    f"remote_port={remote_port}" if remote_port else None,
                ]
                insert_audit(
                    time=compact_time(ts),
                    pid=process_id_as_int(str(pid)) if pid is not None else None,
                    ppid=process_id_as_int(str(ppid)) if ppid is not None else None,
                    pname=simple_name(process_path),
                    process_name=process_path,
                    access=action,
                    object=" | ".join(str(part) for part in object_parts if part),
                    event_record_id=None,
                    event_id=None,
                    subject_user_name=user,
                    source_stream=stream_name,
                    source_object_type=object_type,
                    command_line=cmdline,
                    parent_process_name=simple_name(parent_path),
                    parent_process_path=parent_path,
                    parent_command_line=parent_cmdline,
                    raw_event_type=event_type,
                    filemod_name=filemod_name,
                    regmod_name=regmod_name,
                    modload_name=modload_name,
                    childproc_name=childproc_name,
                    netconn_domain=netconn_domain,
                    remote_ip=remote_ip,
                    remote_port=str(remote_port) if remote_port is not None else None,
                    original_table="cbc_events",
                    source_row_id=str(event_id) if event_id is not None else None,
                )
                audit_count += 1
                cbc_event_count += 1

        cbc_alert_count = 0
        if table_exists(src, "cbc_alerts"):
            alert_rows = src.execute(
                """
                SELECT create_time_utc, process_pid, parent_pid, process_path, reason,
                       alert_id, severity, process_name, threat_cause_actor_name,
                       process_cmdline, stream_name, parent_path, parent_cmdline,
                       report_name, reason_code, category
                FROM cbc_alerts
                """
            )
            for row in alert_rows:
                (
                    ts,
                    pid,
                    ppid,
                    process_path,
                    reason,
                    alert_id,
                    severity,
                    process_name,
                    actor,
                    cmdline,
                    stream_name,
                    parent_path,
                    parent_cmdline,
                    report_name,
                    reason_code,
                    category,
                ) = row
                object_parts = [
                    reason,
                    f"report_name={report_name}" if report_name else None,
                    f"reason_code={reason_code}" if reason_code else None,
                    f"category={category}" if category else None,
                    f"parent_path={parent_path}" if parent_path else None,
                    f"parent_cmdline={parent_cmdline}" if parent_cmdline else None,
                ]
                insert_audit(
                    time=compact_time(ts),
                    pid=process_id_as_int(str(pid)) if pid is not None else None,
                    ppid=process_id_as_int(str(ppid)) if ppid is not None else None,
                    pname=simple_name(process_path) or process_name or actor,
                    process_name=process_path or process_name or actor,
                    access="cbc_alert",
                    object=" | ".join(str(part) for part in object_parts if part),
                    event_record_id=None,
                    event_id=severity,
                    subject_user_name=actor,
                    source_stream=stream_name,
                    source_object_type="Alert",
                    command_line=cmdline,
                    hashes=alert_id,
                    parent_process_name=simple_name(parent_path),
                    parent_process_path=parent_path,
                    parent_command_line=parent_cmdline,
                    alert_name=report_name,
                    alert_reason=reason,
                    alert_category=category,
                    raw_event_type=reason_code,
                    original_table="cbc_alerts",
                    source_row_id=str(alert_id) if alert_id is not None else None,
                )
                audit_count += 1
                cbc_alert_count += 1

        dns_count = 0
        if table_exists(src, "dns_logs"):
            for ts, query_name, query_type, is_response, answer in src.execute(
                "SELECT timestamp_utc, query_name, query_type, is_response, answer_summary FROM dns_logs"
            ):
                dst.execute(
                    "INSERT INTO dns_requests VALUES (?, ?, ?, ?, ?, ?)",
                    (compact_time(ts), query_name, second_level_domain(query_name), answer, query_type, is_response),
                )
                dns_count += 1

        browser_count = 0
        if table_exists(src, "browser_logs"):
            for ts, host, url, method, status_code, raw_line in src.execute(
                "SELECT timestamp_utc, host, url, method, status_code, raw_line FROM browser_logs"
            ):
                dst.execute(
                    "INSERT INTO browser_history VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (compact_time(ts), host, second_level_domain(host), method, raw_line, url, status_code),
                )
                browser_count += 1

        dst.executescript(
            """
            CREATE INDEX idx_audit_time ON audit_logs(time);
            CREATE INDEX idx_audit_process ON audit_logs(process_name);
            CREATE INDEX idx_audit_pname ON audit_logs(pname);
            CREATE INDEX idx_audit_pid ON audit_logs(pid);
            CREATE INDEX idx_audit_ppid ON audit_logs(ppid);
            CREATE INDEX idx_audit_object ON audit_logs(object);
            CREATE INDEX idx_audit_event_record ON audit_logs(event_record_id);
            CREATE INDEX idx_audit_source_stream ON audit_logs(source_stream);
            CREATE INDEX idx_audit_access ON audit_logs(access);
            CREATE INDEX idx_audit_parent_path ON audit_logs(parent_process_path);
            CREATE INDEX idx_audit_parent_cmdline ON audit_logs(parent_command_line);
            CREATE INDEX idx_audit_process_guid ON audit_logs(process_guid);
            CREATE INDEX idx_audit_alert_name ON audit_logs(alert_name);
            CREATE INDEX idx_dns_time ON dns_requests(time);
            CREATE INDEX idx_dns_domain ON dns_requests(domain);
            CREATE INDEX idx_browser_time ON browser_history(time);
            CREATE INDEX idx_browser_host ON browser_history(host);
            """
        )
        dst.commit()
        return {
            "audit_logs": audit_count,
            "sysmon_audit_rows": sysmon_count,
            "cbc_event_audit_rows": cbc_event_count,
            "cbc_alert_audit_rows": cbc_alert_count,
            "dns_requests": dns_count,
            "browser_history": browser_count,
            "adapter_version": adapter_version,
        }
    finally:
        src.close()
        dst.close()


def build_clue(row: Dict[str, Any], difficulty: str) -> str:
    anchor = row["anchor_event"]
    db_time = compact_time(anchor.get("timestamp_utc"))
    if difficulty == "exact":
        return (
            "Normal behavior reconstruction task. "
            f"Investigate whether this anchor log represents {row['expected_behavior']} rather than malicious activity. "
            f"Anchor: event_record_id={anchor.get('event_record_id')}, database_time='{db_time}', original_time={anchor.get('timestamp_utc')}, "
            f"process={anchor.get('process_name')}, object={row['poi']}, action={anchor.get('action')}. "
            "When querying SQLite time columns, use the database_time format, not the original_time format. "
            "Use the available Security, Sysmon, CBC EDR/NGAV, browser, and DNS logs to find concrete supporting or contradicting evidence. "
            "Report actor, object, operation, context label, supporting logs, and unexplored evidence."
        )
    if difficulty == "actor_time":
        return (
            "Normal behavior reconstruction task. "
            f"Investigate {row['actor']} activity near database_time '{db_time}' in this ATLASv2 scenario. "
            "When querying SQLite time columns, use this database_time format. "
            "Decide what normal or attack-adjacent benign behavior is represented. "
            "Use Security, Sysmon, CBC EDR/NGAV, browser, and DNS logs; report concrete supporting rows."
        )
    if difficulty == "behavior_time":
        return (
            "Normal behavior reconstruction task. "
            f"Find evidence of {row['expected_behavior']} near database_time '{db_time}' in this ATLASv2 scenario. "
            "When querying SQLite time columns, use this database_time format. "
            "Identify the actor, object, operation, context label, supporting logs, and missing evidence."
        )
    return (
        "Normal behavior reconstruction task. "
        f"Search the full scenario logs for {row['expected_behavior']}. "
        "Do not assume a malicious incident. Identify the best-supported actor, object, operation, context label, "
        "supporting logs, and any evidence that remains unexplored."
    )


def patch_official_prompts(prompts: Any, constants: Any) -> None:
    constants.DEFAULT_INVESTIGATION_MIN = 0
    prompts.chief_inspector_agent = """You are a cybersecurity expert using CLOUSEAU's hierarchical investigation pipeline on one ATLASv2 host scenario.
Your goal is normal behavior reconstruction, not default attack hunting. You receive a starting clue and can dispatch investigators that query the full SQLite log database.

Instructions:
* Use investigators to query the available Security, Sysmon, CBC EDR/NGAV, browser, and DNS logs.
* Focus on reconstructing the behavior represented by the clue: actor, object, operation, context label, and evidence.
* Distinguish normal behavior from attack-adjacent context. Do not call an actor malicious unless concrete logs support it.
* Increase specificity by asking for exact rows, timestamps, event_record_id values, process names, object paths, and nearby context.
* SQLite time columns use 'YYYY-MM-DD HH:MM:SS'. If the clue contains original_time with T/Z/fractions, convert it before querying.
* You may conduct at most {max_investigations} investigations.
* Final report format: concise JSON with keys actor, object, operation, normal_behavior_label, context_label, supporting_logs, unexplored_logs, behavior_summary, confidence, limitations.

Environment:
{environment}

Message from SOC:
{initial_message}
"""
    prompts.investigation_agent = """You are an investigator inside CLOUSEAU. You can query the full SQLite log database through tools.
Your task is normal behavior reconstruction, not default attack hunting.

Guidelines:
- Ask precise questions with exact timestamps, process names, event_record_id values, object paths, source_stream values, or behavior labels.
- SQLite time columns use 'YYYY-MM-DD HH:MM:SS'. If the clue contains original_time with T/Z/fractions, convert it before querying.
- Use backward, forward, and correlation analysis.
- Return concrete evidence rows and clearly mark missing evidence.
- Do not infer maliciousness unless supported by logs.
- You may perform up to {max_questions} tool queries.

Information about the environment:
{environment}

Lead:
{initial_message}
"""
    prompts.eval_agent = """Summarize the investigation for evaluation as JSON with keys:
actor, object, operation, normal_behavior_label, context_label, supporting_logs, unexplored_logs, behavior_summary, confidence, limitations.
Preserve concrete timestamps and event_record_id values when present. Do not convert normal behavior into attack artifacts unless the report supports that."""
    prompts.sqlexpert_agent = """You are an SQL expert answering questions by querying a SQLite database.
You MUST use the run_sql_query tool for factual claims about log rows. Do not fabricate rows, columns, process trees, PIDs, event IDs, timestamps, or query results.
Use only the provided schema and columns. If a desired column does not exist, query available columns instead or say it is unavailable.
Break the task into simple SQLite queries. If a query errors, correct it using the schema.
If the tool returns "No results found" or "too many results", report that plainly and refine the query if queries remain.

Schema:
{schema}

Examples:
{examples}

You may perform up to {max_queries} SQL tool queries.
Question: {question}
"""


def model_prices(model: str) -> Dict[str, float]:
    prices = {
        "gpt-5": {"input": 1.25, "cached_input": 0.125, "output": 10.0},
        "gpt-5-mini": {"input": 0.25, "cached_input": 0.025, "output": 2.0},
        "gpt-5-nano": {"input": 0.05, "cached_input": 0.005, "output": 0.4},
        "gpt-4.1": {"input": 2.0, "cached_input": 0.5, "output": 8.0},
        "gpt-4.1-mini": {"input": 0.4, "cached_input": 0.1, "output": 1.6},
        "gpt-4.1-nano": {"input": 0.1, "cached_input": 0.025, "output": 0.4},
        "gpt-5.4-mini": {"input": 0.75, "cached_input": 0.075, "output": 4.5},
        "gpt-5.5": {"input": 5.0, "cached_input": 0.5, "output": 30.0},
        "claude-haiku-4-5": {"input": 1.0, "cached_input": 1.0, "output": 5.0},
        "claude-haiku-4-5-20251001": {"input": 1.0, "cached_input": 1.0, "output": 5.0},
        "claude-sonnet-4-6": {"input": 3.0, "cached_input": 3.0, "output": 15.0},
        "claude-opus-4-8": {"input": 5.0, "cached_input": 5.0, "output": 25.0},
        "claude-fable-5": {"input": 10.0, "cached_input": 10.0, "output": 50.0},
    }
    return prices.get(model, {"input": 0.0, "cached_input": 0.0, "output": 0.0})


def append_cost(
    run_id: str,
    scenario: str,
    model: str,
    usage: Dict[str, int],
    note: str = "official_clouseau_normal_behavior",
    cost_estimate: Optional[Dict[str, Any]] = None,
) -> None:
    prices = model_prices(model)
    cost_logger = ROOT / "scripts" / "log_clouseau_cost.py"
    if not cost_logger.exists():
        return
    cmd = [
        sys.executable,
        str(cost_logger),
        "--run-id",
        run_id,
        "--scenario",
        scenario,
        "--model",
        model,
        "--input-tokens",
        str(usage.get("input_tokens", 0)),
        "--output-tokens",
        str(usage.get("output_tokens", 0)),
        "--cached-input-tokens",
        str(usage.get("cached_input_tokens", 0)),
        "--input-price-per-1m",
        str(prices["input"]),
        "--output-price-per-1m",
        str(prices["output"]),
        "--cached-input-price-per-1m",
        str(prices["cached_input"]),
        "--note",
        note,
    ]
    if cost_estimate:
        cmd.extend(
            [
                "--calculated-input-cost-usd",
                str(cost_estimate["input_cost_usd"]),
                "--calculated-output-cost-usd",
                str(cost_estimate["output_cost_usd"]),
                "--calculated-cached-input-cost-usd",
                str(cost_estimate["cached_input_cost_usd"]),
            ]
        )
    subprocess.run(cmd, check=True, cwd=ROOT)


def run_official(row: Dict[str, Any], args: argparse.Namespace) -> Path:
    run_started_at = datetime.now(timezone.utc)
    run_started_monotonic = time.monotonic()
    if getattr(args, "unbounded_agent_calls", False):
        # Keep the persisted configuration semantically accurate.  The
        # external agents use the explicit unbounded flag and treat these
        # call-count ceilings as absent.
        args.max_investigations = None
        args.max_questions = None
        args.max_queries = None

    if str(OFFICIAL_ARTIFACT) not in sys.path:
        sys.path.insert(0, str(OFFICIAL_ARTIFACT))
    from chief_inspector import Clouseau
    from prompts_manager import get_prompt_chief_inspector
    from langchain_core.messages import HumanMessage
    import constants
    import prompts

    env = load_env_file(ENV_PATH)
    provider_hint = env.get("CLOUSEAU_LLM_PROVIDER") or env.get("CLOUSEAU_PROVIDER")
    model = args.model or default_model_for_provider(provider_hint, env)
    provider = infer_llm_provider(model, env)
    api_key = api_key_for_provider(provider, env)
    if not api_key and not args.dry_run:
        expected = "ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY/API_KEY"
        raise RuntimeError(f"{expected} is empty.")

    stamp = run_started_at.strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}_{row['instance_id']}_{model}_official"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    source_db = ROOT / row["database"]
    adapter_db = run_dir / "scenario.db"
    counts = create_adapter_db(source_db, adapter_db)
    clue = build_clue(row, args.difficulty)

    result: Dict[str, Any] = {
        "run_id": run_id,
        "started_at_utc": run_started_at.isoformat(),
        "pipeline": "external/Clouseau/artifact official chief_inspector.investigate_atlas",
        "llm_provider": provider,
        "model": model,
        "instance_id": row["instance_id"],
        "gold_reference": row,
        "source_db": str(source_db),
        "adapter_db": str(adapter_db),
        "adapter_counts": counts,
        "clue": clue,
        "dry_run": args.dry_run,
        "difficulty": args.difficulty,
        "reasoning_effort": args.reasoning_effort,
        "experiment_stage": getattr(args, "experiment_stage", args.difficulty),
        "expected_input_fields": getattr(args, "expected_input_fields", None),
        "configs": {
            "max_investigations": args.max_investigations,
            "max_questions": args.max_questions,
            "max_queries": args.max_queries,
            "max_tokens": args.max_tokens,
            "reasoning_effort": args.reasoning_effort,
            "llm_execution_guard": {
                "max_completion_tokens": args.max_tokens,
                "request_timeout_seconds": float(
                    os.getenv(
                        "CLOUSEAU_LLM_REQUEST_TIMEOUT_SECONDS",
                        "1200",
                    )
                ),
                "hard_wall_timeout_seconds": float(
                    os.getenv(
                        "CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS",
                        "1200",
                    )
                ),
                "hard_wall_enforcement": (
                    "external_active_call_watchdog_v1"
                    if os.getenv("CLOUSEAU_LLM_ACTIVE_CALL_STATE_FILE")
                    else "not_configured"
                ),
                "max_retries": 0,
            },
            "agent_call_limit_policy": (
                "unbounded_by_experiment"
                if getattr(args, "unbounded_agent_calls", False)
                else "bounded"
            ),
            "frontier_closure_policy": getattr(
                args,
                "frontier_closure_policy",
                None,
            ),
            "sql_execution_guard": {
                "timeout_seconds": int(
                    os.getenv("CLOUSEAU_SQL_TIMEOUT_SECONDS", "1200")
                ),
                "vm_step_limit": int(
                    os.getenv("CLOUSEAU_SQL_VM_STEP_LIMIT", "50000000")
                ),
                "result_row_limit": int(
                    os.getenv("CLOUSEAU_SQL_RESULT_ROW_LIMIT", "30")
                ),
                "recursive_union_all_policy": "rejected",
                "query_only": True,
            },
            "process_tree_guard": {
                "cycle_or_pid_reuse_detection": True,
                "pid_plus_observed_time_instance_resolution": True,
                "monotonic_child_time_required": True,
                "max_depth": int(
                    os.getenv("CLOUSEAU_PROCESS_TREE_MAX_DEPTH", "64")
                ),
                "max_nodes": int(
                    os.getenv("CLOUSEAU_PROCESS_TREE_MAX_NODES", "500")
                ),
                "max_parent_child_edge_seconds": int(
                    os.getenv("CLOUSEAU_PROCESS_TREE_MAX_EDGE_SECONDS", "900")
                ),
            },
            "run_budget_guard": {
                "enabled": os.getenv(
                    "CLOUSEAU_RUN_BUDGET_GUARD_ENABLED",
                    "0",
                ).strip().lower() in {"1", "true", "yes", "on"},
                "soft_api_calls": int(
                    os.getenv("CLOUSEAU_RUN_BUDGET_SOFT_API_CALLS", "350")
                ),
                "hard_api_calls": int(
                    os.getenv("CLOUSEAU_RUN_BUDGET_HARD_API_CALLS", "400")
                ),
                "soft_total_tokens": int(
                    os.getenv(
                        "CLOUSEAU_RUN_BUDGET_SOFT_TOTAL_TOKENS",
                        "1600000",
                    )
                ),
                "hard_total_tokens": int(
                    os.getenv(
                        "CLOUSEAU_RUN_BUDGET_HARD_TOTAL_TOKENS",
                        "2000000",
                    )
                ),
                "soft_cost_usd": float(
                    os.getenv("CLOUSEAU_RUN_BUDGET_SOFT_COST_USD", "6")
                ),
                "hard_cost_usd": float(
                    os.getenv("CLOUSEAU_RUN_BUDGET_HARD_COST_USD", "8")
                ),
                "soft_chief_leads": int(
                    os.getenv("CLOUSEAU_RUN_BUDGET_SOFT_CHIEF_LEADS", "20")
                ),
                "hard_chief_leads": int(
                    os.getenv("CLOUSEAU_RUN_BUDGET_HARD_CHIEF_LEADS", "24")
                ),
                "on_soft_trigger": (
                    "stop_new_expansion_and_finalize_with_unresolved_frontier"
                ),
                "on_hard_trigger": (
                    "stop_new_model_calls_and_mark_budget_censored"
                ),
                "formal_scoring_policy": (
                    "exclude_budget_censored_run_until_separate_review"
                ),
            },
            "lead_expansion_guard": {
                "enabled": True,
                "max_investigator_questions_per_lead": int(
                    os.getenv(
                        "CLOUSEAU_MAX_INVESTIGATOR_QUESTIONS_PER_LEAD",
                        "20",
                    )
                ),
                "max_sql_tool_calls_per_question": int(
                    os.getenv(
                        "CLOUSEAU_MAX_SQL_TOOL_CALLS_PER_QUESTION",
                        "12",
                    )
                ),
                "max_sql_tool_calls_per_lead": int(
                    os.getenv(
                        "CLOUSEAU_MAX_SQL_TOOL_CALLS_PER_LEAD",
                        "80",
                    )
                ),
                "max_wall_seconds_per_lead": float(
                    os.getenv(
                        "CLOUSEAU_MAX_WALL_SECONDS_PER_LEAD",
                        "1200",
                    )
                ),
                "on_trigger": (
                    "summarize_collected_evidence_and_return_unresolved_"
                    "frontier_to_chief"
                ),
            },
            "empty_tool_result_guard": {
                "enabled": True,
                "max_consecutive_empty_results_per_lead": int(
                    os.getenv(
                        "CLOUSEAU_MAX_CONSECUTIVE_EMPTY_TOOL_RESULTS",
                        "2",
                    )
                ),
                "on_first_empty": "retry_same_bounded_question_once",
                "on_limit": "fail_run_closed",
            },
            "tool_validation_recovery": {
                "enabled": True,
                "scope": "pydantic_tool_argument_validation_only",
                "action": "return_tool_message_and_reprompt_same_agent",
                "valid_tool_call_limits_affected": False,
                "execution_exceptions_recovered": False,
            },
            "behavior_key_guard": {
                "enabled": bool(
                    getattr(args, "behavior_key_guard_enabled", False)
                ),
                "key_schema": "subject|operation|object",
                "policy": "semantic_fingerprint_atomic_guard_v15",
                "evidence_anchor_required": True,
                "allowed_evidence_anchors": list(
                    getattr(
                        args,
                        "behavior_key_guard_allowed_evidence_anchors",
                        [],
                    )
                ),
                "concrete_subject_object_required_for": [
                    "new_step",
                    "order_resolution",
                ],
                "component_only_operations_rejected": True,
                "component_only_subject_object_labels_rejected": True,
                "process_start_semantic_fingerprint_deduplication": True,
                "temporal_behavior_key_qualifiers_rejected": True,
                "component_relation_terms_rejected": True,
                "explicit_placeholder_values_rejected": True,
                "explicit_placeholder_rejection_scope": "all_materialities",
                "materiality_values": [
                    "new_step",
                    "order_resolution",
                    "missing_component",
                ],
            },
        },
    }
    if not args.dry_run:
        patch_official_prompts(prompts, constants)
        prompts.atlas_env_context = row.get("environment_context") or (
            "You are analyzing ATLASv2 Windows host logs adapted for CLOUSEAU. "
            "The SQLite database contains full scenario tables named audit_logs, browser_history, and dns_requests. "
            "ATLASv2 Sysmon and CBC EDR/NGAV rows are normalized into audit_logs. "
            "Use source_stream values such as 'msft-security', 'sysmon', 'cbc-edr', 'cbc-ngav', 'cbc-edr-alerts', and 'cbc-ngav-alerts' to distinguish evidence sources. "
            "CBC alert rows use access='cbc_alert' and object=alert reason; CBC event rows preserve action/object, command_line, process tree fields, and source_object_type. "
            "The adapter database contains every row from the selected ATLASv2 scenario/host incident.db, not only the clue window. "
            "This task is normal behavior reconstruction, not default attack hunting. "
            "Attack-adjacent context may exist, but do not call an actor malicious unless the logs support it."
        )
        active_call_state_file = os.getenv(
            "CLOUSEAU_LLM_ACTIVE_CALL_STATE_FILE"
        )
        hard_wall_timeout_seconds = float(
            os.getenv("CLOUSEAU_LLM_HARD_WALL_TIMEOUT_SECONDS", "1200")
        )
        full_pipeline_usage = PipelineUsageCallbackHandler(
            active_call_state_path=(
                Path(active_call_state_file)
                if active_call_state_file
                else None
            ),
            hard_wall_timeout_seconds=hard_wall_timeout_seconds,
        )
        run_budget_state = RunBudgetGuard(
            model,
            result["configs"]["run_budget_guard"],
        )
        role_usage_handlers = {
            role: PipelineUsageCallbackHandler(
                budget_state=run_budget_state,
                budget_role=role,
            )
            for role in ("chief", "investigator", "sql_qa")
        }
        live_activity_ledger_file = os.getenv(
            "CLOUSEAU_ACTIVITY_LEDGER_FILE"
        )
        activity_tracker = InvestigationActivityTracker(
            live_ledger_path=(
                Path(live_activity_ledger_file)
                if live_activity_ledger_file
                else None
            )
        )
        llm = build_chat_model(
            provider,
            model,
            api_key,
            args.max_tokens,
            args.reasoning_effort,
            callbacks=[full_pipeline_usage],
        )
        configs = {
            "data_path": str(run_dir),
            "db_name": str(adapter_db),
            "clue": clue,
            "test_name": row["instance_id"],
            "max_investigations": args.max_investigations,
            "max_questions": args.max_questions,
            "max_queries": args.max_queries,
            "max_tokens": args.max_tokens,
            "unbounded_agent_calls": getattr(args, "unbounded_agent_calls", False),
            "runtime_recursion_limit": (
                2_147_483_647
                if getattr(args, "unbounded_agent_calls", False)
                else 125
            ),
            "frontier_closure_review_prompt": getattr(
                args,
                "frontier_closure_review_prompt",
                None,
            ),
            "lead_expansion_guard": result["configs"][
                "lead_expansion_guard"
            ].copy(),
            "empty_tool_result_guard": result["configs"][
                "empty_tool_result_guard"
            ].copy(),
            "tool_validation_recovery": result["configs"][
                "tool_validation_recovery"
            ].copy(),
            "behavior_key_guard": result["configs"][
                "behavior_key_guard"
            ].copy(),
            "run_budget_guard": result["configs"][
                "run_budget_guard"
            ].copy(),
            # Runtime-only callback objects. They are intentionally excluded
            # from the persisted public configs above.
            "_usage_callback_handlers": role_usage_handlers,
            "_activity_tracker": activity_tracker,
            "_run_budget_guard_state": run_budget_state,
        }
        serialized: List[Dict[str, Any]] = []
        try:
            configs["environment"] = prompts.atlas_env_context
            configs["is_darpa"] = False
            chief_prompt = HumanMessage(
                content=get_prompt_chief_inspector(
                    configs["environment"],
                    configs["max_investigations"],
                    configs["clue"],
                )
            )
            agent = Clouseau(llm, configs)
            response = agent.graph.invoke(
                {"messages": chief_prompt},
                config={"recursion_limit": configs["runtime_recursion_limit"]},
            )
            nonempty_contents = []
            for message in response.get("messages", []):
                content = getattr(message, "content", "")
                tool_calls = getattr(message, "tool_calls", None)
                usage_metadata = getattr(message, "usage_metadata", None)
                item = {
                    "type": type(message).__name__,
                    "content": content,
                }
                if usage_metadata:
                    item["usage_metadata"] = dict(usage_metadata)
                if tool_calls:
                    item["tool_calls"] = tool_calls
                if getattr(message, "name", None):
                    item["name"] = getattr(message, "name")
                serialized.append(item)
                if isinstance(content, str) and content.strip():
                    nonempty_contents.append(content)
            result["official_messages"] = serialized
            result["output_text"] = nonempty_contents[-1] if nonempty_contents else ""
        except Exception as exc:
            result["error"] = {"type": type(exc).__name__, "message": str(exc)}

        result["investigation_activity"] = activity_tracker.snapshot()
        result["lead_expansion_guard"] = {
            "config": result["configs"]["lead_expansion_guard"],
            "records": configs.get(
                "_lead_expansion_guard_records",
                [],
            ),
            "trigger_count": sum(
                1
                for record in configs.get(
                    "_lead_expansion_guard_records",
                    [],
                )
                if record.get("triggered")
            ),
        }
        result["empty_tool_result_guard"] = {
            "config": result["configs"]["empty_tool_result_guard"],
            "records": configs.get("_empty_tool_result_guard_records", []),
            "trigger_count": len(
                configs.get("_empty_tool_result_guard_records", [])
            ),
            "fail_closed_count": sum(
                1
                for record in configs.get(
                    "_empty_tool_result_guard_records",
                    [],
                )
                if record.get("action") == "fail_run"
            ),
        }
        result["tool_validation_recovery"] = {
            "config": result["configs"]["tool_validation_recovery"],
            "records": configs.get("_tool_validation_recovery_records", []),
            "recovered_count": len(
                configs.get("_tool_validation_recovery_records", [])
            ),
        }
        result["behavior_key_guard"] = {
            "config": result["configs"]["behavior_key_guard"],
            "records": configs.get("_behavior_key_guard_records", []),
            "accepted_key_count": sum(
                1
                for record in configs.get(
                    "_behavior_key_guard_records",
                    [],
                )
                if record.get("status") == "accepted"
            ),
            "rejected_key_count": sum(
                1
                for record in configs.get(
                    "_behavior_key_guard_records",
                    [],
                )
                if str(record.get("status") or "").startswith("rejected_")
            ),
        }
        result["run_budget_guard"] = {
            "config": result["configs"]["run_budget_guard"],
            **run_budget_state.snapshot(),
        }
        callback_usage = usage_from_callback(full_pipeline_usage)
        role_usage = {
            role: usage_from_callback(handler)
            for role, handler in role_usage_handlers.items()
        }
        role_total = add_usage(
            *[role_payload["total"] for role_payload in role_usage.values()]
        )
        call_ledger_total = add_usage(
            *[
                call["usage"]
                for call in callback_usage["calls"]
            ]
        )
        legacy_parent_usage = usage_from_serialized_messages(serialized)
        callback_aggregate_total = callback_usage["total"]
        full_total = (
            call_ledger_total
            if callback_usage["calls"]
            else callback_aggregate_total
        )
        usage_source = (
            "per_call_ledger"
            if callback_usage["calls"]
            else "callback_aggregate"
        )
        fallback = None
        if not full_total["total_tokens"]:
            if role_total["total_tokens"]:
                full_total = role_total
                fallback = "sum_of_role_callbacks"
                usage_source = fallback
            elif legacy_parent_usage["total_tokens"]:
                full_total = legacy_parent_usage
                fallback = "legacy_parent_graph_messages"
                usage_source = fallback

        result["usage"] = full_total
        result["usage_scope"] = "full_pipeline_callback_v1"
        result["usage_breakdown"] = {
            "chief": role_usage["chief"]["total"],
            "investigator": role_usage["investigator"]["total"],
            "sql_qa": role_usage["sql_qa"]["total"],
            "role_call_counts": {
                role: len(payload["calls"])
                for role, payload in role_usage.items()
            },
            "role_llm_duration_seconds": {
                role: round(
                    sum(
                        float(call.get("duration_seconds") or 0.0)
                        for call in payload["calls"]
                    ),
                    3,
                )
                for role, payload in role_usage.items()
            },
            "role_calls": {
                role: payload["calls"]
                for role, payload in role_usage.items()
            },
            "role_total": role_total,
            "call_ledger_total": call_ledger_total,
            "unattributed": subtract_usage(full_total, role_total),
            "legacy_parent_graph_messages": legacy_parent_usage,
            "callback_aggregate_total": callback_aggregate_total,
            "full_pipeline_by_model": callback_usage["by_model"],
            "full_pipeline_calls": callback_usage["calls"],
            "full_pipeline_llm_duration_seconds": round(
                sum(
                    float(call.get("duration_seconds") or 0.0)
                    for call in callback_usage["calls"]
                ),
                3,
            ),
            "role_by_model": {
                role: payload["by_model"]
                for role, payload in role_usage.items()
            },
        }
        result["usage_audit"] = {
            "full_pipeline_equals_role_total": full_total == role_total,
            "full_pipeline_equals_call_ledger": (
                full_total == call_ledger_total
            ),
            "callback_aggregate_equals_call_ledger": (
                callback_aggregate_total == call_ledger_total
            ),
            "full_pipeline_gte_legacy_parent": all(
                full_total[key] >= legacy_parent_usage[key]
                for key in full_total
            ),
            "fallback": fallback,
            "usage_source": usage_source,
            "full_pipeline_call_count": len(callback_usage["calls"]),
            "role_call_count": sum(
                len(payload["calls"]) for payload in role_usage.values()
            ),
            "role_call_count_by_role": {
                role: len(payload["calls"])
                for role, payload in role_usage.items()
            },
            "role_timed_call_count_by_role": {
                role: sum(
                    isinstance(call.get("duration_seconds"), (int, float))
                    for call in payload["calls"]
                )
                for role, payload in role_usage.items()
            },
            "full_pipeline_timed_call_count": sum(
                isinstance(call.get("duration_seconds"), (int, float))
                for call in callback_usage["calls"]
            ),
        }
        cost_estimate = estimate_usage_cost(
            model,
            callback_usage["calls"],
            fallback_total=full_total,
        )
        result["cost_estimate"] = cost_estimate

        if args.log_cost and (
            full_total["input_tokens"] or full_total["output_tokens"]
        ):
            try:
                append_cost(
                    run_id,
                    row["scenario"],
                    model,
                    full_total,
                    note="official_clouseau_full_pipeline_callback_v1",
                    cost_estimate=cost_estimate,
                )
            except Exception as exc:
                result["cost_logging_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }

    run_finished_at = datetime.now(timezone.utc)
    result["finished_at_utc"] = run_finished_at.isoformat()
    result["elapsed_seconds"] = round(
        time.monotonic() - run_started_monotonic,
        3,
    )
    out_path = run_dir / "run.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


def main() -> None:
    args = parse_args()
    rows = load_gold(args.gold)
    if args.list:
        for row in rows:
            print(f"{row['instance_id']}: {row['scenario']} {row['actor']} {row['expected_behavior']}")
        return
    outputs = []
    for row in select_rows(rows, args):
        out_path = run_official(row, args)
        outputs.append(out_path)
        print(out_path)
    print(f"Completed {len(outputs)} official CLOUSEAU run(s).")


if __name__ == "__main__":
    main()
