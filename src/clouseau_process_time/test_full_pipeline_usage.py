from __future__ import annotations

import csv
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from langchain_core.language_models.fake_chat_models import (
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage, HumanMessage


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "external" / "Clouseau" / "artifact"
RUNNER_DIR = ROOT / "src" / "clouseau_process_time"
for import_path in (ARTIFACT, RUNNER_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

import constants  # noqa: E402
from chief_inspector import Clouseau, finalize_lead_guard  # noqa: E402
from investigator import InvestigateAgent, guard_empty_tool_result  # noqa: E402
from qa_agent import (  # noqa: E402
    SQLAgent,
    atlas_get_children,
    atlas_get_process_record,
)
from run_clouseau_official_normal_behavior import (  # noqa: E402
    InvestigationActivityTracker,
    PipelineUsageCallbackHandler,
    RunBudgetGuard,
    build_chat_model,
    estimate_usage_cost,
    usage_from_callback,
)
from run_atlasv2_s3_s4_attack8_paired_experiment import (  # noqa: E402
    overdue_active_llm_call,
    overdue_post_llm_idle,
    overdue_total_run,
)


class ToolCapableFakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):  # noqa: ANN001, ANN201
        return self


def usage_message() -> AIMessage:
    return AIMessage(
        content="done",
        response_metadata={"model_name": "fake-model"},
        usage_metadata={
            "input_tokens": 10,
            "output_tokens": 3,
            "total_tokens": 13,
            "input_token_details": {"cache_read": 2},
        },
    )


class FullPipelineUsageTests(unittest.TestCase):
    def test_run_budget_guard_soft_then_hard_call_limits(self) -> None:
        guard = RunBudgetGuard(
            "gpt-5.5",
            {
                "enabled": True,
                "soft_api_calls": 2,
                "hard_api_calls": 3,
                "soft_total_tokens": 1000000,
                "hard_total_tokens": 2000000,
                "soft_cost_usd": 100,
                "hard_cost_usd": 200,
                "soft_chief_leads": 20,
                "hard_chief_leads": 24,
            },
        )
        usage = {
            "input_tokens": 10,
            "output_tokens": 2,
            "cached_input_tokens": 0,
            "total_tokens": 12,
        }

        guard.record_call("chief", "gpt-5.5", usage)
        self.assertIsNone(guard.expansion_stop_reason())
        guard.record_call("investigator", "gpt-5.5", usage)
        self.assertIn("soft limit", guard.expansion_stop_reason())
        self.assertFalse(guard.snapshot()["budget_censored"])
        guard.record_call("sql_qa", "gpt-5.5", usage)
        self.assertIn("hard limit", guard.hard_stop_reason())
        snapshot = guard.snapshot()
        self.assertTrue(snapshot["budget_censored"])
        self.assertEqual(snapshot["role_call_counts"]["sql_qa"], 1)

    def test_run_budget_guard_stops_after_completed_soft_lead_count(self) -> None:
        guard = RunBudgetGuard(
            "gpt-5.5",
            {
                "enabled": True,
                "soft_api_calls": 350,
                "hard_api_calls": 400,
                "soft_total_tokens": 1600000,
                "hard_total_tokens": 2000000,
                "soft_cost_usd": 6,
                "hard_cost_usd": 8,
                "soft_chief_leads": 2,
                "hard_chief_leads": 3,
            },
        )

        self.assertIsNone(guard.begin_chief_lead("lead one"))
        guard.finish_chief_lead("lead one")
        self.assertIsNone(guard.begin_chief_lead("lead two"))
        guard.finish_chief_lead("lead two")
        self.assertIn("Chief lead soft limit", guard.expansion_stop_reason())
        self.assertIn("Chief lead soft limit", guard.begin_chief_lead("lead three"))
        self.assertEqual(guard.snapshot()["chief_leads_completed"], 2)

    def test_empty_tool_result_guard_allows_one_explicit_retry(self) -> None:
        configs = {
            "empty_tool_result_guard": {
                "enabled": True,
                "max_consecutive_empty_results_per_lead": 2,
            },
            "_active_lead_guard": {"lead": "bounded registry edge"},
        }

        result = guard_empty_tool_result(
            configs,
            "ask_audit",
            {"question": "Which registry object?"},
            "",
        )

        self.assertIn("Do not treat this as evidence", result)
        self.assertEqual(
            configs["_active_lead_guard"][
                "consecutive_empty_tool_result_count"
            ],
            1,
        )
        self.assertEqual(
            configs["_empty_tool_result_guard_records"][0]["action"],
            "retry_once",
        )

    def test_empty_tool_result_guard_fails_second_consecutive_empty(self) -> None:
        configs = {
            "empty_tool_result_guard": {
                "enabled": True,
                "max_consecutive_empty_results_per_lead": 2,
            },
            "_active_lead_guard": {"lead": "bounded registry edge"},
        }
        guard_empty_tool_result(
            configs,
            "ask_audit",
            {"question": "Which registry object?"},
            "",
        )

        with self.assertRaisesRegex(RuntimeError, "2 consecutive times"):
            guard_empty_tool_result(
                configs,
                "ask_audit",
                {"question": "Which object and access?"},
                None,
            )
        self.assertEqual(
            configs["_empty_tool_result_guard_records"][-1]["action"],
            "fail_run",
        )

    def test_activity_tracker_persists_completed_events_live(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "activity.jsonl"
            tracker = InvestigationActivityTracker(ledger)
            event = tracker.begin(
                "chief",
                "investigate_lead",
                {"lead": "one material edge"},
            )
            tracker.finish(event, result="resolved")

            rows = [
                json.loads(line)
                for line in ledger.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["event_status"], "started")
            self.assertEqual(rows[1]["event_status"], "completed")
            self.assertEqual(rows[1]["role"], "chief")
            self.assertEqual(rows[1]["tool_name"], "investigate_lead")
            self.assertEqual(rows[1]["outcome"], "success")

    def test_lead_guard_records_final_inflight_wall_crossing(self) -> None:
        guard = {
            "started_monotonic": 100.0,
            "triggered": False,
            "stop_reason": None,
        }
        finalize_lead_guard(
            guard,
            {"max_wall_seconds_per_lead": 1200},
            finished_monotonic=1376.36,
        )
        self.assertTrue(guard["triggered"])
        self.assertEqual(guard["duration_seconds"], 1276.36)
        self.assertIn("1200", guard["stop_reason"])

    def test_openai_model_binds_declared_token_cap_and_request_timeout(self) -> None:
        model = build_chat_model(
            provider="openai",
            model="gpt-5.5",
            api_key="sk-test",
            max_tokens=24576,
        )
        self.assertEqual(model.max_tokens, 24576)
        self.assertEqual(model.request_timeout, 1200.0)
        self.assertEqual(model.max_retries, 0)

    def test_active_call_state_tracks_start_and_error_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "active.json"
            handler = PipelineUsageCallbackHandler(
                active_call_state_path=state_path,
                hard_wall_timeout_seconds=1200,
            )
            initialized = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(initialized["active_call_count"], 0)
            handler.on_chat_model_start(run_id="call-1")
            active = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(active["active_call_count"], 1)
            self.assertEqual(active["active_calls"][0]["run_id"], "call-1")
            handler.on_llm_error(RuntimeError("test"), run_id="call-1")
            finished = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(finished["active_call_count"], 0)

    def test_active_call_state_retries_transient_windows_replace_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "active.json"
            handler = PipelineUsageCallbackHandler(
                active_call_state_path=state_path,
                hard_wall_timeout_seconds=1200,
            )
            real_replace = os.replace
            attempts = 0

            def flaky_replace(source, destination):  # noqa: ANN001, ANN202
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise PermissionError("transient sharing violation")
                return real_replace(source, destination)

            with patch(
                "run_clouseau_official_normal_behavior.os.replace",
                side_effect=flaky_replace,
            ):
                handler.on_chat_model_start(run_id="call-retry")

            payload = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(attempts, 3)
            self.assertEqual(payload["active_call_count"], 1)

    def test_hard_wall_watchdog_detects_total_elapsed_time(self) -> None:
        now = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
        payload = {
            "active_calls": [
                {
                    "run_id": "short",
                    "started_at_utc": (
                        now - timedelta(seconds=1199)
                    ).isoformat(),
                },
                {
                    "run_id": "overdue",
                    "started_at_utc": (
                        now - timedelta(seconds=1201)
                    ).isoformat(),
                },
            ]
        }
        overdue = overdue_active_llm_call(payload, now, 1200)
        self.assertIsNotNone(overdue)
        self.assertEqual(overdue["run_id"], "overdue")
        self.assertEqual(overdue["elapsed_seconds"], 1201.0)

    def test_hard_wall_watchdog_detects_post_llm_no_progress(self) -> None:
        now = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
        payload = {
            "event": "llm_end",
            "updated_at_utc": (
                now - timedelta(seconds=1201)
            ).isoformat(),
            "active_call_count": 0,
            "active_calls": [],
        }
        overdue = overdue_post_llm_idle(payload, now, 1200)
        self.assertIsNotNone(overdue)
        self.assertEqual(overdue["event"], "llm_end")
        self.assertEqual(overdue["elapsed_seconds"], 1201.0)

    def test_post_llm_idle_watchdog_ignores_active_or_recent_state(self) -> None:
        now = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
        active = {
            "event": "llm_start",
            "updated_at_utc": (
                now - timedelta(seconds=1201)
            ).isoformat(),
            "active_call_count": 1,
            "active_calls": [{"run_id": "active"}],
        }
        recent = {
            "event": "llm_end",
            "updated_at_utc": (
                now - timedelta(seconds=1199)
            ).isoformat(),
            "active_call_count": 0,
            "active_calls": [],
        }
        self.assertIsNone(overdue_post_llm_idle(active, now, 1200))
        self.assertIsNone(overdue_post_llm_idle(recent, now, 1200))

    def test_total_run_watchdog_is_opt_in_and_detects_overrun(self) -> None:
        self.assertIsNone(overdue_total_run(100.0, 4000.0, 0))
        self.assertIsNone(overdue_total_run(100.0, 1299.9, 1200))
        overdue = overdue_total_run(100.0, 1300.0, 1200)
        self.assertEqual(
            overdue,
            {"elapsed_seconds": 1200.0, "timeout_seconds": 1200},
        )

    def test_atlas_pid_reuse_requires_observed_time_and_resolves_instance(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(
                "CREATE TABLE audit_logs "
                "(time TEXT, pid INTEGER, ppid INTEGER, pname TEXT, "
                "command_line TEXT, process_guid TEXT, "
                "parent_process_guid TEXT)"
            )
            connection.executemany(
                "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        "2026-01-01 17:45:44",
                        3652,
                        1780,
                        "RepWmiUtils.exe",
                        "RepWmiUtils.exe muuid",
                        "rep-guid",
                        "service-guid",
                    ),
                    (
                        "2026-01-01 20:52:11",
                        3652,
                        1612,
                        "cmd.exe",
                        "cmd.exe /c start_dns_logs.bat",
                        "cmd-guid",
                        "explorer-guid",
                    ),
                ],
            )
            ambiguous = atlas_get_process_record(connection, 3652)
            resolved = atlas_get_process_record(
                connection,
                3652,
                "2026-01-01 20:52:11",
            )
        finally:
            connection.close()

        self.assertIsNone(ambiguous)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[4], "cmd.exe")
        self.assertEqual(resolved[6], "cmd-guid")

    def test_atlas_descendants_exclude_late_pid_reuse_edge(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(
                "CREATE TABLE audit_logs "
                "(time TEXT, pid INTEGER, ppid INTEGER, pname TEXT, "
                "command_line TEXT, process_guid TEXT, "
                "parent_process_guid TEXT)"
            )
            connection.executemany(
                "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        "2026-01-01 20:52:11",
                        3288,
                        2496,
                        "dumpcap.exe",
                        "dumpcap.exe -D",
                        None,
                        None,
                    ),
                    (
                        "2026-01-01 22:39:00",
                        2100,
                        3288,
                        "FlashPlayerUpdateService.exe",
                        "FlashPlayerUpdateService.exe",
                        None,
                        None,
                    ),
                ],
            )
            result = atlas_get_children(
                connection,
                3288,
                "2026-01-01 20:52:11",
            )
        finally:
            connection.close()

        self.assertNotIn("FlashPlayerUpdateService.exe", result)

    def test_atlas_descendant_traversal_stops_on_pid_cycle(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(
                "CREATE TABLE audit_logs "
                "(time TEXT, pid INTEGER, ppid INTEGER, pname TEXT)"
            )
            connection.executemany(
                "INSERT INTO audit_logs VALUES (?, ?, ?, ?)",
                [
                    ("2026-01-01 00:00:00", 1, 0, "root.exe"),
                    ("2026-01-01 00:00:01", 2, 1, "child.exe"),
                    ("2026-01-01 00:00:02", 1, 2, "root-reused.exe"),
                ],
            )
            result = atlas_get_children(
                connection,
                1,
                "2026-01-01 00:00:00",
            )
        finally:
            connection.close()

        self.assertIn("2 - child.exe", result)
        self.assertIn("cycle or reused PID omitted: 1", result)

    def test_activity_tracker_records_leads_questions_sql_and_repetition(self) -> None:
        tracker = InvestigationActivityTracker()
        samples = [
            (
                "chief",
                "investigate_lead",
                {
                    "lead": "follow process A",
                    "behavior_key": "parent.exe|start|child.exe",
                },
                "done",
            ),
            (
                "chief",
                "investigate_lead",
                {
                    "lead": "follow process A",
                    "behavior_key": "child.exe|write|target.txt",
                },
                "done",
            ),
            ("investigator", "ask_audit", {"question": "find A"}, "done"),
            (
                "sql_qa",
                "run_sql_query",
                {"query": "select * from audit_logs"},
                "No results found.",
            ),
        ]
        for role, tool_name, arguments, result in samples:
            event = tracker.begin(role, tool_name, arguments)
            tracker.finish(event, result=result)

        snapshot = tracker.snapshot()
        summary = snapshot["summary"]
        self.assertEqual(summary["lead_call_count"], 2)
        self.assertEqual(summary["unique_lead_count"], 1)
        self.assertEqual(summary["repeated_lead_count"], 1)
        self.assertEqual(summary["unique_behavior_key_count"], 2)
        self.assertEqual(summary["repeated_behavior_key_count"], 0)
        self.assertEqual(summary["investigator_question_count"], 1)
        self.assertEqual(summary["sql_query_count"], 1)
        self.assertEqual(
            summary["outcome_count"]["sql_no_results"],
            1,
        )
        self.assertEqual(len(snapshot["events"]), 4)

    def test_per_lead_question_guard_triggers_at_twenty(self) -> None:
        guard = {
            "started_monotonic": time.monotonic(),
            "investigator_question_count": 20,
            "sql_tool_call_count": 10,
            "triggered": False,
            "stop_reason": None,
        }
        configs = {
            "db_name": "unused.db",
            "is_darpa": False,
            "max_questions": None,
            "max_tokens": 1024,
            "unbounded_agent_calls": True,
            "lead_expansion_guard": {
                "enabled": True,
                "max_investigator_questions_per_lead": 20,
                "max_wall_seconds_per_lead": 1200,
            },
            "_active_lead_guard": guard,
        }
        model = ToolCapableFakeModel(responses=[usage_message()])
        agent = InvestigateAgent(model, configs)

        reason = agent.lead_guard_stop_reason()

        self.assertIn("question safety limit", reason)
        self.assertTrue(guard["triggered"])
        self.assertIn("20", guard["stop_reason"])

    def test_sql_guard_has_per_question_and_per_lead_layers(self) -> None:
        guard = {
            "started_monotonic": time.monotonic(),
            "investigator_question_count": 4,
            "sql_tool_call_count": 80,
            "triggered": False,
            "stop_reason": None,
        }
        configs = {
            "max_queries": None,
            "max_tokens": 1024,
            "unbounded_agent_calls": True,
            "lead_expansion_guard": {
                "enabled": True,
                "max_sql_tool_calls_per_question": 12,
                "max_sql_tool_calls_per_lead": 80,
                "max_wall_seconds_per_lead": 1200,
            },
            "_active_lead_guard": guard,
        }
        model = ToolCapableFakeModel(responses=[usage_message()])
        agent = SQLAgent(model, "unused.db", configs)
        agent.current_iteration = 12

        self.assertTrue(agent.sql_question_limit_reached())
        self.assertIn("SQL tool-call safety limit", agent.lead_guard_stop_reason())
        self.assertTrue(guard["triggered"])

    def test_call_ledger_recovers_usage_when_model_name_is_missing(self) -> None:
        message = AIMessage(
            content="done",
            usage_metadata={
                "input_tokens": 7,
                "output_tokens": 2,
                "total_tokens": 9,
            },
        )
        handler = PipelineUsageCallbackHandler()
        model = ToolCapableFakeModel(
            responses=[message],
            callbacks=[handler],
        )

        model.invoke("test")
        collected = usage_from_callback(handler)

        self.assertEqual(collected["by_model"], {})
        self.assertEqual(collected["calls"][0]["model"], "unknown_model")
        self.assertEqual(
            collected["total"],
            {
                "input_tokens": 7,
                "output_tokens": 2,
                "cached_input_tokens": 0,
                "total_tokens": 9,
            },
        )

    def test_global_and_role_collectors_include_all_three_agent_layers(self) -> None:
        global_handler = PipelineUsageCallbackHandler()
        role_handlers = {
            "chief": PipelineUsageCallbackHandler(),
            "investigator": PipelineUsageCallbackHandler(),
            "sql_qa": PipelineUsageCallbackHandler(),
        }
        model = ToolCapableFakeModel(
            responses=[usage_message(), usage_message(), usage_message()],
            callbacks=[global_handler],
        )
        configs = {
            "db_name": "unused.db",
            "is_darpa": False,
            "max_investigations": None,
            "max_questions": None,
            "max_queries": None,
            "max_tokens": 1024,
            "unbounded_agent_calls": True,
            "frontier_closure_review_prompt": None,
            "_usage_callback_handlers": role_handlers,
        }

        original_minimum = constants.DEFAULT_INVESTIGATION_MIN
        constants.DEFAULT_INVESTIGATION_MIN = 1
        try:
            chief = Clouseau(model, configs)
            chief.current_iteration = 1
            chief.call_model({"messages": [HumanMessage(content="chief")]})

            investigator = InvestigateAgent(model, configs)
            investigator.call_model(
                {"messages": [HumanMessage(content="investigator")]}
            )

            sql_qa = SQLAgent(model, "unused.db", configs)
            sql_qa.call_model({"messages": [HumanMessage(content="sql")]})
        finally:
            constants.DEFAULT_INVESTIGATION_MIN = original_minimum

        global_total = usage_from_callback(global_handler)["total"]
        self.assertEqual(len(usage_from_callback(global_handler)["calls"]), 3)
        self.assertEqual(
            global_total,
            {
                "input_tokens": 30,
                "output_tokens": 9,
                "cached_input_tokens": 6,
                "total_tokens": 39,
            },
        )
        for handler in role_handlers.values():
            self.assertEqual(len(usage_from_callback(handler)["calls"]), 1)
            self.assertEqual(
                usage_from_callback(handler)["total"],
                {
                    "input_tokens": 10,
                    "output_tokens": 3,
                    "cached_input_tokens": 2,
                    "total_tokens": 13,
                },
            )

    def test_gpt55_long_context_pricing_is_applied_per_call(self) -> None:
        estimate = estimate_usage_cost(
            "gpt-5.5",
            [
                {
                    "model": "gpt-5.5-2026-04-23",
                    "usage": {
                        "input_tokens": 300_000,
                        "cached_input_tokens": 100_000,
                        "output_tokens": 10_000,
                        "total_tokens": 310_000,
                    },
                }
            ],
        )

        self.assertEqual(estimate["long_context_call_count"], 1)
        self.assertEqual(estimate["input_cost_usd"], 2.0)
        self.assertEqual(estimate["cached_input_cost_usd"], 0.1)
        self.assertEqual(estimate["output_cost_usd"], 0.45)
        self.assertEqual(estimate["total_cost_usd"], 2.55)

    def test_long_context_threshold_is_not_applied_to_aggregate_run_tokens(self) -> None:
        estimate = estimate_usage_cost(
            "gpt-5.5",
            [
                {
                    "model": "gpt-5.5",
                    "usage": {
                        "input_tokens": 150_000,
                        "cached_input_tokens": 0,
                        "output_tokens": 1_000,
                    },
                },
                {
                    "model": "gpt-5.5",
                    "usage": {
                        "input_tokens": 150_000,
                        "cached_input_tokens": 0,
                        "output_tokens": 1_000,
                    },
                },
            ],
        )

        self.assertEqual(estimate["call_count"], 2)
        self.assertEqual(estimate["long_context_call_count"], 0)
        self.assertEqual(estimate["total_cost_usd"], 1.56)

    def test_cost_logger_does_not_charge_cached_tokens_twice(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "costs.csv"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "log_clouseau_cost.py"),
                    "--csv",
                    str(csv_path),
                    "--run-id",
                    "usage-test",
                    "--input-tokens",
                    "100",
                    "--cached-input-tokens",
                    "40",
                    "--output-tokens",
                    "10",
                    "--input-price-per-1m",
                    "2",
                    "--cached-input-price-per-1m",
                    "0.5",
                    "--output-price-per-1m",
                    "8",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))

        self.assertAlmostEqual(float(row["input_cost_usd"]), 0.00012)
        self.assertAlmostEqual(float(row["cached_input_cost_usd"]), 0.00002)
        self.assertAlmostEqual(float(row["output_cost_usd"]), 0.00008)
        self.assertAlmostEqual(float(row["call_total_usd"]), 0.00022)

    def test_per_call_long_context_estimate_is_preserved_in_cost_log(self) -> None:
        estimate = estimate_usage_cost(
            "gpt-5.5",
            [
                {
                    "model": "gpt-5.5",
                    "usage": {
                        "input_tokens": 300_000,
                        "cached_input_tokens": 100_000,
                        "output_tokens": 10_000,
                    },
                }
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "long-context-cost.csv"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "log_clouseau_cost.py"),
                    "--csv",
                    str(csv_path),
                    "--run-id",
                    "long-context-test",
                    "--input-tokens",
                    "300000",
                    "--cached-input-tokens",
                    "100000",
                    "--output-tokens",
                    "10000",
                    "--calculated-input-cost-usd",
                    str(estimate["input_cost_usd"]),
                    "--calculated-cached-input-cost-usd",
                    str(estimate["cached_input_cost_usd"]),
                    "--calculated-output-cost-usd",
                    str(estimate["output_cost_usd"]),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))

        self.assertAlmostEqual(
            float(row["call_total_usd"]),
            estimate["total_cost_usd"],
        )

    def test_parallel_cost_log_appends_preserve_cumulative_total(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "parallel-costs.csv"
            processes = []
            for index in range(8):
                processes.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            str(ROOT / "scripts" / "log_clouseau_cost.py"),
                            "--csv",
                            str(csv_path),
                            "--run-id",
                            f"parallel-{index}",
                            "--input-tokens",
                            "100",
                            "--input-price-per-1m",
                            "1",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(
                    process.returncode,
                    0,
                    msg=f"stdout={stdout}\nstderr={stderr}",
                )
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 8)
        self.assertAlmostEqual(
            float(rows[-1]["cumulative_total_usd"]),
            0.0008,
        )


if __name__ == "__main__":
    unittest.main()
