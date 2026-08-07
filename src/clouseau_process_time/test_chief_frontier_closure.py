from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.utils.function_calling import convert_to_openai_tool


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "external" / "Clouseau" / "artifact"
if str(ARTIFACT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT))
RUNNER_DIR = ROOT / "src" / "clouseau_process_time"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

import constants  # noqa: E402
from chief_inspector import (  # noqa: E402
    Clouseau,
    investigate_ctx,
    investigate_lead,
)
import run_clouseau_official_cbc_dense_eval as attack_runner  # noqa: E402


class FakeModel:
    def __init__(self, responses: list[AIMessage]) -> None:
        self.responses = list(responses)
        self.calls: list[list] = []

    def invoke(self, messages: list, **_: object) -> AIMessage:
        self.calls.append(list(messages))
        return self.responses.pop(0)


def make_agent(responses: list[AIMessage], review_prompt: str | None) -> Clouseau:
    agent = object.__new__(Clouseau)
    agent.current_iteration = 1
    agent.max_iterations = None
    agent.max_tokens = 4096
    agent.configs = {"frontier_closure_review_prompt": review_prompt}
    agent.model = FakeModel(responses)
    return agent


class FrontierClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_minimum = constants.DEFAULT_INVESTIGATION_MIN
        constants.DEFAULT_INVESTIGATION_MIN = 1

    def tearDown(self) -> None:
        constants.DEFAULT_INVESTIGATION_MIN = self.original_minimum

    def test_unresolved_frontier_converts_draft_to_tool_call(self) -> None:
        draft = AIMessage(content='{"status":"completed"}')
        follow_up = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "investigate_lead",
                    "args": {"lead": "観測済み child process の後続 edge を確認する。"},
                    "id": "frontier-call-1",
                    "type": "tool_call",
                }
            ],
        )
        agent = make_agent([draft, follow_up], "未解決フロンティアを確認する。")
        state = {"messages": [HumanMessage(content="起点")]}

        result = agent.call_model(state)

        self.assertIs(result["messages"][0], follow_up)
        self.assertEqual(len(agent.model.calls), 2)
        self.assertEqual(state["messages"][-2], draft)
        self.assertIsInstance(state["messages"][-1], HumanMessage)

    def test_closed_frontier_does_not_force_an_extra_investigation(self) -> None:
        draft = AIMessage(content='{"status":"completed"}')
        reviewed_draft = AIMessage(content='{"status":"completed","frontier":"closed"}')
        agent = make_agent([draft, reviewed_draft], "未解決フロンティアを確認する。")
        state = {"messages": [HumanMessage(content="起点")]}

        result = agent.call_model(state)

        self.assertIs(result["messages"][0], draft)
        self.assertEqual(len(agent.model.calls), 2)
        self.assertEqual(len(state["messages"]), 1)

    def test_policy_is_opt_in_for_existing_normal_runs(self) -> None:
        draft = AIMessage(content='{"status":"completed"}')
        agent = make_agent([draft], None)
        state = {"messages": [HumanMessage(content="起点")]}

        result = agent.call_model(state)

        self.assertIs(result["messages"][0], draft)
        self.assertEqual(len(agent.model.calls), 1)


class ToolValidationRecoveryTests(unittest.TestCase):
    def test_missing_chief_behavior_key_becomes_retry_tool_message(self) -> None:
        """A malformed model tool call must not abort the whole run."""

        configs: dict = {}
        agent = object.__new__(Clouseau)
        agent.ctx = investigate_ctx(llm=SimpleNamespace(), configs=configs)
        agent.configs = configs
        agent.current_iteration = 0
        agent.tools = {"investigate_lead": investigate_lead}
        state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "investigate_lead",
                            "args": {
                                "lead": "python.exe の接続先を確認する。",
                                "materiality": "new_step",
                                "evidence_anchor": "python.exe@2022-07-15 20:52:08",
                            },
                            "id": "missing-behavior-key",
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        }

        result = agent.call_tool(state)

        message = result["messages"][0]
        self.assertIn("tool_validation_recovery:", message.content)
        self.assertIn("behavior_key", message.content)
        self.assertEqual(agent.current_iteration, 1)
        self.assertEqual(
            configs["_tool_validation_recovery_records"][0]["role"],
            "chief",
        )
        self.assertEqual(
            configs["_tool_validation_recovery_records"][0]["missing_fields"],
            ["behavior_key"],
        )


class AttackPromptContractTests(unittest.TestCase):
    def test_active_attack_prompt_exposes_semantic_frontier_contract(self) -> None:
        prompts = SimpleNamespace()
        constants_stub = SimpleNamespace(DEFAULT_INVESTIGATION_MIN=999)

        attack_runner.patch_cbc_prompts_clean(prompts, constants_stub)

        self.assertEqual(constants_stub.DEFAULT_INVESTIGATION_MIN, 1)
        self.assertIn(
            "investigate_lead は必要な回数だけ",
            prompts.chief_inspector_agent,
        )
        self.assertIn(
            "material に接続する未調査 edge が残っている間だけ",
            prompts.chief_inspector_agent,
        )
        self.assertIn("## unresolved_frontier", prompts.investigation_agent)
        self.assertIn("固定個数を満たすため", prompts.chief_inspector_agent)
        self.assertIn("routine fan-out", prompts.chief_inspector_agent)
        self.assertIn("同等siblingは代表例で検証", prompts.investigation_agent)
        self.assertIn(
            "主行動列に異なる atomic behavior step を追加する",
            attack_runner.FRONTIER_CLOSURE_REVIEW_PROMPT,
        )
        self.assertEqual(
            attack_runner.FRONTIER_CLOSURE_POLICY,
            "semantic_fingerprint_atomic_guard_v16_with_empty_response_fail_closed",
        )
        self.assertIn(
            "One investigate_lead call validates one complete candidate atomic step",
            prompts.chief_inspector_agent,
        )
        self.assertIn(
            "do not paginate",
            prompts.sqlexpert_agent,
        )

    def test_stage3_clue_prints_exact_authorized_evidence_anchor(self) -> None:
        cases = attack_runner.load_cases(
            ROOT
            / "data"
            / "current_experiment"
            / "cases"
            / "normal8_observable_component_v3_stage_cases_20260726.jsonl"
        )
        row = next(
            item
            for item in cases
            if item["instance_id"]
            == "chain_10_e07_discord_run_key_registry_chain_stage3"
        )
        original = attack_runner.EXCLUDE_CBC_ALERT_SUMMARY
        try:
            attack_runner.EXCLUDE_CBC_ALERT_SUMMARY = True
            clue = attack_runner.build_cbc_clue_clean(row, "process_time")
        finally:
            attack_runner.EXCLUDE_CBC_ALERT_SUMMARY = original

        self.assertIn("- condition: stage3", clue)
        self.assertIn(
            "- authorized_evidence_anchor: reg.exe@2022-07-16 15:03:54",
            clue,
        )
        self.assertIn("Copy authorized_evidence_anchor exactly", clue)

    def test_tool_descriptions_do_not_request_exhaustive_tree_walks(self) -> None:
        from chief_inspector import investigate_lead
        from investigator import ask_audit

        self.assertIn(
            "one candidate atomic behavior step",
            investigate_lead.description,
        )
        self.assertNotIn("all descendants", investigate_lead.description.lower())
        self.assertIn("one bounded evidence question", ask_audit.description)
        self.assertNotIn("all descendants", ask_audit.description.lower())

    def test_investigate_lead_openai_schema_requires_atomic_key_fields(self) -> None:
        from chief_inspector import investigate_lead

        schema = convert_to_openai_tool(investigate_lead)["function"]["parameters"]

        self.assertEqual(
            set(schema["properties"]),
            {"lead", "behavior_key", "materiality", "evidence_anchor"},
        )
        self.assertEqual(
            set(schema["required"]),
            {"lead", "behavior_key", "materiality", "evidence_anchor"},
        )
        self.assertNotIn("ctx", schema["properties"])

    def test_semantic_guard_rejects_component_only_operation(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch("chief_inspector.investigate_attack") as investigate:
            result = investigate_lead.func(
                ctx,
                "Check the command line separately",
                "reg.exe|command_line|unknown",
                "new_step",
                "reg.exe@2022-07-16 15:03:54",
            )

        investigate.assert_not_called()
        self.assertIn("not standalone operations", result)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_component_only_operation",
        )

    def test_semantic_guard_requires_concrete_new_step(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch("chief_inspector.investigate_attack") as investigate:
            result = investigate_lead.func(
                ctx,
                "Find what started reg.exe",
                "reg.exe|process_start|unknown",
                "new_step",
                "reg.exe@2022-07-16 15:03:54",
            )

        investigate.assert_not_called()
        self.assertIn("require concrete subject and object", result)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_incomplete_atomic_key",
        )

    def test_semantic_guard_allows_bounded_missing_component_discovery(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch(
            "chief_inspector.investigate_attack",
            return_value="bounded result",
        ) as investigate:
            result = investigate_lead.func(
                ctx,
                "Resolve the observed reg.exe process-start edge in one lead",
                "reg.exe|process_start|unknown",
                "missing_component",
                "reg.exe@2022-07-16 15:03:54",
            )

        investigate.assert_called_once()
        self.assertEqual(result, "bounded result")
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "accepted",
        )

    def test_semantic_guard_rejects_noncanonical_or_generic_operation(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        invalid_keys = (
            "reg.exe|実行時行動|未確認対象",
            "reg.exe|runtime_behavior|unknown",
            "reg.exe|operation|unknown",
            "reg.exe|unknown|unknown",
            "reg.exe|unresolved|unknown",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for key in invalid_keys:
                with self.subTest(key=key):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve one bounded edge",
                        key,
                        "missing_component",
                        "reg.exe@2022-07-16 15:03:54",
                    )
                    self.assertIn("concrete canonical ASCII verb", result)

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_generic_operation"
                for record in configs["_behavior_key_guard_records"]
            )
        )

    def test_semantic_guard_accepts_concrete_atomic_step_and_rejects_duplicate(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        args = (
            ctx,
            "Resolve discord.exe creating reg.exe in one bounded lead",
            "discord.exe|create_process|reg.exe",
            "new_step",
            "source_row_id:410470@2022-07-16 15:03:54",
        )
        with patch(
            "chief_inspector.investigate_attack",
            return_value="bounded result",
        ) as investigate:
            first = investigate_lead.func(*args)
            second = investigate_lead.func(*args)

        investigate.assert_called_once()
        self.assertEqual(first, "bounded result")
        self.assertIn("duplicate candidate step rejected", second)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_duplicate_key",
        )

    def test_semantic_guard_rejects_unapproved_anchor(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch("chief_inspector.investigate_attack") as investigate:
            result = investigate_lead.func(
                ctx,
                "Resolve one bounded edge",
                "discord.exe|create_process|reg.exe",
                "new_step",
                "2022-07-16 15:03:54 PID=1234",
            )

        investigate.assert_not_called()
        self.assertIn("Copy one evidence_anchor exactly", result)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_unapproved_evidence_anchor",
        )

    def test_semantic_guard_rejects_generic_new_step_object(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch("chief_inspector.investigate_attack") as investigate:
            result = investigate_lead.func(
                ctx,
                "Resolve one bounded registry edge",
                "reg.exe|create|registry_key",
                "new_step",
                "reg.exe@2022-07-16 15:03:54",
            )

        investigate.assert_not_called()
        self.assertIn("not generic entity types", result)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_incomplete_atomic_key",
        )

    def test_semantic_guard_rejects_compound_generic_entity_labels(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "cmd.exe@2022-07-15 13:12:04"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        invalid_keys = (
            "cmd.exe|access|file_or_registry",
            "cmd.exe|start|process_or_service",
            "unknown_subject|start|cmd.exe",
            "cmd.exe|connect|unknown_endpoint",
            "python.exe|act_as|network_server",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for key in invalid_keys:
                with self.subTest(key=key):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve one bounded edge",
                        key,
                        "new_step",
                        "cmd.exe@2022-07-15 13:12:04",
                    )
                    self.assertIn("not generic entity types", result)

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_incomplete_atomic_key"
                for record in configs["_behavior_key_guard_records"]
            )
        )

    def test_semantic_guard_rejects_generic_missing_component_label(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch("chief_inspector.investigate_attack") as investigate:
            result = investigate_lead.func(
                ctx,
                "Resolve the missing concrete object",
                "cmd.exe|access|file_or_registry",
                "missing_component",
                "cmd.exe@2022-07-15 13:12:04",
            )

        investigate.assert_not_called()
        self.assertIn("not generic entity types", result)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_incomplete_atomic_key",
        )

    def test_semantic_guard_rejects_qualified_generic_target_label(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {"behavior_key_guard": {"enabled": True}}
        ctx = investigate_ctx(SimpleNamespace(), configs)
        invalid_objects = (
            "observed_registry_target",
            "known_process",
            "concrete_network_endpoint",
            "identified_file_object",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for object_value in invalid_objects:
                with self.subTest(object_value=object_value):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve one bounded missing component",
                        f"reg.exe|write|{object_value}",
                        "missing_component",
                        "reg.exe@2022-07-16 15:03:54",
                    )
                    self.assertIn("not generic entity types", result)

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_incomplete_atomic_key"
                for record in configs["_behavior_key_guard_records"]
            )
        )

    def test_semantic_guard_rejects_component_name_in_object_position(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        invalid_objects = (
            "command_line",
            "command_line@2022-07-16 15:03:54",
            "child_process:reg.exe",
            "pid=1234",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for object_value in invalid_objects:
                with self.subTest(object_value=object_value):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve one bounded execution edge",
                        f"reg.exe|execute|{object_value}",
                        "missing_component",
                        "reg.exe@2022-07-16 15:03:54",
                    )
                    self.assertIn("cannot be used as the subject or object", result)

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_component_only_entity"
                for record in configs["_behavior_key_guard_records"]
            )
        )

    def test_semantic_guard_deduplicates_paraphrased_process_start(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch(
            "chief_inspector.investigate_attack",
            return_value="bounded result",
        ) as investigate:
            first = investigate_lead.func(
                ctx,
                "Resolve discord.exe creating reg.exe",
                "discord.exe|create|reg.exe",
                "new_step",
                "reg.exe@2022-07-16 15:03:54",
            )
            paraphrase = investigate_lead.func(
                ctx,
                "Recheck the same process using a prose object label",
                "discord.exe|start|reg.exe process execution details",
                "new_step",
                "reg.exe@2022-07-16 15:03:54",
            )

        investigate.assert_called_once()
        self.assertEqual(first, "bounded result")
        self.assertIn("duplicate candidate step rejected", paraphrase)
        records = configs["_behavior_key_guard_records"]
        self.assertEqual(
            records[0]["semantic_fingerprint"],
            "discord.exe|process_start|reg.exe",
        )
        self.assertEqual(
            records[0]["semantic_fingerprint"],
            records[1]["semantic_fingerprint"],
        )
        self.assertEqual(records[1]["status"], "rejected_duplicate_key")

    def test_semantic_fingerprint_does_not_collapse_concrete_file_creation(self) -> None:
        from chief_inspector import semantic_behavior_fingerprint

        process_step = semantic_behavior_fingerprint(
            "powershell.exe",
            "create",
            "payload.exe",
        )
        file_step = semantic_behavior_fingerprint(
            "powershell.exe",
            "create",
            r"C:\Temp\payload.exe",
        )

        self.assertEqual(
            process_step,
            "powershell.exe|process_start|payload.exe",
        )
        self.assertNotEqual(file_step, process_step)

    def test_semantic_fingerprint_ignores_temporal_entity_suffix(self) -> None:
        from chief_inspector import semantic_behavior_fingerprint

        canonical = semantic_behavior_fingerprint(
            "reg.exe",
            "start",
            "powershell.exe",
        )
        timestamp_qualified = semantic_behavior_fingerprint(
            "reg.exe",
            "start",
            "powershell.exe@2022-07-16 15:03:54",
        )
        window_qualified = semantic_behavior_fingerprint(
            "powershell.exe",
            "read",
            "registry_key@2022-07-16 15:00:00-15:10:00",
        )

        self.assertEqual(canonical, timestamp_qualified)
        self.assertEqual(
            window_qualified,
            "powershell.exe|read|registry_key",
        )

    def test_semantic_guard_rejects_temporal_behavior_key_qualifiers(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        invalid_keys = (
            "reg.exe|start|powershell.exe@2022-07-16 15:03:54",
            "powershell.exe|read|registry_key@2022-07-16 15:00:00-15:10:00",
            "powershell.exe|write|file@15:00:00-15:05:00",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for key in invalid_keys:
                with self.subTest(key=key):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve one bounded candidate edge",
                        key,
                        "missing_component",
                        "reg.exe@2022-07-16 15:03:54",
                    )
                    self.assertIn(
                        "Timestamps and time windows belong only in evidence_anchor",
                        result,
                    )

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_context_qualified_key"
                for record in configs["_behavior_key_guard_records"]
            )
        )

    def test_temporal_suffix_rule_preserves_email_entity(self) -> None:
        from chief_inspector import semantic_behavior_fingerprint

        fingerprint = semantic_behavior_fingerprint(
            "outlook.exe",
            "send",
            "analyst@example.com",
        )

        self.assertEqual(
            fingerprint,
            "outlook.exe|send|analyst@example.com",
        )

    def test_semantic_guard_rejects_component_relation_paraphrases(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        keys = (
            "reg.exe|has_parent|explore_parent_process",
            "reg.exe|resolve_child|unknown",
            "reg.exe|check_pid|unknown",
            "reg.exe|command_line|unknown",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for key in keys:
                with self.subTest(key=key):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve a field-only relation",
                        key,
                        "missing_component",
                        "reg.exe@2022-07-16 15:03:54",
                    )
                    self.assertIn("not standalone operations", result)

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_component_only_operation"
                for record in configs["_behavior_key_guard_records"]
            )
        )

    def test_semantic_guard_rejects_explicit_placeholder_entity(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        with patch("chief_inspector.investigate_attack") as investigate:
            result = investigate_lead.func(
                ctx,
                "Resolve an invented registry candidate",
                r"reg.exe|execute|HKEY_LOCAL_MACHINE\Software\ExampleKey",
                "new_step",
                "reg.exe@2022-07-16 15:03:54",
            )

        investigate.assert_not_called()
        self.assertIn("are not observed entities", result)
        self.assertEqual(
            configs["_behavior_key_guard_records"][-1]["status"],
            "rejected_explicit_placeholder",
        )

    def test_semantic_guard_rejects_explicit_placeholder_for_missing_component(self) -> None:
        from chief_inspector import investigate_ctx, investigate_lead

        configs = {
            "behavior_key_guard": {
                "enabled": True,
                "allowed_evidence_anchors": [
                    "reg.exe@2022-07-16 15:03:54"
                ],
            }
        }
        ctx = investigate_ctx(SimpleNamespace(), configs)
        invalid_objects = (
            r"HKEY_LOCAL_MACHINE\Software\ExampleKey",
            r"C:\Temp\dummy_payload.exe",
            "sample.example.test:443",
        )
        with patch("chief_inspector.investigate_attack") as investigate:
            for object_value in invalid_objects:
                with self.subTest(object_value=object_value):
                    result = investigate_lead.func(
                        ctx,
                        "Resolve one bounded missing component",
                        f"reg.exe|write|{object_value}",
                        "missing_component",
                        "reg.exe@2022-07-16 15:03:54",
                    )
                    self.assertIn(
                        "not observed entities under any materiality",
                        result,
                    )

        investigate.assert_not_called()
        self.assertTrue(
            all(
                record["status"] == "rejected_explicit_placeholder"
                for record in configs["_behavior_key_guard_records"]
            )
        )


if __name__ == "__main__":
    unittest.main()
