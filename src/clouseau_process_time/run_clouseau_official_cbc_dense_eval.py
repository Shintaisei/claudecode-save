#!/usr/bin/env python3
"""CBC-dense 行動復元ケースで official CLOUSEAU を実行する。

この runner は official CLOUSEAU の構造を維持し、以下だけを制御する。
- 正解情報を漏らさない起点情報
- 各モジュールの role prompt
- scenario.db として使う証跡保持 adapter cache
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from typing import Annotated, Any, Dict, List

import run_clouseau_official_normal_behavior as official
from langchain_core.tools import InjectedToolArg


ROOT = Path(__file__).resolve().parents[2]
CURRENT_DATA = ROOT / "data" / "current_experiment"
CASES_PATH = CURRENT_DATA / "cases" / "cbc_dense_clouseau_cases.jsonl"
RUNS_DIR = CURRENT_DATA / "runs" / "clouseau_reconstruction_outputs"
ADAPTER_CACHE_DIR = CURRENT_DATA / "cache" / "adapter_cache"
SQL_PLAYBOOK_MODE = "none"
EXCLUDE_CBC_ALERT_SUMMARY = False
EXCLUDE_CBC_DATABASE = False
ACTIVE_TIME_SCOPE: tuple[str, str] | None = None
DEFAULT_MAX_INVESTIGATIONS = 100
DEFAULT_MAX_QUESTIONS = 200
DEFAULT_MAX_QUERIES = 400
DEFAULT_MAX_TOKENS = 8192
FRONTIER_CLOSURE_POLICY = (
    "semantic_fingerprint_atomic_guard_v16_with_empty_response_fail_closed"
)
FRONTIER_CLOSURE_REVIEW_PROMPT = """
これは最終回答を受理する直前の未解決フロンティア確認である。
これまでの ToolMessage と作成中の最終回答を読み直し、観測済みかつ対象行動列と因果的に接続する
parent/child process、PID/GUID、command line、file/registry object、network endpoint のうち、
主行動列に異なる atomic behavior step を追加する、既存stepの順序を変える、または
subject/operation/object の重要な未確定証拠を解消し得るのに、関連 edge をまだ調査していないものが
残っているか確認すること。

- 上記の意味で material な未調査の因果フロンティアが残る場合だけ、各フロンティアを別の
  investigate_lead tool call として発行する。
- 同一応答で複数の異なる tool call を発行してよい。
- 既に調査済みの対象を繰り返さない。
- 単なる時刻近接、件数合わせ、一般的な攻撃知識だけを理由に tool call を発行しない。
- 直接接続しているという理由だけでは未解決フロンティアにしない。既に確立した主行動列から分岐する
  routine fan-out、同じ役割の sibling process、反復された同種PID、process teardown、module load、
  crash reporting、loopback、通常のアプリ更新・background service・通常通信先は、それ自体が異なる
  operation/object を示して主行動列を変える観測証拠がない限り closed context とする。
- 同じ executable/command family、同じ親、同じ operation class の sibling は、代表例で接続と役割を
  検証した後は同等集合としてまとめ、PIDやendpointを一件ずつ再調査しない。
- 残るedgeの調査が主行動列のstep追加・順序変更・重要証拠解消ではなく、既知stepの周辺情報を
  詳細化するだけならフロンティアは閉じている。
- 未調査の因果フロンティアが残っていなければ、tool call を発行せず最終回答を維持する。
- One investigate_lead call must validate one complete candidate atomic step,
  gathering subject, operation, object, command, and immediate order evidence
  together. Never split one step into separate leads for its parent, command,
  target object, or individual missing fields.
- Every tool call must supply one canonical `subject|operation|object`
  behavior_key and materiality (`new_step`, `order_resolution`, or
  `missing_component`), plus the observed process/time or row evidence_anchor.
  Reuse exactly the same key for the same candidate step.
- Never append a timestamp or time window to a behavior_key subject or object.
  Time belongs only in evidence_anchor and cannot make the same candidate step
  a new lead.
- Example, dummy, sample, fake, or other fabricated entity values are rejected
  under every materiality. Use `unknown` with `missing_component` until evidence
  returns a concrete value.
- `new_step` and `order_resolution` require concrete subject and object values.
  If one component is not yet observed, use `missing_component` for one bounded
  discovery lead. Command line, parent/child, PID, path, timestamp, evidence,
  object, and order are fields of a step and must never be named as standalone
  operations.
- Representative raw rows are sufficient once an edge and its required
  subject/operation/object fields are established. Do not paginate or count
  the remaining equivalent rows merely for completeness.

これは調査回数の最小値・最大値を課す指示ではない。観測された未解決 edge の有無だけで判断すること。
""".strip()


def configure_utf8_stdio() -> None:
    """Keep Japanese CLI output readable on Windows and captured logs."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


configure_utf8_stdio()

ALERT_EXPLORATION_GUIDE = """
CBC alert exploration rule:
- The database description is correct. The issue is not the schema; the agent must actively search the available evidence.
- This adapter DB is already scoped to the scenario host. Do not add host filters unless a host/device column is actually present in the table being queried.
- For audit_logs.time, use the provided database_time_window format: 'YYYY-MM-DD HH:MM:SS'.
- Treat input fields as scope constraints and starting points, not as facts to hallucinate:
  * If process=... is provided, those process names are the mandatory first search targets. First enumerate CBC alert/event rows for those process names within database_time_window. For each matching row, reconstruct its observed parent -> process -> child/object chain before looking at unrelated alerts.
    Use a direct evidence query first: time between database_time_window start/end AND source_stream/access indicates CBC alert AND lower(process fields) matches one of the provided process names. Return the raw rows with parent_process_name/path, parent_command_line, command_line, alert_name/reason, source_row_id/hashes, pid, ppid.
  * If process contains multiple names such as "cmd.exe; python.exe", treat them as possible linked steps in one execution chain. Try to connect them through observed parent_process fields, ppid, childproc_name, command_line, process_guid, or parent_process_guid. Do not drop an earlier parent step just because the child process is easier to explain.
    If one focus process command_line contains another focus process name, treat that as strong chain evidence and preserve the full command_line exactly.
  * If source='CBC alert candidate' is provided but no process is provided, first enumerate CBC alert rows in database_time_window, then select the primary target chain from those observed alert rows. Prefer alert rows with concrete command_line, parent process, child process, registry/file/network object, or process relationship evidence.
  * If only a time window is provided, first enumerate CBC alert rows in database_time_window. If multiple alert/process chains exist, report the best-supported primary chain and list nearby chains separately. Rank by direct alert evidence, concrete command_line/object evidence, parent-child completeness, and whether the chain remains inside database_time_window.
- First enumerate candidate alert rows by time and alert markers:
  source_stream in ('cbc-edr-alerts','cbc-ngav-alerts') OR access='cbc_alert'.
- For each alert row, keep time, pid, ppid, pname/process_name, command_line, parent_process_name, parent_process_path, parent_command_line, alert_name, alert_reason, source_row_id, hashes.
- If the first query returns zero rows, do not conclude that no CBC alert exists. Check time format, source_stream values, and access values, then retry with less restrictive conditions.
- After alert rows are found, expand by the observed pid/ppid, command_line terms, and parent/child process relation. Do not invent unobserved process names, PIDs, paths, or alert IDs.
- The primary chain must use evidence inside database_time_window. Rows outside that window may be mentioned only as outside-scope context, not as primary-chain steps.
"""

CHAIN_RECONSTRUCTION_STOP_GUIDE = """
Behavior-chain reconstruction and stop rule:
- Multiple candidate processes or chains may exist in the time window. Reporting multiple chains is allowed.
- However, choose one primary target chain and mark unrelated or nearby chains separately. Do not merge unrelated steps into the primary chain.
- The primary target chain is chosen by the provided scope: process+alert > alert-only > time-only. When a process is explicitly provided, the primary chain must include that process if any matching evidence exists in database_time_window. In this case, do not spend the main query budget on broad discovery until the specified process chain has parent, process, command_line/object, and child/object evidence checked.
- When a process clue contains several names such as "cmd.exe; python.exe", treat them as linked focus processes. Check whether they are connected by observed parent/child fields, command_line, childproc_name, pid/ppid, or process_guid before considering unrelated chains.
- Do not over-search after the scoped chain is found. For process+alert inputs, prioritize reconstructing the specified process chain with parent, child, command_line, and object evidence over broad discovery of every nearby alert.
- Before finalizing, verify that the primary target chain has subject, action/relation, object, and evidence for each meaningful step.
- Confirm parent-child r　elations using observed pid/ppid, parent_process_name/path, parent_command_line, childproc_name, command_line, process_guid, or parent_process_guid where available.
- If a field is not observed, write null or unknown. Do not invent PIDs, process paths, command lines, alert IDs, or timestamps.
- Never use placeholder examples such as malicious.exe, suspicious.exe, script.py, alert-0001, or made-up powershell commands unless those exact values were observed in tool results.
- The primary chain must be built only from concrete values returned by investigators or QAAgent tool results.
- Stop only after:
  1. Candidate CBC alert rows in the time window have been enumerated, or the absence of such rows has been checked with relaxed conditions.
  2. For the selected primary chain, parent context, process command_line/action, child process or target object, and evidence identifiers have been checked where available.
  3. At least one behavior chain has been constructed when evidence exists. If process+alert evidence exists, returning an empty behavior_sequence is not acceptable.
  4. Nearby chains are separated from the primary chain.
  5. Additional queries are unlikely to add subject/action/object/evidence for the primary chain within the query budget.
"""


GENERIC_SQL_PLAYBOOK = """汎用SQL探索プレイブック:
1. 最初に利用可能なスキーマを確認する。存在しない列を繰り返し使わず、一覧にある近い列へ切り替える。
2. 多数の条件を一度に足す前に、狭い時間窓で候補行や source_stream の分布を確認する。
3. source_stream の値を作らない。スキーマ説明、環境説明、または SELECT DISTINCT source_stream で観測した値だけを使う。
4. host 値を username、domain、URL、process、自由文検索語として流用しない。host/device 列がなければ、host 条件は使えないと明示し、選択済みDB範囲と時間条件で絞る。
5. アラート行や起点行を探す場合は、まず観測済みのアラート系 source_stream と時間窓で調べる。process や host 条件は、該当列にその値が入っていることを確認してから追加する。
5a. 起点情報に process がある場合、最初の高信号クエリは「時間窓 + CBC alert/access + process名」である。このクエリでは command_line、parent_process_name、parent_process_path、parent_command_line、childproc_name、alert_name、alert_reason、source_row_id、hashes、pid、ppid を返す。結果が出たら、その行を主対象chainの最優先証跡にする。
5b. 起点情報に process が複数ある場合、各processを個別に検索し、command_lineやparent/child欄で互いに接続できるかを確認する。片方だけが見つかった場合でも、観測されたcommand_line内にもう片方のprocess名やscript/objectが含まれていないかを確認する。
6. PID だけでDB全体を検索しない。PID相関は時間窓で絞り、可能なら process_guid、parent_process_guid、command_line、source_stream も併用する。
7. 結果が多すぎる場合は、調査方向を変える前に、process fields、command_line、access/action、object/target fields、source_stream、event identifiers など高信号の証跡列で絞り込む。
8. 結果が0件の場合は、条件を一つずつ緩め、どの条件を緩めたかを報告する。1回の0件結果を「証跡が存在しない」証明として扱わない。
9. 回答では行単位の証跡を保持する。source_stream、time、event_record_id または source_row_id、pid、ppid、process fields、parent fields、command_line、access/action、object/target fields を落とさない。
10. 複数ストリームの相関は、時刻、プロセス識別子、親子関係、対象オブジェクトで行う。各関係が直接観測か、部分証跡からの推定かを区別する。
11. 残りのクエリは、前の結果が別方向を示さない限り、最も強い行動仮説の裏取りに使う。
12. よく出現するプロセス名をDB全体に対して無制限に検索しない。親子関係を調べる場合も、起点時間窓、または観測済みPIDと狭い時間範囲で制約する。
"""

CLEAN_SQL_PLAYBOOK = """
Operational SQL exploration guide:
1. Start by confirming the available schema only when needed. Do not over-focus on schema discovery.
2. For CBC alert-centered tasks, first query the exact alert row by source_row_id, hashes, or event_record_id when an alert_id is provided.
3. For time filters on audit_logs, use the database_time_window string format: 'YYYY-MM-DD HH:MM:SS'.
4. CBC alert rows are normally source_stream in ('cbc-edr-alerts','cbc-ngav-alerts') or access='cbc_alert'.
5. After the alert row is found, expand by observed pid, ppid, process_name/pname, parent_process_name, parent_process_path, parent_command_line, command_line, process_guid, parent_process_guid, and target object fields.
6. Preserve source_stream, time, source_row_id, event_record_id, alert_name, pid, ppid, process fields, parent fields, command_line, access/action, object, and target fields in the answer.
7. If the first query returns zero rows, relax only the condition that is likely too strict. Do not conclude absence until time format, source_stream/access values, and alert_id/source_row_id variants have been checked.
8. When multiple chains are found, report them separately. Do not merge unrelated nearby chains into the primary chain.
9. For Stage 1 single-alert tasks, the primary chain must remain centered on the input alert_id. Nearby rows are context unless directly connected by parent/child, same process, same command, same object, or close causal follow-up evidence.
10. For Stage 1 after locating the exact alert row, run at least one focused expansion query over observed values from that row: same pid/ppid, same process_name/pname, same parent_process_path/name, same command-line executable, and same target object family if present.
11. For registry, file, script, module, child-process, or network-object alerts, search nearby rows with the same normalized target object family. Include only rows connected by observed evidence.
12. Do not invent values. Unknown fields must remain null or be described as missing evidence. Never use placeholder identifiers such as zzzzzz, dummy IDs, or made-up PIDs.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--instance-id", action="append")
    parser.add_argument(
        "--stage",
        action="append",
        choices=["stage1", "stage2", "stage3"],
        help="Run or list only the specified experiment stage(s). Use --exclude-cbc-alert-summary with stage3.",
    )
    parser.add_argument("--run-all", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--max-investigations",
        type=int,
        default=DEFAULT_MAX_INVESTIGATIONS,
        help="Safety cap for Chief investigation rounds. Default is intentionally high enough for autonomous exploration.",
    )
    parser.add_argument(
        "--max-questions",
        type=int,
        default=DEFAULT_MAX_QUESTIONS,
        help="Safety cap for Investigator tool questions.",
    )
    parser.add_argument(
        "--max-queries",
        type=int,
        default=DEFAULT_MAX_QUERIES,
        help="Safety cap for QAAgent SQL tool calls.",
    )
    parser.add_argument(
        "--unbounded-agent-calls",
        action="store_true",
        help=(
            "Disable Chief, Investigator, and QAAgent/SQL call-count ceilings. "
            "The agents stop when they produce final answers."
        ),
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help="Maximum output tokens for each model call.",
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default=None,
        help="OpenAI reasoning effort to request for GPT-5-class models.",
    )
    parser.add_argument("--log-cost", action="store_true")
    parser.add_argument(
        "--sql-playbook",
        choices=["none", "generic"],
        default="none",
        help="QAAgent に追加する汎用SQL探索ルール。ケース固有の正解語は含めない。",
    )
    parser.add_argument(
        "--difficulty",
        choices=["exact", "alert_input", "alert_time", "time_window_only", "process_time", "time_only"],
        default="exact",
        help=(
            "CLOUSEAU に渡す起点情報の粒度。現行正式実験では "
            "alert_input=Stage 1 CBC alert input、"
            "process_time=Stage 2、"
            "process_time + --exclude-cbc-alert-summary=Stage 3。"
            "alert_time は過去実験との互換 alias。"
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--exclude-cbc-alert-summary",
        action="store_true",
        help=(
            "Hide CBC alert summary rows from Stage3 SQL tools via a temporary view. "
            "CBC event telemetry remains available. When a case declares a time scope, "
            "the adapter DB is physically filtered to that scope."
        ),
    )
    parser.add_argument(
        "--exclude-cbc-database",
        action="store_true",
        help=(
            "Apply the Stage4 control-only physical CBC DB filter: CBC alert summary and "
            "CBC EDR/NGAV event telemetry become unavailable; Security/Sysmon/DNS/browser "
            "evidence remains. This is not part of the formal Stage1/2/3 experiment."
        ),
    )
    return parser.parse_args()


def load_cases(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def select_rows(rows: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    stage_filtered = [row for row in rows if not args.stage or row.get("stage") in set(args.stage)]
    if args.instance_id:
        wanted = set(args.instance_id)
        selected = [row for row in stage_filtered if row["instance_id"] in wanted]
        missing = sorted(wanted - {row["instance_id"] for row in selected})
        if missing:
            raise SystemExit(f"未知の instance_id: {', '.join(missing)}")
        return selected
    if args.run_all:
        return stage_filtered
    raise SystemExit("--list、--instance-id、--run-all のいずれかを指定してください。")


def build_cbc_clue(row: Dict[str, Any], difficulty: str) -> str:
    """正解情報を漏らさない起点情報を作る。

    起点情報には alert name、command line、parent process、target object、
    expected category、gold behavior を意図的に含めない。
    """
    anchor = row["anchor_event"]
    db_time = anchor.get("database_time") or official.compact_time(anchor.get("timestamp_utc"))
    process = row.get("process_name") or anchor.get("process_name")
    episode = row.get("time_window_utc", {})
    episode_start = episode.get("episode_start") or ""
    episode_end = episode.get("episode_end") or ""
    db_window_start = str(episode_start).replace("T", " ").replace("Z", "")[:19]
    db_window_end = str(episode_end).replace("T", " ").replace("Z", "")[:19]
    host = row.get("host", "")
    guardrails = (
        "これはWindowsエンドポイントログから行動列を復元するタスクである。"
        "以下の起点情報だけを使い、アラート詳細、コマンドライン、親プロセス、対象オブジェクト、行動背景はログから発見する。"
        "隠れたgold answerを仮定してはいけない。ログで確認するまで、正常、悪性、特定アプリ名、特定レジストリキー、親プロセス、対象、背景カテゴリを仮定してはいけない。"
        "CBC alert は調査起点であり、最終的な benign/malicious ラベルではない。"
        "エージェントのリード、質問、要約、最終JSON内の自然言語値は日本語で書く。"
        "raw paths、command lines、process names、source_stream、alert_id、event_record_id、PID、timestamps は観測値のまま保持する。"
    )
    if row.get("evaluation_mode") == "normal_context_escalation":
        return (
            f"{guardrails} "
            f"Starting clue: scenario_host={host}, process={process}, time_window='{episode_start} to {episode_end}', "
            f"database_time_window='{db_window_start} to {db_window_end}'. "
            "First reconstruct the evidence-backed local behavior of the specified process. "
            "Then inspect the same host/time window for a separately reportable process sequence that would make closing the local explanation premature. "
            "Keep that sequence separate from the focus-process chain unless an observed parent/child, command-line, or object edge connects them. "
            "Report the relationship only as co-observed escalation evidence; do not infer causality or malicious intent."
        )
    if difficulty == "multi_alerts" or row.get("input_alert_rows"):
        alert_lines = []
        for idx, alert in enumerate(row.get("input_alert_rows", []), start=1):
            alert_lines.append(
                (
                    f"{idx}. time={alert.get('time')}, alert_id={alert.get('alert_id')}, "
                    f"alert_name={alert.get('alert_name')}, severity={alert.get('severity')}, "
                    f"process={alert.get('process_name')}, pid={alert.get('pid')}, "
                    f"process_path={alert.get('process_path')}, parent_path={alert.get('parent_path')}, "
                    f"command_line={alert.get('command_line')}"
                )
            )
        return (
            f"{guardrails} "
            f"Starting clue: scenario_host={host}, time_window='{episode_start} to {episode_end}', "
            f"database_time_window='{db_window_start} to {db_window_end}', source='CBC alert list'. "
            "以下のCBC alert一覧をSOCアナリストがまとめて入力した。各alertに対応する行動チェーンを、"
            "同じチェーン単位にまとめ、別チェーンは混ぜずに分けて復元する。"
            "入力alertのcommand_lineやparent_pathは観測値として使ってよいが、"
            "gold stepや行動カテゴリは仮定せず、必要な親子関係・対象object・追加証跡はログで確認する。 "
            "CBC alert一覧:\n"
            + "\n".join(alert_lines)
        )
    if difficulty == "exact":
        return (
            f"{guardrails} "
            f"起点情報: host={host}, process={process}, time_hint='{db_time}', "
            f"episode_window='{episode_start} to {episode_end}', database_time_window='{db_window_start} to {db_window_end}', source='CBC alert candidate'. "
            "周辺ログを調査し、この起点付近の行動列を復元する。"
        )
    if is_stage1_difficulty(difficulty):
        return (
            f"{guardrails} "
            f"Starting clue: scenario_host={host}, time_window='{episode_start} to {episode_end}', "
            f"database_time_window='{db_window_start} to {db_window_end}', source='CBC alert candidate'. "
            "When querying audit_logs.time, use database_time_window, not ISO T/Z timestamps. "
            "The adapter database is already scoped to scenario_host; do not filter SQL by host or subject_user_name=host. "
            "Do not assume the target process from the prompt. Discover the related process, "
            "CBC alert rows, command lines, parent/child process relation, target object, "
            "and behavior sequence from logs."
        )
    if difficulty == "time_window_only":
        return (
            f"{guardrails} "
            f"Starting clue: scenario_host={host}, time_window='{episode_start} to {episode_end}', "
            f"database_time_window='{db_window_start} to {db_window_end}'. "
            "When querying audit_logs.time, use database_time_window, not ISO T/Z timestamps. "
            "The adapter database is already scoped to scenario_host; do not filter SQL by host or subject_user_name=host. "
            "No process name and no CBC alert candidate are provided. Discover whether any "
            "relevant CBC alert or process behavior exists in this time window, then reconstruct "
            "the behavior sequence from log evidence."
        )
    if difficulty == "process_time":
        return (
            f"{guardrails} "
            f"起点情報: host={host}, process={process}, time_hint='{db_time}'. "
            "アラート詳細を仮定せず、ログに存在する場合だけ発見する。"
        )
    return (
        f"{guardrails} "
        f"起点情報: host={host}, time_hint='{db_time}'. "
        "関連するプロセスとアラート文脈をログから発見する。"
    )


def build_neutral_environment() -> str:
    return (
        "ATLASv2 の Windows host logs を CLOUSEAU 用に変換したDBを分析している。"
        "SQLite database には audit_logs、browser_history、dns_requests が含まれる。"
        "Security、Sysmon、CBC EDR/NGAV events、CBC alerts は audit_logs に正規化されている。"
        "証跡の出所は source_stream で区別する。代表値は msft-security、sysmon、cbc-edr、cbc-ngav、cbc-edr-alerts、cbc-ngav-alerts である。"
        "audit_logs には従来列として time、pid、ppid、pname、process_name、access、object、event_record_id、event_id、subject_user_name、source_stream、source_object_type、command_line、hashes がある。"
        "証跡保持adapterは parent_process_name、parent_process_path、parent_command_line、process_guid、parent_process_guid、alert_name、alert_reason、alert_category、raw_event_type、filemod_name、regmod_name、modload_name、childproc_name、netconn_domain、remote_ip、remote_port、original_table、source_row_id、adapter_version も保持する。"
        "ppid は parent PID を意味する。parent_process_path と parent_command_line は明示的な親プロセス証跡である。"
        "CBC alert rows は access='cbc_alert' を持つ。hashes または source_row_id に alert_id が含まれる場合があり、alert_name と alert_reason には利用可能な場合にアラート名と理由が入る。"
        "CBC alert を探すときは、まず time と source_stream/access で列挙する。source_stream は cbc-edr-alerts または cbc-ngav-alerts、access は cbc_alert を優先する。"
        "0件の場合は即座に存在しないと結論せず、時刻形式、source_stream 値、access 値、過剰な host/process 条件を疑って再探索する。"
        "複数のprocessやchainを出してよいが、主対象chainを1本明示し、周辺chainとは混ぜずに分ける。"
        "process が起点情報として与えられた場合は、そのprocessを含むCBC alert/event行を最初に確認し、親プロセス、当該processのcommand_line、子プロセスまたは対象objectを優先して復元する。"
        "process+alert条件では、時間窓内のCBC alert行そのものを最優先証跡とし、command_lineやparent_pathがそこに含まれる場合はその値を最終出力へそのまま保持する。"
        "process が複数名で与えられた場合は、別候補ではなく同一行動チェーン内の連続ステップ候補としてまず扱う。"
        "CBC alert候補だけが与えられた場合は、時間窓内のCBC alert行を列挙し、具体的なcommand_line、parent/child、objectを持つ行から主対象chainを選ぶ。"
        "時間窓だけが与えられた場合は、時間窓内のCBC alert候補を列挙し、最も証跡が具体的なchainを主対象にする。ただし、別chainは主対象に混ぜず別項目に分ける。"
        "主対象chainは database_time_window 内の観測値だけで構成する。時間窓外の行は主対象stepに使わない。"
        "終了前に、主対象chainのsubject/action/object/evidenceが揃っているか、観測されない値を作っていないかを確認する。"
        "CBC event rows には filemod_name、regmod_name、modload_name、childproc_name、netconn_domain、remote_ip、remote_port など対象別証跡が含まれる場合がある。"
        "Sysmon rows には process_guid、parent_process_guid、parent_process_path、parent_command_line が含まれる場合がある。"
        "adapter database には、起点時間窓だけでなく、選択された ATLASv2 scenario/host の incident.db 全体の行が含まれる。"
        "このタスクはログからの行動列復元である。証跡確認前に、正常、攻撃関連、悪性のいずれかを仮定してはいけない。"
        "自然言語のエージェント出力はすべて日本語で書く。"
    )


def _legacy_patch_cbc_prompts_unused(prompts: Any, constants: Any) -> None:
    """古い互換用の prompt patch。通常は使用しない。"""
    constants.DEFAULT_INVESTIGATION_MIN = 1
    prompts.chief_inspector_agent = """あなたは CLOUSEAU の階層型調査パイプラインにおける Chief agent である。
目的は、アラート候補の周辺ログ証跡から Windows エンドポイント上の行動列を復元することである。

出力言語:
* 外部に出すリード、質問、要約、最終報告の自然言語値はすべて日本語で書く。
* raw paths、command lines、process names、source_stream、alert_id、event_record_id、PID、PPID、hashes、timestamps は観測値のまま保持する。

Chief の役割:
* SQL は書かない。DB列名の一覧を探索手順として並べない。
* DB操作指示ではなく、調査リードを出す。
* 各リードは1つの論点だけを扱う。その論点が重要な理由と、どの結果が得られれば分析が進むかを書く。
* Use this lead form in Japanese: "論点: ...。理由: ...。期待される確認結果: ...。"
* Investigator が発見するまで、alert title、command line、parent process、target object、background category を明かしたり仮定したりしない。
* CBC alert は調査起点であり、最終的な benign/malicious ラベルではない。
* 実施できる調査数は最大 {max_investigations} 件である。
* 最終回答は有効な JSON のみとする。

環境:
{environment}

SOCからの起点情報:
{initial_message}
"""
    prompts.investigation_agent = """あなたは CLOUSEAU 内の Investigator agent である。
Chief のリードをそのまま QAAgent に渡してはいけない。QAAgent に聞く前に、調査仮説と確認項目へ分解する。

出力言語:
* 仮説、質問、結果要約、次の判断理由は日本語で書く。
* raw log values は観測値のまま保持する。

Investigator の手順:
1. Chief の論点を日本語の調査仮説として言い換える。
2. 調査仮説、確認すべき証跡、期待される結果、次の分岐条件に分ける。
3. QAAgent には自然言語の質問だけを渡す。SQL、SELECT、WHERE、列名リストを書かない。
4. QAAgent から結果が返ったら、観測事実、欠落している証跡、次に有用な質問を要約する。
5. 観測事実、接続された文脈、解釈、限界を分けて書く。

考慮すべき証跡:
* CBC alert rows: access='cbc_alert', source_stream cbc-edr-alerts または cbc-ngav-alerts.
* CBC event rows: source_stream cbc-edr または cbc-ngav.
* 親プロセス証跡: ppid、parent_process_name、parent_process_path、parent_command_line.
* Sysmon 証跡: process_guid、parent_process_guid、parent_process_path、parent_command_line.
* 対象証跡: filemod_name、regmod_name、modload_name、childproc_name、netconn_domain、remote_ip、remote_port、object.

ログなしで user intent、business purpose、file contents、最終的な benign/malicious certainty を推定しない。
実施できる tool question は最大 {max_questions} 件である。

環境:
{environment}

Chief リード:
{initial_message}
"""
    prompts.eval_agent = """あなたは CLOUSEAU の最終統合 agent である。
有効な JSON のみを返す。Markdown は使わない。
自然言語値は日本語で書き、raw log values は観測値のまま保持する。

統合ルール:
1. 最終出力は、構造化された生JSONである behavior_sequence と、読みやすい時系列表示である timeline_ja の2層を中心にする。この2層に不要な広い報告書セクションは追加しない。
2. behavior_sequence は、意味を持つ行動ステップの列として作る。異なる command line、PID、alert name、target object を曖昧な1ステップへ結合しない。
3. 各ステップでは time、type、account_context、subject、relation、object、execution_context、evidence、limitations を保持する。
4. CBC alerts は該当行動ステップの証跡である。alert name を結論として扱わず、それだけを説明にしない。
5. 行に ppid、parent_process_name/path、parent_command_line が含まれる場合、execution_context に親子文脈を含める。親プロセス証跡があるのに unknown と書かない。
6. account_context では subject_user_name、process_username、parent_username があれば保持する。これらが空でも C:\\Users\\<name> のような path や HKCU user context が観測される場合、user は "WIN-32-H1\\<name>"、confidence は "medium"、evidence_ref は "user_profile_path_inference" とする。
7. user intent、business purpose、file contents、最終的な benign/malicious certainty は推定しない。
8. timeline_ja は各 behavior step に対応する自然な日本語1文の配列にする。各文は "[time / ユーザー: user]" で始め、その後に subject、action/relation、object がラベルなしでも分かるように書く。
9. timeline_ja は流れとして読めるようにする。command_line や CBC alert name は、そのステップが存在する理由を説明するのに有用な場合だけ文中に含める。
10. timestamps、event_record_id、alert_id、source_stream、PIDs、PPIDs、command lines、registry paths、file paths を作らない。観測されていない識別子は null にするか省略する。
11. sysmon、msft-security、cbc-edr、cbc-ngav などの source_stream は、調査結果にその値が実際に出た場合だけ引用する。
12. command lines と registry paths は観測値のまま保持する。object path は observed command_line/row と一致させ、Run を RunOnce に変えたり、引数を追加・削除したりしない。
13. 起点アラート、プロセス連鎖、対象オブジェクトの説明に直接必要な behavior steps だけを含める。同じアラート行動に明示的に接続されていない file access、network、browser steps は追加しない。
14. behavior_sequence は観測時刻順に並べる。同一時刻に複数ステップがある場合は、実行文脈を操作文脈より前に置く。

出力スキーマ:
{
  "input_scope": {"host": "", "process": "", "time_window": ""},
  "behavior_sequence": [{
    "order": 1,
    "time": "",
    "type": "実行関係|操作関係|検知関係|文脈",
    "account_context": {"user": "", "evidence_ref": "", "confidence": "high|medium|low"},
    "subject": {"kind": "process|account|sensor|unknown", "process_name": "", "pid": null, "path": "", "role": ""},
    "relation": "",
    "object": {"kind": "process|registry_key|registry_value|file|network|alert|unknown", "value": "", "path": "", "data": ""},
    "execution_context": {"parent_process": "", "parent_pid": null, "parent_command_line": "", "child_process": "", "child_pid": null, "command_line": ""},
    "evidence": [{"source_stream": "", "timestamp": "", "field": "", "value": "", "identifier": null}],
    "limitations": [""]
  }],
  "timeline_ja": ["1. [time / ユーザー: user] subject が relation を行い、object に作用したことが自然に分かる日本語の1文。"]
}
"""
    playbook = f"\n{CLEAN_SQL_PLAYBOOK}\n{ALERT_EXPLORATION_GUIDE}\n{CHAIN_RECONSTRUCTION_STOP_GUIDE}\n" if SQL_PLAYBOOK_MODE == "generic" else ""
    prompts.sqlexpert_agent = """あなたは QAAgent / SQL expert である。SQLite を問い合わせて回答する。
ログ行に関する事実を述べる場合は、必ず run_sql_query を使う。rows、columns、process trees、PIDs、event IDs、timestamps、alert IDs、command lines、query results を作ってはいけない。

出力言語:
* 結果説明は日本語で書く。
* SQL、paths、command lines、process names、source_stream、event_record_id、alert_id、PID、PPID、timestamps は観測値のまま保持する。

重要な列:
* audit_logs legacy: time, pid, ppid, pname, process_name, access, object, event_record_id, event_id, subject_user_name, source_stream, source_object_type, command_line, hashes.
* 親プロセス証跡: parent_process_name, parent_process_path, parent_command_line.
* Sysmon: process_guid, parent_process_guid.
* CBC alert/event: alert_name, alert_reason, alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, original_table, source_row_id.
* dns_requests: time, domain, sld, response, query_type, is_response.
* browser_history: time, host, sld, method, headers, url, status_code.

必要な列が存在しない場合は、その列は利用できないと述べるか、利用可能な列を確認する。
クエリ結果が No results found または too many results の場合は、その事実を明示し、クエリ回数が残っていれば条件を調整する。

スキーマ:
{schema}

例:
{examples}

実行できる SQL tool query は最大 {max_queries} 回である。
質問: {question}
"""
def patch_cbc_prompts(prompts: Any, constants: Any) -> None:
    """元の CLOUSEAU graph を維持したまま role prompt を差し替える。

    この定義は上に残る古い prompt block を意図的に上書きする。
    構造は変えず、調査で行単位の証跡台帳を保持し、最終統合で
    発見済みの parent/process 証跡を曖昧な unknown 表現へ潰さない。
    """
    constants.DEFAULT_INVESTIGATION_MIN = 1
    prompts.chief_inspector_agent = """あなたは CLOUSEAU の階層型調査パイプラインにおける Chief agent である。
目的は、アラート候補の周辺ログ証跡から Windows エンドポイント上の行動列を復元することである。

出力言語:
* 外部に出すリード、質問、要約、最終報告の自然言語値はすべて日本語で書く。
* raw paths、command lines、process names、source_stream、alert_id、event_record_id、PID、PPID、hashes、timestamps は観測値のまま保持する。

Chief の役割:
* SQL は書かない。DB列名の一覧を探索手順として並べない。
* DB操作指示ではなく、調査リードを出す。
* 各リードは1つの論点だけを扱う。その論点が重要な理由と、どの結果が得られれば分析が進むかを書く。
* リードは日本語で「調査: ... / 調査理由: ... / 確認したい証跡: ...」の形式にする。
* Investigator が発見するまで、alert title、command line、parent process、target object、background category を明かしたり仮定したりしない。
* CBC alert は調査起点であり、最終的な benign/malicious ラベルではない。
* 実施できる調査数は最大 {max_investigations} 件である。
* 最終回答は有効な JSON のみとする。

環境:
{environment}

SOCからの起点情報:
{initial_message}
"""
    prompts.investigation_agent = """あなたは CLOUSEAU 内の Investigator agent である。
Chief のリードをそのまま QAAgent に渡してはいけない。QAAgent に聞く前に、調査仮説と確認項目へ分解する。

出力言語:
* 仮説、質問、結果要約、次の判断理由は日本語で書く。
* raw log values は観測値のまま保持する。

Investigator の手順:
1. Chief の論点を日本語の調査仮説として言い換える。
2. 調査仮説、確認すべき証跡、期待される結果、次の分岐条件に分ける。
3. QAAgent には自然言語の質問だけを渡す。SQL、SELECT、WHERE、列名リストを書かない。
4. QAAgent から結果が返ったら、過度に要約しない。まず返却行から証跡台帳を作り、その後に要約する。
5. 証跡台帳では、重要な行または関係ごとに source_stream、time、event_record_id または alert_id/source_row_id、pid、ppid、process_name/pname、parent_process_name/path、command_line、access/action、object/target、subject_user_name/process_username、C:\\Users\\<name> のような user profile path、重要性を保持する。
6. 行に ppid または parent_process_name/path が含まれる場合、親子関係を "child_pid -> parent_pid -> parent_process" として明示する。関連する親フィールドと追加確認がすべて欠落している場合を除き、親を unknown としない。
7. 観測事実、接続された文脈、解釈、限界を分けて書く。
8. 証跡欠落は「問い合わせたが見つからなかった」、弱い証跡は「見つかったが source/field が不完全」として区別する。
9. process path や command line に C:\\Users\\<name> が含まれる場合、subject_user_name/process_username が空でも account-context evidence として報告する。

考慮すべき証跡:
* CBC alert rows: access='cbc_alert', source_stream cbc-edr-alerts または cbc-ngav-alerts.
* CBC event rows: source_stream cbc-edr または cbc-ngav.
* 親プロセス証跡: ppid、parent_process_name、parent_process_path、parent_command_line.
* Sysmon 証跡: process_guid、parent_process_guid、parent_process_path、parent_command_line.
* 対象証跡: filemod_name、regmod_name、modload_name、childproc_name、netconn_domain、remote_ip、remote_port、object.

ログなしで user intent、business purpose、file contents、最終的な benign/malicious certainty を推定しない。
実施できる tool question は最大 {max_questions} 件である。

環境:
{environment}

Chief リード:
{initial_message}
"""
    prompts.eval_agent = """あなたは CLOUSEAU の最終統合 agent である。
有効な JSON のみを返す。Markdown は使わない。
自然言語値は日本語で書き、raw log values は観測値のまま保持する。

統合ルール:
1. 最終出力は、構造化された生JSONである behavior_sequence と、読みやすい時系列表示である timeline_ja の2層を中心にする。この2層に不要な広い報告書セクションは追加しない。
2. behavior_sequence は、意味を持つ行動ステップの列として作る。異なる command line、PID、alert name、target object を曖昧な1ステップへ結合しない。
3. 各ステップでは time、type、account_context、subject、relation、object、execution_context、evidence、limitations を保持する。
4. CBC alerts は該当行動ステップの証跡である。alert name を結論として扱わず、それだけを説明にしない。
5. 行に ppid、parent_process_name/path、parent_command_line が含まれる場合、execution_context に親子文脈を含める。親プロセス証跡があるのに unknown と書かない。
6. account_context では subject_user_name、process_username、parent_username があれば保持する。これらが空でも C:\\Users\\<name> のような path や HKCU user context が観測される場合、user は "WIN-32-H1\\<name>"、confidence は "medium"、evidence_ref は "user_profile_path_inference" とする。
7. user intent、business purpose、file contents、最終的な benign/malicious certainty は推定しない。
8. timeline_ja は各 behavior step に対応する自然な日本語1文の配列にする。各文は "[time / ユーザー: user]" で始め、その後に subject、action/relation、object がラベルなしでも分かるように書く。
9. timeline_ja は流れとして読めるようにする。command_line や CBC alert name は、そのステップが存在する理由を説明するのに有用な場合だけ文中に含める。
10. timestamps、event_record_id、alert_id、source_stream、PIDs、PPIDs、command lines、registry paths、file paths を作らない。観測されていない識別子は null にするか省略する。
11. sysmon、msft-security、cbc-edr、cbc-ngav などの source_stream は、調査結果にその値が実際に出た場合だけ引用する。
12. command lines と registry paths は観測値のまま保持する。object path は observed command_line/row と一致させ、Run を RunOnce に変えたり、引数を追加・削除したりしない。
13. 起点アラート、プロセス連鎖、対象オブジェクトの説明に直接必要な behavior steps だけを含める。同じアラート行動に明示的に接続されていない file access、network、browser steps は追加しない。
14. behavior_sequence は観測時刻順に並べる。同一時刻に複数ステップがある場合は、実行文脈を操作文脈より前に置く。

出力スキーマ:
{
  "input_scope": {"host": "", "process": "", "time_window": ""},
  "behavior_sequence": [{
    "order": 1,
    "time": "",
    "type": "実行関係|操作関係|検知関係|文脈",
    "account_context": {"user": "", "evidence_ref": "", "confidence": "high|medium|low"},
    "subject": {"kind": "process|account|sensor|unknown", "process_name": "", "pid": null, "path": "", "role": ""},
    "relation": "",
    "object": {"kind": "process|registry_key|registry_value|file|network|alert|unknown", "value": "", "path": "", "data": ""},
    "execution_context": {"parent_process": "", "parent_pid": null, "parent_command_line": "", "child_process": "", "child_pid": null, "command_line": ""},
    "evidence": [{"source_stream": "", "timestamp": "", "field": "", "value": "", "identifier": null}],
    "limitations": [""]
  }],
  "timeline_ja": ["1. [time / ユーザー: user] subject が relation を行い、object に作用したことが自然に分かる日本語の1文。"]
}
"""
    playbook = f"\n{CLEAN_SQL_PLAYBOOK}\n{ALERT_EXPLORATION_GUIDE}\n{CHAIN_RECONSTRUCTION_STOP_GUIDE}\n" if SQL_PLAYBOOK_MODE == "generic" else ""
    prompts.sqlexpert_agent = """あなたは QAAgent / SQL expert である。SQLite を問い合わせて回答する。
ログ行に関する事実を述べる場合は、必ず run_sql_query を使う。rows、columns、process trees、PIDs、event IDs、timestamps、alert IDs、command lines、query results を作ってはいけない。

出力言語:
* 結果説明は日本語で書く。
* SQL、paths、command lines、process names、source_stream、event_record_id、alert_id、PID、PPID、timestamps は観測値のまま保持する。

重要な列:
* audit_logs legacy: time, pid, ppid, pname, process_name, access, object, event_record_id, event_id, subject_user_name, source_stream, source_object_type, command_line, hashes.
* 親プロセス証跡: parent_process_name, parent_process_path, parent_command_line.
* Sysmon: process_guid, parent_process_guid.
* CBC alert/event: alert_name, alert_reason, alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, original_table, source_row_id.
* dns_requests: time, domain, sld, response, query_type, is_response.
* browser_history: time, host, sld, method, headers, url, status_code.

必要な列が存在しない場合は、その列は利用できないと述べるか、利用可能な列を確認する。
クエリ結果が No results found または too many results の場合は、その事実を明示し、クエリ回数が残っていれば条件を調整する。
""" + playbook + """
スキーマ:
{schema}

例:
{examples}

実行できる SQL tool query は最大 {max_queries} 回である。
質問: {question}
"""


def adapter_time(value: str) -> str:
    """Normalize the case ISO timestamp to the adapter's sortable TEXT time."""
    return str(value).replace("T", " ").replace("Z", "")[:19]


def remove_time_scope_rows(adapter_db: Path, start_utc: str, end_utc: str) -> Dict[str, int]:
    """Physically remove every adapter row outside the declared case window."""
    start, end = adapter_time(start_utc), adapter_time(end_utc)
    counts: Dict[str, int] = {"time_scope_start_utc": start_utc, "time_scope_end_utc": end_utc}
    conn = sqlite3.connect(adapter_db)
    try:
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        for table in ("audit_logs", "dns_requests", "browser_history"):
            if table not in tables:
                continue
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            if "time" not in columns:
                continue
            before = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            conn.execute(f"DELETE FROM {table} WHERE time < ? OR time > ?", (start, end))
            after = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            outside = int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE time < ? OR time > ?", (start, end)).fetchone()[0])
            if outside:
                raise RuntimeError(f"Hard time scope failed for {table}: {outside} outside-window rows remain")
            counts[f"{table}_rows_removed_outside_time_scope"] = before - after
            counts[f"{table}_rows_retained_in_time_scope"] = after
        conn.commit()
    finally:
        conn.close()
    return counts


def cached_adapter_factory(original_create):
    def link_or_copy(source: Path, dest: Path) -> None:
        if dest.exists():
            dest.unlink()
        try:
            os.link(source, dest)
        except OSError as exc:
            if os.environ.get("CLOUSEAU_ALLOW_ADAPTER_COPY") != "1":
                raise RuntimeError(
                    f"Hardlink failed for adapter DB {source} -> {dest}. "
                    "Refusing to copy the multi-GB adapter DB by default. "
                    "Set CLOUSEAU_ALLOW_ADAPTER_COPY=1 only when enough disk space is available."
                ) from exc
            shutil.copy2(source, dest)

    def cached_filtered_db(cache_db: Path, suffix: str, filter_func) -> tuple[Path, Dict[str, int]]:
        filtered_db = cache_db.with_name(f"{cache_db.stem}_{suffix}{cache_db.suffix}")
        counts_path = filtered_db.with_suffix(".counts.json")
        if filtered_db.exists() and counts_path.exists():
            return filtered_db, json.loads(counts_path.read_text(encoding="utf-8"))

        tmp_db = filtered_db.with_suffix(".building.db")
        if tmp_db.exists():
            tmp_db.unlink()
        shutil.copy2(cache_db, tmp_db)
        counts = filter_func(tmp_db)
        for attempt in range(10):
            try:
                tmp_db.replace(filtered_db)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(1)
        counts_path.write_text(json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8")
        return filtered_db, counts

    def create_cached_adapter(source_db: Path, adapter_db: Path) -> Dict[str, int]:
        ADAPTER_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = source_db.parent.name.replace("-", "_")
        cache_db = ADAPTER_CACHE_DIR / f"{safe_name}_scenario_v3_evidence_preserving.db"
        counts_path = ADAPTER_CACHE_DIR / f"{safe_name}_scenario_v3_evidence_preserving_counts.json"
        alt_counts_path = cache_db.with_suffix(".counts.json")
        if not cache_db.exists():
            counts = original_create(source_db, cache_db)
            counts_path.write_text(json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8")
        elif counts_path.exists():
            counts = json.loads(counts_path.read_text(encoding="utf-8"))
        elif alt_counts_path.exists():
            counts = json.loads(alt_counts_path.read_text(encoding="utf-8"))
        else:
            counts = {}
        adapter_db.parent.mkdir(parents=True, exist_ok=True)
        active_db = cache_db
        if ACTIVE_TIME_SCOPE:
            scope_start, scope_end = ACTIVE_TIME_SCOPE
            suffix = f"time_scope_{adapter_time(scope_start).replace(':', '')}_{adapter_time(scope_end).replace(':', '')}"
            active_db, scope_counts = cached_filtered_db(
                cache_db,
                suffix,
                lambda path: {**dict(counts), **remove_time_scope_rows(path, scope_start, scope_end), "hard_time_scope_enforced": True},
            )
            counts = scope_counts
        if EXCLUDE_CBC_DATABASE:
            filtered_db, filter_counts = cached_filtered_db(
                active_db,
                "no_cbc_database",
                lambda path: {
                    **dict(counts),
                    "cbc_database_rows_removed": remove_cbc_database_rows(path),
                    "cbc_database_removed": True,
                },
            )
            link_or_copy(filtered_db, adapter_db)
            counts = filter_counts
        elif EXCLUDE_CBC_ALERT_SUMMARY:
            # Stage 3 used to install a qa_agent monkeypatch that rewrote
            # audit_logs to a TEMP VIEW.  That replacement silently bypassed
            # the shared SQL execution guard and replaced the process-tree
            # helpers with stale, unbounded implementations.  Filter a cached
            # copy instead so every SQL/process-tree tool keeps the common
            # guarded implementation.
            filtered_db, filter_counts = cached_filtered_db(
                active_db,
                "no_cbc_alert_summary_physical_v2",
                lambda path: physically_filter_cbc_alert_summary_rows(path, counts),
            )
            link_or_copy(filtered_db, adapter_db)
            counts = filter_counts
        else:
            link_or_copy(active_db, adapter_db)
        return counts

    return create_cached_adapter


def remove_cbc_alert_summary_rows(adapter_db: Path) -> int:
    """Physically remove only CBC alert-summary rows from a Stage 3 adapter."""
    conn = sqlite3.connect(adapter_db)
    try:
        cur = conn.execute(
            """
            DELETE FROM audit_logs
            WHERE source_stream IN ('cbc-edr-alerts', 'cbc-ngav-alerts')
               OR access = 'cbc_alert'
               OR original_table = 'cbc_alerts'
            """
        )
        conn.commit()
        return cur.rowcount if cur.rowcount is not None else 0
    finally:
        conn.close()


def count_cbc_alert_summary_rows(adapter_db: Path) -> int:
    """Count remaining CBC alert summary rows after stage filtering."""
    conn = sqlite3.connect(adapter_db)
    try:
        cur = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE source_stream IN ('cbc-edr-alerts', 'cbc-ngav-alerts')
               OR access = 'cbc_alert'
               OR original_table = 'cbc_alerts'
            """
        )
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def physically_filter_cbc_alert_summary_rows(
    adapter_db: Path,
    base_counts: Dict[str, int],
) -> Dict[str, Any]:
    """Filter Stage 3 alert summaries while preserving shared guarded tools."""
    before = count_cbc_alert_summary_rows(adapter_db)
    removed = remove_cbc_alert_summary_rows(adapter_db)
    after = count_cbc_alert_summary_rows(adapter_db)
    if after:
        raise RuntimeError(
            f"Stage 3 physical alert-summary filter left {after} row(s) visible"
        )
    return {
        **dict(base_counts),
        "cbc_alert_summary_filter_mode": "physical_adapter_copy_v2",
        # Retain this established field for downstream compatibility.  It now
        # means rows hidden from every Stage 3 tool by physical exclusion.
        "cbc_alert_summary_rows_hidden_from_stage3_sql": before,
        "cbc_alert_summary_rows_removed": removed,
        "post_filter_cbc_alert_summary_rows": after,
        "post_filter_cbc_event_telemetry_rows": count_cbc_event_telemetry_rows(
            adapter_db
        ),
        "shared_guarded_sql_tools_preserved": True,
        "shared_guarded_process_tree_tools_preserved": True,
    }


def count_cbc_event_telemetry_rows(adapter_db: Path) -> int:
    """Count remaining low-level CBC EDR/NGAV telemetry rows after stage filtering."""
    conn = sqlite3.connect(adapter_db)
    try:
        cur = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE source_stream IN ('cbc-edr', 'cbc-ngav')
               OR original_table = 'cbc_events'
            """
        )
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def remove_cbc_database_rows(adapter_db: Path) -> int:
    """Remove all CBC alert summary and CBC EDR/NGAV telemetry rows from the runtime adapter DB."""
    conn = sqlite3.connect(adapter_db)
    try:
        cur = conn.execute(
            """
            DELETE FROM audit_logs
            WHERE source_stream IN ('cbc-edr-alerts', 'cbc-ngav-alerts', 'cbc-edr', 'cbc-ngav')
               OR access = 'cbc_alert'
               OR original_table IN ('cbc_alerts', 'cbc_events')
            """
        )
        conn.commit()
        return cur.rowcount if cur.rowcount is not None else 0
    finally:
        conn.close()


def current_process_time_condition() -> str:
    if globals().get("EXCLUDE_CBC_DATABASE", False):
        return "stage4_control_cbc_database_removed"
    if globals().get("EXCLUDE_CBC_ALERT_SUMMARY", False):
        return "stage3"
    return "stage2"


def authorized_behavior_anchor(row: Dict[str, Any]) -> str:
    """Return the exact process/time anchor a Chief tool call may reuse."""
    anchor = row.get("anchor_event") or {}
    process = row.get("process_name") or anchor.get("process_name") or "unknown"
    db_time = anchor.get("database_time") or official.compact_time(
        anchor.get("timestamp_utc")
    )
    return f"{process}@{db_time}"


def is_stage1_difficulty(difficulty: str) -> bool:
    return difficulty in {"alert_input", "alert_time"}


def current_experiment_stage(difficulty: str) -> str:
    """Return the formal stage label for the current process-time experiment."""
    if is_stage1_difficulty(difficulty):
        return "stage1"
    if difficulty == "process_time":
        return current_process_time_condition()
    return difficulty or "unknown"


def current_expected_input_fields(difficulty: str) -> list[str]:
    stage = current_experiment_stage(difficulty)
    if stage == "stage1":
        return [
            "host",
            "focus_processes",
            "chain_window_start_utc",
            "chain_window_end_utc",
            "alert_time",
            "alert_id",
            "alert_name",
            "alert_reason",
            "alert_process",
            "alert_pid",
            "alert_source_stream",
            "alert_severity",
        ]
    return ["host", "process", "timestamp"]


def format_stage1_alert_rows(row: Dict[str, Any]) -> str:
    alerts = row.get("input_alert_rows") or []
    if not alerts:
        return ""
    lines = ["- input_alert_rows:"]
    for idx, alert in enumerate(alerts, 1):
        lines.append(
            "  "
            + (
                f"{idx}. alert_time={alert.get('time')}; "
                f"alert_id={alert.get('alert_id')}; "
                f"alert_name={alert.get('alert_name')}; "
                f"alert_reason={alert.get('alert_reason')}; "
                f"alert_process={alert.get('process')}; "
                f"alert_pid={alert.get('pid')}; "
                f"alert_source_stream={alert.get('source_stream')}; "
                f"alert_severity={alert.get('severity')}"
            )
        )
    return "\n".join(lines) + "\n"


def current_cbc_availability_note() -> str:
    if globals().get("EXCLUDE_CBC_DATABASE", False):
        return (
            "Stage4 control-only physical CBC DB filter is active. "
            "CBC alert summary rows and CBC EDR/NGAV event telemetry are unavailable. "
            "Security/Sysmon/DNS/browser evidence remains available. "
            "This is not part of formal Stage 1/2/3.\n"
        )
    if globals().get("EXCLUDE_CBC_ALERT_SUMMARY", False):
        return (
            "実行条件: CBC alert summary rows は Stage3 runtime adapter から物理的に除外され、全 tool で hidden である。"
            "CBC EDR/NGAV event telemetry は物理除外されず利用可能である。\n"
        )
    return (
        "実行条件: process-time full DB。CBC alert summary rows も、CBC EDR/NGAV event telemetry も、"
        "入力には含まれないが、調査で発見できる証拠として database 内に残っている。\n"
    )


def _extract_user_from_text(text: str) -> str:
    direct = re.search(r"WIN-32-H1\\([A-Za-z0-9._-]+)", text, flags=re.IGNORECASE)
    if direct:
        return f"WIN-32-H1\\{direct.group(1)}"
    profile = re.search(r"C:\\Users\\([^\\\"\s]+)", text, flags=re.IGNORECASE)
    if profile:
        return f"WIN-32-H1\\{profile.group(1)}"
    return "不明"


def _extract_reg_command(text: str) -> str:
    match = re.search(
        r"C:\\Windows\\System32\\reg\.exe\s+(?:add|query)\s+HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run[^\t\r\n]*",
        text,
        flags=re.IGNORECASE,
    )
    return match.group(0) if match else ""


def _extract_report_name(text: str) -> str:
    match = re.search(r"report_name=([^|\t\r\n]+)", text)
    return match.group(1).strip() if match else ""


def _extract_parent_field(text: str, key: str) -> str:
    match = re.search(rf"{re.escape(key)}=([^|\t\r\n]+)", text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_discord_reg_rows(events_path: Path) -> List[Dict[str, Any]]:
    """live evidence logs から Discord Run-key に関する高信号行を抽出する。

    これは保守的な後処理である。tool results に実際に現れ、
    Discord Run-key case に必要な具体的な reg.exe command/target を含む行だけを出す。
    agent の調査を置き換えるものではなく、最終報告の hallucination を抑える guardrail として使う。
    """
    if not events_path.exists():
        return []

    rows: List[Dict[str, Any]] = []
    seen = set()
    for raw_line in events_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") not in {"tool_result", "agent_message"}:
            continue
        content = event.get("content")
        if not isinstance(content, str):
            continue
        for line in content.splitlines():
            lower = line.lower()
            if not re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\t", line):
                continue
            if "reg.exe" not in lower or "currentversion\\run" not in lower or "discord" not in lower:
                continue
            command_line = _extract_reg_command(line)
            if not command_line:
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            time, pid, ppid, pname, process_path, access, object_blob = parts[:7]
            report_name = _extract_report_name(line)
            source_stream = next((part for part in parts if part in {"cbc-edr", "cbc-ngav", "cbc-edr-alerts", "cbc-ngav-alerts", "msft-security", "sysmon"}), "")
            if not source_stream and (access == "cbc_alert" or report_name):
                source_stream = "cbc-edr-alerts"
            parent_path = _extract_parent_field(line, "parent_path")
            parent_command_line = _extract_parent_field(line, "parent_cmdline")
            parent_process = "Discord.exe" if "discord.exe" in f"{parent_path} {parent_command_line}".lower() else ""
            user = _extract_user_from_text(line)
            key = (time, pid, command_line, access, object_blob, report_name)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "time": time,
                    "pid": int(pid) if pid.isdigit() else None,
                    "ppid": int(ppid) if ppid.isdigit() else None,
                    "process_name": pname or "reg.exe",
                    "process_path": process_path,
                    "access": access,
                    "object": object_blob,
                    "command_line": command_line,
                    "report_name": report_name,
                    "source_stream": source_stream,
                    "parent_process": parent_process or "Discord.exe",
                    "parent_path": parent_path,
                    "parent_command_line": parent_command_line,
                    "user": user,
                }
            )
    alert_rows = [row for row in rows if row.get("report_name") or row.get("access") == "cbc_alert"]
    if alert_rows:
        rows = alert_rows
    rows.sort(key=lambda item: (item["time"], item["pid"] or 0, item["command_line"]))
    return rows


def _build_discord_run_key_final(rows: List[Dict[str, Any]], instance_id: str) -> Dict[str, Any]:
    primary_user = next((row["user"] for row in rows if row.get("user") and row["user"] != "不明"), "不明")
    times = sorted({row["time"] for row in rows})
    start = times[0] if times else ""
    end = times[-1] if times else start
    if start and end:
        time_window = f"{start} - {end}"
    else:
        time_window = ""

    behavior_sequence: List[Dict[str, Any]] = []
    timeline: List[str] = []

    for row in rows:
        command_line = row["command_line"]
        is_query = re.search(r"\bquery\b", command_line, flags=re.IGNORECASE) is not None
        is_add = re.search(r"\badd\b", command_line, flags=re.IGNORECASE) is not None
        relation = "レジストリ値を照会した" if is_query else "レジストリ値を追加または更新した"
        action_label = "照会" if is_query else "追加または更新"
        object_value = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Discord" if is_query else "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Discord"
        data_match = re.search(r"/d\s+\"([^\"]+)\"", command_line, flags=re.IGNORECASE)
        object_data = data_match.group(1) if data_match else ""
        alert_part = f"CBC は {row['report_name']} として検知した。" if row.get("report_name") else ""

        exec_order = len(behavior_sequence) + 1
        behavior_sequence.append(
            {
                "order": exec_order,
                "time": row["time"],
                "type": "実行関係",
                "account_context": {
                    "user": row.get("user") or primary_user,
                    "evidence_ref": "subject_user_nameまたはC:\\Users\\<name>を含む親/子プロセスのパス",
                    "confidence": "high" if row.get("user") and row["user"] != "不明" else "medium",
                },
                "subject": {
                    "kind": "process",
                    "process_name": row.get("parent_process") or "Discord.exe",
                    "pid": row.get("ppid"),
                    "path": row.get("parent_path"),
                    "role": "親プロセス",
                },
                "relation": "子プロセスとして起動した",
                "object": {
                    "kind": "process",
                    "value": "reg.exe",
                    "path": row.get("process_path"),
                    "data": "",
                },
                "execution_context": {
                    "parent_process": row.get("parent_process") or "Discord.exe",
                    "parent_pid": row.get("ppid"),
                    "parent_command_line": row.get("parent_command_line"),
                    "child_process": "reg.exe",
                    "child_pid": row.get("pid"),
                    "command_line": command_line,
                },
                "evidence": [
                    {
                        "source_stream": row.get("source_stream"),
                        "timestamp": row["time"],
                        "field": "parent_cmdline/process_cmdline",
                        "value": f"{row.get('parent_command_line') or ''} -> {command_line}",
                        "identifier": row.get("pid"),
                    }
                ],
                "limitations": [
                    "この親子プロセス関係だけでは、Discord.exe の起動がユーザー操作か更新処理かは断定できない。"
                ],
            }
        )
        timeline.append(
            f"{exec_order}. [{row['time']} / ユーザー: {row.get('user') or primary_user}] "
            f"{row.get('parent_process') or 'Discord.exe'} は reg.exe (PID {row.get('pid')}) を子プロセスとして起動し、"
            f"その reg.exe に {command_line} を実行させた。"
        )

        op_order = len(behavior_sequence) + 1
        behavior_sequence.append(
            {
                "order": op_order,
                "time": row["time"],
                "type": "操作関係",
                "account_context": {
                    "user": row.get("user") or primary_user,
                    "evidence_ref": "subject_user_nameまたはC:\\Users\\<name>を含むコマンドライン",
                    "confidence": "high" if row.get("user") and row["user"] != "不明" else "medium",
                },
                "subject": {
                    "kind": "process",
                    "process_name": "reg.exe",
                    "pid": row.get("pid"),
                    "path": row.get("process_path"),
                    "role": "操作プロセス",
                },
                "relation": relation,
                "object": {
                    "kind": "registry_value",
                    "value": "Discord",
                    "path": object_value,
                    "data": object_data,
                },
                "execution_context": {
                    "parent_process": row.get("parent_process") or "Discord.exe",
                    "parent_pid": row.get("ppid"),
                    "parent_command_line": row.get("parent_command_line"),
                    "child_process": "reg.exe",
                    "child_pid": row.get("pid"),
                    "command_line": command_line,
                },
                "evidence": [
                    {
                        "source_stream": row.get("source_stream"),
                        "timestamp": row["time"],
                        "field": "access/object/command_line/report_name",
                        "value": " | ".join(
                            part
                            for part in [row.get("access"), row.get("object"), command_line, row.get("report_name")]
                            if part
                        ),
                        "identifier": row.get("pid"),
                    }
                ],
                "limitations": [
                    "Run key 操作は Discord の自動起動設定や更新処理でも発生し得るため、ログだけでは攻撃的永続化とは断定しない。"
                ],
            }
        )
        timeline.append(
            f"{op_order}. [{row['time']} / ユーザー: {row.get('user') or primary_user}] "
            f"reg.exe (PID {row.get('pid')}) は {object_value} を{action_label}した。"
            f"{alert_part}"
        )

    if behavior_sequence:
        limit_order = len(behavior_sequence) + 1
        behavior_sequence.append(
            {
                "order": limit_order,
                "time": None,
                "type": "文脈",
                "account_context": {"user": primary_user, "evidence_ref": "上記の行動列", "confidence": "medium"},
                "subject": {"kind": "process", "process_name": "Discord.exe/reg.exe", "pid": None, "path": "", "role": "判断対象"},
                "relation": "意図は未確定",
                "object": {"kind": "registry_value", "value": "Discord", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Discord", "data": ""},
                "execution_context": {},
                "evidence": [],
                "limitations": [
                    "この行動列は Discord の自動起動設定操作として説明できる可能性を示すが、ログだけではユーザーが明示的に設定したのか、Discord の正規更新なのか、攻撃的永続化なのかまでは断定しない。"
                ],
            }
        )
        timeline.append(
            f"{limit_order}. [限界 / ユーザー: {primary_user}] "
            "この行動列は Discord の Run key 操作として説明できるが、ユーザー操作、正規更新、攻撃的永続化のどれであるかはログだけでは断定しない。"
        )

    return {
        "input_scope": {
            "host": "WIN-32-H1",
            "process": "reg.exe",
            "time_window": time_window,
            "instance_id": instance_id,
        },
        "behavior_sequence": behavior_sequence,
        "timeline_ja": timeline,
    }


def normalize_final_output_from_events(run_json_path: Path, events_path: Path, instance_id: str) -> bool:
    """可能な場合、run.json の output_text を証跡ベースの UI 用 JSON で上書きする。"""
    rows = _extract_discord_reg_rows(events_path)
    if not rows:
        return False
    final_output = _build_discord_run_key_final(rows, instance_id)
    try:
        run_json = json.loads(run_json_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    if "raw_model_output_text" not in run_json:
        run_json["raw_model_output_text"] = run_json.get("output_text")
    run_json["output_text"] = json.dumps(final_output, ensure_ascii=False, indent=2)
    run_json["output_normalization"] = {
        "method": "events_jsonl_discord_run_key_rows",
        "source_events_jsonl": str(events_path),
        "row_count": len(rows),
    }
    run_json_path.write_text(json.dumps(run_json, ensure_ascii=False, indent=2), encoding="utf-8")
    return True


def build_cbc_clue_clean(row: Dict[str, Any], difficulty: str) -> str:
    """Build a non-mojibake clue with the intended Stage 1 / Stage 2 input policy."""
    anchor = row["anchor_event"]
    episode = row.get("time_window_utc", {})
    episode_start = episode.get("episode_start") or ""
    episode_end = episode.get("episode_end") or ""
    db_window_start = str(episode_start).replace("T", " ").replace("Z", "")[:19]
    db_window_end = str(episode_end).replace("T", " ").replace("Z", "")[:19]
    host = row.get("host", "")
    process = row.get("process_name") or anchor.get("process_name")
    db_time = anchor.get("database_time") or official.compact_time(anchor.get("timestamp_utc"))

    guardrails = (
        "This is a Windows endpoint behavior-chain reconstruction task. "
        "Use the starting clue only as investigation scope. Reconstruct subject, action, object, "
        "and evidence from logs. Do not assume benign, malicious, application intent, registry path, "
        "process name, command line, parent process, or target object unless it is observed. "
        "CBC alerts are investigation starting points, not final labels. "
        "Preserve raw paths, command lines, process names, source_stream, alert_id, event_record_id, "
        "PID/PPID, and timestamps exactly as observed. "
        "All natural-language values in the final JSON must be Japanese, but field names must remain ASCII."
    )
    common = (
        f"{guardrails}\n\n"
        f"Scenario host: {host}\n"
        f"Window UTC: {episode_start} to {episode_end}\n"
        f"Database time window: {db_window_start} to {db_window_end}\n"
        "When querying audit_logs.time, use the database time window, not ISO T/Z timestamps. "
        "The adapter database is already scoped to the scenario host; do not add host filters unless "
        "a host/device column exists in the table being queried.\n"
        "Investigate first, then synthesize. The final answer should organize observed behavior chains "
        "and explain evidence, but do not let the output schema replace the investigation.\n"
    )

    if difficulty == "multi_alerts" or row.get("input_alert_rows"):
        alert_lines = []
        for idx, alert in enumerate(row.get("input_alert_rows", []), start=1):
            alert_lines.append(
                (
                    f"{idx}. time={alert.get('time')}, source_stream={alert.get('source_stream')}, "
                    f"alert_id={alert.get('alert_id')}, alert_name={alert.get('alert_name')}, "
                    f"reason={alert.get('alert_reason')}, process={alert.get('process_name')}, "
                    f"pid={alert.get('pid')}, ppid={alert.get('ppid')}, "
                    f"parent={alert.get('parent_process_name') or alert.get('parent_path')}, "
                    f"command_line={alert.get('command_line')}"
                )
            )
        return (
            common
            + "\nInput condition: Stage 2 multi-CBC-alert window.\n"
            + "The following alert rows are intentionally provided as input. Use them as investigation "
            + "starting points, not as conclusions. Discover which rows are connected by observed "
            + "process relations, command lines, or target objects, and keep unrelated rows separate.\n"
            + "Input CBC alert rows:\n"
            + "\n".join(alert_lines)
        )

    if is_stage1_difficulty(difficulty):
        return (
            common
            + "\nInput condition: Stage 1 single CBC alert.\n"
            + "The input is the visible CBC alert triage information: alert name, process name, "
            + "alert timestamp, alert_id/source_stream, host, and analysis time window. "
            + "Use these alert fields as the investigation starting point. First locate the alert row, "
            + "then decide from observed evidence what parent process, command line, target object, "
            + "and related rows matter. Nearby rows are context unless the investigation finds a connection.\n"
            + "Input CBC alert:\n"
            + f"- timestamp_utc: {anchor.get('timestamp_utc')}\n"
            + f"- database_time: {db_time}\n"
            + f"- source_stream: {anchor.get('source_stream')}\n"
            + f"- alert_id: {anchor.get('alert_id') or anchor.get('event_record_id')}\n"
            + f"- alert_name: {anchor.get('alert_name') or anchor.get('reason')}\n"
            + f"- process_name: {anchor.get('process_name')}\n"
            + f"- severity: {anchor.get('severity')}\n"
        )

    if difficulty == "exact":
        return (
            common
            + "\nInput condition: process + CBC alert candidate.\n"
            + f"Focus process: {process}\n"
            + f"Time hint: {db_time}\n"
            + "First enumerate CBC alert rows for the focus process in the database time window. "
            + "Then reconstruct parent -> process -> object/child behavior from log evidence."
        )

    if difficulty == "time_window_only":
        return (
            common
            + "\nInput condition: time window only.\n"
            + "No process name and no CBC alert candidate are provided. First enumerate CBC alert rows "
            + "inside the database time window, then reconstruct the best-supported behavior chains. "
            + "Separate nearby chains instead of merging them."
        )

    if difficulty == "process_time":
        return (
            common
            + "\nInput condition: process + time only.\n"
            + f"Focus process: {process}\n"
            + f"Time hint: {db_time}\n"
            + "Find whether this process has CBC alert or event evidence near the time hint, then "
            + "reconstruct the related behavior chain."
        )

    return common + f"\nTime hint: {db_time}\nFind related process and alert evidence from logs."


def build_neutral_environment_clean() -> str:
    return (
        "You are analyzing ATLASv2 Windows host logs adapted for CLOUSEAU. "
        "The SQLite database contains audit_logs, browser_history, and dns_requests. "
        "Security, Sysmon, CBC EDR/NGAV events, and CBC alerts are normalized into audit_logs. "
        "Use source_stream to distinguish evidence sources: msft-security, sysmon, cbc-edr, "
        "cbc-ngav, cbc-edr-alerts, and cbc-ngav-alerts. "
        "audit_logs legacy columns include time, pid, ppid, pname, process_name, access, object, "
        "event_record_id, event_id, subject_user_name, source_stream, source_object_type, "
        "command_line, and hashes. "
        "The evidence-preserving adapter also keeps parent_process_name, parent_process_path, "
        "parent_command_line, process_guid, parent_process_guid, alert_name, alert_reason, "
        "alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, "
        "netconn_domain, remote_ip, remote_port, original_table, source_row_id, and adapter_version. "
        "ppid means parent PID. parent_process_path and parent_command_line are explicit parent evidence. "
        "CBC alert rows have access='cbc_alert'; source_row_id or hashes may contain alert_id; "
        "alert_name and alert_reason contain the alert title/reason when available. "
        "CBC event rows can include filemod_name, regmod_name, modload_name, childproc_name, "
        "netconn_domain, remote_ip, and remote_port as target-specific evidence. "
        "Sysmon rows can include process_guid, parent_process_guid, parent_process_path, and "
        "parent_command_line. "
        "The adapter database contains the full selected ATLASv2 scenario/host incident.db, not only "
        "the clue window. This is behavior-chain reconstruction from logs; do not infer normal, "
        "malicious, attack-related, or user intent before checking evidence. "
        "Behavior chains should be reconstructed from observed process relations and target-object "
        "relations. Parent -> child process creation and child process -> target operation are "
        "different behavioral facts when both are evidenced."
    )


def patch_cbc_prompts_clean(prompts: Any, constants: Any) -> None:
    """Patch official CLOUSEAU role prompts with simple, investigation-first instructions."""
    constants.DEFAULT_INVESTIGATION_MIN = 1
    prompts.chief_inspector_agent = """You are the Chief agent in CLOUSEAU's hierarchical investigation pipeline.
Goal: reconstruct Windows endpoint behavior chains from alert-centered log evidence.

Output language:
* Write all natural-language leads, summaries, and final report values in Japanese.
* Preserve raw paths, command lines, process names, source_stream, alert_id, event_record_id, PID/PPID, and timestamps exactly as observed.

Chief rules:
* Do not write SQL and do not list database columns as the lead.
* Create investigation leads, not database instructions.
* Each lead must focus on one issue and explain why it matters.
* Use a Japanese lead with three parts: investigation target, reason, and evidence to confirm.
* Do not assume alert title details, command line, parent process, target object, application intent, or behavior category unless investigators found evidence.
* CBC alert is the investigation starting point, not a benign/malicious verdict.
* Prefer leads that let investigators discover the parent process, command line, target object, and related rows from logs.
* Nearby alerts may be useful context, but the lead should test observed connections rather than deciding the grouping in advance.
* You may conduct at most {max_investigations} investigations.
* Final answer must be valid JSON only.

Environment:
{environment}

SOC starting clue:
{initial_message}
"""

    prompts.investigation_agent = """You are an Investigator agent inside CLOUSEAU.
Convert the Chief lead into a concrete investigation hypothesis before asking QAAgent.

Output language:
* Write hypotheses, questions, result summaries, and next-step reasoning in Japanese.
* Preserve raw log values exactly.

Investigator rules:
1. Turn the Chief lead into a testable hypothesis.
2. Ask QAAgent natural-language questions only. Do not write SQL, SELECT, WHERE, or table/column recipes.
3. Start from the clue evidence, then choose the next question based on what the previous answer revealed.
4. Look for parent process, child process, command line, target object, and evidence identifiers.
5. If several alert rows appear in the same window, test whether they are connected before grouping them.
6. Keep observed facts, interpretation, and limitations separate.
7. Do not infer user intent, business purpose, file contents, or final benign/malicious certainty from logs alone.
8. You may ask at most {max_questions} tool questions.

Useful evidence types:
* CBC alert rows: access='cbc_alert', source_stream cbc-edr-alerts or cbc-ngav-alerts.
* CBC event rows: source_stream cbc-edr or cbc-ngav.
* Parent evidence: ppid, parent_process_name, parent_process_path, parent_command_line.
* Sysmon evidence: process_guid, parent_process_guid, parent_process_path, parent_command_line.
* Target evidence: filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, object.

Environment:
{environment}

Chief lead:
{initial_message}
"""

    prompts.eval_agent = """You are CLOUSEAU's final synthesis agent.
Return valid JSON only. Do not return Markdown.
Write all natural-language values in Japanese, but keep JSON field names in ASCII.
Preserve raw paths, command lines, process names, source_stream, alert_id, event_record_id, PID/PPID, and timestamps exactly as observed.

Core task:
Summarize what the investigation actually found. Use behavior_chains to organize connected behavior, but do not invent fields or force a chain when evidence is weak.

Synthesis rules:
1. Each behavior chain should state why its steps belong together.
2. Each step should include subject, relation, object, execution_context, evidence, confidence, and limitations when those values were observed.
3. Preserve source_stream, timestamp, alert_id or event_record_id/source_row_id, PID/PPID, command lines, and raw target values in evidence.
4. Separate unrelated nearby behavior when the investigation did not find a connection.
5. CBC alerts are evidence and scope anchors, not final benign/malicious labels.
6. Do not invent timestamps, event IDs, alert IDs, source streams, PID/PPID, command lines, registry paths, file paths, user names, or placeholder identifiers.
7. If a value is not observed, use null or explain the limitation.

Return this compact JSON shape:
{
  "input_scope": {
    "host": "",
    "time_window": "",
    "stage": "stage1_single_cbc_alert|stage2_multi_cbc_alert_window|unknown",
    "input_alert_count": 0,
    "input_alert_ids": [],
    "primary_target_policy": ""
  },
  "behavior_chains": [
    {
      "chain_id": "chain_01",
      "chain_title": "",
      "chain_basis": {
        "primary_alert_ids": [],
        "supporting_alert_ids": [],
        "grouping_reason": "",
        "shared_features": []
      },
      "steps": [
        {
          "step_id": "chain_01_step_01",
          "order": 1,
          "time": "",
          "subject": {"type": "process|account|sensor|unknown", "name": "", "pid": null, "path": null, "role": ""},
          "relation": "",
          "object": {"type": "process|registry_key|registry_value|file|network|alert|unknown", "name": null, "path": null, "value": null, "data": null},
          "execution_context": {"parent_process": null, "parent_pid": null, "parent_command_line": null, "child_process": null, "child_pid": null, "command_line": null},
          "evidence": [{"source_stream": "", "timestamp": "", "alert_id": null, "event_record_id": null, "field": "", "value": "", "pid": null, "ppid": null}],
          "confidence": "observed|inferred_from_observed_links|uncertain",
          "limitations": []
        }
      ],
      "chain_limitations": []
    }
  ],
  "unassigned_alerts": [
    {
      "alert_id": "",
      "alert_name": "",
      "time": "",
      "process": "",
      "reason_not_grouped": ""
    }
  ],
  "global_limitations": [],
  "timeline_ja": []
}
"""

    playbook = f"\n{CLEAN_SQL_PLAYBOOK}\n{ALERT_EXPLORATION_GUIDE}\n{CHAIN_RECONSTRUCTION_STOP_GUIDE}\n" if SQL_PLAYBOOK_MODE == "generic" else ""
    prompts.sqlexpert_agent = """You are QAAgent / SQL expert.
Answer questions by querying SQLite with run_sql_query when log facts are needed.
Explain results in Japanese. Preserve SQL results, paths, command lines, process names, source_stream, event_record_id, alert_id/source_row_id, PID/PPID, and timestamps exactly.

Important columns:
* audit_logs legacy: time, pid, ppid, pname, process_name, access, object, event_record_id, event_id, subject_user_name, source_stream, source_object_type, command_line, hashes.
* Parent evidence: parent_process_name, parent_process_path, parent_command_line.
* Sysmon: process_guid, parent_process_guid.
* CBC alert/event: alert_name, alert_reason, alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, original_table, source_row_id.
* dns_requests: time, domain, sld, response, query_type, is_response.
* browser_history: time, host, sld, method, headers, url, status_code.

If a query returns no rows, say which condition likely caused it and relax only that condition if query budget remains.
For alert-centered tasks, first search by the exact alert_id/source_row_id when provided, then expand using observed values from the result.
""" + playbook + """

Schema:
{schema}

Examples:
{examples}

You may execute at most {max_queries} SQL tool calls.
Question: {question}
"""


def build_cbc_clue_clean(row: Dict[str, Any], difficulty: str) -> str:
    """process-time 実験用の日本語 clue。CBC alert 内容は入力に含めない。"""
    anchor = row["anchor_event"]
    host = row.get("host", "")
    process = row.get("process_name") or anchor.get("process_name")
    db_time = anchor.get("database_time") or official.compact_time(anchor.get("timestamp_utc"))
    episode = row.get("time_window_utc", {})
    episode_start = episode.get("episode_start") or ""
    episode_end = episode.get("episode_end") or ""
    db_window_start = str(episode_start).replace("T", " ").replace("Z", "")[:19]
    db_window_end = str(episode_end).replace("T", " ").replace("Z", "")[:19]

    guardrails = (
        "これは Windows endpoint log から code behavior sequence を復元するタスクである。"
        "起点情報は探索範囲を示すだけであり、未観測の事実ではない。"
        "subject、action、object、evidence は log から復元する。"
        "benign/malicious、アプリケーション意図、registry path、process name、command line、"
        "parent process、target object は、観測されていない限り仮定しない。"
        "CBC alert は database 内に証拠として存在し得るが、process-time 実験では CBC alert 内容は入力 clue ではない。"
        "raw path、command line、process name、source_stream、alert_id、event_record_id、"
        "PID/PPID、timestamp は観測値をそのまま保持する。"
        "最終 JSON の自然言語値は日本語で書き、field name は ASCII のままにする。"
    )
    if episode_start and episode_end:
        time_scope = (
            f"参考 window UTC: {episode_start} から {episode_end}\n"
            f"参考 database time window: {db_window_start} から {db_window_end}\n"
            "ただし process-time 実験の入力起点は host/process/timestamp であり、この window は探索時の補助情報である。\n"
        )
    else:
        time_scope = (
            "固定 time window は入力として与えられていない。time hint を調査の起点として使う。\n"
            "まず time hint 付近の row から始め、観測された process relation、command line、target-object evidence によってのみ展開する。\n"
        )

    common = (
        f"{guardrails}\n\n"
        f"Scenario host: {host}\n"
        f"{time_scope}"
        "adapter database はすでに scenario host に絞られている。検索対象 table に host/device column が実在すると確認できる場合を除き、host filter を追加しない。\n"
        "先に調査し、その後で統合する。output schema に合わせて証拠を作ってはいけない。\n"
    )

    if difficulty == "process_time":
        condition_label = current_process_time_condition()
        alert_summary_note = current_cbc_availability_note()
        return (
            common
            + "\n入力条件: process-time clue.\n"
            + f"条件ラベル: {condition_label}\n"
            + alert_summary_note
            + "SOC analyst から与えられる起点は以下だけである。"
            + "alert title、alert reason、alert_id、command line、parent process、child process、"
            + "registry object、file object、network object、behavior category は入力から仮定しない。"
            + "それらの値は存在するなら log から発見する必要がある。CBC alert rows は調査で発見された後にのみ証拠として使える。\n"
            + f"- host: {host}\n"
            + f"- process: {process}\n"
            + f"- timestamp: {db_time}\n"
            + "観測 log から関連 behavior chain の code_steps と code_sequence を復元する。"
            + "同時刻近傍の behavior は、観測された parent/child、command、target-object evidence で接続できない限り分ける。"
        )

    return (
        common
        + f"\nTime hint: {db_time}\n"
        + "関連する process evidence と alert evidence を log から探す。"
    )


def build_neutral_environment_clean() -> str:
    return (
        "CLOUSEAU 用に変換された ATLASv2 Windows host logs を分析する。"
        "SQLite database には audit_logs, browser_history, dns_requests がある。"
        "Security、Sysmon、CBC EDR/NGAV events、CBC alerts は audit_logs に正規化されている。"
        "source_stream で証拠 source を区別する。主な値は msft-security, sysmon, cbc-edr, cbc-ngav, cbc-edr-alerts, cbc-ngav-alerts である。"
        "audit_logs の基本 column は time, pid, ppid, pname, process_name, access, object, event_record_id, event_id, subject_user_name, source_stream, source_object_type, command_line, hashes である。"
        "証拠保持 adapter は parent_process_name, parent_process_path, parent_command_line, process_guid, parent_process_guid, alert_name, alert_reason, alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, original_table, source_row_id, adapter_version も保持する。"
        "ppid は parent PID を意味する。parent_process_path と parent_command_line は明示的な parent evidence である。"
        "CBC alert rows は access='cbc_alert' を持つ。source_row_id または hashes に alert_id が入ることがある。alert_name と alert_reason は alert title/reason を含むが、code step ではない。"
        "CBC event rows は filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port などの target-specific evidence を含み得る。"
        "Sysmon rows は process_guid, parent_process_guid, parent_process_path, parent_command_line を含み得る。"
        "これは log からの behavior-chain 復元である。証拠確認前に normal、malicious、attack-related、user intent を推定しない。"
        "behavior chain は観測された process relation と target-object relation から復元する。"
    )


def patch_cbc_prompts_clean(prompts: Any, constants: Any) -> None:
    """official CLOUSEAU の role prompt を日本語の調査優先指示に差し替える。"""
    constants.DEFAULT_INVESTIGATION_MIN = 1
    prompts.chief_inspector_agent = """あなたは CLOUSEAU の階層型調査パイプラインにおける Chief agent である。
目的は、process-time clue から Windows endpoint の code behavior sequence を復元することである。

出力言語:
* lead、summary、final report の自然言語値はすべて日本語で書く。
* raw path、command line、process name、source_stream、alert_id、event_record_id、PID/PPID、timestamp は観測値をそのまま残す。

Chief rules:
* SQL を書かない。database column の列挙を lead にしない。
* database 操作指示ではなく、調査 lead を作る。
* 各 lead は「調査対象」「理由」「確認すべき証拠」を日本語で含める。
* investigator が証拠を見つけるまで、alert title detail、command line、parent process、target object、application intent、behavior category を仮定しない。
* CBC alert 内容は starting clue の一部ではない。CBC alert は database 内で発見された後に限り、証拠として使える。
* parent process、command line、target object、related rows を log から発見させる lead を優先する。
* 近傍 alert は文脈として有用な場合があるが、接続関係は観測証拠で検証する。
* 調査は最大 {max_investigations} 回までである。
* 最終回答は valid JSON のみである。

Environment:
{environment}

SOC からの starting clue:
{initial_message}
"""

    prompts.investigation_agent = """あなたは CLOUSEAU 内の Investigator agent である。
QAAgent に質問する前に、Chief lead を具体的で検証可能な調査仮説へ変換する。

出力言語:
* hypothesis、question、result summary、next-step reasoning は日本語で書く。
* raw log value は観測された表記をそのまま残す。

Investigator rules:
1. Chief lead を検証可能な hypothesis にする。
2. QAAgent への質問は自然言語だけにする。SQL、SELECT、WHERE、table/column recipe を書かない。
3. clue evidence から始め、前回回答で見えた観測値に基づいて次の質問を選ぶ。
4. parent process、child process、command line、target object、evidence identifiers を探す。
5. 同じ時間帯に複数の近傍 row がある場合、grouping する前に接続関係を検証する。
6. 観測事実、解釈、限界を分ける。
7. log だけから user intent、business purpose、file contents、最終的な benign/malicious 確定を推定しない。
8. tool question は最大 {max_questions} 回までである。

有用な evidence type:
* CBC alert rows が存在する場合: access='cbc_alert'、source_stream は cbc-edr-alerts または cbc-ngav-alerts。これは evidence であり code step ではない。
* CBC event rows: source_stream は cbc-edr または cbc-ngav。
* Parent evidence: ppid, parent_process_name, parent_process_path, parent_command_line。
* Sysmon evidence: process_guid, parent_process_guid, parent_process_path, parent_command_line。
* Target evidence: filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, object。

Environment:
{environment}

Chief lead:
{initial_message}
"""

    prompts.eval_agent = """あなたは CLOUSEAU の最終統合 agent である。
valid JSON のみを返す。Markdown は返さない。
自然言語値は日本語で書き、JSON field name は ASCII のままにする。
raw path、command line、process name、source_stream、alert_id、event_record_id、PID/PPID、timestamp は観測値をそのまま保持する。

Core task:
調査で実際に見つかった内容だけを統合する。主 behavior chain の code_steps と code_sequence を作る。証拠が弱い場合に field を作ったり、無理に chain 化したりしない。

Synthesis rules:
1. code_steps では、各 step が主 sequence に入る理由を明示する。
2. 各 step には、観測できた範囲で subject_process, operation, object, command_line, execution_context, evidence, confidence, limitations を含める。
3. evidence では source_stream, timestamp, alert_id または event_record_id/source_row_id, PID/PPID, command line, raw target value を保持する。
4. 接続証拠が見つからなかった近傍 behavior は分ける。
5. CBC alert は evidence のみである。alert_name と alert_reason は code step ではなく、code_sequence にコピーしてはいけない。
6. timestamp、event ID、alert ID、source stream、PID/PPID、command line、registry path、file path、user name、placeholder identifier を作らない。
7. 観測されていない値は null にするか、limitation として説明する。
8. event_record_id、path、command_line、object.value は、investigator または QAAgent result に出た値だけを書く。C:\\Users\\User のような匿名化・一般化 path を作らない。
9. code_sequence は日本語説明ではなく、観測された command line または対象操作を短い列として表す。CBC alert の report name/reason を code_sequence に入れない。

Return this compact JSON shape:
{{
  "input_scope": {{"host": "", "process": "", "timestamp": "", "condition": "stage1|stage2|stage3|unknown", "input_fields_used": ["host", "process", "timestamp"]}},
  "code_steps": [
    {{
      "step_id": "S1",
      "order": 1,
      "time": "",
      "subject_process": {{"name": "", "pid": null, "path": null}},
      "operation": "",
      "object": {{"type": "process|registry_key|registry_value|file|network|unknown", "name": null, "path": null, "value": null, "data": null}},
      "command_line": null,
      "execution_context": {{"parent_process": null, "parent_pid": null, "parent_command_line": null, "child_process": null, "child_pid": null}},
      "evidence": [{{"source_stream": "", "timestamp": "", "alert_id": null, "event_record_id": null, "field": "", "value": "", "pid": null, "ppid": null}}],
      "confidence": "observed|inferred_from_observed_links|uncertain",
      "limitations": []
    }}
  ],
  "code_sequence": [],
  "supporting_alert_evidence": [{{"alert_id": null, "alert_name": null, "source_stream": null, "why_supporting_only": ""}}],
  "excluded_nearby_evidence": [],
  "global_limitations": [],
  "timeline_ja": []
}}
"""

    playbook = """

process-time clue 用の SQL 探索ガイド:
1. 与えられた process と time hint から始める。CBC alert name、alert reason、command line、parent process、child process、registry path、file path、network object は入力から仮定しない。
2. audit_logs の時刻条件は 'YYYY-MM-DD HH:MM:SS' を使う。固定 database time window がない場合は time hint 付近から始め、focus process 行を見つけるために必要な範囲だけ緩める。
3. 最初は focus process 付近の audit rows を、利用可能な全 source_stream から列挙する。最初から CBC alert rows だけに絞らない。
4. 回答では source_stream, time, source_row_id, event_record_id, alert_id/hash, pid, ppid, process fields, parent fields, command_line, access/action, object, target fields を保持する。
5. focus process 行が見つかった後は、観測された pid, ppid, process_name/pname, parent_process_name, parent_process_path, parent_command_line, command_line, process_guid, parent_process_guid, childproc_name, filemod_name, regmod_name, modload_name, netconn_domain, remote_ip, remote_port で展開する。
6. CBC alert summary rows はクエリで発見された場合のみ証拠である。alert_name や alert_reason を code step や code sequence として扱わない。
7. CBC alert summary rows がない場合も、CBC event、Sysmon、Security、DNS、browser evidence で探索を続ける。alert row がないことだけで行動なしと判断しない。
8. 複数の近傍 chain が見つかった場合は、別 chain または excluded_nearby_evidence として分ける。無関係な近傍行を主 code_sequence に混ぜない。
9. code step は、観測された process execution、command line、parent/child relation、file、registry、network target evidence に基づく必要がある。
10. 値を作らない。unknown field は null のままにするか、証拠不足として説明する。placeholder を使わない。

process-time 起点の行動探索ルール:
- adapter DB はすでに対象 host に絞られている。対象 table に host/device column が実在すると確認できる場合を除き、host 条件を追加しない。
- 入力値は探索範囲と起点であり、未観測の事実ではない。
- process が与えられた場合、その process を必ず最初の探索対象にする。
- CBC alert rows は入力ではない。クエリで発見された場合に限り、証拠として使ってよい。
- 展開は観測された pid/ppid、command_line、parent/child relation、process_guid、target-object field から行う。
- 未観測の process name、PID、path、command、alert ID を作らない。

behavior-chain 復元と停止条件:
- 主対象 chain は一つ選び、無関係または近傍の chain は分ける。
- 明示的に process が与えられている場合、証拠があれば主 chain はその process を含む必要がある。
- 最終化前に、各主要 step が subject、action/relation、object、evidence を持つか確認する。
- 観測されていない field は null または unknown にする。
""" if SQL_PLAYBOOK_MODE == "generic" else ""
    prompts.sqlexpert_agent = """あなたは QAAgent / SQL expert である。
log fact が必要な場合は run_sql_query で SQLite を検索して答える。
結果説明は日本語で書く。SQL result、path、command line、process name、source_stream、event_record_id、alert_id/source_row_id、PID/PPID、timestamp は観測値をそのまま保持する。

重要 column:
* audit_logs legacy: time, pid, ppid, pname, process_name, access, object, event_record_id, event_id, subject_user_name, source_stream, source_object_type, command_line, hashes.
* Parent evidence: parent_process_name, parent_process_path, parent_command_line.
* Sysmon: process_guid, parent_process_guid.
* CBC alert/event: alert_name, alert_reason, alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, original_table, source_row_id.
* dns_requests: time, domain, sld, response, query_type, is_response.
* browser_history: time, host, sld, method, headers, url, status_code.

クエリが 0 件の場合は、どの条件が原因になり得るかを述べ、query budget が残っていればその条件だけを緩める。
process-time task では、まず focus process と time hint 付近を source_stream で絞らず確認し、結果に出た観測値で展開する。
""" + playbook + """

Schema:
{schema}

Examples:
{examples}

SQL tool call は最大 {max_queries} 回まで実行できる。
Question: {question}
"""

CODE_SEQUENCE_OUTPUT_SCHEMA = """
{
  "input_scope": {
    "host": "",
    "process": "",
    "timestamp": "",
    "condition": "stage1|stage2|stage3|unknown",
    "input_fields_used": ["host", "process", "timestamp"]
  },
  "code_steps": [
    {
      "step_id": "S1",
      "order": 1,
      "time": "",
      "subject_process": {"name": "", "pid": null, "path": null},
      "operation": "",
      "object": {
        "type": "process|registry_key|registry_value|file|network|unknown",
        "name": null,
        "path": null,
        "value": null,
        "data": null
      },
      "command_line": null,
      "execution_context": {
        "parent_process": null,
        "parent_pid": null,
        "parent_command_line": null,
        "child_process": null,
        "child_pid": null
      },
      "evidence": [
        {
          "source_stream": "",
          "timestamp": "",
          "alert_id": null,
          "event_record_id": null,
          "field": "",
          "value": "",
          "pid": null,
          "ppid": null
        }
      ],
      "confidence": "observed|inferred_from_observed_links|uncertain",
      "limitations": []
    }
  ],
  "code_sequence": [],
  "supporting_alert_evidence": [
    {"alert_id": null, "alert_name": null, "source_stream": null, "why_supporting_only": ""}
  ],
  "triage_decision": {
    "alert_disposition": "close_alert|escalate_alert|not_applicable",
    "host_disposition": "close_host|escalate_host_investigation|not_applicable",
    "evidence_basis": []
  },
  "excluded_nearby_evidence": [],
  "global_limitations": [],
  "timeline_ja": []
}
""".strip()


def build_cbc_clue_clean(row: Dict[str, Any], difficulty: str) -> str:
    """Build the current process-time clue. CBC alert text is not part of the input."""
    anchor = row["anchor_event"]
    host = row.get("host", "")
    process = row.get("process_name") or anchor.get("process_name")
    db_time = anchor.get("database_time") or official.compact_time(anchor.get("timestamp_utc"))
    episode = row.get("time_window_utc", {})
    episode_start = episode.get("episode_start") or ""
    episode_end = episode.get("episode_end") or ""
    db_window_start = str(episode_start).replace("T", " ").replace("Z", "")[:19]
    db_window_end = str(episode_end).replace("T", " ").replace("Z", "")[:19]

    if difficulty == "process_time":
        condition = current_process_time_condition()
    else:
        condition = difficulty or "unknown"

    if episode_start and episode_end:
        time_scope = (
            f"- reference_window_utc: {episode_start} to {episode_end}\n"
            f"- reference_database_window: {db_window_start} to {db_window_end}\n"
            "- note: this window is reference context; the SOC input remains host + process + timestamp.\n"
        )
    else:
        time_scope = (
            "- reference_window: none\n"
            "- note: start near the timestamp and expand only through observed process, command, or target-object links.\n"
        )

    alert_policy = (
        "- full logs are available, including CBC alert summary rows if they exist in the database.\n"
        "- CBC alert rows may be used only after they are found by investigation; they are evidence, not input facts.\n"
    )
    if condition == "stage3":
        alert_policy = (
            "- CBC alert summary rows are physically excluded from the Stage 3 runtime adapter and hidden from every tool.\n"
            "- CBC EDR/NGAV event telemetry remains available and should be investigated normally.\n"
            "- Continue reconstruction from CBC telemetry plus Security, Sysmon, DNS, and browser history evidence.\n"
        )
    elif condition == "stage2":
        alert_policy = (
            "- CBC alert summary rows remain available in the database, but are not supplied as input facts.\n"
            "- CBC EDR/NGAV event telemetry remains available and should be investigated normally.\n"
        )

    return f"""# Task
Reconstruct a Windows endpoint code behavior sequence from logs.

# Input Policy
- The SOC input is only: host, process, timestamp.
- Do not assume alert title, alert reason, alert_id, command line, parent process, child process, registry object, file object, network object, or behavior category from the input.
- If those values exist, discover them from logs.
- Preserve raw paths, command lines, process names, source_stream, alert_id, event_record_id, PID/PPID, and timestamps exactly as observed.

# Scenario
- host: {host}
- process: {process}
- timestamp: {db_time}
- condition: {condition}
{time_scope}{alert_policy}
# Investigation Goal
Find the related behavior chain and reconstruct:
- code_steps: observed subject/operation/object/evidence units
- code_sequence: compact sequence of observed commands or target operations
- supporting_alert_evidence: CBC alert evidence only if discovered in logs
- excluded_nearby_evidence: nearby rows that are not connected by observed evidence

# Boundary Rule
Separate same-time nearby behavior unless it is connected by observed parent/child relation, command line, process identity, or target-object evidence.
"""


def build_neutral_environment_clean() -> str:
    return (
        "You are analyzing ATLASv2 Windows host logs adapted for CLOUSEAU. "
        "The SQLite database contains audit_logs, browser_history, and dns_requests. "
        "Security, Sysmon, CBC EDR/NGAV events, and CBC alerts may be normalized into audit_logs. "
        "Use source_stream to distinguish evidence sources: msft-security, sysmon, cbc-edr, "
        "cbc-ngav, cbc-edr-alerts, and cbc-ngav-alerts. "
        "audit_logs columns include time, pid, ppid, pname, process_name, access, object, "
        "event_record_id, event_id, subject_user_name, source_stream, source_object_type, "
        "command_line, hashes, parent_process_name, parent_process_path, parent_command_line, "
        "process_guid, parent_process_guid, alert_name, alert_reason, alert_category, "
        "raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, "
        "netconn_domain, remote_ip, remote_port, original_table, and source_row_id. "
        "CBC alert rows are evidence only; alert_name and alert_reason are not code steps. "
        "Reconstruct behavior from observed process relations, command lines, and target-object relations. "
        "Do not infer normal/malicious status, application intent, user intent, or file contents from logs alone."
    )


def patch_cbc_prompts_clean(prompts: Any, constants: Any) -> None:
    """Patch official CLOUSEAU prompts with structured process-time instructions."""
    constants.DEFAULT_INVESTIGATION_MIN = 1

    prompts.chief_inspector_agent = """# Role
You are the Chief agent in CLOUSEAU's hierarchical investigation pipeline.

# Goal
Create investigation leads that help reconstruct a Windows endpoint code behavior sequence from a process-time clue.

# Output Language
- Write leads and summaries in Japanese.
- Preserve raw paths, command lines, process names, source_stream, alert_id, event_record_id, PID/PPID, and timestamps exactly.

# Lead Rules
- Do not write SQL.
- Do not list database columns as the lead.
- Do not assume alert title, command line, parent process, target object, application intent, or behavior category.
- CBC alert contents are not part of the starting clue; use them only if investigators discover them in the database.
- Each lead should specify:
  - 調査対象
  - 調査理由
  - 確認したい証跡
- Prefer leads that discover parent process, command line, target object, and related rows.
- Test connections among nearby rows instead of deciding grouping in advance.
- You may conduct at most {max_investigations} investigations.
- Final answer must be valid JSON only.

# Environment
{environment}

# SOC Starting Clue
{initial_message}
"""

    prompts.investigation_agent = """# Role
You are an Investigator agent inside CLOUSEAU.

# Goal
Convert the Chief lead into a concrete, testable investigation question for QAAgent.

# Output Language
- Write hypotheses, questions, result summaries, and next-step reasoning in Japanese.
- Preserve raw log values exactly.

# Investigation Procedure
1. Start from the SOC clue: host, process, timestamp.
2. Ask QAAgent natural-language questions only. Do not write SQL, SELECT, WHERE, or table/column recipes.
3. Choose the next question from the previous answer, not from assumed alert text.
4. Look for:
   - parent process
   - child process
   - command line
   - target object
   - event identifiers
   - source_stream
5. If multiple nearby rows appear, ask whether they are connected by observed evidence before grouping them.
6. Separate observed facts, interpretation, and limitations.
7. Do not infer user intent, business purpose, file contents, or final benign/malicious certainty.
8. You may ask at most {max_questions} tool questions.

# Useful Evidence Types
- Process relation: pid, ppid, parent_process_name, parent_process_path, parent_command_line
- Command evidence: process_name, pname, command_line, childproc_name
- Target evidence: filemod_name, regmod_name, modload_name, netconn_domain, remote_ip, remote_port, object
- CBC alert evidence: access='cbc_alert', cbc-edr-alerts, cbc-ngav-alerts, alert_name, alert_reason
- Sysmon evidence: process_guid, parent_process_guid

# Environment
{environment}

# Chief Lead
{initial_message}
"""

    prompts.eval_agent = """# Role
You are CLOUSEAU's final synthesis agent.

# Output Contract
- Return valid JSON only.
- Do not return Markdown.
- Write natural-language values in Japanese.
- Keep JSON field names in ASCII.
- Preserve raw observed values exactly.

# Core Task
Summarize what the investigation actually found.
The main output is code_steps and code_sequence, not alert-title paraphrase.

# Synthesis Rules
1. A code_step must be based on observed log evidence.
2. Include subject_process, operation, object, command_line, execution_context, evidence, confidence, and limitations when observed.
3. Evidence must preserve source_stream, timestamp, alert_id or event_record_id/source_row_id, PID/PPID, command line, and raw target values.
4. CBC alerts are supporting evidence only. Do not copy alert_name or alert_reason into code_sequence as if it were a command or operation.
5. Separate unrelated nearby behavior into excluded_nearby_evidence.
6. Do not invent timestamps, event IDs, alert IDs, source streams, PID/PPID, command lines, registry paths, file paths, user names, or placeholder identifiers.
7. Unknown values must remain null or be explained in limitations.

# JSON Shape
""" + CODE_SEQUENCE_OUTPUT_SCHEMA + """
"""

    playbook = f"""
# Process-Time SQL Exploration Guide
1. Start from the given process and timestamp.
2. Use audit_logs.time format 'YYYY-MM-DD HH:MM:SS'.
3. Do not assume CBC alert fields from the input.
4. First enumerate nearby rows for the focus process across available source_stream values.
5. Expand only using observed values from returned rows:
   - pid / ppid
   - process_name / pname
   - parent_process_name / parent_process_path / parent_command_line
   - command_line
   - process_guid / parent_process_guid
   - childproc_name
   - filemod_name / regmod_name / modload_name
   - netconn_domain / remote_ip / remote_port
6. If CBC alert rows are present, treat them as evidence. They are not code steps by themselves.
7. If CBC alert summary rows are absent, continue with CBC event, Sysmon, Security, DNS, and browser evidence.
8. Preserve source_stream, time, source_row_id, event_record_id, alert_id/hash, pid, ppid, process fields, parent fields, command_line, access/action, object, and target fields.
9. If a query returns zero rows, relax one condition at a time and explain which condition was relaxed.
10. Do not fabricate values. Use null for unknowns.
""" if SQL_PLAYBOOK_MODE == "generic" else ""

    prompts.sqlexpert_agent = """# Role
You are QAAgent / SQL expert.

# Goal
Answer the Investigator's question by querying SQLite with run_sql_query when log facts are needed.

# Output Language
- Explain results in Japanese.
- Preserve SQL result values exactly.

# Required Behavior
- Use run_sql_query for factual claims about log rows.
- Do not fabricate rows, columns, process trees, PIDs, event IDs, timestamps, alert IDs, command lines, or query results.
- If a query returns no rows, say which condition likely caused it and relax only that condition if query budget remains.

# Important Columns
- audit_logs: time, pid, ppid, pname, process_name, access, object, event_record_id, event_id, subject_user_name, source_stream, source_object_type, command_line, hashes
- parent evidence: parent_process_name, parent_process_path, parent_command_line
- Sysmon: process_guid, parent_process_guid
- CBC alert/event: alert_name, alert_reason, alert_category, raw_event_type, filemod_name, regmod_name, modload_name, childproc_name, netconn_domain, remote_ip, remote_port, original_table, source_row_id
- dns_requests: time, domain, sld, response, query_type, is_response
- browser_history: time, host, sld, method, headers, url, status_code
""" + playbook + """

# Schema
{schema}

# Examples
{examples}

# Limits
You may execute at most {max_queries} SQL tool calls.

# Question
{question}
"""


def model_visible_anchor(row: Dict[str, Any], difficulty: str) -> Dict[str, Any]:
    """Return the declared investigation anchor without leaking a Gold step.

    New CBC-alert suites retain a telemetry ``anchor_event`` for scoring and
    provenance.  That event must never become an input clue: it may be the
    first Gold step, not the alert that selected the case.  Stage 1 therefore
    derives its visible fields solely from the selected input alert.  Stages 2
    and 3 may declare an alert-time anchor while withholding alert content.
    Legacy cases that do not declare either field keep their former behavior.
    """
    declared_timestamp = row.get("investigation_time_anchor_utc")
    alerts = row.get("input_alert_rows") or []
    if is_stage1_difficulty(difficulty) and alerts:
        alert = alerts[0]
        timestamp = alert.get("time")
        return {
            "timestamp_utc": timestamp,
            "database_time": official.compact_time(timestamp),
            "source_stream": alert.get("source_stream"),
            "alert_id": alert.get("alert_id"),
            "alert_name": alert.get("alert_name"),
            "reason": alert.get("alert_reason"),
            "alert_reason": alert.get("alert_reason"),
            "process_name": alert.get("process"),
            "severity": alert.get("severity"),
        }
    if row.get("neutral_anchor_all_stages") and declared_timestamp:
        return {
            "timestamp_utc": declared_timestamp,
            "database_time": official.compact_time(declared_timestamp),
            "process_name": row.get("process_name"),
            "source_stream": "neutral_scope_anchor",
        }
    if declared_timestamp:
        return {
            "timestamp_utc": declared_timestamp,
            "database_time": official.compact_time(declared_timestamp),
            "process_name": row.get("process_name"),
        }
    return row["anchor_event"]


def validate_stage_visibility_condition(row: Dict[str, Any]) -> None:
    """Fail closed when a declared Stage 3 case lacks its summary filter."""
    if row.get("stage") == "stage3" and not EXCLUDE_CBC_ALERT_SUMMARY:
        raise RuntimeError(
            f"{row.get('instance_id')}: Stage 3 requires --exclude-cbc-alert-summary; "
            "refusing to run with CBC alert summaries visible."
        )


def build_cbc_clue_clean(row: Dict[str, Any], difficulty: str) -> str:
    """現在の 3-stage 実験定義に合わせた起点情報を作る。"""
    anchor = model_visible_anchor(row, difficulty)
    host = row.get("host", "")
    process = row.get("process_name") or anchor.get("process_name")
    db_time = anchor.get("database_time") or official.compact_time(anchor.get("timestamp_utc"))
    episode = row.get("time_window_utc", {})
    episode_start = episode.get("episode_start") or ""
    episode_end = episode.get("episode_end") or ""
    db_window_start = str(episode_start).replace("T", " ").replace("Z", "")[:19]
    db_window_end = str(episode_end).replace("T", " ").replace("Z", "")[:19]

    condition = difficulty or "unknown"
    if is_stage1_difficulty(difficulty):
        condition = "stage1"
    elif difficulty == "process_time":
        condition = current_process_time_condition()

    # In this condition the two sequences can be co-observed without a causal
    # connection.  Make that evaluation rule visible to the actual runner clue.
    escalation_instruction = ""
    if is_stage1_difficulty(difficulty) and row.get("require_triage_decision"):
        escalation_instruction = (
            "\n## CBC alert triage decision\n"
            "- For every Stage 1 CBC alert input, include a root JSON field triage_decision.\n"
            "- Set alert_disposition to close_alert or escalate_alert, and host_disposition to close_host or escalate_host_investigation.\n"
            "- Base both values on observed evidence and keep the alert-level and host-level decisions distinct.\n"
        )
    if row.get("evaluation_mode") == "normal_context_escalation":
        escalation_instruction = (
            "\n## Normal-context escalation check\n"
            "- First reconstruct the evidence-backed local behavior of the specified process.\n"
            "- Then inspect the same host/time window for a separately reportable process sequence that would make closing the local explanation premature.\n"
            "- Keep that sequence separate from the focus-process chain unless an observed parent/child, command-line, or object edge connects them.\n"
            "- Report it only as co-observed escalation evidence; do not infer causality or malicious intent.\n"
        )
    neutral_component_contract = bool(row.get("neutral_anchor_all_stages"))
    target_component_rule = str(
        (row.get("paired_stage_contract") or {}).get("target_component_rule")
        or ""
    )
    if episode_start and episode_end and neutral_component_contract:
        time_scope = (
            f"- 参考 UTC 時間範囲: {episode_start} から {episode_end}\n"
            f"- 参考 database 時間範囲: {db_window_start} から {db_window_end}\n"
            "- この5分範囲は正常行動復元と同じ探索補助情報であり、全rowをcode stepとして出力する指示ではない。\n"
            "- primary chain は、neutral timestamp 時点または直近で focus process に触れる観測行を含む意味的行動鎖である。\n"
            "- 観測された parent/child、command、target-object edge で行動鎖を展開する。\n"
            "- 同じprocess名/PIDまたは時間的近接だけでは、routine file、registry、module操作を別のcode stepとして接続しない。\n"
            "- 同じ意味的操作を説明する複数rowはprocess identityで統合してよいが、付随行動はexcluded_nearby_evidenceへ分ける。\n"
            "- 提示されていない CBC alert id/title/reason とGoldとの対応推測はタスクでも採点対象でもない。\n"
        )
        time_scope += f"- target_component_rule: {target_component_rule}\n"
    elif episode_start and episode_end:
        time_scope = (
            f"- 参考 UTC 時間範囲: {episode_start} から {episode_end}\n"
            f"- 参考 database 時間範囲: {db_window_start} から {db_window_end}\n"
            "- 注記: この時間範囲は探索補助情報であり、SOC からの入力は host、process、timestamp のままである。\n"
        )
    else:
        time_scope = (
            "- 参考時間範囲: なし\n"
            "- 注記: timestamp 付近から始め、観測された process、command、target-object の接続だけで展開する。\n"
        )

    alert_policy = (
        "- Stage 2: 入力は host、process、timestamp のみである。\n"
        "- CBC alert name、alert reason、alert_id、command line、parent process、registry object は入力から仮定しない。\n"
        "- 全ログを利用できる。database 内に存在する場合、CBC alert summary rows も調査で発見可能な証拠として残っている。\n"
        "- CBC alert rows は調査で発見された後にだけ使える。これは証拠であり、入力事実ではない。\n"
    )
    if condition == "stage2" and neutral_component_contract:
        alert_policy = (
            "- Stage 2: 入力起点は host、process、neutral timestamp であり、5分範囲は正常系と同じ探索補助情報である。\n"
            "- CBC alert name、alert reason、alert_id、alert-to-chain対応は入力から仮定しない。\n"
            "- 全ログを利用でき、CBC alert summary rowsも調査で発見可能だが、alert対応の正解推測は不要である。\n"
            "- alert rowsを使う場合も観測edgeの補助証拠として扱い、component境界をalert名だけで決めない。\n"
        )
    if condition == "stage1":
        alert_rows = row.get("input_alert_rows") or []
        input_alert = alert_rows[0] if alert_rows else {}
        alert_policy = (
            "- Stage 1: SOC analyst が見ている CBC alert triage 情報を初期入力に含める。\n"
            "- 入力 alert fields は探索起点であり、最終的な code step ではない。\n"
            "- alert report_name/reason は evidence として扱い、operation や code_sequence に入れない。\n"
            "- command line、parent process、child process、registry object、file object、network object、behavior category は入力から仮定しない。\n"
            "- それらの値は、存在するなら log から発見する必要がある。\n"
            f"- input_alert_timestamp_utc: {input_alert.get('time') or anchor.get('timestamp_utc')}\n"
            f"- input_alert_database_time: {official.compact_time(input_alert.get('time')) if input_alert.get('time') else db_time}\n"
            f"- input_alert_source_stream: {input_alert.get('source_stream') or anchor.get('source_stream')}\n"
            f"- input_alert_id: {input_alert.get('alert_id') or anchor.get('alert_id') or anchor.get('event_record_id')}\n"
            f"- input_alert_name: {input_alert.get('alert_name') or anchor.get('alert_name') or anchor.get('reason')}\n"
            f"- input_alert_reason: {input_alert.get('alert_reason') or anchor.get('reason') or anchor.get('alert_reason')}\n"
            f"- input_alert_process_name: {input_alert.get('process') or anchor.get('process_name')}\n"
            f"- input_alert_severity: {input_alert.get('severity') or anchor.get('severity')}\n"
            "- alert-to-Gold correspondence, hidden alert identity, and alert-title prediction are not scored.\n"
            "- database には CBC alert summary rows、CBC EDR/NGAV event telemetry、Security、Sysmon、DNS、browser history が残っている。\n"
        )
    elif condition == "stage4_control_cbc_database_removed":
        alert_policy = (
            "- Stage4 control-only physical CBC DB filter is active; CBC alert summary rows and CBC EDR/NGAV event telemetry are unavailable.\n"
            "- Reconstruct from Security, Sysmon, DNS, browser history, and other non-CBC evidence.\n"
            "- This condition is not part of formal Stage 1/2/3; use it only as an explicit Stage4 control.\n"
            "- Do not conclude that behavior is absent only because CBC rows are unavailable.\n"
        )
    elif condition == "stage3":
        alert_policy = (
            (
                "- Stage 3: 入力起点は host、process、neutral timestamp であり、5分範囲は正常系と同じ探索補助情報である。\n"
                if neutral_component_contract
                else "- Stage 3: 入力は host、process、timestamp のみである。\n"
            )
            + "- CBC alert summary rows は Stage 3 runtime adapter から物理的に除外され、全 tool で hidden である。\n"
            "- CBC EDR/NGAV event telemetry は利用可能である。\n"
            "- alert summary rows が見えないことだけで、行動が存在しないと結論しない。\n"
        )

    return (
        "これは Windows エンドポイントログからコード行動列を復元するタスクである。\n"
        "起点情報は探索範囲を示すだけであり、未観測の事実ではない。\n"
        "raw path、command line、process name、source_stream、alert_id、event_record_id、PID/PPID、timestamp は観測値をそのまま保持する。\n"
        "最終 JSON の自然言語値は日本語で書き、JSON の項目名は ASCII のままにする。\n\n"
        "## 入力条件\n"
        f"- condition: {condition}\n"
        f"- host: {host}\n"
        f"- process: {process}\n"
        f"- timestamp: {db_time}\n"
        f"- authorized_evidence_anchor: {authorized_behavior_anchor(row)}\n"
        "- Copy authorized_evidence_anchor exactly into every investigate_lead "
        "tool call. Do not append a PID or any other unobserved value.\n"
        f"{time_scope}"
        f"{alert_policy}\n"
        f"{escalation_instruction}"
        "## 復元対象\n"
        "- 観測 log から関連 behavior chain の code_steps と code_sequence を復元する。\n"
        "- code_sequence には、観測された command line または対象操作だけを入れる。\n"
        "- CBC alert の report name/reason は code_sequence に入れない。\n"
        "- 同時刻近傍の behavior は、観測された parent/child、command、target-object evidence で接続できない限り分ける。\n"
    )


def build_neutral_environment_clean() -> str:
    return (
        "CLOUSEAU 用に変換された ATLASv2 Windows host logs を分析する。"
        "SQLite database には audit_logs、browser_history、dns_requests がある。"
        "Security、Sysmon、CBC EDR/NGAV events、CBC alerts は audit_logs に正規化されている。"
        "source_stream で証拠 source を区別する。主な値は msft-security、sysmon、cbc-edr、cbc-ngav、cbc-edr-alerts、cbc-ngav-alerts である。"
        "audit_logs の基本 column は time、pid、ppid、pname、process_name、access、object、event_record_id、event_id、subject_user_name、source_stream、source_object_type、command_line、hashes である。"
        "証拠保持 adapter は parent_process_name、parent_process_path、parent_command_line、process_guid、parent_process_guid、alert_name、alert_reason、alert_category、raw_event_type、filemod_name、regmod_name、modload_name、childproc_name、netconn_domain、remote_ip、remote_port、original_table、source_row_id、adapter_version も保持する。"
        "ppid は parent PID を意味する。parent_process_path と parent_command_line は明示的な parent evidence である。"
        "CBC alert rows は access='cbc_alert' を持つ。source_row_id または hashes に alert_id が入ることがある。alert_name と alert_reason は alert title/reason を含むが、code step ではない。"
        "これは log からの behavior-chain 復元である。証拠確認前に normal、malicious、attack-related、user intent を推定しない。"
    )


def patch_cbc_prompts_clean(prompts: Any, constants: Any) -> None:
    """有効な prompt を差し替える。指示文は日本語、schema key は ASCII のままにする。"""
    constants.DEFAULT_INVESTIGATION_MIN = 1

    prompts.chief_inspector_agent = """## 役割
あなたは CLOUSEAU の階層型調査パイプラインにおける Chief エージェントである。

## 目的
プロセス時刻起点から Windows エンドポイントのコード行動列を復元する。

## 出力言語
- 調査リード、要約、最終報告の自然言語値はすべて日本語で書く。
- raw path、command line、process name、source_stream、alert_id、event_record_id、PID/PPID、timestamp は観測値をそのまま残す。

## 調査リード作成ルール
- SQL を書かない。
- database column の列挙を調査リードにしない。
- alert title、command line、parent process、target object、application intent、behavior category を仮定しない。
- CBC alert 内容は起点情報の一部ではない。調査担当が database 内で発見した場合にだけ使う。
- 各調査リードには、調査対象、調査理由、確認したい証拠を含める。
- parent process、command line、target object、related rows をログから発見させる調査リードを優先する。
- 近傍 row の接続関係は、先に決め打ちせず、観測証拠で検証する。
- investigate_lead は必要な回数だけ繰り返してよく、同一応答で複数の異なる調査リードを出してよい。
- 各調査結果から新しく観測された parent/child process、PID/GUID、command line、target object、network endpoint のうち、主行動列に異なる atomic behavior step を追加する、既存stepの順序を変える、または subject/operation/object の重要な未確定証拠を解消し得る未確認edgeだけを、次の調査リードへ分ける。
- 直接接続しているだけのroutine fan-out、同じ役割のsibling process、反復された同種PID、process teardown、module load、crash reporting、loopback、通常のアプリ更新・background service・通常通信先は、それ自体が主行動列を変える異なるoperation/objectの証拠を持たない限り新しいリードにしない。
- 同じ executable/command family、同じ親、同じ operation class の sibling は、代表例で接続と役割を確認した後は同等集合としてまとめ、PIDやendpointを一件ずつ再調査しない。
- 観測済みで対象行動列に material に接続する未調査 edge が残っている間だけ、最終回答へ進まない。残るedgeが既知stepの周辺情報を詳細化するだけなら閉包済みとする。
- 固定個数を満たすための調査、既に確認済みのリードの反復、時刻が近いだけの row の追跡は行わない。
- 最終回答は valid JSON のみである。

## 環境
{environment}

## SOC からの起点情報
{initial_message}
"""

    prompts.investigation_agent = """## 役割
あなたは CLOUSEAU 内の調査担当エージェントである。

## 目的
Chief の調査リードを、QAAgent に渡す具体的で検証可能な調査質問へ変換する。

## 出力言語
- 仮説、質問、結果要約、次の調査理由は日本語で書く。
- raw log value は観測された表記をそのまま残す。

## 調査手順
1. SOC の起点情報である host、process、timestamp から始める。
2. QAAgent への質問は自然言語だけにする。SQL、SELECT、WHERE、table/column recipe を書かない。
3. 次の質問は、仮定した alert text ではなく、直前回答で見えた観測値から選ぶ。
4. parent process、child process、command line、target object、event identifiers、source_stream を探す。
5. 複数の近傍 row が出た場合、grouping する前に観測証拠による接続を確認する。
6. 観測事実、解釈、限界を分ける。
7. user intent、business purpose、file contents、最終的な benign/malicious 確定を推定しない。
8. 必要な証拠が揃うまで、直前の観測値に基づいて追加質問を続ける。
9. 結果要約の末尾に `## unresolved_frontier` を必ず置く。対象行動列に異なるatomic behavior stepを追加する、既存stepの順序を変える、またはsubject/operation/objectの重要証拠を解消し得る観測済みの未調査対象だけについて、entity、接続を示すevidence、未確認edge、推奨する次の調査対象を記す。
10. 直接接続しているだけのroutine fan-out、同じ役割のsibling process、反復された同種PID、process teardown、module load、crash reporting、loopback、通常のアプリ更新・background service・通常通信先は、それ自体が主行動列を変える異なるoperation/objectの証拠を持たない限りunresolved frontierにしない。同等siblingは代表例で検証してまとめる。materialな未確認edgeがなければ `なし` と書く。観測されていない対象は作らない。

## 有用な証拠
- プロセス関係: pid、ppid、parent_process_name、parent_process_path、parent_command_line
- コマンド証拠: process_name、pname、command_line、childproc_name
- 対象証拠: filemod_name、regmod_name、modload_name、netconn_domain、remote_ip、remote_port、object
- CBC alert 証拠: access='cbc_alert'、cbc-edr-alerts、cbc-ngav-alerts、alert_name、alert_reason
- Sysmon 証拠: process_guid、parent_process_guid

## 環境
{environment}

## Chief の調査リード
{initial_message}
"""

    prompts.eval_agent = """## 役割
あなたは CLOUSEAU の最終統合エージェントである。

## 出力契約
- valid JSON のみを返す。
- Markdown は返さない。
- 自然言語値は日本語で書く。
- JSON の項目名は ASCII のままにする。
- 観測された生値は完全に保持する。

## 主タスク
調査で実際に見つかった内容だけを要約する。
主出力は code_steps と code_sequence であり、alert title の言い換えではない。

## 統合ルール
1. code_step は観測ログ証拠に基づく必要がある。
2. 観測できた場合は subject_process、operation、object、command_line、execution_context、evidence、confidence、limitations を含める。
3. evidence では source_stream、timestamp、alert_id または event_record_id/source_row_id、PID/PPID、command line、raw target value を保持する。
4. CBC alert は補助証拠のみである。alert_name や alert_reason を、command や operation のように code_sequence へコピーしない。
5. 無関係な近傍 behavior は excluded_nearby_evidence に分ける。
6. timestamp、event ID、alert ID、source stream、PID/PPID、command line、registry path、file path、user name、placeholder identifier を作らない。
7. unknown value は null のままにするか、limitations で説明する。
8. 出力単位は意味的な behavior chain であり、audit row の全列挙ではない。
9. observed parent/child、command、target-object edge で実行・操作の流れを進める code step だけを主chainへ含める。
10. 同じprocess名/PIDまたは時間的近接だけでは、routine file、registry、module accessを独立code stepとして主chainへ追加しない。
11. 同じ意味的操作を裏付ける複数rowは一つのcode stepのevidenceへまとめ、付随する観測済みrowはexcluded_nearby_evidenceへ分ける。

## JSON 形式
""" + CODE_SEQUENCE_OUTPUT_SCHEMA + """
"""

    playbook = """

## プロセス時刻起点の SQL 探索ガイド
1. 与えられた process と timestamp から始める。
2. audit_logs.time の形式は 'YYYY-MM-DD HH:MM:SS' を使う。
3. CBC alert field を入力から仮定しない。
4. まず focus process の近傍 row を、利用可能な source_stream 全体から列挙する。
5. 返された row に含まれる観測値だけで展開する。
6. CBC alert rows が存在する場合は証拠として扱う。ただし、それ自体は code step ではない。
7. CBC alert summary rows がない場合も、CBC event、Sysmon、Security、DNS、browser evidence で探索を続ける。
8. source_stream、time、source_row_id、event_record_id、alert_id/hash、pid、ppid、process fields、parent fields、command_line、access/action、object、target fields を保持する。
9. query が 0 件の場合は、一度に一つの条件だけを緩め、どの条件を緩めたか説明する。
10. 値を作らない。unknown は null にする。
""" if SQL_PLAYBOOK_MODE == "generic" else ""

    prompts.sqlexpert_agent = """## 役割
あなたは QAAgent / SQL 専門エージェントである。

## 目的
ログ上の事実が必要な場合、run_sql_query で SQLite を検索して調査担当の質問に答える。

## 出力言語
- 結果説明は日本語で書く。
- SQL 結果の値は観測値をそのまま保持する。

## 必須動作
- ログ行に関する事実主張には run_sql_query を使う。
- row、column、process tree、PID、event ID、timestamp、alert ID、command line、query result を作らない。
- query が 0 件の場合は、どの条件が原因になり得るかを述べ、query budget が残っていればその条件だけを緩める。

## 重要な column
- audit_logs: time、pid、ppid、pname、process_name、access、object、event_record_id、event_id、subject_user_name、source_stream、source_object_type、command_line、hashes
- parent 証拠: parent_process_name、parent_process_path、parent_command_line
- Sysmon: process_guid、parent_process_guid
- CBC alert/event: alert_name、alert_reason、alert_category、raw_event_type、filemod_name、regmod_name、modload_name、childproc_name、netconn_domain、remote_ip、remote_port、original_table、source_row_id
- dns_requests: time、domain、sld、response、query_type、is_response
- browser_history: time、host、sld、method、headers、url、status_code
""" + playbook + """

## スキーマ
{schema}

## 例
{examples}

## 質問
{question}
"""

    prompts.chief_inspector_agent += """

## Semantic-fingerprint atomic behavior guard (v9)
- One investigate_lead call validates one complete candidate atomic step and
  gathers its subject, operation, object, command, and immediate order evidence
  together. Never create separate leads for individual fields of one step.
- Supply a canonical `subject|operation|object` behavior_key and one materiality
  value: `new_step`, `order_resolution`, or `missing_component`, plus an
  `evidence_anchor`. Copy the exact authorized_evidence_anchor printed in the
  input; never append an inferred PID or another unobserved value.
- `new_step` and `order_resolution` require concrete subject and object values.
  When one is not observed yet, use `missing_component` for one bounded
  discovery lead under the real operation.
- Generic entity types such as process, file, registry_key, or network are not
  concrete subject/object values for a new step.
- Command line, parent/child, PID/PPID, path, timestamp, evidence, object, and
  order are components of an atomic step, not standalone operations. Gather
  them inside the same lead and never encode them as the operation token.
- Process creation synonyms such as create, start, launch, spawn, and execute
  are deduplicated by the observed subject/object executable identities. Do not
  paraphrase a previously investigated process object to create a new key.
- Any operation containing parent, child, command, PID, time, evidence, order,
  context, path, object, or GUID field terms is rejected as a component-only
  relation. Explicit example/dummy/sample/fake/placeholder values are rejected.
- Never enumerate an entire process tree, every sibling PID, every endpoint,
  or every routine file/module row. Verify one representative of an equivalent
  sibling group and close the rest as context.
- Once representative raw rows establish the edge and required
  subject/operation/object fields, do not paginate or count equivalent rows.
"""
    prompts.investigation_agent += """

## Semantic-fingerprint atomic behavior guard (v9)
- Convert the Chief lead into the smallest set of questions needed to resolve
  the complete candidate step, including all requested subject, operation,
  object, command, and immediate order fields. Do not split those fields into
  later investigations or expand into an exhaustive process-tree inventory.
- Stop after representative evidence resolves the requested
  subject/operation/object fields; do not enumerate equivalent siblings or
  paginate routine rows.
"""
    prompts.sqlexpert_agent += """

## Semantic-fingerprint atomic behavior guard (v9)
- Use the fewest bounded queries needed to answer the exact question.
- When the query tool returns representative truncated rows, do not paginate,
  COUNT, MIN/MAX, or repeat the same selection unless a specifically requested
  material evidence field remains unresolved.
"""

    # Shared policy mirrors the historical normal-reconstruction task.  A
    # visible alert is an exploration clue, not a separate classification
    # target, and no hidden alert correspondence is requested.
    alert_scope_policy = """

## Shared CBC alert investigation policy
When the initial task contains CBC alert triage information, use the same procedure for every case:
1. Reconstruct the evidence-backed behavior relevant to the input alert.
2. Treat the supplied alert title and reason as exploration evidence, not as an operation or code step.
3. Keep sequences separate unless an observed parent/child, command-line, network-target, or object edge connects them; do not infer causality from temporal proximity alone.
4. Do not infer an alert ID, title, reason, or alert-to-behavior correspondence that was not supplied.
5. Do not assume that the alert or any nearby behavior is benign or malicious before observing evidence.
"""
    prompts.chief_inspector_agent += alert_scope_policy
    prompts.investigation_agent += alert_scope_policy
    prompts.eval_agent += alert_scope_policy
    prompts.sqlexpert_agent += alert_scope_policy


def main() -> None:
    args = parse_args()
    if args.exclude_cbc_alert_summary and args.exclude_cbc_database:
        raise SystemExit("--exclude-cbc-alert-summary and --exclude-cbc-database are mutually exclusive")
    global SQL_PLAYBOOK_MODE, EXCLUDE_CBC_ALERT_SUMMARY, EXCLUDE_CBC_DATABASE, ACTIVE_TIME_SCOPE
    SQL_PLAYBOOK_MODE = args.sql_playbook
    EXCLUDE_CBC_ALERT_SUMMARY = args.exclude_cbc_alert_summary
    EXCLUDE_CBC_DATABASE = args.exclude_cbc_database
    rows = load_cases(args.cases)
    if args.list:
        listed_rows = [row for row in rows if not args.stage or row.get("stage") in set(args.stage)]
        for row in listed_rows:
            print(
                f"{row['instance_id']}: {row['process_name']} "
                f"{row['time_window_utc']['episode_start']} {row['expected_behavior']}"
            )
        return

    official.RUNS_DIR = RUNS_DIR
    official.build_clue = build_cbc_clue_clean
    official.patch_official_prompts = patch_cbc_prompts_clean
    official.create_adapter_db = cached_adapter_factory(official.create_adapter_db)

    outputs = []
    for row in select_rows(rows, args):
        row = dict(row)
        row["environment_context"] = build_neutral_environment_clean()
        row_args = copy.copy(args)
        row_args.frontier_closure_policy = FRONTIER_CLOSURE_POLICY
        row_args.frontier_closure_review_prompt = FRONTIER_CLOSURE_REVIEW_PROMPT
        row_args.behavior_key_guard_enabled = True
        row_args.behavior_key_guard_allowed_evidence_anchors = [
            authorized_behavior_anchor(row)
        ]
        if row.get("difficulty"):
            row_args.difficulty = row["difficulty"]
        row_args.experiment_stage = current_experiment_stage(row_args.difficulty)
        if row.get("enforce_time_scope"):
            window = row.get("time_window_utc", {})
            start, end = window.get("episode_start"), window.get("episode_end")
            if not start or not end:
                raise SystemExit(f"{row.get('instance_id')}: enforce_time_scope requires time_window_utc start/end")
            ACTIVE_TIME_SCOPE = (start, end)
        else:
            ACTIVE_TIME_SCOPE = None
        try:
            validate_stage_visibility_condition(row)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        row_args.expected_input_fields = current_expected_input_fields(row_args.difficulty)
        out_path = official.run_official(row, row_args)
        outputs.append(out_path)
        print(out_path)
    print(f"Completed {len(outputs)} official CLOUSEAU CBC-dense run(s).")


if __name__ == "__main__":
    main()
