#!/usr/bin/env python3
"""Run one CLOUSEAU-like multi-step investigation and record real API cost."""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from openai import OpenAI


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env.clouseau"
RUNS_DIR = ROOT / "Clouseau" / "artifact" / "runs" / "atlasv2_multistep"
DEFAULT_DB = ROOT / "Clouseau" / "artifact" / "scenarios" / "atlasv2" / "attack" / "h1" / "m5" / "incident.db"
DEFAULT_POI = r"C:\Users\aalsahee\Downloads\m5\msf.doc"
DEFAULT_PRICES = {
    "gpt-5": {"input": 1.25, "cached_input": 0.125, "output": 10.0},
    "gpt-5-mini": {"input": 0.25, "cached_input": 0.025, "output": 2.0},
    "gpt-5-nano": {"input": 0.05, "cached_input": 0.005, "output": 0.4},
}


@dataclass
class UsageSnapshot:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to incident.db")
    parser.add_argument("--scenario", default="m5", help="Scenario label for reports")
    parser.add_argument("--host", default="h1", help="Host label for reports")
    parser.add_argument("--split", default="attack", help="Split label for reports")
    parser.add_argument("--poi", default=DEFAULT_POI, help="Point of interest object path")
    parser.add_argument("--model", default=None, help="Override model name")
    parser.add_argument("--log-cost", action="store_true", help="Append each API call to clouseau_api_costs.csv")
    parser.add_argument("--dry-run", action="store_true", help="Build prompts only and skip API calls")
    return parser.parse_args()


def load_env_file(env_path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def parse_ts(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def ts_str(value: datetime) -> str:
    text = value.astimezone(timezone.utc).isoformat()
    return text.replace("+00:00", "Z")


def top_rows(
    conn: sqlite3.Connection,
    sql: str,
    params: Iterable[Any],
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute(sql, tuple(params))
    rows = [dict(row) for row in cur.fetchmany(limit)] if limit else [dict(row) for row in cur.fetchall()]
    conn.row_factory = None
    return rows


def compact_rows(rows: List[Dict[str, Any]], keys: List[str]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for row in rows:
        output.append({key: row.get(key) for key in keys})
    return output


def shorten_text(text: Optional[str], max_len: int = 160) -> str:
    if not text:
        return ""
    value = str(text)
    return value if len(value) <= max_len else value[: max_len - 3] + "..."


def build_case_payload(db_path: Path, poi: str, labels: Dict[str, str]) -> Dict[str, Any]:
    conn = sqlite3.connect(str(db_path))
    poi_like = f"%{poi.lower()}%"
    try:
        poi_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE lower(coalesce(object_name, '')) LIKE ?
            """,
            (poi_like,),
        ).fetchone()[0]
        min_ts, max_ts = conn.execute(
            """
            SELECT MIN(timestamp_utc), MAX(timestamp_utc)
            FROM audit_logs
            WHERE lower(coalesce(object_name, '')) LIKE ?
            """,
            (poi_like,),
        ).fetchone()
        if not min_ts or not max_ts:
            raise RuntimeError(f"No POI rows found for {poi}")

        first_ts = parse_ts(min_ts)
        last_ts = parse_ts(max_ts)
        browser_start = first_ts - timedelta(minutes=2)
        browser_end = first_ts + timedelta(minutes=2)
        timeline_start = first_ts - timedelta(minutes=1)
        timeline_end = first_ts + timedelta(minutes=5)

        poi_rows = top_rows(
            conn,
            """
            SELECT timestamp_utc, event_id, process_name, object_name, access_mask,
                   access_list, action, subject_user_name
            FROM audit_logs
            WHERE lower(coalesce(object_name, '')) LIKE ?
            ORDER BY timestamp_utc
            """,
            (poi_like,),
            limit=60,
        )

        process_window_counts = top_rows(
            conn,
            """
            SELECT process_name, COUNT(*) AS count
            FROM audit_logs
            WHERE timestamp_utc BETWEEN ? AND ?
            GROUP BY process_name
            ORDER BY count DESC
            """,
            (ts_str(timeline_start), ts_str(timeline_end)),
            limit=20,
        )

        object_window_counts = top_rows(
            conn,
            """
            SELECT object_name, COUNT(*) AS count
            FROM audit_logs
            WHERE timestamp_utc BETWEEN ? AND ?
            GROUP BY object_name
            ORDER BY count DESC
            """,
            (ts_str(timeline_start), ts_str(timeline_end)),
            limit=25,
        )

        relevant_processes = [
            row["process_name"]
            for row in process_window_counts
            if row.get("process_name")
            and any(token in row["process_name"].lower() for token in ["explorer", "winword", "searchprotocolhost", "mshta"])
        ]
        relevant_processes = relevant_processes[:4]

        process_timeline_rows: List[Dict[str, Any]] = []
        if relevant_processes:
            placeholders = ",".join("?" for _ in relevant_processes)
            process_timeline_rows = top_rows(
                conn,
                f"""
                SELECT timestamp_utc, event_id, process_name, object_name, access_list, action
                FROM audit_logs
                WHERE timestamp_utc BETWEEN ? AND ?
                  AND process_name IN ({placeholders})
                ORDER BY timestamp_utc
                """,
                (ts_str(timeline_start), ts_str(timeline_end), *relevant_processes),
                limit=120,
            )

        related_path_counts = top_rows(
            conn,
            """
            SELECT object_name, COUNT(*) AS count
            FROM audit_logs
            WHERE lower(coalesce(object_name, '')) LIKE '%downloads\\m5%'
               OR lower(coalesce(object_name, '')) LIKE '%msf.doc%'
               OR lower(coalesce(object_name, '')) LIKE '%m5.zip%'
               OR lower(coalesce(object_name, '')) LIKE '%mshta%'
            GROUP BY object_name
            ORDER BY count DESC
            """,
            (),
            limit=30,
        )

        browser_rows = top_rows(
            conn,
            """
            SELECT timestamp_utc, host, url, status_code, status_text
            FROM browser_logs
            WHERE timestamp_utc BETWEEN ? AND ?
            ORDER BY timestamp_utc
            """,
            (
                ts_str(browser_start).replace("T", " ").replace("Z", " UTC"),
                ts_str(browser_end).replace("T", " ").replace("Z", " UTC"),
            ),
            limit=40,
        )

        dns_rows = top_rows(
            conn,
            """
            SELECT timestamp_utc, query_name, query_type, is_response, answer_summary
            FROM dns_logs
            WHERE timestamp_utc BETWEEN ? AND ?
            ORDER BY timestamp_utc
            """,
            (
                ts_str(browser_start).replace("T", " ").replace("Z", ""),
                ts_str(browser_end).replace("T", " ").replace("Z", ""),
            ),
            limit=40,
        )

        payload = {
            "case": {
                "split": labels["split"],
                "host": labels["host"],
                "scenario": labels["scenario"],
                "database": str(db_path),
                "poi": poi,
                "poi_match_count": poi_count,
                "poi_time_range_utc": {"start": min_ts, "end": max_ts},
                "browser_dns_window_utc": {
                    "start": ts_str(browser_start),
                    "end": ts_str(browser_end),
                },
                "timeline_window_utc": {
                    "start": ts_str(timeline_start),
                    "end": ts_str(timeline_end),
                },
            },
            "facts": {
                "top_process_counts": process_window_counts,
                "top_object_counts": object_window_counts,
                "related_path_counts": related_path_counts,
                "relevant_processes": relevant_processes,
            },
            "samples": {
                "poi_rows": poi_rows,
                "process_timeline_rows": process_timeline_rows,
                "browser_rows": browser_rows,
                "dns_rows": dns_rows,
            },
        }
        return payload
    finally:
        conn.close()


def build_chief_plan_prompt(payload: Dict[str, Any]) -> str:
    summary = {
        "case": payload["case"],
        "top_process_counts": payload["facts"]["top_process_counts"][:12],
        "top_object_counts": payload["facts"]["top_object_counts"][:15],
        "related_path_counts": payload["facts"]["related_path_counts"][:15],
        "poi_rows": compact_rows(
            payload["samples"]["poi_rows"][:12],
            ["timestamp_utc", "event_id", "process_name", "object_name", "access_list", "action"],
        ),
        "browser_rows": compact_rows(
            payload["samples"]["browser_rows"][:12],
            ["timestamp_utc", "host", "url", "status_code"],
        ),
        "dns_rows": compact_rows(
            payload["samples"]["dns_rows"][:12],
            ["timestamp_utc", "query_name", "query_type", "is_response"],
        ),
    }
    return (
        "You are the Chief Inspector in a hierarchical cyber investigation.\n"
        "A Point of Interest (POI) was provided from an ATLASv2 incident dataset.\n"
        "Use only the evidence below. Do not invent facts.\n"
        "Return strict JSON with keys exactly:\n"
        "case_assessment, initial_hypotheses, priority_questions, investigator_assignments, likely_relevance, caution_points.\n"
        "investigator_assignments must be a list with short tasks for file, browser_dns, and timeline investigators.\n\n"
        f"Evidence JSON:\n{json.dumps(summary, ensure_ascii=False, indent=2)}"
    )


def build_file_prompt(payload: Dict[str, Any], chief_plan: str) -> str:
    evidence = {
        "case": payload["case"],
        "chief_plan": chief_plan,
        "poi_rows": compact_rows(
            payload["samples"]["poi_rows"][:45],
            ["timestamp_utc", "event_id", "process_name", "object_name", "access_mask", "access_list", "action"],
        ),
        "related_path_counts": payload["facts"]["related_path_counts"][:20],
        "timeline_rows": compact_rows(
            payload["samples"]["process_timeline_rows"][:60],
            ["timestamp_utc", "event_id", "process_name", "object_name", "access_list", "action"],
        ),
    }
    return (
        "You are the File Investigator.\n"
        "Focus on file-access semantics around the POI. Use only the supplied evidence.\n"
        "Return strict JSON with keys exactly:\n"
        "file_findings, likely_actor_chain, supporting_events, confidence, limitations.\n"
        "supporting_events should be a short list of concrete event summaries.\n\n"
        f"Evidence JSON:\n{json.dumps(evidence, ensure_ascii=False, indent=2)}"
    )


def build_browser_prompt(payload: Dict[str, Any], chief_plan: str) -> str:
    browser_rows = []
    for row in payload["samples"]["browser_rows"][:30]:
        browser_rows.append(
            {
                "timestamp_utc": row.get("timestamp_utc"),
                "host": row.get("host"),
                "url_excerpt": shorten_text(row.get("url")),
                "status_code": row.get("status_code"),
            }
        )
    dns_rows = []
    for row in payload["samples"]["dns_rows"][:30]:
        dns_rows.append(
            {
                "timestamp_utc": row.get("timestamp_utc"),
                "query_name": row.get("query_name"),
                "query_type": row.get("query_type"),
                "is_response": row.get("is_response"),
                "answer_excerpt": shorten_text(row.get("answer_summary")),
            }
        )
    evidence = {
        "case": payload["case"],
        "chief_plan": chief_plan,
        "browser_rows": browser_rows,
        "dns_rows": dns_rows,
    }
    return (
        "You are the Browser/DNS Investigator.\n"
        "Assess whether the POI has support from web or DNS context in the nearby time window.\n"
        "Use only the supplied evidence. If the browser/DNS logs do not support a connection, say so plainly.\n"
        "Return strict JSON with keys exactly:\n"
        "browser_dns_findings, candidate_web_context, supporting_events, confidence, limitations.\n\n"
        f"Evidence JSON:\n{json.dumps(evidence, ensure_ascii=False, indent=2)}"
    )


def build_timeline_prompt(payload: Dict[str, Any], chief_plan: str) -> str:
    evidence = {
        "case": payload["case"],
        "chief_plan": chief_plan,
        "top_process_counts": payload["facts"]["top_process_counts"][:15],
        "top_object_counts": payload["facts"]["top_object_counts"][:20],
        "related_path_counts": payload["facts"]["related_path_counts"][:25],
        "timeline_rows": compact_rows(
            payload["samples"]["process_timeline_rows"][:100],
            ["timestamp_utc", "event_id", "process_name", "object_name", "access_list", "action"],
        ),
    }
    return (
        "You are the Timeline Investigator.\n"
        "Reconstruct a short, evidence-grounded chain around the POI from nearby process and file activity.\n"
        "Use only the supplied evidence.\n"
        "Return strict JSON with keys exactly:\n"
        "timeline_findings, candidate_sequence, key_entities, confidence, limitations.\n\n"
        f"Evidence JSON:\n{json.dumps(evidence, ensure_ascii=False, indent=2)}"
    )


def build_final_prompt(
    payload: Dict[str, Any],
    chief_plan: str,
    file_report: str,
    browser_report: str,
    timeline_report: str,
) -> str:
    evidence = {
        "case": payload["case"],
        "chief_plan": chief_plan,
        "file_report": file_report,
        "browser_report": browser_report,
        "timeline_report": timeline_report,
        "anchor_facts": {
            "poi_rows": compact_rows(
                payload["samples"]["poi_rows"][:10],
                ["timestamp_utc", "event_id", "process_name", "object_name", "access_list", "action"],
            ),
            "top_process_counts": payload["facts"]["top_process_counts"][:10],
        },
    }
    return (
        "You are the Chief Inspector synthesizing a CLOUSEAU-style investigation.\n"
        "Combine the sub-investigator outputs into one concise incident reconstruction.\n"
        "Use only supported evidence. Explicitly preserve uncertainty where needed.\n"
        "Return strict JSON with keys exactly:\n"
        "poi, investigation_scope, final_assessment, attack_or_benign_context, narrative_steps, key_artifacts, confidence, limitations.\n"
        "narrative_steps should be a short ordered list.\n\n"
        f"Evidence JSON:\n{json.dumps(evidence, ensure_ascii=False, indent=2)}"
    )


def get_usage(response: Any) -> UsageSnapshot:
    usage = getattr(response, "usage", None)
    if usage is None:
        return UsageSnapshot(0, 0, 0)
    input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
    output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
    details = getattr(usage, "input_tokens_details", None)
    cached = int(getattr(details, "cached_tokens", 0) or 0) if details is not None else 0
    return UsageSnapshot(input_tokens, output_tokens, cached)


def prices_for_model(model: str) -> Dict[str, float]:
    return DEFAULT_PRICES.get(model, {"input": 0.0, "cached_input": 0.0, "output": 0.0})


def usd(tokens: int, price_per_1m: float) -> float:
    return (tokens / 1_000_000.0) * price_per_1m


def append_cost(run_id: str, scenario: str, model: str, usage: UsageSnapshot, note: str) -> None:
    prices = prices_for_model(model)
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "log_clouseau_cost.py"),
        "--run-id",
        run_id,
        "--scenario",
        scenario,
        "--model",
        model,
        "--input-tokens",
        str(usage.input_tokens),
        "--output-tokens",
        str(usage.output_tokens),
        "--cached-input-tokens",
        str(usage.cached_input_tokens),
        "--input-price-per-1m",
        str(prices["input"]),
        "--output-price-per-1m",
        str(prices["output"]),
        "--cached-input-price-per-1m",
        str(prices["cached_input"]),
        "--note",
        note,
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)


def call_step(
    client: OpenAI,
    model: str,
    run_id: str,
    scenario: str,
    step_name: str,
    prompt: str,
    log_cost: bool,
) -> Dict[str, Any]:
    response = client.responses.create(model=model, input=prompt)
    usage = get_usage(response)
    prices = prices_for_model(model)
    call_total = (
        usd(usage.input_tokens, prices["input"])
        + usd(usage.output_tokens, prices["output"])
        + usd(usage.cached_input_tokens, prices["cached_input"])
    )
    if log_cost:
        append_cost(run_id, scenario, model, usage, step_name)
    return {
        "step_name": step_name,
        "response_id": response.id,
        "output_text": response.output_text,
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cached_input_tokens": usage.cached_input_tokens,
            "estimated_call_total_usd": round(call_total, 8),
        },
        "prompt": prompt,
    }


def main() -> None:
    args = parse_args()
    env_values = load_env_file(ENV_PATH)
    model = args.model or env_values.get("OPENAI_MODEL", "gpt-5")
    labels = {"split": args.split, "host": args.host, "scenario": args.scenario}
    payload = build_case_payload(args.db, args.poi, labels)

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{run_stamp}_{args.scenario}_multistep"

    result: Dict[str, Any] = {
        "run_id": run_id,
        "model": model,
        "api_calls": 0,
        "case": payload["case"],
        "dry_run": args.dry_run,
        "steps": [],
    }

    chief_prompt = build_chief_plan_prompt(payload)
    file_prompt = browser_prompt = timeline_prompt = final_prompt = None

    if args.dry_run:
        result["steps"] = [
            {"step_name": "chief_plan", "prompt": chief_prompt},
        ]
    else:
        api_key = env_values.get("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is empty.")
        client = OpenAI(api_key=api_key)

        chief_step = call_step(client, model, run_id, args.scenario, "chief_plan", chief_prompt, args.log_cost)
        result["steps"].append(chief_step)

        file_prompt = build_file_prompt(payload, chief_step["output_text"])
        browser_prompt = build_browser_prompt(payload, chief_step["output_text"])
        timeline_prompt = build_timeline_prompt(payload, chief_step["output_text"])

        file_step = call_step(client, model, run_id, args.scenario, "file_investigator", file_prompt, args.log_cost)
        browser_step = call_step(client, model, run_id, args.scenario, "browser_dns_investigator", browser_prompt, args.log_cost)
        timeline_step = call_step(client, model, run_id, args.scenario, "timeline_investigator", timeline_prompt, args.log_cost)

        result["steps"].extend([file_step, browser_step, timeline_step])

        final_prompt = build_final_prompt(
            payload,
            chief_step["output_text"],
            file_step["output_text"],
            browser_step["output_text"],
            timeline_step["output_text"],
        )
        final_step = call_step(client, model, run_id, args.scenario, "chief_synthesis", final_prompt, args.log_cost)
        result["steps"].append(final_step)

        result["api_calls"] = len(result["steps"])
        total_input = sum(step["usage"]["input_tokens"] for step in result["steps"])
        total_output = sum(step["usage"]["output_tokens"] for step in result["steps"])
        total_cached = sum(step["usage"]["cached_input_tokens"] for step in result["steps"])
        total_cost = sum(step["usage"]["estimated_call_total_usd"] for step in result["steps"])
        result["totals"] = {
            "input_tokens": total_input,
            "output_tokens": total_output,
            "cached_input_tokens": total_cached,
            "estimated_total_usd": round(total_cost, 8),
        }
        result["final_output_text"] = final_step["output_text"]

    out_path = RUNS_DIR / f"{run_id}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(out_path)
    if result.get("totals"):
        print(json.dumps(result["totals"], ensure_ascii=False))


if __name__ == "__main__":
    main()
