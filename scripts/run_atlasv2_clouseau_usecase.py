#!/usr/bin/env python3
"""Run current ATLASv2 use cases with a minimal CLOUSEAU-style pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from openai import OpenAI


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env.clouseau"
USECASE_PATH = ROOT / "Clouseau" / "artifact" / "scenarios" / "atlasv2" / "current_usecases.json"
RUNS_DIR = ROOT / "Clouseau" / "artifact" / "runs" / "atlasv2"
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
    parser.add_argument("--list", action="store_true", help="List available use cases")
    parser.add_argument("--usecase-id", help="Run one use case by ID")
    parser.add_argument("--run-all", action="store_true", help="Run all configured use cases")
    parser.add_argument("--dry-run", action="store_true", help="Build evidence only and skip the API call")
    parser.add_argument("--model", default=None, help="Override model name")
    parser.add_argument("--sample-limit", type=int, default=12)
    parser.add_argument("--log-cost", action="store_true", help="Append the API cost to clouseau_api_costs.csv")
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


def load_usecases(path: Path) -> List[Dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def db_path_for(usecase: Dict[str, Any]) -> Path:
    return (
        ROOT
        / "Clouseau"
        / "artifact"
        / "scenarios"
        / "atlasv2"
        / usecase["split"]
        / usecase["host"]
        / usecase["scenario"]
        / "incident.db"
    )


def parse_ts(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def ts_str(value: datetime) -> str:
    text = value.astimezone(timezone.utc).isoformat()
    return text.replace("+00:00", "Z")


def top_rows(conn: sqlite3.Connection, sql: str, params: Iterable[Any], limit: int = 10) -> List[Dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute(sql, tuple(params))
    rows = [dict(row) for row in cur.fetchmany(limit)]
    conn.row_factory = None
    return rows


def build_evidence(usecase: Dict[str, Any], sample_limit: int) -> Dict[str, Any]:
    db = db_path_for(usecase)
    if not db.exists():
        raise FileNotFoundError(f"incident.db not found: {db}")

    conn = sqlite3.connect(db)
    try:
        like_actor = f"%{usecase['actor'].lower()}%"
        event_id = int(usecase["event_id"])
        object_type = usecase["object_type"].lower()

        total_matches = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE event_id = ?
              AND lower(coalesce(object_type, '')) = ?
              AND lower(coalesce(process_name, '')) LIKE ?
            """,
            (event_id, object_type, like_actor),
        ).fetchone()[0]

        min_ts, max_ts = conn.execute(
            """
            SELECT MIN(timestamp_utc), MAX(timestamp_utc)
            FROM audit_logs
            WHERE event_id = ?
              AND lower(coalesce(object_type, '')) = ?
              AND lower(coalesce(process_name, '')) LIKE ?
            """,
            (event_id, object_type, like_actor),
        ).fetchone()

        top_objects = top_rows(
            conn,
            """
            SELECT object_name, COUNT(*) AS count
            FROM audit_logs
            WHERE event_id = ?
              AND lower(coalesce(object_type, '')) = ?
              AND lower(coalesce(process_name, '')) LIKE ?
            GROUP BY object_name
            ORDER BY count DESC
            """,
            (event_id, object_type, like_actor),
            limit=10,
        )

        top_accesses = top_rows(
            conn,
            """
            SELECT access_mask, access_list, action, COUNT(*) AS count
            FROM audit_logs
            WHERE event_id = ?
              AND lower(coalesce(object_type, '')) = ?
              AND lower(coalesce(process_name, '')) LIKE ?
            GROUP BY access_mask, access_list, action
            ORDER BY count DESC
            """,
            (event_id, object_type, like_actor),
            limit=10,
        )

        sample_rows = top_rows(
            conn,
            """
            SELECT timestamp_utc, event_record_id, process_name, object_name,
                   access_mask, access_list, action, subject_user_name
            FROM audit_logs
            WHERE event_id = ?
              AND lower(coalesce(object_type, '')) = ?
              AND lower(coalesce(process_name, '')) LIKE ?
            ORDER BY timestamp_utc
            """,
            (event_id, object_type, like_actor),
            limit=sample_limit,
        )

        context_process_counts: List[Dict[str, Any]] = []
        if sample_rows:
            stamps = [parse_ts(row["timestamp_utc"]) for row in sample_rows[:3]]
            proc_counter: Counter[str] = Counter()
            for stamp in stamps:
                start = ts_str(stamp - timedelta(seconds=2))
                end = ts_str(stamp + timedelta(seconds=2))
                rows = conn.execute(
                    """
                    SELECT process_name, COUNT(*) AS count
                    FROM audit_logs
                    WHERE timestamp_utc BETWEEN ? AND ?
                    GROUP BY process_name
                    """,
                    (start, end),
                ).fetchall()
                for proc, count in rows:
                    proc_counter[proc or "(null)"] += int(count)
            context_process_counts = [
                {"process_name": proc, "count": count}
                for proc, count in proc_counter.most_common(10)
            ]

        dns_samples = []
        browser_samples = []
        if min_ts and max_ts:
            dns_samples = top_rows(
                conn,
                """
                SELECT timestamp_utc, query_type, query_name, is_response, answer_summary
                FROM dns_logs
                WHERE timestamp_utc BETWEEN ? AND ?
                ORDER BY timestamp_utc
                """,
                (min_ts.replace("T", " ").replace("Z", ""), max_ts.replace("T", " ").replace("Z", "")),
                limit=8,
            )
            browser_samples = top_rows(
                conn,
                """
                SELECT timestamp_utc, host, url, status_code, status_text
                FROM browser_logs
                WHERE timestamp_utc BETWEEN ? AND ?
                ORDER BY timestamp_utc
                """,
                (
                    min_ts.replace("T", " ").replace("Z", " UTC"),
                    max_ts.replace("T", " ").replace("Z", " UTC"),
                ),
                limit=8,
            )

        evidence = {
            "usecase": usecase,
            "database": str(db),
            "match_summary": {
                "total_poi_matches": total_matches,
                "time_range_utc": {"start": min_ts, "end": max_ts},
                "top_objects": top_objects,
                "top_access_patterns": top_accesses,
                "sample_poi_rows": sample_rows,
                "context_process_counts": context_process_counts,
                "dns_samples": dns_samples,
                "browser_samples": browser_samples,
            },
        }
        return evidence
    finally:
        conn.close()


def build_prompt(evidence: Dict[str, Any]) -> str:
    uc = evidence["usecase"]
    match_summary = evidence["match_summary"]
    payload = {
        "usecase_id": uc["usecase_id"],
        "title": uc["title"],
        "actor": uc["actor"],
        "expected_actor_type": uc["actor_type"],
        "expected_access_behavior": uc["access_behavior"],
        "expected_context_label": uc["context_label"],
        "notes": uc["notes"],
        "evidence": match_summary,
    }
    return (
        "You are investigating one ATLASv2 file-access use case with a CLOUSEAU-style workflow.\n"
        "Use only the provided evidence summary. Do not invent unsupported facts.\n"
        "Return strict JSON with these keys exactly:\n"
        "poi_event, actor, actor_type, object_type, access_behavior, context_label, "
        "related_events, behavior_summary, limitation, confidence.\n"
        "Keep related_events short and concrete.\n\n"
        f"Evidence JSON:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
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


def run_one(usecase: Dict[str, Any], env_values: Dict[str, str], model_override: Optional[str], sample_limit: int, dry_run: bool, log_cost: bool) -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{run_stamp}_{usecase['usecase_id']}"
    evidence = build_evidence(usecase, sample_limit)
    prompt = build_prompt(evidence)

    result: Dict[str, Any] = {
        "run_id": run_id,
        "api_calls": 0,
        "model": model_override or env_values.get("OPENAI_MODEL", "gpt-5"),
        "usecase": usecase,
        "evidence": evidence["match_summary"],
        "dry_run": dry_run,
    }

    if not dry_run:
        api_key = env_values.get("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is empty.")
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=result["model"],
            input=prompt,
        )
        usage = get_usage(response)
        prices = prices_for_model(result["model"])
        call_total = (
            usd(usage.input_tokens, prices["input"])
            + usd(usage.output_tokens, prices["output"])
            + usd(usage.cached_input_tokens, prices["cached_input"])
        )
        result["api_calls"] = 1
        result["response_id"] = response.id
        result["output_text"] = response.output_text
        result["usage"] = {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cached_input_tokens": usage.cached_input_tokens,
            "estimated_call_total_usd": round(call_total, 8),
        }
        if log_cost:
            append_cost(run_id, usecase["scenario"], result["model"], usage, f"usecase {usecase['usecase_id']}")

    out_path = RUNS_DIR / f"{run_id}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


def main() -> None:
    args = parse_args()
    usecases = load_usecases(USECASE_PATH)
    if args.list:
        for uc in usecases:
            print(
                f"{uc['usecase_id']}: {uc['title']} | {uc['split']}/{uc['host']}/{uc['scenario']} | "
                f"{uc['actor']} | {uc['context_label']}"
            )
        return

    if not args.usecase_id and not args.run_all:
        raise SystemExit("Use --list, --usecase-id, or --run-all.")

    env_values = load_env_file(ENV_PATH)
    selected = usecases
    if args.usecase_id:
        selected = [uc for uc in usecases if uc["usecase_id"] == args.usecase_id]
        if not selected:
            raise SystemExit(f"Unknown use case ID: {args.usecase_id}")

    outputs = []
    for uc in selected:
        out_path = run_one(
            usecase=uc,
            env_values=env_values,
            model_override=args.model,
            sample_limit=args.sample_limit,
            dry_run=args.dry_run,
            log_cost=args.log_cost,
        )
        outputs.append(out_path)
        print(out_path)


if __name__ == "__main__":
    main()
