#!/usr/bin/env python3
"""Append one CLOUSEAU API cost row and keep a running cumulative total."""

from __future__ import annotations

import argparse
import csv
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="clouseau_api_costs.csv", help="Cost CSV path")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument("--scenario", default="", help="Scenario name, e.g. s1 or m4")
    parser.add_argument("--model", default="", help="Model name")
    parser.add_argument("--input-tokens", type=int, default=0)
    parser.add_argument("--output-tokens", type=int, default=0)
    parser.add_argument("--cached-input-tokens", type=int, default=0)
    parser.add_argument("--input-price-per-1m", type=float, default=None)
    parser.add_argument("--output-price-per-1m", type=float, default=None)
    parser.add_argument("--cached-input-price-per-1m", type=float, default=None)
    parser.add_argument("--calculated-input-cost-usd", type=float, default=None)
    parser.add_argument("--calculated-output-cost-usd", type=float, default=None)
    parser.add_argument(
        "--calculated-cached-input-cost-usd",
        type=float,
        default=None,
    )
    parser.add_argument("--note", default="", help="Optional note")
    return parser.parse_args()


def env_float(name: str) -> float:
    raw = os.getenv(name, "").strip()
    return float(raw) if raw else 0.0


def first_env_float(*names: str) -> float:
    for name in names:
        value = env_float(name)
        if value:
            return value
    return 0.0


def load_last_cumulative(csv_path: Path) -> float:
    if not csv_path.exists():
        return 0.0
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        return 0.0
    return float(rows[-1]["cumulative_total_usd"] or 0.0)


def ensure_header(csv_path: Path) -> None:
    if csv_path.exists():
        return
    csv_path.write_text(
        "timestamp,run_id,scenario,model,input_tokens,output_tokens,cached_input_tokens,"
        "input_cost_usd,output_cost_usd,cached_input_cost_usd,call_total_usd,"
        "cumulative_total_usd,note\n",
        encoding="utf-8",
    )


def usd(tokens: int, price_per_1m: float) -> float:
    return (tokens / 1_000_000.0) * price_per_1m


@contextmanager
def exclusive_cost_log_lock(csv_path: Path):
    """Serialize cumulative reads and appends across parallel runner processes."""
    lock_path = csv_path.with_name(csv_path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv)

    input_price = (
        args.input_price_per_1m
        if args.input_price_per_1m is not None
        else first_env_float("CLOUSEAU_INPUT_PRICE_PER_1M", "ANTHROPIC_INPUT_PRICE_PER_1M", "OPENAI_INPUT_PRICE_PER_1M")
    )
    output_price = (
        args.output_price_per_1m
        if args.output_price_per_1m is not None
        else first_env_float("CLOUSEAU_OUTPUT_PRICE_PER_1M", "ANTHROPIC_OUTPUT_PRICE_PER_1M", "OPENAI_OUTPUT_PRICE_PER_1M")
    )
    cached_price = (
        args.cached_input_price_per_1m
        if args.cached_input_price_per_1m is not None
        else first_env_float(
            "CLOUSEAU_CACHED_INPUT_PRICE_PER_1M",
            "ANTHROPIC_CACHED_INPUT_PRICE_PER_1M",
            "OPENAI_CACHED_INPUT_PRICE_PER_1M",
        )
    )

    # API usage reports cached input as a subset of input_tokens.  Charge the
    # uncached portion at the regular input rate and the cached subset at its
    # lower rate instead of double-counting it.
    uncached_input_tokens = max(
        args.input_tokens - args.cached_input_tokens,
        0,
    )
    input_cost = (
        args.calculated_input_cost_usd
        if args.calculated_input_cost_usd is not None
        else usd(uncached_input_tokens, input_price)
    )
    output_cost = (
        args.calculated_output_cost_usd
        if args.calculated_output_cost_usd is not None
        else usd(args.output_tokens, output_price)
    )
    cached_input_cost = (
        args.calculated_cached_input_cost_usd
        if args.calculated_cached_input_cost_usd is not None
        else usd(args.cached_input_tokens, cached_price)
    )
    call_total = input_cost + output_cost + cached_input_cost

    with exclusive_cost_log_lock(csv_path):
        ensure_header(csv_path)
        cumulative_total = load_last_cumulative(csv_path) + call_total
        row = [
            datetime.now(timezone.utc).isoformat(),
            args.run_id,
            args.scenario,
            args.model,
            str(args.input_tokens),
            str(args.output_tokens),
            str(args.cached_input_tokens),
            f"{input_cost:.8f}",
            f"{output_cost:.8f}",
            f"{cached_input_cost:.8f}",
            f"{call_total:.8f}",
            f"{cumulative_total:.8f}",
            args.note,
        ]

        with csv_path.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(row)

    print(f"call_total_usd={call_total:.8f}")
    print(f"cumulative_total_usd={cumulative_total:.8f}")


if __name__ == "__main__":
    main()
