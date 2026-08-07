#!/usr/bin/env python3
"""Run one minimal OpenAI API call and report usage, call count, and cost."""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from openai import OpenAI


ROOT_ENV = Path(".env.clouseau")
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
    parser.add_argument("--env-file", default=str(ROOT_ENV))
    parser.add_argument("--model", default=None)
    parser.add_argument("--run-id", default="smoke-test")
    parser.add_argument("--scenario", default="smoke")
    parser.add_argument("--prompt", default="Reply with exactly: OK")
    parser.add_argument("--log-cost", action="store_true")
    return parser.parse_args()


def load_env_file(env_path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not env_path.exists():
        raise SystemExit(f"Env file not found: {env_path}")
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def get_usage(response) -> UsageSnapshot:
    usage = getattr(response, "usage", None)
    if usage is None:
        return UsageSnapshot(0, 0, 0)

    input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
    output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
    input_details = getattr(usage, "input_tokens_details", None)
    cached_input_tokens = 0
    if input_details is not None:
        cached_input_tokens = int(getattr(input_details, "cached_tokens", 0) or 0)
    return UsageSnapshot(input_tokens, output_tokens, cached_input_tokens)


def prices_for_model(model: str) -> Dict[str, float]:
    return DEFAULT_PRICES.get(model, {"input": 0.0, "cached_input": 0.0, "output": 0.0})


def usd(tokens: int, price_per_1m: float) -> float:
    return (tokens / 1_000_000.0) * price_per_1m


def append_cost_row(args: argparse.Namespace, usage: UsageSnapshot, model: str, prices: Dict[str, float]) -> None:
    cmd = [
        sys.executable,
        "scripts/log_clouseau_cost.py",
        "--run-id",
        args.run_id,
        "--scenario",
        args.scenario,
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
        "one-call smoke test",
    ]
    subprocess.run(cmd, check=True)


def main() -> None:
    args = parse_args()
    env_values = load_env_file(Path(args.env_file))
    api_key = env_values.get("OPENAI_API_KEY", "")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is empty in the env file.")

    model = args.model or env_values.get("OPENAI_MODEL", "gpt-5")
    client = OpenAI(api_key=api_key)

    response = client.responses.create(
        model=model,
        input=args.prompt,
    )

    usage = get_usage(response)
    prices = prices_for_model(model)
    input_cost = usd(usage.input_tokens, prices["input"])
    output_cost = usd(usage.output_tokens, prices["output"])
    cached_cost = usd(usage.cached_input_tokens, prices["cached_input"])
    total_cost = input_cost + output_cost + cached_cost

    print(f"response_id={response.id}")
    print(f"model={model}")
    print("api_calls=1")
    print(f"input_tokens={usage.input_tokens}")
    print(f"output_tokens={usage.output_tokens}")
    print(f"cached_input_tokens={usage.cached_input_tokens}")
    print(f"input_cost_usd={input_cost:.8f}")
    print(f"output_cost_usd={output_cost:.8f}")
    print(f"cached_input_cost_usd={cached_cost:.8f}")
    print(f"call_total_usd={total_cost:.8f}")
    print(f"output_text={response.output_text!r}")

    if args.log_cost:
        append_cost_row(args, usage, model, prices)


if __name__ == "__main__":
    main()
