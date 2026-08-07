#!/usr/bin/env python3
"""Run a selected subset of official Clouseau scenarios with root env settings."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env.clouseau"
ARTIFACT_DIR = ROOT / "external" / "Clouseau-official" / "artifact"

sys.path.insert(0, str(ARTIFACT_DIR))

from langchain_openai import ChatOpenAI  # noqa: E402
import app as clouseau_app  # noqa: E402
import constants as clouseau_constants  # noqa: E402


def load_env_file(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=["si", "ml", "se", "ss", "optc"], required=True)
    parser.add_argument("--scenario", required=True, help="Scenario name such as s1, s4, m5h1, se2")
    parser.add_argument("--csv-file", required=True, help="Output CSV path relative to artifact directory or absolute path")
    parser.add_argument("--max-investigations", type=int, default=2)
    parser.add_argument("--max-questions", type=int, default=2)
    parser.add_argument("--max-queries", type=int, default=3)
    parser.add_argument("--model", default=None)
    return parser.parse_args()


def scenario_group(name: str):
    groups = {
        "si": clouseau_app.si_scn,
        "ml": clouseau_app.ml_scn,
        "se": clouseau_app.se_scn,
        "ss": clouseau_app.ss_scn,
        "optc": clouseau_app.optc_scn,
    }
    return groups[name]


def main() -> None:
    args = parse_args()
    env_values = load_env_file(ENV_PATH)
    os.chdir(ARTIFACT_DIR)

    model = args.model or os.environ.get("LLM_MODEL") or env_values.get("OPENAI_MODEL") or "gpt-4.1-mini"
    api_key = os.environ.get("API_KEY") or env_values.get("OPENAI_API_KEY")
    base_url = os.environ.get("BASE_URL") or env_values.get("OPENAI_BASE_URL")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is missing in .env.clouseau")

    configs = {
        "max_investigations": args.max_investigations,
        "max_questions": args.max_questions,
        "max_queries": args.max_queries,
        "max_tokens": clouseau_constants.DEFAULT_MAX_TOKENS,
    }

    llm_kwargs = {"model": model, "temperature": 0, "api_key": api_key}
    if base_url:
        llm_kwargs["base_url"] = base_url
    llm = ChatOpenAI(**llm_kwargs)

    selected = [item for item in scenario_group(args.group) if item["name"].lower() == args.scenario.lower()]
    if not selected:
        raise SystemExit(f"Scenario not found: {args.scenario}")

    csv_file = args.csv_file
    print(f"Using model: {model}")
    print(f"Running scenarios: {[item['name'] for item in selected]}")
    print(f"Saving results to: {csv_file}")
    clouseau_app.run_scenarios(
        scns=selected,
        llm=llm,
        configs=configs,
        ablation=False,
        darpa=(args.group == "optc"),
        csv_file=csv_file,
    )


if __name__ == "__main__":
    main()
