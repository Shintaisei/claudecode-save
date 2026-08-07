#!/usr/bin/env python3
"""Run the official Clouseau GitHub code with envs sourced from .env.clouseau."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env.clouseau"
ARTIFACT_DIR = ROOT / "external" / "Clouseau-official" / "artifact"


def load_env_file(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def main() -> None:
    env_values = load_env_file(ENV_PATH)
    child_env = os.environ.copy()

    if env_values.get("OPENAI_API_KEY") and not child_env.get("API_KEY"):
        child_env["API_KEY"] = env_values["OPENAI_API_KEY"]
    if env_values.get("OPENAI_MODEL") and not child_env.get("LLM_MODEL"):
        child_env["LLM_MODEL"] = env_values["OPENAI_MODEL"]
    if env_values.get("OPENAI_BASE_URL") and not child_env.get("BASE_URL"):
        child_env["BASE_URL"] = env_values["OPENAI_BASE_URL"]

    if not child_env.get("API_KEY"):
        raise SystemExit("OPENAI_API_KEY is missing in .env.clouseau")
    if not child_env.get("LLM_MODEL"):
        child_env["LLM_MODEL"] = "gpt-5"

    cmd = [sys.executable, "app.py", *sys.argv[1:]]
    subprocess.run(cmd, check=True, cwd=ARTIFACT_DIR, env=child_env)


if __name__ == "__main__":
    main()
