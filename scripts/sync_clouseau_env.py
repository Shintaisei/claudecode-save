#!/usr/bin/env python3
"""Copy the root CLOUSEAU env file to Clouseau/artifact/.env."""

from __future__ import annotations

from pathlib import Path


ROOT_ENV = Path(".env.clouseau")
ARTIFACT_ENV = Path("Clouseau") / "artifact" / ".env"


def main() -> None:
    if not ROOT_ENV.exists():
        raise SystemExit(f"Missing root env file: {ROOT_ENV}")
    ARTIFACT_ENV.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_ENV.write_text(ROOT_ENV.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Synced {ROOT_ENV} -> {ARTIFACT_ENV}")


if __name__ == "__main__":
    main()
