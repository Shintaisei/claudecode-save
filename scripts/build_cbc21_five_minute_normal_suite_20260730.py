"""Create the 21-case normal suite by excluding the two repeated long-window cases.

The source 23-case suite is immutable.  This builder is intentionally create-only:
it refuses to overwrite either the filtered JSONL or its audit manifest.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "data"
    / "current_experiment"
    / "cases"
    / "cbc_23_chain_stage_cases_2026-06-12.jsonl"
)
OUTPUT = (
    ROOT
    / "data"
    / "current_experiment"
    / "cases"
    / "cbc_21_five_minute_chain_stage_cases_20260730.jsonl"
)
MANIFEST = (
    ROOT
    / "docs"
    / "current_experiment"
    / "cbc_21_five_minute_normal_suite_manifest_20260730.json"
)

EXCLUDED = {
    "chain_07_e05_sublime_python_script_execution_chain": {
        "window_minutes": 10,
        "reason": "two nearby Sublime/Python executions grouped into one Gold chain",
    },
    "chain_13_e09_dns_packet_capture_batch_chain": {
        "window_minutes": 15,
        "reason": "two DNS capture batch executions about ten minutes apart grouped into one Gold chain",
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def window_minutes(row: dict) -> float:
    window = row["time_window_utc"]
    start = datetime.fromisoformat(window["episode_start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(window["episode_end"].replace("Z", "+00:00"))
    return (end - start).total_seconds() / 60.0


def main() -> None:
    for target in (OUTPUT, MANIFEST):
        if target.exists():
            raise FileExistsError(f"create-only target already exists: {target}")

    source_rows = [
        json.loads(line)
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    source_chain_ids = {row["chain_id"] for row in source_rows}
    if len(source_rows) != 69 or len(source_chain_ids) != 23:
        raise ValueError(
            f"unexpected source cardinality: rows={len(source_rows)}, "
            f"chains={len(source_chain_ids)}"
        )
    if not set(EXCLUDED).issubset(source_chain_ids):
        raise ValueError("one or more excluded chain IDs are absent from source")

    output_rows = [
        row for row in source_rows if row["chain_id"] not in EXCLUDED
    ]
    output_chain_ids = {row["chain_id"] for row in output_rows}
    durations = Counter(window_minutes(row) for row in output_rows)

    if len(output_rows) != 63 or len(output_chain_ids) != 21:
        raise ValueError(
            f"unexpected output cardinality: rows={len(output_rows)}, "
            f"chains={len(output_chain_ids)}"
        )
    if durations != Counter({5.0: 63}):
        raise ValueError(f"remaining suite is not uniformly five minutes: {durations}")
    if Counter(row["stage"] for row in output_rows) != Counter(
        {"stage1": 21, "stage2": 21, "stage3": 21}
    ):
        raise ValueError("stage cardinality mismatch")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            for row in output_rows
        ),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "cbc_21_five_minute_normal_suite_manifest_v1",
        "created_at_utc": datetime.now().astimezone().isoformat(),
        "source": str(SOURCE.relative_to(ROOT)),
        "source_sha256": sha256(SOURCE),
        "output": str(OUTPUT.relative_to(ROOT)),
        "output_sha256": sha256(OUTPUT),
        "source_chain_count": 23,
        "output_chain_count": 21,
        "source_row_count": 69,
        "output_row_count": 63,
        "stage_counts": {"stage1": 21, "stage2": 21, "stage3": 21},
        "remaining_window_minutes": 5,
        "excluded": EXCLUDED,
        "policy": (
            "Exclude only the two Gold chains that group temporally separated "
            "repetitions; preserve all source rows and Gold files unchanged."
        ),
        "audit": {
            "excluded_absent": not (set(EXCLUDED) & output_chain_ids),
            "all_remaining_windows_five_minutes": durations == Counter({5.0: 63}),
            "cardinality_pass": len(output_chain_ids) == 21,
            "status": "PASS",
        },
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(OUTPUT)
    print(MANIFEST)


if __name__ == "__main__":
    main()
