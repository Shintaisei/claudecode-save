#!/usr/bin/env python3
"""Show per-call and cumulative CLOUSEAU API costs from the root CSV."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="clouseau_api_costs.csv", help="Cost CSV path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise SystemExit(f"Cost CSV not found: {csv_path}")

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    if not rows:
        print("No cost rows recorded yet.")
        return

    total = float(rows[-1]["cumulative_total_usd"] or 0.0)
    by_run = defaultdict(float)
    by_model = defaultdict(float)

    for row in rows:
        call_total = float(row["call_total_usd"] or 0.0)
        by_run[row["run_id"]] += call_total
        by_model[row["model"]] += call_total

    print("Latest Calls")
    for row in rows[-10:]:
        print(
            f"{row['timestamp']} | run={row['run_id']} | scenario={row['scenario']} | "
            f"model={row['model']} | call=${float(row['call_total_usd'] or 0.0):.8f} | "
            f"total=${float(row['cumulative_total_usd'] or 0.0):.8f}"
        )

    print("\nTotals By Run")
    for run_id, amount in sorted(by_run.items()):
        print(f"{run_id}: ${amount:.8f}")

    print("\nTotals By Model")
    for model, amount in sorted(by_model.items()):
        label = model or "(blank)"
        print(f"{label}: ${amount:.8f}")

    print(f"\nGrand Total: ${total:.8f}")


if __name__ == "__main__":
    main()
