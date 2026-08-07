from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
AUDIT_ROOT = ROOT / "data/current_experiment/scores/formal_23_chain_2rep_20260612/strict_reaudit_20260613"
MANIFEST = AUDIT_ROOT / "strict_reaudit_manifest.jsonl"
OUT = AUDIT_ROOT / "strict_reaudit_discrepancy_union_27.jsonl"


KEYS = [
    ("replicate_01", "gpt-4.1-mini", "stage1", "chain_06_e04_python_simplehttpserver_network_chain_stage1"),
    ("replicate_01", "gpt-4.1-mini", "stage1", "chain_14_e09_python_simplehttpserver_network_chain_stage1"),
    ("replicate_01", "gpt-4.1-mini", "stage1", "chain_21_e15_python_simplehttpserver_network_chain_stage1"),
    ("replicate_01", "gpt-4.1-mini", "stage1", "chain_26_e18_python_simplehttpserver_network_chain_stage1"),
    ("replicate_01", "gpt-4.1-mini", "stage2", "chain_05_e03_python_simplehttpserver_network_chain_stage2"),
    ("replicate_01", "gpt-4.1-mini", "stage2", "chain_12_e08_python_simplehttpserver_network_chain_stage2"),
    ("replicate_01", "gpt-4.1-mini", "stage2", "chain_23_e17_python_simplehttpserver_network_chain_stage2"),
    ("replicate_01", "gpt-4.1-mini", "stage3", "chain_01_e01_dns_packet_capture_batch_chain_stage3"),
    ("replicate_01", "gpt-4.1-mini", "stage3", "chain_04_e03_dns_packet_capture_batch_chain_stage3"),
    ("replicate_01", "gpt-4.1-mini", "stage3", "chain_14_e09_python_simplehttpserver_network_chain_stage3"),
    ("replicate_01", "gpt-4.1-mini", "stage3", "chain_19_e13_python_simplehttpserver_network_chain_stage3"),
    ("replicate_01", "gpt-4.1-mini", "stage3", "chain_23_e17_python_simplehttpserver_network_chain_stage3"),
    ("replicate_01", "gpt-4.1-mini", "stage3", "chain_26_e18_python_simplehttpserver_network_chain_stage3"),
    ("replicate_01", "gpt-5.4-mini", "stage2", "chain_16_e11_python_simplehttpserver_network_chain_stage2"),
    ("replicate_01", "gpt-5.4-mini", "stage2", "chain_19_e13_python_simplehttpserver_network_chain_stage2"),
    ("replicate_01", "gpt-5.4-mini", "stage3", "chain_25_e18_dns_packet_capture_batch_chain_stage3"),
    ("replicate_02", "gpt-4.1-mini", "stage1", "chain_05_e03_python_simplehttpserver_network_chain_stage1"),
    ("replicate_02", "gpt-4.1-mini", "stage1", "chain_14_e09_python_simplehttpserver_network_chain_stage1"),
    ("replicate_02", "gpt-4.1-mini", "stage2", "chain_21_e15_python_simplehttpserver_network_chain_stage2"),
    ("replicate_02", "gpt-4.1-mini", "stage2", "chain_22_e16_python_simplehttpserver_network_chain_stage2"),
    ("replicate_02", "gpt-4.1-mini", "stage3", "chain_23_e17_python_simplehttpserver_network_chain_stage3"),
    ("replicate_02", "gpt-4.1-mini", "stage3", "chain_25_e18_dns_packet_capture_batch_chain_stage3"),
    ("replicate_02", "gpt-5.4-mini", "stage1", "chain_22_e16_python_simplehttpserver_network_chain_stage1"),
    ("replicate_02", "gpt-5.4-mini", "stage2", "chain_10_e07_discord_run_key_registry_chain_stage2"),
    ("replicate_02", "gpt-5.4-mini", "stage2", "chain_13_e09_dns_packet_capture_batch_chain_stage2"),
    ("replicate_02", "gpt-5.4-mini", "stage2", "chain_22_e16_python_simplehttpserver_network_chain_stage2"),
    ("replicate_02", "gpt-5.4-mini", "stage3", "chain_10_e07_discord_run_key_registry_chain_stage3"),
]


def row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    key = row["key"]
    return (
        str(key["replicate"]),
        str(key["model"]),
        str(key["stage"]),
        str(key["instance_id"]),
    )


def main() -> None:
    rows = [json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_key = {row_key(row): row for row in rows}
    selected = []
    missing = []
    for item in KEYS:
        row = by_key.get(item)
        if row is None:
            missing.append(item)
            continue
        selected.append(row)
    with OUT.open("w", encoding="utf-8", newline="") as f:
        for row in selected:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(
        json.dumps(
            {
                "selected": len(selected),
                "missing": missing,
                "output": OUT.relative_to(ROOT).as_posix(),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
