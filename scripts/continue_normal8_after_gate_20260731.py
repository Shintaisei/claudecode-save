"""Start the normal8 full phase only after the live sentinel gate passes.

This is a narrow continuation supervisor for the approved formal_04 run.  It
does not execute or retry the gate itself.  It observes the specified gate
PID, requires a deterministic PASS artifact, and then starts ``--full`` in a
separate hidden process.  A failed gate never launches the full experiment.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = (
    ROOT
    / "docs/current_experiment/results_2026-07-31"
    / "normal8_three_model_three_stage_formal_04"
)
DRIVER = ROOT / "scripts/run_normal8_three_model_formal_20260731.py"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def process_is_alive(pid: int) -> bool:
    process_query_limited_information = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(
        process_query_limited_information,
        False,
        pid,
    )
    if not handle:
        return False
    ctypes.windll.kernel32.CloseHandle(handle)
    return True


def write_create_only(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    with path.open("x", encoding="utf-8") as handle:
        handle.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-pid", type=int, required=True)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    args = parser.parse_args()

    gate_audit_path = RESULT_ROOT / "gate_audit.json"
    status_path = RESULT_ROOT / "_logs" / "continuation_status.json"
    full_stdout = RESULT_ROOT / "_logs" / "full_stdout.log"
    full_stderr = RESULT_ROOT / "_logs" / "full_stderr.log"

    while True:
        if gate_audit_path.is_file():
            gate_audit = json.loads(
                gate_audit_path.read_text(encoding="utf-8")
            )
            if gate_audit.get("status") != "PASS":
                write_create_only(
                    status_path,
                    {
                        "schema_version": "normal8_continuation_v1",
                        "at_utc": utc_now(),
                        "status": "NOT_STARTED",
                        "reason": "gate_audit_not_pass",
                        "gate_status": gate_audit.get("status"),
                    },
                )
                return

            full_stdout.parent.mkdir(parents=True, exist_ok=True)
            with full_stdout.open("x", encoding="utf-8") as stdout_handle, (
                full_stderr.open("x", encoding="utf-8")
            ) as stderr_handle:
                creation_flags = getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0,
                )
                process = subprocess.Popen(
                    [sys.executable, str(DRIVER), "--full"],
                    cwd=ROOT,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    creationflags=creation_flags,
                )
            write_create_only(
                status_path,
                {
                    "schema_version": "normal8_continuation_v1",
                    "at_utc": utc_now(),
                    "status": "FULL_STARTED",
                    "gate_status": "PASS",
                    "full_pid": process.pid,
                    "stdout": str(full_stdout),
                    "stderr": str(full_stderr),
                },
            )
            return

        if not process_is_alive(args.gate_pid):
            write_create_only(
                status_path,
                {
                    "schema_version": "normal8_continuation_v1",
                    "at_utc": utc_now(),
                    "status": "NOT_STARTED",
                    "reason": "gate_process_exited_without_audit",
                    "gate_pid": args.gate_pid,
                },
            )
            return
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
