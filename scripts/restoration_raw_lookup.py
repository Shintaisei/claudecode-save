"""Resolve ATLASv2 Security JSONL paths and index raw events per session."""

from __future__ import annotations

import json
import sys
from collections import OrderedDict
from pathlib import Path


def _import_prepare():
    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import prepare_atlasv2_for_deeploglizer as prep

    return prep


def resolve_jsonl_path(
    scenario: str,
    root: Path,
    jsonl_dir: Path | None = None,
) -> tuple[Path | None, Path | None, str]:
    """Return (jsonl_path, groundtruth_path, status_message)."""
    scenario = scenario.lower()
    candidates: list[Path] = []
    if jsonl_dir:
        candidates.append(jsonl_dir / f"msft-security-h1-{scenario}.jsonl")
    candidates.append(root / "analysis_data" / "atlasv2_attack_runs" / "jsonl" / f"msft-security-h1-{scenario}.jsonl")

    data_desc = (
        root
        / "analysis_data"
        / "atlasv2_for_deep-loglizer"
        / f"exp_benign1to4_vs_{scenario}_cu10"
        / "data_desc.json"
    )
    if data_desc.exists():
        desc = json.loads(data_desc.read_text(encoding="utf-8"))
        test_desc = desc.get("test_desc", {})
        src = test_desc.get("source_jsonl", "")
        if src:
            candidates.append(Path(src))
        gt = test_desc.get("groundtruth", "")
        gt_path = Path(gt) if gt else None
    else:
        gt_path = None

    jsonl_path = next((p for p in candidates if p.exists()), None)
    if jsonl_path and gt_path and not gt_path.exists():
        gt_path = None

    if jsonl_path:
        return jsonl_path, gt_path, f"OK: {jsonl_path.name}"
    expected = candidates[0] if candidates else Path(f"msft-security-h1-{scenario}.jsonl")
    return None, gt_path, f"JSONL不在 → {expected} に配置後に再生成"


def build_session_event_index(
    jsonl_path: Path,
    groundtruth_path: Path | None,
    session_mode: str = "computer_user",
    time_window_minutes: int = 10,
) -> dict[str, list[dict]]:
    prep = _import_prepare()
    gt_ids = prep.load_groundtruth(str(groundtruth_path) if groundtruth_path else None)
    events = prep.read_events([jsonl_path], max_events=0)
    grouped: OrderedDict[str, list[dict]] = OrderedDict()
    for event in events:
        sess_id = prep.build_session_id(event, session_mode, time_window_minutes)
        grouped.setdefault(sess_id, []).append(event)
    return dict(grouped)


def global_offset(
    coarse_chunk_index: int,
    micro_chunk_index: int,
    offset_in_micro: int,
    coarse_chunk_size: int = 100,
    micro_chunk_size: int = 10,
) -> int:
    return (
        int(coarse_chunk_index) * coarse_chunk_size
        + int(micro_chunk_index) * micro_chunk_size
        + (int(offset_in_micro) - 1)
    )


def lookup_raw_event(
    session_index: dict[str, list[dict]],
    parent_session_id: str,
    coarse_chunk_index: int,
    micro_chunk_index: int,
    offset_in_micro: int,
) -> dict | None:
    events = session_index.get(parent_session_id)
    if not events:
        return None
    idx = global_offset(coarse_chunk_index, micro_chunk_index, offset_in_micro)
    if 0 <= idx < len(events):
        return events[idx]
    return None
