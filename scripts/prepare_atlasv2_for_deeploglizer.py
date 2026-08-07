import argparse
import json
import math
import pickle
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_FIELDS = [
    "Provider",
    "Channel",
    "EventID",
    "ProcessName",
    "NewProcessName",
    "Image",
    "Application",
    "ObjectType",
    "DestPort",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert ATLAS v2 JSONL into deep-loglizer session data."
    )
    parser.add_argument(
        "--jsonl",
        nargs="+",
        required=True,
        help="One or more input ATLAS v2 JSONL paths",
    )
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument(
        "--groundtruth",
        help="Optional ground truth file containing one EventRecordID per line",
    )
    parser.add_argument(
        "--session-mode",
        default="computer_user",
        choices=[
            "all",
            "computer",
            "user",
            "process",
            "computer_user",
            "computer_process",
        ],
        help="How to group events into sessions before time bucketing",
    )
    parser.add_argument(
        "--time-window-minutes",
        type=int,
        default=30,
        help="Time bucket size used in session grouping",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Fraction of sessions assigned to train split",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="Optional cap for the number of events to read, 0 means unlimited",
    )
    parser.add_argument(
        "--max-events-per-session",
        type=int,
        default=0,
        help="Optional cap for events per session chunk, 0 means unlimited",
    )
    return parser.parse_args()


def load_groundtruth(path: str | None) -> set[str]:
    if not path:
        return set()
    gt_path = Path(path)
    return {
        line.strip()
        for line in gt_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def basename_like(value: str) -> str:
    if not value:
        return "-"
    value = value.replace("\\", "/").strip()
    if "/" in value:
        return value.rsplit("/", 1)[-1].lower()
    return value.lower()


def normalize_value(key: str, value) -> str:
    if value is None or value == "":
        return "-"
    if key in {"ProcessName", "NewProcessName", "Image", "Application"}:
        return basename_like(str(value))
    if key == "Provider":
        return basename_like(str(value))
    if key == "Channel":
        return str(value).replace("Microsoft-Windows-", "").replace("/Operational", "")
    if key == "ObjectType":
        return str(value).lower()
    if key == "DestPort":
        return str(value)
    if key == "EventID":
        return str(value)
    return str(value)


def build_template(event: dict) -> str:
    parts = []
    for key in DEFAULT_FIELDS:
        value = normalize_value(key, event.get(key))
        if value != "-":
            parts.append(f"{key}={value}")
    if not parts:
        parts.append(f"EventID={event.get('EventID', '-')}")
    return " | ".join(parts)


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def bucket_id(ts: datetime, minutes: int) -> str:
    bucket_seconds = minutes * 60
    bucket_epoch = int(ts.timestamp()) // bucket_seconds * bucket_seconds
    bucket_dt = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    return bucket_dt.strftime("%Y%m%dT%H%MZ")


def event_actor(event: dict) -> str:
    for key in ("ProcessName", "NewProcessName", "Image", "Application"):
        value = event.get(key)
        if value:
            return basename_like(str(value))
    return "-"


def event_user(event: dict) -> str:
    for key in ("SubjectUserName", "User", "UserName", "TargetUserName"):
        value = event.get(key)
        if value:
            return str(value).lower()
    return "-"


def session_prefix(event: dict, mode: str) -> str:
    computer = str(event.get("Computer", "-")).lower()
    user = event_user(event)
    process = event_actor(event)
    if mode == "all":
        return "all"
    if mode == "computer":
        return computer
    if mode == "user":
        return user
    if mode == "process":
        return process
    if mode == "computer_user":
        return f"{computer}|{user}"
    if mode == "computer_process":
        return f"{computer}|{process}"
    return "all"


def build_session_id(event: dict, mode: str, time_window_minutes: int) -> str:
    if mode == "all":
        return "all"
    ts = parse_timestamp(event["@timestamp"])
    return f"{session_prefix(event, mode)}|{bucket_id(ts, time_window_minutes)}"


def read_events(jsonl_paths: list[Path], max_events: int) -> list[dict]:
    events: list[dict] = []
    count = 0
    for jsonl_path in jsonl_paths:
        with jsonl_path.open(encoding="utf-8") as fh:
            for line in fh:
                if max_events and count >= max_events:
                    break
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                if "@timestamp" not in event:
                    continue
                events.append(event)
                count += 1
        if max_events and count >= max_events:
            break
    events.sort(
        key=lambda x: (
            parse_timestamp(x["@timestamp"]),
            str(x.get("EventRecordID", "")),
        )
    )
    return events


def split_sessions(session_ids: list[str], train_ratio: float) -> tuple[set[str], set[str]]:
    split_idx = max(1, int(math.floor(len(session_ids) * train_ratio)))
    split_idx = min(split_idx, len(session_ids))
    train_ids = set(session_ids[:split_idx])
    test_ids = set(session_ids[split_idx:])
    if not test_ids and session_ids:
        last_id = session_ids[-1]
        train_ids.discard(last_id)
        test_ids.add(last_id)
    return train_ids, test_ids


def session_is_anomalous(labels: Iterable[int]) -> int:
    return int(any(label == 1 for label in labels))


def chunk_grouped_sessions(
    grouped: OrderedDict[str, dict], max_events_per_session: int
) -> OrderedDict[str, dict]:
    if max_events_per_session <= 0:
        return grouped

    chunked: OrderedDict[str, dict] = OrderedDict()
    for sess_id, payload in grouped.items():
        templates = payload["templates"]
        labels = payload["label"]
        if len(templates) <= max_events_per_session:
            chunked[sess_id] = payload
            continue
        chunk_count = math.ceil(len(templates) / max_events_per_session)
        for idx in range(chunk_count):
            start = idx * max_events_per_session
            end = start + max_events_per_session
            chunked[f"{sess_id}|chunk{idx:03d}"] = {
                "templates": templates[start:end],
                "label": labels[start:end],
            }
    return chunked


def convert(
    events: list[dict],
    groundtruth_ids: set[str],
    session_mode: str,
    time_window_minutes: int,
    train_ratio: float,
    max_events_per_session: int,
) -> tuple[dict, dict, dict]:
    grouped: OrderedDict[str, dict] = OrderedDict()
    for event in events:
        sess_id = build_session_id(event, session_mode, time_window_minutes)
        if sess_id not in grouped:
            grouped[sess_id] = defaultdict(list)
        record_id = str(event.get("EventRecordID", "")).strip()
        label = int(record_id in groundtruth_ids) if groundtruth_ids else 0
        grouped[sess_id]["templates"].append(build_template(event))
        grouped[sess_id]["label"].append(label)

    grouped = chunk_grouped_sessions(grouped, max_events_per_session)
    session_ids = list(grouped.keys())
    train_ids, test_ids = split_sessions(session_ids, train_ratio)

    session_train = OrderedDict()
    session_test = OrderedDict()
    for sess_id, payload in grouped.items():
        sample = {
            "templates": payload["templates"],
            "label": payload["label"],
        }
        if sess_id in train_ids:
            session_train[sess_id] = sample
        else:
            session_test[sess_id] = sample

    meta = {
        "session_mode": session_mode,
        "time_window_minutes": time_window_minutes,
        "train_ratio": train_ratio,
        "max_events_per_session": max_events_per_session,
        "events": len(events),
        "sessions_total": len(grouped),
        "sessions_train": len(session_train),
        "sessions_test": len(session_test),
        "event_anomalies_total": sum(
            sum(sample["label"]) for sample in grouped.values()
        ),
        "session_anomalies_train": sum(
            session_is_anomalous(sample["label"]) for sample in session_train.values()
        ),
        "session_anomalies_test": sum(
            session_is_anomalous(sample["label"]) for sample in session_test.values()
        ),
    }
    return session_train, session_test, meta


def dump_outputs(
    output_dir: Path,
    source_jsonl: list[Path],
    groundtruth_path: str | None,
    session_train: dict,
    session_test: dict,
    meta: dict,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    data_desc = {
        "source_jsonl": [str(path) for path in source_jsonl],
        "groundtruth": groundtruth_path or "",
        **meta,
    }
    (output_dir / "data_desc.json").write_text(
        json.dumps(data_desc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with (output_dir / "session_train.pkl").open("wb") as fh:
        pickle.dump(session_train, fh)
    with (output_dir / "session_test.pkl").open("wb") as fh:
        pickle.dump(session_test, fh)


def main() -> None:
    args = parse_args()
    jsonl_paths = [Path(path) for path in args.jsonl]
    output_dir = Path(args.output_dir)
    groundtruth_ids = load_groundtruth(args.groundtruth)
    events = read_events(jsonl_paths, args.max_events)
    session_train, session_test, meta = convert(
        events=events,
        groundtruth_ids=groundtruth_ids,
        session_mode=args.session_mode,
        time_window_minutes=args.time_window_minutes,
        train_ratio=args.train_ratio,
        max_events_per_session=args.max_events_per_session,
    )
    dump_outputs(
        output_dir=output_dir,
        source_jsonl=jsonl_paths,
        groundtruth_path=args.groundtruth,
        session_train=session_train,
        session_test=session_test,
        meta=meta,
    )
    print(output_dir)
    print(json.dumps(meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
