import argparse
import json
import math
import pickle
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score


ROOT = Path(__file__).resolve().parents[1]
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
DEFAULT_FIELDS = [
    "Provider",
    "Channel",
    "EventID",
    "Image",
    "ParentImage",
    "User",
    "IntegrityLevel",
    "DestinationPort",
]
PATH_LIKE_FIELDS = {"Image", "ParentImage", "ParentCommandLine", "CommandLine"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a benign-only Sysmon minute-bucket experiment for ATLAS v2 scenarios."
    )
    parser.add_argument("--benign-xml", nargs="+", required=True)
    parser.add_argument("--attack-xml", required=True)
    parser.add_argument("--security-minute-source", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--time-window-minutes", type=int, default=1)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--contamination", type=float, default=0.10)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def basename_like(value: str) -> str:
    value = value.replace("\\", "/").strip()
    if "/" in value:
        return value.rsplit("/", 1)[-1].lower()
    return value.lower()


def normalize_value(key: str, value: str) -> str:
    if value is None or value == "":
        return "-"
    if key in PATH_LIKE_FIELDS:
        return basename_like(str(value))
    if key == "Provider":
        return basename_like(str(value))
    if key == "Channel":
        return str(value).replace("Microsoft-Windows-", "").replace("/Operational", "")
    return str(value).lower()


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


def parse_sysmon_xml(xml_path: Path) -> list[dict]:
    rows = []
    for _, elem in ET.iterparse(xml_path, events=("end",)):
        if not elem.tag.endswith("Event"):
            continue
        provider = elem.find("./evt:System/evt:Provider", NS)
        event_id = elem.findtext("./evt:System/evt:EventID", default="-", namespaces=NS)
        channel = elem.findtext("./evt:System/evt:Channel", default="-", namespaces=NS)
        computer = elem.findtext("./evt:System/evt:Computer", default="-", namespaces=NS).lower()
        time_created = elem.find("./evt:System/evt:TimeCreated", NS)
        event_record_id = elem.findtext(
            "./evt:System/evt:EventRecordID", default="-", namespaces=NS
        )
        event = {
            "Provider": provider.attrib.get("Name", "-") if provider is not None else "-",
            "EventID": event_id,
            "Channel": channel,
            "Computer": computer,
            "EventRecordID": event_record_id,
            "@timestamp": time_created.attrib.get("SystemTime", "")
            if time_created is not None
            else "",
        }
        for data in elem.findall("./evt:EventData/evt:Data", NS):
            name = data.attrib.get("Name", "")
            if name:
                event[name] = data.text or ""
        rows.append(event)
        elem.clear()
    rows.sort(key=lambda x: (parse_timestamp(x["@timestamp"]), str(x.get("EventRecordID", ""))))
    return rows


def parse_sysmon_xml_many(paths: list[str]) -> list[dict]:
    rows = []
    for path in paths:
        rows.extend(parse_sysmon_xml(Path(path)))
    rows.sort(key=lambda x: (parse_timestamp(x["@timestamp"]), str(x.get("EventRecordID", ""))))
    return rows


def build_template(event: dict) -> str:
    parts = []
    for key in DEFAULT_FIELDS:
        value = normalize_value(key, event.get(key, "-"))
        if value != "-":
            parts.append(f"{key}={value}")
    if not parts:
        parts.append(f"EventID={event.get('EventID', '-')}")
    return " | ".join(parts)


def event_user(event: dict) -> str:
    value = event.get("User", "")
    if not value:
        return "-"
    value = value.lower()
    if "\\" in value:
        return value.rsplit("\\", 1)[-1]
    return value


def build_session_id(event: dict, minutes: int) -> str:
    ts = parse_timestamp(event["@timestamp"])
    return f"{event['Computer']}|{event_user(event)}|{bucket_id(ts, minutes)}"


def group_events(events: list[dict], minutes: int) -> OrderedDict[str, dict]:
    grouped: OrderedDict[str, dict] = OrderedDict()
    for event in events:
        sess_id = build_session_id(event, minutes)
        if sess_id not in grouped:
            grouped[sess_id] = {"templates": [], "events": []}
        grouped[sess_id]["templates"].append(build_template(event))
        grouped[sess_id]["events"].append(event)
    return grouped


def split_sessions(session_ids: list[str], train_ratio: float = 0.8) -> tuple[list[str], list[str]]:
    split_idx = max(1, int(math.floor(len(session_ids) * train_ratio)))
    split_idx = min(split_idx, len(session_ids))
    train_ids = session_ids[:split_idx]
    test_ids = session_ids[split_idx:]
    if not test_ids and session_ids:
        train_ids = session_ids[:-1]
        test_ids = session_ids[-1:]
    return train_ids, test_ids


def tokenized_session(sample: dict) -> str:
    return " || ".join(sample["templates"])


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def evaluate_threshold(scores: list[float], y_true: list[int], threshold: float) -> dict:
    y_pred = [int(score > threshold) for score in scores]
    return {
        "threshold": float(threshold),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "rc": float(recall_score(y_true, y_pred, zero_division=0)),
        "pc": float(precision_score(y_true, y_pred, zero_division=0)),
        "predicted_positive": int(sum(y_pred)),
    }


def build_security_anomaly_map(path: Path) -> dict[str, int]:
    with path.open("rb") as fh:
        session_dict = pickle.load(fh)
    by_bucket = defaultdict(int)
    for session_id, sample in session_dict.items():
        bucket = session_id.split("|")[2]
        by_bucket[bucket] += int(sum(sample["label"]))
    return {bucket: int(value > 0) for bucket, value in by_bucket.items()}


def summarize_bucket(sample: dict) -> dict:
    event_ids = Counter()
    images = Counter()
    users = Counter()
    for event in sample["events"]:
        event_ids[normalize_value("EventID", event.get("EventID", "-"))] += 1
        image = normalize_value("Image", event.get("Image", "-"))
        if image != "-":
            images[image] += 1
        user = event_user(event)
        if user != "-":
            users[user] += 1
    return {
        "top_event_ids": event_ids.most_common(5),
        "top_images": images.most_common(5),
        "top_users": users.most_common(5),
    }


def main() -> int:
    args = parse_args()
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    benign_events = parse_sysmon_xml_many(args.benign_xml)
    attack_events = parse_sysmon_xml(Path(args.attack_xml))

    benign_grouped = group_events(benign_events, args.time_window_minutes)
    attack_grouped = group_events(attack_events, args.time_window_minutes)

    benign_ids = list(benign_grouped.keys())
    train_ids, val_ids = split_sessions(benign_ids, train_ratio=0.8)
    benign_train = OrderedDict((sid, benign_grouped[sid]) for sid in train_ids)
    benign_val = OrderedDict((sid, benign_grouped[sid]) for sid in val_ids)

    security_anomaly_map = build_security_anomaly_map(ROOT / args.security_minute_source)
    attack_ids = list(attack_grouped.keys())
    y_attack = [security_anomaly_map.get(sid.split("|")[2], 0) for sid in attack_ids]

    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(args.ngram_min, args.ngram_max),
        max_features=args.max_features,
    )
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in benign_train.values())
    x_val = vectorizer.transform(tokenized_session(sample) for sample in benign_val.values())
    x_attack = vectorizer.transform(tokenized_session(sample) for sample in attack_grouped.values())

    model = IsolationForest(
        n_estimators=300,
        contamination=args.contamination,
        random_state=args.random_seed,
        n_jobs=1,
    )
    model.fit(x_train)

    train_scores = (-model.score_samples(x_train)).tolist()
    val_scores = (-model.score_samples(x_val)).tolist()
    attack_scores = (-model.score_samples(x_attack)).tolist()

    benign_thresholds = {
        "p95_0": percentile(val_scores, 95.0),
        "p99_0": percentile(val_scores, 99.0),
    }
    benign_eval = {
        key: evaluate_threshold(attack_scores, y_attack, threshold)
        for key, threshold in benign_thresholds.items()
    }

    oracle_best = None
    for threshold in sorted(attack_scores):
        candidate = evaluate_threshold(attack_scores, y_attack, threshold)
        if oracle_best is None or candidate["f1"] > oracle_best["f1"]:
            oracle_best = candidate

    attack_rows = []
    for session_id, score, label in zip(attack_ids, attack_scores, y_attack):
        sample = attack_grouped[session_id]
        summary = summarize_bucket(sample)
        attack_rows.append(
            {
                "session_id": session_id,
                "bucket": session_id.split("|")[2],
                "score": float(score),
                "pseudo_anomaly": int(label),
                "events": len(sample["templates"]),
                "top_event_ids": summary["top_event_ids"],
                "top_images": summary["top_images"],
                "top_users": summary["top_users"],
            }
        )
    top_by_score = sorted(attack_rows, key=lambda x: x["score"], reverse=True)[: args.top_k]

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "benign_buckets_train": len(benign_train),
        "benign_buckets_val": len(benign_val),
        "attack_buckets": len(attack_grouped),
        "attack_pseudo_anomalous_buckets": int(sum(y_attack)),
        "security_anomaly_minutes": sorted([k for k, v in security_anomaly_map.items() if v == 1]),
        "oracle_best": oracle_best,
        "benign_thresholds": benign_eval,
        "score_summary": {
            "train_mean": float(sum(train_scores) / len(train_scores)),
            "val_mean": float(sum(val_scores) / len(val_scores)),
            "attack_mean": float(sum(attack_scores) / len(attack_scores)),
        },
        "top_sysmon_buckets": top_by_score,
    }
    dump_json(output_dir / "results.json", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
