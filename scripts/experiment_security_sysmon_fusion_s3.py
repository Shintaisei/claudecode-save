import argparse
import json
import math
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pickle
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score


ROOT = Path(__file__).resolve().parents[1]
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
SYSMON_FIELDS = [
    "Provider",
    "Channel",
    "EventID",
    "Image",
    "ParentImage",
    "User",
    "IntegrityLevel",
    "DestinationPort",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare Security-only, Sysmon-only, and fused minute detectors on ATLAS v2 S3."
    )
    parser.add_argument("--security-exp-dir", required=True)
    parser.add_argument("--sysmon-benign-xml", required=True)
    parser.add_argument("--sysmon-attack-xml", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--contamination", type=float, default=0.10)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--top-k", type=int, default=10)
    return parser.parse_args()


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def basename_like(value: str) -> str:
    value = value.replace("\\", "/").strip()
    if "/" in value:
        return value.rsplit("/", 1)[-1].lower()
    return value.lower()


def normalize_value(key: str, value: str) -> str:
    if value is None or value == "":
        return "-"
    if key in {"ProcessName", "Image", "ParentImage", "NewProcessName"}:
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


def minute_bucket(ts: datetime) -> str:
    bucket_epoch = int(ts.timestamp()) // 60 * 60
    bucket_dt = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    return bucket_dt.strftime("%Y%m%dT%H%MZ")


def event_user(event: dict) -> str:
    for key in ("User", "SubjectUserName", "UserName", "TargetUserName"):
        value = event.get(key, "")
        if value:
            value = str(value).lower()
            if "\\" in value:
                value = value.rsplit("\\", 1)[-1]
            return value
    return "-"


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


def train_iforest_scores(
    train_docs: OrderedDict[str, dict],
    val_docs: OrderedDict[str, dict],
    test_docs: OrderedDict[str, dict],
    ngram_min: int,
    ngram_max: int,
    max_features: int,
    contamination: float,
    random_seed: int,
) -> tuple[list[float], list[float], list[float]]:
    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(ngram_min, ngram_max),
        max_features=max_features,
    )
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_docs.values())
    x_val = vectorizer.transform(tokenized_session(sample) for sample in val_docs.values())
    x_test = vectorizer.transform(tokenized_session(sample) for sample in test_docs.values())

    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        random_state=random_seed,
        n_jobs=1,
    )
    model.fit(x_train)
    return (
        (-model.score_samples(x_train)).tolist(),
        (-model.score_samples(x_val)).tolist(),
        (-model.score_samples(x_test)).tolist(),
    )


def security_minute_from_samples(session_dict: dict) -> OrderedDict[str, dict]:
    grouped = OrderedDict()
    for session_id, sample in session_dict.items():
        parts = session_id.split("|")
        bucket = parts[2]
        if bucket not in grouped:
            grouped[bucket] = {
                "templates": [],
                "label": [],
                "source_sessions": [],
            }
        grouped[bucket]["templates"].extend(sample["templates"])
        label = sample["label"]
        if isinstance(label, list):
            grouped[bucket]["label"].extend(label)
        else:
            grouped[bucket]["label"].append(label)
        grouped[bucket]["source_sessions"].append(session_id)
    return grouped


def security_label(sample: dict) -> int:
    return int(any(int(x) == 1 for x in sample["label"]))


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
        event = {
            "Provider": provider.attrib.get("Name", "-") if provider is not None else "-",
            "EventID": event_id,
            "Channel": channel,
            "Computer": computer,
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
    rows.sort(key=lambda x: parse_timestamp(x["@timestamp"]))
    return rows


def build_sysmon_template(event: dict) -> str:
    parts = []
    for key in SYSMON_FIELDS:
        value = normalize_value(key, event.get(key, "-"))
        if value != "-":
            parts.append(f"{key}={value}")
    if not parts:
        parts.append(f"EventID={event.get('EventID', '-')}")
    return " | ".join(parts)


def sysmon_minute_from_events(events: list[dict]) -> OrderedDict[str, dict]:
    grouped = OrderedDict()
    for event in events:
        bucket = minute_bucket(parse_timestamp(event["@timestamp"]))
        if bucket not in grouped:
            grouped[bucket] = {
                "templates": [],
                "events": [],
            }
        grouped[bucket]["templates"].append(build_sysmon_template(event))
        grouped[bucket]["events"].append(event)
    return grouped


def split_ordered_docs(docs: OrderedDict[str, dict], train_ratio: float = 0.8) -> tuple[OrderedDict[str, dict], OrderedDict[str, dict]]:
    keys = list(docs.keys())
    split_idx = max(1, int(math.floor(len(keys) * train_ratio)))
    split_idx = min(split_idx, len(keys))
    train_keys = keys[:split_idx]
    val_keys = keys[split_idx:]
    if not val_keys and keys:
        train_keys = keys[:-1]
        val_keys = keys[-1:]
    return (
        OrderedDict((key, docs[key]) for key in train_keys),
        OrderedDict((key, docs[key]) for key in val_keys),
    )


def summarize_sysmon_minute(sample: dict) -> dict:
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


def build_ratio_scores(scores: list[float], threshold: float) -> list[float]:
    return [score / max(threshold, 1e-9) for score in scores]


def main() -> int:
    args = parse_args()
    security_exp_dir = ROOT / args.security_exp_dir
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    security_train_raw = load_pickle(security_exp_dir / "session_train.pkl")
    security_test_raw = load_pickle(security_exp_dir / "session_test.pkl")

    train_source = json.loads((security_exp_dir / "data_desc.json").read_text(encoding="utf-8"))[
        "train_source"
    ]
    security_val_raw = load_pickle(ROOT / train_source / "session_test.pkl")

    security_train = security_minute_from_samples(security_train_raw)
    security_val = security_minute_from_samples(security_val_raw)
    security_test = security_minute_from_samples(security_test_raw)
    y_true = [security_label(sample) for sample in security_test.values()]
    minute_keys = list(security_test.keys())

    sec_train_scores, sec_val_scores, sec_test_scores = train_iforest_scores(
        security_train,
        security_val,
        security_test,
        args.ngram_min,
        args.ngram_max,
        args.max_features,
        args.contamination,
        args.random_seed,
    )
    sec_threshold = percentile(sec_val_scores, 99.0)
    sec_eval = evaluate_threshold(sec_test_scores, y_true, sec_threshold)

    benign_sysmon = parse_sysmon_xml(Path(args.sysmon_benign_xml))
    attack_sysmon = parse_sysmon_xml(Path(args.sysmon_attack_xml))
    sysmon_benign_docs = sysmon_minute_from_events(benign_sysmon)
    sysmon_attack_docs = sysmon_minute_from_events(attack_sysmon)
    sysmon_train, sysmon_val = split_ordered_docs(sysmon_benign_docs, 0.8)

    aligned_sysmon_test = OrderedDict()
    for minute in minute_keys:
        if minute in sysmon_attack_docs:
            aligned_sysmon_test[minute] = sysmon_attack_docs[minute]
        else:
            aligned_sysmon_test[minute] = {"templates": ["missing_sysmon_bucket"], "events": []}

    _, sys_val_scores, sys_test_scores = train_iforest_scores(
        sysmon_train,
        sysmon_val,
        aligned_sysmon_test,
        args.ngram_min,
        args.ngram_max,
        args.max_features,
        args.contamination,
        args.random_seed,
    )
    sys_threshold = percentile(sys_val_scores, 99.0)
    sys_eval = evaluate_threshold(sys_test_scores, y_true, sys_threshold)

    sec_ratio = build_ratio_scores(sec_test_scores, sec_threshold)
    sys_ratio = build_ratio_scores(sys_test_scores, sys_threshold)
    fused_scores = [max(sec, 0.8 * sys) for sec, sys in zip(sec_ratio, sys_ratio)]
    fused_val_scores = [
        max(sec / max(sec_threshold, 1e-9), 0.8 * (sys / max(sys_threshold, 1e-9)))
        for sec, sys in zip(sec_val_scores[: min(len(sec_val_scores), len(sys_val_scores))], sys_val_scores[: min(len(sec_val_scores), len(sys_val_scores))])
    ]
    fused_threshold = percentile(fused_val_scores, 99.0) if fused_val_scores else 1.0
    fused_eval = evaluate_threshold(fused_scores, y_true, fused_threshold)

    oracle_best = None
    for threshold in sorted(fused_scores):
        candidate = evaluate_threshold(fused_scores, y_true, threshold)
        if oracle_best is None or candidate["f1"] > oracle_best["f1"]:
            oracle_best = candidate

    rows = []
    for minute, label, sec_score, sys_score, fused_score in zip(
        minute_keys, y_true, sec_test_scores, sys_test_scores, fused_scores
    ):
        sysmon_sample = aligned_sysmon_test[minute]
        sys_summary = summarize_sysmon_minute(sysmon_sample) if sysmon_sample["events"] else {
            "top_event_ids": [],
            "top_images": [],
            "top_users": [],
        }
        rows.append(
            {
                "minute": minute,
                "security_label": int(label),
                "security_score": float(sec_score),
                "sysmon_score": float(sys_score),
                "fused_score": float(fused_score),
                "sysmon_events": len(sysmon_sample["events"]),
                "top_sysmon_event_ids": sys_summary["top_event_ids"],
                "top_sysmon_images": sys_summary["top_images"],
                "top_sysmon_users": sys_summary["top_users"],
            }
        )
    top_fused = sorted(rows, key=lambda x: x["fused_score"], reverse=True)[: args.top_k]

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "minute_test_count": len(minute_keys),
        "minute_anomaly_count": int(sum(y_true)),
        "security_only": {
            "threshold": sec_threshold,
            "eval": sec_eval,
        },
        "sysmon_only": {
            "threshold": sys_threshold,
            "eval": sys_eval,
        },
        "fusion": {
            "threshold": fused_threshold,
            "eval": fused_eval,
            "oracle_best": oracle_best,
        },
        "top_fused_minutes": top_fused,
    }
    dump_json(output_dir / "results.json", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
