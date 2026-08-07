import argparse
import csv
import json
import math
import xml.etree.ElementTree as ET
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select up-to-100 Sysmon events using only anomaly scores and sequence attachment."
    )
    parser.add_argument("--review-queue", required=True)
    parser.add_argument("--sysmon-xml", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-events", type=int, default=100)
    parser.add_argument("--sequence-weight", type=float, default=0.25)
    parser.add_argument("--exact-user-bonus", type=float, default=0.02)
    parser.add_argument("--multi-attach-bonus", type=float, default=0.02)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def minute_bucket(ts: datetime) -> str:
    bucket_epoch = int(ts.timestamp()) // 60 * 60
    bucket_dt = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    return bucket_dt.strftime("%Y%m%dT%H%MZ")


def basename_like(value: str) -> str:
    value = value.replace("\\", "/").strip()
    if "/" in value:
        return value.rsplit("/", 1)[-1].lower()
    return value.lower()


def parse_sysmon_xml(xml_path: Path) -> list[dict]:
    rows = []
    for _, elem in ET.iterparse(xml_path, events=("end",)):
        if not elem.tag.endswith("Event"):
            continue
        provider = elem.find("./evt:System/evt:Provider", NS)
        channel = elem.findtext("./evt:System/evt:Channel", default="-", namespaces=NS)
        event_id = elem.findtext("./evt:System/evt:EventID", default="-", namespaces=NS)
        computer = elem.findtext("./evt:System/evt:Computer", default="-", namespaces=NS).lower()
        record_id = elem.findtext("./evt:System/evt:EventRecordID", default="-", namespaces=NS)
        time_created = elem.find("./evt:System/evt:TimeCreated", NS)
        event = {
            "Provider": provider.attrib.get("Name", "-") if provider is not None else "-",
            "Channel": channel,
            "EventID": event_id,
            "Computer": computer,
            "EventRecordID": record_id,
            "@timestamp": time_created.attrib.get("SystemTime", "") if time_created is not None else "",
        }
        for data in elem.findall("./evt:EventData/evt:Data", NS):
            name = data.attrib.get("Name", "")
            if name:
                event[name] = data.text or ""
        rows.append(event)
        elem.clear()
    rows.sort(key=lambda x: (parse_timestamp(x["@timestamp"]), str(x.get("EventRecordID", ""))))
    return rows


def group_events_by_session(events: list[dict]) -> OrderedDict[str, list[dict]]:
    grouped: OrderedDict[str, list[dict]] = OrderedDict()
    for event in events:
        user = basename_like(event.get("User", "-"))
        session_id = f"{event['Computer']}|{user}|{minute_bucket(parse_timestamp(event['@timestamp']))}"
        grouped.setdefault(session_id, []).append(event)
    return grouped


def build_candidates(review_queue: dict, args: argparse.Namespace) -> tuple[list[dict], list[dict]]:
    sequence_rows = [row for row in review_queue["review_queue"] if row.get("predicted_positive") == 1]
    sequence_rows.sort(key=lambda x: (-float(x["score"]), x["session_id"]))

    candidates = {}
    for seq in sequence_rows:
        seq_meta = {
            "session_id": seq["session_id"],
            "sequence_score": float(seq["score"]),
            "sequence_label": int(seq["label"]),
        }
        for source_name in ("sysmon_exact_user_minutes", "sysmon_same_host_minutes"):
            is_exact = source_name == "sysmon_exact_user_minutes"
            for minute in seq.get(source_name, []):
                sid = minute["sysmon_session_id"]
                row = candidates.get(sid)
                if row is None:
                    row = {
                        "sysmon_session_id": sid,
                        "minute_bucket": minute["minute_bucket"],
                        "minute_score": float(minute["score"]),
                        "events": int(minute["events"]),
                        "top_images": minute.get("top_images", []),
                        "top_event_ids": minute.get("top_event_ids", []),
                        "top_users": minute.get("top_users", []),
                        "attached_sequences": [],
                        "exact_user_support": 0,
                        "same_host_support": 0,
                    }
                    candidates[sid] = row
                row["attached_sequences"].append(seq_meta)
                if is_exact:
                    row["exact_user_support"] += 1
                else:
                    row["same_host_support"] += 1

    rows = list(candidates.values())
    for row in rows:
        attached = row["attached_sequences"]
        max_seq_score = max(item["sequence_score"] for item in attached)
        exact_flag = 1 if row["exact_user_support"] > 0 else 0
        row["max_sequence_score"] = max_seq_score
        row["attached_sequence_count"] = len(attached)
        row["combined_score"] = (
            row["minute_score"]
            + args.sequence_weight * max_seq_score
            + args.exact_user_bonus * exact_flag
            + args.multi_attach_bonus * max(0, len(attached) - 1)
        )
        row["primary_sequence_id"] = max(attached, key=lambda x: (x["sequence_score"], x["session_id"]))["session_id"]
        labels = {item["sequence_label"] for item in attached}
        if labels == {1}:
            row["attachment_type"] = "attack_sequence_only"
        elif labels == {0}:
            row["attachment_type"] = "fp_sequence_only"
        else:
            row["attachment_type"] = "mixed_sequence_support"

    rows.sort(key=lambda x: (-x["combined_score"], -x["minute_score"], x["sysmon_session_id"]))
    return sequence_rows, rows


def select_minutes_round_robin(sequence_rows: list[dict], candidate_rows: list[dict], grouped_events: dict[str, list[dict]], max_events: int) -> tuple[list[dict], list[dict]]:
    per_sequence: dict[str, list[dict]] = defaultdict(list)
    for row in candidate_rows:
        per_sequence[row["primary_sequence_id"]].append(row)

    for seq_id in per_sequence:
        per_sequence[seq_id].sort(key=lambda x: (-x["combined_score"], -x["minute_score"], x["sysmon_session_id"]))

    selected_minutes = []
    selected_events = []
    seen_minutes = set()
    total = 0

    ordered_sequence_ids = [row["session_id"] for row in sequence_rows]
    while total < max_events:
        progressed = False
        for seq_id in ordered_sequence_ids:
            queue = per_sequence.get(seq_id, [])
            while queue and queue[0]["sysmon_session_id"] in seen_minutes:
                queue.pop(0)
            if not queue:
                continue
            minute = queue.pop(0)
            events = grouped_events.get(minute["sysmon_session_id"], [])
            if not events:
                continue
            remaining = max_events - total
            take_events = events[:remaining]
            if not take_events:
                continue
            selected_minutes.append(
                {
                    **minute,
                    "selected_event_count": len(take_events),
                    "selected_full_minute": int(len(take_events) == len(events)),
                    "selection_stage": "round_robin",
                }
            )
            selected_events.extend(take_events)
            seen_minutes.add(minute["sysmon_session_id"])
            total += len(take_events)
            progressed = True
            if total >= max_events:
                break
        if not progressed:
            break

    if total < max_events:
        leftovers = [row for row in candidate_rows if row["sysmon_session_id"] not in seen_minutes]
        leftovers.sort(key=lambda x: (-x["combined_score"], -x["minute_score"], x["sysmon_session_id"]))
        for minute in leftovers:
            events = grouped_events.get(minute["sysmon_session_id"], [])
            if not events:
                continue
            remaining = max_events - total
            if remaining <= 0:
                break
            take_events = events[:remaining]
            selected_minutes.append(
                {
                    **minute,
                    "selected_event_count": len(take_events),
                    "selected_full_minute": int(len(take_events) == len(events)),
                    "selection_stage": "global_fill",
                }
            )
            selected_events.extend(take_events)
            seen_minutes.add(minute["sysmon_session_id"])
            total += len(take_events)
            if total >= max_events:
                break

    return selected_minutes, selected_events


def build_summary(sequence_rows: list[dict], candidate_rows: list[dict], selected_minutes: list[dict], selected_events: list[dict]) -> dict:
    selected_by_attachment = {
        "attack_sequence_only": 0,
        "fp_sequence_only": 0,
        "mixed_sequence_support": 0,
    }
    selected_by_stage = {
        "round_robin": 0,
        "global_fill": 0,
    }
    sequence_event_coverage = {}

    for row in selected_minutes:
        selected_by_attachment[row["attachment_type"]] += int(row["selected_event_count"])
        selected_by_stage[row["selection_stage"]] += int(row["selected_event_count"])
        for seq in row["attached_sequences"]:
            sid = seq["session_id"]
            sequence_event_coverage.setdefault(
                sid,
                {
                    "sequence_score": seq["sequence_score"],
                    "sequence_label": seq["sequence_label"],
                    "selected_events": 0,
                    "minute_hits": 0,
                },
            )
            sequence_event_coverage[sid]["selected_events"] += int(row["selected_event_count"])
            sequence_event_coverage[sid]["minute_hits"] += 1

    return {
        "predicted_sequences": len(sequence_rows),
        "candidate_minutes": len(candidate_rows),
        "selected_minutes": len(selected_minutes),
        "selected_events": len(selected_events),
        "selected_event_attachment_breakdown": selected_by_attachment,
        "selected_event_stage_breakdown": selected_by_stage,
        "sequence_event_coverage": sequence_event_coverage,
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main() -> int:
    args = parse_args()
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    review_queue = load_json(ROOT / args.review_queue)
    events = parse_sysmon_xml(ROOT / args.sysmon_xml)
    grouped_events = group_events_by_session(events)

    sequence_rows, candidate_rows = build_candidates(review_queue, args)
    selected_minutes, selected_events = select_minutes_round_robin(sequence_rows, candidate_rows, grouped_events, args.max_events)
    summary = build_summary(sequence_rows, candidate_rows, selected_minutes, selected_events)

    dump_json(output_dir / "summary.json", summary)
    dump_json(output_dir / "selected_minutes.json", selected_minutes)
    dump_json(output_dir / "selected_events.json", selected_events)

    minute_rows = []
    for row in selected_minutes:
        minute_rows.append(
            {
                "sysmon_session_id": row["sysmon_session_id"],
                "minute_bucket": row["minute_bucket"],
                "minute_score": row["minute_score"],
                "max_sequence_score": row["max_sequence_score"],
                "combined_score": row["combined_score"],
                "events": row["events"],
                "selected_event_count": row["selected_event_count"],
                "selected_full_minute": row["selected_full_minute"],
                "selection_stage": row["selection_stage"],
                "attachment_type": row["attachment_type"],
                "exact_user_support": row["exact_user_support"],
                "same_host_support": row["same_host_support"],
                "top_images": "; ".join(f"{name}:{count}" if isinstance(name, str) else str(name) for name, count in row["top_images"]),
                "top_event_ids": "; ".join(f"{eid}:{count}" for eid, count in row["top_event_ids"]),
                "attached_sequences": "; ".join(
                    f"{item['session_id']}|score={item['sequence_score']:.4f}|label={item['sequence_label']}" for item in row["attached_sequences"]
                ),
            }
        )

    write_csv(
        output_dir / "selected_minutes.csv",
        minute_rows,
        [
            "sysmon_session_id",
            "minute_bucket",
            "minute_score",
            "max_sequence_score",
            "combined_score",
            "events",
            "selected_event_count",
            "selected_full_minute",
            "selection_stage",
            "attachment_type",
            "exact_user_support",
            "same_host_support",
            "top_images",
            "top_event_ids",
            "attached_sequences",
        ],
    )

    event_rows = []
    minute_meta = {row["sysmon_session_id"]: row for row in selected_minutes}
    for event in selected_events:
        user = basename_like(event.get("User", "-"))
        sid = f"{event['Computer']}|{user}|{minute_bucket(parse_timestamp(event['@timestamp']))}"
        meta = minute_meta.get(sid, {})
        event_rows.append(
            {
                "timestamp": event.get("@timestamp", ""),
                "sysmon_session_id": sid,
                "minute_bucket": minute_bucket(parse_timestamp(event["@timestamp"])),
                "selection_stage": meta.get("selection_stage", ""),
                "attachment_type": meta.get("attachment_type", ""),
                "minute_score": meta.get("minute_score", ""),
                "combined_score": meta.get("combined_score", ""),
                "Computer": event.get("Computer", ""),
                "EventID": event.get("EventID", ""),
                "Image": basename_like(event.get("Image", "")),
                "ParentImage": basename_like(event.get("ParentImage", "")),
                "User": basename_like(event.get("User", "")),
                "IntegrityLevel": event.get("IntegrityLevel", ""),
                "CommandLine": event.get("CommandLine", ""),
                "ParentCommandLine": event.get("ParentCommandLine", ""),
                "TargetFilename": event.get("TargetFilename", ""),
                "DestinationIp": event.get("DestinationIp", ""),
                "DestinationPort": event.get("DestinationPort", ""),
                "SourceIp": event.get("SourceIp", ""),
                "SourcePort": event.get("SourcePort", ""),
            }
        )

    write_csv(
        output_dir / "selected_events.csv",
        event_rows,
        [
            "timestamp",
            "sysmon_session_id",
            "minute_bucket",
            "selection_stage",
            "attachment_type",
            "minute_score",
            "combined_score",
            "Computer",
            "EventID",
            "Image",
            "ParentImage",
            "User",
            "IntegrityLevel",
            "CommandLine",
            "ParentCommandLine",
            "TargetFilename",
            "DestinationIp",
            "DestinationPort",
            "SourceIp",
            "SourcePort",
        ],
    )

    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
