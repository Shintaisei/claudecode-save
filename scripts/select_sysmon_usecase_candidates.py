import argparse
import csv
import json
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

SCENARIO_CONFIG = {
    "s3": {
        "preferred_normal": {"explorer.exe", "winword.exe"},
        "suspicious": {"payload.exe", "powershell.exe", "mshta.exe", "regsvr32.exe", "eqnedt32.exe"},
        "background": {
            "repwmiutils.exe",
            "conhost.exe",
            "dllhost.exe",
            "dumpcap.exe",
            "searchprotocolhost.exe",
            "searchfilterhost.exe",
            "wsqmcons.exe",
            "flashplayerupdateservice.exe",
            "schtasks.exe",
        },
    },
    "m4": {
        "preferred_normal": {"excel.exe", "mmc.exe", "winword.exe"},
        "suspicious": {"payload.exe", "powershell.exe", "mshta.exe", "regsvr32.exe", "eqnedt32.exe"},
        "background": {
            "repwmiutils.exe",
            "conhost.exe",
            "dllhost.exe",
            "dumpcap.exe",
            "searchprotocolhost.exe",
            "searchfilterhost.exe",
            "wsqmcons.exe",
            "flashplayerupdateservice.exe",
            "schtasks.exe",
            "firefox.exe",
            "python.exe",
        },
    },
    "m6": {
        "preferred_normal": {"excel.exe", "winword.exe"},
        "suspicious": {"payload.exe", "powershell.exe", "mshta.exe", "regsvr32.exe", "eqnedt32.exe"},
        "background": {
            "repwmiutils.exe",
            "conhost.exe",
            "dllhost.exe",
            "dumpcap.exe",
            "searchprotocolhost.exe",
            "searchfilterhost.exe",
            "wsqmcons.exe",
            "flashplayerupdateservice.exe",
            "schtasks.exe",
            "firefox.exe",
        },
    },
    "s4": {
        "preferred_normal": {"upd.exe", "winword.exe", "mmc.exe"},
        "suspicious": {"payload.exe", "powershell.exe", "mshta.exe", "regsvr32.exe", "eqnedt32.exe"},
        "background": {
            "repwmiutils.exe",
            "conhost.exe",
            "dllhost.exe",
            "dumpcap.exe",
            "searchprotocolhost.exe",
            "searchfilterhost.exe",
            "wsqmcons.exe",
            "flashplayerupdateservice.exe",
            "schtasks.exe",
            "firefox.exe",
            "repux.exe",
        },
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select up-to-100 Sysmon events as usecase candidates.")
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIO_CONFIG))
    parser.add_argument("--review-queue", required=True)
    parser.add_argument("--sysmon-xml", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-events", type=int, default=100)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=sorted), encoding="utf-8")


def basename_like(value: str) -> str:
    value = value.replace("\\", "/").strip()
    if "/" in value:
        return value.rsplit("/", 1)[-1].lower()
    return value.lower()


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def minute_bucket(ts: datetime) -> str:
    bucket_epoch = int(ts.timestamp()) // 60 * 60
    bucket_dt = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    return bucket_dt.strftime("%Y%m%dT%H%MZ")


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


def classify_bucket(images: set[str], config: dict) -> str:
    if images & config["suspicious"]:
        return "attack_near"
    if images & config["preferred_normal"]:
        return "core_normal"
    if images and images <= config["background"]:
        return "background_context"
    return "neutral_context"


def choose_minutes(review_queue: dict, scenario: str) -> list[dict]:
    config = SCENARIO_CONFIG[scenario]
    buckets = OrderedDict()
    for seq in review_queue["review_queue"]:
        seq_meta = {
            "parent_session_id": seq["session_id"],
            "coarse_bucket": seq["coarse_bucket"],
            "sequence_label": seq["label"],
        }
        for source_name in ("sysmon_exact_user_minutes", "sysmon_same_host_minutes"):
            for minute in seq.get(source_name, []):
                sid = minute["sysmon_session_id"]
                if sid not in buckets:
                    top_images = [name for name, _ in minute.get("top_images", [])]
                    image_set = {basename_like(name) for name in top_images}
                    buckets[sid] = {
                        "sysmon_session_id": sid,
                        "minute_bucket": minute["minute_bucket"],
                        "score": float(minute["score"]),
                        "events": int(minute["events"]),
                        "top_images": top_images,
                        "top_event_ids": minute.get("top_event_ids", []),
                        "source_names": {source_name},
                        "attached_sequences": [seq_meta],
                        "classification": classify_bucket(image_set, config),
                    }
                else:
                    buckets[sid]["source_names"].add(source_name)
                    buckets[sid]["attached_sequences"].append(seq_meta)

    rows = list(buckets.values())
    priority = {"core_normal": 0, "attack_near": 1, "neutral_context": 2, "background_context": 3}
    rows.sort(key=lambda x: (priority[x["classification"]], -x["score"], x["sysmon_session_id"]))
    return rows


def select_to_max_events(candidate_minutes: list[dict], grouped_events: dict[str, list[dict]], max_events: int) -> tuple[list[dict], list[dict]]:
    selected_minutes = []
    selected_events = []
    total = 0
    for minute in candidate_minutes:
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
            }
        )
        selected_events.extend(take_events)
        total += len(take_events)
        if total >= max_events:
            break
    return selected_minutes, selected_events


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def build_summary(scenario: str, selected_minutes: list[dict], selected_events: list[dict], all_candidates: list[dict]) -> dict:
    counts = {"core_normal": 0, "neutral_context": 0, "background_context": 0, "attack_near": 0}
    for row in all_candidates:
        counts[row["classification"]] += 1
    selected_processes = {}
    for row in selected_minutes:
        for proc in row["top_images"]:
            selected_processes[proc] = selected_processes.get(proc, 0) + 1
    return {
        "scenario": scenario,
        "selected_minutes": len(selected_minutes),
        "selected_events": len(selected_events),
        "candidate_minute_counts": counts,
        "selected_processes": sorted(selected_processes.items(), key=lambda x: (-x[1], x[0])),
        "selected_minute_ids": [row["sysmon_session_id"] for row in selected_minutes],
    }


def main() -> int:
    args = parse_args()
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    review_queue = load_json(ROOT / args.review_queue)
    events = parse_sysmon_xml(ROOT / args.sysmon_xml)
    grouped_events = group_events_by_session(events)
    candidate_minutes = choose_minutes(review_queue, args.scenario)
    selected_minutes, selected_events = select_to_max_events(candidate_minutes, grouped_events, args.max_events)

    summary = build_summary(args.scenario, selected_minutes, selected_events, candidate_minutes)
    dump_json(output_dir / "summary.json", summary)
    dump_json(output_dir / "selected_minutes.json", selected_minutes)
    dump_json(output_dir / "selected_events.json", selected_events)

    minute_rows = []
    for row in selected_minutes:
        minute_rows.append(
            {
                "sysmon_session_id": row["sysmon_session_id"],
                "minute_bucket": row["minute_bucket"],
                "classification": row["classification"],
                "score": row["score"],
                "events": row["events"],
                "selected_event_count": row["selected_event_count"],
                "selected_full_minute": row["selected_full_minute"],
                "top_images": "; ".join(row["top_images"]),
                "top_event_ids": "; ".join(f"{k}:{v}" for k, v in row["top_event_ids"]),
                "source_names": "; ".join(sorted(row["source_names"])),
                "attached_sequences": "; ".join(
                    f"{item['parent_session_id']}|label={item['sequence_label']}" for item in row["attached_sequences"]
                ),
            }
        )
    write_csv(
        output_dir / "selected_minutes.csv",
        minute_rows,
        [
            "sysmon_session_id",
            "minute_bucket",
            "classification",
            "score",
            "events",
            "selected_event_count",
            "selected_full_minute",
            "top_images",
            "top_event_ids",
            "source_names",
            "attached_sequences",
        ],
    )

    event_rows = []
    for event in selected_events:
        event_rows.append(
            {
                "timestamp": event.get("@timestamp", ""),
                "minute_bucket": minute_bucket(parse_timestamp(event["@timestamp"])),
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
            "minute_bucket",
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
