import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert ATLAS v2 Security XML exports into flattened JSONL."
    )
    parser.add_argument(
        "--xml",
        nargs="+",
        required=True,
        help="One or more input Security XML files in chronological order.",
    )
    parser.add_argument("--output", required=True, help="Output JSONL path.")
    return parser.parse_args()


def maybe_set(payload: dict, key: str, value: str) -> None:
    if value not in (None, ""):
        payload[key] = value


def add_alias_fields(payload: dict) -> None:
    process_name = payload.get("ProcessName")
    object_name = payload.get("ObjectName")
    new_process_name = payload.get("NewProcessName")

    if process_name and "Image" not in payload:
        payload["Image"] = process_name
    if new_process_name and "NewProcess" not in payload:
        payload["NewProcess"] = new_process_name
    if object_name:
        payload.setdefault("TargetFilename", object_name)
        payload.setdefault("FileName", object_name)
        payload.setdefault("TargetObject", object_name)


def parse_event(elem: ET.Element) -> dict:
    provider = elem.find("./evt:System/evt:Provider", NS)
    time_created = elem.find("./evt:System/evt:TimeCreated", NS)
    execution = elem.find("./evt:System/evt:Execution", NS)

    event = {}
    if provider is not None:
        maybe_set(event, "Provider", provider.attrib.get("Name"))
        maybe_set(event, "ProviderGuid", provider.attrib.get("Guid"))
    maybe_set(event, "EventID", elem.findtext("./evt:System/evt:EventID", default="", namespaces=NS))
    maybe_set(event, "Version", elem.findtext("./evt:System/evt:Version", default="", namespaces=NS))
    maybe_set(event, "Level", elem.findtext("./evt:System/evt:Level", default="", namespaces=NS))
    maybe_set(event, "Task", elem.findtext("./evt:System/evt:Task", default="", namespaces=NS))
    maybe_set(event, "Opcode", elem.findtext("./evt:System/evt:Opcode", default="", namespaces=NS))
    maybe_set(event, "Keywords", elem.findtext("./evt:System/evt:Keywords", default="", namespaces=NS))
    maybe_set(event, "@timestamp", time_created.attrib.get("SystemTime") if time_created is not None else "")
    maybe_set(
        event,
        "EventRecordID",
        elem.findtext("./evt:System/evt:EventRecordID", default="", namespaces=NS),
    )
    if execution is not None:
        maybe_set(event, "ProcessID", execution.attrib.get("ProcessID"))
        maybe_set(event, "ThreadID", execution.attrib.get("ThreadID"))
    maybe_set(event, "Channel", elem.findtext("./evt:System/evt:Channel", default="", namespaces=NS))
    maybe_set(event, "Computer", elem.findtext("./evt:System/evt:Computer", default="", namespaces=NS))

    for data in elem.findall("./evt:EventData/evt:Data", NS):
        name = data.attrib.get("Name", "").strip()
        if name:
            maybe_set(event, name, data.text or "")

    for child in elem.findall("./evt:UserData/*", NS):
        for node in child.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            text = (node.text or "").strip()
            if tag and text and tag not in event:
                maybe_set(event, tag, text)

    add_alias_fields(event)
    return event


def convert_one(xml_path: Path, out_fh) -> int:
    count = 0
    for _, elem in ET.iterparse(xml_path, events=("end",)):
        if not elem.tag.endswith("Event"):
            continue
        event = parse_event(elem)
        if event.get("@timestamp"):
            out_fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            count += 1
        elem.clear()
    return count


def main() -> None:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    with output_path.open("w", encoding="utf-8", newline="\n") as out_fh:
        for xml in args.xml:
            total += convert_one(Path(xml), out_fh)

    print(json.dumps({"output": str(output_path), "events_written": total}, ensure_ascii=False))


if __name__ == "__main__":
    main()
