import argparse
import csv
import json
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_KEYS = ["ProcessName", "NewProcessName", "Image", "Application"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export second-pass top-ranked chunks with raw events for review."
    )
    parser.add_argument("--results-json", required=True)
    parser.add_argument("--session-pkl", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--topn", type=int, default=30)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--label", default="second-pass")
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def parse_template(template: str) -> dict:
    fields = {}
    for part in template.split(" | "):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value
    return fields


def process_name(fields: dict) -> str:
    for key in PROCESS_KEYS:
        value = fields.get(key)
        if value:
            return Path(value).name.lower()
    return "-"


def chunk_key(row: dict) -> str:
    return row.get("chunk_id") or row.get("session_id")


def parent_session_id(row: dict) -> str:
    if "parent_session_id" in row:
        return row["parent_session_id"]
    key = chunk_key(row)
    return "|".join(key.split("|")[:-1])


def chunk_index(row: dict) -> int:
    if "chunk_index" in row:
        return int(row["chunk_index"])
    key = chunk_key(row)
    return int(key.split("chunk")[-1])


def build_markdown(rows: list[dict], args: argparse.Namespace) -> str:
    lines = []
    lines.append(f"# {args.label} top{args.topn} chunks")
    lines.append("")
    lines.append(f"- generated: `{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %z')}`")
    lines.append(f"- source results: `{args.results_json}`")
    lines.append(f"- session source: `{args.session_pkl}`")
    lines.append(f"- chunk size: `{args.chunk_size}` events")
    lines.append("")
    lines.append("## Chunk Summary")
    lines.append("")
    lines.append("| rank | session | chunk | score | attack / normal | top processes |")
    lines.append("| --- | --- | ---: | ---: | ---: | --- |")
    for row in rows:
        top_proc = ", ".join(proc for proc, _ in row["top_processes"][:4])
        lines.append(
            f"| `{row['rank']}` | `{row['parent_session_id']}` | `{row['chunk_index']}` | `{row['score']:.6f}` | `{row['attack_events']} / {row['normal_events']}` | `{top_proc}` |"
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    results = load_json(ROOT / args.results_json)
    sessions = load_pickle(ROOT / args.session_pkl)
    top_chunks = results["top_chunks"][: args.topn]

    export_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": vars(args),
        "chunks": [],
    }
    flat_events = []

    for rank, row in enumerate(top_chunks, start=1):
        p_session = parent_session_id(row)
        c_index = chunk_index(row)
        session = sessions[p_session]
        start = c_index * args.chunk_size
        end = min(len(session["templates"]), start + args.chunk_size)
        templates = session["templates"][start:end]
        labels = session["label"][start:end]

        process_counter = Counter()
        event_counter = Counter()
        events = []
        for offset, (template, label) in enumerate(zip(templates, labels), start=1):
            fields = parse_template(template)
            process = process_name(fields)
            process_counter[process] += 1
            event_counter[fields.get("EventID", "-")] += 1
            record = {
                "rank": rank,
                "parent_session_id": p_session,
                "chunk_index": c_index,
                "offset_in_chunk": offset,
                "label": int(label),
                "process": process,
                "event_id": fields.get("EventID", "-"),
                "template": template,
                "fields": fields,
            }
            events.append(record)
            flat_events.append(record)

        chunk_record = {
            "rank": rank,
            "chunk_id": chunk_key(row),
            "parent_session_id": p_session,
            "chunk_index": c_index,
            "score": row["score"],
            "attack_events": row["attack_events"],
            "normal_events": row["normal_events"],
            "total_events": row["total_events"],
            "top_processes": process_counter.most_common(5),
            "top_event_ids": event_counter.most_common(5),
            "events": events,
        }
        export_payload["chunks"].append(chunk_record)

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "top_chunks_index.md").write_text(
        build_markdown(export_payload["chunks"], args),
        encoding="utf-8",
    )
    (output_dir / "top_chunks_raw_events.json").write_text(
        json.dumps(export_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with (output_dir / "top_chunks_flat_events.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "rank",
                "parent_session_id",
                "chunk_index",
                "offset_in_chunk",
                "label",
                "process",
                "event_id",
                "template",
            ]
        )
        for row in flat_events:
            writer.writerow(
                [
                    row["rank"],
                    row["parent_session_id"],
                    row["chunk_index"],
                    row["offset_in_chunk"],
                    row["label"],
                    row["process"],
                    row["event_id"],
                    row["template"],
                ]
            )

    print(output_dir / "top_chunks_index.md")
    print(output_dir / "top_chunks_raw_events.json")
    print(output_dir / "top_chunks_flat_events.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
