import argparse
import json
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_KEYS = ["ProcessName", "NewProcessName", "Image", "Application"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export top-ranked micro-chunks with raw events for analyst review."
    )
    parser.add_argument("--third-pass-results", required=True)
    parser.add_argument("--session-pkl", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--model", default="lof")
    parser.add_argument("--topn", type=int, default=10)
    parser.add_argument("--coarse-chunk-size", type=int, default=100)
    parser.add_argument("--micro-chunk-size", type=int, default=10)
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


def build_markdown(rows: list[dict], source_results: str, model: str, topn: int) -> str:
    lines = []
    lines.append(f"# {model.upper()} top{topn} micro-chunk 生ログレビュー")
    lines.append("")
    lines.append(f"更新日: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## 1. 前提")
    lines.append("")
    lines.append(f"- 対象は `{source_results}` の `{model} top{topn} micro-chunk`")
    lines.append("- 各 micro-chunk は `10 event` 単位")
    lines.append(f"- したがって今回の実観察対象は `計 {topn * 10} event`")
    lines.append("- 目的は、実務者が実際に見るログの粒度と中身をそのまま確認すること")
    lines.append("")
    lines.append("## 2. micro-chunk 一覧")
    lines.append("")
    lines.append("| micro rank | micro-chunk | attack / normal | 主なプロセス |")
    lines.append("| --- | --- | ---: | --- |")
    for row in rows:
        top_proc_text = ", ".join(proc for proc, _ in row["top_processes"][:4])
        lines.append(
            f"| `{row['micro_rank']}` | `chunk{row['coarse_chunk_index']:03d} micro{row['micro_chunk_index']:02d}` | `{row['attack_events']} / {row['normal_events']}` | `{top_proc_text}` |"
        )
    lines.append("")
    lines.append("## 3. event 一覧")
    lines.append("")
    for row in rows:
        lines.append(
            f"### micro rank {row['micro_rank']}: `chunk{row['coarse_chunk_index']:03d} micro{row['micro_chunk_index']:02d}`"
        )
        lines.append("")
        lines.append(
            f"- attack / normal: `{row['attack_events']} / {row['normal_events']}`"
        )
        lines.append(f"- 主なプロセス: `{', '.join(proc for proc, _ in row['top_processes'][:4])}`")
        lines.append("")
        lines.append("| event | label | EventID | process | template |")
        lines.append("| --- | ---: | --- | --- | --- |")
        for event in row["events"]:
            template = event["template"].replace("|", "\\|")
            lines.append(
                f"| `{event['offset_in_micro']}` | `{event['label']}` | `{event['event_id']}` | `{event['process']}` | `{template}` |"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    results = load_json(ROOT / args.third_pass_results)
    sessions = load_pickle(ROOT / args.session_pkl)

    model_row = next((row for row in results["models"] if row["model"] == args.model), None)
    if model_row is None:
        raise ValueError(f"model not found: {args.model}")

    export = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "third_pass_results": args.third_pass_results,
            "session_pkl": args.session_pkl,
            "model": args.model,
            "topn": args.topn,
            "coarse_chunk_size": args.coarse_chunk_size,
            "micro_chunk_size": args.micro_chunk_size,
        },
        "micro_chunks": [],
    }
    rows = []

    for micro_rank, row in enumerate(model_row["top_micro_chunks"][: args.topn], start=1):
        parent_session_id = row["parent_session_id"]
        coarse_chunk_index = int(row["coarse_chunk_index"])
        micro_chunk_index = int(row["micro_chunk_index"])
        session = sessions[parent_session_id]

        coarse_start = coarse_chunk_index * args.coarse_chunk_size
        micro_start = coarse_start + (micro_chunk_index * args.micro_chunk_size)
        micro_end = min(micro_start + args.micro_chunk_size, len(session["templates"]))

        templates = session["templates"][micro_start:micro_end]
        labels = session["label"][micro_start:micro_end]

        process_counter = Counter()
        event_counter = Counter()
        events = []
        for idx, (template, label) in enumerate(zip(templates, labels), start=1):
            fields = parse_template(template)
            proc = process_name(fields)
            process_counter[proc] += 1
            event_counter[fields.get("EventID", "-")] += 1
            events.append(
                {
                    "offset_in_micro": idx,
                    "offset_in_session": micro_start + idx - 1,
                    "label": int(label),
                    "template": template,
                    "fields": fields,
                    "process": proc,
                    "event_id": fields.get("EventID", "-"),
                }
            )

        record = {
            "micro_rank": micro_rank,
            "micro_chunk_id": row["micro_chunk_id"],
            "parent_session_id": parent_session_id,
            "coarse_chunk_rank": int(row["coarse_chunk_rank"]),
            "coarse_chunk_index": coarse_chunk_index,
            "micro_chunk_index": micro_chunk_index,
            "score": row["score"],
            "attack_events": int(row["attack_events"]),
            "normal_events": int(row["normal_events"]),
            "total_events": int(row["total_events"]),
            "top_processes": process_counter.most_common(5),
            "top_event_ids": event_counter.most_common(5),
            "events": events,
        }
        rows.append(record)
        export["micro_chunks"].append(record)

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "top10_micro_index.md").write_text(
        build_markdown(rows, args.third_pass_results, args.model, args.topn),
        encoding="utf-8",
    )
    (output_dir / "top10_micro_raw_events.json").write_text(
        json.dumps(export, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(output_dir / "top10_micro_index.md")
    print(output_dir / "top10_micro_raw_events.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
