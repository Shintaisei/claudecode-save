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
        description="Export LOF top-ranked chunks with raw events for manual review."
    )
    parser.add_argument("--results-json", required=True)
    parser.add_argument("--session-pkl", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--topn", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=100)
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


def classify_chunk(attack_events: int, top_processes: list[tuple[str, int]]) -> str:
    if attack_events > 0:
        return "attack-mixed"

    process_set = {proc for proc, _ in top_processes}
    if "winword.exe" in process_set or "repmgr.exe" in process_set:
        return "office-doc"
    if "explorer.exe" in process_set:
        return "user-file"
    if "firefox.exe" in process_set:
        return "browser"
    if process_set & {"regsvr32.exe", "dllhost.exe", "svchost.exe", "csrss.exe"}:
        return "ambiguous-system"
    return "background-vmware"


def build_markdown(rows: list[dict], source_results: str) -> str:
    lines = []
    lines.append("# LOF top100 生ログレビュー用一覧")
    lines.append("")
    lines.append(f"更新日: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## 1. 前提")
    lines.append("")
    lines.append(f"- 対象は `{source_results}` の `top100 chunk`")
    lines.append("- 各 chunk は `100 event` 単位")
    lines.append("- rank 順に、人手観察しやすいように category と代表プロセスを付けた")
    lines.append("")
    lines.append("## 2. 一覧")
    lines.append("")
    lines.append("| rank | chunk | category | attack / normal | 主なプロセス |")
    lines.append("| --- | --- | --- | ---: | --- |")
    for row in rows:
        top_proc_text = ", ".join(proc for proc, _ in row["top_processes"][:4])
        lines.append(
            f"| `{row['rank']}` | `chunk{row['chunk_index']:03d}` | `{row['category']}` | `{row['attack_events']} / {row['normal_events']}` | `{top_proc_text}` |"
        )
    lines.append("")
    lines.append("## 3. すぐ見たい候補")
    lines.append("")
    lines.append("- 文書操作系: `rank 4, 5, 7`")
    lines.append("- ファイル操作系: `rank 6, 9`")
    lines.append("- browser 系を追加で見たいなら: `rank 43, 44, 46, 47`")
    lines.append("- background noise が増え始める境目: `rank 10` 以降")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    results = load_json(ROOT / args.results_json)
    sessions = load_pickle(ROOT / args.session_pkl)

    rows = []
    raw_export = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "results_json": args.results_json,
            "session_pkl": args.session_pkl,
            "topn": args.topn,
            "chunk_size": args.chunk_size,
        },
        "chunks": [],
    }

    for rank, chunk in enumerate(results["top_chunks"][: args.topn], start=1):
        session_id = chunk["session_id"]
        parent_session_id = "|".join(session_id.split("|")[:-1])
        chunk_index = int(session_id.split("chunk")[-1])
        session = sessions[parent_session_id]
        start = chunk_index * args.chunk_size
        end = min(len(session["templates"]), start + args.chunk_size)
        templates = session["templates"][start:end]
        labels = session["label"][start:end]

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
                    "offset": idx,
                    "label": int(label),
                    "template": template,
                    "fields": fields,
                    "process": proc,
                    "event_id": fields.get("EventID", "-"),
                }
            )

        top_processes = process_counter.most_common(5)
        category = classify_chunk(chunk["attack_events"], top_processes)
        row = {
            "rank": rank,
            "session_id": session_id,
            "parent_session_id": parent_session_id,
            "chunk_index": chunk_index,
            "score": chunk["score"],
            "attack_events": chunk["attack_events"],
            "normal_events": chunk["normal_events"],
            "total_events": chunk["total_events"],
            "category": category,
            "top_processes": top_processes,
            "top_event_ids": event_counter.most_common(5),
        }
        rows.append(row)
        raw_export["chunks"].append({**row, "events": events})

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "top100_index.md").write_text(
        build_markdown(rows, args.results_json),
        encoding="utf-8",
    )
    (output_dir / "top100_raw_events.json").write_text(
        json.dumps(raw_export, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(output_dir / "top100_index.md")
    print(output_dir / "top100_raw_events.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
