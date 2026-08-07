import argparse
import csv
import json
import pickle
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export top micro-chunks from third-pass benchmark results."
    )
    parser.add_argument("--results-json", required=True)
    parser.add_argument("--session-pkl", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--topn", type=int, default=10)
    parser.add_argument("--coarse-chunk-size", type=int, default=100)
    parser.add_argument("--micro-chunk-size", type=int, default=10)
    parser.add_argument("--label", default="third-pass")
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def build_markdown(rows: list[dict], args: argparse.Namespace) -> str:
    lines = []
    lines.append(f"# {args.label} top{args.topn} micro-chunks")
    lines.append("")
    lines.append(f"- source results: `{args.results_json}`")
    lines.append(f"- session source: `{args.session_pkl}`")
    lines.append("")
    lines.append("| rank | session | coarse rank | chunk | micro | score | attack / normal |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for row in rows:
        lines.append(
            f"| `{row['rank']}` | `{row['parent_session_id']}` | `{row['coarse_chunk_rank']}` | `{row['coarse_chunk_index']}` | `{row['micro_chunk_index']}` | `{row['score']:.6f}` | `{row['attack_events']} / {row['normal_events']}` |"
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    results = load_json(ROOT / args.results_json)
    sessions = load_pickle(ROOT / args.session_pkl)

    selected = results["top_micro_chunks"][: args.topn]
    flat_rows = []
    export_rows = []

    for rank, row in enumerate(selected, start=1):
        parent = row["parent_session_id"]
        session = sessions[parent]
        coarse_start = int(row["coarse_chunk_index"]) * args.coarse_chunk_size
        micro_start = coarse_start + int(row["micro_chunk_index"]) * args.micro_chunk_size
        micro_end = min(len(session["templates"]), micro_start + args.micro_chunk_size)
        templates = session["templates"][micro_start:micro_end]
        labels = session["label"][micro_start:micro_end]

        export_row = dict(row)
        export_row["rank"] = rank
        export_row["events"] = []
        for offset, (template, label) in enumerate(zip(templates, labels), start=1):
            event = {
                "rank": rank,
                "parent_session_id": parent,
                "coarse_chunk_rank": row["coarse_chunk_rank"],
                "coarse_chunk_index": row["coarse_chunk_index"],
                "micro_chunk_index": row["micro_chunk_index"],
                "offset_in_micro": offset,
                "label": int(label),
                "template": template,
            }
            export_row["events"].append(event)
            flat_rows.append(event)
        export_rows.append(export_row)

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "top_micro_index.md").write_text(build_markdown(export_rows, args), encoding="utf-8")
    (output_dir / "top_micro_raw_events.json").write_text(
        json.dumps(
            {
                "generated_from": args.results_json,
                "top_micro_chunks": export_rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    with (output_dir / "top_micro_flat_events.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "rank",
                "parent_session_id",
                "coarse_chunk_rank",
                "coarse_chunk_index",
                "micro_chunk_index",
                "offset_in_micro",
                "label",
                "template",
            ]
        )
        for row in flat_rows:
            writer.writerow(
                [
                    row["rank"],
                    row["parent_session_id"],
                    row["coarse_chunk_rank"],
                    row["coarse_chunk_index"],
                    row["micro_chunk_index"],
                    row["offset_in_micro"],
                    row["label"],
                    row["template"],
                ]
            )
    print(output_dir / "top_micro_index.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
