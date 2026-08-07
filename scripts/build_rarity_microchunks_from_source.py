import argparse
import json
import math
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_KEYS = ["ProcessName", "NewProcessName", "Image", "Application"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build micro-chunk rarity rankings from either top_chunks or review_queue sources."
    )
    parser.add_argument("--coarse-data-dir", required=True)
    parser.add_argument("--source-type", choices=["top_chunks", "review_queue"], required=True)
    parser.add_argument("--source-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--top-items", type=int, default=10)
    parser.add_argument("--coarse-chunk-size", type=int, default=100)
    parser.add_argument("--micro-chunk-size", type=int, default=10)
    parser.add_argument("--top-k", type=int, default=10)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def parse_template(template: str) -> dict:
    fields = {}
    for part in template.split(" | "):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields


def process_name(template: str) -> str:
    fields = parse_template(template)
    for key in PROCESS_KEYS:
        value = fields.get(key)
        if value:
            return Path(value).name.lower()
    return "-"


def split_session_dict(session_dict: dict, chunk_size: int) -> dict:
    chunked = {}
    for session_id, sample in session_dict.items():
        templates = sample["templates"]
        labels = sample["label"]
        chunk_count = math.ceil(len(templates) / chunk_size)
        for idx in range(chunk_count):
            start = idx * chunk_size
            end = min(len(templates), start + chunk_size)
            chunked[f"{session_id}|micro{idx:03d}"] = {
                "templates": templates[start:end],
                "label": labels[start:end],
            }
    return chunked


def rarity_from_chunks(chunk_dict: dict) -> dict:
    counter = Counter()
    total = 0
    for sample in chunk_dict.values():
        counter.update(sample["templates"])
        total += len(sample["templates"])
    rarity = {template: math.log((total + 1) / (count + 1)) for template, count in counter.items()}
    rarity["_default_"] = math.log(total + 1)
    return rarity


def build_candidate_microchunks_from_top_chunks(
    session_test: dict,
    source_results: dict,
    top_items: int,
    coarse_chunk_size: int,
    micro_chunk_size: int,
) -> dict:
    microchunks = {}
    ranked = source_results["top_chunks"][:top_items]
    for coarse_rank, row in enumerate(ranked, start=1):
        chunk_session_id = row["session_id"]
        parent_session_id = "|".join(chunk_session_id.split("|")[:-1])
        coarse_chunk_index = int(chunk_session_id.split("chunk")[-1])
        sample = session_test[parent_session_id]
        start = coarse_chunk_index * coarse_chunk_size
        end = min(len(sample["templates"]), start + coarse_chunk_size)
        templates = sample["templates"][start:end]
        labels = sample["label"][start:end]
        micro_count = math.ceil(len(templates) / micro_chunk_size)
        for micro_idx in range(micro_count):
            ms = micro_idx * micro_chunk_size
            me = min(len(templates), ms + micro_chunk_size)
            micro_id = f"{parent_session_id}|chunk{coarse_chunk_index:03d}|micro{micro_idx:02d}"
            microchunks[micro_id] = {
                "parent_session_id": parent_session_id,
                "coarse_chunk_rank": coarse_rank,
                "coarse_chunk_index": coarse_chunk_index,
                "micro_chunk_index": micro_idx,
                "templates": templates[ms:me],
                "label": labels[ms:me],
            }
    return microchunks


def build_candidate_microchunks_from_review_queue(
    session_test: dict,
    source_results: dict,
    top_items: int,
    coarse_chunk_size: int,
    micro_chunk_size: int,
) -> dict:
    windows = []
    for session in source_results["review_queue"]:
        windows.extend(session["security_review_windows"])
    selected = windows[:top_items]
    microchunks = {}
    for window_rank, row in enumerate(selected, start=1):
        parent_session_id = row["parent_session_id"]
        sample = session_test[parent_session_id]
        for coarse_chunk_index in range(int(row["start_chunk"]), int(row["end_chunk"]) + 1):
            start = coarse_chunk_index * coarse_chunk_size
            end = min(len(sample["templates"]), start + coarse_chunk_size)
            templates = sample["templates"][start:end]
            labels = sample["label"][start:end]
            micro_count = math.ceil(len(templates) / micro_chunk_size)
            for micro_idx in range(micro_count):
                ms = micro_idx * micro_chunk_size
                me = min(len(templates), ms + micro_chunk_size)
                micro_id = f"{parent_session_id}|chunk{coarse_chunk_index:03d}|micro{micro_idx:02d}"
                if micro_id in microchunks:
                    continue
                microchunks[micro_id] = {
                    "parent_session_id": parent_session_id,
                    "coarse_chunk_rank": window_rank,
                    "coarse_chunk_index": coarse_chunk_index,
                    "micro_chunk_index": micro_idx,
                    "templates": templates[ms:me],
                    "label": labels[ms:me],
                }
    return microchunks


def summarize_template_mix(templates: list[str]) -> list[tuple[str, int]]:
    return Counter(process_name(template) for template in templates).most_common(4)


def event_anomaly_count(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(sum(label))
    return int(label)


def score_rows(candidate_micro: dict, rarity: dict) -> list[dict]:
    default = rarity["_default_"]
    rows = []
    for cid, sample in candidate_micro.items():
        per_event = [rarity.get(template, default) for template in sample["templates"]]
        score = float(sum(per_event) / len(per_event)) if per_event else 0.0
        total_events = len(sample["templates"])
        attack_events = event_anomaly_count(sample)
        rows.append(
            {
                "micro_chunk_id": cid,
                "parent_session_id": sample["parent_session_id"],
                "coarse_chunk_rank": sample["coarse_chunk_rank"],
                "coarse_chunk_index": sample["coarse_chunk_index"],
                "micro_chunk_index": sample["micro_chunk_index"],
                "score": score,
                "total_events": total_events,
                "attack_events": attack_events,
                "normal_events": total_events - attack_events,
                "top_processes": summarize_template_mix(sample["templates"]),
            }
        )
    return sorted(rows, key=lambda x: x["score"], reverse=True)


def ranked_summary(rows: list[dict]) -> dict:
    top10 = rows[:10]
    return {
        "top_10": {
            "micro_chunks": len(top10),
            "total_events": int(sum(r["total_events"] for r in top10)),
            "attack_events": int(sum(r["attack_events"] for r in top10)),
            "normal_events": int(sum(r["normal_events"] for r in top10)),
            "attack_mixed_micro_chunks": int(sum(1 for r in top10 if r["attack_events"] > 0)),
            "normal_only_micro_chunks": int(sum(1 for r in top10 if r["attack_events"] == 0)),
        }
    }


def build_summary_md(payload: dict) -> str:
    lines = []
    lines.append("# third pass micro10 summary")
    lines.append("")
    lines.append(f"更新日: {payload['generated_at'][:10]}")
    lines.append("")
    lines.append("## 1. 設定")
    lines.append("")
    lines.append(f"- source type: `{payload['inputs']['source_type']}`")
    lines.append(f"- 上位対象: `{payload['inputs']['top_items']}`")
    lines.append(f"- `100 event chunk` を `{payload['inputs']['micro_chunk_size']} event` に分割")
    lines.append(f"- 候補 micro-chunk 数: `{payload['population']['candidate_micro_chunks']}`")
    lines.append("")
    lines.append("## 2. top10 micro-chunk")
    lines.append("")
    lines.append("| rank | parent chunk | micro | attack / normal | 主なプロセス |")
    lines.append("| --- | --- | ---: | ---: | --- |")
    for idx, row in enumerate(payload["models"][0]["top_micro_chunks"], start=1):
        procs = ", ".join(proc for proc, _ in row["top_processes"])
        lines.append(
            f"| `{idx}` | `chunk{row['coarse_chunk_index']:03d} (rank {row['coarse_chunk_rank']})` | `{row['micro_chunk_index']}` | `{row['attack_events']} / {row['normal_events']}` | `{procs}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    coarse_data_dir = ROOT / args.coarse_data_dir
    coarse_desc = load_json(coarse_data_dir / "data_desc.json")
    coarse_train = load_pickle(coarse_data_dir / "session_train.pkl")
    coarse_test = load_pickle(coarse_data_dir / "session_test.pkl")
    source_results = load_json(ROOT / args.source_results)

    train_micro = split_session_dict(coarse_train, args.micro_chunk_size)
    rarity = rarity_from_chunks(train_micro)

    if args.source_type == "top_chunks":
        candidate_micro = build_candidate_microchunks_from_top_chunks(
            coarse_test, source_results, args.top_items, args.coarse_chunk_size, args.micro_chunk_size
        )
    else:
        candidate_micro = build_candidate_microchunks_from_review_queue(
            coarse_test, source_results, args.top_items, args.coarse_chunk_size, args.micro_chunk_size
        )

    rows = score_rows(candidate_micro, rarity)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": vars(args),
        "population": {
            "candidate_micro_chunks": len(candidate_micro),
            "candidate_total_events": int(sum(len(sample["templates"]) for sample in candidate_micro.values())),
            "train_source": coarse_desc["train_source"],
        },
        "models": [
            {
                "model": "rarity",
                "ranked_summary": ranked_summary(rows),
                "top_micro_chunks": rows[: args.top_k],
            }
        ],
    }

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "summary.md").write_text(build_summary_md(payload), encoding="utf-8")
    print(output_dir / "summary.md")
    print(output_dir / "results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
