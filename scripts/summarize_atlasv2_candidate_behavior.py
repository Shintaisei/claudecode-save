import argparse
import json
import pickle
from collections import Counter, defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize behavioral origins of normal events inside candidate sessions."
    )
    parser.add_argument("--data-dir", required=True, help="Dataset directory")
    parser.add_argument("--candidate-json", required=True, help="Candidate quality JSON path")
    parser.add_argument(
        "--topn",
        type=int,
        default=10,
        help="How many candidates from candidate-json to summarize",
    )
    parser.add_argument("--output-json", help="Optional output path")
    return parser.parse_args()


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def build_session_lookup(data_dir: Path) -> dict:
    sessions = {}
    for name in ("session_train.pkl", "session_test.pkl"):
        path = data_dir / name
        if path.exists():
            sessions.update(load_pickle(path))
    return sessions


def parse_template(template: str) -> dict:
    fields = {}
    for part in template.split(" | "):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value
    return fields


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir)
    candidate_path = Path(args.candidate_json)
    candidate_doc = json.loads(candidate_path.read_text(encoding="utf-8"))
    sessions = build_session_lookup(data_dir)

    selected = candidate_doc["candidates"][: args.topn]
    provider_counter = Counter()
    channel_counter = Counter()
    event_counter = Counter()
    process_counter = Counter()
    provider_event_counter = Counter()
    session_breakdown = []

    for candidate in selected:
        session_id = candidate["session_id"]
        sample = sessions[session_id]
        labels = sample["label"]
        label_list = labels if isinstance(labels, list) else [labels] * len(sample["templates"])
        normal_templates = []
        for template, label in zip(sample["templates"], label_list):
            if label == 0:
                fields = parse_template(template)
                provider = fields.get("Provider", "-")
                channel = fields.get("Channel", "-")
                event_id = fields.get("EventID", "-")
                process = (
                    fields.get("ProcessName")
                    or fields.get("NewProcessName")
                    or fields.get("Image")
                    or fields.get("Application")
                    or "-"
                )
                provider_counter[provider] += 1
                channel_counter[channel] += 1
                event_counter[event_id] += 1
                process_counter[process] += 1
                provider_event_counter[(provider, event_id)] += 1
                normal_templates.append((provider, channel, event_id, process))

        local_provider = Counter(item[0] for item in normal_templates)
        local_process = Counter(item[3] for item in normal_templates)
        session_breakdown.append(
            {
                "session_id": session_id,
                "normal_event_ratio": candidate["normal_event_ratio"],
                "normal_events": candidate["normal_events"],
                "anomalous_events": candidate["anomalous_events"],
                "top_normal_providers": local_provider.most_common(5),
                "top_normal_processes": local_process.most_common(5),
            }
        )

    output = {
        "data_dir": str(data_dir),
        "candidate_json": str(candidate_path),
        "topn": args.topn,
        "summary": {
            "candidate_sessions": len(selected),
            "top_normal_providers": provider_counter.most_common(10),
            "top_normal_channels": channel_counter.most_common(10),
            "top_normal_event_ids": event_counter.most_common(10),
            "top_normal_processes": process_counter.most_common(15),
            "top_normal_provider_event_pairs": [
                [provider, event_id, count]
                for (provider, event_id), count in provider_event_counter.most_common(15)
            ],
        },
        "sessions": session_breakdown,
    }

    if args.output_json:
        output_path = Path(args.output_json)
    else:
        output_path = data_dir / f"candidate_behavior_top{args.topn}.json"
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
