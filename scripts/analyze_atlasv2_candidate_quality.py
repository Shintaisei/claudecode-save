import argparse
import json
import pickle
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize candidate session quality from ATLAS v2 local baseline outputs."
    )
    parser.add_argument("--data-dir", required=True, help="Dataset directory")
    parser.add_argument("--ranking-json", required=True, help="local_ngram JSON path")
    parser.add_argument(
        "--mode",
        choices=["flagged_windows", "score"],
        default="flagged_windows",
        help="How to rank candidate sessions",
    )
    parser.add_argument(
        "--topn",
        type=int,
        default=10,
        help="Number of candidate sessions to keep",
    )
    parser.add_argument(
        "--min-total-windows",
        type=int,
        default=50,
        help="Minimum session window count to consider",
    )
    parser.add_argument(
        "--exclude-processes",
        default="",
        help="Comma-separated process names to suppress from ranking",
    )
    parser.add_argument(
        "--output-json",
        help="Optional output path, default is under data-dir",
    )
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


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir)
    ranking_path = Path(args.ranking_json)
    ranking = json.loads(ranking_path.read_text(encoding="utf-8"))
    sessions = build_session_lookup(data_dir)
    excluded = {
        item.strip().lower() for item in args.exclude_processes.split(",") if item.strip()
    }

    candidates = []
    for session_id, metrics in ranking["sessions"].items():
        total_windows = metrics["total_windows"]
        flagged_windows = metrics["flagged_windows"]
        if flagged_windows <= 0 or total_windows < args.min_total_windows:
            continue
        parts = session_id.split("|")
        process = parts[1].lower() if len(parts) >= 3 else "-"
        if process in excluded:
            continue
        if args.mode == "score":
            sort_value = metrics["flagged_ratio"] * min(flagged_windows, 100)
        else:
            sort_value = flagged_windows
        sample = sessions.get(session_id)
        if not sample:
            continue
        labels = sample["label"]
        label_list = labels if isinstance(labels, list) else [labels] * len(sample["templates"])
        event_count = len(label_list)
        anomalous_events = sum(label_list)
        normal_events = event_count - anomalous_events
        normal_ratio = normal_events / event_count if event_count else 0.0
        candidates.append(
            {
                "session_id": session_id,
                "process": process,
                "sort_value": sort_value,
                "flagged_windows": flagged_windows,
                "flagged_ratio": metrics["flagged_ratio"],
                "flagged_true_positive_windows": metrics["flagged_true_positive_windows"],
                "labeled_anomalous_windows": metrics["labeled_anomalous_windows"],
                "precision_proxy": metrics["precision_proxy"],
                "recall_proxy": metrics["recall_proxy"],
                "events": event_count,
                "normal_events": normal_events,
                "anomalous_events": anomalous_events,
                "normal_event_ratio": normal_ratio,
            }
        )

    candidates.sort(
        key=lambda item: (
            item["sort_value"],
            item["flagged_true_positive_windows"],
            item["flagged_ratio"],
        ),
        reverse=True,
    )
    selected = candidates[: args.topn]

    total_anomalous_events = sum(item["anomalous_events"] for item in selected)
    total_events = sum(item["events"] for item in selected)
    total_tp_windows = sum(item["flagged_true_positive_windows"] for item in selected)
    total_flagged_windows = sum(item["flagged_windows"] for item in selected)

    output = {
        "data_dir": str(data_dir),
        "ranking_json": str(ranking_path),
        "mode": args.mode,
        "topn": args.topn,
        "min_total_windows": args.min_total_windows,
        "excluded_processes": sorted(excluded),
        "summary": {
            "candidate_sessions": len(selected),
            "total_events": total_events,
            "total_anomalous_events": total_anomalous_events,
            "total_normal_events": total_events - total_anomalous_events,
            "normal_event_ratio": (
                (total_events - total_anomalous_events) / total_events if total_events else 0.0
            ),
            "total_flagged_windows": total_flagged_windows,
            "total_flagged_true_positive_windows": total_tp_windows,
            "mean_precision_proxy": (
                sum(item["precision_proxy"] for item in selected) / len(selected)
                if selected
                else 0.0
            ),
        },
        "candidates": selected,
    }

    if args.output_json:
        output_path = Path(args.output_json)
    else:
        suffix = "filtered" if excluded else "plain"
        output_path = data_dir / f"candidate_quality_{args.mode}_{suffix}_top{args.topn}.json"
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
