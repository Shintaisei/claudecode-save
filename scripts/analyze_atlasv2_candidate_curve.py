import argparse
import json
import pickle
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build top-k candidate coverage curves for ATLAS v2 session rankings."
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
        "--ks",
        default="1,3,5,10,20,50",
        help="Comma-separated top-k checkpoints",
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


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir)
    ranking_path = Path(args.ranking_json)
    ranking = json.loads(ranking_path.read_text(encoding="utf-8"))
    sessions = build_session_lookup(data_dir)
    ks = sorted({int(item) for item in args.ks.split(",") if item.strip()})
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
        candidates.append(
            {
                "session_id": session_id,
                "process": process,
                "sort_value": sort_value,
                "flagged_windows": flagged_windows,
                "flagged_ratio": metrics["flagged_ratio"],
                "flagged_true_positive_windows": metrics["flagged_true_positive_windows"],
                "events": event_count,
                "anomalous_events": anomalous_events,
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

    total_tp_windows = sum(item["flagged_true_positive_windows"] for item in candidates)
    total_events = sum(item["events"] for item in candidates)
    points = []
    for k in ks:
        selected = candidates[:k]
        selected_tp = sum(item["flagged_true_positive_windows"] for item in selected)
        selected_events = sum(item["events"] for item in selected)
        selected_anomalous_events = sum(item["anomalous_events"] for item in selected)
        points.append(
            {
                "topk": k,
                "candidate_sessions": len(selected),
                "events": selected_events,
                "anomalous_events": selected_anomalous_events,
                "normal_event_ratio": (
                    (selected_events - selected_anomalous_events) / selected_events
                    if selected_events
                    else 0.0
                ),
                "flagged_true_positive_windows": selected_tp,
                "tp_window_coverage": (
                    selected_tp / total_tp_windows if total_tp_windows else 0.0
                ),
                "event_share": selected_events / total_events if total_events else 0.0,
            }
        )

    output = {
        "data_dir": str(data_dir),
        "ranking_json": str(ranking_path),
        "mode": args.mode,
        "ks": ks,
        "min_total_windows": args.min_total_windows,
        "excluded_processes": sorted(excluded),
        "population": {
            "candidate_sessions": len(candidates),
            "total_events": total_events,
            "total_flagged_true_positive_windows": total_tp_windows,
        },
        "points": points,
    }

    if args.output_json:
        output_path = Path(args.output_json)
    else:
        suffix = "filtered" if excluded else "plain"
        output_path = data_dir / f"candidate_curve_{args.mode}_{suffix}.json"
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    print(json.dumps(points, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
