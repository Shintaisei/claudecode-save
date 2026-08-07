import argparse
import json
import math
import pickle
from collections import Counter, defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a simple next-event n-gram baseline on ATLAS v2 session data."
    )
    parser.add_argument("--data-dir", required=True, help="Dataset directory")
    parser.add_argument("--window-size", type=int, default=5, help="Context size")
    parser.add_argument("--topk", type=int, default=5, help="Allowed top-k next events")
    parser.add_argument(
        "--min-context-count",
        type=int,
        default=1,
        help="Minimum count required for a context to be trusted",
    )
    parser.add_argument(
        "--output-json",
        help="Optional output JSON path, default is under data-dir",
    )
    return parser.parse_args()


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def train_ngram(session_train: dict, window_size: int) -> tuple[dict, Counter]:
    next_event_counts: dict[tuple[str, ...], Counter] = defaultdict(Counter)
    context_counts: Counter = Counter()

    for sample in session_train.values():
        templates = sample["templates"]
        if len(templates) <= window_size:
            continue
        for idx in range(len(templates) - window_size):
            context = tuple(templates[idx : idx + window_size])
            nxt = templates[idx + window_size]
            next_event_counts[context][nxt] += 1
            context_counts[context] += 1

    return next_event_counts, context_counts


def evaluate_session(
    templates: list[str],
    labels: list[int] | int,
    model: dict[tuple[str, ...], Counter],
    context_counts: Counter,
    window_size: int,
    topk: int,
    min_context_count: int,
) -> dict:
    total_windows = 0
    flagged_windows = 0
    flagged_true_positive_windows = 0
    labeled_anomalous_windows = 0

    if len(templates) <= window_size:
        return {
            "total_windows": 0,
            "flagged_windows": 0,
            "flagged_ratio": 0.0,
            "flagged_true_positive_windows": 0,
            "labeled_anomalous_windows": 0,
            "precision_proxy": 0.0,
            "recall_proxy": 0.0,
        }

    label_list = labels if isinstance(labels, list) else [labels] * len(templates)

    for idx in range(len(templates) - window_size):
        context = tuple(templates[idx : idx + window_size])
        nxt = templates[idx + window_size]
        total_windows += 1

        ranked = model.get(context)
        is_flagged = False
        if ranked is None or context_counts[context] < min_context_count:
            is_flagged = True
        else:
            allowed = {item for item, _ in ranked.most_common(topk)}
            if nxt not in allowed:
                is_flagged = True

        window_label = int(any(label_list[idx : idx + window_size + 1]))
        if window_label == 1:
            labeled_anomalous_windows += 1

        if is_flagged:
            flagged_windows += 1
            if window_label == 1:
                flagged_true_positive_windows += 1

    precision_proxy = (
        flagged_true_positive_windows / flagged_windows if flagged_windows else 0.0
    )
    recall_proxy = (
        flagged_true_positive_windows / labeled_anomalous_windows
        if labeled_anomalous_windows
        else 0.0
    )

    return {
        "total_windows": total_windows,
        "flagged_windows": flagged_windows,
        "flagged_ratio": flagged_windows / total_windows if total_windows else 0.0,
        "flagged_true_positive_windows": flagged_true_positive_windows,
        "labeled_anomalous_windows": labeled_anomalous_windows,
        "precision_proxy": precision_proxy,
        "recall_proxy": recall_proxy,
    }


def evaluate_dataset(
    session_test: dict,
    model: dict[tuple[str, ...], Counter],
    context_counts: Counter,
    window_size: int,
    topk: int,
    min_context_count: int,
) -> dict:
    session_results = {}
    totals = Counter()

    for session_id, sample in session_test.items():
        result = evaluate_session(
            templates=sample["templates"],
            labels=sample["label"],
            model=model,
            context_counts=context_counts,
            window_size=window_size,
            topk=topk,
            min_context_count=min_context_count,
        )
        session_results[session_id] = result
        totals.update(
            {
                "total_windows": result["total_windows"],
                "flagged_windows": result["flagged_windows"],
                "flagged_true_positive_windows": result["flagged_true_positive_windows"],
                "labeled_anomalous_windows": result["labeled_anomalous_windows"],
            }
        )

    summary = {
        "total_windows": totals["total_windows"],
        "flagged_windows": totals["flagged_windows"],
        "flagged_ratio": (
            totals["flagged_windows"] / totals["total_windows"]
            if totals["total_windows"]
            else 0.0
        ),
        "flagged_true_positive_windows": totals["flagged_true_positive_windows"],
        "labeled_anomalous_windows": totals["labeled_anomalous_windows"],
        "precision_proxy": (
            totals["flagged_true_positive_windows"] / totals["flagged_windows"]
            if totals["flagged_windows"]
            else 0.0
        ),
        "recall_proxy": (
            totals["flagged_true_positive_windows"] / totals["labeled_anomalous_windows"]
            if totals["labeled_anomalous_windows"]
            else 0.0
        ),
    }
    return {"summary": summary, "sessions": session_results}


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir)
    session_train = load_pickle(data_dir / "session_train.pkl")
    session_test = load_pickle(data_dir / "session_test.pkl")

    model, context_counts = train_ngram(session_train, args.window_size)
    results = evaluate_dataset(
        session_test=session_test,
        model=model,
        context_counts=context_counts,
        window_size=args.window_size,
        topk=args.topk,
        min_context_count=args.min_context_count,
    )

    output = {
        "data_dir": str(data_dir),
        "window_size": args.window_size,
        "topk": args.topk,
        "min_context_count": args.min_context_count,
        "train_sessions": len(session_train),
        "test_sessions": len(session_test),
        "known_contexts": len(model),
        **results,
    }

    if args.output_json:
        output_path = Path(args.output_json)
    else:
        output_path = data_dir / f"ngram_w{args.window_size}_top{args.topk}.json"
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
