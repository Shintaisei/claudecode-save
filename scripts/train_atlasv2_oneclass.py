import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from atlasv2_single_detector_utils import (
    compute_event_summary,
    dump_json,
    evaluate_threshold,
    load_pickle,
    parse_scenario_from_data_dir,
    percentile,
    session_label,
    tokenized_session,
)


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a single-stage benign-only one-class detector for ATLAS v2."
    )
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--model",
        required=True,
        choices=["iforest", "lof", "ocsvm"],
        help="One-class detector type",
    )
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument(
        "--vectorizer",
        default="tfidf",
        choices=["tfidf", "count", "binary", "tf"],
        help="Text vectorization method",
    )
    parser.add_argument("--contamination", type=float, default=0.10)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--neighbors", type=int, default=20)
    parser.add_argument(
        "--kernel",
        default="rbf",
        choices=["rbf", "linear", "sigmoid"],
    )
    parser.add_argument("--nu", type=float, default=0.10)
    parser.add_argument("--gamma", default="scale")
    return parser.parse_args()


def build_model(args: argparse.Namespace):
    if args.model == "iforest":
        return IsolationForest(
            n_estimators=300,
            contamination=args.contamination,
            random_state=args.random_seed,
            n_jobs=1,
        )
    if args.model == "lof":
        return LocalOutlierFactor(
            n_neighbors=args.neighbors,
            contamination=args.contamination,
            novelty=True,
        )
    return OneClassSVM(
        kernel=args.kernel,
        nu=args.nu,
        gamma=args.gamma,
    )


def fit_and_score(model, x_train, x_eval):
    model.fit(x_train)
    train_scores = (-model.score_samples(x_train)).tolist()
    eval_scores = (-model.score_samples(x_eval)).tolist()
    return train_scores, eval_scores


def main() -> int:
    args = parse_args()
    data_dir = ROOT / args.data_dir
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    session_train = load_pickle(data_dir / "session_train.pkl")
    session_test = load_pickle(data_dir / "session_test.pkl")
    data_desc = json.loads((data_dir / "data_desc.json").read_text(encoding="utf-8"))
    benign_val = load_pickle(ROOT / data_desc["train_source"] / "session_test.pkl")

    x_train_text = [tokenized_session(sample) for sample in session_train.values()]
    x_test_text = [tokenized_session(sample) for sample in session_test.values()]
    x_benign_text = [tokenized_session(sample) for sample in benign_val.values()]
    y_test = [session_label(sample) for sample in session_test.values()]

    common_vectorizer_kwargs = {
        "analyzer": "word",
        "ngram_range": (args.ngram_min, args.ngram_max),
        "max_features": args.max_features,
    }
    if args.vectorizer == "tfidf":
        vectorizer = TfidfVectorizer(**common_vectorizer_kwargs)
    elif args.vectorizer == "tf":
        vectorizer = TfidfVectorizer(use_idf=False, **common_vectorizer_kwargs)
    elif args.vectorizer == "binary":
        vectorizer = CountVectorizer(binary=True, **common_vectorizer_kwargs)
    else:
        vectorizer = CountVectorizer(**common_vectorizer_kwargs)
    x_train = vectorizer.fit_transform(x_train_text)
    x_test = vectorizer.transform(x_test_text)
    x_benign = vectorizer.transform(x_benign_text)

    model = build_model(args)
    train_scores, benign_scores = fit_and_score(model, x_train, x_benign)
    test_scores = (-model.score_samples(x_test)).tolist()

    benign_sorted = sorted(benign_scores)
    benign_thresholds = {
        "p95_0": percentile(benign_sorted, 95.0),
        "p99_0": percentile(benign_sorted, 99.0),
        "p99_5": percentile(benign_sorted, 99.5),
    }
    benign_eval = {
        key: evaluate_threshold(test_scores, y_test, threshold)
        for key, threshold in benign_thresholds.items()
    }
    benign_event_summary = {
        key: compute_event_summary(
            session_test,
            dict(zip(session_test.keys(), test_scores)),
            threshold,
        )
        for key, threshold in benign_thresholds.items()
    }

    oracle_best = None
    for threshold in sorted(test_scores):
        candidate = evaluate_threshold(test_scores, y_test, threshold)
        if oracle_best is None or candidate["f1"] > oracle_best["f1"]:
            oracle_best = candidate

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "scenario": parse_scenario_from_data_dir(data_dir),
        "train_sessions": len(session_train),
        "test_sessions": len(session_test),
        "test_anomaly_sessions": int(sum(y_test)),
        "oracle_best": oracle_best,
        "benign_thresholds": benign_eval,
        "benign_event_summary": benign_event_summary,
        "score_summary": {
            "train_mean": float(sum(train_scores) / len(train_scores)),
            "benign_val_mean": float(sum(benign_scores) / len(benign_scores)),
            "test_mean": float(sum(test_scores) / len(test_scores)),
        },
    }
    dump_json(output_dir / "results.json", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
