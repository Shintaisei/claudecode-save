import argparse
import hashlib
import json
import math
import pickle
from datetime import datetime, timezone
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a benign-only session-level IsolationForest detector for ATLAS v2."
    )
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=3)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def session_label(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(any(x == 1 for x in label))
    return int(label == 1)


def tokenized_session(sample: dict) -> str:
    templates = sample["templates"]
    tokens = []
    for template in templates:
        digest = hashlib.md5(template.encode("utf-8")).hexdigest()[:12]
        tokens.append(f"tpl_{digest}")
    return " ".join(tokens)


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    pos = (len(sorted_values) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def evaluate_threshold(scores, y_true, threshold):
    y_pred = [int(score > threshold) for score in scores]
    return {
        "threshold": float(threshold),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "rc": float(recall_score(y_true, y_pred, zero_division=0)),
        "pc": float(precision_score(y_true, y_pred, zero_division=0)),
        "predicted_positive": int(sum(y_pred)),
    }


def main() -> int:
    args = parse_args()
    data_dir = ROOT / args.data_dir
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    session_train = load_pickle(data_dir / "session_train.pkl")
    session_test = load_pickle(data_dir / "session_test.pkl")

    train_source = json.loads((data_dir / "data_desc.json").read_text(encoding="utf-8"))[
        "train_source"
    ]
    benign_val = load_pickle(ROOT / train_source / "session_test.pkl")

    x_train_text = [tokenized_session(sample) for sample in session_train.values()]
    x_test_text = [tokenized_session(sample) for sample in session_test.values()]
    x_benign_text = [tokenized_session(sample) for sample in benign_val.values()]
    y_test = [session_label(sample) for sample in session_test.values()]

    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(args.ngram_min, args.ngram_max),
        max_features=args.max_features,
    )
    x_train = vectorizer.fit_transform(x_train_text)
    x_test = vectorizer.transform(x_test_text)
    x_benign = vectorizer.transform(x_benign_text)

    model = IsolationForest(
        n_estimators=300,
        contamination=args.contamination,
        random_state=args.random_seed,
        n_jobs=1,
    )
    model.fit(x_train)

    train_scores = (-model.score_samples(x_train)).tolist()
    benign_scores = (-model.score_samples(x_benign)).tolist()
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

    oracle_best = None
    for threshold in sorted(test_scores):
        candidate = evaluate_threshold(test_scores, y_test, threshold)
        if oracle_best is None or candidate["f1"] > oracle_best["f1"]:
            oracle_best = candidate

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "train_sessions": len(session_train),
        "test_sessions": len(session_test),
        "test_anomaly_sessions": int(sum(y_test)),
        "oracle_best": oracle_best,
        "benign_thresholds": benign_eval,
        "score_summary": {
            "train_mean": float(sum(train_scores) / len(train_scores)),
            "benign_val_mean": float(sum(benign_scores) / len(benign_scores)),
            "test_mean": float(sum(test_scores) / len(test_scores)),
        },
    }
    (output_dir / "results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
