import argparse
import hashlib
import json
import math
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run second-pass chunk ranking using SVD reconstruction error."
    )
    parser.add_argument("--coarse-data-dir", required=True)
    parser.add_argument("--first-pass-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--svd-components", type=int, default=64)
    parser.add_argument(
        "--threshold-key",
        default="p95_0",
        choices=["p95_0", "p99_0", "p99_5"],
    )
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--random-seed", type=int, default=42)
    return parser.parse_args()


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def session_label(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(any(x == 1 for x in label))
    return int(label == 1)


def event_anomaly_count(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(sum(label))
    return int(label)


def tokenized_session(sample: dict) -> str:
    tokens = []
    for template in sample["templates"]:
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


def build_vectorizer(ngram_min: int, ngram_max: int, max_features: int):
    return TfidfVectorizer(
        analyzer="word",
        ngram_range=(ngram_min, ngram_max),
        max_features=max_features,
    )


def split_into_chunks(session_dict: dict, chunk_size: int) -> dict:
    chunked = {}
    for session_id, sample in session_dict.items():
        templates = sample["templates"]
        labels = sample["label"]
        chunk_count = math.ceil(len(templates) / chunk_size)
        for idx in range(chunk_count):
            start = idx * chunk_size
            end = min(len(templates), start + chunk_size)
            chunk_id = f"{session_id}|chunk{idx:03d}"
            chunked[chunk_id] = {
                "parent_session_id": session_id,
                "chunk_index": idx,
                "templates": templates[start:end],
                "label": labels[start:end],
            }
    return chunked


def reconstruction_scores(model: TruncatedSVD, x) -> np.ndarray:
    z = model.transform(x)
    x_hat = model.inverse_transform(z)
    diff = x.toarray() - x_hat
    return np.sqrt((diff * diff).sum(axis=1))


def score_chunks(model, vectorizer, chunk_dict: dict) -> list[dict]:
    chunk_ids = list(chunk_dict.keys())
    chunk_texts = [tokenized_session(chunk_dict[cid]) for cid in chunk_ids]
    x = vectorizer.transform(chunk_texts)
    scores = reconstruction_scores(model, x).tolist()
    rows = []
    for idx, cid in enumerate(chunk_ids):
        sample = chunk_dict[cid]
        total_events = len(sample["templates"])
        attack_events = event_anomaly_count(sample)
        rows.append(
            {
                "chunk_id": cid,
                "parent_session_id": sample["parent_session_id"],
                "chunk_index": int(sample["chunk_index"]),
                "score": float(scores[idx]),
                "true_session_anomaly": session_label(sample),
                "total_events": total_events,
                "attack_events": attack_events,
                "normal_events": total_events - attack_events,
            }
        )
    return rows


def evaluate(rows: list[dict], threshold: float) -> dict:
    y_true = [row["true_session_anomaly"] for row in rows]
    y_pred = [int(row["score"] > threshold) for row in rows]
    for row, pred in zip(rows, y_pred):
        row["pred"] = pred
    return {
        "threshold": float(threshold),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "rc": float(recall_score(y_true, y_pred, zero_division=0)),
        "pc": float(precision_score(y_true, y_pred, zero_division=0)),
        "predicted_positive": int(sum(y_pred)),
    }


def summarize_predictions(rows: list[dict]) -> dict:
    predicted = [row for row in rows if row["pred"] == 1]
    true_positive = [row for row in predicted if row["true_session_anomaly"] == 1]
    false_positive = [row for row in predicted if row["true_session_anomaly"] == 0]
    return {
        "predicted_positive": len(predicted),
        "true_positive": len(true_positive),
        "false_positive": len(false_positive),
        "predicted_total_events": int(sum(r["total_events"] for r in predicted)),
        "predicted_attack_events": int(sum(r["attack_events"] for r in predicted)),
        "predicted_normal_events": int(sum(r["normal_events"] for r in predicted)),
        "true_positive_total_events": int(sum(r["total_events"] for r in true_positive)),
        "true_positive_attack_events": int(sum(r["attack_events"] for r in true_positive)),
        "true_positive_normal_events": int(sum(r["normal_events"] for r in true_positive)),
        "false_positive_total_events": int(sum(r["total_events"] for r in false_positive)),
        "false_positive_attack_events": int(sum(r["attack_events"] for r in false_positive)),
        "false_positive_normal_events": int(sum(r["normal_events"] for r in false_positive)),
    }


def summarize_ranked_chunks(rows: list[dict], ks: list[int]) -> dict:
    ranked = sorted(rows, key=lambda x: x["score"], reverse=True)
    first_attack_rank = None
    for idx, row in enumerate(ranked, start=1):
        if row["attack_events"] > 0:
            first_attack_rank = idx
            break
    payload = {"first_attack_rank": first_attack_rank}
    for k in ks:
        topk = ranked[:k]
        payload[f"top_{k}"] = {
            "chunks": len(topk),
            "total_events": int(sum(r["total_events"] for r in topk)),
            "attack_events": int(sum(r["attack_events"] for r in topk)),
            "normal_events": int(sum(r["normal_events"] for r in topk)),
            "attack_hit": bool(any(r["attack_events"] > 0 for r in topk)),
        }
    return payload


def main() -> int:
    args = parse_args()
    coarse_data_dir = ROOT / args.coarse_data_dir
    first_pass_results = json.loads((ROOT / args.first_pass_results).read_text(encoding="utf-8"))
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    coarse_desc = json.loads((coarse_data_dir / "data_desc.json").read_text(encoding="utf-8"))
    coarse_train = load_pickle(coarse_data_dir / "session_train.pkl")
    coarse_test = load_pickle(coarse_data_dir / "session_test.pkl")
    benign_val = load_pickle(ROOT / coarse_desc["train_source"] / "session_test.pkl")

    coarse_predicted_ids = {
        row["session_id"]
        for row in first_pass_results.get("predicted_coarse_sessions", [])
        if row.get("pred", 1) == 1
    }
    if not coarse_predicted_ids:
        raise RuntimeError("first-pass results must include predicted_coarse_sessions")

    predicted_sessions = {
        sid: coarse_test[sid] for sid in coarse_predicted_ids if sid in coarse_test
    }

    benign_train_chunks = split_into_chunks(coarse_train, args.chunk_size)
    benign_val_chunks = split_into_chunks(benign_val, args.chunk_size)
    candidate_chunks = split_into_chunks(predicted_sessions, args.chunk_size)

    vectorizer = build_vectorizer(args.ngram_min, args.ngram_max, args.max_features)
    x_train = vectorizer.fit_transform(
        tokenized_session(sample) for sample in benign_train_chunks.values()
    )
    n_components = min(args.svd_components, max(2, x_train.shape[1] - 1))
    model = TruncatedSVD(n_components=n_components, random_state=args.random_seed)
    model.fit(x_train)

    benign_rows = score_chunks(model, vectorizer, benign_val_chunks)
    benign_scores = sorted(row["score"] for row in benign_rows)
    chunk_threshold = percentile(
        benign_scores,
        {"p95_0": 95.0, "p99_0": 99.0, "p99_5": 99.5}[args.threshold_key],
    )

    chunk_rows = score_chunks(model, vectorizer, candidate_chunks)
    chunk_eval = evaluate(chunk_rows, chunk_threshold)
    chunk_summary = summarize_predictions(chunk_rows)
    ranked_summary = summarize_ranked_chunks(chunk_rows, [1, 3, 5, 10, 20, 50, 100])
    top_chunks = sorted(chunk_rows, key=lambda x: x["score"], reverse=True)[: args.top_k]

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "chunk_threshold": chunk_threshold,
        "chunk_eval": chunk_eval,
        "chunk_summary": chunk_summary,
        "ranked_summary": ranked_summary,
        "top_chunks": top_chunks,
    }
    dump_json(output_dir / "results.json", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
