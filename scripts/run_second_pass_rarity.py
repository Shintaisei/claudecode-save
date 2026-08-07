import argparse
import json
import math
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import f1_score, precision_score, recall_score


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run second-pass chunk reranking using benign template rarity."
    )
    parser.add_argument("--coarse-data-dir", required=True)
    parser.add_argument("--first-pass-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument(
        "--score-stat",
        default="mean",
        choices=["mean", "max", "p95", "unseen_ratio"],
    )
    parser.add_argument(
        "--threshold-key",
        default="p95_0",
        choices=["p95_0", "p99_0", "p99_5"],
    )
    parser.add_argument("--top-k", type=int, default=10)
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


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    pos = (len(sorted_values) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


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


def build_template_rarity(session_dict: dict) -> dict:
    counter = Counter()
    total = 0
    for sample in session_dict.values():
        counter.update(sample["templates"])
        total += len(sample["templates"])
    rarity = {}
    for template, count in counter.items():
        rarity[template] = math.log((total + 1) / (count + 1))
    rarity["_default_"] = math.log(total + 1)
    return rarity


def summarize_scores(values: list[float], stat: str) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if stat == "max":
        return float(ordered[-1])
    if stat == "p95":
        return float(percentile(ordered, 95.0))
    return float(sum(values) / len(values))


def score_chunks(chunk_dict: dict, rarity: dict, stat: str) -> list[dict]:
    rows = []
    default = rarity["_default_"]
    for chunk_id, sample in chunk_dict.items():
        per_event_scores = [rarity.get(t, default) for t in sample["templates"]]
        if stat == "unseen_ratio":
            score = sum(1 for t in sample["templates"] if t not in rarity) / max(
                1, len(sample["templates"])
            )
        else:
            score = summarize_scores(per_event_scores, stat)
        total_events = len(sample["templates"])
        attack_events = event_anomaly_count(sample)
        rows.append(
            {
                "chunk_id": chunk_id,
                "parent_session_id": sample["parent_session_id"],
                "chunk_index": int(sample["chunk_index"]),
                "score": float(score),
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
    predicted_sessions = {
        sid: coarse_test[sid] for sid in coarse_predicted_ids if sid in coarse_test
    }

    benign_train_chunks = split_into_chunks(coarse_train, args.chunk_size)
    benign_val_chunks = split_into_chunks(benign_val, args.chunk_size)
    candidate_chunks = split_into_chunks(predicted_sessions, args.chunk_size)

    rarity = build_template_rarity(benign_train_chunks)
    benign_rows = score_chunks(benign_val_chunks, rarity, args.score_stat)
    benign_scores = sorted(row["score"] for row in benign_rows)
    threshold = percentile(
        benign_scores,
        {"p95_0": 95.0, "p99_0": 99.0, "p99_5": 99.5}[args.threshold_key],
    )

    candidate_rows = score_chunks(candidate_chunks, rarity, args.score_stat)
    chunk_eval = evaluate(candidate_rows, threshold)
    chunk_summary = summarize_predictions(candidate_rows)
    top_chunks = sorted(candidate_rows, key=lambda x: x["score"], reverse=True)[: args.top_k]

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "threshold": threshold,
        "chunk_eval": chunk_eval,
        "chunk_summary": chunk_summary,
        "topk_summary": {
            "top_k": args.top_k,
            "topk_total_events": int(sum(row["total_events"] for row in top_chunks)),
            "topk_attack_events": int(sum(row["attack_events"] for row in top_chunks)),
            "topk_normal_events": int(sum(row["normal_events"] for row in top_chunks)),
            "topk_true_positive_chunks": int(sum(row["true_session_anomaly"] for row in top_chunks)),
        },
        "top_chunks": top_chunks,
    }
    dump_json(output_dir / "results.json", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
