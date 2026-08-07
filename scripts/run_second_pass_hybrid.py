import argparse
import hashlib
import json
import math
import pickle
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors


ROOT = Path(__file__).resolve().parents[1]
PROCESS_RE = re.compile(r"ProcessName=([^ |]+)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run hybrid second-pass fine-grained reranking on first-pass anomalous sessions."
    )
    parser.add_argument("--coarse-data-dir", required=True)
    parser.add_argument("--first-pass-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--neighbors", type=int, default=5)
    parser.add_argument("--rare-process-min-share", type=float, default=0.5)
    parser.add_argument("--rare-process-window", type=int, default=10)
    parser.add_argument("--delta-window", type=int, default=3)
    parser.add_argument("--delta-percentile", type=float, default=95.0)
    parser.add_argument("--top-k", type=int, default=10)
    return parser.parse_args()


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def event_anomaly_count(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(sum(label))
    return int(label)


def split_into_chunks(session_dict: dict, chunk_size: int) -> list[dict]:
    rows = []
    for session_id, sample in session_dict.items():
        templates = sample["templates"]
        labels = sample["label"]
        chunk_count = math.ceil(len(templates) / chunk_size)
        for idx in range(chunk_count):
            start = idx * chunk_size
            end = min(len(templates), start + chunk_size)
            rows.append(
                {
                    "chunk_id": f"{session_id}|chunk{idx:03d}",
                    "parent_session_id": session_id,
                    "chunk_index": idx,
                    "templates": templates[start:end],
                    "label": labels[start:end],
                    "total_events": end - start,
                }
            )
    return rows


def tokenized_session(sample: dict) -> str:
    return " || ".join(template.lower() for template in sample["templates"])


def tokenized_session_first_pass(sample: dict) -> str:
    tokens = []
    for template in sample["templates"]:
        digest = hashlib.md5(template.encode("utf-8")).hexdigest()[:12]
        tokens.append(f"tpl_{digest}")
    return " ".join(tokens)


def extract_process_names(templates: list[str]) -> list[str]:
    names = []
    for template in templates:
        names.extend(match.group(1).lower() for match in PROCESS_RE.finditer(template))
    return names


def dominant_unseen_process(
    process_names: list[str], benign_process_counter: Counter
) -> tuple[str, float, float]:
    if not process_names:
        return "", 0.0, 0.0
    unseen = [name for name in process_names if name not in benign_process_counter]
    unseen_ratio = len(unseen) / len(process_names)
    if not unseen:
        return "", unseen_ratio, 0.0
    counts = Counter(unseen)
    dominant, count = counts.most_common(1)[0]
    return dominant, unseen_ratio, count / len(process_names)


def build_vectorizer(ngram_min: int, ngram_max: int, max_features: int):
    return TfidfVectorizer(
        analyzer="word",
        ngram_range=(ngram_min, ngram_max),
        max_features=max_features,
    )


def score_chunks(
    train_chunks: list[dict],
    score_chunks: list[dict],
    vectorizer,
    neighbors: int,
    benign_process_counter: Counter,
) -> list[dict]:
    train_texts = [tokenized_session(sample) for sample in train_chunks]
    x_train = vectorizer.fit_transform(train_texts)
    knn = NearestNeighbors(metric="cosine", n_neighbors=neighbors)
    knn.fit(x_train)

    chunk_texts = [tokenized_session(sample) for sample in score_chunks]
    x = vectorizer.transform(chunk_texts)
    distances, _ = knn.kneighbors(x, n_neighbors=neighbors)

    rows = []
    by_session = defaultdict(list)
    for sample, distance in zip(score_chunks, distances):
        process_names = extract_process_names(sample["templates"])
        dominant, unseen_ratio, dominant_share = dominant_unseen_process(
            process_names, benign_process_counter
        )
        row = {
            "chunk_id": sample["chunk_id"],
            "parent_session_id": sample["parent_session_id"],
            "chunk_index": int(sample["chunk_index"]),
            "base_score": float(distance.mean()),
            "dominant_unseen_process": dominant,
            "unseen_process_ratio": float(unseen_ratio),
            "dominant_unseen_share": float(dominant_share),
            "attack_events": event_anomaly_count(sample),
            "total_events": int(sample["total_events"]),
        }
        row["normal_events"] = row["total_events"] - row["attack_events"]
        by_session[row["parent_session_id"]].append(row)

    for session_rows in by_session.values():
        session_rows.sort(key=lambda x: x["chunk_index"])
        prev_score = 0.0
        for row in session_rows:
            row["delta_base_score"] = row["base_score"] - prev_score
            prev_score = row["base_score"]
            rows.append(row)
    return rows


def build_benign_process_counter(session_dict: dict) -> Counter:
    counter = Counter()
    for sample in session_dict.values():
        counter.update(extract_process_names(sample["templates"]))
    return counter


def candidate_score(
    base_score: float,
    base_threshold: float,
    delta_score: float,
    delta_threshold: float,
    unseen_ratio: float,
) -> float:
    base_component = base_score / max(base_threshold, 1e-9)
    delta_component = max(0.0, delta_score) / max(delta_threshold, 1e-9)
    return base_component + 0.75 * delta_component + 0.75 * unseen_ratio


def create_rare_process_candidates(
    rows_by_session: dict[str, list[dict]],
    base_threshold: float,
    delta_threshold: float,
    min_share: float,
    window_size: int,
) -> list[dict]:
    candidates = []
    for session_id, session_rows in rows_by_session.items():
        idx = 0
        while idx < len(session_rows):
            row = session_rows[idx]
            if not (
                row["dominant_unseen_process"] and row["dominant_unseen_share"] >= min_share
            ):
                idx += 1
                continue

            dominant = row["dominant_unseen_process"]
            end = idx + 1
            while end < len(session_rows):
                nxt = session_rows[end]
                is_contiguous = nxt["chunk_index"] == session_rows[end - 1]["chunk_index"] + 1
                same_process = (
                    nxt["dominant_unseen_process"] == dominant
                    and nxt["dominant_unseen_share"] >= min_share
                )
                if not (is_contiguous and same_process):
                    break
                end += 1

            run_rows = session_rows[idx:end]
            focus_rows = run_rows[: min(window_size, len(run_rows))]
            score = 0.0
            for offset, focus_row in enumerate(focus_rows):
                decay = 1.0 / (1.0 + 0.2 * offset)
                score += decay * candidate_score(
                    focus_row["base_score"],
                    base_threshold,
                    focus_row["delta_base_score"],
                    delta_threshold,
                    focus_row["unseen_process_ratio"],
                )
            candidates.append(
                {
                    "candidate_type": "rare_process_onset",
                    "parent_session_id": session_id,
                    "start_chunk": focus_rows[0]["chunk_index"],
                    "end_chunk": focus_rows[-1]["chunk_index"],
                    "run_length_chunks": len(run_rows),
                    "dominant_process": dominant,
                    "score": float(score + 0.1 * min(len(run_rows), window_size)),
                    "attack_events": int(sum(row["attack_events"] for row in focus_rows)),
                    "normal_events": int(sum(row["normal_events"] for row in focus_rows)),
                    "total_events": int(sum(row["total_events"] for row in focus_rows)),
                }
            )
            idx = end
    return candidates


def create_delta_candidates(
    rows_by_session: dict[str, list[dict]],
    base_threshold: float,
    delta_threshold: float,
    delta_window: int,
) -> list[dict]:
    candidates = []
    for session_id, session_rows in rows_by_session.items():
        for idx, row in enumerate(session_rows):
            if row["delta_base_score"] <= delta_threshold:
                continue
            focus_rows = session_rows[idx : min(len(session_rows), idx + delta_window)]
            score = 0.0
            for offset, focus_row in enumerate(focus_rows):
                decay = 1.0 / (1.0 + 0.3 * offset)
                score += decay * candidate_score(
                    focus_row["base_score"],
                    base_threshold,
                    focus_row["delta_base_score"],
                    delta_threshold,
                    focus_row["unseen_process_ratio"],
                )
            candidates.append(
                {
                    "candidate_type": "delta_onset",
                    "parent_session_id": session_id,
                    "start_chunk": focus_rows[0]["chunk_index"],
                    "end_chunk": focus_rows[-1]["chunk_index"],
                    "run_length_chunks": len(focus_rows),
                    "dominant_process": focus_rows[0]["dominant_unseen_process"],
                    "score": float(score),
                    "attack_events": int(sum(r["attack_events"] for r in focus_rows)),
                    "normal_events": int(sum(r["normal_events"] for r in focus_rows)),
                    "total_events": int(sum(r["total_events"] for r in focus_rows)),
                }
            )
    return candidates


def create_base_fallback_candidates(
    rows_by_session: dict[str, list[dict]],
    base_threshold: float,
    delta_threshold: float,
) -> list[dict]:
    candidates = []
    for session_id, session_rows in rows_by_session.items():
        best_row = max(session_rows, key=lambda x: x["base_score"])
        candidates.append(
            {
                "candidate_type": "base_fallback",
                "parent_session_id": session_id,
                "start_chunk": best_row["chunk_index"],
                "end_chunk": best_row["chunk_index"],
                "run_length_chunks": 1,
                "dominant_process": best_row["dominant_unseen_process"],
                "score": float(
                    candidate_score(
                        best_row["base_score"],
                        base_threshold,
                        best_row["delta_base_score"],
                        delta_threshold,
                        best_row["unseen_process_ratio"],
                    )
                ),
                "attack_events": int(best_row["attack_events"]),
                "normal_events": int(best_row["normal_events"]),
                "total_events": int(best_row["total_events"]),
            }
        )
    return candidates


def dedupe_candidates(candidates: list[dict]) -> list[dict]:
    kept = {}
    priority = {
        "rare_process_onset": 3,
        "delta_onset": 2,
        "base_fallback": 1,
    }
    for candidate in candidates:
        key = (
            candidate["parent_session_id"],
            candidate["start_chunk"],
            candidate["end_chunk"],
        )
        prev = kept.get(key)
        if prev is None:
            kept[key] = candidate
            continue
        if candidate["score"] > prev["score"]:
            kept[key] = candidate
            continue
        if (
            candidate["score"] == prev["score"]
            and priority[candidate["candidate_type"]] > priority[prev["candidate_type"]]
        ):
            kept[key] = candidate
    return list(kept.values())


def review_priority(candidate_type: str) -> int:
    priority = {
        "rare_process_onset": 3,
        "delta_onset": 2,
        "base_fallback": 1,
    }
    return priority.get(candidate_type, 0)


def review_sorted(candidates: list[dict]) -> list[dict]:
    return sorted(
        candidates,
        key=lambda x: (review_priority(x["candidate_type"]), x["score"]),
        reverse=True,
    )


def summarize_topk(candidates: list[dict], top_k: int) -> dict:
    top_rows = candidates[:top_k]
    hit_sessions = sorted(
        {
            row["parent_session_id"]
            for row in top_rows
            if row["attack_events"] > 0
        }
    )
    return {
        "top_k": top_k,
        "windows_with_attack": int(sum(1 for row in top_rows if row["attack_events"] > 0)),
        "hit_parent_sessions": hit_sessions,
        "topk_total_events": int(sum(row["total_events"] for row in top_rows)),
        "topk_attack_events": int(sum(row["attack_events"] for row in top_rows)),
        "topk_normal_events": int(sum(row["normal_events"] for row in top_rows)),
    }


def summarize_per_session_best(candidates: list[dict]) -> list[dict]:
    best_by_session = {}
    for candidate in candidates:
        session_id = candidate["parent_session_id"]
        prev = best_by_session.get(session_id)
        if prev is None:
            best_by_session[session_id] = candidate
            continue
        if review_priority(candidate["candidate_type"]) > review_priority(prev["candidate_type"]):
            best_by_session[session_id] = candidate
            continue
        if (
            review_priority(candidate["candidate_type"]) == review_priority(prev["candidate_type"])
            and candidate["score"] > prev["score"]
        ):
            best_by_session[session_id] = candidate
    return review_sorted(list(best_by_session.values()))


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
        first_pass_args = first_pass_results.get("args", {})
        first_pass_vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(
                int(first_pass_args.get("ngram_min", 1)),
                int(first_pass_args.get("ngram_max", 2)),
            ),
            max_features=int(first_pass_args.get("max_features", 20000)),
        )
        x_train = first_pass_vectorizer.fit_transform(
            tokenized_session_first_pass(sample) for sample in coarse_train.values()
        )
        x_test = first_pass_vectorizer.transform(
            tokenized_session_first_pass(sample) for sample in coarse_test.values()
        )
        first_pass_model = NearestNeighbors(metric="cosine", n_neighbors=1)
        if "contamination" in first_pass_args:
            from sklearn.ensemble import IsolationForest

            first_pass_model = IsolationForest(
                n_estimators=300,
                contamination=float(first_pass_args.get("contamination", 0.1)),
                random_state=int(first_pass_args.get("random_seed", 42)),
                n_jobs=1,
            )
            first_pass_model.fit(x_train)
            test_scores = (-first_pass_model.score_samples(x_test)).tolist()
            coarse_threshold = first_pass_results["benign_thresholds"]["p95_0"]["threshold"]
            session_ids = list(coarse_test.keys())
            coarse_predicted_ids = {
                sid
                for sid, score in zip(session_ids, test_scores)
                if score > coarse_threshold
            }

    predicted_sessions = {
        sid: coarse_test[sid] for sid in coarse_predicted_ids if sid in coarse_test
    }

    train_chunks = split_into_chunks(coarse_train, args.chunk_size)
    val_chunks = split_into_chunks(benign_val, args.chunk_size)
    predicted_chunks = split_into_chunks(predicted_sessions, args.chunk_size)

    benign_process_counter = build_benign_process_counter(coarse_train)
    vectorizer = build_vectorizer(args.ngram_min, args.ngram_max, args.max_features)

    scored_val_rows = score_chunks(
        train_chunks, val_chunks, vectorizer, args.neighbors, benign_process_counter
    )
    scored_pred_rows = score_chunks(
        train_chunks, predicted_chunks, vectorizer, args.neighbors, benign_process_counter
    )

    base_threshold = percentile([row["base_score"] for row in scored_val_rows], 95.0)
    delta_threshold = percentile(
        [row["delta_base_score"] for row in scored_val_rows], args.delta_percentile
    )

    rows_by_session = defaultdict(list)
    for row in scored_pred_rows:
        rows_by_session[row["parent_session_id"]].append(row)
    for session_rows in rows_by_session.values():
        session_rows.sort(key=lambda x: x["chunk_index"])

    candidates = []
    candidates.extend(
        create_rare_process_candidates(
            rows_by_session,
            base_threshold,
            delta_threshold,
            args.rare_process_min_share,
            args.rare_process_window,
        )
    )
    candidates.extend(
        create_delta_candidates(
            rows_by_session,
            base_threshold,
            delta_threshold,
            args.delta_window,
        )
    )
    candidates.extend(
        create_base_fallback_candidates(rows_by_session, base_threshold, delta_threshold)
    )

    deduped = dedupe_candidates(candidates)
    ranked = sorted(deduped, key=lambda x: x["score"], reverse=True)
    review_ranked = review_sorted(deduped)
    per_session_best = summarize_per_session_best(deduped)

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "first_pass_summary": first_pass_results.get("coarse_summary", {}),
        "thresholds": {
            "base_p95": base_threshold,
            "delta_percentile": args.delta_percentile,
            "delta_threshold": delta_threshold,
        },
        "candidate_counts": {
            "total": len(deduped),
            "rare_process_onset": int(
                sum(1 for row in deduped if row["candidate_type"] == "rare_process_onset")
            ),
            "delta_onset": int(sum(1 for row in deduped if row["candidate_type"] == "delta_onset")),
            "base_fallback": int(
                sum(1 for row in deduped if row["candidate_type"] == "base_fallback")
            ),
        },
        "topk_summary_by_score": summarize_topk(ranked, args.top_k),
        "topk_summary_review_order": summarize_topk(review_ranked, args.top_k),
        "per_session_best": per_session_best,
        "top_windows_by_score": ranked[: args.top_k],
        "review_windows": review_ranked[: args.top_k],
    }
    dump_json(output_dir / "results.json", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
