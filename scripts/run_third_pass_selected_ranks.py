import argparse
import hashlib
import json
import math
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM


ROOT = Path(__file__).resolve().parents[1]
PROCESS_KEYS = ["ProcessName", "NewProcessName", "Image", "Application"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run third-pass reranking on explicitly selected second-pass ranks."
    )
    parser.add_argument("--coarse-data-dir", required=True)
    parser.add_argument("--second-pass-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--ranks", required=True, help="Comma-separated 1-based second-pass ranks")
    parser.add_argument("--coarse-chunk-size", type=int, default=100)
    parser.add_argument("--micro-chunk-size", type=int, default=10)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--lof-neighbors", type=int, default=20)
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--ocsvm-nu", type=float, default=0.1)
    parser.add_argument("--ocsvm-gamma", default="scale")
    parser.add_argument("--top-k", type=int, default=20)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def tokenized_session(sample: dict) -> str:
    tokens = []
    for template in sample["templates"]:
        digest = hashlib.md5(template.encode("utf-8")).hexdigest()[:12]
        tokens.append(f"tpl_{digest}")
    return " ".join(tokens)


def event_anomaly_count(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(sum(label))
    return int(label)


def session_label(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(any(x == 1 for x in label))
    return int(label == 1)


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


def split_session_dict(session_dict: dict, chunk_size: int, prefix: str = "chunk") -> dict:
    chunked = {}
    for session_id, sample in session_dict.items():
        templates = sample["templates"]
        labels = sample["label"]
        chunk_count = math.ceil(len(templates) / chunk_size)
        for idx in range(chunk_count):
            start = idx * chunk_size
            end = min(len(templates), start + chunk_size)
            chunk_id = f"{session_id}|{prefix}{idx:03d}"
            chunked[chunk_id] = {
                "parent_session_id": session_id,
                "chunk_index": idx,
                "templates": templates[start:end],
                "label": labels[start:end],
            }
    return chunked


def build_vectorizer(args: argparse.Namespace) -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="word",
        ngram_range=(args.ngram_min, args.ngram_max),
        max_features=args.max_features,
    )


def parse_ranks(text: str) -> list[int]:
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def build_microchunks_from_selected_ranks(
    session_test: dict,
    second_pass_results: dict,
    selected_ranks: list[int],
    coarse_chunk_size: int,
    micro_chunk_size: int,
) -> dict:
    microchunks = {}
    ranked = second_pass_results["top_chunks"]
    for local_seq, coarse_rank in enumerate(selected_ranks, start=1):
        row = ranked[coarse_rank - 1]
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
            micro_id = (
                f"{parent_session_id}|chunk{coarse_chunk_index:03d}|micro{micro_idx:02d}"
            )
            microchunks[micro_id] = {
                "parent_session_id": parent_session_id,
                "selected_rank_group_index": local_seq,
                "coarse_chunk_rank": coarse_rank,
                "coarse_chunk_index": coarse_chunk_index,
                "micro_chunk_index": micro_idx,
                "templates": templates[ms:me],
                "label": labels[ms:me],
            }
    return microchunks


def rarity_from_chunks(chunk_dict: dict) -> dict:
    counter = Counter()
    total = 0
    for sample in chunk_dict.values():
        counter.update(sample["templates"])
        total += len(sample["templates"])
    rarity = {template: math.log((total + 1) / (count + 1)) for template, count in counter.items()}
    rarity["_default_"] = math.log(total + 1)
    return rarity


def summarize_template_mix(templates: list[str]) -> list[tuple[str, int]]:
    return Counter(process_name(template) for template in templates).most_common(5)


def score_model_rows(scores: list[float], chunk_ids: list[str], chunk_dict: dict) -> list[dict]:
    rows = []
    for chunk_id, score in zip(chunk_ids, scores):
        sample = chunk_dict[chunk_id]
        total_events = len(sample["templates"])
        attack_events = event_anomaly_count(sample)
        rows.append(
            {
                "micro_chunk_id": chunk_id,
                "parent_session_id": sample["parent_session_id"],
                "selected_rank_group_index": sample["selected_rank_group_index"],
                "coarse_chunk_rank": sample["coarse_chunk_rank"],
                "coarse_chunk_index": sample["coarse_chunk_index"],
                "micro_chunk_index": sample["micro_chunk_index"],
                "score": float(score),
                "true_session_anomaly": session_label(sample),
                "total_events": total_events,
                "attack_events": attack_events,
                "normal_events": total_events - attack_events,
                "top_processes": summarize_template_mix(sample["templates"]),
            }
        )
    return rows


def ranked_summary(rows: list[dict], ks: list[int]) -> dict:
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
            "micro_chunks": len(topk),
            "total_events": int(sum(r["total_events"] for r in topk)),
            "attack_events": int(sum(r["attack_events"] for r in topk)),
            "normal_events": int(sum(r["normal_events"] for r in topk)),
            "attack_hit": bool(any(r["attack_events"] > 0 for r in topk)),
            "normal_only_micro_chunks": int(sum(1 for r in topk if r["attack_events"] == 0)),
        }
    return payload


def run_lof(train_chunks: dict, candidate_chunks: dict, args: argparse.Namespace) -> dict:
    vectorizer = build_vectorizer(args)
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    model = LocalOutlierFactor(
        n_neighbors=args.lof_neighbors,
        contamination=args.contamination,
        novelty=True,
    )
    model.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    scores = (-model.score_samples(x)).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {
        "model": "lof",
        "ranked_summary": ranked_summary(rows, [1, 3, 5, 10, 20, 30, 50, 100, 200, 300]),
        "top_micro_chunks": sorted(rows, key=lambda x: x["score"], reverse=True)[: args.top_k],
    }


def run_ocsvm(train_chunks: dict, candidate_chunks: dict, args: argparse.Namespace) -> dict:
    vectorizer = build_vectorizer(args)
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    model = OneClassSVM(kernel="rbf", nu=args.ocsvm_nu, gamma=args.ocsvm_gamma)
    model.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    scores = (-model.score_samples(x)).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {
        "model": "ocsvm",
        "ranked_summary": ranked_summary(rows, [1, 3, 5, 10, 20, 30, 50, 100, 200, 300]),
        "top_micro_chunks": sorted(rows, key=lambda x: x["score"], reverse=True)[: args.top_k],
    }


def run_rarity(train_chunks: dict, candidate_chunks: dict, args: argparse.Namespace) -> dict:
    rarity = rarity_from_chunks(train_chunks)
    default = rarity["_default_"]
    chunk_ids = list(candidate_chunks.keys())
    scores = []
    for cid in chunk_ids:
        templates = candidate_chunks[cid]["templates"]
        per_event = [rarity.get(template, default) for template in templates]
        score = float(sum(per_event) / len(per_event)) if per_event else 0.0
        scores.append(score)
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {
        "model": "rarity",
        "ranked_summary": ranked_summary(rows, [1, 3, 5, 10, 20, 30, 50, 100, 200, 300]),
        "top_micro_chunks": sorted(rows, key=lambda x: x["score"], reverse=True)[: args.top_k],
    }


def main() -> int:
    args = parse_args()
    selected_ranks = parse_ranks(args.ranks)
    coarse_data_dir = ROOT / args.coarse_data_dir
    second_pass_results = load_json(ROOT / args.second_pass_results)
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    coarse_train = load_pickle(coarse_data_dir / "session_train.pkl")
    coarse_test = load_pickle(coarse_data_dir / "session_test.pkl")

    train_micro = split_session_dict(coarse_train, args.micro_chunk_size, prefix="micro")
    candidate_micro = build_microchunks_from_selected_ranks(
        coarse_test,
        second_pass_results,
        selected_ranks,
        args.coarse_chunk_size,
        args.micro_chunk_size,
    )

    models = [
        run_lof(train_micro, candidate_micro, args),
        run_ocsvm(train_micro, candidate_micro, args),
        run_rarity(train_micro, candidate_micro, args),
    ]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            **vars(args),
            "selected_ranks": selected_ranks,
        },
        "population": {
            "candidate_micro_chunks": len(candidate_micro),
            "candidate_total_events": int(sum(len(sample["templates"]) for sample in candidate_micro.values())),
        },
        "models": models,
    }
    (output_dir / "results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
