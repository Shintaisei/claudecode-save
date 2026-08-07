import argparse
import hashlib
import json
import math
import pickle
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.linear_model import SGDOneClassSVM
from sklearn.svm import OneClassSVM


ROOT = Path(__file__).resolve().parents[1]


SCENARIOS = {
    "s3": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_s3_cu10",
        "second_pass_results": "analysis_data/model_runs/secondpass_model_benchmark_benign1to4/s3_iforest/results.json",
    },
    "m4": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_m4_cu10",
        "second_pass_results": "analysis_data/model_runs/secondpass_model_benchmark_benign1to4/m4_iforest/results.json",
    },
    "m6": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_m6_cu10",
        "second_pass_results": "analysis_data/model_runs/secondpass_model_benchmark_benign1to4/m6_iforest/results.json",
    },
    "s4": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_s4_cu10",
        "second_pass_results": "analysis_data/model_runs/secondpass_model_benchmark_benign1to4/s4_iforest/results.json",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark pure model third-pass reranking from second-pass top chunks."
    )
    parser.add_argument("--scenarios", default="s3,m4,m6,s4")
    parser.add_argument("--models", default="iforest,lof,ocsvm,sgdocsvm,knn")
    parser.add_argument("--top-chunks", type=int, default=30)
    parser.add_argument("--coarse-chunk-size", type=int, default=100)
    parser.add_argument("--micro-chunk-size", type=int, default=10)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument(
        "--output-root",
        default="analysis_data/model_runs/thirdpass_model_benchmark_benign1to4",
    )
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


def build_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=20000,
    )


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


def second_pass_chunk_key(row: dict) -> str:
    return row.get("chunk_id") or row.get("session_id")


def build_microchunks_from_second_pass(
    session_test: dict,
    second_pass_results: dict,
    top_chunks: int,
    coarse_chunk_size: int,
    micro_chunk_size: int,
) -> dict:
    microchunks = {}
    ranked = second_pass_results["top_chunks"][:top_chunks]
    for coarse_rank, row in enumerate(ranked, start=1):
        chunk_session_id = second_pass_chunk_key(row)
        parent_session_id = row.get("parent_session_id") or "|".join(chunk_session_id.split("|")[:-1])
        coarse_chunk_index = int(row.get("chunk_index", int(chunk_session_id.split("chunk")[-1])))
        sample = session_test[parent_session_id]
        start = coarse_chunk_index * coarse_chunk_size
        end = min(len(sample["templates"]), start + coarse_chunk_size)
        templates = sample["templates"][start:end]
        labels = sample["label"][start:end]
        micro_count = math.ceil(len(templates) / micro_chunk_size)
        for micro_idx in range(micro_count):
            ms = micro_idx * micro_chunk_size
            me = min(len(templates), ms + micro_chunk_size)
            micro_id = f"{parent_session_id}|chunk{coarse_chunk_index:03d}|micro{micro_idx:02d}"
            microchunks[micro_id] = {
                "parent_session_id": parent_session_id,
                "coarse_chunk_rank": coarse_rank,
                "coarse_chunk_index": coarse_chunk_index,
                "micro_chunk_index": micro_idx,
                "templates": templates[ms:me],
                "label": labels[ms:me],
            }
    return microchunks


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
                "coarse_chunk_rank": sample["coarse_chunk_rank"],
                "coarse_chunk_index": sample["coarse_chunk_index"],
                "micro_chunk_index": sample["micro_chunk_index"],
                "score": float(score),
                "true_session_anomaly": session_label(sample),
                "total_events": total_events,
                "attack_events": attack_events,
                "normal_events": total_events - attack_events,
            }
        )
    return rows


def summarize_topk(rows: list[dict], k: int) -> dict:
    ranked = sorted(rows, key=lambda x: x["score"], reverse=True)
    subset = ranked[:k]
    attack_rows = [row for row in subset if row["attack_events"] > 0]
    fp_rows = [row for row in subset if row["attack_events"] == 0]
    return {
        "micro_chunks": len(subset),
        "total_events": int(sum(r["total_events"] for r in subset)),
        "attack_events": int(sum(r["attack_events"] for r in subset)),
        "normal_events": int(sum(r["normal_events"] for r in subset)),
        "attack_micro_chunks": len(attack_rows),
        "fp_micro_chunks": len(fp_rows),
        "attack_hit": bool(attack_rows),
        "fp_hit": bool(fp_rows),
    }


def summarize_ranked(rows: list[dict]) -> dict:
    ranked = sorted(rows, key=lambda x: x["score"], reverse=True)
    first_attack_rank = None
    for idx, row in enumerate(ranked, start=1):
        if row["attack_events"] > 0:
            first_attack_rank = idx
            break
    return {
        "first_attack_rank": first_attack_rank,
        "top10": summarize_topk(rows, min(10, len(rows))),
        "top20": summarize_topk(rows, min(20, len(rows))),
        "top30": summarize_topk(rows, min(30, len(rows))),
    }


def run_iforest(train_chunks: dict, candidate_chunks: dict) -> dict:
    vectorizer = build_vectorizer()
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    model = IsolationForest(
        n_estimators=300,
        contamination=0.10,
        random_state=42,
        n_jobs=1,
    )
    model.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    scores = (-model.score_samples(x)).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {"model": "iforest", "rows": rows}


def run_lof(train_chunks: dict, candidate_chunks: dict) -> dict:
    vectorizer = build_vectorizer()
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    model = LocalOutlierFactor(n_neighbors=20, contamination=0.10, novelty=True)
    model.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    scores = (-model.score_samples(x)).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {"model": "lof", "rows": rows}


def run_ocsvm(train_chunks: dict, candidate_chunks: dict) -> dict:
    vectorizer = build_vectorizer()
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    model = OneClassSVM(kernel="rbf", nu=0.10, gamma="scale")
    model.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    scores = (-model.score_samples(x)).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {"model": "ocsvm", "rows": rows}


def run_sgdocsvm(train_chunks: dict, candidate_chunks: dict) -> dict:
    vectorizer = build_vectorizer()
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    model = SGDOneClassSVM(nu=0.10, random_state=42)
    model.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    scores = (-model.score_samples(x)).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {"model": "sgdocsvm", "rows": rows}


def run_knn(train_chunks: dict, candidate_chunks: dict) -> dict:
    vectorizer = build_vectorizer()
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in train_chunks.values())
    knn = NearestNeighbors(metric="cosine", n_neighbors=5)
    knn.fit(x_train)
    chunk_ids = list(candidate_chunks.keys())
    x = vectorizer.transform(tokenized_session(candidate_chunks[cid]) for cid in chunk_ids)
    distances, _ = knn.kneighbors(x, n_neighbors=5)
    scores = distances.mean(axis=1).tolist()
    rows = score_model_rows(scores, chunk_ids, candidate_chunks)
    return {"model": "knn", "rows": rows}


MODEL_FUNCS = {
    "iforest": run_iforest,
    "lof": run_lof,
    "ocsvm": run_ocsvm,
    "sgdocsvm": run_sgdocsvm,
    "knn": run_knn,
}


def main() -> int:
    args = parse_args()
    scenarios = [item.strip().lower() for item in args.scenarios.split(",") if item.strip()]
    models = [item.strip().lower() for item in args.models.split(",") if item.strip()]
    output_root = ROOT / args.output_root
    output_root.mkdir(parents=True, exist_ok=True)

    summary = {"args": vars(args), "results": {}}

    for scenario in scenarios:
        spec = SCENARIOS[scenario]
        coarse_dir = ROOT / spec["coarse_data_dir"]
        coarse_train = load_pickle(coarse_dir / "session_train.pkl")
        coarse_test = load_pickle(coarse_dir / "session_test.pkl")
        second_pass_results = load_json(ROOT / spec["second_pass_results"])

        train_micro = split_session_dict(coarse_train, args.micro_chunk_size, prefix="micro")
        candidate_micro = build_microchunks_from_second_pass(
            coarse_test,
            second_pass_results,
            args.top_chunks,
            args.coarse_chunk_size,
            args.micro_chunk_size,
        )

        scenario_out = {}
        for model_name in models:
            model_result = MODEL_FUNCS[model_name](train_micro, candidate_micro)
            ranked = summarize_ranked(model_result["rows"])
            model_payload = {
                "model": model_name,
                "population": {
                    "candidate_micro_chunks": len(candidate_micro),
                    "candidate_total_events": int(sum(len(sample["templates"]) for sample in candidate_micro.values())),
                },
                "ranked_summary": ranked,
                "all_micro_chunks": sorted(model_result["rows"], key=lambda x: x["score"], reverse=True),
                "top_micro_chunks": sorted(model_result["rows"], key=lambda x: x["score"], reverse=True)[: args.top_k],
            }
            out_dir = output_root / f"{scenario}_{model_name}"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "results.json").write_text(
                json.dumps(model_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            scenario_out[model_name] = ranked
        summary["results"][scenario] = scenario_out

    (output_root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(output_root / "summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
