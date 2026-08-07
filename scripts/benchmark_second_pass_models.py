import argparse
import hashlib
import json
import math
import pickle
import subprocess
import sys
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer


ROOT = Path(__file__).resolve().parents[1]


SCENARIOS = {
    "s3": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_s3_cu10",
        "first_pass_results": "analysis_data/model_runs/iforest_benign1to4_s3_cu10_g1_2_c010/results.json",
    },
    "m4": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_m4_cu10",
        "first_pass_results": "analysis_data/model_runs/iforest_benign1to4_m4_cu10_g1_2_c010/results.json",
    },
    "m6": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_m6_cu10",
        "first_pass_results": "analysis_data/model_runs/iforest_benign1to4_m6_cu10_g1_2_c010/results.json",
    },
    "s4": {
        "coarse_data_dir": "analysis_data/atlasv2_for_deep-loglizer/exp_benign1to4_vs_s4_cu10",
        "first_pass_results": "analysis_data/model_runs/iforest_benign1to4_s4_cu10_g1_2_c010/results.json",
    },
}


MODEL_SPECS = {
    "iforest": {
        "script": "scripts/run_second_pass_iforest.py",
        "args": ["--model", "iforest", "--contamination", "0.10"],
    },
    "lof": {
        "script": "scripts/run_second_pass_iforest.py",
        "args": ["--model", "lof", "--contamination", "0.10", "--neighbors", "20"],
    },
    "ocsvm": {
        "script": "scripts/run_second_pass_iforest.py",
        "args": ["--model", "ocsvm", "--nu", "0.10", "--kernel", "rbf", "--gamma", "scale"],
    },
    "sgdocsvm": {
        "script": "scripts/run_second_pass_iforest.py",
        "args": ["--model", "sgdocsvm", "--sgd-nu", "0.10"],
    },
    "knn": {
        "script": "scripts/run_second_pass_knn.py",
        "args": ["--neighbors", "5"],
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark pure model-based second-pass chunk ranking across ATLAS scenarios."
    )
    parser.add_argument(
        "--scenarios",
        default="s3,m4,m6,s4",
        help="Comma-separated scenarios to run.",
    )
    parser.add_argument(
        "--models",
        default="iforest,lof,ocsvm,sgdocsvm,knn",
        help="Comma-separated model names to run.",
    )
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--top-k", type=int, default=30)
    parser.add_argument("--threshold-key", default="p95_0")
    parser.add_argument(
        "--output-root",
        default="analysis_data/model_runs/secondpass_model_benchmark_benign1to4",
    )
    parser.add_argument(
        "--summary-path",
        default="analysis_data/model_runs/secondpass_model_benchmark_benign1to4/summary.json",
    )
    return parser.parse_args()


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


def score_sessions(model, vectorizer, session_dict: dict) -> list[dict]:
    session_ids = list(session_dict.keys())
    session_texts = [tokenized_session(session_dict[sid]) for sid in session_ids]
    scores = (-model.score_samples(vectorizer.transform(session_texts))).tolist()
    rows = []
    for sid, score in zip(session_ids, scores):
        sample = session_dict[sid]
        total_events = len(sample["templates"])
        attack_events = event_anomaly_count(sample)
        rows.append(
            {
                "session_id": sid,
                "score": float(score),
                "true_session_anomaly": session_label(sample),
                "total_events": total_events,
                "attack_events": attack_events,
                "normal_events": total_events - attack_events,
            }
        )
    return rows


def build_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=20000,
    )


def ensure_enriched_first_pass(
    scenario: str,
    coarse_data_dir: str,
    first_pass_results_path: str,
    output_root: Path,
) -> Path:
    coarse_dir = ROOT / coarse_data_dir
    first_pass_path = ROOT / first_pass_results_path
    payload = load_json(first_pass_path)
    if "predicted_coarse_sessions" in payload:
        return first_pass_path

    coarse_desc = load_json(coarse_dir / "data_desc.json")
    coarse_train = load_pickle(coarse_dir / "session_train.pkl")
    coarse_test = load_pickle(coarse_dir / "session_test.pkl")

    vectorizer = build_vectorizer()
    x_train = vectorizer.fit_transform(
        tokenized_session(sample) for sample in coarse_train.values()
    )
    model = IsolationForest(
        n_estimators=300,
        contamination=0.10,
        random_state=42,
        n_jobs=1,
    )
    model.fit(x_train)
    coarse_rows = score_sessions(model, vectorizer, coarse_test)

    threshold = payload["benign_thresholds"]["p95_0"]["threshold"]
    predicted_rows = []
    for row in coarse_rows:
        row["pred"] = int(row["score"] > threshold)
        if row["pred"] == 1:
            predicted_rows.append(row)

    enriched = dict(payload)
    enriched["predicted_coarse_sessions"] = predicted_rows

    enriched_dir = output_root / "_enriched_firstpass"
    enriched_dir.mkdir(parents=True, exist_ok=True)
    enriched_path = enriched_dir / f"{scenario}.json"
    enriched_path.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
    return enriched_path


def run_command(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_topk(top_chunks: list[dict], k: int) -> dict:
    subset = top_chunks[:k]
    attack_chunks = [row for row in subset if row["attack_events"] > 0]
    fp_chunks = [row for row in subset if row["attack_events"] == 0]
    return {
        "chunks": len(subset),
        "total_events": int(sum(row["total_events"] for row in subset)),
        "attack_events": int(sum(row["attack_events"] for row in subset)),
        "normal_events": int(sum(row["normal_events"] for row in subset)),
        "attack_chunks": len(attack_chunks),
        "fp_chunks": len(fp_chunks),
        "attack_hit": bool(attack_chunks),
        "fp_hit": bool(fp_chunks),
    }


def evaluate_result(payload: dict) -> dict:
    top_chunks = payload.get("top_chunks", [])
    ranked_summary = payload.get("ranked_summary", {})
    top10 = summarize_topk(top_chunks, min(10, len(top_chunks)))
    top30 = summarize_topk(top_chunks, min(30, len(top_chunks)))
    return {
        "chunk_eval": payload.get("chunk_eval", {}),
        "chunk_summary": payload.get("chunk_summary", {}),
        "predicted_coarse_sessions": len(payload.get("predicted_coarse_sessions", [])),
        "first_attack_rank": ranked_summary.get("first_attack_rank"),
        "top10": top10,
        "top30": top30,
    }


def main() -> int:
    args = parse_args()
    scenarios = [item.strip().lower() for item in args.scenarios.split(",") if item.strip()]
    models = [item.strip().lower() for item in args.models.split(",") if item.strip()]

    output_root = ROOT / args.output_root
    output_root.mkdir(parents=True, exist_ok=True)

    summary_path = ROOT / args.summary_path
    if summary_path.exists():
        summary = load_json(summary_path)
    else:
        summary = {"args": vars(args), "results": {}}
    summary["args"] = vars(args)

    for scenario in scenarios:
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario}")
        spec = SCENARIOS[scenario]
        enriched_first_pass = ensure_enriched_first_pass(
            scenario,
            spec["coarse_data_dir"],
            spec["first_pass_results"],
            output_root,
        )
        summary["results"][scenario] = {}
        for model_name in models:
            if model_name not in MODEL_SPECS:
                raise ValueError(f"Unknown model: {model_name}")
            model_spec = MODEL_SPECS[model_name]
            out_dir = output_root / f"{scenario}_{model_name}"
            command = [
                sys.executable,
                model_spec["script"],
                "--coarse-data-dir",
                spec["coarse_data_dir"],
                "--first-pass-results",
                str(enriched_first_pass.relative_to(ROOT)),
                "--output-dir",
                str(out_dir.relative_to(ROOT)),
                "--chunk-size",
                str(args.chunk_size),
                "--top-k",
                str(args.top_k),
                "--threshold-key",
                args.threshold_key,
            ] + model_spec["args"]
            run_command(command)
            payload = load_json(out_dir / "results.json")
            summary["results"][scenario][model_name] = evaluate_result(payload)

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
