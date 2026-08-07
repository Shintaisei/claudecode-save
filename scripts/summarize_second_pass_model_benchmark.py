import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT / "analysis_data/model_runs/secondpass_model_benchmark_benign1to4"
SUMMARY_PATH = OUTPUT_ROOT / "summary_all.json"
MODELS = ["iforest", "lof", "ocsvm", "sgdocsvm", "knn"]
SCENARIOS = ["s3", "m4", "m6", "s4"]


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
    return {
        "chunk_eval": payload.get("chunk_eval", {}),
        "chunk_summary": payload.get("chunk_summary", {}),
        "predicted_coarse_sessions": len(payload.get("predicted_coarse_sessions", [])),
        "first_attack_rank": ranked_summary.get("first_attack_rank"),
        "top10": summarize_topk(top_chunks, min(10, len(top_chunks))),
        "top30": summarize_topk(top_chunks, min(30, len(top_chunks))),
    }


def main() -> int:
    summary = {"results": {}}
    for scenario in SCENARIOS:
        scenario_payload = {}
        for model in MODELS:
            result_path = OUTPUT_ROOT / f"{scenario}_{model}" / "results.json"
            if result_path.exists():
                scenario_payload[model] = evaluate_result(load_json(result_path))
        summary["results"][scenario] = scenario_payload
    SUMMARY_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(SUMMARY_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
