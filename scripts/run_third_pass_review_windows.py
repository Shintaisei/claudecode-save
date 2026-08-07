import argparse
import json
import math
import pickle
from datetime import datetime, timezone
from pathlib import Path

from run_third_pass_microchunks import (
    build_markdown,
    load_json,
    load_pickle,
    run_lof,
    run_ocsvm,
    run_rarity,
    split_session_dict,
)


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run third-pass reranking on review windows from security_review_queue results."
    )
    parser.add_argument("--coarse-data-dir", required=True)
    parser.add_argument("--review-queue-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--top-windows", type=int, default=10)
    parser.add_argument("--coarse-chunk-size", type=int, default=100)
    parser.add_argument("--micro-chunk-size", type=int, default=10)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=20000)
    parser.add_argument("--lof-neighbors", type=int, default=20)
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--ocsvm-nu", type=float, default=0.1)
    parser.add_argument("--ocsvm-gamma", default="scale")
    parser.add_argument("--top-k", type=int, default=10)
    return parser.parse_args()


def build_microchunks_from_review_queue(
    session_test: dict,
    review_results: dict,
    top_windows: int,
    coarse_chunk_size: int,
    micro_chunk_size: int,
) -> dict:
    review_windows = []
    for session in review_results["review_queue"]:
        review_windows.extend(session["security_review_windows"])
    selected = review_windows[:top_windows]

    microchunks = {}
    for window_rank, row in enumerate(selected, start=1):
        parent_session_id = row["parent_session_id"]
        sample = session_test[parent_session_id]
        start_chunk = int(row["start_chunk"])
        end_chunk = int(row["end_chunk"])
        for coarse_chunk_index in range(start_chunk, end_chunk + 1):
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
                    "coarse_chunk_rank": window_rank,
                    "coarse_chunk_index": coarse_chunk_index,
                    "micro_chunk_index": micro_idx,
                    "templates": templates[ms:me],
                    "label": labels[ms:me],
                }
    return microchunks


def main() -> int:
    args = parse_args()
    coarse_data_dir = ROOT / args.coarse_data_dir
    review_results = load_json(ROOT / args.review_queue_results)
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    coarse_desc = load_json(coarse_data_dir / "data_desc.json")
    coarse_train = load_pickle(coarse_data_dir / "session_train.pkl")
    coarse_test = load_pickle(coarse_data_dir / "session_test.pkl")
    benign_val = load_pickle(ROOT / coarse_desc["train_source"] / "session_test.pkl")

    train_micro = split_session_dict(coarse_train, args.micro_chunk_size, prefix="micro")
    benign_val_micro = split_session_dict(benign_val, args.micro_chunk_size, prefix="micro")
    del benign_val_micro

    candidate_micro = build_microchunks_from_review_queue(
        coarse_test,
        review_results,
        args.top_windows,
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
        "inputs": vars(args),
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
    (output_dir / "summary.md").write_text(build_markdown(payload), encoding="utf-8")
    print(output_dir / "summary.md")
    print(output_dir / "results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
