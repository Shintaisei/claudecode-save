import argparse
import json
import logging
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEEPLOGLIZER_ROOT = ROOT / "external" / "deep-loglizer"
if str(DEEPLOGLIZER_ROOT) not in sys.path:
    sys.path.insert(0, str(DEEPLOGLIZER_ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a deep-loglizer sequence model on ATLAS v2 session data."
    )
    parser.add_argument(
        "--data-dir",
        required=True,
        help="Dataset directory containing session_train.pkl, session_test.pkl, and data_desc.json",
    )
    parser.add_argument(
        "--model",
        default="lstm",
        choices=["lstm", "transformer", "ae"],
        help="Sequence model to train",
    )
    parser.add_argument(
        "--feature-type",
        default="sequentials",
        choices=["sequentials", "semantics"],
        help="Input representation used by deep-loglizer",
    )
    parser.add_argument(
        "--label-type",
        default="next_log",
        choices=["next_log", "anomaly"],
        help="Training objective",
    )
    parser.add_argument("--window-size", type=int, default=10)
    parser.add_argument("--stride", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--test-batch-size", type=int, default=2048)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--topk", type=int, default=10)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--gpu", type=int, default=-1, help="Use -1 for CPU")
    parser.add_argument("--hidden-size", type=int, default=128)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--embedding-dim", type=int, default=32)
    parser.add_argument("--num-directions", type=int, default=2)
    parser.add_argument("--nhead", type=int, default=2)
    parser.add_argument("--use-attention", action="store_true")
    parser.add_argument("--use-tfidf", action="store_true")
    parser.add_argument("--max-token-len", type=int, default=50)
    parser.add_argument("--min-token-count", type=int, default=1)
    parser.add_argument(
        "--ae-score-stat",
        default="max",
        choices=["mean", "max", "p95"],
        help="Session score statistic for autoencoder outputs",
    )
    parser.add_argument(
        "--eval-only",
        action="store_true",
        help="Skip training and evaluate an existing checkpoint in output-dir/artifacts",
    )
    parser.add_argument(
        "--output-dir",
        help="Optional explicit output directory. Defaults under analysis_data/model_runs/",
    )
    return parser.parse_args()


def default_output_dir(args: argparse.Namespace) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return (
        ROOT
        / "analysis_data"
        / "model_runs"
        / f"{Path(args.data_dir).name}_{args.model}_{args.feature_type}_{stamp}"
    )


def build_output_dir(args: argparse.Namespace) -> Path:
    if args.output_dir:
        return Path(args.output_dir)
    return default_output_dir(args)


def configure_logging(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / "train.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
        force=True,
    )


def load_model_class(name: str):
    try:
        if name == "lstm":
            from deeploglizer.models import LSTM

            return LSTM
        if name == "ae":
            from deeploglizer.models import AutoEncoder

            return AutoEncoder
        from deeploglizer.models import Transformer

        return Transformer
    except OSError as exc:
        raise RuntimeError(
            "PyTorch could not be loaded on this machine. "
            "The current environment is failing to initialize torch DLLs."
        ) from exc


def build_model_kwargs(args: argparse.Namespace, model_save_path: Path) -> dict:
    common = {
        "feature_type": args.feature_type,
        "label_type": args.label_type,
        "eval_type": "session",
        "topk": args.topk,
        "use_tfidf": args.use_tfidf,
        "embedding_dim": args.embedding_dim,
        "gpu": args.gpu,
        "model_save_path": str(model_save_path),
    }
    if args.model == "lstm":
        common.update(
            {
                "hidden_size": args.hidden_size,
                "num_layers": args.num_layers,
                "num_directions": args.num_directions,
                "window_size": args.window_size,
                "use_attention": args.use_attention,
            }
        )
    elif args.model == "ae":
        common.update(
            {
                "hidden_size": args.hidden_size,
                "num_layers": args.num_layers,
                "num_directions": args.num_directions,
                "label_type": "none",
            }
        )
    else:
        common.update(
            {
                "hidden_size": args.hidden_size,
                "num_layers": args.num_layers,
                "nhead": args.nhead,
            }
        )
    return common


def summarize_dataset(data_dir: Path, session_train: dict, session_test: dict) -> dict:
    desc_path = data_dir / "data_desc.json"
    source_desc = {}
    if desc_path.exists():
        source_desc = json.loads(desc_path.read_text(encoding="utf-8"))
    return {
        "data_dir": str(data_dir),
        "train_sessions": len(session_train),
        "test_sessions": len(session_test),
        "data_desc": source_desc,
    }


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def load_sessions_utf8(data_dir: Path) -> tuple[dict, dict]:
    desc_path = data_dir / "data_desc.json"
    if desc_path.exists():
        logging.info("Dataset desc: %s", desc_path)
        logging.info(desc_path.read_text(encoding="utf-8"))
    session_train = load_pickle(data_dir / "session_train.pkl")
    session_test = load_pickle(data_dir / "session_test.pkl")
    logging.info("# train sessions %s", len(session_train))
    logging.info("# test sessions %s", len(session_test))
    return session_train, session_test


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    if q <= 0:
        return sorted_values[0]
    if q >= 100:
        return sorted_values[-1]
    pos = (len(sorted_values) - 1) * (q / 100.0)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def summarize_window_scores(values: list[float], stat: str) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    if stat == "mean":
        return float(sum(sorted_values) / len(sorted_values))
    if stat == "p95":
        return float(percentile(sorted_values, 95.0))
    return float(sorted_values[-1])


def score_next_log_sessions(model, loader, topk: int, tensor2flatten_arr):
    import pandas as pd
    import torch

    model.eval()
    store_dict = {"session_idx": [], "window_anomalies": [], "window_labels": []}
    for k in range(1, topk + 1):
        store_dict[f"window_pred_anomaly_{k}"] = []

    with torch.no_grad():
        for batch_input in loader:
            batch_device = {k: v.to(model.device) for k, v in batch_input.items()}
            return_dict = model.forward(batch_device)
            y_pred = return_dict["y_pred"]
            _, y_pred_topk = torch.topk(y_pred, topk)

            store_dict["session_idx"].extend(
                tensor2flatten_arr(batch_input["session_idx"])
            )
            store_dict["window_anomalies"].extend(
                tensor2flatten_arr(batch_input["window_anomalies"])
            )
            store_dict["window_labels"].extend(
                tensor2flatten_arr(batch_input["window_labels"])
            )

            topkdf = pd.DataFrame(y_pred_topk.data.cpu().numpy().tolist())
            hit_df = pd.DataFrame()
            for col in sorted(topkdf.columns):
                rank = col + 1
                hit = (topkdf[col] == store_dict["window_labels"][-len(topkdf):]).astype(int)
                hit_df[rank] = hit
                if col == 0:
                    acc_sum = 2 ** rank * hit
                else:
                    acc_sum += 2 ** rank * hit
            acc_sum[acc_sum == 0] = 2 ** (1 + len(topkdf.columns))
            hit_df["acc_num"] = acc_sum

            for col in sorted(topkdf.columns):
                rank = col + 1
                check_num = 2 ** rank
                pred = (~(hit_df["acc_num"] <= check_num)).astype(int)
                store_dict[f"window_pred_anomaly_{rank}"].extend(pred.tolist())

    store_df = pd.DataFrame(store_dict)
    session_rows = []
    for session_idx, session_df in store_df.groupby("session_idx", as_index=False):
        row = {
            "session_idx": int(session_idx),
            "window_total": int(len(session_df)),
            "true_anomaly": int(session_df["window_anomalies"].sum() > 0),
            "anomaly_windows": int(session_df["window_anomalies"].sum()),
        }
        for rank in range(1, topk + 1):
            miss_count = int(session_df[f"window_pred_anomaly_{rank}"].sum())
            row[f"miss_count_top{rank}"] = miss_count
            row[f"miss_ratio_top{rank}"] = miss_count / max(1, len(session_df))
        session_rows.append(row)
    return pd.DataFrame(session_rows)


def evaluate_session_scores(session_scores, topk: int):
    from sklearn.metrics import f1_score, precision_score, recall_score

    payload = {"oracle": {}, "benign_percentiles": {}}
    y_true = session_scores["true_anomaly"].astype(int)

    for rank in range(1, topk + 1):
        score_col = f"miss_ratio_top{rank}"
        values = sorted(session_scores[score_col].astype(float).tolist())
        best = None
        for threshold in values:
            y_pred = (session_scores[score_col] > threshold).astype(int)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            rc = recall_score(y_true, y_pred, zero_division=0)
            pc = precision_score(y_true, y_pred, zero_division=0)
            candidate = {
                "threshold": float(threshold),
                "f1": float(f1),
                "rc": float(rc),
                "pc": float(pc),
                "predicted_positive": int(y_pred.sum()),
            }
            if best is None or candidate["f1"] > best["f1"]:
                best = candidate
        payload["oracle"][f"top{rank}"] = best
    return payload


def evaluate_with_benign_thresholds(benign_scores, test_scores, topk: int):
    from sklearn.metrics import f1_score, precision_score, recall_score

    payload = {}
    for rank in range(1, topk + 1):
        score_col = f"miss_ratio_top{rank}"
        benign_values = sorted(benign_scores[score_col].astype(float).tolist())
        rank_payload = {}
        for q in (95.0, 99.0, 99.5):
            threshold = percentile(benign_values, q)
            y_true = test_scores["true_anomaly"].astype(int)
            y_pred = (test_scores[score_col] > threshold).astype(int)
            rank_payload[f"p{str(q).replace('.', '_')}"] = {
                "threshold": float(threshold),
                "f1": float(f1_score(y_true, y_pred, zero_division=0)),
                "rc": float(recall_score(y_true, y_pred, zero_division=0)),
                "pc": float(precision_score(y_true, y_pred, zero_division=0)),
                "predicted_positive": int(y_pred.sum()),
            }
        payload[f"top{rank}"] = rank_payload
    return payload


def score_autoencoder_sessions(model, loader, tensor2flatten_arr, stat: str):
    import pandas as pd
    import torch

    model.eval()
    store_dict = {"session_idx": [], "window_anomalies": [], "window_score": []}
    with torch.no_grad():
        for batch_input in loader:
            batch_device = {k: v.to(model.device) for k, v in batch_input.items()}
            return_dict = model.forward(batch_device)
            y_pred = return_dict["y_pred"]
            store_dict["session_idx"].extend(
                tensor2flatten_arr(batch_input["session_idx"])
            )
            store_dict["window_anomalies"].extend(
                tensor2flatten_arr(batch_input["window_anomalies"])
            )
            store_dict["window_score"].extend(tensor2flatten_arr(y_pred))

    store_df = pd.DataFrame(store_dict)
    session_rows = []
    for session_idx, session_df in store_df.groupby("session_idx", as_index=False):
        scores = session_df["window_score"].astype(float).tolist()
        row = {
            "session_idx": int(session_idx),
            "window_total": int(len(session_df)),
            "true_anomaly": int(session_df["window_anomalies"].sum() > 0),
            "anomaly_windows": int(session_df["window_anomalies"].sum()),
            "score_mean": float(sum(scores) / max(1, len(scores))),
            "score_max": float(max(scores)),
            "score_p95": float(percentile(sorted(scores), 95.0)),
            "score_selected": summarize_window_scores(scores, stat),
        }
        session_rows.append(row)
    return pd.DataFrame(session_rows)


def evaluate_scalar_scores(session_scores, score_col: str):
    from sklearn.metrics import f1_score, precision_score, recall_score

    y_true = session_scores["true_anomaly"].astype(int)
    values = sorted(session_scores[score_col].astype(float).tolist())
    best = None
    for threshold in values:
        y_pred = (session_scores[score_col] > threshold).astype(int)
        candidate = {
            "threshold": float(threshold),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "rc": float(recall_score(y_true, y_pred, zero_division=0)),
            "pc": float(precision_score(y_true, y_pred, zero_division=0)),
            "predicted_positive": int(y_pred.sum()),
        }
        if best is None or candidate["f1"] > best["f1"]:
            best = candidate
    return best


def evaluate_scalar_with_benign_thresholds(benign_scores, test_scores, score_col: str):
    from sklearn.metrics import f1_score, precision_score, recall_score

    benign_values = sorted(benign_scores[score_col].astype(float).tolist())
    y_true = test_scores["true_anomaly"].astype(int)
    payload = {}
    for q in (95.0, 99.0, 99.5):
        threshold = percentile(benign_values, q)
        y_pred = (test_scores[score_col] > threshold).astype(int)
        payload[f"p{str(q).replace('.', '_')}"] = {
            "threshold": float(threshold),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "rc": float(recall_score(y_true, y_pred, zero_division=0)),
            "pc": float(precision_score(y_true, y_pred, zero_division=0)),
            "predicted_positive": int(y_pred.sum()),
        }
    return payload


def mean_autoencoder_window_score(model, loader, tensor2flatten_arr) -> float:
    import torch

    model.eval()
    scores = []
    with torch.no_grad():
        for batch_input in loader:
            batch_device = {k: v.to(model.device) for k, v in batch_input.items()}
            return_dict = model.forward(batch_device)
            scores.extend(tensor2flatten_arr(return_dict["y_pred"]).tolist())
    if not scores:
        return 0.0
    return float(sum(scores) / len(scores))


def train_autoencoder(
    model,
    train_loader,
    validation_loader,
    tensor2flatten_arr,
    epochs: int,
    learning_rate: float,
    patience: int,
):
    import torch

    model.to(model.device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    best_score = None
    best_epoch = 0
    worse_count = 0
    for epoch in range(1, epochs + 1):
        epoch_start = time.time()
        model.train()
        batch_cnt = 0
        epoch_loss = 0.0
        for batch_input in train_loader:
            batch_device = {k: v.to(model.device) for k, v in batch_input.items()}
            loss = model.forward(batch_device)["loss"]
            loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            epoch_loss += float(loss.item())
            batch_cnt += 1
        epoch_loss /= max(1, batch_cnt)
        model.time_tracker["train"] = time.time() - epoch_start
        logging.info(
            "Epoch %s/%s, training loss: %.5f [%.2fs]",
            epoch,
            epochs,
            epoch_loss,
            model.time_tracker["train"],
        )

        val_start = time.time()
        val_score = mean_autoencoder_window_score(
            model, validation_loader, tensor2flatten_arr
        )
        model.time_tracker["test"] = time.time() - val_start
        logging.info("Validation reconstruction mean: %.6f", val_score)
        if best_score is None or val_score < best_score:
            best_score = val_score
            best_epoch = epoch
            model.save_model()
            worse_count = 0
        else:
            worse_count += 1
            if worse_count >= patience:
                logging.info("Early stop at epoch: %s", epoch)
                break

    model.load_model(model.model_save_file)
    return {"val_reconstruction_mean": best_score, "converge": best_epoch}


def load_benign_validation_sessions(dataset_summary: dict) -> dict | None:
    train_source = dataset_summary.get("data_desc", {}).get("train_source")
    if not train_source:
        return None
    source_dir = ROOT / train_source
    val_path = source_dir / "session_test.pkl"
    if not val_path.exists():
        return None
    return load_pickle(val_path)


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    output_dir = build_output_dir(args)
    configure_logging(output_dir)

    logging.info("Using dataset: %s", data_dir)
    logging.info("Results will be saved under: %s", output_dir)

    try:
        import torch
        from torch.utils.data import DataLoader
    except OSError as exc:
        raise RuntimeError(
            "PyTorch import failed while preparing training. "
            "The local torch installation is currently broken."
        ) from exc

    from deeploglizer.common.dataloader import log_dataset
    from deeploglizer.common.preprocess import FeatureExtractor
    from deeploglizer.common.utils import seed_everything, tensor2flatten_arr

    seed_everything(args.random_seed)

    session_train_raw, session_test_raw = load_sessions_utf8(data_dir)
    session_train = session_train_raw
    session_test = session_test_raw
    dataset_summary = summarize_dataset(data_dir, session_train, session_test)
    dump_json(output_dir / "dataset_summary.json", dataset_summary)

    extractor = FeatureExtractor(
        feature_type=args.feature_type,
        label_type=args.label_type,
        window_size=args.window_size,
        stride=args.stride,
        max_token_len=args.max_token_len,
        min_token_count=args.min_token_count,
        use_tfidf=args.use_tfidf,
    )
    session_train = extractor.fit_transform(session_train)
    session_test = extractor.transform(session_test, datatype="test")
    benign_val_raw = load_benign_validation_sessions(dataset_summary)
    benign_val = None
    if benign_val_raw:
        benign_val = extractor.transform(benign_val_raw, datatype="test")

    train_dataset = log_dataset(session_train, feature_type=args.feature_type)
    test_dataset = log_dataset(session_test, feature_type=args.feature_type)
    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        pin_memory=True,
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=args.test_batch_size,
        shuffle=False,
        pin_memory=True,
    )
    benign_val_loader = None
    if benign_val is not None:
        benign_val_dataset = log_dataset(benign_val, feature_type=args.feature_type)
        benign_val_loader = DataLoader(
            benign_val_dataset,
            batch_size=args.test_batch_size,
            shuffle=False,
            pin_memory=True,
        )

    model_class = load_model_class(args.model)
    model_save_path = output_dir / "artifacts"
    model = model_class(
        meta_data=extractor.meta_data,
        patience=args.patience,
        **build_model_kwargs(args, model_save_path),
    )

    if args.eval_only:
        model.load_model(str(model_save_path / "model.ckpt"))
        if args.model == "ae":
            eval_results = {
                "val_reconstruction_mean": mean_autoencoder_window_score(
                    model,
                    benign_val_loader or test_loader,
                    tensor2flatten_arr,
                )
            }
        else:
            eval_results = model.evaluate(test_loader)
    else:
        if args.model == "ae":
            eval_results = train_autoencoder(
                model=model,
                train_loader=train_loader,
                validation_loader=benign_val_loader or test_loader,
                tensor2flatten_arr=tensor2flatten_arr,
                epochs=args.epochs,
                learning_rate=args.learning_rate,
                patience=args.patience,
            )
        else:
            eval_results = model.fit(
                train_loader,
                test_loader=test_loader,
                epoches=args.epochs,
                learning_rate=args.learning_rate,
            )

    custom_eval = None
    if args.model == "ae":
        test_scores = score_autoencoder_sessions(
            model, test_loader, tensor2flatten_arr, args.ae_score_stat
        )
        custom_eval = {
            "oracle_selected_score": evaluate_scalar_scores(
                test_scores, "score_selected"
            )
        }
        if benign_val_loader is not None:
            benign_scores = score_autoencoder_sessions(
                model, benign_val_loader, tensor2flatten_arr, args.ae_score_stat
            )
            custom_eval["benign_percentile_thresholds"] = (
                evaluate_scalar_with_benign_thresholds(
                    benign_scores, test_scores, "score_selected"
                )
            )
            benign_scores.to_csv(output_dir / "benign_val_session_scores.csv", index=False)
        test_scores.to_csv(output_dir / "test_session_scores.csv", index=False)
    elif args.label_type == "next_log":
        test_scores = score_next_log_sessions(
            model, test_loader, args.topk, tensor2flatten_arr
        )
        custom_eval = {
            "oracle_miss_ratio": evaluate_session_scores(test_scores, args.topk),
        }
        if benign_val_loader is not None:
            benign_scores = score_next_log_sessions(
                model, benign_val_loader, args.topk, tensor2flatten_arr
            )
            custom_eval["benign_percentile_thresholds"] = evaluate_with_benign_thresholds(
                benign_scores, test_scores, args.topk
            )
            test_scores.to_csv(output_dir / "test_session_scores.csv", index=False)
            benign_scores.to_csv(output_dir / "benign_val_session_scores.csv", index=False)
        else:
            test_scores.to_csv(output_dir / "test_session_scores.csv", index=False)

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "dataset": dataset_summary,
        "meta_data": extractor.meta_data,
        "eval_results": eval_results,
        "custom_eval": custom_eval,
        "time_tracker": getattr(model, "time_tracker", {}),
        "torch_version": getattr(torch, "__version__", "unknown"),
    }
    dump_json(output_dir / "results.json", payload)
    logging.info("Finished training. Best results: %s", eval_results)
    logging.info("Results json: %s", output_dir / "results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
