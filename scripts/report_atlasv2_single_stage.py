import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a comparison report for single-stage ATLAS v2 detectors."
    )
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--title", default="ATLASv2 Single-Stage Detector Comparison")
    parser.add_argument(
        "--result",
        action="append",
        default=[],
        help="Result JSON path to include. Can be passed multiple times.",
    )
    parser.add_argument(
        "--deep-result",
        action="append",
        default=[],
        help="deep-loglizer result JSON path to include. Can be passed multiple times.",
    )
    parser.add_argument(
        "--local-ngram-json",
        action="append",
        default=[],
        help="Local n-gram baseline JSON path to include.",
    )
    parser.add_argument(
        "--threshold-key",
        default="p95_0",
        choices=["p95_0", "p99_0", "p99_5"],
    )
    parser.add_argument("--drop-f1-below", type=float, default=0.2)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "-"
    value = (1.0 - (numerator / denominator)) * 100.0
    return f"{value:.1f}%"


def summarize_oneclass(payload: dict, threshold_key: str) -> dict:
    eval_row = payload["benign_thresholds"][threshold_key]
    event_summary = payload.get("benign_event_summary", {}).get(threshold_key, {})
    total = payload["test_sessions"]
    predicted = eval_row["predicted_positive"]
    event_total = payload.get("test_event_total")
    predicted_events = event_summary.get("predicted_total_events")
    return {
        "method": payload["args"]["model"],
        "summary": f"{payload['args']['model']} one-class on TF-IDF sessions",
        "granularity": payload["args"].get("data_dir", "").split("_vs_")[-1],
        "representation": f"{payload['args']['ngram_min']}-{payload['args']['ngram_max']}gram TF-IDF",
        "f1": eval_row["f1"],
        "rc": eval_row["rc"],
        "pc": eval_row["pc"],
        "predicted": predicted,
        "total": total,
        "reduction": pct(predicted, total),
        "event_reduction": pct(predicted_events, event_total) if event_total and predicted_events is not None else "-",
        "comment": "",
    }


def summarize_deep(payload: dict, label: str) -> dict:
    eval_row = payload.get("eval_results", {})
    total = payload["dataset"]["test_sessions"]
    predicted = "-"
    comment = "No benign percentile session threshold emitted"
    f1 = eval_row.get("f1")
    rc = eval_row.get("rc")
    pc = eval_row.get("pc")
    custom = payload.get("custom_eval", {}).get("benign_percentile_thresholds", {})
    if custom:
        first = next(iter(custom.values()))
        p95 = first.get("p95_0")
        if p95:
            predicted = p95["predicted_positive"]
            comment = "Benign-threshold session output"
            if f1 is None:
                f1 = p95["f1"]
                rc = p95["rc"]
                pc = p95["pc"]
    if f1 is None:
        f1 = 0.0
        rc = 0.0
        pc = 0.0
    return {
        "method": label,
        "summary": f"{payload['args']['model']} via deep-loglizer",
        "granularity": payload["dataset"]["data_desc"]["test_desc"]["session_mode"] + "+" + str(payload["dataset"]["data_desc"]["test_desc"]["time_window_minutes"]) + "m",
        "representation": payload["args"]["feature_type"],
        "f1": f1,
        "rc": rc,
        "pc": pc,
        "predicted": predicted,
        "total": total,
        "reduction": pct(predicted, total) if isinstance(predicted, int) else "-",
        "event_reduction": "-",
        "comment": comment,
    }


def summarize_local_ngram(payload: dict) -> dict:
    summary = payload["summary"]
    return {
        "method": "local_ngram",
        "summary": "Local next-event n-gram baseline",
        "granularity": payload["data_dir"].split("_vs_")[-1],
        "representation": f"w{payload['window_size']} top{payload['topk']}",
        "f1": summary["precision_proxy"],
        "rc": summary["recall_proxy"],
        "pc": summary["precision_proxy"],
        "predicted": summary["flagged_windows"],
        "total": summary["total_windows"],
        "reduction": pct(summary["flagged_windows"], summary["total_windows"]),
        "event_reduction": "-",
        "comment": "Proxy metrics on flagged windows, not session-level F1",
    }


def recommendation(row: dict, drop_f1_below: float) -> str:
    predicted_ratio = None
    if isinstance(row["predicted"], int) and row["total"]:
        predicted_ratio = row["predicted"] / row["total"]
    if isinstance(row["predicted"], int) and row["predicted"] == 0:
        return "Drop: 0 positives"
    if predicted_ratio is not None and predicted_ratio >= 0.8:
        return "Drop: too many positives"
    if row["f1"] < drop_f1_below:
        return f"Drop: F1<{drop_f1_below}"
    return "Keep"


def main() -> int:
    args = parse_args()
    rows = []

    for result_path in args.result:
        payload = load_json(ROOT / result_path)
        data_dir = ROOT / payload["args"]["data_dir"]
        desc = load_json(data_dir / "data_desc.json")
        payload["test_event_total"] = desc["test_desc"]["events"]
        rows.append(summarize_oneclass(payload, args.threshold_key))

    for result_path in args.deep_result:
        payload = load_json(ROOT / result_path)
        label = Path(result_path).parent.name
        rows.append(summarize_deep(payload, label))

    for result_path in args.local_ngram_json:
        payload = load_json(ROOT / result_path)
        rows.append(summarize_local_ngram(payload))

    rows.sort(key=lambda x: (x["f1"], x["rc"], x["pc"]), reverse=True)

    lines = [f"# {args.title}", "", "| 手法 | 手法の概要 | 入力粒度 | 入力表現 | F1 | Recall | Precision | predicted/total | 削減率 | event削減率 | 判定 | コメント |", "| --- | --- | --- | --- | ---: | ---: | ---: | --- | ---: | ---: | --- | --- |"]
    for row in rows:
        lines.append(
            "| {method} | {summary} | {granularity} | {representation} | {f1:.4f} | {rc:.4f} | {pc:.4f} | {predicted}/{total} | {reduction} | {event_reduction} | {decision} | {comment} |".format(
                **row,
                decision=recommendation(row, args.drop_f1_below),
            )
        )

    output_path = ROOT / args.output_md
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
