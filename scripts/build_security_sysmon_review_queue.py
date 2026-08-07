import argparse
import hashlib
import json
import math
import pickle
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a practical Security+Sysmon review queue from first- and second-pass results."
    )
    parser.add_argument("--first-pass-results", required=True)
    parser.add_argument("--second-pass-results", required=True)
    parser.add_argument("--sysmon-results")
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def dump_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def tokenized_session(sample: dict) -> str:
    tokens = []
    for template in sample["templates"]:
        digest = hashlib.md5(template.encode("utf-8")).hexdigest()[:12]
        tokens.append(f"tpl_{digest}")
    return " ".join(tokens)


def session_label(sample: dict) -> int:
    label = sample["label"]
    if isinstance(label, list):
        return int(any(x == 1 for x in label))
    return int(label == 1)


def session_event_counts(sample: dict) -> tuple[int, int, int]:
    label = sample["label"]
    if isinstance(label, list):
        attack = int(sum(label))
        total = int(len(label))
    else:
        attack = int(label)
        total = int(len(sample["templates"]))
    normal = total - attack
    return total, attack, normal


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    pos = (len(sorted_values) - 1) * (q / 100.0)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def floor_to_10m_bucket(bucket_text: str) -> str:
    dt = datetime.strptime(bucket_text, "%Y%m%dT%H%MZ").replace(tzinfo=timezone.utc)
    floored_minute = (dt.minute // 10) * 10
    return dt.replace(minute=floored_minute).strftime("%Y%m%dT%H%MZ")


def build_first_pass_session_rows(first_pass: dict) -> list[dict]:
    data_dir = ROOT / first_pass["args"]["data_dir"]
    session_train = load_pickle(data_dir / "session_train.pkl")
    session_test = load_pickle(data_dir / "session_test.pkl")
    data_desc = load_json(data_dir / "data_desc.json")
    benign_val = load_pickle(ROOT / data_desc["train_source"] / "session_test.pkl")

    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(first_pass["args"]["ngram_min"], first_pass["args"]["ngram_max"]),
        max_features=first_pass["args"]["max_features"],
    )
    x_train = vectorizer.fit_transform(tokenized_session(sample) for sample in session_train.values())
    x_test = vectorizer.transform(tokenized_session(sample) for sample in session_test.values())
    x_benign = vectorizer.transform(tokenized_session(sample) for sample in benign_val.values())

    model = IsolationForest(
        n_estimators=300,
        contamination=first_pass["args"]["contamination"],
        random_state=first_pass["args"]["random_seed"],
        n_jobs=1,
    )
    model.fit(x_train)

    benign_scores = (-model.score_samples(x_benign)).tolist()
    test_scores = (-model.score_samples(x_test)).tolist()
    threshold = percentile(sorted(benign_scores), 95.0)

    rows = []
    for (session_id, sample), score in zip(session_test.items(), test_scores):
        total, attack, normal = session_event_counts(sample)
        host, user, coarse_bucket = session_id.split("|")
        rows.append(
            {
                "session_id": session_id,
                "host": host,
                "user": user,
                "coarse_bucket": coarse_bucket,
                "score": float(score),
                "predicted_positive": int(score > threshold),
                "label": session_label(sample),
                "total_events": total,
                "attack_events": attack,
                "normal_events": normal,
            }
        )
    rows.sort(key=lambda x: (-x["predicted_positive"], -x["score"], x["session_id"]))
    return rows


def annotate_windows(
    predicted_sessions: list[dict], second_pass: dict, sysmon: dict | None
) -> list[dict]:
    windows_by_session = defaultdict(list)
    for row in second_pass.get("review_windows", []):
        windows_by_session[row["parent_session_id"]].append(dict(row))

    sysmon_exact = defaultdict(list)
    sysmon_host = defaultdict(list)
    for bucket in (sysmon or {}).get("top_sysmon_buckets", []):
        session_id = bucket["session_id"]
        host, user, minute_bucket = session_id.split("|")
        coarse_bucket = floor_to_10m_bucket(minute_bucket)
        exact_key = f"{host}|{user}|{coarse_bucket}"
        host_key = f"{host}|{coarse_bucket}"
        enriched = {
            "sysmon_session_id": session_id,
            "minute_bucket": minute_bucket,
            "score": bucket["score"],
            "pseudo_anomaly": bucket["pseudo_anomaly"],
            "events": bucket["events"],
            "top_images": bucket["top_images"],
            "top_event_ids": bucket["top_event_ids"],
            "top_users": bucket["top_users"],
        }
        sysmon_exact[exact_key].append(enriched)
        sysmon_host[host_key].append(enriched)

    queue = []
    for session in predicted_sessions:
        if not session["predicted_positive"]:
            continue
        session_id = session["session_id"]
        exact_key = session_id
        host_key = f"{session['host']}|{session['coarse_bucket']}"
        queue.append(
            {
                **session,
                "security_review_windows": windows_by_session.get(session_id, []),
                "sysmon_exact_user_minutes": sysmon_exact.get(exact_key, []),
                "sysmon_same_host_minutes": sysmon_host.get(host_key, []),
            }
        )
    return queue


def summarize_queue(queue: list[dict]) -> dict:
    sequence_total = sum(row["total_events"] for row in queue)
    sequence_attack = sum(row["attack_events"] for row in queue)
    sequence_normal = sum(row["normal_events"] for row in queue)
    review_windows = [window for row in queue for window in row["security_review_windows"]]
    review_total = sum(window["total_events"] for window in review_windows)
    review_attack = sum(window["attack_events"] for window in review_windows)
    review_normal = sum(window["normal_events"] for window in review_windows)
    return {
        "predicted_sequences": len(queue),
        "true_positive_sequences": int(sum(row["label"] for row in queue)),
        "false_positive_sequences": int(sum(1 for row in queue if row["label"] == 0)),
        "sequence_total_events": sequence_total,
        "sequence_attack_events": sequence_attack,
        "sequence_normal_events": sequence_normal,
        "review_window_count": len(review_windows),
        "review_total_events": review_total,
        "review_attack_events": review_attack,
        "review_normal_events": review_normal,
    }


def build_markdown(summary: dict, queue: list[dict], paths: dict) -> str:
    lines = []
    lines.append("# ATLAS v2 S3 Security+Sysmon Review Queue")
    lines.append("")
    lines.append(f"更新日: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## 1. 概要")
    lines.append("")
    lines.append("この出力は、`Security first pass -> Security second pass -> Sysmon補助` をそのまま読むための review queue である。")
    lines.append("まず coarse detector で上がった sequence を並べ、その各 sequence に対して Security chunk と Sysmon minute を付けている。")
    lines.append("")
    lines.append("## 2. 全体サマリ")
    lines.append("")
    lines.append(f"- predicted sequence: `{summary['predicted_sequences']}`")
    lines.append(f"- true positive sequence: `{summary['true_positive_sequences']}`")
    lines.append(f"- false positive sequence: `{summary['false_positive_sequences']}`")
    lines.append(f"- first-pass events: `{summary['sequence_total_events']}`")
    lines.append(f"- first-pass attack events: `{summary['sequence_attack_events']}`")
    lines.append(f"- first-pass normal events: `{summary['sequence_normal_events']}`")
    lines.append(f"- second-pass review windows: `{summary['review_window_count']}`")
    lines.append(f"- second-pass review events: `{summary['review_total_events']}`")
    lines.append(f"- second-pass review attack events: `{summary['review_attack_events']}`")
    lines.append(f"- second-pass review normal events: `{summary['review_normal_events']}`")
    lines.append("")
    lines.append("## 3. 読む順")
    lines.append("")
    for idx, row in enumerate(queue, start=1):
        lines.append(f"### 3.{idx} `{row['session_id']}`")
        lines.append("")
        lines.append(
            f"- first-pass score: `{row['score']:.4f}` / label=`{row['label']}` / events=`{row['total_events']}` / attack=`{row['attack_events']}` / normal=`{row['normal_events']}`"
        )
        if row["security_review_windows"]:
            top = row["security_review_windows"][0]
            lines.append(
                f"- strongest security chunk: `{top['candidate_type']}` / `{top['dominant_process'] or '-'}'` / `chunk {top['start_chunk']}-{top['end_chunk']}` / events=`{top['total_events']}` / attack=`{top['attack_events']}`"
            )
        else:
            lines.append("- strongest security chunk: `なし`")

        if row["sysmon_exact_user_minutes"]:
            seeds = ", ".join(
                f"{item['minute_bucket']}({item['score']:.3f})"
                for item in row["sysmon_exact_user_minutes"][:3]
            )
            lines.append(f"- sysmon exact-user minutes: `{seeds}`")
        else:
            lines.append("- sysmon exact-user minutes: `なし`")

        if row["sysmon_same_host_minutes"]:
            seeds = ", ".join(
                f"{item['minute_bucket']}[{item['top_images'][0][0] if item['top_images'] else '-'}]"
                for item in row["sysmon_same_host_minutes"][:3]
            )
            lines.append(f"- sysmon same-host minutes: `{seeds}`")
        else:
            lines.append("- sysmon same-host minutes: `なし`")
        lines.append("")

        if row["security_review_windows"]:
            lines.append("Security review windows:")
            for window in row["security_review_windows"][:5]:
                dominant = window["dominant_process"] or "-"
                lines.append(
                    f"- `{window['candidate_type']}` / `{dominant}` / `chunk {window['start_chunk']}-{window['end_chunk']}` / events=`{window['total_events']}` / attack=`{window['attack_events']}` / normal=`{window['normal_events']}`"
                )
            lines.append("")

        if row["sysmon_exact_user_minutes"]:
            lines.append("Sysmon exact-user minutes:")
            for item in row["sysmon_exact_user_minutes"][:5]:
                top_image = item["top_images"][0][0] if item["top_images"] else "-"
                lines.append(
                    f"- `{item['minute_bucket']}` / score=`{item['score']:.3f}` / events=`{item['events']}` / top_image=`{top_image}` / pseudo_anomaly=`{item['pseudo_anomaly']}`"
                )
            lines.append("")

        if row["sysmon_same_host_minutes"]:
            lines.append("Sysmon same-host minutes:")
            for item in row["sysmon_same_host_minutes"][:5]:
                top_image = item["top_images"][0][0] if item["top_images"] else "-"
                lines.append(
                    f"- `{item['minute_bucket']}` / score=`{item['score']:.3f}` / events=`{item['events']}` / top_image=`{top_image}` / pseudo_anomaly=`{item['pseudo_anomaly']}`"
                )
            lines.append("")

    lines.append("## 4. 参照")
    lines.append("")
    lines.append(f"- first pass: `{paths['first_pass']}`")
    lines.append(f"- second pass: `{paths['second_pass']}`")
    lines.append(f"- sysmon minute: `{paths['sysmon']}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    first_pass = load_json(ROOT / args.first_pass_results)
    second_pass = load_json(ROOT / args.second_pass_results)
    sysmon = load_json(ROOT / args.sysmon_results) if args.sysmon_results else None

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    first_pass_rows = build_first_pass_session_rows(first_pass)
    queue = annotate_windows(first_pass_rows, second_pass, sysmon)
    summary = summarize_queue(queue)

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "first_pass_results": args.first_pass_results,
            "second_pass_results": args.second_pass_results,
            "sysmon_results": args.sysmon_results,
        },
        "summary": summary,
        "review_queue": queue,
    }
    dump_json(output_dir / "results.json", payload)
    dump_text(
        output_dir / "review_queue.md",
        build_markdown(
            summary,
            queue,
            {
                "first_pass": args.first_pass_results,
                "second_pass": args.second_pass_results,
                "sysmon": args.sysmon_results or "(not used)",
            },
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
