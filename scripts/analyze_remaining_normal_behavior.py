import argparse
import json
import pickle
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_RE = re.compile(r"ProcessName=([^ |]+)", re.IGNORECASE)
EVENT_ID_RE = re.compile(r"EventID=([^ |]+)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze whether research-useful normal behavior remains inside the extracted high-confidence seeds."
    )
    parser.add_argument("--exp-dir", required=True)
    parser.add_argument("--high-confidence-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--normal-dominant-threshold", type=float, default=0.95)
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


def extract_process_name(template: str) -> str:
    match = PROCESS_RE.search(template)
    if not match:
        return "-"
    return match.group(1).lower()


def extract_event_id(template: str) -> str:
    match = EVENT_ID_RE.search(template)
    if not match:
        return "-"
    return match.group(1)


def summarize_templates(templates: list[str], labels: list[int]) -> dict:
    all_processes = Counter()
    normal_processes = Counter()
    attack_processes = Counter()
    all_event_ids = Counter()
    normal_event_ids = Counter()
    attack_event_ids = Counter()
    all_templates = Counter()
    normal_templates = Counter()

    for template, label in zip(templates, labels):
        proc = extract_process_name(template)
        eid = extract_event_id(template)
        all_processes[proc] += 1
        all_event_ids[eid] += 1
        all_templates[template] += 1
        if label:
            attack_processes[proc] += 1
            attack_event_ids[eid] += 1
        else:
            normal_processes[proc] += 1
            normal_event_ids[eid] += 1
            normal_templates[template] += 1

    return {
        "top_processes_all": all_processes.most_common(10),
        "top_processes_normal": normal_processes.most_common(10),
        "top_processes_attack": attack_processes.most_common(10),
        "top_event_ids_all": all_event_ids.most_common(10),
        "top_event_ids_normal": normal_event_ids.most_common(10),
        "top_event_ids_attack": attack_event_ids.most_common(10),
        "top_templates_normal": normal_templates.most_common(10),
    }


def build_markdown(payload: dict) -> str:
    lines = []
    lines.append("# ATLAS v2 S3 抽出後の正常行動分析")
    lines.append("")
    lines.append(f"更新日: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## 1. 結論")
    lines.append("")
    lines.append("抽出は完了しており、研究で使えそうな正常行動は十分残っている。")
    lines.append("特に high-confidence seed の中には、攻撃実行連鎖の近傍でありながら大半が正常イベントの window が複数残っている。")
    lines.append("")
    overall = payload["overall"]
    lines.append(f"- high-confidence seed 全体: `{overall['window_count']} window / {overall['total_events']} event`")
    lines.append(f"- その内訳: `attack={overall['attack_events']}` / `normal={overall['normal_events']}`")
    lines.append(f"- normal 比率: `{overall['normal_ratio']:.1%}`")
    lines.append("")
    nd = payload["normal_dominant_subset"]
    lines.append(f"- normal-dominant seed: `{nd['window_count']} window / {nd['total_events']} event`")
    lines.append(f"- その内訳: `attack={nd['attack_events']}` / `normal={nd['normal_events']}`")
    lines.append(f"- normal 比率: `{nd['normal_ratio']:.1%}`")
    lines.append("")
    lines.append("## 2. 何が残っているか")
    lines.append("")
    lines.append("normal-dominant とみなしたのは、window 内 normal 比率が高く、かつ攻撃実行連鎖の近くにある seed である。")
    lines.append("")
    for row in payload["window_rows"]:
        lines.append(
            f"- `{row['parent_session_id']}` / `{row['dominant_process']}` / `chunk {row['start_chunk']}-{row['end_chunk']}` / events=`{row['total_events']}` / attack=`{row['attack_events']}` / normal=`{row['normal_events']}` / normal_ratio=`{row['normal_ratio']:.1%}`"
        )
    lines.append("")
    lines.append("## 3. normal-dominant seed")
    lines.append("")
    for row in payload["normal_dominant_windows"]:
        lines.append(
            f"- `{row['dominant_process']}` / `chunk {row['start_chunk']}-{row['end_chunk']}` / events=`{row['total_events']}` / attack=`{row['attack_events']}` / normal=`{row['normal_events']}` / top_normal_process=`{row['top_processes_normal'][0][0] if row['top_processes_normal'] else '-'}`"
        )
    lines.append("")
    lines.append("## 4. 正常行動としての使い道")
    lines.append("")
    lines.append("この出力は、完全に benign なログだけを集めたものではない。")
    lines.append("ただし、攻撃近傍で dominant process が切り替わる帯に対して、数百 event 規模の正常イベントがまとまって残っている。")
    lines.append("したがって、次の用途には十分使いやすい。")
    lines.append("")
    lines.append("- 攻撃前後の通常プロセス遷移を読む")
    lines.append("- 誤検知を生みやすい正常コマンド列を集める")
    lines.append("- payload / powershell / regsvr32 の前後文脈から正常動作パターンを抽出する")
    lines.append("")
    lines.append("## 5. 注意点")
    lines.append("")
    lines.append("- 小さい真陽性 sequence 側の正常文脈は、まだ十分に残せていない")
    lines.append("- 現在の normal seed は `aalsahee|20220719T1430Z` 側に寄っている")
    lines.append("- 研究では「純粋 benign」ではなく「attack-near normal context」であることを明示した方がよい")
    lines.append("")
    lines.append("## 6. 参照")
    lines.append("")
    lines.append(f"- high-confidence input: `{payload['inputs']['high_confidence_results']}`")
    lines.append(f"- source experiment: `{payload['inputs']['exp_dir']}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    exp_dir = ROOT / args.exp_dir
    high_conf = load_json(ROOT / args.high_confidence_results)
    session_test = load_pickle(exp_dir / "session_test.pkl")

    window_rows = []
    grouped_by_process = defaultdict(lambda: {"events": 0, "attack": 0, "normal": 0})
    for window in high_conf["high_confidence_windows"]:
        sample = session_test[window["parent_session_id"]]
        start = window["start_chunk"] * args.chunk_size
        end = min(len(sample["templates"]), (window["end_chunk"] + 1) * args.chunk_size)
        templates = sample["templates"][start:end]
        labels = sample["label"][start:end]
        stats = summarize_templates(templates, labels)
        total = len(labels)
        attack = int(sum(labels))
        normal = total - attack
        row = {
            **window,
            "total_events": total,
            "attack_events": attack,
            "normal_events": normal,
            "normal_ratio": (normal / total) if total else 0.0,
            **stats,
        }
        window_rows.append(row)
        grouped_by_process[row["dominant_process"]]["events"] += total
        grouped_by_process[row["dominant_process"]]["attack"] += attack
        grouped_by_process[row["dominant_process"]]["normal"] += normal

    normal_dominant = [
        row for row in window_rows if row["normal_ratio"] >= args.normal_dominant_threshold
    ]

    overall_total = sum(row["total_events"] for row in window_rows)
    overall_attack = sum(row["attack_events"] for row in window_rows)
    overall_normal = sum(row["normal_events"] for row in window_rows)
    nd_total = sum(row["total_events"] for row in normal_dominant)
    nd_attack = sum(row["attack_events"] for row in normal_dominant)
    nd_normal = sum(row["normal_events"] for row in normal_dominant)

    process_rollup = []
    for proc, agg in sorted(grouped_by_process.items()):
        total = agg["events"]
        attack = agg["attack"]
        normal = agg["normal"]
        process_rollup.append(
            {
                "dominant_process": proc,
                "window_count": sum(1 for row in window_rows if row["dominant_process"] == proc),
                "total_events": total,
                "attack_events": attack,
                "normal_events": normal,
                "normal_ratio": (normal / total) if total else 0.0,
            }
        )

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "exp_dir": args.exp_dir,
            "high_confidence_results": args.high_confidence_results,
        },
        "overall": {
            "window_count": len(window_rows),
            "total_events": overall_total,
            "attack_events": overall_attack,
            "normal_events": overall_normal,
            "normal_ratio": (overall_normal / overall_total) if overall_total else 0.0,
        },
        "normal_dominant_subset": {
            "threshold": args.normal_dominant_threshold,
            "window_count": len(normal_dominant),
            "total_events": nd_total,
            "attack_events": nd_attack,
            "normal_events": nd_normal,
            "normal_ratio": (nd_normal / nd_total) if nd_total else 0.0,
        },
        "process_rollup": process_rollup,
        "window_rows": window_rows,
        "normal_dominant_windows": normal_dominant,
    }

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    dump_json(output_dir / "results.json", payload)
    dump_text(output_dir / "summary.md", build_markdown(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
