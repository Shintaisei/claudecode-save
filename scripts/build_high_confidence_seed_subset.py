import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOW = ["payload.exe", "powershell.exe", "regsvr32.exe"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a narrower high-confidence seed subset from the Security+Sysmon review queue."
    )
    parser.add_argument("--review-queue-results", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--allow-processes", nargs="*", default=DEFAULT_ALLOW)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def dump_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def summarize(windows: list[dict]) -> dict:
    return {
        "window_count": len(windows),
        "total_events": int(sum(window["total_events"] for window in windows)),
        "attack_events": int(sum(window["attack_events"] for window in windows)),
        "normal_events": int(sum(window["normal_events"] for window in windows)),
        "hit_sessions": sorted({window["parent_session_id"] for window in windows}),
    }


def build_markdown(payload: dict) -> str:
    lines = []
    lines.append("# ATLAS v2 S3 High-Confidence Seed Subset")
    lines.append("")
    lines.append(f"更新日: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## 1. ねらい")
    lines.append("")
    lines.append("Security second pass の review windows から、より攻撃実行連鎖らしい帯だけを残してさらに読量を絞る。")
    lines.append("")
    lines.append("使った allow process:")
    for proc in payload["allow_processes"]:
        lines.append(f"- `{proc}`")
    lines.append("")
    lines.append("## 2. 結果")
    lines.append("")
    hc = payload["high_confidence_summary"]
    lines.append(f"- high-confidence windows: `{hc['window_count']}`")
    lines.append(f"- total events: `{hc['total_events']}`")
    lines.append(f"- attack events: `{hc['attack_events']}`")
    lines.append(f"- normal events: `{hc['normal_events']}`")
    lines.append("")
    oracle = payload["oracle_attack_positive_summary"]
    lines.append("評価上の upper bound:")
    lines.append(f"- attack-positive windows: `{oracle['window_count']}`")
    lines.append(f"- total events: `{oracle['total_events']}`")
    lines.append(f"- attack events: `{oracle['attack_events']}`")
    lines.append(f"- normal events: `{oracle['normal_events']}`")
    lines.append("")
    lines.append("## 3. 採用 window")
    lines.append("")
    for window in payload["high_confidence_windows"]:
        lines.append(
            f"- `{window['parent_session_id']}` / `{window['dominant_process']}` / `chunk {window['start_chunk']}-{window['end_chunk']}` / events=`{window['total_events']}` / attack=`{window['attack_events']}` / normal=`{window['normal_events']}`"
        )
    lines.append("")
    lines.append("## 4. 解釈")
    lines.append("")
    lines.append("この subset は、review queue 全体より攻撃実行連鎖に寄せた aggressive な読解起点である。")
    lines.append("特に `payload.exe` 帯を核にしつつ、前後の `powershell.exe` と `regsvr32.exe` を残すことで、攻撃近傍の正常文脈を保ったまま量をさらに減らしている。")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    review = load_json(ROOT / args.review_queue_results)
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    allow = {value.lower() for value in args.allow_processes}
    all_windows = []
    for row in review["review_queue"]:
        for window in row.get("security_review_windows", []):
            enriched = dict(window)
            enriched["parent_label"] = row["label"]
            all_windows.append(enriched)

    high_confidence = [
        window
        for window in all_windows
        if window.get("dominant_process", "").lower() in allow
    ]
    oracle_attack_positive = [window for window in all_windows if window["attack_events"] > 0]

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "input_review_queue_results": args.review_queue_results,
        "allow_processes": sorted(allow),
        "high_confidence_summary": summarize(high_confidence),
        "oracle_attack_positive_summary": summarize(oracle_attack_positive),
        "high_confidence_windows": high_confidence,
        "oracle_attack_positive_windows": oracle_attack_positive,
    }
    dump_json(output_dir / "results.json", payload)
    dump_text(output_dir / "summary.md", build_markdown(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
