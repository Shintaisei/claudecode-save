import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {"payload.exe", "tpautoconnect.exe"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze non-core processes in top-ranked micro-chunks."
    )
    parser.add_argument("--input-json", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def classify_usecase_target(process: str) -> str:
    if process in {"repmgr.exe", "explorer.exe", "winword.exe", "firefox.exe"}:
        return "yes"
    if process in {"csrss.exe", "svchost.exe", "dllhost.exe"}:
        return "no"
    return "maybe"


def describe_process(process: str) -> str:
    if process == "repmgr.exe":
        return "document-access chain candidate"
    if process == "explorer.exe":
        return "file-operation candidate"
    if process == "winword.exe":
        return "document-viewing candidate"
    if process == "firefox.exe":
        return "browser candidate"
    if process == "csrss.exe":
        return "system-side noise"
    return "needs manual interpretation"


def build_markdown(rows: list[dict], micro_rows: list[dict], input_json: str) -> str:
    total_events = sum(row["event_count"] for row in rows)
    lines = []
    lines.append("# LOF top10 micro-chunk の非 payload / 非 tpautoconnect プロセス分析")
    lines.append("")
    lines.append(f"更新日: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## 1. 前提")
    lines.append("")
    lines.append(f"- 対象は `{input_json}`")
    lines.append("- 母集団は `LOF top10 micro-chunk = 100 event`")
    lines.append("- `payload.exe` と `tpautoconnect.exe` を除いた残りのプロセスだけを見る")
    lines.append("- 今回ここで出てくるプロセスが、そのままユースケース候補の母集団になる")
    lines.append("")
    lines.append("## 2. 全体像")
    lines.append("")
    lines.append(f"- 残ったプロセス種別数: `{len(rows)}`")
    lines.append(f"- 残った event 数: `{total_events}`")
    lines.append("- 出てきたプロセスは `repmgr.exe`, `explorer.exe`, `winword.exe`, `csrss.exe` の4種だけ")
    lines.append("- このうちユースケース対象として自然なのは `repmgr.exe`, `explorer.exe`, `winword.exe`")
    lines.append("- `csrss.exe` は system-side noise とみなすのが自然")
    lines.append("")
    lines.append("## 3. プロセス別集計")
    lines.append("")
    lines.append("| process | event数 | 出現micro数 | 出現rank | attack label数 | normal label数 | ユースケース対象 | 見え方 |")
    lines.append("| --- | ---: | ---: | --- | ---: | ---: | --- | --- |")
    for row in rows:
        lines.append(
            f"| `{row['process']}` | `{row['event_count']}` | `{row['micro_count']}` | `{', '.join(map(str, row['micro_ranks']))}` | `{row['attack_events']}` | `{row['normal_events']}` | `{row['usecase_target']}` | `{row['description']}` |"
        )
    lines.append("")
    lines.append("## 4. micro rank ごとの出現")
    lines.append("")
    lines.append("| micro rank | micro-chunk | 非coreプロセス | event数 | attack / normal |")
    lines.append("| --- | --- | --- | ---: | ---: |")
    for row in micro_rows:
        lines.append(
            f"| `{row['micro_rank']}` | `{row['micro_name']}` | `{row['processes_text']}` | `{row['noncore_event_count']}` | `{row['attack_events']} / {row['normal_events']}` |"
        )
    lines.append("")
    lines.append("## 5. 解釈")
    lines.append("")
    lines.append("- `repmgr.exe`")
    lines.append("  文書関連アクセスの中心候補。`rank 6, 9` に出ていて、今回もっとも手続型ユースケースに近い。")
    lines.append("- `explorer.exe`")
    lines.append("  `rank 7` にまとまって出ており、単発のファイル操作ユースケースとして扱いやすい。")
    lines.append("- `winword.exe`")
    lines.append("  出現は `rank 10` の1 eventだけだが、文書閲覧起点として意味が明確。")
    lines.append("- `csrss.exe`")
    lines.append("  `rank 1, 2` に少量出るだけで、今回のユースケース対象にはしない方が自然。")
    lines.append("")
    lines.append("## 6. 今回のユースケース対象")
    lines.append("")
    lines.append("| 優先度 | process | 主な型 | 根拠 |")
    lines.append("| --- | --- | --- | --- |")
    lines.append("| `高` | `repmgr.exe` | 手続型 | `rank 6, 9` に計5 event 出現し、文書アクセス連鎖として読める |")
    lines.append("| `高` | `explorer.exe` | 単発操作型 | `rank 7` に計3 event 出現し、ファイル操作として説明しやすい |")
    lines.append("| `中` | `winword.exe` | 単発操作型 | `rank 10` に1 event だが、文書閲覧の意味が明確 |")
    lines.append("| `低` | `csrss.exe` | 対象外 | system-side noise であり、関連ログ調達の起点にしにくい |")
    lines.append("")
    lines.append("## 7. まとめ")
    lines.append("")
    lines.append("- 今回の `100 event` で、ユースケース対象として本当に見るべきプロセスは実質 `3種`")
    lines.append("- `repmgr.exe` と `explorer.exe` が主対象、`winword.exe` が補助対象")
    lines.append("- 研究上は、この `3種` を起点候補として自動化可否を評価するのがちょうどよい")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    payload = load_json(ROOT / args.input_json)

    process_counts = Counter()
    attack_counts = Counter()
    normal_counts = Counter()
    process_ranks = defaultdict(set)
    process_micro_ids = defaultdict(set)
    micro_rows = []

    for chunk in payload["micro_chunks"]:
        local_counter = Counter()
        for event in chunk["events"]:
            process = event["process"]
            if process in EXCLUDED:
                continue
            local_counter[process] += 1
            process_counts[process] += 1
            process_ranks[process].add(chunk["micro_rank"])
            process_micro_ids[process].add(chunk["micro_chunk_id"])
            if int(event["label"]) == 1:
                attack_counts[process] += 1
            else:
                normal_counts[process] += 1

        if local_counter:
            micro_rows.append(
                {
                    "micro_rank": chunk["micro_rank"],
                    "micro_name": f"chunk{chunk['coarse_chunk_index']:03d} micro{chunk['micro_chunk_index']:02d}",
                    "processes_text": ", ".join(
                        f"{proc}:{count}" for proc, count in local_counter.most_common()
                    ),
                    "noncore_event_count": sum(local_counter.values()),
                    "attack_events": chunk["attack_events"],
                    "normal_events": chunk["normal_events"],
                }
            )

    rows = []
    for process, count in process_counts.most_common():
        rows.append(
            {
                "process": process,
                "event_count": count,
                "micro_count": len(process_micro_ids[process]),
                "micro_ranks": sorted(process_ranks[process]),
                "attack_events": int(attack_counts[process]),
                "normal_events": int(normal_counts[process]),
                "usecase_target": classify_usecase_target(process),
                "description": describe_process(process),
            }
        )

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    md_path = output_dir / "summary.md"
    md_path.write_text(build_markdown(rows, micro_rows, args.input_json), encoding="utf-8")

    with (output_dir / "process_summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "process",
                "event_count",
                "micro_count",
                "micro_ranks",
                "attack_events",
                "normal_events",
                "usecase_target",
                "description",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row["process"],
                    row["event_count"],
                    row["micro_count"],
                    ",".join(map(str, row["micro_ranks"])),
                    row["attack_events"],
                    row["normal_events"],
                    row["usecase_target"],
                    row["description"],
                ]
            )

    with (output_dir / "micro_presence.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "micro_rank",
                "micro_name",
                "processes_text",
                "noncore_event_count",
                "attack_events",
                "normal_events",
            ]
        )
        for row in micro_rows:
            writer.writerow(
                [
                    row["micro_rank"],
                    row["micro_name"],
                    row["processes_text"],
                    row["noncore_event_count"],
                    row["attack_events"],
                    row["normal_events"],
                ]
            )

    print(md_path)
    print(output_dir / "process_summary.csv")
    print(output_dir / "micro_presence.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
