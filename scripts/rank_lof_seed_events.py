import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_WEIGHTS = {
    "winword.exe": 100,
    "repmgr.exe": 95,
    "explorer.exe": 90,
    "firefox.exe": 85,
    "taskhost.exe": 40,
    "vmtoolsd.exe": 20,
    "tpautoconnect.exe": -40,
    "tpautoconnsvc.exe": -45,
    "spoolsv.exe": -45,
}
EVENT_WEIGHTS = {
    "4688": 30,
    "4656": 16,
    "4663": 12,
    "4658": 4,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rank event-level normal-behavior seed candidates inside LOF top chunks."
    )
    parser.add_argument("--raw-json", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--chunk-limit", type=int, default=10)
    parser.add_argument("--topn", type=int, default=10)
    parser.add_argument("--max-per-chunk", type=int, default=2)
    return parser.parse_args()


def event_seed_score(chunk: dict, event: dict, prev_process: str | None, seen_processes: set[str]) -> tuple[float, list[str]]:
    reasons = []
    score = 0.0

    process = event["process"]
    event_id = event["event_id"]

    score += 300 - chunk["rank"] * 10
    reasons.append(f"chunk rank {chunk['rank']}")

    process_weight = PROCESS_WEIGHTS.get(process, 0)
    score += process_weight
    if process_weight:
        reasons.append(f"process {process}")

    event_weight = EVENT_WEIGHTS.get(event_id, 0)
    score += event_weight
    if event_weight:
        reasons.append(f"event {event_id}")

    if process not in seen_processes:
        score += 35
        reasons.append("first process appearance in chunk")

    if prev_process is not None and process != prev_process:
        score += 20
        reasons.append("process transition")

    if event["offset"] <= 10:
        score += 10
        reasons.append("early in chunk")
    elif event["offset"] <= 30:
        score += 5

    if process in {"tpautoconnect.exe", "tpautoconnsvc.exe", "spoolsv.exe"}:
        score -= 25
        reasons.append("background-noise penalty")

    return score, reasons


def build_markdown(payload: dict) -> str:
    lines = []
    lines.append("# LOF top10 chunk からさらに絞った event shortlist")
    lines.append("")
    lines.append(f"更新日: {payload['generated_at'][:10]}")
    lines.append("")
    lines.append("## 1. 目的")
    lines.append("")
    lines.append("- `LOF` の高順位 chunk から、さらに実務の初動で先に見るべき event を `10件` に絞る")
    lines.append("- 今回は `top10 chunk` を対象にし、normal seed 候補を優先している")
    lines.append("")
    lines.append("## 2. ルール")
    lines.append("")
    lines.append("- 親の `chunk rank` が高い event を優先")
    lines.append("- `winword.exe` / `repmgr.exe` / `explorer.exe` / `firefox.exe` を優先")
    lines.append("- `4656` のような起点寄り event をやや優先")
    lines.append("- chunk 内で最初に出るプロセス切り替わりを優先")
    lines.append("- `tpautoconnect.exe` など反復 background noise は下げる")
    lines.append("- 1 chunk あたり最大 `2 event` までに制限")
    lines.append("")
    lines.append("## 3. shortlist")
    lines.append("")
    lines.append("| rank | parent chunk | event offset | process | event_id | category | 理由 |")
    lines.append("| --- | --- | ---: | --- | --- | --- | --- |")
    for idx, row in enumerate(payload["shortlist"], start=1):
        lines.append(
            f"| `{idx}` | `chunk{row['chunk_index']:03d} (rank {row['chunk_rank']})` | `{row['event_offset']}` | `{row['process']}` | `{row['event_id']}` | `{row['chunk_category']}` | `{'; '.join(row['reasons'])}` |"
        )
    lines.append("")
    lines.append("## 4. 読み")
    lines.append("")
    lines.append("- 先頭は `office-doc` と `user-file` の起点 event が中心")
    lines.append("- `chunk203`, `chunk204`, `chunk210` からは `winword.exe` / `repmgr.exe` の開始側 event が選ばれている")
    lines.append("- `chunk244`, `chunk243` からは `explorer.exe` が現れた切り替わり地点が拾われている")
    lines.append("- 今回は `top10 chunk` 限定なので browser 系はまだ入れていない")
    lines.append("")
    lines.append("## 5. 次の広げ方")
    lines.append("")
    lines.append("- browser 系も欲しいなら対象を `rank 43〜47` まで拡張する")
    lines.append("- その場合は `firefox.exe` の最初の出現 event を同じロジックで追加するとよい")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    raw = json.loads((ROOT / args.raw_json).read_text(encoding="utf-8"))
    chunks = raw["chunks"][: args.chunk_limit]

    candidates = []
    for chunk in chunks:
        if chunk["category"] not in {"office-doc", "user-file", "browser"}:
            continue

        prev_process = None
        seen_processes: set[str] = set()
        for event in chunk["events"]:
            if event["label"] != 0:
                prev_process = event["process"]
                seen_processes.add(event["process"])
                continue

            process = event["process"]
            if process not in {"winword.exe", "repmgr.exe", "explorer.exe", "firefox.exe"}:
                prev_process = process
                seen_processes.add(process)
                continue

            score, reasons = event_seed_score(chunk, event, prev_process, seen_processes)
            candidates.append(
                {
                    "score": score,
                    "chunk_rank": chunk["rank"],
                    "chunk_index": chunk["chunk_index"],
                    "chunk_category": chunk["category"],
                    "event_offset": event["offset"],
                    "process": process,
                    "event_id": event["event_id"],
                    "template": event["template"],
                    "reasons": reasons,
                }
            )
            prev_process = process
            seen_processes.add(process)

    candidates.sort(
        key=lambda row: (
            row["score"],
            -row["chunk_rank"],
            -row["event_offset"],
        ),
        reverse=True,
    )

    shortlist = []
    per_chunk = {}
    for row in candidates:
        chunk_key = row["chunk_index"]
        used = per_chunk.get(chunk_key, 0)
        if used >= args.max_per_chunk:
            continue
        shortlist.append(row)
        per_chunk[chunk_key] = used + 1
        if len(shortlist) >= args.topn:
            break

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "raw_json": args.raw_json,
            "chunk_limit": args.chunk_limit,
            "topn": args.topn,
            "max_per_chunk": args.max_per_chunk,
        },
        "shortlist": shortlist,
        "all_candidates": candidates,
    }

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "event_shortlist.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "event_shortlist.md").write_text(
        build_markdown(payload),
        encoding="utf-8",
    )
    print(output_dir / "event_shortlist.md")
    print(output_dir / "event_shortlist.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
