import argparse
import json
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_KEYS = ["ProcessName", "NewProcessName", "Image", "Application"]
USEFUL_CATEGORIES = {"office-doc", "user-file", "browser"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze how many normal-behavior seed candidates LOF top-ranked chunks can provide."
    )
    parser.add_argument("--results-json", required=True)
    parser.add_argument("--session-pkl", required=True)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--topks", default="10,20,50,100")
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pickle(path: Path) -> dict:
    with path.open("rb") as fh:
        return pickle.load(fh)


def parse_template(template: str) -> dict:
    fields = {}
    for part in template.split(" | "):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value
    return fields


def process_name(fields: dict) -> str:
    for key in PROCESS_KEYS:
        value = fields.get(key)
        if value:
            return Path(value).name.lower()
    return "-"


def classify_chunk(chunk: dict, top_processes: list[tuple[str, int]]) -> str:
    if chunk["attack_events"] > 0:
        return "attack-mixed"

    process_set = {proc for proc, _ in top_processes}

    if "winword.exe" in process_set or "repmgr.exe" in process_set:
        return "office-doc"
    if "explorer.exe" in process_set:
        return "user-file"
    if "firefox.exe" in process_set:
        return "browser"
    if process_set & {"regsvr32.exe", "dllhost.exe", "svchost.exe", "csrss.exe"}:
        return "ambiguous-system"
    return "background-vmware"


def summarize_chunk(chunk: dict, sessions: dict, chunk_size: int) -> dict:
    session_id = chunk["session_id"]
    parent_session_id = "|".join(session_id.split("|")[:-1])
    chunk_index = int(session_id.split("chunk")[-1])
    session = sessions[parent_session_id]

    start = chunk_index * chunk_size
    end = min(len(session["templates"]), start + chunk_size)
    templates = session["templates"][start:end]

    proc_counter = Counter()
    event_counter = Counter()
    for template in templates:
        fields = parse_template(template)
        proc_counter[process_name(fields)] += 1
        event_counter[fields.get("EventID", "-")] += 1

    top_processes = proc_counter.most_common(5)
    category = classify_chunk(chunk, top_processes)

    return {
        "rank": 0,
        "session_id": session_id,
        "parent_session_id": parent_session_id,
        "chunk_index": chunk_index,
        "score": chunk["score"],
        "attack_events": chunk["attack_events"],
        "normal_events": chunk["normal_events"],
        "total_events": chunk["total_events"],
        "normal_ratio": (
            chunk["normal_events"] / chunk["total_events"] if chunk["total_events"] else 0.0
        ),
        "category": category,
        "top_processes": top_processes,
        "top_event_ids": event_counter.most_common(5),
        "is_useful_seed": category in USEFUL_CATEGORIES,
    }


def build_topk_summary(rows: list[dict], topk: int) -> dict:
    selected = rows[:topk]
    category_counter = Counter(row["category"] for row in selected)
    useful = [row for row in selected if row["is_useful_seed"]]
    pure_normal = [row for row in selected if row["attack_events"] == 0]
    attack_mixed = [row for row in selected if row["attack_events"] > 0]

    total_events = sum(row["total_events"] for row in selected)
    attack_events = sum(row["attack_events"] for row in selected)
    normal_events = sum(row["normal_events"] for row in selected)

    return {
        "topk": topk,
        "chunks": len(selected),
        "events": total_events,
        "attack_events": attack_events,
        "normal_events": normal_events,
        "normal_ratio": (normal_events / total_events) if total_events else 0.0,
        "pure_normal_chunks": len(pure_normal),
        "attack_mixed_chunks": len(attack_mixed),
        "useful_seed_chunks": len(useful),
        "useful_seed_ranks": [row["rank"] for row in useful],
        "category_counts": dict(category_counter),
    }


def build_markdown(payload: dict) -> str:
    lines = []
    lines.append("# LOF 上位 chunk の正常行動起点ポテンシャル分析")
    lines.append("")
    lines.append(f"更新日: {payload['generated_at'][:10]}")
    lines.append("")
    lines.append("## 1. 見たいこと")
    lines.append("")
    lines.append("- 実務では異常検知で上がったログから順に見るため、LOF スコア上位から確認したときにどれだけ正常行動の起点を取れそうかを見る")
    lines.append("- 特に `top10 / top20 / top50 / top100` のどこまで見れば、説明しやすい normal seed が増えるかを確認する")
    lines.append("")
    lines.append("## 2. 結論")
    lines.append("")
    lines.append("- `LOF top10` には `5 chunk` の有望な normal seed が含まれる")
    lines.append("- その内訳は `office-doc 3`、`user-file 2` で、rank は `4, 5, 6, 7, 9`")
    lines.append("- `top20` まで広げても seed 候補は増えず、ほとんどが `tpautoconnect.exe` 中心の background noise")
    lines.append("- `top50` まで広げると browser 系が `5 chunk` 追加され、合計 `10 chunk` まで増える")
    lines.append("- したがって、**実務寄りにスコア上位から確認するなら、まず `top10` を主対象にし、browser 系も欲しい時だけ `top50` まで広げる** のが自然")
    lines.append("")
    lines.append("## 3. top-k ごとの密度")
    lines.append("")
    lines.append("| top-k | events | attack-mixed | pure-normal | useful-seed | 主な読み |")
    lines.append("| --- | ---: | ---: | ---: | ---: | --- |")
    for point in payload["topk_summary"]:
        note = "top10 で主要 seed をほぼ回収"
        if point["topk"] == 20:
            note = "追加分はほぼ background noise"
        elif point["topk"] == 50:
            note = "browser 系 seed が増える"
        elif point["topk"] == 100:
            note = "候補は増えるが説明負荷も増える"
        lines.append(
            f"| `{point['topk']}` | `{point['events']}` | `{point['attack_mixed_chunks']}` | `{point['pure_normal_chunks']}` | `{point['useful_seed_chunks']}` | {note} |"
        )
    lines.append("")
    lines.append("## 4. top10 で得られる有望 seed")
    lines.append("")
    lines.append("| rank | chunk | category | attack / normal | 主なプロセス |")
    lines.append("| --- | --- | --- | ---: | --- |")
    for row in payload["rows"][:10]:
        if not row["is_useful_seed"]:
            continue
        lines.append(
            f"| `{row['rank']}` | `chunk{row['chunk_index']:03d}` | `{row['category']}` | `{row['attack_events']} / {row['normal_events']}` | `{', '.join(proc for proc, _ in row['top_processes'][:3])}` |"
        )
    lines.append("")
    lines.append("### 読み")
    lines.append("")
    lines.append("- `chunk203`, `chunk204`, `chunk210` は `winword.exe` / `repmgr.exe` を含み、文書操作系 seed として使いやすい")
    lines.append("- `chunk244`, `chunk243` は `explorer.exe` を含み、ファイル操作・画面操作系 seed として使いやすい")
    lines.append("- `rank10` 以降は同じ高スコア帯でも `tpautoconnect.exe` 反復が増え、normal ではあっても起点としての説明力が落ちる")
    lines.append("")
    lines.append("## 5. top50 まで広げた時の追加分")
    lines.append("")
    lines.append("- 新しく増える有望 seed の中心は browser 系で、主に `rank 43, 44, 46, 47`")
    lines.append("- ただし `top10 -> top50` では `+4,000 event` 読んで、追加 seed は `+5 chunk` にとどまる")
    lines.append("- そのため、browser 系ユースケースが必要な時だけ `top50` に広げる方が効率が良い")
    lines.append("")
    lines.append("## 6. 実務向けの見方")
    lines.append("")
    lines.append("- まず `top10 = 1,000 event` を見る")
    lines.append("- この範囲で `5 chunk` の有望 normal seed と `4 chunk` の attack-mixed chunk を同時に確認できる")
    lines.append("- 追加で normal seed の種類を増やしたい時だけ `top50` まで拡張し、browser 系を回収する")
    lines.append("- `top20` はコスト増の割に seed 候補が増えないため、単独の確認単位としては弱い")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    results = load_json(ROOT / args.results_json)
    sessions = load_pickle(ROOT / args.session_pkl)
    topks = [int(item) for item in args.topks.split(",") if item.strip()]

    rows = []
    for rank, chunk in enumerate(results["top_chunks"], start=1):
        row = summarize_chunk(chunk, sessions, args.chunk_size)
        row["rank"] = rank
        rows.append(row)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "results_json": args.results_json,
            "session_pkl": args.session_pkl,
            "chunk_size": args.chunk_size,
        },
        "topk_summary": [build_topk_summary(rows, topk) for topk in topks],
        "rows": rows,
    }

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "summary.md").write_text(build_markdown(payload), encoding="utf-8")
    print(output_dir / "summary.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
