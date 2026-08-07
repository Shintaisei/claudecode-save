import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW_JSON = ROOT / "docs" / "lof_top10micro_review_2026-05-10" / "top10_micro_raw_events.json"
OUT_SVG = ROOT / "docs_active" / "top10_micro_sequence_composition_2026-05-19.svg"
OUT_MD = ROOT / "docs_active" / "top10_micro_sequence_composition_2026-05-19.md"


ATTACK = "#c0392b"
PAYLOAD = "#f39c12"
NORMAL = "#2e86ab"
GRID = "#d7dde5"
TEXT = "#1f2d3d"
SUBTEXT = "#5b6776"
BG = "#f7f9fb"


def load_rows():
    raw = json.loads(RAW_JSON.read_text(encoding="utf-8"))
    rows = []
    totals = {"attack": 0, "payload_label0": 0, "non_payload_label0": 0}
    for mc in raw["micro_chunks"]:
        attack = 0
        payload_label0 = 0
        non_payload_label0 = 0
        for event in mc["events"]:
            label = int(event["label"])
            process = (event.get("process") or "").lower()
            if label == 1:
                attack += 1
            elif process == "payload.exe":
                payload_label0 += 1
            else:
                non_payload_label0 += 1
        rows.append(
            {
                "rank": mc["micro_rank"],
                "attack": attack,
                "payload_label0": payload_label0,
                "non_payload_label0": non_payload_label0,
            }
        )
        totals["attack"] += attack
        totals["payload_label0"] += payload_label0
        totals["non_payload_label0"] += non_payload_label0
    rows.sort(key=lambda x: x["rank"])
    return rows, totals


def rect(x, y, w, h, fill, rx=0):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" rx="{rx}" />'


def text(x, y, value, size=16, weight="400", fill=TEXT, anchor="start"):
    return (
        f'<text x="{x}" y="{y}" font-family="Segoe UI, Yu Gothic, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{value}</text>'
    )


def build_svg(rows, totals):
    width = 1400
    height = 860
    left = 110
    top = 180
    chart_w = 1120
    chart_h = 480
    bar_w = 72
    gap = 36
    unit = chart_h / 10

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        rect(0, 0, width, height, BG),
        text(70, 74, "Top10 micro-chunk composition by sequence", size=30, weight="700"),
        text(
            70,
            110,
            "Each bar sums to 10 events. Categories are exclusive: attack label, label=0 payload.exe, label=0 non-payload.",
            size=16,
            fill=SUBTEXT,
        ),
    ]

    parts.append(rect(70, 128, 1240, 32, "#ffffff", rx=8))
    parts.append(text(88, 149, f"Attack-labeled events: {totals['attack']}", size=15, weight="600", fill=ATTACK))
    parts.append(text(360, 149, f"Label 0 + payload.exe: {totals['payload_label0']}", size=15, weight="600", fill=PAYLOAD))
    parts.append(text(695, 149, f"Label 0 + non-payload: {totals['non_payload_label0']}", size=15, weight="600", fill=NORMAL))

    for i in range(11):
        y = top + chart_h - i * unit
        parts.append(f'<line x1="{left}" y1="{y}" x2="{left + chart_w}" y2="{y}" stroke="{GRID}" stroke-width="1" />')
        parts.append(text(left - 18, y + 5, str(i), size=14, fill=SUBTEXT, anchor="end"))

    parts.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + chart_h}" stroke="{TEXT}" stroke-width="2" />')
    parts.append(f'<line x1="{left}" y1="{top + chart_h}" x2="{left + chart_w}" y2="{top + chart_h}" stroke="{TEXT}" stroke-width="2" />')

    x = left + 40
    for row in rows:
        a_h = row["attack"] * unit
        p_h = row["payload_label0"] * unit
        n_h = row["non_payload_label0"] * unit
        base_y = top + chart_h

        if n_h:
            parts.append(rect(x, base_y - n_h, bar_w, n_h, NORMAL, rx=6))
        if p_h:
            parts.append(rect(x, base_y - n_h - p_h, bar_w, p_h, PAYLOAD, rx=6))
        if a_h:
            parts.append(rect(x, base_y - n_h - p_h - a_h, bar_w, a_h, ATTACK, rx=6))

        parts.append(text(x + bar_w / 2, base_y + 48, f"Seq {row['rank']}", size=14, weight="600", anchor="middle"))
        parts.append(text(x + bar_w / 2, base_y - n_h - p_h - a_h - 16, f"{row['attack']}/{row['payload_label0']}/{row['non_payload_label0']}", size=12, fill=SUBTEXT, anchor="middle"))
        x += bar_w + gap

    legend_y = 715
    parts.append(rect(80, legend_y - 28, 18, 18, ATTACK, rx=4))
    parts.append(text(108, legend_y - 13, "Attack label = 1", size=15))
    parts.append(rect(330, legend_y - 28, 18, 18, PAYLOAD, rx=4))
    parts.append(text(358, legend_y - 13, "Label = 0 and process = payload.exe", size=15))
    parts.append(rect(760, legend_y - 28, 18, 18, NORMAL, rx=4))
    parts.append(text(788, legend_y - 13, "Label = 0 and process != payload.exe", size=15))

    parts.append(text(80, 780, "Readout", size=18, weight="700"))
    parts.append(text(80, 808, "Seq 4 and Seq 5 are dominated by payload.exe-adjacent events plus 3 attack-labeled events.", size=15, fill=SUBTEXT))
    parts.append(text(80, 833, "Seq 6, 7, 9, 10 are fully composed of label 0 non-payload events, making them the cleanest normal-use-case candidates.", size=15, fill=SUBTEXT))

    parts.append("</svg>")
    return "\n".join(parts)


def build_md(rows, totals):
    lines = [
        "# top10 sequence composition",
        "",
        "作成日: 2026-05-19",
        "",
        "## 区分",
        "- `attack label`: `label = 1` の event",
        "- `payload.exe`: `label = 0` かつ `process = payload.exe` の event",
        "- `non-payload normal`: `label = 0` かつ `process != payload.exe` の event",
        "",
        "この3区分は重ならないように切ってあり、各シーケンスは必ず `10 event` に合計されます。",
        "",
        "## 全体合計",
        f"- attack label: `{totals['attack']}`",
        f"- label 0 + payload.exe: `{totals['payload_label0']}`",
        f"- label 0 + non-payload: `{totals['non_payload_label0']}`",
        "",
        "## シーケンス別",
        "",
        "| seq rank | attack label | label 0 + payload.exe | label 0 + non-payload |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| `{row['rank']}` | `{row['attack']}` | `{row['payload_label0']}` | `{row['non_payload_label0']}` |"
        )
    lines.extend(
        [
            "",
            "## 読み方",
            "- `seq 4` と `seq 5` は `payload.exe` 近傍がかなり多く、attack label も `3` 件ずつ入る",
            "- `seq 6, 7, 9, 10` は `label 0 + non-payload` だけで構成される",
            "- `seq 2` は attack label はないが `payload.exe` が `3` 件含まれるため、clean normal と言い切りにくい",
        ]
    )
    return "\n".join(lines) + "\n"


def main():
    rows, totals = load_rows()
    OUT_SVG.write_text(build_svg(rows, totals), encoding="utf-8")
    OUT_MD.write_text(build_md(rows, totals), encoding="utf-8")
    print(f"wrote {OUT_SVG}")
    print(f"wrote {OUT_MD}")


if __name__ == "__main__":
    main()
