import csv
import json
import math
from collections import defaultdict
from pathlib import Path


ROOT = Path("docs/current_experiment/handoff_20260614_component_rubric_experiment")
AGG = ROOT / "03_aggregated_results"
OUT = ROOT / "04_discussion_base" / "usecase_deep_dive_20260614"
LEDGER = AGG / "ledgers" / "final_comparison_per_run_component_scores.csv"
CASES = Path("data/current_experiment/cases/cbc_23_chain_stage_cases_2026-06-12.jsonl")
GOLD_ROOT = Path("data/current_experiment/gold/cbc_alert_behavior_chain_gold/by_chain")

METRIC_PAIRS = [
    ("action_step_recall_hits", "action_step_recall_total", "action_step_recall"),
    ("critical_evidence_recall_hits", "critical_evidence_recall_total", "critical_evidence_recall"),
    ("behavior_sequence_order_hits", "behavior_sequence_order_total", "behavior_sequence_order"),
    ("candidate_claim_precision_hits", "candidate_claim_precision_total", "candidate_claim_precision"),
]

MODEL_ORDER = ["gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5 low raw"]
MOJIBAKE_MARKERS = tuple(chr(code) for code in (
    0x7e3a, 0x873f, 0x8815, 0x9a3e, 0x90b1,
    0x8373, 0x8b41, 0x9aef, 0x908f, 0x566a,
))


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def as_int(row, key):
    return int(float(row.get(key) or 0))


def rate(hit, total):
    return hit / total if total else ""


def fmt(v, digits=3):
    if v == "" or v is None:
        return ""
    return f"{float(v):.{digits}f}"


def has_mojibake(text):
    return any(marker in str(text) for marker in MOJIBAKE_MARKERS)


def clean_items(items):
    cleaned = []
    for item in items:
        text = str(item).strip()
        if not text or has_mojibake(text):
            continue
        cleaned.append(text)
    return cleaned


def aggregate(rows, group_cols):
    buckets = defaultdict(list)
    for r in rows:
        buckets[tuple(r.get(c, "") for c in group_cols)].append(r)
    out = []
    for key, items in sorted(buckets.items()):
        row = {c: key[i] for i, c in enumerate(group_cols)}
        row["run_count"] = len(items)
        row["replicate_count"] = len(set(r.get("replicate", "") for r in items if r.get("replicate")))
        row["stage_count"] = len(set(r.get("stage", "") for r in items if r.get("stage")))
        row["overclaim_slot_count"] = sum(as_int(r, "overclaim_slot_count") for r in items)
        row["overclaim_per_run"] = fmt(row["overclaim_slot_count"] / row["run_count"], 2)
        for h, t, m in METRIC_PAIRS:
            hit = sum(as_int(r, h) for r in items)
            total = sum(as_int(r, t) for r in items)
            row[h] = hit
            row[t] = total
            row[m] = fmt(rate(hit, total), 3)
        out.append(row)
    return out


def load_case_meta():
    by_chain = {}
    with CASES.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            c = json.loads(line)
            chain = c["chain_id"]
            by_chain.setdefault(
                chain,
                {
                    "chain_id": chain,
                    "chain_type": c.get("chain_type", ""),
                    "expected_behavior": c.get("expected_behavior", ""),
                    "actor": c.get("actor", ""),
                    "process_name": c.get("process_name", ""),
                    "host": c.get("host", ""),
                    "episode_start": (c.get("time_window_utc") or {}).get("episode_start", ""),
                    "episode_end": (c.get("time_window_utc") or {}).get("episode_end", ""),
                    "framework_group": "",
                    "scenario_group": "",
                },
            )
    return by_chain


def load_gold_meta(chain_id):
    p = GOLD_ROOT / chain_id / "chain_gold.json"
    if not p.exists():
        return {"chain_title": "", "gold_step_count": "", "gold_objects": "", "gold_subjects": "", "evidence_basis": ""}
    d = json.loads(p.read_text(encoding="utf-8"))
    steps = d.get("behavior_timeline") or d.get("gold_steps") or []
    objects = []
    subjects = []
    evid = []
    for s in steps:
        if s.get("subject"):
            subjects.append(str(s.get("subject")))
        obj = s.get("process_code_object") or s.get("object") or ""
        if obj:
            objects.append(str(obj))
        if s.get("evidence_basis"):
            evid.append(str(s.get("evidence_basis")))
    objects = clean_items(objects)
    subjects = clean_items(subjects)
    return {
        "chain_title": d.get("chain_title", ""),
        "gold_step_count": len(steps),
        "gold_objects": " | ".join(objects[:5]),
        "gold_subjects": " -> ".join(subjects[:5]),
        "evidence_basis": " | ".join(evid[:5]),
    }


def classify_usecase(g54, g41, g55):
    if not g54:
        return "unclassified"
    ev = float(g54.get("critical_evidence_recall") or 0)
    order = float(g54.get("behavior_sequence_order") or 0)
    precision = float(g54.get("candidate_claim_precision") or 0)
    over = float(g54.get("overclaim_per_run") or 0)
    if ev >= 0.80 and order >= 0.70 and precision >= 0.60:
        return "easy_or_well_reconstructed"
    if ev >= 0.60 and order >= 0.45:
        return "moderate_reconstructable"
    if ev < 0.50 or order < 0.35:
        return "hard_or_unstable"
    if over >= 4.0:
        return "overclaim_prone"
    return "mixed"


def interpretation(chain, g41, g54, g55):
    if not g54:
        return "No gpt-5.4-mini aggregate available."
    ev54 = float(g54.get("critical_evidence_recall") or 0)
    act54 = float(g54.get("action_step_recall") or 0)
    ord54 = float(g54.get("behavior_sequence_order") or 0)
    prec54 = float(g54.get("candidate_claim_precision") or 0)
    over54 = float(g54.get("overclaim_per_run") or 0)
    parts = []
    if g41:
        ev41 = float(g41.get("critical_evidence_recall") or 0)
        act41 = float(g41.get("action_step_recall") or 0)
        if act54 - act41 >= 0.25 or ev54 - ev41 >= 0.25:
            parts.append("5.4-mini improves substantially over 4.1-mini, especially on evidence/action recovery.")
        elif abs(act54 - act41) < 0.10 and abs(ev54 - ev41) < 0.15:
            parts.append("4.1-mini and 5.4-mini are relatively close here; this is not a clean model-separation case.")
    if ev54 >= 0.80 and ord54 >= 0.70:
        parts.append("For 5.4-mini this is a high-confidence reconstruction case: evidence and ordering are both strong.")
    elif ev54 >= 0.60:
        parts.append("For 5.4-mini the main behavior is usually recoverable, but order or precision still needs caution.")
    else:
        parts.append("Even 5.4-mini struggles to tie the behavior to sufficient non-alert evidence, so this is a hard case.")
    if prec54 < 0.50 or over54 >= 4:
        parts.append("Precision/overclaim is a concern; the model tends to add nearby or extra claims.")
    if g55:
        ev55 = float(g55.get("critical_evidence_recall") or 0)
        if ev55 >= 0.90:
            parts.append("GPT-5.5 raw salvage recovers much of the content, but it remains a format-failed raw-text condition.")
    return " ".join(parts)


def usecase_story(row):
    title = row.get("chain_title") or row.get("expected_behavior") or ""
    objects = row.get("gold_objects") or ""
    step_count = int(row.get("gold_step_count") or 0)
    if "SimpleHTTPServer" in title:
        endpoint = ""
        for part in objects.split(" | "):
            if "10.193." in part:
                endpoint = part
                break
        endpoint_note = f"、接続先/通信先として `{endpoint}` まで拾えるケース" if endpoint else "、通信先詳細はgold側で明示しにくいケース"
        return f"`python -m SimpleHTTPServer` による簡易HTTPサーバ起動を追うユースケース{endpoint_note}。プロセス名とコマンドが短く、正解ステップも{step_count}なので、証跡が揃うと比較的再構成しやすい。"
    if "DNS packet capture" in title:
        tshark_note = "tshark実行まで含む" if "tshark" in objects.lower() else "バッチ起動部分が中心"
        return f"Explorer/cmd起点で `start_dns_logs.bat` を起動し、DNSログ取得のためのバッチ実行を追うユースケース。{tshark_note}ため、`cmd.exe`、bat、`tshark.exe` のどこまでを同一行動として切るかで過剰出力が出やすい。"
    if "Sublime" in title:
        script = "helloworld.py" if "helloworld.py" in objects else "hello.py"
        return f"Sublime Textの `plugin_host.exe` から `cmd.exe` を経由し、Pythonスクリプト `{script}` を実行する連鎖。cmdやpythonの重複ステップが多く、正解ステップ数も{step_count}なので、内容想起より順序評価が厳しく出やすい。"
    if "Discord Run key" in title:
        return "`discord.exe` から `reg.exe` を呼び、HKCU Runキーのquery/addを通じてDiscord自動起動設定を確認・登録する永続化系ユースケース。単なるプロセス実行ではなく、レジストリキーの意味づけまで必要なので、証跡と順序の両方が難しい。"
    if "cmd.exe alert" in title and "nvidia-smi" in objects:
        return "Discord起点で `cmd.exe` が `nvidia-smi.exe` 実行コマンドを呼ぶユースケース。コマンド列自体は短いが、親プロセスDiscordとの関係とコマンド本文の保持が必要になる。"
    if "cmd.exe alert" in title and "run_http_server.bat" in objects:
        return "Explorer/cmdから `run_http_server.bat` を起動し、最終的にPython HTTPサーバ実行へつながるユースケース。bat名、cmd起動、python起動が近接しているため、候補ステップを広く取りすぎると適合率が落ちる。"
    return "個別のプロセス連鎖を再構成するユースケース。正解ステップ、証跡、順序を同時に満たすかで難度が変わる。"


def japanese_interpretation(row):
    def f(key):
        val = row.get(key)
        return float(val) if val not in ("", None) else 0.0

    ev54 = f("g54_critical_evidence_recall")
    act54 = f("g54_action_step_recall")
    ord54 = f("g54_behavior_sequence_order")
    prec54 = f("g54_candidate_claim_precision")
    over54 = f("g54_overclaim_per_run")
    ev41 = f("g41_critical_evidence_recall")
    act41 = f("g41_action_step_recall")
    ev55 = f("g55raw_critical_evidence_recall")
    parts = []
    if act54 - act41 >= 0.25 or ev54 - ev41 >= 0.25:
        parts.append("5.4-miniでは4.1-miniより、行動内容または証跡の回収が明確に改善している。")
    elif abs(act54 - act41) < 0.10 and abs(ev54 - ev41) < 0.15:
        parts.append("4.1-miniと5.4-miniの差は小さく、モデル差よりもユースケース自体の曖昧さが効いている可能性がある。")
    else:
        parts.append("5.4-miniの改善はあるが、全指標で安定して伸びるケースではない。")

    if ev54 >= 0.80 and ord54 >= 0.70 and prec54 >= 0.60:
        parts.append("5.4-miniでは証跡・順序・適合率が揃っており、発表では「再構成しやすい場面」の代表にできる。")
    elif ev54 >= 0.60 and ord54 >= 0.45:
        parts.append("主要行動は拾えているが、順序または余計な候補の混入が残る中難度ケース。")
    else:
        parts.append("証跡または順序が弱く、単に行動名を当てるだけでは正解にならない難ケース。")

    if prec54 < 0.50 or over54 >= 4:
        parts.append("余計な出力が多く、周辺ログや近接プロセスを根拠付き行動として広げすぎる傾向がある。")
    if ev55 >= 0.90:
        parts.append("GPT-5.5 low rawは内容回収は強いが、出力契約違反の救済採点なので、構造化出力条件の結果とは分けて扱う。")
    return "".join(parts)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows = read_csv(LEDGER)
    case_meta = load_case_meta()
    for r in rows:
        cm = case_meta.setdefault(r["chain_id"], {"chain_id": r["chain_id"]})
        cm["framework_group"] = r.get("framework_group") or cm.get("framework_group", "")
        cm["scenario_group"] = r.get("scenario_group") or cm.get("scenario_group", "")

    by_chain_model = aggregate(rows, ["chain_id", "model"])
    by_chain_model_stage = aggregate(rows, ["chain_id", "model", "stage"])

    for r in by_chain_model + by_chain_model_stage:
        cm = case_meta.get(r["chain_id"], {})
        gm = load_gold_meta(r["chain_id"])
        r.update(cm)
        r.update(gm)

    write_csv(
        OUT / "by_usecase_model.csv",
        by_chain_model,
        [
            "chain_id",
            "chain_title",
            "expected_behavior",
            "chain_type",
            "scenario_group",
            "framework_group",
            "model",
            "run_count",
            "replicate_count",
            "stage_count",
            "gold_step_count",
            "action_step_recall",
            "critical_evidence_recall",
            "behavior_sequence_order",
            "candidate_claim_precision",
            "overclaim_slot_count",
            "overclaim_per_run",
            "gold_subjects",
            "gold_objects",
        ],
    )
    write_csv(
        OUT / "by_usecase_model_stage.csv",
        by_chain_model_stage,
        [
            "chain_id",
            "chain_title",
            "expected_behavior",
            "model",
            "stage",
            "run_count",
            "replicate_count",
            "gold_step_count",
            "action_step_recall",
            "critical_evidence_recall",
            "behavior_sequence_order",
            "candidate_claim_precision",
            "overclaim_slot_count",
            "overclaim_per_run",
        ],
    )

    by_key = {(r["chain_id"], r["model"]): r for r in by_chain_model}
    summary_rows = []
    for chain in sorted(case_meta):
        g41 = by_key.get((chain, "gpt-4.1-mini"))
        g54 = by_key.get((chain, "gpt-5.4-mini"))
        g55 = by_key.get((chain, "gpt-5.5 low raw"))
        cm = case_meta[chain]
        gm = load_gold_meta(chain)
        row = {
            "chain_id": chain,
            "chain_title": gm.get("chain_title") or cm.get("expected_behavior", ""),
            "expected_behavior": cm.get("expected_behavior", ""),
            "scenario_group": cm.get("scenario_group", ""),
            "framework_group": cm.get("framework_group", ""),
            "gold_step_count": gm.get("gold_step_count", ""),
            "gold_subjects": gm.get("gold_subjects", ""),
            "gold_objects": gm.get("gold_objects", ""),
            "difficulty_label": classify_usecase(g54, g41, g55),
            "interpretation": interpretation(chain, g41, g54, g55),
        }
        for prefix, g in [("g41", g41), ("g54", g54), ("g55raw", g55)]:
            for metric in ["action_step_recall", "critical_evidence_recall", "behavior_sequence_order", "candidate_claim_precision", "overclaim_per_run"]:
                row[f"{prefix}_{metric}"] = g.get(metric, "") if g else ""
        if g41 and g54:
            row["delta_g54_minus_g41_action"] = fmt(float(g54["action_step_recall"]) - float(g41["action_step_recall"]), 3)
            row["delta_g54_minus_g41_evidence"] = fmt(float(g54["critical_evidence_recall"]) - float(g41["critical_evidence_recall"]), 3)
        summary_rows.append(row)

    write_csv(
        OUT / "usecase_interpretation_matrix.csv",
        summary_rows,
        [
            "chain_id",
            "chain_title",
            "expected_behavior",
            "scenario_group",
            "framework_group",
            "gold_step_count",
            "difficulty_label",
            "g41_action_step_recall",
            "g41_critical_evidence_recall",
            "g41_behavior_sequence_order",
            "g41_candidate_claim_precision",
            "g41_overclaim_per_run",
            "g54_action_step_recall",
            "g54_critical_evidence_recall",
            "g54_behavior_sequence_order",
            "g54_candidate_claim_precision",
            "g54_overclaim_per_run",
            "g55raw_action_step_recall",
            "g55raw_critical_evidence_recall",
            "g55raw_behavior_sequence_order",
            "g55raw_candidate_claim_precision",
            "g55raw_overclaim_per_run",
            "delta_g54_minus_g41_action",
            "delta_g54_minus_g41_evidence",
            "gold_subjects",
            "gold_objects",
            "interpretation",
        ],
    )

    write_markdown(summary_rows, by_chain_model_stage)


def write_markdown(summary_rows, stage_rows):
    stage_by_chain_model = defaultdict(list)
    for r in stage_rows:
        stage_by_chain_model[(r["chain_id"], r["model"])].append(r)

    lines = []
    lines.append("# ユースケース別詳細考察 2026-06-14")
    lines.append("")
    lines.append("集計単位は1ユースケース単位。gpt-4.1-mini / gpt-5.4-miniは各ユースケースにつき3ステージ x 3 source set = 9行平均。gpt-5.5 low rawは3ステージ x 1周 = 3行平均で、構造化出力に失敗した素の出力を救済採点した参考値。")
    lines.append("")
    lines.append("## 読み方")
    lines.append("")
    lines.append("- `action`: 主体・行動・対象の内容再現率。")
    lines.append("- `evidence`: 重要証跡の再現率。")
    lines.append("- `order`: 行動列の順序再現率。")
    lines.append("- `precision`: 候補として出した主張の適合率。")
    lines.append("- `over/run`: 1 runあたりの余計な主張数。")
    lines.append("")
    lines.append("## 難度ラベル別の件数")
    lines.append("")
    counts = defaultdict(int)
    for r in summary_rows:
        counts[r["difficulty_label"]] += 1
    for k in sorted(counts):
        lines.append(f"- `{k}`: {counts[k]}ユースケース")
    lines.append("")
    lines.append("## 代表的な読み取り")
    lines.append("")
    lines.append("- SimpleHTTPServer系は、IP/portなど通信先まで証跡として拾えるケースでは5.4-miniが高く、再構成しやすい場面の代表。")
    lines.append("- DNS packet capture系は、`start_dns_logs.bat` と `tshark.exe` の境界を広げすぎやすく、actionは上がってもprecisionが伸びにくい。")
    lines.append("- Sublime/Python script系は、cmd/pythonの重複ステップが多く、証跡は拾えても順序スコアが低くなりやすい。")
    lines.append("- Discord Run keyは、レジストリ永続化という意味づけが必要で、短い3ステップでも難ケースとして残る。")
    lines.append("")
    lines.append("## ユースケース別メモ")
    lines.append("")

    def metric_row(label, row):
        if not row:
            return f"| {label} | - | - | - | - | - |"
        return (
            f"| {label} | {row.get('action_step_recall','')} | {row.get('critical_evidence_recall','')} | "
            f"{row.get('behavior_sequence_order','')} | {row.get('candidate_claim_precision','')} | {row.get('overclaim_per_run','')} |"
        )

    by_key = {}
    chain_model_rows = read_csv(OUT / "by_usecase_model.csv")
    for r in chain_model_rows:
        by_key[(r["chain_id"], r["model"])] = r

    for i, r in enumerate(summary_rows, 1):
        chain = r["chain_id"]
        lines.append(f"### {i}. {chain}")
        lines.append("")
        lines.append(f"- 場面: {r['chain_title'] or r['expected_behavior']}")
        lines.append(f"- 分類: `{r['scenario_group']}` / `{r['framework_group']}`")
        lines.append(f"- 正解ステップ数: {r['gold_step_count']}")
        lines.append(f"- 正解の骨子: `{r['gold_subjects']}` -> `{r['gold_objects']}`")
        lines.append(f"- 難度ラベル: `{r['difficulty_label']}`")
        lines.append(f"- 何を見る場面か: {usecase_story(r)}")
        lines.append("")
        lines.append("| model | action | evidence | order | precision | over/run |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        lines.append(metric_row("gpt-4.1-mini", by_key.get((chain, "gpt-4.1-mini"))))
        lines.append(metric_row("gpt-5.4-mini", by_key.get((chain, "gpt-5.4-mini"))))
        lines.append(metric_row("gpt-5.5 low raw", by_key.get((chain, "gpt-5.5 low raw"))))
        lines.append("")
        lines.append(f"考察: {japanese_interpretation(r)}")
        lines.append("")
        lines.append("gpt-5.4-miniのステージ別パターン:")
        lines.append("")
        lines.append("| stage | action | evidence | order | precision | over/run |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for sr in sorted(stage_by_chain_model.get((chain, "gpt-5.4-mini"), []), key=lambda x: x["stage"]):
            lines.append(
                f"| {sr['stage']} | {sr['action_step_recall']} | {sr['critical_evidence_recall']} | "
                f"{sr['behavior_sequence_order']} | {sr['candidate_claim_precision']} | {sr['overclaim_per_run']} |"
            )
        lines.append("")

    (OUT / "usecase_deep_dive.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
