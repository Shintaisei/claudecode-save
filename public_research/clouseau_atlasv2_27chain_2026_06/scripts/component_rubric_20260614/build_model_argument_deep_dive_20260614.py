import csv
import ast
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path("docs/current_experiment/handoff_20260614_component_rubric_experiment")
LEDGER = ROOT / "03_aggregated_results" / "ledgers" / "final_comparison_per_run_component_scores.csv"
OUT = ROOT / "04_discussion_base" / "model_argument_deep_dive_20260614"
RAW_ROOT = ROOT / "01_experiment_raw_outputs"
USECASE_MATRIX = ROOT / "04_discussion_base" / "usecase_deep_dive_20260614" / "usecase_interpretation_matrix.csv"


MOJIBAKE_MARKERS = ("縺", "蜿", "蠕", "騾", "荳", "譁", "髯", "邏", "噪", "繝")
MODEL_ORDER = {"gpt-4.1-mini": 0, "gpt-5.4-mini": 1, "gpt-5.5 low raw": 2}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def clean_text(value):
    text = "" if value is None else str(value)
    if any(marker in text for marker in MOJIBAKE_MARKERS):
        return ""
    return re.sub(r"\s+", " ", text).strip()


def clean_source_stream(value):
    text = "" if value is None else str(value).strip()
    low = text.lower()
    if low.startswith("cbc-ng"):
        return "cbc-ngav"
    if low.startswith("cbc-edr-alert"):
        return "cbc-edr-alerts"
    if low.startswith("cbc-ngav-alert"):
        return "cbc-ngav-alerts"
    if low.startswith("cbc-edr"):
        return "cbc-edr"
    if any(marker in text for marker in MOJIBAKE_MARKERS):
        return ""
    return clean_text(text)


def fmt(v, digits=3):
    if v == "" or v is None:
        return ""
    return f"{float(v):.{digits}f}"


def safe_json_loads(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except Exception:
            return None
    return None


def extract_raw_text(text):
    if not text:
        return ""
    parsed = safe_json_loads(text)
    if isinstance(parsed, list):
        return "\n".join(clean_text(x.get("text") or x.get("content") or "") for x in parsed if isinstance(x, dict))
    try:
        lit = ast.literal_eval(text)
        if isinstance(lit, list):
            return "\n".join(clean_text(x.get("text") or x.get("content") or "") for x in lit if isinstance(x, dict))
    except Exception:
        pass
    return clean_text(text)


def raw_claims(text):
    claims = []
    for line in text.splitlines():
        line = clean_text(line.strip(" #|-"))
        if not line:
            continue
        if any(key in line for key in ["仮説", "観測事実", "結論", "復元", "code_steps", "時系列", "QAAgent"]):
            claims.append(line[:220])
        if len(claims) >= 6:
            break
    return claims


def resolve_run_path(row):
    if row.get("run_json"):
        p = Path(row["run_json"])
        if p.exists():
            return p
        # Prefer the handoff copy when the original results path moved.
        parts = p.parts
        if "formal_23_chain_experiment_2rep_20260612" in parts:
            rep = row.get("replicate") or "replicate_01"
            model = row["model"].replace(" low raw", "")
            return RAW_ROOT / "f23_2rep" / rep / model / row["stage"] / f"{row['chain_id']}_{row['stage']}_run.json"
        if "formal_23_chain_gpt55_low_3rep_20260613" in parts:
            return RAW_ROOT / "gpt55_r1" / "replicate_01" / "gpt-5.5" / row["stage"] / f"{row['chain_id']}_{row['stage']}_run.json"
    if row.get("source_set") == "formal_27_chain_20260609_filtered_to_current_23":
        return RAW_ROOT / "legacy27_raw" / "legacy27" / row["model"] / row["stage"] / f"{row['chain_id']}_{row['stage']}_run.json"
    return None


def parse_run_output(path):
    if not path or not path.exists():
        return {"parse_status": "missing", "steps": [], "limits": [], "excluded": [], "alerts": [], "timeline": [], "raw_excerpt": ""}
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"parse_status": "bad_run_json", "steps": [], "limits": [], "excluded": [], "alerts": [], "timeline": [], "raw_excerpt": ""}
    text = d.get("output_text") or ""
    obj = safe_json_loads(text)
    if not isinstance(obj, dict):
        return {
            "parse_status": "raw_unparsed",
            "steps": [],
            "limits": [],
            "excluded": [],
            "alerts": [],
            "timeline": [],
            "raw_text": extract_raw_text(text),
            "raw_excerpt": clean_text(extract_raw_text(text)[:1200]),
        }
    return {
        "parse_status": "parsed_json",
        "steps": obj.get("code_steps") or [],
        "limits": obj.get("global_limitations") or [],
        "excluded": obj.get("excluded_nearby_evidence") or [],
        "alerts": obj.get("supporting_alert_evidence") or [],
        "timeline": obj.get("timeline_ja") or [],
        "raw_text": "",
        "raw_excerpt": "",
    }


def step_text(step):
    bits = []
    subj = step.get("subject_process") or {}
    obj = step.get("object") or {}
    ctx = step.get("execution_context") or {}
    for value in [
        subj.get("name"),
        step.get("operation"),
        obj.get("type"),
        obj.get("name"),
        obj.get("path"),
        obj.get("value"),
        obj.get("data"),
        step.get("command_line"),
        ctx.get("parent_process"),
        ctx.get("child_process"),
    ]:
        if value:
            bits.append(str(value))
    return " ".join(bits)


def categories_for_text(text):
    low = text.lower()
    cats = []
    if any(x in low for x in ["simplehttpserver", "http server", "10.193.", ":581", ":392", ":548", ":516", ":485", ":491", ":582", ":413"]):
        cats.append("network_service_or_http_server")
    if any(x in low for x in ["run\\discord", "currentversion\\run", "reg.exe", "registry", "レジストリ"]):
        cats.append("registry_persistence")
    if any(x in low for x in ["start_dns_logs", "tshark", "dumpcap", "dns"]):
        cats.append("dns_capture_or_collection")
    if any(x in low for x in ["sublime", "plugin_host", "helloworld.py", "hello.py"]):
        cats.append("script_execution_chain")
    if any(x in low for x in ["cmd.exe", ".bat", "run_http_server"]):
        cats.append("shell_or_batch_execution")
    if "nvidia-smi" in low:
        cats.append("gpu_tool_command")
    if any(x in low for x in ["cbc-edr-alert", "cbc-ngav-alert", "alert_id", "alert"]):
        cats.append("alert_reference")
    if any(x in low for x in ["除外", "excluded", "直接証拠ではない", "code_steps から除外"]):
        cats.append("boundary_exclusion")
    return cats or ["other"]


def short_claim(step):
    subj = clean_text((step.get("subject_process") or {}).get("name"))
    op = clean_text(step.get("operation"))
    obj = step.get("object") or {}
    target = clean_text(obj.get("name") or obj.get("path") or obj.get("value") or obj.get("data"))
    cmd = clean_text(step.get("command_line"))
    if len(cmd) > 120:
        cmd = cmd[:117] + "..."
    parts = [x for x in [subj, op, target or cmd] if x]
    return " / ".join(parts)[:220]


def summarize_categories(counter):
    return "; ".join(f"{k}:{v}" for k, v in counter.most_common(6))


def load_usecase_meta():
    meta = {}
    if USECASE_MATRIX.exists():
        for r in read_csv(USECASE_MATRIX):
            meta[r["chain_id"]] = r
    return meta


def qualitative_note(chain_id, model, row, meta):
    cats = set((row.get("top_argument_categories") or "").split("; "))
    title = meta.get(chain_id, {}).get("chain_title", chain_id)
    precision = float(row.get("candidate_claim_precision") or 0)
    evidence = float(row.get("critical_evidence_recall") or 0)
    order = float(row.get("behavior_sequence_order") or 0)
    over = float(row.get("overclaim_per_run") or 0)
    notes = []
    if "network_service_or_http_server" in " ".join(cats):
        notes.append("HTTPサーバ起動/通信先を中心論点にしている。")
    if "dns_capture_or_collection" in " ".join(cats):
        notes.append("DNS収集、bat、tshark周辺をまとめて論点化している。")
    if "registry_persistence" in " ".join(cats):
        notes.append("Runキー/registry操作を永続化の論点として扱っている。")
    if "script_execution_chain" in " ".join(cats):
        notes.append("Sublimeからcmd/python/scriptへ至る実行連鎖を論点化している。")
    if "gpu_tool_command" in " ".join(cats):
        notes.append("Discord起点のnvidia-smi実行をコマンド実行論点として扱っている。")
    if "boundary_exclusion" in " ".join(cats):
        notes.append("近傍ログを除外する境界判断にも触れている。")
    if evidence < 0.55:
        notes.append("ただし証跡の当て方が弱く、論点名だけ先に立っている可能性がある。")
    if order < 0.40:
        notes.append("順序が弱く、複数ステップを正しい行動列として並べる部分に課題がある。")
    if precision < 0.50 or over >= 4:
        notes.append("余計な候補を広げすぎる傾向が強い。")
    if model == "gpt-5.5 low raw":
        notes.append("raw救済採点なので、内容論点の参考値として扱う。")
    return "".join(notes) or f"{title}に関する主要行動を論点化している。"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ledger = read_csv(LEDGER)
    meta = load_usecase_meta()
    extracted = []
    for r in ledger:
        path = resolve_run_path(r)
        parsed = parse_run_output(path)
        cat_counter = Counter()
        op_counter = Counter()
        source_counter = Counter()
        claims = []
        for step in parsed["steps"]:
            text = step_text(step)
            for c in categories_for_text(text):
                cat_counter[c] += 1
            op = clean_text(step.get("operation"))
            if op:
                op_counter[op] += 1
            for ev in step.get("evidence") or []:
                ss = clean_source_stream(ev.get("source_stream"))
                if ss:
                    source_counter[ss] += 1
            claim = short_claim(step)
            if claim:
                claims.append(claim)
        for item in parsed["limits"] + parsed["excluded"] + parsed["alerts"] + parsed["timeline"]:
            for c in categories_for_text(clean_text(item)):
                cat_counter[c] += 1
        if parsed.get("raw_text"):
            raw = parsed["raw_text"]
            for c in categories_for_text(raw):
                cat_counter[c] += 1
            for claim in raw_claims(raw):
                claims.append(claim)
            for source in ["msft-security", "sysmon", "cbc-edr", "cbc-ngav", "cbc-edr-alerts", "cbc-ngav-alerts", "dns_requests"]:
                n = raw.lower().count(source)
                if n:
                    source_counter[source] += n
        extracted.append(
            {
                "chain_id": r["chain_id"],
                "model": r["model"],
                "stage": r["stage"],
                "replicate": r.get("replicate", ""),
                "source_set": r.get("source_set", ""),
                "parse_status": parsed["parse_status"],
                "step_count": len(parsed["steps"]),
                "argument_categories": summarize_categories(cat_counter),
                "operations": summarize_categories(op_counter),
                "evidence_sources": summarize_categories(source_counter),
                "representative_claims": " || ".join(claims[:4]),
                "limitations_or_exclusions": " || ".join(clean_text(x) for x in (parsed["limits"] + parsed["excluded"])[:4] if clean_text(x)),
                "raw_excerpt": parsed["raw_excerpt"],
                "action_step_recall": r.get("action_step_recall", ""),
                "critical_evidence_recall": r.get("critical_evidence_recall", ""),
                "behavior_sequence_order": r.get("behavior_sequence_order", ""),
                "candidate_claim_precision": r.get("candidate_claim_precision", ""),
                "overclaim_slot_count": r.get("overclaim_slot_count", ""),
                "candidate_step_count": r.get("candidate_step_count", ""),
            }
        )

    write_csv(
        OUT / "per_run_argument_extraction.csv",
        extracted,
        [
            "chain_id",
            "model",
            "stage",
            "replicate",
            "source_set",
            "parse_status",
            "step_count",
            "argument_categories",
            "operations",
            "evidence_sources",
            "representative_claims",
            "limitations_or_exclusions",
            "raw_excerpt",
            "action_step_recall",
            "critical_evidence_recall",
            "behavior_sequence_order",
            "candidate_claim_precision",
            "overclaim_slot_count",
            "candidate_step_count",
        ],
    )

    buckets = defaultdict(list)
    for r in extracted:
        buckets[(r["chain_id"], r["model"])].append(r)

    summary = []
    for (chain, model), items in sorted(buckets.items(), key=lambda kv: (kv[0][0], MODEL_ORDER.get(kv[0][1], 9))):
        cat = Counter()
        ops = Counter()
        src = Counter()
        claims = Counter()
        limits = Counter()
        parse = Counter()
        for it in items:
            parse[it["parse_status"]] += 1
            for field, counter in [("argument_categories", cat), ("operations", ops), ("evidence_sources", src)]:
                for part in it[field].split("; "):
                    if not part or ":" not in part:
                        continue
                    k, v = part.rsplit(":", 1)
                    counter[k] += int(v)
            for claim in it["representative_claims"].split(" || "):
                if claim:
                    claims[claim] += 1
            for lim in it["limitations_or_exclusions"].split(" || "):
                if lim:
                    limits[lim] += 1
        def avg(field):
            vals = [float(x[field]) for x in items if x.get(field) not in ("", None)]
            return sum(vals) / len(vals) if vals else 0.0
        row = {
            "chain_id": chain,
            "chain_title": meta.get(chain, {}).get("chain_title", chain),
            "model": model,
            "run_count": len(items),
            "parse_status_counts": summarize_categories(parse),
            "top_argument_categories": summarize_categories(cat),
            "top_operations": summarize_categories(ops),
            "top_evidence_sources": summarize_categories(src),
            "representative_claims": " || ".join(c for c, _ in claims.most_common(5)),
            "representative_limitations_or_exclusions": " || ".join(c for c, _ in limits.most_common(4)),
            "action_step_recall": fmt(avg("action_step_recall")),
            "critical_evidence_recall": fmt(avg("critical_evidence_recall")),
            "behavior_sequence_order": fmt(avg("behavior_sequence_order")),
            "candidate_claim_precision": fmt(avg("candidate_claim_precision")),
            "overclaim_per_run": fmt(sum(float(x["overclaim_slot_count"] or 0) for x in items) / len(items), 2),
        }
        row["qualitative_note"] = qualitative_note(chain, model, row, meta)
        summary.append(row)

    write_csv(
        OUT / "by_usecase_model_argument_summary.csv",
        summary,
        [
            "chain_id",
            "chain_title",
            "model",
            "run_count",
            "parse_status_counts",
            "top_argument_categories",
            "top_operations",
            "top_evidence_sources",
            "representative_claims",
            "representative_limitations_or_exclusions",
            "action_step_recall",
            "critical_evidence_recall",
            "behavior_sequence_order",
            "candidate_claim_precision",
            "overclaim_per_run",
            "qualitative_note",
        ],
    )

    write_markdown(summary, meta)


def write_markdown(summary, meta):
    by_chain = defaultdict(list)
    for r in summary:
        by_chain[r["chain_id"]].append(r)

    lines = []
    lines.append("# モデル論点の詳細考察 2026-06-14")
    lines.append("")
    lines.append("目的は、スコアではなく「モデルが何を論点として出したか」を見ること。`code_steps`、`operation`、`object`、`evidence`、`global_limitations`、`excluded_nearby_evidence` を抽出し、ユースケース別・モデル別に集約した。")
    lines.append("")
    lines.append("## 全体の読み取り")
    lines.append("")
    lines.append("- 5.4-miniは、SimpleHTTPServerのような短い実行連鎖では、プロセス・コマンド・通信先を論点として安定して出す。")
    lines.append("- DNS/bat/tshark系では、モデルはDNS収集という大枠の論点を出せるが、cmd、bat、tshark、近傍python/http serverを同一行動列に広げやすい。")
    lines.append("- Sublime/Python系では、Sublime、cmd、python、script fileという論点は出るが、重複cmd/pythonの順序付けが難しい。")
    lines.append("- Discord Run keyでは、registry/Run keyという論点は出るが、query/addと永続化設定の意味づけ、親Discordとの接続が揺れる。")
    lines.append("- gpt-5.5 low rawは論点の網羅は強いが、raw救済採点であり、運用面では構造化出力失敗と費用が大きな制約になる。")
    lines.append("")
    lines.append("## ユースケース別")
    lines.append("")

    for i, chain in enumerate(sorted(by_chain), 1):
        title = meta.get(chain, {}).get("chain_title", chain)
        lines.append(f"### {i}. {chain}")
        lines.append("")
        lines.append(f"- 場面: {title}")
        lines.append(f"- 正解ステップ数: {meta.get(chain, {}).get('gold_step_count', '')}")
        lines.append("")
        lines.append("| model | runs | 論点カテゴリ | operation傾向 | evidence source | precision | over/run |")
        lines.append("| --- | ---: | --- | --- | --- | ---: | ---: |")
        for r in sorted(by_chain[chain], key=lambda x: MODEL_ORDER.get(x["model"], 9)):
            lines.append(
                f"| {r['model']} | {r['run_count']} | {r['top_argument_categories']} | {r['top_operations']} | "
                f"{r['top_evidence_sources']} | {r['candidate_claim_precision']} | {r['overclaim_per_run']} |"
            )
        lines.append("")
        for r in sorted(by_chain[chain], key=lambda x: MODEL_ORDER.get(x["model"], 9)):
            claims = r["representative_claims"] or "-"
            if len(claims) > 650:
                claims = claims[:647] + "..."
            lines.append(f"**{r['model']}の論点。** {r['qualitative_note']}")
            lines.append("")
            lines.append(f"代表的な主張: {claims}")
            if r["representative_limitations_or_exclusions"]:
                lim = r["representative_limitations_or_exclusions"]
                if len(lim) > 500:
                    lim = lim[:497] + "..."
                lines.append(f"境界判断/限界: {lim}")
            lines.append("")

    (OUT / "model_argument_deep_dive.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
