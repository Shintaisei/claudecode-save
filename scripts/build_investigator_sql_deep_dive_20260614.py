import ast
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path("docs/current_experiment/handoff_20260614_component_rubric_experiment")
OUT = ROOT / "04_discussion_base" / "investigator_sql_deep_dive_20260614"
LEDGER = ROOT / "03_aggregated_results" / "ledgers" / "final_comparison_per_run_component_scores.csv"
ARG_PER_RUN = ROOT / "04_discussion_base" / "model_argument_deep_dive_20260614" / "per_run_argument_extraction.csv"
USECASE_MATRIX = ROOT / "04_discussion_base" / "usecase_deep_dive_20260614" / "usecase_interpretation_matrix.csv"
RAW_ROOT = ROOT / "01_experiment_raw_outputs"


MODEL_ORDER = {"gpt-4.1-mini": 0, "gpt-5.4-mini": 1, "gpt-5.5 low raw": 2}
CATEGORY_TERMS = {
    "network_service_or_http_server": ["simplehttpserver", "http", "server", "remote_ip", "remote_port", "10.193."],
    "registry_persistence": ["reg.exe", "registry", "run key", "currentversion\\run", "hkcu", "regmod", "永続"],
    "dns_capture_or_collection": ["dns", "tshark", "dumpcap", "start_dns_logs", "packet"],
    "script_execution_chain": ["sublime", "plugin_host", "python", "hello.py", "helloworld.py", "script"],
    "shell_or_batch_execution": ["cmd.exe", ".bat", "batch", "run_http_server"],
    "gpu_tool_command": ["nvidia-smi"],
}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def fmt(v, digits=3):
    return f"{float(v):.{digits}f}"


def clean_text(value):
    text = "" if value is None else str(value)
    return re.sub(r"\s+", " ", text).strip()


def extract_text_payload(text):
    if not text:
        return ""
    try:
        obj = ast.literal_eval(text)
        if isinstance(obj, list):
            return "\n".join(clean_text(x.get("text") or x.get("content") or "") for x in obj if isinstance(x, dict))
    except Exception:
        pass
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return "\n".join(clean_text(x.get("text") or x.get("content") or "") for x in obj if isinstance(x, dict))
    except Exception:
        pass
    return text


def resolve_run_path(row):
    if row.get("run_json"):
        p = Path(row["run_json"])
        if p.exists():
            return p
        if "formal_23_chain_experiment_2rep_20260612" in row["run_json"]:
            return RAW_ROOT / "f23_2rep" / row.get("replicate", "replicate_01") / row["model"] / row["stage"] / f"{row['chain_id']}_{row['stage']}_run.json"
        if "formal_23_chain_gpt55_low_3rep_20260613" in row["run_json"]:
            return RAW_ROOT / "gpt55_r1" / "replicate_01" / "gpt-5.5" / row["stage"] / f"{row['chain_id']}_{row['stage']}_run.json"
    if row.get("source_set") == "formal_27_chain_20260609_filtered_to_current_23":
        return RAW_ROOT / "legacy27_raw" / "legacy27" / row["model"] / row["stage"] / f"{row['chain_id']}_{row['stage']}_run.json"
    return None


def run_output_text(path):
    if not path or not path.exists():
        return ""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return extract_text_payload(d.get("output_text") or "")
    except Exception:
        return ""


def categories(text):
    low = text.lower()
    out = []
    for name, terms in CATEGORY_TERMS.items():
        if any(t in low for t in terms):
            out.append(name)
    return out or ["other"]


def gold_terms(row):
    terms = []
    for field in ["gold_subjects", "gold_objects", "chain_title", "expected_behavior"]:
        for token in re.split(r"[|> /\\\\\"'(),]+", row.get(field, "")):
            token = token.strip()
            if len(token) >= 4 and not token.endswith(".exe"):
                terms.append(token.lower())
            elif token.lower().endswith(".exe"):
                terms.append(token.lower())
    return sorted(set(terms))


def quality_flags(text):
    low = text.lower()
    flags = []
    if re.search(r"\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}", text):
        flags.append("time_window_or_timestamp")
    if any(x in low for x in ["pid", "ppid", "process_name", "pname", "parent_process"]):
        flags.append("process_identity")
    if "command_line" in low or "command line" in low:
        flags.append("command_line")
    if any(x in low for x in ["source_stream", "cbc-edr", "msft-security", "sysmon", "dns_requests"]):
        flags.append("source_stream")
    if any(x in low for x in ["event_record_id", "source_row_id", "alert_id"]):
        flags.append("row_identifier")
    if any(x in low for x in ["parent", "child", "親", "子"]):
        flags.append("parent_child_relation")
    if "select " in low or " from " in low or " where " in low:
        flags.append("sql_leak_in_question")
    if any(x in low for x in ["alert summary", "cbc alert summary"]):
        flags.append("alert_summary_reference")
    return flags


def extract_gpt55_qa(row, text, meta_terms):
    rows = []
    if not text:
        return rows
    blocks = re.split(r"\n(?=## |### )", text)
    current_hypothesis = ""
    question_index = 0
    for block in blocks:
        header = clean_text(block.splitlines()[0] if block.splitlines() else "")
        body = clean_text(block)
        if "仮説" in header or "調査仮説" in header:
            current_hypothesis = body[:800]
        if "質問" in header or "QAAgent" in header:
            question_index += 1
            qtext = body[:1200]
            flags = quality_flags(qtext)
            matched = [t for t in meta_terms if t and t in qtext.lower()]
            cat = categories(qtext)
            rows.append(
                {
                    "chain_id": row["chain_id"],
                    "model": row["model"],
                    "stage": row["stage"],
                    "replicate": row.get("replicate", ""),
                    "question_index": question_index,
                    "hypothesis_excerpt": current_hypothesis[:360],
                    "question_excerpt": qtext[:520],
                    "categories": ";".join(cat),
                    "quality_flags": ";".join(flags),
                    "gold_term_hits": ";".join(matched[:12]),
                    "gold_term_hit_count": len(matched),
                    "asks_sql_directly": "yes" if "sql_leak_in_question" in flags else "no",
                    "uses_alert_summary": "yes" if "alert_summary_reference" in flags else "no",
                }
            )
    # Some outputs put the whole report under one "仮説" section with inline questions.
    if not rows:
        for i, m in enumerate(re.finditer(r"(QAAgent.*?|質問\s*\d*).*?(?=(QAAgent|質問\s*\d*|結果要約|$))", text, flags=re.S), 1):
            qtext = clean_text(m.group(0))[:1200]
            flags = quality_flags(qtext)
            matched = [t for t in meta_terms if t and t in qtext.lower()]
            rows.append(
                {
                    "chain_id": row["chain_id"],
                    "model": row["model"],
                    "stage": row["stage"],
                    "replicate": row.get("replicate", ""),
                    "question_index": i,
                    "hypothesis_excerpt": "",
                    "question_excerpt": qtext[:520],
                    "categories": ";".join(categories(qtext)),
                    "quality_flags": ";".join(flags),
                    "gold_term_hits": ";".join(matched[:12]),
                    "gold_term_hit_count": len(matched),
                    "asks_sql_directly": "yes" if "sql_leak_in_question" in flags else "no",
                    "uses_alert_summary": "yes" if "alert_summary_reference" in flags else "no",
                }
            )
    return rows


def summarize_counter(counter, n=8):
    return "; ".join(f"{k}:{v}" for k, v in counter.most_common(n))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ledger = read_csv(LEDGER)
    arg_rows = read_csv(ARG_PER_RUN) if ARG_PER_RUN.exists() else []
    usecase = {r["chain_id"]: r for r in read_csv(USECASE_MATRIX)}

    availability = []
    qa_rows = []
    for r in ledger:
        p = resolve_run_path(r)
        text = run_output_text(p)
        has_structured = bool(text.strip().startswith("{"))
        has_raw_qa = any(k in text for k in ["QAAgent", "質問", "仮説", "調査仮説"])
        has_sql = "SELECT " in text.upper() or " FROM " in text.upper()
        availability.append(
            {
                "chain_id": r["chain_id"],
                "model": r["model"],
                "stage": r["stage"],
                "replicate": r.get("replicate", ""),
                "run_path_exists": "yes" if p and p.exists() else "no",
                "structured_final_json": "yes" if has_structured else "no",
                "raw_hypothesis_or_qa_visible": "yes" if has_raw_qa else "no",
                "sql_text_visible_in_output": "yes" if has_sql else "no",
                "runner_trace_log_available": "no",
            }
        )
        if r["model"] == "gpt-5.5 low raw":
            qa_rows.extend(extract_gpt55_qa(r, text, gold_terms(usecase.get(r["chain_id"], {}))))

    write_csv(
        OUT / "trace_availability.csv",
        availability,
        [
            "chain_id",
            "model",
            "stage",
            "replicate",
            "run_path_exists",
            "structured_final_json",
            "raw_hypothesis_or_qa_visible",
            "sql_text_visible_in_output",
            "runner_trace_log_available",
        ],
    )
    write_csv(
        OUT / "gpt55_raw_hypothesis_qa_extraction.csv",
        qa_rows,
        [
            "chain_id",
            "model",
            "stage",
            "replicate",
            "question_index",
            "hypothesis_excerpt",
            "question_excerpt",
            "categories",
            "quality_flags",
            "gold_term_hits",
            "gold_term_hit_count",
            "asks_sql_directly",
            "uses_alert_summary",
        ],
    )

    # Downstream QA/SQL quality proxy from final evidence selection.
    buckets = defaultdict(list)
    for r in arg_rows:
        buckets[(r["chain_id"], r["model"])].append(r)
    qa_by_chain = defaultdict(list)
    for r in qa_rows:
        qa_by_chain[(r["chain_id"], r["model"])].append(r)

    summary = []
    for key, items in buckets.items():
        chain, model = key
        flags = Counter()
        cats = Counter()
        for q in qa_by_chain.get(key, []):
            for f in q["quality_flags"].split(";"):
                if f:
                    flags[f] += 1
            for c in q["categories"].split(";"):
                if c:
                    cats[c] += 1
        evidence_sources = Counter()
        for it in items:
            for part in it.get("evidence_sources", "").split("; "):
                if ":" in part:
                    k, v = part.rsplit(":", 1)
                    if k == "未確定":
                        k = "unresolved_source"
                    evidence_sources[k] += int(v)

        def avg(field):
            vals = [float(x[field]) for x in items if x.get(field) not in ("", None)]
            return sum(vals) / len(vals) if vals else 0.0

        row = {
            "chain_id": chain,
            "chain_title": usecase.get(chain, {}).get("chain_title", chain),
            "model": model,
            "run_count": len(items),
            "visible_qa_question_count": len(qa_by_chain.get(key, [])),
            "qa_quality_flags": summarize_counter(flags),
            "qa_categories": summarize_counter(cats),
            "final_evidence_sources": summarize_counter(evidence_sources),
            "action_step_recall": fmt(avg("action_step_recall")),
            "critical_evidence_recall": fmt(avg("critical_evidence_recall")),
            "behavior_sequence_order": fmt(avg("behavior_sequence_order")),
            "candidate_claim_precision": fmt(avg("candidate_claim_precision")),
            "overclaim_per_run": fmt(sum(float(x.get("overclaim_slot_count") or 0) for x in items) / len(items), 2),
        }
        row["investigator_sql_note"] = note_for_summary(row)
        summary.append(row)

    write_csv(
        OUT / "by_usecase_model_investigator_sql_summary.csv",
        sorted(summary, key=lambda r: (r["chain_id"], MODEL_ORDER.get(r["model"], 9))),
        [
            "chain_id",
            "chain_title",
            "model",
            "run_count",
            "visible_qa_question_count",
            "qa_quality_flags",
            "qa_categories",
            "final_evidence_sources",
            "action_step_recall",
            "critical_evidence_recall",
            "behavior_sequence_order",
            "candidate_claim_precision",
            "overclaim_per_run",
            "investigator_sql_note",
        ],
    )
    write_markdown(summary, availability, qa_rows, usecase)


def note_for_summary(row):
    model = row["model"]
    evidence = float(row["critical_evidence_recall"])
    precision = float(row["candidate_claim_precision"])
    order = float(row["behavior_sequence_order"])
    over = float(row["overclaim_per_run"])
    parts = []
    if row["visible_qa_question_count"] != "0" and int(row["visible_qa_question_count"]):
        parts.append("raw出力にInvestigator/QAAgent質問が残っており、仮説と確認項目を直接読める。")
    else:
        parts.append("中間質問・SQL実体は保存されていないため、最終証跡選択からの間接評価。")
    if evidence >= 0.75 and precision >= 0.60:
        parts.append("最終出力の証跡選択は正解証跡にかなり近い。")
    elif evidence >= 0.55:
        parts.append("主要証跡には届くが、余計な候補または順序の弱さが残る。")
    else:
        parts.append("探索論点は立つが、正解証跡への接続が弱い。")
    if order < 0.40:
        parts.append("複数結果の時系列統合が弱い。")
    if precision < 0.50 or over >= 4:
        parts.append("最終証跡選択が広がりすぎる、または近傍ログの切り分けが甘い。")
    if model == "gpt-5.5 low raw":
        parts.append("ただしraw救済であり構造化出力条件とは分ける。")
    return "".join(parts)


def write_markdown(summary, availability, qa_rows, usecase):
    by_chain = defaultdict(list)
    for r in summary:
        by_chain[r["chain_id"]].append(r)
    avail_counts = Counter((r["model"], r["raw_hypothesis_or_qa_visible"], r["sql_text_visible_in_output"]) for r in availability)
    lines = []
    lines.append("# Investigator / SQL 深掘り考察 2026-06-14")
    lines.append("")
    lines.append("この文書は、モデルの最終回答ではなく、CLOUSEAU内部の Investigator/QAAgent/SQL 探索がどの程度うまく働いたかを見るための補助分析である。")
    lines.append("")
    lines.append("## 重要な制約")
    lines.append("")
    lines.append("- 現在の正式23チェーンrunには、実行されたSQL文字列やrunner traceが保存されていない。")
    lines.append("- そのため、4.1-mini/5.4-miniのSQL精度は、最終 `code_steps` の証跡選択、証跡source、recall/precisionからの間接評価である。")
    lines.append("- GPT-5.5 low rawは構造化出力に失敗したが、69 run中66 runでは本文中にQA/質問材料が残っている。仮説や結果要約も多くのrunで復元できるが、すべてのrunで3点セットが揃うわけではない。残り3 runではraw QAは可視ではない。")
    lines.append("- SQLが「正しく書けたか」は評価できない。ここで見るのは、最終出力の証跡選択が正解証跡に届いたか、余計なログを拾いすぎたか、rawに残った仮説が正解行動を含んでいたかである。")
    lines.append("- `final evidence sources` は最終出力に記載されたsource_streamの集計であり、実際にSQLで取得した行数やbackend query coverageではない。未正規化の件数なので、特に長文rawのGPT-5.5では多く見えやすい。")
    lines.append("- GPT-5.5 low rawは1 replicateかつ出力契約失敗の救済採点であり、207 structured runsの4.1/5.4と形式的に同列比較しない。表中のGPT-5.5行は質問設計と内容回収の参考値である。")
    lines.append("")
    lines.append("## Trace Availability")
    lines.append("")
    lines.append("| model | raw QA visible | SQL text visible | rows |")
    lines.append("| --- | --- | --- | ---: |")
    for (model, raw, sql), n in sorted(avail_counts.items(), key=lambda x: (MODEL_ORDER.get(x[0][0], 9), x[0][1], x[0][2])):
        lines.append(f"| {model} | {raw} | {sql} | {n} |")
    lines.append("")
    lines.append("## 全体の読み取り")
    lines.append("")
    lines.append("- 5.4-miniは、最終出力の証跡選択を見る限り、SimpleHTTPServer系ではプロセス、command_line、通信先に届きやすい。")
    lines.append("- DNS/bat/tshark系は、最終証跡選択として近傍ログを広く採用し、`run_http_server.bat` やpython/http serverまで混ぜやすい。")
    lines.append("- Sublime/Python系は、Sublime、cmd、python、script fileを拾えるが、重複cmd/pythonの時系列統合が弱い。")
    lines.append("- Discord Run keyは、GPT-5.5 rawを見ると、Investigatorはまずmsft-securityのreg.exe DLL accessを拾い、その後PID 5424/5504でCBC EDR/NGAVに掘り下げる流れを作っている。この探索方針は妥当そうに見えるが、5.4-miniの構造化最終出力ではquery/addの片方や順序が揺れる。")
    lines.append("- Stage3ではCBC alert summaryがSQL toolから隠されるが、CBC EDR/NGAV telemetryは残る。したがって、Stage3の成功は「alert文面なしでもtelemetryから復元できた」ことを意味し、CBC全除去条件ではない。")
    lines.append("")
    lines.extend(gpt55_complete_examples(qa_rows))
    lines.append("")

    lines.append("## ユースケース別")
    lines.append("")
    for i, chain in enumerate(sorted(by_chain), 1):
        title = usecase.get(chain, {}).get("chain_title", chain)
        lines.append(f"### {i}. {chain}")
        lines.append("")
        lines.append(f"- 場面: {title}")
        lines.append(f"- 正解ステップ数: {usecase.get(chain, {}).get('gold_step_count', '')}")
        lines.append("")
        lines.append("| model | runs | visible QA | evidence | order | precision | over/run | final evidence sources |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
        for r in sorted(by_chain[chain], key=lambda x: MODEL_ORDER.get(x["model"], 9)):
            lines.append(
                f"| {r['model']} | {r['run_count']} | {r['visible_qa_question_count']} | {r['critical_evidence_recall']} | "
                f"{r['behavior_sequence_order']} | {r['candidate_claim_precision']} | {r['overclaim_per_run']} | {r['final_evidence_sources']} |"
            )
        lines.append("")
        for r in sorted(by_chain[chain], key=lambda x: MODEL_ORDER.get(x["model"], 9)):
            lines.append(f"**{r['model']}。** {r['investigator_sql_note']}")
            if r["qa_quality_flags"]:
                lines.append(f"QA質問の特徴: {r['qa_quality_flags']}")
            if r["qa_categories"]:
                lines.append(f"QA論点カテゴリ: {r['qa_categories']}")
            lines.append("")

        g55_examples = [q for q in qa_rows if q["chain_id"] == chain][:2]
        if g55_examples:
            lines.append("GPT-5.5 rawに残った質問例:")
            for q in g55_examples:
                lines.append(f"- {q['question_excerpt']}")
            lines.append("")

    (OUT / "investigator_sql_deep_dive.md").write_text("\n".join(lines), encoding="utf-8")


def gpt55_complete_examples(qa_rows):
    targets = [
        ("chain_10_e07_discord_run_key_registry_chain", "Discord Run key"),
        ("chain_01_e01_dns_packet_capture_batch_chain", "DNS/bat/tshark"),
        ("chain_06_e04_python_simplehttpserver_network_chain", "SimpleHTTPServer"),
        ("chain_07_e05_sublime_python_script_execution_chain", "Sublime/Python"),
    ]
    lines = []
    lines.append("## GPT-5.5 Rawに残った質問設計の例")
    lines.append("")
    lines.append("以下はactual `SELECT`/SQL textではない。raw出力に残ったInvestigatorの仮説、QAAgentへの自然言語質問、結果要約の例である。")
    lines.append("")
    for chain_id, label in targets:
        cand = None
        for row in qa_rows:
            if row.get("chain_id") == chain_id and row.get("hypothesis_excerpt"):
                cand = row
                break
        if not cand:
            for row in qa_rows:
                if row.get("chain_id") == chain_id:
                    cand = row
                    break
        if not cand:
            continue
        hyp, q, result = split_example_parts(cand)
        if len(hyp) > 500:
            hyp = hyp[:497] + "..."
        if len(q) > 700:
            q = q[:697] + "..."
        if len(result) > 500:
            result = result[:497] + "..."
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- chain/stage: `{cand['chain_id']}` / `{cand['stage']}`")
        lines.append(f"- 仮説: {hyp}")
        lines.append(f"- QAAgentへの質問: {q}")
        lines.append(f"- 結果要約: {result or '同じraw section内では明示抽出できず。'}")
        lines.append(f"- 質問の特徴: {cand.get('quality_flags', '')}")
        lines.append("")
    return lines


def split_example_parts(row):
    text = clean_text(row.get("question_excerpt") or "")
    hyp = clean_text(row.get("hypothesis_excerpt") or "")
    if not hyp:
        hyp = text

    # Keep the hypothesis before the first explicit QA/question heading.
    hyp = re.split(r"(?:QAAgent\s*へ|QAAgentへの質問|QAAgent\s*に|###\s*質問|質問\s*\d+)", hyp, maxsplit=1)[0]
    hyp = re.sub(r"^#+\s*仮説\s*", "", hyp).strip(" -")

    q_source = text
    m = re.search(r"(?:QAAgent\s*へ[^。]*質問|QAAgentへの質問|###\s*質問\s*\d*|質問\s*\d+)", q_source)
    if m:
        q_source = q_source[m.end() :]
    q_source = re.split(r"(?:###\s*結果要約|結果要約\s*\d*|####\s*観測事実|観測事実)", q_source, maxsplit=1)[0]
    q_source = q_source.strip(" `:-")

    result = ""
    m = re.search(r"(?:###\s*結果要約|結果要約\s*\d*|####\s*観測事実|観測事実)(.*)", text)
    if m:
        result = clean_text(m.group(1)).strip(" :-")

    return hyp or "-", q_source or "-", result or ""


if __name__ == "__main__":
    main()
