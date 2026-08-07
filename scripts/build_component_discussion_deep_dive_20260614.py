import csv
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("docs/current_experiment/handoff_20260614_component_rubric_experiment")
AGG = ROOT / "03_aggregated_results"
OUT = ROOT / "04_discussion_base" / "deep_dive_20260614"
RAW = ROOT / "01_experiment_raw_outputs"
SCORES = ROOT / "02_scoring_ledgers"
COST_CSV = Path("clouseau_api_costs.csv")

METRICS = [
    "action_step_recall",
    "critical_evidence_recall",
    "behavior_sequence_order",
    "candidate_claim_precision",
]

LOCAL_PRICES_PER_1M = {
    "gpt-4.1-mini": {"input": 0.40, "cached": 0.10, "output": 1.60},
    "gpt-5.4-mini": {"input": 0.75, "cached": 0.075, "output": 4.50},
    "gpt-5.5": {"input": 5.00, "cached": 0.50, "output": 30.00},
    "gpt-5.5 low raw": {"input": 5.00, "cached": 0.50, "output": 30.00},
}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_dt(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def run_start_from_id(run_id):
    m = re.match(r"^(\d{8}T\d{6}Z)_", run_id or "")
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)


def stdev(values):
    vals = [float(v) for v in values if v is not None and v != ""]
    if len(vals) < 2:
        return ""
    mean = sum(vals) / len(vals)
    return math.sqrt(sum((v - mean) ** 2 for v in vals) / (len(vals) - 1))


def mean(values):
    vals = [float(v) for v in values if v is not None and v != ""]
    return sum(vals) / len(vals) if vals else ""


def percentile(values, p):
    vals = sorted(float(v) for v in values if v is not None and v != "")
    if not vals:
        return ""
    k = (len(vals) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return vals[int(k)]
    return vals[lo] * (hi - k) + vals[hi] * (k - lo)


def fmt(v, digits=3):
    if v == "" or v is None:
        return ""
    return f"{float(v):.{digits}f}"


def local_estimated_cost(model, input_tokens, output_tokens, cached_input_tokens):
    prices = LOCAL_PRICES_PER_1M.get(model)
    if not prices:
        return ""
    return (
        (int(input_tokens or 0) / 1_000_000) * prices["input"]
        + (int(output_tokens or 0) / 1_000_000) * prices["output"]
        + (int(cached_input_tokens or 0) / 1_000_000) * prices["cached"]
    )


def model_label(model, source_set=None):
    if model == "gpt-5.5":
        return "gpt-5.5 low raw"
    return model


def source_and_replicate(path):
    parts = path.parts
    if "f23_2rep" in parts:
        rep = next((p for p in parts if p.startswith("replicate_")), "")
        return "formal_23_chain_2rep_20260612", rep
    if "legacy27_raw" in parts:
        return "formal_27_chain_20260609_filtered_to_current_23", "legacy_27_filtered_20260609"
    if "gpt55_r1" in parts:
        return "gpt55_low_raw_20260613", "replicate_01"
    return "", ""


def load_run_meta():
    rows = []
    for p in RAW.rglob("*_run.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        usage = data.get("usage") or {}
        source_set, replicate = source_and_replicate(p)
        rows.append(
            {
                "run_id": data.get("run_id", ""),
                "model": model_label(data.get("model", ""), source_set),
                "raw_model": data.get("model", ""),
                "stage": data.get("experiment_stage", ""),
                "instance_id": data.get("instance_id", ""),
                "source_set": source_set,
                "replicate": replicate,
                "reasoning_effort": data.get("reasoning_effort", ""),
                "input_tokens": int(usage.get("input_tokens") or 0),
                "output_tokens": int(usage.get("output_tokens") or 0),
                "cached_input_tokens": int(usage.get("cached_input_tokens") or 0),
                "path": str(p),
            }
        )
    return rows


def load_costs():
    costs = {}
    if not COST_CSV.exists():
        return costs
    for r in read_csv(COST_CSV):
        rid = r.get("run_id", "")
        costs[rid] = {
            "completed_at_utc": r.get("timestamp", ""),
            "input_cost_usd": float(r.get("input_cost_usd") or 0),
            "output_cost_usd": float(r.get("output_cost_usd") or 0),
            "cached_input_cost_usd": float(r.get("cached_input_cost_usd") or 0),
            "call_total_usd": float(r.get("call_total_usd") or 0),
        }
    return costs


def key_for(row):
    return (
        row.get("model", ""),
        row.get("source_set", ""),
        row.get("replicate", ""),
        row.get("stage", ""),
        row.get("instance_id", ""),
    )


def enrich_final_ledger():
    ledger = read_csv(AGG / "ledgers" / "final_comparison_per_run_component_scores.csv")
    meta = load_run_meta()
    costs = load_costs()
    meta_by_key = {key_for(m): m for m in meta}

    enriched = []
    for r in ledger:
        m = meta_by_key.get(key_for(r))
        if not m and r.get("model") == "gpt-5.5 low raw":
            k = ("gpt-5.5 low raw", "gpt55_low_raw_20260613", r.get("replicate", ""), r.get("stage", ""), r.get("instance_id", ""))
            m = meta_by_key.get(k)
        out = dict(r)
        if m:
            local_cost = local_estimated_cost(
                out.get("model") or m["model"],
                m["input_tokens"],
                m["output_tokens"],
                m["cached_input_tokens"],
            )
            out.update(
                {
                    "run_id": m["run_id"],
                    "input_tokens": m["input_tokens"],
                    "output_tokens": m["output_tokens"],
                    "cached_input_tokens": m["cached_input_tokens"],
                    "reasoning_effort": m["reasoning_effort"],
                    "run_path_in_handoff": m["path"],
                    "local_price_estimated_cost_usd": local_cost,
                }
            )
            c = costs.get(m["run_id"])
            if c:
                start = run_start_from_id(m["run_id"])
                done = parse_dt(c["completed_at_utc"])
                dur = (done - start).total_seconds() if start and done else ""
                logged = c["call_total_usd"]
                effective = logged if logged > 0 else local_cost
                source = "cost_log" if logged > 0 else "local_price_estimate_cost_log_zero"
                out.update(
                    {
                        "completed_at_utc": c["completed_at_utc"],
                        "call_total_usd": c["call_total_usd"],
                        "effective_cost_usd": effective,
                        "cost_source": source,
                        "duration_seconds_from_runid_to_costlog": dur,
                    }
                )
            else:
                out.update(
                    {
                        "completed_at_utc": "",
                        "call_total_usd": "",
                        "effective_cost_usd": local_cost,
                        "cost_source": "local_price_estimate_no_cost_log" if local_cost != "" else "missing",
                        "duration_seconds_from_runid_to_costlog": "",
                    }
                )
        enriched.append(out)
    return enriched


def aggregate_operational(rows, group_cols, path):
    groups = defaultdict(list)
    for r in rows:
        groups[tuple(r.get(c, "") for c in group_cols)].append(r)
    out = []
    for key, items in sorted(groups.items()):
        logged_costs = [
            float(r["call_total_usd"])
            for r in items
            if r.get("call_total_usd") not in ("", None) and float(r.get("call_total_usd") or 0) > 0
        ]
        costs = [float(r["effective_cost_usd"]) for r in items if r.get("effective_cost_usd") not in ("", None)]
        durs = [float(r["duration_seconds_from_runid_to_costlog"]) for r in items if r.get("duration_seconds_from_runid_to_costlog") not in ("", None)]
        starts = [run_start_from_id(r.get("run_id", "")) for r in items if r.get("run_id")]
        ends = [parse_dt(r.get("completed_at_utc", "")) for r in items if r.get("completed_at_utc")]
        starts = [x for x in starts if x]
        ends = [x for x in ends if x]
        row = {c: key[i] for i, c in enumerate(group_cols)}
        row.update(
            {
                "run_count": len(items),
                "logged_cost_runs": len(logged_costs),
                "estimated_cost_runs": len(costs),
                "total_effective_cost_usd": fmt(sum(costs), 4),
                "avg_effective_cost_per_run_usd": fmt(mean(costs), 4),
                "p50_effective_cost_per_run_usd": fmt(percentile(costs, 0.5), 4),
                "p90_effective_cost_per_run_usd": fmt(percentile(costs, 0.9), 4),
                "input_tokens_total": sum(int(r.get("input_tokens") or 0) for r in items),
                "output_tokens_total": sum(int(r.get("output_tokens") or 0) for r in items),
                "duration_covered_runs": len(durs),
                "avg_duration_min": fmt(mean(durs) / 60 if durs else "", 2),
                "p50_duration_min": fmt(percentile(durs, 0.5) / 60 if durs else "", 2),
                "p90_duration_min": fmt(percentile(durs, 0.9) / 60 if durs else "", 2),
                "serial_sum_hours": fmt(sum(durs) / 3600 if durs else "", 2),
                "four_parallel_est_hours": fmt((sum(durs) / 4) / 3600 if durs else "", 2),
                "observed_window_hours": fmt(((max(ends) - min(starts)).total_seconds() / 3600) if starts and ends else "", 2),
            }
        )
        out.append(row)
    fields = group_cols + [
        "run_count",
        "logged_cost_runs",
        "estimated_cost_runs",
        "total_effective_cost_usd",
        "avg_effective_cost_per_run_usd",
        "p50_effective_cost_per_run_usd",
        "p90_effective_cost_per_run_usd",
        "input_tokens_total",
        "output_tokens_total",
        "duration_covered_runs",
        "avg_duration_min",
        "p50_duration_min",
        "p90_duration_min",
        "serial_sum_hours",
        "four_parallel_est_hours",
        "observed_window_hours",
    ]
    write_csv(path, out, fields)


def replicate_variability():
    rows = read_csv(AGG / "by_replicate_4_1_5_4.csv")
    groups = defaultdict(list)
    for r in rows:
        groups[r["model"]].append(r)
    out = []
    for model, items in sorted(groups.items()):
        row = {"model": model, "replicate_count": len(items)}
        for m in METRICS:
            vals = [float(r[m]) for r in items]
            row[f"{m}_mean"] = fmt(mean(vals), 3)
            row[f"{m}_sd"] = fmt(stdev(vals), 3)
            row[f"{m}_min"] = fmt(min(vals), 3)
            row[f"{m}_max"] = fmt(max(vals), 3)
            row[f"{m}_range"] = fmt(max(vals) - min(vals), 3)
        over = [float(r["overclaim_slot_count"]) for r in items]
        row["overclaim_mean"] = fmt(mean(over), 1)
        row["overclaim_sd"] = fmt(stdev(over), 1)
        row["overclaim_range"] = fmt(max(over) - min(over), 1)
        out.append(row)
    fields = ["model", "replicate_count"]
    for m in METRICS:
        fields += [f"{m}_mean", f"{m}_sd", f"{m}_min", f"{m}_max", f"{m}_range"]
    fields += ["overclaim_mean", "overclaim_sd", "overclaim_range"]
    write_csv(OUT / "model_replicate_variability.csv", out, fields)


def chain_variability(rows):
    # Only 4.1/5.4 have three source sets. Average stages within chain+replicate, then measure replicate spread.
    per = defaultdict(list)
    for r in rows:
        if r.get("model") not in ("gpt-4.1-mini", "gpt-5.4-mini"):
            continue
        key = (r["model"], r["chain_id"], r["replicate"])
        per[key].append(r)
    rep_rows = []
    for (model, chain, rep), items in per.items():
        rr = {"model": model, "chain_id": chain, "replicate": rep}
        for m in METRICS:
            rr[m] = mean([x.get(m) for x in items])
        rep_rows.append(rr)
    groups = defaultdict(list)
    for r in rep_rows:
        groups[(r["model"], r["chain_id"])].append(r)
    out = []
    for (model, chain), items in groups.items():
        row = {"model": model, "chain_id": chain, "replicate_count": len(items)}
        sds = []
        for m in METRICS:
            sd = stdev([r[m] for r in items])
            row[f"{m}_sd"] = fmt(sd, 3) if sd != "" else ""
            if sd != "":
                sds.append(sd)
        row["mean_metric_sd"] = fmt(mean(sds), 3)
        out.append(row)
    out.sort(key=lambda r: float(r["mean_metric_sd"] or 0), reverse=True)
    fields = ["model", "chain_id", "replicate_count", "mean_metric_sd"] + [f"{m}_sd" for m in METRICS]
    write_csv(OUT / "top_chain_replicate_variability.csv", out, fields)


def reviewer_variability():
    conflicts_path = SCORES / "component_rubric_20260614" / "review_conflicts.jsonl"
    adopted_path = SCORES / "component_rubric_20260614" / "codex_component_double_reviews.jsonl"
    conflicts = []
    if conflicts_path.exists():
        with conflicts_path.open(encoding="utf-8") as f:
            conflicts = [json.loads(line) for line in f if line.strip()]
    adopted = []
    if adopted_path.exists():
        with adopted_path.open(encoding="utf-8") as f:
            adopted = [json.loads(line) for line in f if line.strip()]
    mismatch_counter = Counter()
    model_counter = Counter()
    for c in conflicts:
        for m in c.get("mismatches", []):
            mismatch_counter[m] += 1
        key = c.get("key") or []
        if len(key) >= 2:
            model_counter[key[1]] += 1
    total_reviewed = len(adopted) + len(conflicts)
    rows = [
        {
            "total_two_review_rows_exact_adopted": len(adopted),
            "third_review_conflict_rows": len(conflicts),
            "total_rows_with_two_reviews": total_reviewed,
            "exact_adoption_rate": fmt(len(adopted) / total_reviewed if total_reviewed else "", 3),
            "third_review_rate": fmt(len(conflicts) / total_reviewed if total_reviewed else "", 3),
        }
    ]
    write_csv(
        OUT / "reviewer_variability_summary.csv",
        rows,
        [
            "total_two_review_rows_exact_adopted",
            "third_review_conflict_rows",
            "total_rows_with_two_reviews",
            "exact_adoption_rate",
            "third_review_rate",
        ],
    )
    write_csv(
        OUT / "reviewer_conflict_fields.csv",
        [{"field": k, "conflict_count": v} for k, v in mismatch_counter.most_common()],
        ["field", "conflict_count"],
    )
    write_csv(
        OUT / "reviewer_conflicts_by_model.csv",
        [{"model": k, "conflict_count": v} for k, v in sorted(model_counter.items())],
        ["model", "conflict_count"],
    )


def cost_effectiveness():
    overall = read_csv(AGG / "overall.csv")
    cost_rows = read_csv(OUT / "cost_time_by_model.csv")
    cost_by_model = {r["model"]: r for r in cost_rows}
    out = []
    for r in overall:
        c = cost_by_model.get(r["model"], {})
        total_cost = float(c.get("total_effective_cost_usd") or 0)
        action_hits = int(r.get("action_step_recall_hits") or 0)
        evidence_hits = int(r.get("critical_evidence_recall_hits") or 0)
        order_hits = int(r.get("behavior_sequence_order_hits") or 0)
        precision_hits = int(r.get("candidate_claim_precision_hits") or 0)
        out.append(
            {
                "model": r["model"],
                "run_count": r["run_count"],
                "total_effective_cost_usd": fmt(total_cost, 4),
                "cost_source_note": "logged+local_price_estimate" if int(c.get("logged_cost_runs") or 0) else "local_price_estimate_only",
                "action_step_recall": r["action_step_recall"],
                "critical_evidence_recall": r["critical_evidence_recall"],
                "behavior_sequence_order": r["behavior_sequence_order"],
                "candidate_claim_precision": r["candidate_claim_precision"],
                "cost_per_action_hit_usd": fmt(total_cost / action_hits if action_hits else "", 4),
                "cost_per_evidence_hit_usd": fmt(total_cost / evidence_hits if evidence_hits else "", 4),
                "cost_per_order_hit_usd": fmt(total_cost / order_hits if order_hits else "", 4),
                "cost_per_precision_hit_usd": fmt(total_cost / precision_hits if precision_hits else "", 4),
                "overclaim_slot_count": r["overclaim_slot_count"],
            }
        )
    write_csv(
        OUT / "cost_effectiveness_by_model.csv",
        out,
        [
            "model",
            "run_count",
            "total_effective_cost_usd",
            "cost_source_note",
            "action_step_recall",
            "critical_evidence_recall",
            "behavior_sequence_order",
            "candidate_claim_precision",
            "cost_per_action_hit_usd",
            "cost_per_evidence_hit_usd",
            "cost_per_order_hit_usd",
            "cost_per_precision_hit_usd",
            "overclaim_slot_count",
        ],
    )


def exclusion_summary():
    status_path = SCORES / "component_rubric_20260614" / "review_queue_status.json"
    row = {}
    if status_path.exists():
        status = json.loads(status_path.read_text(encoding="utf-8"))
        row = {
            "adopted_review_count": status.get("adopted_review_count", ""),
            "valid_unreviewed_count": status.get("valid_unreviewed_count", ""),
            "invalid_run_count": status.get("invalid_run_count", ""),
            "missing_run_count": status.get("missing_run_count", ""),
            "note": "Queue status spans the broader prepared component review queue; final comparison separately uses 483 rows.",
        }
    write_csv(
        OUT / "exclusion_and_queue_status.csv",
        [row],
        ["adopted_review_count", "valid_unreviewed_count", "invalid_run_count", "missing_run_count", "note"],
    )


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    enriched = enrich_final_ledger()
    write_csv(
        OUT / "operational_per_run_enriched.csv",
        enriched,
        list(enriched[0].keys()),
    )
    aggregate_operational(enriched, ["model"], OUT / "cost_time_by_model.csv")
    aggregate_operational(enriched, ["model", "stage"], OUT / "cost_time_by_model_stage.csv")
    aggregate_operational(enriched, ["model", "replicate", "source_set"], OUT / "cost_time_by_replicate_source.csv")
    aggregate_operational(enriched, ["model", "scenario_group"], OUT / "cost_time_by_scenario_group.csv")
    replicate_variability()
    chain_variability(enriched)
    reviewer_variability()
    cost_effectiveness()
    exclusion_summary()


if __name__ == "__main__":
    main()
