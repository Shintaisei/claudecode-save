import csv
import json
import re
from pathlib import Path


SCENARIOS = ["s3", "s4", "m4", "m5", "m6"]


def extract_first(details: str, patterns: list[str]) -> str:
    for pat in patterns:
        m = re.search(pat, details)
        if m:
            return m.group(1).strip()
    return ""


def main() -> None:
    desktop = Path.home() / "OneDrive" / "Desktop"
    atlas_base = desktop / "ATLAS系データセット取得"
    out = {}
    summary = {}

    for sc in SCENARIOS:
        gt_path = (
            atlas_base
            / "atlasv2"
            / "data"
            / "attack"
            / "h1"
            / "msft-security"
            / "groundtruth"
            / f"h1_{sc}"
        )
        gt = {
            line.strip()
            for line in gt_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

        csv_path = (
            atlas_base
            / "hayabusa"
            / "atlasv2_runs"
            / "csv"
            / f"msft-security-h1-{sc}.csv"
        )

        rows = []
        all_rows = []
        with csv_path.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                details = row["Details"]
                rid = extract_first(details, [r"EventRecordID: ([0-9]+)"])
                label = "TP" if rid in gt else "FP"
                proc = extract_first(
                    details,
                    [
                        r"ProcessName: ([^¦]+)",
                        r"NewProcessName: ([^¦]+)",
                        r"Application: ([^¦]+)",
                    ],
                )
                user = extract_first(
                    details,
                    [r"SubjectUserName: ([^¦]+)", r"User: ([^¦]+)"],
                )
                priv = extract_first(details, [r"PrivilegeList: ([^¦]+)"])
                dest_addr = extract_first(details, [r"DestAddress: ([^¦]+)"])
                dest_port = extract_first(details, [r"DestPort: ([^¦]+)"])
                dest = f"{dest_addr}:{dest_port}" if dest_addr else ""

                parsed = {
                    "timestamp": row["Timestamp"],
                    "rule": row["RuleTitle"],
                    "level": row["Level"],
                    "event_id": row["EventID"],
                    "record_id": rid,
                    "label": label,
                    "process": proc,
                    "user": user,
                    "privilege": priv,
                    "dest": dest,
                    "details": details,
                }
                all_rows.append(parsed)
                if row["Level"] != "info":
                    rows.append(parsed)

        out[sc] = rows
        fp_info = [r for r in all_rows if r["level"] == "info" and r["label"] == "FP"]
        top_rules = {}
        top_procs = {}
        for r in fp_info:
            top_rules[r["rule"]] = top_rules.get(r["rule"], 0) + 1
            key = r["process"] or "(unknown)"
            top_procs[key] = top_procs.get(key, 0) + 1
        summary[sc] = {
            "all_fp_info_count": len(fp_info),
            "top_info_rules": sorted(top_rules.items(), key=lambda x: (-x[1], x[0]))[:10],
            "top_info_processes": sorted(top_procs.items(), key=lambda x: (-x[1], x[0]))[:10],
        }

    out_path = Path("analysis_data/atlas_fp_noninfo_selected.json")
    out_path.write_text(
        json.dumps(out, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(out_path)
    summary_path = Path("analysis_data/atlas_fp_info_summary.json")
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(summary_path)
    for sc, rows in out.items():
        fps = [r for r in rows if r["label"] == "FP"]
        print(f"{sc} noninfo={len(rows)} fp={len(fps)}")
        for r in fps:
            print(
                f"  {r['timestamp']} | {r['rule']} | {r['event_id']} | "
                f"{r['record_id']} | {r['process']} | {r['dest']} | {r['privilege']}"
            )


if __name__ == "__main__":
    main()
