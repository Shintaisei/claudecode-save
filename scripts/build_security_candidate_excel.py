from __future__ import annotations

import csv
import json
import os
import posixpath
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
RAW_JSONL = ROOT / "analysis_data" / "atlasv2_benign_runs" / "jsonl" / "msft-security-h1-benign-2to4.jsonl"
FP_JSON = ROOT / "analysis_data" / "atlas_fp_noninfo_selected.json"
OUT_DIR = ROOT / "docs_active"
OUT_TXT = OUT_DIR / "セキュリティ生ログ起点候補一覧_2026-05-12.txt"
OUT_XLSX = OUT_DIR / "セキュリティ生ログ_ユースケース候補抽出_2026-05-12.xlsx"
OUT_CSV = OUT_DIR / "セキュリティ生ログ_ユースケース候補抽出_2026-05-12.csv"


CANDIDATE_PROCESSES = [
    "explorer.exe",
    "winword.exe",
    "repmgr.exe",
    "firefox.exe",
    "repwmiutils.exe",
    "spoolsv.exe",
    "tpautoconnsvc.exe",
]
MAX_EVENT_ROWS_PER_PROCESS = 300


def basename_lower(value: str) -> str:
    value = (value or "").strip().strip('"')
    if not value:
        return ""
    value = value.replace("/", "\\")
    parts = [p for p in value.split("\\") if p]
    return parts[-1].lower() if parts else value.lower()


def clean_cell(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def format_counter(counter: Counter[str], limit: int = 5) -> str:
    if not counter:
        return ""
    return " | ".join(f"{key}:{count}" for key, count in counter.most_common(limit))


def inline_cell(value: object) -> str:
    text = clean_cell(value)
    if text == "":
        return '<c t="inlineStr"><is><t></t></is></c>'
    preserve = ' xml:space="preserve"' if text.startswith(" ") or text.endswith(" ") or "\n" in text else ""
    return f'<c t="inlineStr"><is><t{preserve}>{escape(text)}</t></is></c>'


def worksheet_xml(rows: list[list[object]]) -> str:
    row_xml = []
    for r_idx, row in enumerate(rows, start=1):
        cells = "".join(inline_cell(value) for value in row)
        row_xml.append(f'<row r="{r_idx}">{cells}</row>')
    body = "".join(row_xml)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>'
        f"{body}"
        "</sheetData>"
        "</worksheet>"
    )


def workbook_xml(sheet_names: list[str]) -> str:
    sheets = []
    for idx, name in enumerate(sheet_names, start=1):
        sheets.append(
            f'<sheet name="{escape(name)}" sheetId="{idx}" '
            f'r:id="rId{idx}"/>'
        )
    body = "".join(sheets)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{body}</sheets>"
        "</workbook>"
    )


def workbook_rels_xml(sheet_count: int) -> str:
    rels = []
    for idx in range(1, sheet_count + 1):
        rels.append(
            '<Relationship '
            f'Id="rId{idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
    body = "".join(rels)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{body}"
        "</Relationships>"
    )


def root_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def content_types_xml(sheet_count: int) -> str:
    overrides = [
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    ]
    for idx in range(1, sheet_count + 1):
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    body = "".join(overrides)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f"{body}"
        "</Types>"
    )


def write_xlsx(path: Path, sheets: list[tuple[str, list[list[object]]]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml(len(sheets)))
        zf.writestr("_rels/.rels", root_rels_xml())
        zf.writestr("xl/workbook.xml", workbook_xml([name for name, _ in sheets]))
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheets)))
        for idx, (_, rows) in enumerate(sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", worksheet_xml(rows))


@dataclass
class CandidateStats:
    count: int = 0
    min_ts: str = ""
    max_ts: str = ""
    event_ids: Counter[str] = field(default_factory=Counter)
    users: Counter[str] = field(default_factory=Counter)
    hit_fields: Counter[str] = field(default_factory=Counter)
    object_types: Counter[str] = field(default_factory=Counter)
    object_examples: Counter[str] = field(default_factory=Counter)

    def update(self, event: dict, matched_field: str) -> None:
        self.count += 1
        ts = event.get("@timestamp", "")
        if ts and (not self.min_ts or ts < self.min_ts):
            self.min_ts = ts
        if ts and (not self.max_ts or ts > self.max_ts):
            self.max_ts = ts
        self.event_ids[event.get("EventID", "")] += 1
        self.users[event.get("SubjectUserName", "")] += 1
        self.hit_fields[matched_field] += 1
        self.object_types[event.get("ObjectType", "")] += 1
        for field_name in ("ObjectName", "TargetFilename", "TargetObject"):
            value = clean_cell(event.get(field_name, ""))
            if value:
                self.object_examples[value] += 1
                break


def parse_fp_examples() -> list[dict[str, str]]:
    with FP_JSON.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        items: list[dict[str, object]] = []
        for value in data.values():
            if isinstance(value, list):
                items.extend(item for item in value if isinstance(item, dict))
    elif isinstance(data, list):
        items = [item for item in data if isinstance(item, dict)]
    else:
        items = []
    rows = []
    for item in items:
        rows.append(
            {
                "timestamp": clean_cell(item.get("timestamp", "")),
                "event_id": clean_cell(item.get("event_id", "")),
                "label": clean_cell(item.get("label", "")),
                "rule": clean_cell(item.get("rule", "")),
                "process": clean_cell(item.get("process", "")),
                "user": clean_cell(item.get("user", "")),
                "privilege": clean_cell(item.get("privilege", "")),
                "dest": clean_cell(item.get("dest", "")),
                "details": clean_cell(item.get("details", "")),
            }
        )
    return rows


def scan_raw_candidates() -> tuple[list[dict[str, str]], dict[str, CandidateStats], dict[str, object]]:
    candidate_rows: list[dict[str, str]] = []
    stats = {proc: CandidateStats() for proc in CANDIDATE_PROCESSES}

    total_rows = 0
    event_id_counter: Counter[str] = Counter()
    field_nonempty = Counter()
    field_examples: dict[str, set[str]] = defaultdict(set)
    field_event_ids: dict[str, set[str]] = defaultdict(set)
    seen_per_process = Counter()

    inspect_fields = [
        "ObjectName",
        "TargetFilename",
        "TargetObject",
        "ProcessName",
        "Image",
        "Application",
        "SubjectUserName",
        "SubjectLogonId",
        "ObjectType",
        "AccessMask",
        "AccessList",
        "DestAddress",
        "DestPort",
        "NewProcessName",
        "PrivilegeList",
        "ServiceName",
        "TargetUserName",
        "LogonType",
    ]

    with RAW_JSONL.open("r", encoding="utf-8") as fh:
        for line in fh:
            total_rows += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_id = clean_cell(event.get("EventID", ""))
            event_id_counter[event_id] += 1
            for field_name in inspect_fields:
                value = clean_cell(event.get(field_name, ""))
                if value:
                    field_nonempty[field_name] += 1
                    if len(field_examples[field_name]) < 5:
                        field_examples[field_name].add(value)
                    if len(field_event_ids[field_name]) < 10 and event_id:
                        field_event_ids[field_name].add(event_id)

            matched_field = ""
            matched_process = ""
            for field_name in ("ProcessName", "Image", "Application", "NewProcessName"):
                base = basename_lower(clean_cell(event.get(field_name, "")))
                if base in stats:
                    matched_field = field_name
                    matched_process = base
                    break
            if not matched_process:
                continue

            stats[matched_process].update(event, matched_field)
            if seen_per_process[matched_process] >= MAX_EVENT_ROWS_PER_PROCESS:
                continue

            row = {
                "candidate_process": matched_process,
                "matched_field": matched_field,
                "timestamp": clean_cell(event.get("@timestamp", "")),
                "event_id": event_id,
                "event_record_id": clean_cell(event.get("EventRecordID", "")),
                "computer": clean_cell(event.get("Computer", "")),
                "subject_user": clean_cell(event.get("SubjectUserName", "")),
                "subject_logon_id": clean_cell(event.get("SubjectLogonId", "")),
                "process_name": clean_cell(event.get("ProcessName", "")),
                "image": clean_cell(event.get("Image", "")),
                "application": clean_cell(event.get("Application", "")),
                "new_process_name": clean_cell(event.get("NewProcessName", "")),
                "object_type": clean_cell(event.get("ObjectType", "")),
                "object_name": clean_cell(event.get("ObjectName", "")),
                "target_filename": clean_cell(event.get("TargetFilename", "")),
                "target_object": clean_cell(event.get("TargetObject", "")),
                "access_mask": clean_cell(event.get("AccessMask", "")),
                "access_list": clean_cell(event.get("AccessList", "")),
                "privilege_list": clean_cell(event.get("PrivilegeList", "")),
                "dest_address": clean_cell(event.get("DestAddress", "")),
                "dest_port": clean_cell(event.get("DestPort", "")),
                "handle_id": clean_cell(event.get("HandleId", "")),
            }
            candidate_rows.append(row)
            seen_per_process[matched_process] += 1

    global_stats = {
        "total_rows": total_rows,
        "event_id_counter": event_id_counter,
        "field_nonempty": field_nonempty,
        "field_examples": {k: sorted(v) for k, v in field_examples.items()},
        "field_event_ids": {k: sorted(v) for k, v in field_event_ids.items()},
    }
    return candidate_rows, stats, global_stats


def build_seed_rows(global_stats: dict[str, object]) -> list[list[object]]:
    nonempty: Counter[str] = global_stats["field_nonempty"]  # type: ignore[assignment]
    examples: dict[str, list[str]] = global_stats["field_examples"]  # type: ignore[assignment]
    field_event_ids: dict[str, list[str]] = global_stats["field_event_ids"]  # type: ignore[assignment]

    def observed(*fields: str) -> str:
        return "yes" if any(nonempty.get(name, 0) > 0 for name in fields) else "no"

    def examples_text(*fields: str) -> str:
        vals = []
        for name in fields:
            vals.extend(examples.get(name, []))
        return " | ".join(vals[:5])

    def event_ids_text(*fields: str) -> str:
        vals = []
        for name in fields:
            vals.extend(field_event_ids.get(name, []))
        seen = []
        for val in vals:
            if val not in seen:
                seen.append(val)
        return ",".join(seen[:10])

    rows = [[
        "seed_class",
        "specificity",
        "required_fields",
        "typical_event_ids_seen",
        "observed_in_raw",
        "example_values",
        "note",
    ]]
    rows.extend([
        [
            "specific file or directory path",
            "high",
            "ObjectName / TargetFilename / TargetObject",
            event_ids_text("ObjectName", "TargetFilename", "TargetObject"),
            observed("ObjectName", "TargetFilename", "TargetObject"),
            examples_text("ObjectName", "TargetFilename", "TargetObject"),
            "Security file/handle events can start from a concrete file, shortcut, DLL, user profile path, or folder.",
        ],
        [
            "specific process image",
            "medium",
            "ProcessName / Image / Application",
            event_ids_text("ProcessName", "Image", "Application"),
            observed("ProcessName", "Image", "Application"),
            examples_text("ProcessName", "Image", "Application"),
            "Process path itself can be a seed, but broad processes need another field to become strong.",
        ],
        [
            "process + user session",
            "medium",
            "ProcessName + SubjectUserName + SubjectLogonId",
            event_ids_text("ProcessName", "SubjectUserName", "SubjectLogonId"),
            observed("ProcessName", "SubjectUserName", "SubjectLogonId"),
            examples_text("SubjectUserName", "SubjectLogonId"),
            "Useful when the same process appears in multiple contexts and the actor must be narrowed down.",
        ],
        [
            "spawned process",
            "high",
            "NewProcessName",
            event_ids_text("NewProcessName"),
            observed("NewProcessName"),
            examples_text("NewProcessName"),
            "4688 style process creation gives a direct executable seed.",
        ],
        [
            "network destination",
            "high",
            "DestAddress + DestPort + Application",
            event_ids_text("DestAddress", "DestPort", "Application"),
            observed("DestAddress", "DestPort", "Application"),
            examples_text("DestAddress", "DestPort"),
            "5156 family events can seed on a concrete remote endpoint.",
        ],
        [
            "privilege use",
            "medium",
            "PrivilegeList + ProcessName + SubjectUserName",
            event_ids_text("PrivilegeList"),
            observed("PrivilegeList"),
            examples_text("PrivilegeList"),
            "Privilege-based starts are good for admin-like actions but usually need process/user context.",
        ],
        [
            "access intent",
            "medium",
            "AccessMask / AccessList + ObjectName",
            event_ids_text("AccessMask", "AccessList"),
            observed("AccessMask", "AccessList"),
            examples_text("AccessMask", "AccessList"),
            "Read/write/delete/handle semantics can separate similar file events.",
        ],
        [
            "object type",
            "low",
            "ObjectType",
            event_ids_text("ObjectType"),
            observed("ObjectType"),
            examples_text("ObjectType"),
            "Useful as a filter, but too broad as a seed by itself.",
        ],
        [
            "target user or logon type",
            "low",
            "TargetUserName / LogonType",
            event_ids_text("TargetUserName", "LogonType"),
            observed("TargetUserName", "LogonType"),
            examples_text("TargetUserName", "LogonType"),
            "Present only sparsely in this raw set, so it is not a reliable main seed here.",
        ],
        [
            "service name",
            "low",
            "ServiceName",
            event_ids_text("ServiceName"),
            observed("ServiceName"),
            examples_text("ServiceName"),
            "Not observed in the scanned raw data, so not a practical Security seed in this dataset.",
        ],
    ])
    return rows


def build_candidate_summary_rows(stats: dict[str, CandidateStats]) -> list[list[object]]:
    rows = [[
        "candidate_process",
        "raw_match_count",
        "first_timestamp",
        "last_timestamp",
        "top_event_ids",
        "top_subject_users",
        "top_object_types",
        "top_example_objects",
        "matched_fields",
    ]]
    for process in CANDIDATE_PROCESSES:
        item = stats[process]
        rows.append([
            process,
            item.count,
            item.min_ts,
            item.max_ts,
            format_counter(item.event_ids),
            format_counter(item.users),
            format_counter(item.object_types),
            format_counter(item.object_examples),
            format_counter(item.hit_fields),
        ])
    return rows


def build_candidate_event_rows(candidate_rows: list[dict[str, str]]) -> list[list[object]]:
    headers = [
        "candidate_process",
        "matched_field",
        "timestamp",
        "event_id",
        "event_record_id",
        "computer",
        "subject_user",
        "subject_logon_id",
        "process_name",
        "image",
        "application",
        "new_process_name",
        "object_type",
        "object_name",
        "target_filename",
        "target_object",
        "access_mask",
        "access_list",
        "privilege_list",
        "dest_address",
        "dest_port",
        "handle_id",
    ]
    rows = [headers]
    for item in candidate_rows:
        rows.append([item.get(key, "") for key in headers])
    return rows


def build_fp_rows(fp_rows: list[dict[str, str]]) -> list[list[object]]:
    headers = ["timestamp", "event_id", "label", "rule", "process", "user", "privilege", "dest", "details"]
    rows = [headers]
    for item in fp_rows:
        rows.append([item.get(key, "") for key in headers])
    return rows


def build_uc_map_rows(stats: dict[str, CandidateStats]) -> list[list[object]]:
    mapping = [
        ["UC01", "explorer.exe", "win-32-h1|aalsahee|20220719T1430Z", "single file operation", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
        ["UC02", "winword.exe", "win-32-h1|aalsahee|20220719T1430Z", "document viewing", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
        ["UC03", "repmgr.exe", "win-32-h1|aalsahee|20220719T1430Z", "document procedure chain", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
        ["UC04", "firefox.exe", "win-32-h1|aalsahee|20220719T1430Z", "browser operation", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
        ["UC05", "repwmiutils.exe", "win-32-h1|win-32-h1$|20220719T1430Z", "background procedural access", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
        ["UC06", "spoolsv.exe", "win-32-h1|win-32-h1$|20220719T1420Z", "background service activity", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
        ["UC07", "tpautoconnsvc.exe", "win-32-h1|win-32-h1$|20220719T1420Z", "background service activity", "raw direct match by process exists; exact micro-chunk to raw line not re-linked"],
    ]
    rows = [[
        "usecase_id",
        "candidate_process",
        "anomaly_session_bucket",
        "usecase_label",
        "raw_match_count",
        "first_timestamp",
        "last_timestamp",
        "example_objects",
        "note",
    ]]
    for usecase_id, process, bucket, label, note in mapping:
        item = stats[process]
        rows.append([
            usecase_id,
            process,
            bucket,
            label,
            item.count,
            item.min_ts,
            item.max_ts,
            format_counter(item.object_examples, limit=3),
            note,
        ])
    return rows


def write_csv(candidate_rows: list[dict[str, str]]) -> None:
    headers = [
        "candidate_process",
        "matched_field",
        "timestamp",
        "event_id",
        "event_record_id",
        "computer",
        "subject_user",
        "subject_logon_id",
        "process_name",
        "image",
        "application",
        "new_process_name",
        "object_type",
        "object_name",
        "target_filename",
        "target_object",
        "access_mask",
        "access_list",
        "privilege_list",
        "dest_address",
        "dest_port",
        "handle_id",
    ]
    with OUT_CSV.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        writer.writerows(candidate_rows)


def write_txt(global_stats: dict[str, object], stats: dict[str, CandidateStats]) -> None:
    event_counter: Counter[str] = global_stats["event_id_counter"]  # type: ignore[assignment]
    total_rows = global_stats["total_rows"]
    lines = []
    lines.append("セキュリティ生ログ起点候補一覧")
    lines.append("更新日: 2026-05-12")
    lines.append("")
    lines.append("1. 対象")
    lines.append(f"- raw source: {RAW_JSONL}")
    lines.append(f"- scanned rows: {total_rows}")
    lines.append(f"- candidate processes: {', '.join(CANDIDATE_PROCESSES)}")
    lines.append("")
    lines.append("2. Security 生ログで起点になりうる軸")
    lines.append("- 高: 具体的なファイル/ディレクトリパス (ObjectName / TargetFilename / TargetObject)")
    lines.append("- 高: 生成された実行ファイル名 (NewProcessName, 4688)")
    lines.append("- 高: 通信先 IP / Port (DestAddress / DestPort, 5156 系)")
    lines.append("- 中: ProcessName / Image / Application")
    lines.append("- 中: ProcessName + SubjectUserName + SubjectLogonId")
    lines.append("- 中: PrivilegeList + ProcessName")
    lines.append("- 中: AccessMask / AccessList + ObjectName")
    lines.append("- 低: ObjectType 単独")
    lines.append("- 低: TargetUserName / LogonType")
    lines.append("- 実用外: ServiceName は今回の走査では観測できず")
    lines.append("")
    lines.append("3. raw 全体で多かった EventID")
    for event_id, count in event_counter.most_common(12):
        lines.append(f"- EventID {event_id}: {count}")
    lines.append("")
    lines.append("4. ユースケース候補プロセスの raw 抽出状況")
    for process in CANDIDATE_PROCESSES:
        item = stats[process]
        lines.append(
            f"- {process}: count={item.count}, "
            f"first={item.min_ts}, last={item.max_ts}, "
            f"top_event_ids={format_counter(item.event_ids, 4)}, "
            f"sample_objects={format_counter(item.object_examples, 3)}"
        )
    lines.append("")
    lines.append("5. 注意")
    lines.append("- 今回の Excel は raw Security から候補 process を抽出したもの。")
    lines.append("- 既存の anomaly micro-chunk ID と raw の 1 行 1 行を完全に再リンクした表ではない。")
    lines.append("- ただし、候補 process 自体は raw Security 上で実在確認できており、起点候補の議論には使える。")
    OUT_TXT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    fp_rows = parse_fp_examples()
    candidate_rows, stats, global_stats = scan_raw_candidates()

    seed_rows = build_seed_rows(global_stats)
    summary_rows = build_candidate_summary_rows(stats)
    event_rows = build_candidate_event_rows(candidate_rows)
    fp_sheet_rows = build_fp_rows(fp_rows)
    uc_map_rows = build_uc_map_rows(stats)

    sheets = [
        ("seed_inventory", seed_rows),
        ("candidate_summary", summary_rows),
        ("candidate_event_samples", event_rows),
        ("fp_security_examples", fp_sheet_rows),
        ("uc_process_map", uc_map_rows),
    ]

    write_xlsx(OUT_XLSX, sheets)
    write_csv(candidate_rows)
    write_txt(global_stats, stats)

    print(f"Wrote: {OUT_XLSX}")
    print(f"Wrote: {OUT_CSV}")
    print(f"Wrote: {OUT_TXT}")


if __name__ == "__main__":
    main()
