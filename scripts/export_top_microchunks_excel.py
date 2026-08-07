import argparse
import csv
import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export top micro-chunk review JSON to Excel-friendly files."
    )
    parser.add_argument("--input-json", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def stringify(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def build_rows(payload: dict) -> tuple[list[list], list[list]]:
    summary_rows = [[
        "micro_rank",
        "micro_chunk_id",
        "coarse_chunk_rank",
        "coarse_chunk_index",
        "micro_chunk_index",
        "attack_events",
        "normal_events",
        "total_events",
        "score",
        "top_processes",
        "top_event_ids",
    ]]
    event_rows = [[
        "micro_rank",
        "micro_chunk_id",
        "coarse_chunk_rank",
        "coarse_chunk_index",
        "micro_chunk_index",
        "event_offset_in_micro",
        "event_offset_in_session",
        "label",
        "event_id",
        "process",
        "template",
        "fields_json",
    ]]

    for chunk in payload["micro_chunks"]:
        summary_rows.append([
            chunk["micro_rank"],
            chunk["micro_chunk_id"],
            chunk["coarse_chunk_rank"],
            chunk["coarse_chunk_index"],
            chunk["micro_chunk_index"],
            chunk["attack_events"],
            chunk["normal_events"],
            chunk["total_events"],
            chunk["score"],
            ", ".join(f"{proc}:{count}" for proc, count in chunk["top_processes"]),
            ", ".join(f"{eid}:{count}" for eid, count in chunk["top_event_ids"]),
        ])
        for event in chunk["events"]:
            event_rows.append([
                chunk["micro_rank"],
                chunk["micro_chunk_id"],
                chunk["coarse_chunk_rank"],
                chunk["coarse_chunk_index"],
                chunk["micro_chunk_index"],
                event["offset_in_micro"],
                event["offset_in_session"],
                event["label"],
                event["event_id"],
                event["process"],
                event["template"],
                json.dumps(event["fields"], ensure_ascii=False),
            ])
    return summary_rows, event_rows


def write_csv(path: Path, rows: list[list]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerows(rows)


def col_name(index: int) -> str:
    result = ""
    n = index
    while n > 0:
        n, rem = divmod(n - 1, 26)
        result = chr(65 + rem) + result
    return result


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def build_shared_strings(sheets: list[list[list]]) -> tuple[dict[str, int], list[str]]:
    strings = []
    mapping = {}
    for rows in sheets:
        for row in rows:
            for value in row:
                if is_number(value):
                    continue
                text = stringify(value)
                if text not in mapping:
                    mapping[text] = len(strings)
                    strings.append(text)
    return mapping, strings


def sheet_xml(rows: list[list], shared: dict[str, int]) -> str:
    xml_rows = []
    for r_idx, row in enumerate(rows, start=1):
        cells = []
        for c_idx, value in enumerate(row, start=1):
            ref = f"{col_name(c_idx)}{r_idx}"
            if is_number(value):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                text = stringify(value)
                cells.append(f'<c r="{ref}" t="s"><v>{shared[text]}</v></c>')
        xml_rows.append(f'<row r="{r_idx}">{"".join(cells)}</row>')
    dimension = f"A1:{col_name(max(len(r) for r in rows))}{len(rows)}"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dimension}"/>'
        '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        f'<sheetData>{"".join(xml_rows)}</sheetData>'
        '</worksheet>'
    )


def shared_strings_xml(strings: list[str]) -> str:
    items = "".join(f"<si><t>{escape(text)}</t></si>" for text in strings)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        f'count="{len(strings)}" uniqueCount="{len(strings)}">{items}</sst>'
    )


def workbook_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets>'
        '<sheet name="summary" sheetId="1" r:id="rId1"/>'
        '<sheet name="events" sheetId="2" r:id="rId2"/>'
        '</sheets>'
        '</workbook>'
    )


def workbook_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet2.xml"/>'
        '<Relationship Id="rId3" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" '
        'Target="sharedStrings.xml"/>'
        '</Relationships>'
    )


def root_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )


def content_types_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/worksheets/sheet2.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/sharedStrings.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '</Types>'
    )


def write_xlsx(path: Path, summary_rows: list[list], event_rows: list[list]) -> None:
    shared, strings = build_shared_strings([summary_rows, event_rows])
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml())
        zf.writestr("_rels/.rels", root_rels_xml())
        zf.writestr("xl/workbook.xml", workbook_xml())
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml())
        zf.writestr("xl/sharedStrings.xml", shared_strings_xml(strings))
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml(summary_rows, shared))
        zf.writestr("xl/worksheets/sheet2.xml", sheet_xml(event_rows, shared))


def main() -> int:
    args = parse_args()
    payload = load_json(ROOT / args.input_json)
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_rows, event_rows = build_rows(payload)
    write_csv(output_dir / "top10_micro_summary.csv", summary_rows)
    write_csv(output_dir / "top10_micro_events.csv", event_rows)
    write_xlsx(output_dir / "top10_micro_review.xlsx", summary_rows, event_rows)
    print(output_dir / "top10_micro_review.xlsx")
    print(output_dir / "top10_micro_summary.csv")
    print(output_dir / "top10_micro_events.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
