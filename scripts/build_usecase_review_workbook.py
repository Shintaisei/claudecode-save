import argparse
import csv
import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a consolidated workbook for usecase review."
    )
    parser.add_argument("--output-xlsx", required=True)
    return parser.parse_args()


def read_csv_rows(path: Path) -> list[list]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def is_number(value: str) -> bool:
    try:
        float(value)
        return value != ""
    except Exception:
        return False


def col_name(index: int) -> str:
    result = ""
    n = index
    while n > 0:
        n, rem = divmod(n - 1, 26)
        result = chr(65 + rem) + result
    return result


def build_shared_strings(sheets: list[list[list]]) -> tuple[dict[str, int], list[str]]:
    strings = []
    mapping = {}
    for rows in sheets:
        for row in rows:
            for value in row:
                text = "" if value is None else str(value)
                if is_number(text):
                    continue
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
            text = "" if value is None else str(value)
            if is_number(text):
                cells.append(f'<c r="{ref}"><v>{text}</v></c>')
            else:
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


def workbook_xml(sheet_names: list[str]) -> str:
    sheets = "".join(
        f'<sheet name="{escape(name[:31])}" sheetId="{i}" r:id="rId{i}"/>'
        for i, name in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{sheets}</sheets>'
        '</workbook>'
    )


def workbook_rels_xml(sheet_count: int) -> str:
    rels = []
    for i in range(1, sheet_count + 1):
        rels.append(
            f'<Relationship Id="rId{i}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{i}.xml"/>'
        )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" '
        'Target="sharedStrings.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + '</Relationships>'
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


def content_types_xml(sheet_count: int) -> str:
    overrides = [
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    ]
    for i in range(1, sheet_count + 1):
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    overrides.append(
        '<Override PartName="/xl/sharedStrings.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(overrides)
        + '</Types>'
    )


def write_xlsx(path: Path, sheets: list[tuple[str, list[list]]]) -> None:
    sheet_names = [name for name, _ in sheets]
    sheet_rows = [rows for _, rows in sheets]
    shared, strings = build_shared_strings(sheet_rows)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml(len(sheets)))
        zf.writestr("_rels/.rels", root_rels_xml())
        zf.writestr("xl/workbook.xml", workbook_xml(sheet_names))
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheets)))
        zf.writestr("xl/sharedStrings.xml", shared_strings_xml(strings))
        for i, (_, rows) in enumerate(sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{i}.xml", sheet_xml(rows, shared))


def main() -> int:
    args = parse_args()
    base = ROOT / "docs_active"

    candidate_rows = read_csv_rows(base / "usecase_candidate_ranking_2026-05-10.csv")
    top10_rows = read_csv_rows(base / "lof_top10micro_review_2026-05-10" / "top10_micro_summary.csv")
    browser_rows = read_csv_rows(base / "lof_browser_ranks42_47_review_2026-05-10" / "top10_micro_summary.csv")
    background_rows = read_csv_rows(base / "lof_background_ranks74_100_review_2026-05-10" / "top10_micro_summary.csv")

    write_xlsx(
        ROOT / args.output_xlsx,
        [
            ("candidate_summary", candidate_rows),
            ("top10_core", top10_rows),
            ("browser_band", browser_rows),
            ("background_band", background_rows),
        ],
    )
    print(ROOT / args.output_xlsx)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
