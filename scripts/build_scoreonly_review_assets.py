import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
MODEL_RUNS = ROOT / "analysis_data" / "model_runs"
DOCS_ACTIVE = ROOT / "docs_active"
OUT_XLSX = DOCS_ACTIVE / "security_sysmon_mixed_usecases_400rawlogs_2026-05-20.xlsx"
OUT_SVG = DOCS_ACTIVE / "security_sysmon_mixed_usecases_top_sequences_2026-05-20.svg"

SCENARIOS = [
    {"key": "s4", "label": "S4", "usecase_focus": "upd.exe を含む正常側文脈"},
    {"key": "m4", "label": "M4", "usecase_focus": "mmc / excel / winword を含む正常側文脈"},
    {"key": "m6", "label": "M6", "usecase_focus": "excel を含む正常側文脈"},
    {"key": "s3", "label": "S3", "usecase_focus": "attack-near 対照例"},
]


def xml_safe(text) -> str:
    value = "" if text is None else str(text)
    cleaned = []
    for ch in value:
        code = ord(ch)
        if code in (0x9, 0xA, 0xD) or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF:
            cleaned.append(ch)
    return "".join(cleaned)


def column_letter(index: int) -> str:
    result = ""
    while index > 0:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result


def infer_numeric(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def build_shared_strings(sheet_rows):
    strings = []
    index_map = {}
    for _, rows in sheet_rows:
        for row in rows:
            for value in row:
                if isinstance(value, str):
                    safe = xml_safe(value)
                    if safe not in index_map:
                        index_map[safe] = len(strings)
                        strings.append(safe)
    return strings, index_map


def sheet_xml(rows, shared_string_map):
    max_cols = max(len(r) for r in rows) if rows else 1
    xml = []
    xml.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    xml.append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    xml.append(f'<dimension ref="A1:{column_letter(max_cols)}{len(rows)}"/>')
    xml.append('<sheetViews><sheetView workbookViewId="0"/></sheetViews>')
    xml.append('<sheetFormatPr defaultRowHeight="18"/>')
    xml.append("<sheetData>")
    for row_idx, row in enumerate(rows, start=1):
        xml.append(f'<row r="{row_idx}">')
        for col_idx, value in enumerate(row, start=1):
            ref = f"{column_letter(col_idx)}{row_idx}"
            numeric = infer_numeric(value)
            if numeric is not None:
                xml.append(f'<c r="{ref}"><v>{numeric}</v></c>')
            else:
                text = xml_safe(value)
                s_idx = shared_string_map[text]
                xml.append(f'<c r="{ref}" t="s"><v>{s_idx}</v></c>')
        xml.append("</row>")
    xml.append("</sheetData></worksheet>")
    return "".join(xml)


def shared_strings_xml(strings):
    items = "".join(f'<si><t xml:space="preserve">{escape(s)}</t></si>' for s in strings)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(strings)}" uniqueCount="{len(strings)}">{items}</sst>'
    )


def workbook_xml(sheet_names):
    sheets = "".join(
        f'<sheet name="{escape(xml_safe(name)[:31])}" sheetId="{idx}" r:id="rId{idx}"/>'
        for idx, name in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<workbookPr defaultThemeVersion="166925"/>'
        f'<sheets>{sheets}</sheets>'
        '</workbook>'
    )


def workbook_rels_xml(sheet_count):
    rels = []
    for idx in range(1, sheet_count + 1):
        rels.append(
            f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>'
        )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>'
    )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 3}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + '</Relationships>'
    )


def root_rels_xml():
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""


def content_types_xml(sheet_count):
    overrides = [
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
        '<Override PartName="/xl/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>',
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>',
    ]
    for idx in range(1, sheet_count + 1):
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(overrides)
        + '</Types>'
    )


def styles_xml():
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><color theme="1"/><name val="Aptos"/><family val="2"/><scheme val="minor"/></font></fonts>
  <fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


def theme_xml():
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office Theme">
  <a:themeElements>
    <a:clrScheme name="Office">
      <a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>
      <a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>
      <a:dk2><a:srgbClr val="1F1F1F"/></a:dk2>
      <a:lt2><a:srgbClr val="EEECE1"/></a:lt2>
      <a:accent1><a:srgbClr val="4F81BD"/></a:accent1>
      <a:accent2><a:srgbClr val="C0504D"/></a:accent2>
      <a:accent3><a:srgbClr val="9BBB59"/></a:accent3>
      <a:accent4><a:srgbClr val="8064A2"/></a:accent4>
      <a:accent5><a:srgbClr val="4BACC6"/></a:accent5>
      <a:accent6><a:srgbClr val="F79646"/></a:accent6>
      <a:hlink><a:srgbClr val="0000FF"/></a:hlink>
      <a:folHlink><a:srgbClr val="800080"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="Office">
      <a:majorFont><a:latin typeface="Aptos"/><a:ea typeface="Yu Gothic"/><a:cs typeface=""/></a:majorFont>
      <a:minorFont><a:latin typeface="Aptos"/><a:ea typeface="Yu Gothic"/><a:cs typeface=""/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="Office">
      <a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>
      <a:lnStyleLst><a:ln w="9525" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>
      <a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
      <a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
  <a:objectDefaults/>
  <a:extraClrSchemeLst/>
</a:theme>"""


def app_xml(sheet_names):
    titles = "".join(f"<vt:lpstr>{escape(xml_safe(name))}</vt:lpstr>" for name in sheet_names)
    heading_pairs = f"&lt;vt:vector size=&quot;2&quot; baseType=&quot;variant&quot;&gt;&lt;vt:variant&gt;&lt;vt:lpstr&gt;Worksheets&lt;/vt:lpstr&gt;&lt;/vt:variant&gt;&lt;vt:variant&gt;&lt;vt:i4&gt;{len(sheet_names)}&lt;/vt:i4&gt;&lt;/vt:variant&gt;&lt;/vt:vector&gt;"
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Microsoft Excel</Application>
  <DocSecurity>0</DocSecurity>
  <ScaleCrop>false</ScaleCrop>
  <HeadingPairs>{heading_pairs}</HeadingPairs>
  <TitlesOfParts><vt:vector size="{len(sheet_names)}" baseType="lpstr">{titles}</vt:vector></TitlesOfParts>
  <Company>OpenAI</Company>
  <LinksUpToDate>false</LinksUpToDate>
  <SharedDoc>false</SharedDoc>
  <HyperlinksChanged>false</HyperlinksChanged>
  <AppVersion>16.0300</AppVersion>
</Properties>"""


def core_xml():
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>security sysmon score only usecases 400 raw logs</dc:title>
  <dc:creator>OpenAI Codex</dc:creator>
  <cp:lastModifiedBy>OpenAI Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>
</cp:coreProperties>"""


def write_xlsx(sheet_rows):
    strings, string_map = build_shared_strings(sheet_rows)
    sheet_names = [name for name, _ in sheet_rows]
    with zipfile.ZipFile(OUT_XLSX, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml(len(sheet_rows)))
        zf.writestr("_rels/.rels", root_rels_xml())
        zf.writestr("docProps/app.xml", app_xml(sheet_names))
        zf.writestr("docProps/core.xml", core_xml())
        zf.writestr("xl/workbook.xml", workbook_xml(sheet_names))
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheet_rows)))
        zf.writestr("xl/styles.xml", styles_xml())
        zf.writestr("xl/theme/theme1.xml", theme_xml())
        zf.writestr("xl/sharedStrings.xml", shared_strings_xml(strings))
        for idx, (_, rows) in enumerate(sheet_rows, start=1):
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", sheet_xml(rows, string_map))


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def scenario_data(item: dict) -> dict:
    key = item["key"]
    score_dir = MODEL_RUNS / f"usecase_sysmon100_scoreonly_{key}"
    review = read_json(MODEL_RUNS / f"security_sysmon_review_queue_benign1to4_{key}" / "results.json")
    return {
        **item,
        "score_dir": score_dir,
        "summary": read_json(score_dir / "summary.json"),
        "minutes": read_json(score_dir / "selected_minutes.json"),
        "events": read_json(score_dir / "selected_events.json"),
        "review": review,
    }


def build_overview_rows(data: list[dict]) -> list[list]:
    return [
        ["section", "item", "value", "note"],
        ["purpose", "selection_mode", "score-only", "process 名ルールを使わず score と sequence への紐づきだけで選択"],
        ["purpose", "final_output", "100 event x 4 scenarios", "合計 400 event の raw Sysmon review set"],
        ["legend", "attack_sequence_only", "attack label 付き上位 sequence にだけ支えられる minute/event", "後付け評価にのみ使用"],
        ["legend", "fp_sequence_only", "false positive sequence にだけ支えられる minute/event", "後付け評価にのみ使用"],
        ["legend", "mixed_sequence_support", "attack/FP の両方から支えられる minute/event", "今回ほぼ 0"],
        ["total", "selected_events", sum(d["summary"]["selected_events"] for d in data), "4 scenario 合計"],
    ]


def build_pipeline_rows(data: list[dict]) -> list[list]:
    rows = [[
        "scenario",
        "source_events",
        "source_sessions_used",
        "first_pass_predicted_sequences",
        "first_pass_sequence_events",
        "second_pass_review_events",
        "candidate_minutes",
        "selected_minutes",
        "selected_events",
        "attack_sequence_only_events",
        "fp_sequence_only_events",
        "mixed_sequence_support_events",
    ]]
    source_stats = {
        "s3": {"source_events": 257887, "source_sessions_used": 18},
        "m4": {"source_events": 200015, "source_sessions_used": 14},
        "m6": {"source_events": 220858, "source_sessions_used": 14},
        "s4": {"source_events": 231335, "source_sessions_used": 15},
    }
    for d in data:
        s = d["summary"]
        r = d["review"]["summary"]
        src = source_stats[d["key"]]
        rows.append([
            d["label"],
            src["source_events"],
            src["source_sessions_used"],
            r["predicted_sequences"],
            r["sequence_total_events"],
            r["review_total_events"],
            s["candidate_minutes"],
            s["selected_minutes"],
            s["selected_events"],
            s["selected_event_attachment_breakdown"]["attack_sequence_only"],
            s["selected_event_attachment_breakdown"]["fp_sequence_only"],
            s["selected_event_attachment_breakdown"]["mixed_sequence_support"],
        ])
    return rows


def build_minutes_rows(data: list[dict]) -> list[list]:
    rows = [[
        "scenario",
        "sysmon_session_id",
        "minute_bucket",
        "minute_score",
        "max_sequence_score",
        "combined_score",
        "events_in_minute",
        "selected_event_count",
        "selection_stage",
        "attachment_type",
        "exact_user_support",
        "same_host_support",
        "attached_sequences",
        "top_images",
    ]]
    for d in data:
        for row in d["minutes"]:
            rows.append([
                d["label"],
                row["sysmon_session_id"],
                row["minute_bucket"],
                round(float(row["minute_score"]), 6),
                round(float(row["max_sequence_score"]), 6),
                round(float(row["combined_score"]), 6),
                row["events"],
                row["selected_event_count"],
                row["selection_stage"],
                row["attachment_type"],
                row["exact_user_support"],
                row["same_host_support"],
                "; ".join(
                    f'{item["session_id"]}|score={item["sequence_score"]:.4f}|label={item["sequence_label"]}'
                    for item in row["attached_sequences"]
                ),
                "; ".join(f"{name}:{count}" for name, count in row["top_images"]),
            ])
    return rows


def build_all_events_rows(data: list[dict]) -> list[list]:
    rows = [[
        "scenario",
        "timestamp",
        "sysmon_session_id",
        "minute_bucket",
        "selection_stage",
        "attachment_type",
        "minute_score",
        "combined_score",
        "Computer",
        "EventID",
        "Image",
        "ParentImage",
        "User",
        "IntegrityLevel",
        "CommandLine",
        "ParentCommandLine",
        "TargetFilename",
        "DestinationIp",
        "DestinationPort",
        "SourceIp",
        "SourcePort",
    ]]
    for d in data:
        for row in d["events"]:
            rows.append([
                d["label"],
                row.get("timestamp", ""),
                row.get("sysmon_session_id", ""),
                row.get("minute_bucket", ""),
                row.get("selection_stage", ""),
                row.get("attachment_type", ""),
                row.get("minute_score", ""),
                row.get("combined_score", ""),
                row.get("Computer", ""),
                row.get("EventID", ""),
                row.get("Image", ""),
                row.get("ParentImage", ""),
                row.get("User", ""),
                row.get("IntegrityLevel", ""),
                row.get("CommandLine", ""),
                row.get("ParentCommandLine", ""),
                row.get("TargetFilename", ""),
                row.get("DestinationIp", ""),
                row.get("DestinationPort", ""),
                row.get("SourceIp", ""),
                row.get("SourcePort", ""),
            ])
    return rows


def build_sources_rows(data: list[dict]) -> list[list]:
    rows = [["kind", "path", "description"]]
    rows.append(["security_train_desc", "analysis_data/atlasv2_for_deep-loglizer/benign1to4_cu10/data_desc.json", "Security 学習データの件数"])
    for d in data:
        rows.append(["scoreonly_summary", str((d["score_dir"] / "summary.json").relative_to(ROOT)), f'{d["label"]} score-only summary'])
        rows.append(["scoreonly_events", str((d["score_dir"] / "selected_events.csv").relative_to(ROOT)), f'{d["label"]} selected 100 events'])
        rows.append(["review_queue", str((MODEL_RUNS / f"security_sysmon_review_queue_benign1to4_{d['key']}" / "results.json").relative_to(ROOT)), f'{d["label"]} review queue'])
    return rows


def build_svg(data: list[dict]) -> None:
    width = 1560
    height = 1040
    bg = "#f7f4ec"
    panel = "#fffdf8"
    text = "#1d1d1b"
    sub = "#59554f"
    attack_color = "#c62828"
    fp_color = "#1565c0"
    mix_color = "#f9a825"
    shrink_color = "#6d4c41"
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="{bg}"/>',
        f'<rect x="40" y="40" width="{width-80}" height="{height-80}" rx="28" fill="{panel}" stroke="#e5dccb"/>',
        f'<text x="80" y="100" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="34" font-weight="700" fill="{text}">score-only 抽出の絞り込み量と 100ログ内訳</text>',
        f'<text x="80" y="136" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="18" fill="{sub}">左: 元データから 100ログまでどれだけ縮んだか。右: 100ログが attack-side / FP-side にどう分かれたか。</text>',
    ]
    # legends
    lines += [
        f'<rect x="80" y="930" width="18" height="18" fill="{shrink_color}"/><text x="108" y="945" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">event 数の絞り込み</text>',
        f'<rect x="360" y="930" width="18" height="18" fill="{attack_color}"/><text x="388" y="945" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">attack sequence 側に支えられた event</text>',
        f'<rect x="760" y="930" width="18" height="18" fill="{fp_color}"/><text x="788" y="945" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">false positive sequence 側に支えられた event</text>',
        f'<rect x="1220" y="930" width="18" height="18" fill="{mix_color}"/><text x="1248" y="945" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">mixed support</text>',
    ]
    source_stats = {
        "s3": {"source_events": 257887},
        "m4": {"source_events": 200015},
        "m6": {"source_events": 220858},
        "s4": {"source_events": 231335},
    }
    start_y = 210
    row_h = 170
    left_x = 420
    left_w = 360
    right_x = 940
    right_w = 420
    max_source = max(source_stats[d["key"]]["source_events"] for d in data)
    for idx, d in enumerate(data):
        y = start_y + idx * row_h
        src = source_stats[d["key"]]["source_events"]
        review_events = d["review"]["summary"]["review_total_events"]
        final_events = d["summary"]["selected_events"]
        attack = d["summary"]["selected_event_attachment_breakdown"]["attack_sequence_only"]
        fp = d["summary"]["selected_event_attachment_breakdown"]["fp_sequence_only"]
        mix = d["summary"]["selected_event_attachment_breakdown"]["mixed_sequence_support"]
        src_w = left_w * src / max_source
        review_w = left_w * review_events / max_source
        final_w = left_w * final_events / max_source
        attack_w = right_w * attack / 100
        fp_w = right_w * fp / 100
        mix_w = right_w * mix / 100
        lines += [
            f'<text x="230" y="{y}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="30" font-weight="700" text-anchor="end" fill="{text}">{d["label"]}</text>',
            f'<text x="230" y="{y+26}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="16" text-anchor="end" fill="{sub}">{escape(d["usecase_focus"])}</text>',
            f'<text x="{left_x}" y="{y-20}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">source {src:,} -> review {review_events:,} -> final {final_events}</text>',
            f'<rect x="{left_x}" y="{y-2}" width="{src_w}" height="18" rx="8" fill="#d7ccc8"/>',
            f'<rect x="{left_x}" y="{y+22}" width="{review_w}" height="18" rx="8" fill="#a1887f"/>',
            f'<rect x="{left_x}" y="{y+46}" width="{final_w}" height="18" rx="8" fill="{shrink_color}"/>',
            f'<text x="{left_x+left_w+12}" y="{y+12}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="14" fill="{sub}">{src:,}</text>',
            f'<text x="{left_x+left_w+12}" y="{y+36}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="14" fill="{sub}">{review_events:,}</text>',
            f'<text x="{left_x+left_w+12}" y="{y+60}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="14" fill="{sub}">{final_events}</text>',
            f'<text x="{right_x}" y="{y-20}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">100ログの内訳: attack-side {attack} / FP-side {fp} / mixed {mix}</text>',
            f'<rect x="{right_x}" y="{y-2}" width="{right_w}" height="32" rx="10" fill="#ece7db"/>',
            f'<rect x="{right_x}" y="{y-2}" width="{attack_w}" height="32" rx="10" fill="{attack_color}"/>',
            f'<rect x="{right_x+attack_w}" y="{y-2}" width="{fp_w}" height="32" rx="10" fill="{fp_color}"/>',
            f'<rect x="{right_x+attack_w+fp_w}" y="{y-2}" width="{mix_w}" height="32" rx="10" fill="{mix_color}"/>',
            f'<text x="{right_x + attack_w/2}" y="{y+18}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="16" font-weight="700" text-anchor="middle" fill="white">{attack}</text>',
            f'<text x="{right_x + attack_w + fp_w/2}" y="{y+18}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="16" font-weight="700" text-anchor="middle" fill="white">{fp}</text>',
            (f'<text x="{right_x + attack_w + fp_w + mix_w/2}" y="{y+18}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="16" font-weight="700" text-anchor="middle" fill="#4e342e">{mix}</text>' if mix > 0 else ""),
        ]
    lines += [
        f'<text x="80" y="885" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">解釈: S3 / M4 / S4 は rule-free な score-only 抽出でも attack-side と FP-side の両方が残る。M6 は upstream の sequence 段階で attack が残っていないため 100ログでも attack-side が 0 になる。</text>',
        "</svg>",
    ]
    OUT_SVG.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    data = [scenario_data(s) for s in SCENARIOS]
    build_svg(data)
    sheet_rows = [
        ("overview", build_overview_rows(data)),
        ("pipeline", build_pipeline_rows(data)),
        ("selected_minutes", build_minutes_rows(data)),
        ("all_400_events", build_all_events_rows(data)),
        ("sources", build_sources_rows(data)),
    ]
    write_xlsx(sheet_rows)
    print(OUT_SVG)
    print(OUT_XLSX)


if __name__ == "__main__":
    main()
