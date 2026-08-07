import csv
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
MODEL_RUNS = ROOT / "analysis_data" / "model_runs"
DOCS_ACTIVE = ROOT / "docs_active"
OUT_XLSX = DOCS_ACTIVE / "security_sysmon_mixed_usecases_400rawlogs_2026-05-20.xlsx"
OUT_SVG = DOCS_ACTIVE / "security_sysmon_mixed_usecases_top_sequences_2026-05-20.svg"

SCENARIOS = [
    {
        "key": "s4",
        "label": "S4",
        "usecase_core": "upd.exe",
        "attack_focus": "powershell/mshta/payload",
    },
    {
        "key": "m4",
        "label": "M4",
        "usecase_core": "mmc/excel/winword",
        "attack_focus": "payload.exe",
    },
    {
        "key": "m6",
        "label": "M6",
        "usecase_core": "excel.exe",
        "attack_focus": "winword/eqnedt32/regsvr32",
    },
    {
        "key": "s3",
        "label": "S3",
        "usecase_core": "no stable normal core",
        "attack_focus": "payload/powershell/cmd",
    },
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
    xml.append("</sheetData>")
    xml.append("</worksheet>")
    return "".join(xml)


def shared_strings_xml(strings):
    xml = []
    xml.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    xml.append(
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(strings)}" uniqueCount="{len(strings)}">'
    )
    for s in strings:
        xml.append(f'<si><t xml:space="preserve">{escape(s)}</t></si>')
    xml.append("</sst>")
    return "".join(xml)


def workbook_xml(sheet_names):
    xml = []
    xml.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    xml.append('<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">')
    xml.append('<workbookPr defaultThemeVersion="166925"/>')
    xml.append("<sheets>")
    for idx, name in enumerate(sheet_names, start=1):
        xml.append(f'<sheet name="{escape(xml_safe(name)[:31])}" sheetId="{idx}" r:id="rId{idx}"/>')
    xml.append("</sheets></workbook>")
    return "".join(xml)


def workbook_rels_xml(sheet_count):
    xml = []
    xml.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    xml.append('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')
    for idx in range(1, sheet_count + 1):
        xml.append(
            f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>'
        )
    xml.append(
        f'<Relationship Id="rId{sheet_count + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    xml.append(
        f'<Relationship Id="rId{sheet_count + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>'
    )
    xml.append(
        f'<Relationship Id="rId{sheet_count + 3}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
    )
    xml.append("</Relationships>")
    return "".join(xml)


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
        + "</Types>"
    )


def styles_xml():
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1">
    <font>
      <sz val="11"/>
      <color theme="1"/>
      <name val="Aptos"/>
      <family val="2"/>
      <scheme val="minor"/>
    </font>
  </fonts>
  <fills count="2">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
  </fills>
  <borders count="1">
    <border><left/><right/><top/><bottom/><diagonal/></border>
  </borders>
  <cellStyleXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
  </cellStyleXfs>
  <cellXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
  </cellXfs>
  <cellStyles count="1">
    <cellStyle name="Normal" xfId="0" builtinId="0"/>
  </cellStyles>
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
    heading_pairs = f"&lt;vt:vector size=&quot;2&quot; baseType=&quot;variant&quot;&gt;&lt;vt:variant&gt;&lt;vt:lpstr&gt;Worksheets&lt;/vt:lpstr&gt;&lt;/vt:variant&gt;&lt;vt:variant&gt;&lt;vt:i4&gt;{len(sheet_names)}&lt;/vt:i4&gt;&lt;/vt:variant&gt;&lt;/vt:vector&gt;"
    titles = "".join(f"<vt:lpstr>{escape(xml_safe(name))}</vt:lpstr>" for name in sheet_names)
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
  <dc:title>security sysmon mixed usecases 400 raw logs</dc:title>
  <dc:creator>OpenAI Codex</dc:creator>
  <cp:lastModifiedBy>OpenAI Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>
</cp:coreProperties>"""


def write_xlsx(sheet_rows):
    strings, string_map = build_shared_strings(sheet_rows)
    sheet_names = [name for name, _ in sheet_rows]
    OUT_XLSX.parent.mkdir(parents=True, exist_ok=True)
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


def top_images_text(minute_row: dict) -> str:
    items = minute_row.get("top_images", [])
    if items and isinstance(items[0], list):
        return ", ".join(f"{name}:{count}" for name, count in items)
    return ", ".join(str(x) for x in items)


def attached_sequence_text(minute_row: dict) -> str:
    parts = []
    for seq in minute_row.get("attached_sequences", []):
        parts.append(f'{seq.get("coarse_bucket","")} label={seq.get("sequence_label","")}')
    return " | ".join(parts)


def scenario_data(s: dict) -> dict:
    key = s["key"]
    base = MODEL_RUNS / f"usecase_sysmon100_mixed_{key}"
    review = read_json(MODEL_RUNS / f"security_sysmon_review_queue_benign1to4_{key}" / "results.json")
    summary = read_json(base / "summary.json")
    minutes = read_json(base / "selected_minutes.json")
    events = read_json(base / "selected_events.json")
    minute_map = {m["sysmon_session_id"]: m for m in minutes}
    return {
        **s,
        "base": base,
        "review": review,
        "summary": summary,
        "minutes": minutes,
        "events": events,
        "minute_map": minute_map,
    }


def scenario_interpretation(item: dict) -> str:
    label = item["label"]
    if label == "S4":
        return "attack と normal の同居が最も明確"
    if label == "M4":
        return "normal 核が太く usecase 化しやすい"
    if label == "M6":
        return "attack は残るが normal 核は細い"
    return "attack-near 対照例として使いやすい"


def build_overview_rows(data: list[dict]) -> list[list]:
    rows = [
        ["section", "item", "value", "note"],
        ["summary", "target", "Top anomaly sequences -> mixed 100 raw logs x 4 scenarios", "各 scenario 100 event, 合計 400 event"],
        ["summary", "reading_goal", "attack と normal-context の混在比率を見て normal 側から usecase を作る", "attack は除外しない"],
        ["summary", "total_selected_events", sum(d["summary"]["selected_events"] for d in data), "4 scenario 合計"],
        ["summary", "scenarios", ", ".join(d["label"] for d in data), "優先度は S4 -> M4 -> M6 -> S3"],
        ["legend", "attack_near", "payload/powershell/mshta/regsvr32 など", "攻撃近傍の minute と event"],
        ["legend", "normal_context", "core_normal + neutral_context + background_context", "usecase 化の母集団"],
        ["legend", "core_normal", "mmc/excel/winword/upd など", "normal usecase の核"],
    ]
    return rows


def build_scenario_summary_rows(data: list[dict]) -> list[list]:
    rows = [[
        "scenario",
        "usecase_core",
        "attack_focus",
        "predicted_sequences",
        "tp_sequences",
        "fp_sequences",
        "selected_minutes",
        "selected_events",
        "attack_near_events",
        "normal_context_events",
        "core_normal_events",
        "attack_share_pct",
        "normal_context_share_pct",
        "interpretation",
    ]]
    for d in data:
        s = d["summary"]
        r = d["review"]["summary"]
        attack = s["selected_event_counts"]["attack_near"]
        normal = (
            s["selected_event_counts"]["core_normal"]
            + s["selected_event_counts"]["neutral_context"]
            + s["selected_event_counts"]["background_context"]
        )
        total = s["selected_events"]
        rows.append([
            d["label"],
            d["usecase_core"],
            d["attack_focus"],
            r["predicted_sequences"],
            r["true_positive_sequences"],
            r["false_positive_sequences"],
            s["selected_minutes"],
            total,
            attack,
            normal,
            s["selected_event_counts"]["core_normal"],
            round(attack * 100 / total, 1),
            round(normal * 100 / total, 1),
            scenario_interpretation(d),
        ])
    return rows


def build_minute_index_rows(data: list[dict]) -> list[list]:
    rows = [[
        "scenario",
        "classification",
        "sysmon_session_id",
        "minute_bucket",
        "minute_score",
        "selected_event_count",
        "top_images",
        "top_event_ids",
        "attached_sequences",
        "usecase_core",
    ]]
    for d in data:
        for minute in d["minutes"]:
            rows.append([
                d["label"],
                minute.get("classification", ""),
                minute.get("sysmon_session_id", ""),
                minute.get("minute_bucket", ""),
                round(float(minute.get("score", 0.0)), 6),
                minute.get("selected_event_count", 0),
                top_images_text(minute),
                ", ".join(f"{eid}:{count}" for eid, count in minute.get("top_event_ids", [])),
                attached_sequence_text(minute),
                d["usecase_core"],
            ])
    return rows


def event_process_name(ev: dict) -> str:
    image = ev.get("Image", "") or ""
    if not image:
        return ""
    return Path(image).name.lower()


def build_all_events_rows(data: list[dict]) -> list[list]:
    rows = [[
        "scenario",
        "classification",
        "usecase_core",
        "minute_bucket",
        "sysmon_session_id",
        "minute_score",
        "attached_sequences",
        "timestamp",
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
        "Description",
        "Product",
        "Company",
        "OriginalFileName",
        "event_note",
    ]]
    for d in data:
        for ev in d["events"]:
            user_part = (ev.get("User", "") or "").split("\\")[-1].lower()
            utc_time = ev.get("UtcTime", "") or ""
            compact_time = utc_time.replace(" ", "T").replace(":", "")
            minute_bucket = utc_time.replace(" ", "T").replace("-", "").replace(":", "")[:13] + "Z" if utc_time else ""
            session_id = f'{ev.get("Computer","")}|{user_part}|{compact_time[:13]}Z'
            minute_info = d["minute_map"].get(session_id)
            if minute_info is None:
                minute_info = next((m for m in d["minutes"] if m.get("minute_bucket") == minute_bucket and session_id.startswith(f'{ev.get("Computer","")}|')), None)
            classification = minute_info.get("classification", "") if minute_info else ""
            process_name = event_process_name(ev)
            if classification == "attack_near":
                note = "攻撃近傍 minute 内の生ログ"
            elif classification == "core_normal":
                note = "usecase 核 minute 内の生ログ"
            elif process_name in {"repwmiutils.exe", "dllhost.exe", "conhost.exe"}:
                note = "周辺文脈または背景動作"
            else:
                note = "normal/context 側の補助ログ"
            rows.append([
                d["label"],
                classification,
                d["usecase_core"],
                minute_info.get("minute_bucket", minute_bucket) if minute_info else minute_bucket,
                minute_info.get("sysmon_session_id", session_id) if minute_info else session_id,
                round(float(minute_info.get("score", 0.0)), 6) if minute_info else "",
                attached_sequence_text(minute_info) if minute_info else "",
                ev.get("@timestamp", ""),
                ev.get("EventID", ""),
                ev.get("Image", ""),
                ev.get("ParentImage", ""),
                ev.get("User", ""),
                ev.get("IntegrityLevel", ""),
                ev.get("CommandLine", ""),
                ev.get("ParentCommandLine", ""),
                ev.get("TargetFilename", ""),
                ev.get("DestinationIp", ""),
                ev.get("DestinationPort", ""),
                ev.get("SourceIp", ""),
                ev.get("SourcePort", ""),
                ev.get("Description", ""),
                ev.get("Product", ""),
                ev.get("Company", ""),
                ev.get("OriginalFileName", ""),
                note,
            ])
    return rows


def build_scenario_event_rows(d: dict) -> list[list]:
    all_rows = build_all_events_rows([d])
    return all_rows


def build_sources_rows(data: list[dict]) -> list[list]:
    rows = [["kind", "path", "description"]]
    for d in data:
        rows.append(["summary_json", str((d["base"] / "summary.json").relative_to(ROOT)), f'{d["label"]} の 100ログ要約'])
        rows.append(["selected_events_json", str((d["base"] / "selected_events.json").relative_to(ROOT)), f'{d["label"]} の raw sysmon 100 event'])
        rows.append(["selected_minutes_json", str((d["base"] / "selected_minutes.json").relative_to(ROOT)), f'{d["label"]} の selected minute index'])
        rows.append(["review_queue_json", str((MODEL_RUNS / f"security_sysmon_review_queue_benign1to4_{d['key']}" / "results.json").relative_to(ROOT)), f'{d["label"]} の top anomaly sequences'])
    return rows


def build_svg(data: list[dict]) -> None:
    width = 1500
    height = 1080
    margin_left = 250
    bar_x = 500
    seq_bar_w = 360
    event_bar_w = 720
    row_h = 205
    start_y = 230
    attack_color = "#c62828"
    normal_color = "#1565c0"
    core_color = "#f9a825"
    seq_normal_color = "#9e9e9e"
    bg = "#f7f4ec"
    panel = "#fffdf8"
    text = "#1d1d1b"
    sub = "#59554f"
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="{bg}"/>',
        f'<rect x="40" y="40" width="{width-80}" height="{height-80}" rx="28" fill="{panel}" stroke="#e5dccb"/>',
        f'<text x="80" y="100" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="34" font-weight="700" fill="{text}">上位異常シーケンスと抽出100ログの分布</text>',
        f'<text x="80" y="138" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="18" fill="{sub}">左は上位に来た異常シーケンス本数、右はそこから抽出した100件の生Sysmonログの内訳。</text>',
        f'<text x="500" y="185" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="18" font-weight="700" fill="{text}">上位異常シーケンス</text>',
        f'<text x="910" y="185" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="18" font-weight="700" fill="{text}">抽出した100ログ</text>',
        f'<text x="{bar_x}" y="210" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">攻撃シーケンス / 正常シーケンス</text>',
        f'<text x="{bar_x + seq_bar_w + 50}" y="210" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">攻撃近傍 / 正常・周辺文脈 / うち正常核</text>',
        f'<rect x="80" y="960" width="18" height="18" fill="{attack_color}" stroke="#7f0000"/><text x="108" y="975" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">攻撃近傍</text>',
        f'<rect x="250" y="960" width="18" height="18" fill="{seq_normal_color}" stroke="#616161"/><text x="278" y="975" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">正常シーケンス</text>',
        f'<rect x="470" y="960" width="18" height="18" fill="{normal_color}" stroke="#0d47a1"/><text x="498" y="975" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">正常・周辺文脈</text>',
        f'<rect x="750" y="960" width="18" height="18" fill="{core_color}" stroke="#e65100"/><text x="778" y="975" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" fill="{text}">正常核</text>',
    ]
    for i, d in enumerate(data):
        y = start_y + i * row_h
        s = d["summary"]
        r = d["review"]["summary"]
        attack = s["selected_event_counts"]["attack_near"]
        normal = s["selected_event_counts"]["core_normal"] + s["selected_event_counts"]["neutral_context"] + s["selected_event_counts"]["background_context"]
        core = s["selected_event_counts"]["core_normal"]
        attack_w = event_bar_w * attack / 100
        normal_w = event_bar_w * normal / 100
        core_w = event_bar_w * core / 100
        pred = max(r["predicted_sequences"], 1)
        tp = r["true_positive_sequences"]
        fp = r["false_positive_sequences"]
        tp_w = seq_bar_w * tp / pred
        fp_w = seq_bar_w * fp / pred
        box_y = y - 55
        lines += [
            f'<rect x="70" y="{box_y}" width="{width-140}" height="150" rx="18" fill="#fffaf0" stroke="#e8decc"/>',
            f'<text x="{margin_left}" y="{y-2}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="30" font-weight="700" text-anchor="end" fill="{text}">{d["label"]}</text>',
            f'<text x="{margin_left}" y="{y+26}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" text-anchor="end" fill="{sub}">ユースケース核: {escape(d["usecase_core"])}</text>',
            f'<text x="{margin_left}" y="{y+50}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="16" text-anchor="end" fill="{sub}">攻撃側主体: {escape(d["attack_focus"])}</text>',
            f'<rect x="{bar_x}" y="{y-28}" width="{seq_bar_w}" height="26" rx="8" fill="#ece7db"/>',
            f'<rect x="{bar_x}" y="{y-28}" width="{tp_w}" height="26" rx="8" fill="{attack_color}"/>',
            f'<rect x="{bar_x+tp_w}" y="{y-28}" width="{fp_w}" height="26" rx="8" fill="{seq_normal_color}"/>',
            f'<text x="{bar_x}" y="{y-38}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="14" fill="{sub}">上位 {pred}本</text>',
            f'<text x="{bar_x + seq_bar_w + 12}" y="{y-8}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{text}">攻撃 {tp} / 正常 {fp}</text>',
            f'<rect x="{bar_x + 410}" y="{y-28}" width="{event_bar_w}" height="34" rx="10" fill="#ece7db"/>',
            f'<rect x="{bar_x + 410}" y="{y-28}" width="{attack_w}" height="34" rx="10" fill="{attack_color}"/>',
            f'<rect x="{bar_x + 410 + attack_w}" y="{y-28}" width="{normal_w}" height="34" rx="10" fill="{normal_color}"/>',
            f'<rect x="{bar_x + 410 + attack_w}" y="{y-28}" width="{core_w}" height="34" rx="10" fill="{core_color}" opacity="0.98"/>',
            f'<text x="{bar_x + 410 + attack_w/2}" y="{y-6}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" font-weight="700" text-anchor="middle" fill="white">{attack}件</text>',
            f'<text x="{bar_x + 410 + attack_w + normal_w/2}" y="{y-6}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="17" font-weight="700" text-anchor="middle" fill="white">{normal}件</text>',
            f'<text x="{bar_x + 410}" y="{y+28}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">100ログ中 攻撃近傍 {attack}% / 正常・周辺文脈 {normal}% / 正常核 {core}件</text>',
            f'<text x="{bar_x + 410}" y="{y+52}" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">選択 minute {s["selected_minutes"]}本</text>',
        ]
    lines += [
        f'<text x="80" y="1015" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">見方: 左で上位に来たシーケンスが攻撃寄りか正常寄りかを見る。右で、その中から作った100ログに攻撃近傍と正常文脈がどの割合で入っているかを見る。</text>',
        f'<text x="80" y="1040" font-family="Segoe UI, Yu Gothic, sans-serif" font-size="15" fill="{sub}">結論: S4 と M4 は、攻撃が見えたまま正常核も残っているため、ユースケース化しやすい。</text>',
        "</svg>",
    ]
    OUT_SVG.write_text("".join(lines), encoding="utf-8")


def validate_xml_strings(sheet_rows) -> None:
    strings, mapping = build_shared_strings(sheet_rows)
    _ = shared_strings_xml(strings)
    for _, rows in sheet_rows:
        _ = sheet_xml(rows, mapping)


def main() -> None:
    data = [scenario_data(s) for s in SCENARIOS]
    build_svg(data)
    sheet_rows = [
        ("overview", build_overview_rows(data)),
        ("scenario_summary", build_scenario_summary_rows(data)),
        ("minute_index", build_minute_index_rows(data)),
        ("all_400_events", build_all_events_rows(data)),
        ("S4_events", build_scenario_event_rows(data[0])),
        ("M4_events", build_scenario_event_rows(data[1])),
        ("M6_events", build_scenario_event_rows(data[2])),
        ("S3_events", build_scenario_event_rows(data[3])),
        ("sources", build_sources_rows(data)),
    ]
    validate_xml_strings(sheet_rows)
    write_xlsx(sheet_rows)
    print(OUT_SVG)
    print(OUT_XLSX)


if __name__ == "__main__":
    main()
