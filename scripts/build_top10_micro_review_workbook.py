import csv
import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
RAW_JSON = ROOT / "docs" / "lof_top10micro_review_2026-05-10" / "top10_micro_raw_events.json"
SUMMARY_CSV = ROOT / "docs" / "lof_top10micro_review_2026-05-10" / "top10_micro_summary.csv"
OUT_XLSX = ROOT / "docs_active" / "top10_micro_rawlog_with_context_2026-05-19.xlsx"


def column_letter(index: int) -> str:
    result = ""
    while index > 0:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result


def build_shared_strings(sheet_rows):
    strings = []
    index_map = {}

    def add(value: str) -> int:
        if value not in index_map:
            index_map[value] = len(strings)
            strings.append(value)
        return index_map[value]

    for _, rows in sheet_rows:
        for row in rows:
            for value in row:
                if isinstance(value, str):
                    add(value)
    return strings, index_map


def infer_numeric(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


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
                text = "" if value is None else str(value)
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
        xml.append(f'<sheet name="{escape(name)}" sheetId="{idx}" r:id="rId{idx}"/>')
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
      <a:majorFont>
        <a:latin typeface="Aptos"/>
        <a:ea typeface="Yu Gothic"/>
        <a:cs typeface=""/>
      </a:majorFont>
      <a:minorFont>
        <a:latin typeface="Aptos"/>
        <a:ea typeface="Yu Gothic"/>
        <a:cs typeface=""/>
      </a:minorFont>
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
    titles = "".join(f"<vt:lpstr>{escape(name)}</vt:lpstr>" for name in sheet_names)
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
  <dc:title>top10 micro rawlog with context</dc:title>
  <dc:creator>OpenAI Codex</dc:creator>
  <cp:lastModifiedBy>OpenAI Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>
</cp:coreProperties>"""


def parse_data():
    raw = json.loads(RAW_JSON.read_text(encoding="utf-8"))
    summary_rows = list(csv.DictReader(SUMMARY_CSV.open(encoding="utf-8-sig")))
    summary_map = {int(r["micro_rank"]): r for r in summary_rows}
    return raw["micro_chunks"], summary_map


def review_group(rank: int, attack_events: int, processes: str):
    if rank in {1, 3, 4, 5, 8}:
        return "attack_nearby", "Attack近傍として先に読む"
    if rank == 2:
        return "boundary_case", "正常ラベルだがpayload.exeを含む境界事例"
    if rank in {6, 7, 9, 10}:
        return "normal_candidate", "正常ユースケース候補として重点確認"
    if attack_events > 0:
        return "attack_nearby", "Attack近傍"
    if "payload.exe" in processes:
        return "boundary_case", "Payload混在"
    return "normal_candidate", "正常候補"


def build_overview_rows(micro_chunks):
    attack_chunk_count = sum(1 for mc in micro_chunks if mc["attack_events"] > 0)
    normal_only_chunk_count = sum(1 for mc in micro_chunks if mc["attack_events"] == 0)
    attack_events = sum(mc["attack_events"] for mc in micro_chunks)
    normal_events = sum(mc["normal_events"] for mc in micro_chunks)

    rows = [
        ["section", "item", "value", "note"],
        ["summary", "target_model", "LOF third pass top10 micro-chunk", "10-event単位の異常検知結果"],
        ["summary", "micro_chunk_count", len(micro_chunks), "top10なので10窓"],
        ["summary", "event_count", attack_events + normal_events, "各窓10 eventなので合計100 event"],
        ["summary", "attack_including_micro_chunks", attack_chunk_count, "attack eventを1件以上含む窓"],
        ["summary", "normal_only_micro_chunks", normal_only_chunk_count, "attack eventを含まない窓"],
        ["summary", "attack_events_total", attack_events, "100 event中のattack event総数"],
        ["summary", "normal_events_total", normal_events, "100 event中のnormal event総数"],
        ["read_order", "1", "rank 1, 3, 4, 5, 8", "attack近傍としてまず確認"],
        ["read_order", "2", "rank 6, 7, 9, 10", "正常ユースケース候補として確認"],
        ["read_order", "3", "rank 2", "正常ラベルだがpayload.exe混在のため境界事例として扱う"],
        ["source", "raw_events_json", str(RAW_JSON.relative_to(ROOT)), "全100 eventの元データ"],
        ["source", "summary_csv", str(SUMMARY_CSV.relative_to(ROOT)), "top10窓のサマリ"],
    ]
    return rows


def build_micro_chunk_rows(micro_chunks, summary_map):
    rows = [[
        "micro_rank",
        "review_group",
        "review_note",
        "micro_chunk_id",
        "parent_session_id",
        "coarse_chunk_rank",
        "coarse_chunk_index",
        "micro_chunk_index",
        "score",
        "attack_events",
        "normal_events",
        "total_events",
        "attack_including",
        "top_processes",
        "top_event_ids",
        "supplementary_interpretation",
    ]]
    note_map = {
        1: "payload.exe主体のattack近傍。LOF最上位で異常側を強く表す。",
        2: "normal-onlyだがpayload.exeを含む。clean normalというより攻撃隣接の混合文脈。",
        3: "payload.exeの4663が複数回出るattack近傍。",
        4: "payload.exe主体のattack近傍。rank3親窓内の別局所窓。",
        5: "payload.exe主体のattack近傍。親chunk rankは8だが局所的に濃い。",
        6: "repmgr.exeが4件まとまって出る正常候補。文書系seedとして見やすい。",
        7: "explorer.exeが後半3件出る正常候補。ファイル操作系seedとして見やすい。",
        8: "attack eventは1件だがpayload.exe混在。attack近傍として読む方が安全。",
        9: "repmgr.exeが終端に1件出る正常候補。文書系の補助根拠。",
        10: "winword.exeが先頭に1件出る正常候補。文書閲覧文脈の補助根拠。",
    }
    for mc in micro_chunks:
        rank = int(mc["micro_rank"])
        top_processes = ", ".join(f"{name}:{count}" for name, count in mc["top_processes"])
        top_event_ids = ", ".join(f"{eid}:{count}" for eid, count in mc["top_event_ids"])
        group, group_note = review_group(rank, mc["attack_events"], top_processes)
        rows.append([
            rank,
            group,
            group_note,
            mc["micro_chunk_id"],
            mc["parent_session_id"],
            mc["coarse_chunk_rank"],
            mc["coarse_chunk_index"],
            mc["micro_chunk_index"],
            summary_map[rank]["score"],
            mc["attack_events"],
            mc["normal_events"],
            mc["total_events"],
            "yes" if mc["attack_events"] > 0 else "no",
            top_processes,
            top_event_ids,
            note_map.get(rank, ""),
        ])
    return rows


def build_event_rows(micro_chunks):
    rows = [[
        "micro_rank",
        "review_group",
        "micro_chunk_id",
        "parent_session_id",
        "coarse_chunk_rank",
        "coarse_chunk_index",
        "micro_chunk_index",
        "micro_score",
        "micro_attack_events",
        "micro_normal_events",
        "micro_top_processes",
        "event_no_in_micro",
        "offset_in_session",
        "label",
        "label_name",
        "event_id",
        "process",
        "provider",
        "channel",
        "object_type",
        "template",
        "fields_json",
        "event_interpretation",
    ]]
    for mc in micro_chunks:
        rank = int(mc["micro_rank"])
        top_processes = ", ".join(f"{name}:{count}" for name, count in mc["top_processes"])
        group, _ = review_group(rank, mc["attack_events"], top_processes)
        for event in mc["events"]:
            fields = event.get("fields", {})
            label = int(event["label"])
            process = event.get("process", "")
            object_type = fields.get("ObjectType", "")
            label_name = "attack" if label == 1 else "normal"
            if label == 1:
                interp = "attack event。異常検知がどの攻撃断片を含んだかを見る。"
            elif process in {"repmgr.exe", "explorer.exe", "winword.exe"}:
                interp = "正常候補として重要。人の行動として意味づけしやすい。"
            elif process == "payload.exe":
                interp = "label上はnormalでもpayload.exeを含むため境界的。攻撃隣接として注意。"
            elif process == "tpautoconnect.exe":
                interp = "背景反復プロセス。候補窓の周辺ノイズとして読む。"
            else:
                interp = "補助的な周辺イベント。"
            rows.append([
                rank,
                group,
                mc["micro_chunk_id"],
                mc["parent_session_id"],
                mc["coarse_chunk_rank"],
                mc["coarse_chunk_index"],
                mc["micro_chunk_index"],
                mc["score"],
                mc["attack_events"],
                mc["normal_events"],
                top_processes,
                event["offset_in_micro"],
                event["offset_in_session"],
                label,
                label_name,
                event.get("event_id", ""),
                process,
                fields.get("Provider", ""),
                fields.get("Channel", ""),
                object_type,
                event.get("template", ""),
                json.dumps(fields, ensure_ascii=False, sort_keys=True),
                interp,
            ])
    return rows


def build_sources_rows():
    return [
        ["kind", "path", "description"],
        ["raw_events_json", str(RAW_JSON.relative_to(ROOT)), "top10 micro-chunkの全100 event rawレビュー元データ"],
        ["summary_csv", str(SUMMARY_CSV.relative_to(ROOT)), "top10 micro-chunkの窓サマリ"],
        ["reference_md", "docs/lof_top10micro_review_2026-05-10/top10_micro_index.md", "既存のMarkdownレビュー"],
        ["reference_md", "docs/LOF_micro10_実務レビュー集合_2026-05-10.md", "attack近傍帯/正常候補帯の補助説明"],
        ["reference_md", "docs/thirdpass_top10chunk_micro10_2026-05-10/summary.md", "third pass全体要約"],
    ]


def write_xlsx(sheet_rows):
    strings, string_map = build_shared_strings(sheet_rows)
    OUT_XLSX.parent.mkdir(parents=True, exist_ok=True)
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


def main():
    micro_chunks, summary_map = parse_data()
    sheet_rows = [
        ("overview", build_overview_rows(micro_chunks)),
        ("micro_chunks", build_micro_chunk_rows(micro_chunks, summary_map)),
        ("all_events", build_event_rows(micro_chunks)),
        ("sources", build_sources_rows()),
    ]
    write_xlsx(sheet_rows)
    print(OUT_XLSX)


if __name__ == "__main__":
    main()
