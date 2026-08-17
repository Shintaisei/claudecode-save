import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "file:///C:/Users/komat/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs";

const root = process.cwd();
const sourceDir = path.join(
  root,
  "docs/current_experiment/results_2026-08-14/three_model_observable_semantic_v2",
);
const outputDir = path.join(
  root,
  "outputs/019fdadc-05b6-70c2-a054-e19dcccc2d0c",
);
const previewDir = path.join(outputDir, "observable_semantic_rescore_previews");
const outputPath = path.join(outputDir, "FIT2026_observable_semantic_rescore_20260814.xlsx");

const summary = JSON.parse(
  await fs.readFile(path.join(sourceDir, "summary.json"), "utf8"),
);
const runRows = (await fs.readFile(path.join(sourceDir, "observable_rescore_all_384.jsonl"), "utf8"))
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));

const wb = Workbook.create();
const navy = "#18324A";
const blue = "#DCEAF7";
const pale = "#F4F7FA";
const border = "#CBD5E1";
const accent = "#166534";
const warn = "#9A3412";

function styleTitle(sheet, range) {
  const r = sheet.getRange(range);
  r.format.fill = navy;
  r.format.font = { bold: true, color: "#FFFFFF", size: 15 };
  r.format.rowHeight = 28;
}

function styleHeader(sheet, range) {
  const r = sheet.getRange(range);
  r.format.fill = blue;
  r.format.font = { bold: true, color: navy };
  r.format.borders = { preset: "all", style: "thin", color: border };
  r.format.wrapText = true;
}

function styleBody(sheet, range) {
  const r = sheet.getRange(range);
  r.format.borders = { preset: "all", style: "thin", color: border };
  r.format.wrapText = true;
}

function setPercentFormula(sheet, row, hitCol, denCol, rateCol) {
  sheet.getRange(`${rateCol}${row}`).formulas = [[`=IF(${denCol}${row}=0,"",${hitCol}${row}/${denCol}${row})`]];
  sheet.getRange(`${rateCol}${row}`).format.numberFormat = "0.00%";
}

function metricValues(label, value) {
  return [
    label,
    value.run_count,
    value.gold_step_count,
    value.action.hits,
    value.action.denominator,
    null,
    value.precision.hits,
    value.precision.denominator,
    null,
    value.complete_step.hits,
    value.complete_step.denominator,
    null,
    value.evidence.hits,
    value.evidence.denominator,
    null,
    value.order.hits,
    value.order.denominator,
    null,
    value.average_cost_usd,
    value.average_elapsed_seconds,
  ];
}

function populateMetricSheet(sheet, title, rows, firstLabel = "区分") {
  sheet.showGridLines = false;
  sheet.getRange("A1:T1").merge();
  sheet.getRange("A1").values = [[title]];
  styleTitle(sheet, "A1:T1");
  const header = [
    firstLabel,
    "試行数",
    "Gold step",
    "Action hit",
    "Action den",
    "Action",
    "TP slot",
    "Candidate den",
    "Precision",
    "Complete hit",
    "Complete den",
    "Complete step",
    "Evidence hit",
    "Evidence den",
    "Evidence",
    "Order hit",
    "Order den",
    "Order",
    "平均コスト ($)",
    "平均時間 (秒)",
  ];
  sheet.getRange("A3:T3").values = [header];
  styleHeader(sheet, "A3:T3");
  if (rows.length) {
    sheet.getRangeByIndexes(3, 0, rows.length, 20).values = rows.map((r) => metricValues(r.label, r.value));
    for (let i = 0; i < rows.length; i += 1) {
      const row = 4 + i;
      setPercentFormula(sheet, row, "D", "E", "F");
      setPercentFormula(sheet, row, "G", "H", "I");
      setPercentFormula(sheet, row, "J", "K", "L");
      setPercentFormula(sheet, row, "M", "N", "O");
      setPercentFormula(sheet, row, "P", "Q", "R");
    }
    styleBody(sheet, `A4:T${3 + rows.length}`);
  }
  sheet.freezePanes.freezeRows(3);
  sheet.getRange("A:T").format.autofitColumns();
  sheet.getRange("A:A").format.columnWidth = 38;
  for (const col of ["D:E", "G:H", "J:K", "M:N", "P:Q"]) {
    sheet.getRange(col).format.columnWidth = 11;
  }
  for (const col of ["F:F", "I:I", "L:L", "O:O", "R:R"]) {
    sheet.getRange(col).format.columnWidth = 12;
  }
  sheet.getRange("S:S").format.columnWidth = 16;
  sheet.getRange("T:T").format.columnWidth = 16;
  sheet.getRange("S:S").format.numberFormat = "$0.000";
  sheet.getRange("T:T").format.numberFormat = "0.0";
}

const readme = wb.worksheets.add("README");
readme.showGridLines = false;
readme.getRange("A1:H1").merge();
readme.getRange("A1").values = [["FIT2026 全試行 Observable-semantic 再採点"]];
styleTitle(readme, "A1:H1");
readme.getRange("A3:B10").values = [
  ["項目", "内容"],
  ["再採点範囲", `${summary.coverage.rescored_existing_runs}試行・${summary.coverage.gold_steps} Gold step`],
  ["モデル別", "GPT-4.1-mini 144 / GPT-5.4-mini 144 / GPT-5.5 96"],
  ["モデル比較", "従来と同じ共通46 strata。GPT-5.5のbudget-censored 2試行は除外。"],
  ["採用した意味同値", "Gold stepに対応済みの同一観測関係、Word起動コマンドライン中の入力文書、adapterで欠落したlocal port。"],
  ["不正解のまま", "主体・対象の逆転、別endpoint、未提示の関係、捏造、検索上限で取得できなかった証跡。"],
  ["主体の感度分析", "cmd.exe と python.exe のlauncher/interpreter差は採用値に含めず、summary JSONに別記。"],
  ["生成元", "three_model_observable_semantic_v2/summary.json と observable_rescore_all_384.jsonl"],
];
styleHeader(readme, "A3:B3");
styleBody(readme, "A4:B10");
readme.getRange("A:A").format.columnWidth = 23;
readme.getRange("B:B").format.columnWidth = 95;
readme.getRange("A3:B10").format.wrapText = true;
readme.freezePanes.freezeRows(3);

const headline = wb.worksheets.add("全体46strata");
populateMetricSheet(
  headline,
  "3モデル全体比較（共通46 strata）",
  ["gpt-4.1-mini", "gpt-5.4-mini", "gpt-5.5"].map((model) => ({ label: model, value: summary.headline_by_model[model] })),
  "モデル",
);
headline.getRange("A6:T6").format.fill = "#E7F6EC";
headline.getRange("A6:T6").format.font = { bold: true, color: accent };

const stage2 = wb.worksheets.add("GPT55_Stage2");
populateMetricSheet(
  stage2,
  "GPT-5.5 Stage 2：正常／攻撃",
  [
    { label: "正常行動", value: summary.gpt55_headline_phase_stage["normal8/stage2"] },
    { label: "攻撃行動", value: summary.gpt55_headline_phase_stage["attack8/stage2"] },
  ],
  "対象",
);

const stages = wb.worksheets.add("GPT55_全Stage");
const stageRows = [];
for (const [phase, phaseLabel] of [["normal8", "正常"], ["attack8", "攻撃"]]) {
  for (const stage of ["stage1", "stage2", "stage3"]) {
    stageRows.push({ label: `${phaseLabel} / ${stage}`, value: summary.gpt55_headline_phase_stage[`${phase}/${stage}`] });
  }
}
populateMetricSheet(stages, "GPT-5.5 Stage別", stageRows, "対象 / Stage");

const usecase = wb.worksheets.add("GPT55_Stage2_ケース");
const usecaseRows = Object.entries(summary.gpt55_stage2_usecase)
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([key, value]) => {
    const [phase, ...chainParts] = key.split("/");
    return { label: `${phase === "normal8" ? "正常" : "攻撃"} / ${chainParts.join("/")}`, value };
  });
populateMetricSheet(usecase, "GPT-5.5 Stage 2 ユースケース別（各1試行）", usecaseRows, "対象 / ユースケース");
usecase.getRange("A:A").format.columnWidth = 58;

const failure = wb.worksheets.add("失敗分析");
failure.showGridLines = false;
failure.getRange("A1:I1").merge();
failure.getRange("A1").values = [["Observable採点後の失敗分析（追跡可能な失敗内）"]];
styleTitle(failure, "A1:I1");
failure.getRange("A3:I3").values = [["大分類", "小分類", "4.1 件数", "4.1 割合", "5.4 件数", "5.4 割合", "5.5 件数", "5.5 割合", "定義"]];
styleHeader(failure, "A3:I3");
const failureDefs = [
  ["調査段階", "調査論点の設定漏れ", "調査対象の関係を論点として立てられなかった"],
  ["調査段階", "証跡探索の失敗", "論点は立てたが対応する証跡を取得できなかった"],
  ["まとめ段階", "調査結果の採用漏れ", "証跡を得たが最終行動列へ反映しなかった"],
  ["まとめ段階", "関係整理の誤り", "証跡から主体・行動・対象の関係を誤って構成した"],
];
const failureLabels = [
  "調査段階／調査論点の設定漏れ",
  "調査段階／証跡探索の失敗",
  "まとめ段階／調査結果の採用漏れ",
  "まとめ段階／関係整理の誤り",
];
const failureValues = failureDefs.map(([major, minor, definition], index) => {
  const label = failureLabels[index];
  return [
    major,
    minor,
    summary.failure_analysis["gpt-4.1-mini"].counts[label],
    null,
    summary.failure_analysis["gpt-5.4-mini"].counts[label],
    null,
    summary.failure_analysis["gpt-5.5"].counts[label],
    null,
    definition,
  ];
});
failure.getRange("A4:I7").values = failureValues;
for (let row = 4; row <= 7; row += 1) {
  failure.getRange(`D${row}`).formulas = [[`=C${row}/SUM($C$4:$C$7)`]];
  failure.getRange(`F${row}`).formulas = [[`=E${row}/SUM($E$4:$E$7)`]];
  failure.getRange(`H${row}`).formulas = [[`=G${row}/SUM($G$4:$G$7)`]];
  failure.getRange(`D${row}`).format.numberFormat = "0.00%";
  failure.getRange(`F${row}`).format.numberFormat = "0.00%";
  failure.getRange(`H${row}`).format.numberFormat = "0.00%";
}
styleBody(failure, "A4:I7");
failure.getRange("A9:I9").merge();
failure.getRange("A9").values = [[
  `追跡不能な失敗は割合の分母から除外：4.1=${summary.failure_analysis["gpt-4.1-mini"].untraceable_failure_steps}、5.4=${summary.failure_analysis["gpt-5.4-mini"].untraceable_failure_steps}、5.5=${summary.failure_analysis["gpt-5.5"].untraceable_failure_steps}。`,
]];
failure.getRange("A9:I9").format.fill = "#FFF7ED";
failure.getRange("A9:I9").format.font = { color: warn };
failure.getRange("A9:I9").format.wrapText = true;
failure.freezePanes.freezeRows(3);
failure.getRange("A:I").format.autofitColumns();
failure.getRange("I:I").format.columnWidth = 52;

const audit = wb.worksheets.add("全384試行監査");
audit.showGridLines = false;
audit.getRange("A1:P1").merge();
audit.getRange("A1").values = [["全384試行：Observable-semantic 採点監査台帳"]];
styleTitle(audit, "A1:P1");
audit.getRange("A3:P3").values = [[
  "モデル", "対象", "反復", "Stage", "ユースケース", "Gold step",
  "Action hit", "Action den", "Action", "Complete hit", "Complete",
  "Evidence hit", "Evidence", "Order hit", "Order den", "Order",
]];
styleHeader(audit, "A3:P3");
const auditRows = runRows.map((row) => {
  const stepCount = row.steps.length;
  const actionHit = row.steps.reduce((sum, step) => sum + step.observable.subject + step.observable.action + step.observable.object, 0);
  const completeHit = row.steps.reduce((sum, step) => sum + step.observable_complete, 0);
  const evidenceHit = row.steps.reduce((sum, step) => sum + step.observable.evidence, 0);
  const orderHit = row.order_pairs.reduce((sum, pair) => sum + pair.observable_score, 0);
  return [row.model, row.phase, row.replicate, row.stage, row.chain_id, stepCount, actionHit, stepCount * 3, null, completeHit, null, evidenceHit, null, orderHit, row.order_pairs.length, null];
});
audit.getRangeByIndexes(3, 0, auditRows.length, 16).values = auditRows;
for (let i = 0; i < auditRows.length; i += 1) {
  const row = 4 + i;
  setPercentFormula(audit, row, "G", "H", "I");
  setPercentFormula(audit, row, "J", "F", "K");
  setPercentFormula(audit, row, "L", "F", "M");
  setPercentFormula(audit, row, "N", "O", "P");
}
styleBody(audit, `A4:P${3 + auditRows.length}`);
audit.freezePanes.freezeRows(3);
audit.getRange("A:P").format.autofitColumns();
audit.getRange("E:E").format.columnWidth = 52;

await fs.mkdir(outputDir, { recursive: true });
await fs.mkdir(previewDir, { recursive: true });
const out = await SpreadsheetFile.exportXlsx(wb);
await out.save(outputPath);

const sheetNames = ["README", "全体46strata", "GPT55_Stage2", "GPT55_全Stage", "GPT55_Stage2_ケース", "失敗分析", "全384試行監査"];
for (const sheetName of sheetNames) {
  const preview = await wb.render({ sheetName, autoCrop: "all", scale: 1, format: "png" });
  const bytes = new Uint8Array(await preview.arrayBuffer());
  await fs.writeFile(path.join(previewDir, `${sheetName}.png`), bytes);
}

const inspection = await wb.inspect({
  kind: "sheet,formula",
  maxChars: 12000,
  tableMaxRows: 8,
  tableMaxCols: 20,
  options: { maxResults: 200 },
});
await fs.writeFile(path.join(outputDir, "workbook_inspection.txt"), inspection.ndjson ?? String(inspection), "utf8");

console.log(JSON.stringify({ outputPath, previewDir, sheetNames }, null, 2));
