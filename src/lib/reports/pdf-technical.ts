/**
 * Technical PDF report — full detailed DFIR report for a Case: findings,
 * evidence-derived IOCs, and timeline aggregated across every investigation
 * and Log/PCAP/RAM analysis upload tied to the case.
 */
import path from "path";
// pdfmake's root export is a singleton with its own setFonts/createPdf API —
// NOT a PdfPrinter constructor (that was the bug: `new require("pdfmake")()`
// threw "is not a constructor" since the export is a plain instance).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const pdfMake = require("pdfmake");
import type { TDocumentDefinitions, Content } from "pdfmake/interfaces";
import { normalizeSeverity } from "@/lib/severity";
import type { CaseReportCase, CaseReportFinding, ModuleCounts } from "./types";

// Resolved from process.cwd() rather than require.resolve("pdfmake/package.json")
// — this module also loads inside the Next.js server bundle (via
// instrumentation.ts, which starts a report worker embedded in the web app
// process alongside the dedicated forensicator-workers.service). Under
// webpack, require.resolve() on a bundled module gets statically rewritten
// to a bundle-internal path instead of a real filesystem path, which broke
// font loading only in that embedded context ("ENOENT ... (instrument)/...").
// process.cwd() is the project root in every execution context here: plain
// `tsx worker.ts` and `next start`/`next dev` both run with cwd = APP_DIR.
// These are the real Roboto .ttf files pdfmake ships — the previous code
// pointed at vfs_fonts.js (a base64 JSON blob for the browser build), which
// isn't a font file at all.
const pdfmakeDir = path.join(process.cwd(), "node_modules/pdfmake");
pdfMake.setFonts({
  Roboto: {
    normal:      path.join(pdfmakeDir, "build/fonts/Roboto/Roboto-Regular.ttf"),
    bold:        path.join(pdfmakeDir, "build/fonts/Roboto/Roboto-Medium.ttf"),
    italics:     path.join(pdfmakeDir, "build/fonts/Roboto/Roboto-Italic.ttf"),
    bolditalics: path.join(pdfmakeDir, "build/fonts/Roboto/Roboto-MediumItalic.ttf"),
  },
});
// No remote fonts/images are ever referenced in these reports — allow local
// font file access, deny remote URLs outright (also silences pdfmake's
// startup warnings about unset access policies).
pdfMake.setLocalAccessPolicy(() => true);
pdfMake.setUrlAccessPolicy(() => false);

const C = {
  bg:       "#0f1117",
  accent:   "#14b8a6",
  text:     "#e4e4e7",
  subtext:  "#71717a",
  border:   "#27272a",
  Important:     "#ef4444",
  Notable:       "#f97316",
  Interesting:   "#eab308",
  Informational: "#22c55e",
  white:         "#ffffff",
};

function sev(s: string) {
  return C[normalizeSeverity(s)];
}

function formatCaseNumber(seq: number): string {
  return `CASE-${String(seq).padStart(4, "0")}`;
}

const SOURCE_LABEL: Record<CaseReportFinding["source"], string> = {
  investigation: "Investigation",
  log:           "Log Analysis",
  pcap:          "PCAP Analysis",
  ram:           "RAM Analysis",
};

export type TechnicalReportInput = {
  case: CaseReportCase;
  hosts: string[];
  investigationCount: number;
  moduleCounts: ModuleCounts;
  findings: CaseReportFinding[];
  iocs: { type: string; value: string }[];
  timelineEvents: { timestamp: Date; title: string; category: string; severity: string }[];
};

export async function generateTechnicalPdf(input: TechnicalReportInput): Promise<Buffer> {
  const { case: kase, hosts, investigationCount, moduleCounts, findings, iocs, timelineEvents } = input;

  const content: Content[] = [
    // Cover
    {
      columns: [
        { text: "FORENSICATOR", style: "brand", width: "*" },
        { text: "TECHNICAL REPORT", style: "reportType", alignment: "right", width: "auto" },
      ],
      marginBottom: 4,
    },
    { canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: C.accent }], marginBottom: 20 },
    { text: `${formatCaseNumber(kase.caseSeq)} — ${kase.title}`, style: "h1", marginBottom: 4 },
    {
      columns: [
        { text: `Hosts: ${hosts.join(", ") || "—"}`, color: C.subtext, fontSize: 9 },
        { text: new Date().toUTCString(), color: C.subtext, fontSize: 9, alignment: "right" },
      ],
      marginBottom: 24,
    },

    // Case metadata table
    { text: "CASE METADATA", style: "h2", marginBottom: 8 },
    {
      table: {
        widths: ["auto", "*"],
        body: [
          [{ text: "Case ID",           style: "tableHeader" }, { text: kase.id, style: "cell" }],
          [{ text: "Case Number",       style: "tableHeader" }, { text: formatCaseNumber(kase.caseSeq), style: "cell" }],
          [{ text: "Status",            style: "tableHeader" }, { text: kase.status, style: "cell" }],
          [{ text: "Severity",          style: "tableHeader" }, { text: kase.severity, style: "cell" }],
          [{ text: "Investigations",    style: "tableHeader" }, { text: String(investigationCount), style: "cell" }],
          [{ text: "Hosts",             style: "tableHeader" }, { text: hosts.join(", ") || "—", style: "cell" }],
          [{ text: "Opened",            style: "tableHeader" }, { text: kase.createdAt.toUTCString(), style: "cell" }],
          [{ text: "Tags",              style: "tableHeader" }, { text: kase.tags.join(", ") || "—", style: "cell" }],
        ],
      },
      layout: { hLineWidth: () => 0.5, vLineWidth: () => 0, hLineColor: () => C.border, fillColor: (i: number) => i % 2 === 0 ? "#18181b" : "transparent" },
      marginBottom: 20,
    },

    // Module breakdown
    { text: "MODULE BREAKDOWN", style: "h2", marginBottom: 8 },
    {
      table: {
        headerRows: 1,
        widths: ["*", "auto"],
        body: [
          [{ text: "MODULE", style: "tableHeader" }, { text: "FINDINGS", style: "tableHeader" }],
          [{ text: "Investigation Analysis", style: "cell" }, { text: String(moduleCounts.investigations), style: "cell" }],
          [{ text: "Log Analysis",           style: "cell" }, { text: String(moduleCounts.log), style: "cell" }],
          [{ text: "PCAP Analysis",          style: "cell" }, { text: String(moduleCounts.pcap), style: "cell" }],
          [{ text: "RAM Analysis",           style: "cell" }, { text: String(moduleCounts.ram), style: "cell" }],
        ],
      },
      layout: { hLineWidth: () => 0.5, vLineWidth: () => 0, hLineColor: () => C.border, fillColor: (i: number) => i === 0 ? "#18181b" : "transparent" },
      marginBottom: 20,
    },

    // Findings
    { text: "FINDINGS", style: "h2", marginBottom: 8, pageBreak: "before" },
    {
      table: {
        headerRows: 1,
        widths: ["auto", "auto", "auto", "auto", "*"],
        body: [
          [
            { text: "SOURCE",   style: "tableHeader" },
            { text: "TITLE",    style: "tableHeader" },
            { text: "CATEGORY", style: "tableHeader" },
            { text: "SEVERITY", style: "tableHeader" },
            { text: "SUMMARY",  style: "tableHeader" },
          ],
          ...findings.map((f) => [
            { text: SOURCE_LABEL[f.source],          style: "cellSub" },
            { text: f.title,                         style: "cell" },
            { text: f.category,                      style: "cell" },
            { text: f.severity, color: sev(f.severity), style: "cell" },
            { text: f.summary ?? "—",                 style: "cellSub" },
          ]),
        ],
      },
      layout: { hLineWidth: () => 0.5, vLineWidth: () => 0, hLineColor: () => C.border, fillColor: (i: number) => i === 0 ? "#18181b" : i % 2 === 0 ? "#18181b" : "transparent" },
      marginBottom: 20,
    },

    // IOC List (investigation evidence-derived)
    ...(iocs.length > 0
      ? [
          { text: "INDICATORS OF COMPROMISE", style: "h2", marginBottom: 8, pageBreak: "before" } as Content,
          {
            table: {
              headerRows: 1,
              widths: ["auto", "*"],
              body: [
                [{ text: "TYPE", style: "tableHeader" }, { text: "VALUE", style: "tableHeader" }],
                ...iocs.map((i) => [{ text: i.type, style: "cell" }, { text: i.value, style: "cellSub" }]),
              ],
            },
            layout: { hLineWidth: () => 0.5, vLineWidth: () => 0, hLineColor: () => C.border, fillColor: (i: number) => i % 2 === 0 ? "#18181b" : "transparent" },
            marginBottom: 20,
          } as Content,
        ]
      : []),

    // Timeline (first 100)
    ...(timelineEvents.length > 0
      ? [
          { text: "TIMELINE", style: "h2", marginBottom: 8, pageBreak: "before" } as Content,
          {
            table: {
              headerRows: 1,
              widths: ["auto", "auto", "*", "auto"],
              body: [
                [
                  { text: "TIMESTAMP", style: "tableHeader" },
                  { text: "CATEGORY",  style: "tableHeader" },
                  { text: "EVENT",     style: "tableHeader" },
                  { text: "SEVERITY",  style: "tableHeader" },
                ],
                ...timelineEvents.slice(0, 100).map((e) => [
                  { text: e.timestamp.toISOString(), style: "cellSub" },
                  { text: e.category, style: "cell" },
                  { text: e.title, style: "cell" },
                  { text: e.severity, color: sev(e.severity), style: "cell" },
                ]),
              ],
            },
            layout: { hLineWidth: () => 0.5, vLineWidth: () => 0, hLineColor: () => C.border, fillColor: (i: number) => i % 2 === 0 ? "#18181b" : "transparent" },
          } as Content,
        ]
      : []),

    // Footer
    { canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 0.5, lineColor: C.border }], marginTop: 30 },
    { text: "CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY", alignment: "center", color: C.subtext, fontSize: 8, marginTop: 6 },
  ];

  const docDef: TDocumentDefinitions = {
    pageSize: "A4",
    pageMargins: [40, 60, 40, 60],
    background: () => ({ canvas: [{ type: "rect", x: 0, y: 0, w: 595.28, h: 841.89, color: C.bg }] }),
    defaultStyle: { font: "Roboto", color: C.text, fontSize: 10 },
    content,
    styles: {
      brand:       { fontSize: 18, bold: true, color: C.accent },
      reportType:  { fontSize: 10, color: C.subtext, marginTop: 6 },
      h1:          { fontSize: 20, bold: true, color: C.white },
      h2:          { fontSize: 11, bold: true, color: C.accent },
      tableHeader: { bold: true, color: C.accent, fontSize: 9, fillColor: "#18181b" },
      cell:        { fontSize: 9, color: C.text },
      cellSub:     { fontSize: 8, color: C.subtext },
    },
  };

  const pdfDoc = pdfMake.createPdf(docDef);
  return pdfDoc.getBuffer();
}
