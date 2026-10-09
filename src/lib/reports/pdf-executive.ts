/**
 * Executive PDF report — high-level summary for management, generated per Case.
 * Uses pdfmake (Node.js) for reliable server-side generation.
 */
import path from "path";
// pdfmake's root export is a singleton with its own setFonts/createPdf API —
// NOT a PdfPrinter constructor (that was the bug: `new require("pdfmake")()`
// threw "is not a constructor" since the export is a plain instance).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const pdfMake = require("pdfmake");
import type { TDocumentDefinitions, Content } from "pdfmake/interfaces";
import { normalizeSeverity, HIGH_SEVERITY_LABELS, type SeverityLabel } from "@/lib/severity";
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

// ── Colour palette ────────────────────────────────────────────────────────────
const C = {
  bg:       "#0f1117",
  accent:   "#14b8a6",  // teal-500
  text:     "#e4e4e7",  // zinc-200
  subtext:  "#71717a",  // zinc-500
  border:   "#27272a",  // zinc-800
  Important:     "#ef4444",
  Notable:       "#f97316",
  Interesting:   "#eab308",
  Informational: "#22c55e",
  white:         "#ffffff",
  black:         "#000000",
};

function severityColor(sev: string): string {
  return C[normalizeSeverity(sev)];
}

const SOURCE_LABEL: Record<CaseReportFinding["source"], string> = {
  investigation: "Investigation",
  log:           "Log Analysis",
  pcap:          "PCAP Analysis",
  ram:           "RAM Analysis",
};

export type ExecutiveReportInput = {
  case: CaseReportCase;
  hosts: string[];
  investigationCount: number;
  findings: CaseReportFinding[];
  moduleCounts: ModuleCounts;
  evidenceCount: number;
  iocCount: number;
};

export async function generateExecutivePdf(input: ExecutiveReportInput): Promise<Buffer> {
  const { case: kase, hosts, investigationCount, findings, moduleCounts, evidenceCount, iocCount } = input;

  const tierCounts: Record<SeverityLabel, number> = { Important: 0, Notable: 0, Interesting: 0, Informational: 0 };
  for (const f of findings) {
    tierCounts[normalizeSeverity(f.severity)]++;
  }

  const hostsLabel = hosts.length === 0 ? "No hosts" : hosts.length <= 3 ? hosts.join(", ") : `${hosts.slice(0, 3).join(", ")} +${hosts.length - 3} more`;

  const docDef: TDocumentDefinitions = {
    pageSize: "A4",
    pageMargins: [40, 60, 40, 60],
    background: () => ({ canvas: [{ type: "rect", x: 0, y: 0, w: 595.28, h: 841.89, color: C.bg }] }),
    defaultStyle: { font: "Roboto", color: C.text, fontSize: 10 },

    content: [
      // Header
      {
        columns: [
          { text: "FORENSICATOR", style: "brand", width: "*" },
          { text: "EXECUTIVE REPORT", style: "reportType", alignment: "right", width: "auto" },
        ],
        marginBottom: 4,
      },
      { canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: C.accent }], marginBottom: 20 },

      // Case title
      { text: `${formatCaseNumber(kase.caseSeq)} — ${kase.title}`, style: "h1", marginBottom: 4 },
      {
        columns: [
          { text: `Hosts: ${hostsLabel}`, color: C.subtext, fontSize: 9 },
          { text: `Generated: ${new Date().toUTCString()}`, color: C.subtext, fontSize: 9, alignment: "right" },
        ],
        marginBottom: 24,
      },

      // Executive summary
      { text: "EXECUTIVE SUMMARY", style: "h2", marginBottom: 8 },
      {
        text: buildExecutiveSummary(kase, hosts, investigationCount, moduleCounts, findings, evidenceCount, iocCount),
        marginBottom: 20,
        lineHeight: 1.5,
      },

      // Stat tiles
      { text: "KEY METRICS", style: "h2", marginBottom: 8 },
      buildMetricRow(tierCounts, evidenceCount, iocCount, findings.length),

      // Module breakdown
      { text: "FINDINGS BY MODULE", style: "h2", marginBottom: 8, marginTop: 20 },
      buildModuleRow(moduleCounts),

      // Top findings
      { text: "NOTABLE FINDINGS", style: "h2", marginBottom: 8, marginTop: 20 },
      buildFindingsTable(findings.slice(0, 20)),

      // Tags / hypotheses
      ...(kase.tags.length > 0
        ? [
            { text: "TAGS", style: "h2", marginBottom: 8, marginTop: 20 },
            { text: kase.tags.join("  ·  "), color: C.accent, fontSize: 9 },
          ]
        : []),

      // Footer divider
      { canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 0.5, lineColor: C.border }], marginTop: 30 },
      { text: "CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY", alignment: "center", color: C.subtext, fontSize: 8, marginTop: 6 },
    ],

    styles: {
      brand:      { fontSize: 18, bold: true, color: C.accent },
      reportType: { fontSize: 10, color: C.subtext, marginTop: 6 },
      h1:         { fontSize: 20, bold: true, color: C.white },
      h2:         { fontSize: 11, bold: true, color: C.accent },
      tableHeader:{ bold: true, color: C.accent, fontSize: 9, fillColor: "#18181b" },
      cell:       { fontSize: 9, color: C.text },
      cellSub:    { fontSize: 8, color: C.subtext },
    },
  };

  const pdfDoc = pdfMake.createPdf(docDef);
  return pdfDoc.getBuffer();
}

function formatCaseNumber(seq: number): string {
  return `CASE-${String(seq).padStart(4, "0")}`;
}

function buildExecutiveSummary(
  kase: CaseReportCase,
  hosts: string[],
  investigationCount: number,
  moduleCounts: ModuleCounts,
  findings: CaseReportFinding[],
  evidenceCount: number,
  iocCount: number,
): string {
  const critHigh = findings.filter((f) => HIGH_SEVERITY_LABELS.includes(normalizeSeverity(f.severity))).length;
  const moduleParts = [
    moduleCounts.investigations > 0 ? `${moduleCounts.investigations} from investigation analysis` : null,
    moduleCounts.log > 0  ? `${moduleCounts.log} from log analysis`  : null,
    moduleCounts.pcap > 0 ? `${moduleCounts.pcap} from PCAP analysis` : null,
    moduleCounts.ram > 0  ? `${moduleCounts.ram} from RAM analysis`  : null,
  ].filter(Boolean).join(", ");

  return (
    `Case ${formatCaseNumber(kase.caseSeq)} — "${kase.title}" — spans ${investigationCount} investigation${investigationCount !== 1 ? "s" : ""} ` +
    `across ${hosts.length} host${hosts.length !== 1 ? "s" : ""}, opened ${kase.createdAt.toDateString()}. ` +
    `This case surfaced ${findings.length} total finding${findings.length !== 1 ? "s" : ""} (${moduleParts || "none"}), ${critHigh} of which are rated Important or Notable. ` +
    `${evidenceCount.toLocaleString()} evidence records were extracted and ${iocCount} indicators of compromise were identified. ` +
    `Immediate remediation action is recommended for all Important and Notable findings.`
  );
}

function buildMetricRow(
  tierCounts: Record<SeverityLabel, number>,
  evidenceCount: number,
  iocCount: number,
  total: number,
): Content {
  const cells = [
    { label: "Findings",  value: String(total),                   color: C.accent },
    { label: "Important", value: String(tierCounts.Important),    color: C.Important },
    { label: "Notable",   value: String(tierCounts.Notable),      color: C.Notable },
    { label: "Evidence",  value: evidenceCount.toLocaleString(), color: C.text },
    { label: "IOCs",      value: iocCount.toLocaleString(),      color: C.text },
  ];

  return {
    columns: cells.map((c) => ({
      stack: [
        { text: c.value, fontSize: 22, bold: true, color: c.color, alignment: "center" },
        { text: c.label, fontSize: 8, color: C.subtext, alignment: "center" },
      ],
      width: "*",
      margin: [0, 0, 0, 0],
    })),
    marginBottom: 4,
  };
}

function buildModuleRow(moduleCounts: ModuleCounts): Content {
  const cells = [
    { label: "Investigations", value: moduleCounts.investigations },
    { label: "Log Analysis",   value: moduleCounts.log },
    { label: "PCAP Analysis",  value: moduleCounts.pcap },
    { label: "RAM Analysis",   value: moduleCounts.ram },
  ];
  return {
    columns: cells.map((c) => ({
      stack: [
        { text: String(c.value), fontSize: 16, bold: true, color: C.accent, alignment: "center" },
        { text: c.label, fontSize: 8, color: C.subtext, alignment: "center" },
      ],
      width: "*",
    })),
    marginBottom: 4,
  };
}

function buildFindingsTable(
  findings: CaseReportFinding[],
): Content {
  return {
    table: {
      headerRows: 1,
      widths: ["auto", "auto", "auto", "*"],
      body: [
        [
          { text: "SOURCE",   style: "tableHeader" },
          { text: "CATEGORY", style: "tableHeader" },
          { text: "SEVERITY", style: "tableHeader" },
          { text: "SUMMARY",  style: "tableHeader" },
        ],
        ...findings.map((f) => [
          { text: SOURCE_LABEL[f.source], style: "cell" },
          { text: f.category,    style: "cell" },
          { text: f.severity,    style: "cell", color: severityColor(f.severity) },
          { text: f.summary ?? f.title, style: "cellSub" },
        ]),
      ],
    },
    layout: {
      hLineWidth: () => 0.5,
      vLineWidth: () => 0,
      hLineColor: () => C.border,
      fillColor: (i: number) => i === 0 ? "#18181b" : i % 2 === 0 ? "#18181b" : "transparent",
    },
  };
}
