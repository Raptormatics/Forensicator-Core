/**
 * CSV export — one row per evidence record.
 */
import type { Prisma } from "@prisma/client";

type EvidenceForCsv = {
  id: string;
  type: string;
  source: string | null;
  timestamp: Date | null;
  hostname: string | null;
  username: string | null;
  ip: string | null;
  domain: string | null;
  url: string | null;
  hash: string | null;
  processName: string | null;
  commandLine: string | null;
  searchableText: string | null;
  finding: {
    findingId: string;
    findingType: string;
    category: string;
    severity: string;
  };
};

const HEADERS = [
  "id", "type", "finding_id", "finding_type", "category", "severity",
  "timestamp", "hostname", "username", "source",
  "ip", "domain", "url", "hash", "process_name", "command_line", "summary",
];

function esc(v: string | null | undefined): string {
  if (v == null) return "";
  const s = String(v).replace(/"/g, '""');
  return s.includes(",") || s.includes("\n") || s.includes('"') ? `"${s}"` : s;
}

export function generateEvidenceCsv(rows: EvidenceForCsv[]): string {
  const lines = [HEADERS.join(",")];
  for (const r of rows) {
    lines.push(
      [
        r.id,
        r.type,
        r.finding.findingId,
        r.finding.findingType,
        r.finding.category,
        r.finding.severity,
        r.timestamp?.toISOString() ?? "",
        r.hostname,
        r.username,
        r.source,
        r.ip,
        r.domain,
        r.url,
        r.hash,
        r.processName,
        r.commandLine,
        r.searchableText,
      ]
        .map(esc)
        .join(",")
    );
  }
  return lines.join("\r\n");
}
