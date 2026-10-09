/** Shared types for case-wide report generation — see src/lib/jobs/report-worker.ts. */

export type ReportFindingSource = "investigation" | "log" | "pcap" | "ram";

/** Normalized finding shape spanning Finding/LogFinding/PcapFinding/RamFinding. */
export type CaseReportFinding = {
  id: string;
  source: ReportFindingSource;
  title: string;
  category: string;
  severity: string;
  summary: string | null;
};

export type CaseReportCase = {
  id: string;
  caseSeq: number;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  tags: string[];
  createdAt: Date;
};

export type ModuleCounts = {
  investigations: number;
  log: number;
  pcap: number;
  ram: number;
};
