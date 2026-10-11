/**
 * Built-in v1 detections — plain functions over pslist/malfind results, not
 * user-editable rules (RamAnalysisRule is a separate, later layer on top of
 * the same data). Each returns zero or more RamFinding-shaped rows with
 * ruleId left for the caller to set to null.
 */
import type { RamProcessRow, RamMalfindHit, RamOsType } from "./types";

export interface HeuristicFinding {
  title: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  matchCount: number;
  matchedField: string | null;
  matchedValue: string | null;
  // Structured process linkage (see RamFinding.pid's schema comment) — null
  // for findings with no single process to point at.
  pid: number | null;
  processName: string | null;
}

/** A malfind-derived finding, grouped by process — carries every injected
 * VAD region behind it (see RamMalfindRegion) rather than being one region
 * per finding row. */
export interface MalfindGroupFinding extends HeuristicFinding {
  regions: RamMalfindHit[];
}

/** Detection 1 — malfind hits grouped by process: a process with N injected
 * VAD regions produces ONE finding (matchCount: N) carrying all N regions,
 * not N visually-identical findings. Hits Volatility3 couldn't attribute to
 * a PID each become their own singleton finding rather than being merged
 * together under a false shared identity. */
function detectMalfindHits(hits: RamMalfindHit[]): MalfindGroupFinding[] {
  const byPid = new Map<number, RamMalfindHit[]>();
  const unattributed: RamMalfindHit[] = [];
  for (const hit of hits) {
    if (hit.pid === null) { unattributed.push(hit); continue; }
    const arr = byPid.get(hit.pid) ?? [];
    arr.push(hit);
    byPid.set(hit.pid, arr);
  }

  function describe(regions: RamMalfindHit[]): string {
    const distinctTags = [...new Set(regions.map((r) => r.tag).filter(Boolean))];
    const distinctProtections = [...new Set(regions.map((r) => r.protection).filter(Boolean))];
    return [
      `${regions.length} injected memory region${regions.length !== 1 ? "s" : ""} detected.`,
      distinctTags.length > 0 ? `Region tag(s): ${distinctTags.join(", ")}.` : null,
      distinctProtections.length > 0 ? `Protection(s): ${distinctProtections.join(", ")}.` : null,
      "Volatility3's malfind plugin flags memory regions with characteristics commonly seen in process-injection/hollowing techniques — verify manually before treating as confirmed malicious.",
    ].filter(Boolean).join(" ");
  }

  const findings: MalfindGroupFinding[] = [];
  for (const [pid, regions] of byPid.entries()) {
    const processName = regions.find((r) => r.process)?.process ?? "(unknown)";
    findings.push({
      title: `Possible injected/hidden code in process ${processName} (PID ${pid})`,
      description: describe(regions),
      severity: "high",
      matchCount: regions.length,
      matchedField: "pid",
      matchedValue: String(pid),
      pid,
      processName,
      regions,
    });
  }
  for (const hit of unattributed) {
    findings.push({
      title: `Possible injected/hidden code in process ${hit.process ?? "(unknown)"} (PID unknown)`,
      description: describe([hit]),
      severity: "high",
      matchCount: 1,
      matchedField: null,
      matchedValue: null,
      pid: null,
      processName: hit.process,
      regions: [hit],
    });
  }
  return findings;
}

// Small, deliberately conservative v1 watch-list of well-known Windows
// process names and the parent process that legitimately spawns them.
// Anything more elaborate belongs in RamAnalysisRule.
const EXPECTED_PARENT: Record<string, string> = {
  "svchost.exe": "services.exe",
  "lsass.exe":   "wininit.exe",
  "services.exe": "wininit.exe",
  "csrss.exe":   "smss.exe",
  "winlogon.exe": "smss.exe",
};

/** Detection 2 — a watched process name whose actual parent name doesn't
 * match its expected legitimate parent (classic masquerading signal). */
function detectProcessMasquerading(processes: RamProcessRow[]): HeuristicFinding[] {
  const byPid = new Map<number, RamProcessRow>();
  for (const p of processes) byPid.set(p.pid, p);

  const findings: HeuristicFinding[] = [];
  for (const proc of processes) {
    const expectedParent = EXPECTED_PARENT[proc.name.toLowerCase()];
    if (!expectedParent) continue;
    if (proc.ppid === null) continue;
    const parent = byPid.get(proc.ppid);
    const actualParentName = parent?.name.toLowerCase() ?? null;
    if (actualParentName === expectedParent.toLowerCase()) continue;

    findings.push({
      title: `${proc.name} (PID ${proc.pid}) running under an unexpected parent process`,
      description: `Expected parent ${expectedParent}, actual parent ${parent ? `${parent.name} (PID ${proc.ppid})` : `PID ${proc.ppid} (not found in this snapshot)`} — a common process-masquerading signal.`,
      severity: "high",
      matchCount: 1,
      matchedField: "pid",
      matchedValue: String(proc.pid),
      pid: proc.pid,
      processName: proc.name,
    });
  }
  return findings;
}

/** Detection 3 — a process whose ppid doesn't correspond to any pid present
 * in the same pslist snapshot (excluding System/pid 4 and the first
 * process in the list, which legitimately has no parent in-snapshot).
 * Classic process-injection/PPID-spoofing tradecraft signal — or simply a
 * parent that already exited, which is why this stays "medium" not "high". */
function detectOrphanedParent(processes: RamProcessRow[]): HeuristicFinding[] {
  const pids = new Set(processes.map((p) => p.pid));
  const findings: HeuristicFinding[] = [];

  for (const [index, proc] of processes.entries()) {
    if (index === 0) continue; // typically the System/Idle process, no real parent
    if (proc.pid === 4) continue; // System process
    if (proc.ppid === null || proc.ppid === 0) continue;
    if (pids.has(proc.ppid)) continue;

    findings.push({
      title: `${proc.name} (PID ${proc.pid}) has no matching parent process in this snapshot`,
      description: `Reported PPID ${proc.ppid} does not correspond to any process present at capture time — either the parent already exited, or this is a PPID-spoofing indicator worth investigating.`,
      severity: "medium",
      matchCount: 1,
      matchedField: "ppid",
      matchedValue: String(proc.ppid),
      pid: proc.pid,
      processName: proc.name,
    });
  }
  return findings;
}

/**
 * The masquerading heuristic's EXPECTED_PARENT map is Windows-process-name
 * specific (svchost.exe/services.exe/etc.) — deliberately skipped for
 * linux/macos rather than inventing unvalidated process-tree assumptions
 * for those OSes. Malfind and orphaned-parent are OS-agnostic (operate on
 * the shared RamProcessRow/RamMalfindHit shapes) and apply to all three.
 */
export function runHeuristics(
  processes: RamProcessRow[],
  malfindHits: RamMalfindHit[],
  osType: RamOsType
): { malfindFindings: MalfindGroupFinding[]; otherFindings: HeuristicFinding[] } {
  return {
    malfindFindings: detectMalfindHits(malfindHits),
    otherFindings: [
      ...(osType === "windows" ? detectProcessMasquerading(processes) : []),
      ...detectOrphanedParent(processes),
    ],
  };
}
