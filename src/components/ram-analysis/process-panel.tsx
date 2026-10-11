"use client";

import { useMemo, useState, useRef, useEffect } from "react";
import { ChevronDown, ChevronRight, ListTree, Table2, AlertTriangle } from "lucide-react";
import type { Finding } from "./finding-card";

export type ProcessRow = {
  id: string; pid: number; ppid: number | null; name: string;
  path: string | null; commandLine: string | null;
  createTime: string | null; exitTime: string | null;
  sessionId: number | null; threads: number | null; handles: number | null;
};

// Well-known Windows system binaries and the path substring (lowercased)
// they're expected to run from. RamProcess.path is a best-effort guess
// parsed from the command line's first token, not an authoritative
// Volatility field, so this is a heuristic hint, not a definitive verdict.
const EXPECTED_PATH: Record<string, string> = {
  "svchost.exe": "system32",
  "lsass.exe": "system32",
  "csrss.exe": "system32",
  "winlogon.exe": "system32",
  "services.exe": "system32",
  "smss.exe": "system32",
  "wininit.exe": "system32",
  "explorer.exe": "windows",
};

export interface ProcessTreeNode extends ProcessRow {
  children: ProcessTreeNode[];
}

export function buildProcessTree(processes: ProcessRow[]): ProcessTreeNode[] {
  const pidSet = new Set(processes.map((p) => p.pid));
  const childrenByPpid = new Map<number, ProcessRow[]>();
  for (const p of processes) {
    if (p.ppid === null) continue;
    const arr = childrenByPpid.get(p.ppid) ?? [];
    arr.push(p);
    childrenByPpid.set(p.ppid, arr);
  }
  const build = (p: ProcessRow): ProcessTreeNode => ({
    ...p,
    children: (childrenByPpid.get(p.pid) ?? []).sort((a, b) => a.pid - b.pid).map(build),
  });
  return processes
    .filter((p) => p.ppid === null || !pidSet.has(p.ppid))
    .sort((a, b) => a.pid - b.pid)
    .map(build);
}

function isMasquerading(p: ProcessRow): boolean {
  if (!p.path) return false;
  const expected = EXPECTED_PATH[p.name.toLowerCase()];
  return expected !== undefined && !p.path.toLowerCase().includes(expected);
}

type FindingBadge = { findingId: string; label: string; tone: "red" | "amber" };

function findingBadges(pid: number, findingsByPid: Map<number, Finding[]>): FindingBadge[] {
  const findings = findingsByPid.get(pid) ?? [];
  return findings.map((f) => {
    const isMalfind = f.malfindRegions.length > 0;
    const tone: "red" | "amber" = isMalfind || f.severity === "critical" || f.severity === "high" ? "red" : "amber";
    const label = isMalfind ? "Injected Code" : (f.rule?.name ?? f.title);
    return { findingId: f.id, label, tone };
  });
}

const BADGE_TONE: Record<"red" | "amber", string> = {
  red:   "bg-red-900/40 text-red-400 border-red-900 hover:bg-red-900/60",
  amber: "bg-amber-900/40 text-amber-400 border-amber-900 hover:bg-amber-900/60",
};

function ProcessBadges({ pid, findingsByPid, onJumpToFinding }: { pid: number; findingsByPid: Map<number, Finding[]>; onJumpToFinding?: (findingId: string) => void }) {
  const badges = findingBadges(pid, findingsByPid);
  if (badges.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1 ml-2">
      {badges.map((b) => (
        <button
          key={b.findingId}
          onClick={(e) => { e.stopPropagation(); onJumpToFinding?.(b.findingId); }}
          className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${BADGE_TONE[b.tone]}`}
          title="Jump to this finding"
        >
          {b.label}
        </button>
      ))}
    </span>
  );
}

function ProcessMeta({
  p, highlightPid, highlightedRowRef, findingsByPid, onJumpToFinding, orphan,
}: {
  p: ProcessRow; highlightPid: number | null; highlightedRowRef: React.RefObject<HTMLDivElement>;
  findingsByPid: Map<number, Finding[]>; onJumpToFinding?: (findingId: string) => void; orphan: boolean;
}) {
  const masquerading = isMasquerading(p);
  return (
    <div
      ref={p.pid === highlightPid ? highlightedRowRef : undefined}
      className={`flex flex-wrap items-center gap-x-2 gap-y-1 py-1 px-2 rounded ${p.pid === highlightPid ? "bg-teal-900/30 ring-1 ring-inset ring-teal-700" : ""}`}
    >
      <span className="font-mono text-zinc-500 text-xs">{p.pid}</span>
      <span className="text-teal-400 font-medium text-xs">{p.name}</span>
      {orphan && (
        <span className="inline-flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400" title={`PPID ${p.ppid} not present in this memory image`}>
          <AlertTriangle className="h-2.5 w-2.5" /> Orphan
        </span>
      )}
      {masquerading && (
        <span className="inline-flex items-center gap-1 rounded border border-orange-900 bg-orange-900/40 px-1.5 py-0.5 text-[10px] text-orange-400" title={`Unexpected path for ${p.name}: ${p.path} (heuristic — path is best-effort parsed, not authoritative)`}>
          <AlertTriangle className="h-2.5 w-2.5" /> Unexpected path
        </span>
      )}
      <ProcessBadges pid={p.pid} findingsByPid={findingsByPid} onJumpToFinding={onJumpToFinding} />
      {p.commandLine && <span className="text-zinc-600 text-xs truncate max-w-[420px]" title={p.commandLine}>{p.commandLine}</span>}
    </div>
  );
}

function TreeNode({
  process, childrenByPpid, depth, highlightPid, highlightedRowRef, findingsByPid, onJumpToFinding, pidSet,
}: {
  process: ProcessRow; childrenByPpid: Map<number, ProcessRow[]>; depth: number;
  highlightPid: number | null; highlightedRowRef: React.RefObject<HTMLDivElement>;
  findingsByPid: Map<number, Finding[]>; onJumpToFinding?: (findingId: string) => void; pidSet: Set<number>;
}) {
  const children = childrenByPpid.get(process.pid) ?? [];
  const [expanded, setExpanded] = useState(true);
  const orphan = process.ppid !== null && process.ppid !== 0 && !pidSet.has(process.ppid);

  return (
    <div>
      <div className="flex items-center" style={{ paddingLeft: depth * 20 }}>
        {children.length > 0 ? (
          <button onClick={() => setExpanded((v) => !v)} className="text-zinc-500 hover:text-zinc-300 shrink-0">
            {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        ) : (
          <span className="w-3.5 shrink-0" />
        )}
        <ProcessMeta p={process} highlightPid={highlightPid} highlightedRowRef={highlightedRowRef} findingsByPid={findingsByPid} onJumpToFinding={onJumpToFinding} orphan={orphan} />
      </div>
      {expanded && children.map((c) => (
        <TreeNode key={c.id} process={c} childrenByPpid={childrenByPpid} depth={depth + 1} highlightPid={highlightPid} highlightedRowRef={highlightedRowRef} findingsByPid={findingsByPid} onJumpToFinding={onJumpToFinding} pidSet={pidSet} />
      ))}
    </div>
  );
}

export function ProcessesPanel({
  processes, findings, highlightPid, onJumpToFinding,
}: {
  processes: ProcessRow[]; findings: Finding[]; highlightPid: number | null; onJumpToFinding?: (findingId: string) => void;
}) {
  const [view, setView] = useState<"tree" | "flat">("tree");
  const highlightedTreeRowRef = useRef<HTMLDivElement>(null);
  const highlightedFlatRowRef = useRef<HTMLTableRowElement>(null);

  const pidSet = useMemo(() => new Set(processes.map((p) => p.pid)), [processes]);
  const childrenByPpid = useMemo(() => {
    const map = new Map<number, ProcessRow[]>();
    for (const p of processes) {
      if (p.ppid === null) continue;
      const arr = map.get(p.ppid) ?? [];
      arr.push(p);
      map.set(p.ppid, arr);
    }
    return map;
  }, [processes]);
  const roots = useMemo(
    () => processes.filter((p) => p.ppid === null || !pidSet.has(p.ppid)).sort((a, b) => a.pid - b.pid),
    [processes, pidSet]
  );
  const findingsByPid = useMemo(() => {
    const map = new Map<number, Finding[]>();
    for (const f of findings) {
      if (f.pid === null) continue;
      const arr = map.get(f.pid) ?? [];
      arr.push(f);
      map.set(f.pid, arr);
    }
    return map;
  }, [findings]);

  useEffect(() => {
    if (highlightPid === null) return;
    const ref = view === "tree" ? highlightedTreeRowRef : highlightedFlatRowRef;
    ref.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [highlightPid, view]);

  if (processes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <p className="text-sm text-zinc-400 font-medium">No processes extracted</p>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-3 flex items-center gap-1">
        <button
          onClick={() => setView("tree")}
          className={`inline-flex items-center gap-1.5 rounded-l-lg border px-3 py-1.5 text-xs font-medium ${view === "tree" ? "border-teal-700 bg-teal-900/30 text-teal-400" : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200"}`}
        >
          <ListTree className="h-3.5 w-3.5" /> Tree View
        </button>
        <button
          onClick={() => setView("flat")}
          className={`inline-flex items-center gap-1.5 rounded-r-lg border border-l-0 px-3 py-1.5 text-xs font-medium ${view === "flat" ? "border-teal-700 bg-teal-900/30 text-teal-400" : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200"}`}
        >
          <Table2 className="h-3.5 w-3.5" /> Flat Table
        </button>
      </div>

      {view === "tree" ? (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs overflow-x-auto">
          {roots.map((p) => (
            <TreeNode key={p.id} process={p} childrenByPpid={childrenByPpid} depth={0} highlightPid={highlightPid} highlightedRowRef={highlightedTreeRowRef} findingsByPid={findingsByPid} onJumpToFinding={onJumpToFinding} pidSet={pidSet} />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900">
                <th className="px-3 py-2.5 text-right text-zinc-500 font-medium">PID</th>
                <th className="px-3 py-2.5 text-right text-zinc-500 font-medium">PPID</th>
                <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Name</th>
                <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Flags</th>
                <th className="px-3 py-2.5 text-left text-zinc-500 font-medium">Command Line</th>
                <th className="px-3 py-2.5 text-left text-zinc-500 font-medium whitespace-nowrap">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50 bg-zinc-950">
              {processes.map((p) => {
                const orphan = p.ppid !== null && p.ppid !== 0 && !pidSet.has(p.ppid);
                const masquerading = isMasquerading(p);
                return (
                  <tr
                    key={p.id}
                    ref={p.pid === highlightPid ? highlightedFlatRowRef : undefined}
                    className={`transition-colors ${p.pid === highlightPid ? "bg-teal-900/30 ring-1 ring-inset ring-teal-700" : "hover:bg-zinc-900/60"}`}
                  >
                    <td className="px-3 py-2 text-right font-mono text-zinc-300">{p.pid}</td>
                    <td className="px-3 py-2 text-right font-mono text-zinc-500">{p.ppid ?? "—"}</td>
                    <td className="px-3 py-2 text-teal-400 font-medium">{p.name}</td>
                    <td className="px-3 py-2">
                      <span className="inline-flex flex-wrap gap-1">
                        {orphan && <span className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">Orphan</span>}
                        {masquerading && <span className="rounded border border-orange-900 bg-orange-900/40 px-1.5 py-0.5 text-[10px] text-orange-400">Unexpected path</span>}
                        <ProcessBadges pid={p.pid} findingsByPid={findingsByPid} onJumpToFinding={onJumpToFinding} />
                      </span>
                    </td>
                    <td className="px-3 py-2 text-zinc-400 truncate max-w-[280px]" title={p.commandLine ?? ""}>{p.commandLine ?? "—"}</td>
                    <td className="px-3 py-2 text-zinc-500 whitespace-nowrap">{p.createTime ? new Date(p.createTime).toLocaleString() : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
