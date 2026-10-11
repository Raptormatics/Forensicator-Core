"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Zap, Download } from "lucide-react";
import { deriveRuleScopes, RULE_SCOPE_LABEL } from "@/lib/ram-analysis/rule-scope";

export type MalfindRegion = {
  id: string;
  tag: string | null;
  protection: string | null;
  startAddress: string | null;
  endAddress: string | null;
  commitCharge: number | null;
  privateMemory: number | null;
  path: string | null;
  previewHex: string | null;
};

export type FindingMatch = {
  id: string;
  pid: number | null;
  processName: string | null;
  matchedField: string | null;
  matchedValue: string | null;
};

export type Finding = {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  matchCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  matchedField: string | null;
  matchedValue: string | null;
  pid: number | null;
  processName: string | null;
  rule: { id: string; name: string; tags: string[]; conditions?: unknown } | null;
  yaraRule: { id: string; name: string; tags: string[] } | null;
  malfindRegions: MalfindRegion[];
  matches: FindingMatch[];
};

export const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400 border-red-900",
  high:     "bg-orange-900/40 text-orange-400 border-orange-900",
  medium:   "bg-yellow-900/40 text-yellow-400 border-yellow-900",
  low:      "bg-blue-900/40 text-blue-400 border-blue-900",
  info:     "bg-zinc-800 text-zinc-400 border-zinc-700",
};

/** A spaced-hex string ("4d 5a 90 00 ...") into its printable-ASCII column. */
function hexToAscii(hex: string): string {
  return hex
    .trim()
    .split(/\s+/)
    .map((b) => {
      const n = parseInt(b, 16);
      return Number.isFinite(n) && n >= 0x20 && n <= 0x7e ? String.fromCharCode(n) : ".";
    })
    .join("");
}

function HexPreview({ hex }: { hex: string }) {
  return (
    <div className="mt-2 rounded border border-zinc-800 bg-zinc-950 p-2 font-mono text-[11px] leading-5 overflow-x-auto">
      <div className="flex gap-4 whitespace-nowrap">
        <span className="text-zinc-500">{hex}</span>
        <span className="text-teal-400">{hexToAscii(hex)}</span>
      </div>
    </div>
  );
}

function RegionRow({ uploadId, region }: { uploadId: string; region: MalfindRegion }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      <tr
        className="border-b border-zinc-800/50 hover:bg-zinc-900/60 cursor-pointer transition-colors"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-2 py-1.5 text-zinc-300">{region.tag ?? "—"}</td>
        <td className="px-2 py-1.5 font-mono text-orange-400">{region.protection ?? "—"}</td>
        <td className="px-2 py-1.5 font-mono text-zinc-400">{region.startAddress ?? "—"}</td>
        <td className="px-2 py-1.5 font-mono text-zinc-400">{region.endAddress ?? "—"}</td>
        <td className="px-2 py-1.5 text-right">
          <a
            href={`/api/ram-analysis/uploads/${uploadId}/malfind-regions/${region.id}/dump?download=1`}
            onClick={(e) => e.stopPropagation()}
            className="inline-flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300"
            title="Dump the full memory region"
          >
            <Download className="h-3 w-3" /> Dump
          </a>
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-zinc-800/50">
          <td colSpan={5} className="px-2 py-2 bg-zinc-950/50">
            {region.previewHex
              ? <HexPreview hex={region.previewHex} />
              : <p className="text-xs text-zinc-600">No preview captured for this region.</p>}
          </td>
        </tr>
      )}
    </>
  );
}

function MalfindFindingBody({ uploadId, f }: { uploadId: string; f: Finding }) {
  return (
    <div className="mt-3 overflow-x-auto rounded border border-zinc-800">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-zinc-800 bg-zinc-950/80 text-left text-zinc-500">
            <th className="px-2 py-1.5 font-medium">VAD Tag</th>
            <th className="px-2 py-1.5 font-medium">Protection</th>
            <th className="px-2 py-1.5 font-medium">Start Address</th>
            <th className="px-2 py-1.5 font-medium">End Address</th>
            <th className="px-2 py-1.5 font-medium text-right">Full dump</th>
          </tr>
        </thead>
        <tbody>
          {f.malfindRegions.map((r) => <RegionRow key={r.id} uploadId={uploadId} region={r} />)}
        </tbody>
      </table>
    </div>
  );
}

function RuleMatchBody({ f }: { f: Finding }) {
  return (
    <div className="mt-3 max-h-72 overflow-y-auto overflow-x-auto rounded border border-zinc-800">
      <table className="w-full text-xs">
        <thead className="sticky top-0">
          <tr className="border-b border-zinc-800 bg-zinc-950/95 text-left text-zinc-500">
            <th className="px-2 py-1.5 font-medium text-right">PID</th>
            <th className="px-2 py-1.5 font-medium">Process</th>
            <th className="px-2 py-1.5 font-medium">Matched Field</th>
            <th className="px-2 py-1.5 font-medium">Matched Value</th>
          </tr>
        </thead>
        <tbody>
          {f.matches.map((m) => (
            <tr key={m.id} className="border-b border-zinc-800/50 hover:bg-zinc-900/40">
              <td className="px-2 py-1.5 text-right font-mono text-zinc-300">{m.pid ?? "—"}</td>
              <td className="px-2 py-1.5 text-teal-400 font-medium">{m.processName ?? "—"}</td>
              <td className="px-2 py-1.5 font-mono text-zinc-500">{m.matchedField ?? "—"}</td>
              <td className="px-2 py-1.5 font-mono text-zinc-400 truncate max-w-[280px]">{m.matchedValue ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function FindingCard({ uploadId, f, onJumpToProcess }: { uploadId: string; f: Finding; onJumpToProcess?: (pid: number) => void }) {
  const groupable = f.malfindRegions.length > 0 || f.matches.length > 0;
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-start gap-3">
        {groupable && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="mt-0.5 text-zinc-500 hover:text-zinc-300 shrink-0"
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        )}
        <span className={`mt-0.5 rounded border px-2 py-0.5 text-xs font-medium capitalize shrink-0 ${SEVERITY_BADGE[f.severity] ?? SEVERITY_BADGE.info}`}>
          {f.severity}
        </span>
        <div className="flex-1 min-w-0">
          <p
            className={`text-sm font-medium text-zinc-100 ${groupable ? "cursor-pointer" : ""}`}
            onClick={groupable ? () => setExpanded((v) => !v) : undefined}
          >
            {f.title}
          </p>
          {f.description && <p className="text-xs text-zinc-500 mt-0.5">{f.description}</p>}
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-zinc-500">
            <span className="flex items-center gap-1">
              <Zap className="h-3 w-3" /> {f.matchCount.toLocaleString()} match{f.matchCount !== 1 ? "es" : ""}
            </span>
            {f.pid !== null && (
              <button
                onClick={() => onJumpToProcess?.(f.pid!)}
                className="font-mono text-teal-400 hover:text-teal-300 hover:underline"
                title="Jump to this process"
              >
                PID {f.pid} · {f.processName ?? "—"}
              </button>
            )}
            {f.pid === null && f.matchedField && (
              <span className="font-mono text-zinc-400">
                {f.matchedField}: <span className="text-teal-400">{f.matchedValue}</span>
              </span>
            )}
          </div>
          {expanded && f.malfindRegions.length > 0 && <MalfindFindingBody uploadId={uploadId} f={f} />}
          {expanded && f.matches.length > 0 && <RuleMatchBody f={f} />}
        </div>
        {f.rule && (
          <div className="shrink-0 flex flex-wrap gap-1 justify-end">
            {f.rule.tags.slice(0, 3).map((t) => (
              <span key={t} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-500">{t}</span>
            ))}
            {deriveRuleScopes(f.rule.conditions).map((scope) => (
              <span key={scope} className="rounded border border-sky-900 bg-sky-900/30 px-1.5 py-0.5 text-[10px] text-sky-400" title="Volatility-derived dataset this rule inspects">
                {RULE_SCOPE_LABEL[scope]}
              </span>
            ))}
          </div>
        )}
        {f.yaraRule && (
          <div className="shrink-0 flex flex-wrap gap-1 justify-end">
            {f.yaraRule.tags.slice(0, 3).map((t) => (
              <span key={t} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-500">{t}</span>
            ))}
            <span className="rounded border border-purple-900 bg-purple-900/30 px-1.5 py-0.5 text-[10px] text-purple-400" title="Custom Yara signature — scanned directly against raw memory bytes">
              Yara
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
