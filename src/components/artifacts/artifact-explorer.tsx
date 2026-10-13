"use client";

import { ChevronLeft, ChevronRight, EyeOff, Search, X } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { formatDateTime } from "@/lib/utils";
import { ArtifactTypeEnrichButton } from "@/components/artifacts/artifact-type-enrich-button";

type EvidenceRow = {
  id: string;
  type: string;
  source: string | null;
  timestamp: string | null;
  hostname: string | null;
  username: string | null;
  url: string | null;
  ip: string | null;
  domain: string | null;
  hash: string | null;
  processName: string | null;
  commandLine: string | null;
  findingId: string;
};

type ArtifactResponse = {
  rows: EvidenceRow[];
  total: number;
  page: number;
  limit: number;
  pages: number;
  types: string[];
  caseId: string | null;
  knownGoodCount: number;
};

type ArtifactExplorerProps = {
  investigationId: string;
};

export function ArtifactExplorer({ investigationId }: ArtifactExplorerProps) {
  const router = useRouter();
  const sp = useSearchParams();

  const [data, setData] = useState<ArtifactResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState(sp.get("q") ?? "");
  const [activeType, setActiveType] = useState(sp.get("type") ?? "");
  const [page, setPage] = useState(Number(sp.get("page") ?? 1));
  const [hideKnownGood, setHideKnownGood] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchData = useCallback(
    async (q: string, type: string, p: number, hideGood: boolean) => {
      setLoading(true);
      const params = new URLSearchParams({ page: String(p), limit: "50" });
      if (q) params.set("q", q);
      if (type) params.set("type", type);
      if (hideGood) params.set("hideKnownGood", "true");
      const res = await fetch(
        `/api/investigations/${investigationId}/artifacts?${params}`
      );
      if (res.ok) {
        setData(await res.json());
      }
      setLoading(false);
    },
    [investigationId]
  );

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      fetchData(query, activeType, page, hideKnownGood);
    }, 300);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, activeType, page, hideKnownGood]);

  function handleTypeChange(type: string) {
    setActiveType(type);
    setPage(1);
  }

  const types = data?.types ?? [];
  const rows = data?.rows ?? [];

  return (
    <div className="grid gap-4">
      {/* Type tabs */}
      {types.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          <TypeTab label="All" active={!activeType} onClick={() => handleTypeChange("")} />
          {types.map((t) => (
            <TypeTab key={t} label={t} active={activeType === t} onClick={() => handleTypeChange(t)} />
          ))}
        </div>
      )}

      {/* Search + bulk enrich */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative max-w-md flex-1 min-w-[240px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(1); }}
            placeholder="Search evidence…"
            className="w-full rounded-md border border-zinc-800 bg-zinc-900/60 py-2 pl-8 pr-8 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-teal-400/50 focus:ring-1 focus:ring-teal-400/20"
          />
          {query && (
            <button onClick={() => setQuery("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        <ArtifactTypeEnrichButton investigationId={investigationId} type={activeType || undefined} />
      </div>

      {/* Count + known-good filter */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {data && (
          <p className="text-xs text-zinc-500">
            {data.total.toLocaleString()} evidence row{data.total !== 1 ? "s" : ""}
            {data.pages > 1 ? ` · page ${data.page} of ${data.pages}` : ""}
          </p>
        )}
        {data && data.caseId && data.knownGoodCount > 0 && (
          <label className="flex items-center gap-1.5 text-xs text-zinc-400">
            <input
              type="checkbox"
              checked={hideKnownGood}
              onChange={(e) => { setHideKnownGood(e.target.checked); setPage(1); }}
              className="rounded border-zinc-700 bg-zinc-900"
            />
            <EyeOff className="h-3.5 w-3.5 text-zinc-500" />
            Hide known-good ({data.knownGoodCount.toLocaleString()} hashes in this case)
          </label>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        {loading ? (
          <div className="py-12 text-center text-sm text-zinc-500">Loading…</div>
        ) : rows.length === 0 ? (
          <div className="py-12 text-center text-sm text-zinc-500">No evidence found.</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-950/80">
                <Th>Type</Th>
                <Th>Process / Name</Th>
                <Th>IOC</Th>
                <Th>Host · User</Th>
                <Th>Command</Th>
                <Th>Time</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-b border-zinc-800/40 hover:bg-zinc-900/40">
                  <Td>
                    <Link href={`/evidence/${row.id}`} className="text-teal-300 hover:underline">
                      <span className="text-xs">{row.type}</span>
                    </Link>
                  </Td>
                  <Td>{row.processName ?? "—"}</Td>
                  <Td>
                    {row.url || row.ip || row.domain || row.hash ? (
                      <IocLink value={(row.url ?? row.ip ?? row.domain ?? row.hash)!} />
                    ) : "—"}
                  </Td>
                  <Td className="text-zinc-400 text-xs">
                    {[row.hostname, row.username].filter(Boolean).join(" · ") || "—"}
                  </Td>
                  <Td className="font-mono text-xs text-zinc-400">
                    {row.commandLine ? row.commandLine.slice(0, 60) + (row.commandLine.length > 60 ? "…" : "") : "—"}
                  </Td>
                  <Td className="text-zinc-500 text-xs">
                    {row.timestamp ? formatDateTime(new Date(row.timestamp)) : "—"}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {data && data.pages > 1 && (
        <div className="flex items-center justify-between">
          <button
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="inline-flex items-center gap-1 rounded border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-100 disabled:opacity-30"
          >
            <ChevronLeft className="h-3.5 w-3.5" /> Prev
          </button>
          <span className="text-xs text-zinc-600">{page} / {data.pages}</span>
          <button
            disabled={page >= data.pages}
            onClick={() => setPage((p) => p + 1)}
            className="inline-flex items-center gap-1 rounded border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-100 disabled:opacity-30"
          >
            Next <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

function TypeTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
        active
          ? "border-teal-400/50 bg-teal-400/15 text-teal-200"
          : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-teal-400/30 hover:text-zinc-200"
      }`}
    >
      {label}
    </button>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">
      {children}
    </th>
  );
}

function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <td className={`px-4 py-2.5 ${className ?? "text-zinc-200"}`}>{children}</td>
  );
}

function IocLink({ value }: { value: string }) {
  return (
    <Link
      href={`/intelligence/ioc/${encodeURIComponent(value)}`}
      className="font-mono text-xs text-amber-300 hover:underline"
      title={value}
    >
      {value.length > 35 ? `${value.slice(0, 35)}…` : value}
    </Link>
  );
}
