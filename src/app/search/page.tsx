import { AlertCircle, FileSearch, Fingerprint, Globe, Hash, Monitor, Search, Server, Terminal } from "lucide-react";
import Link from "next/link";
import { prisma } from "@/lib/db/prisma";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { formatDateTime } from "@/lib/utils";
import { notArchived, investigationNotArchived } from "@/lib/cases/archive";

export const dynamic = "force-dynamic";

type SearchPageProps = {
  searchParams: Promise<{ q?: string; archived?: string }>;
};

export default async function SearchPage(props: SearchPageProps) {
  const searchParams = await props.searchParams;
  const q = (searchParams.q ?? "").trim();

  if (!q) {
    return (
      <main className="mx-auto min-h-screen w-full max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center gap-4 py-24 text-center">
          <Search className="h-10 w-10 text-zinc-600" />
          <p className="text-lg font-medium text-zinc-300">Enter a search query</p>
          <p className="text-sm text-zinc-500">
            Search for IPs, hashes, URLs, domains, processes, usernames, or any evidence text.
          </p>
        </div>
      </main>
    );
  }

  const LIMIT = 15;
  // Archived cases/investigations are left out unless asked for — but old
  // incidents are exactly where a known IOC is worth looking, so it's one click.
  const includeArchived = searchParams.archived === "include";
  const invScope = includeArchived ? {} : { AND: [notArchived()] };
  const childScope = includeArchived ? {} : investigationNotArchived();

  const [investigations, findings, evidenceRows] = await Promise.all([
    prisma.investigation.findMany({
      where: {
        ...invScope,
        OR: [
          { title: { contains: q, mode: "insensitive" } },
          { hostname: { contains: q, mode: "insensitive" } },
          { username: { contains: q, mode: "insensitive" } },
          { tags: { has: q } },
        ],
      },
      select: { id: true, title: true, hostname: true, username: true, tags: true, status: true, createdAt: true },
      take: LIMIT,
    }),
    prisma.finding.findMany({
      where: {
        ...childScope,
        OR: [
          { searchText: { contains: q, mode: "insensitive" } },
          { findingType: { contains: q, mode: "insensitive" } },
          { category: { contains: q, mode: "insensitive" } },
        ],
      },
      select: {
        id: true,
        findingId: true,
        findingType: true,
        category: true,
        severity: true,
        riskScore: true,
        sourceCategory: true,
        investigationId: true,
        investigation: { select: { id: true, title: true } },
      },
      take: LIMIT,
    }),
    prisma.evidence.findMany({
      where: {
        ...childScope,
        OR: [
          { url: { contains: q, mode: "insensitive" } },
          { ip: { contains: q, mode: "insensitive" } },
          { domain: { contains: q, mode: "insensitive" } },
          { hash: { contains: q, mode: "insensitive" } },
          { processName: { contains: q, mode: "insensitive" } },
          { commandLine: { contains: q, mode: "insensitive" } },
          { username: { contains: q, mode: "insensitive" } },
          { hostname: { contains: q, mode: "insensitive" } },
          { searchableText: { contains: q, mode: "insensitive" } },
        ],
      },
      select: {
        id: true,
        type: true,
        timestamp: true,
        hostname: true,
        username: true,
        url: true,
        ip: true,
        domain: true,
        hash: true,
        processName: true,
        commandLine: true,
        investigationId: true,
        investigation: { select: { id: true, title: true } },
      },
      orderBy: { timestamp: "desc" },
      take: LIMIT,
    }),
  ]);

  const total = investigations.length + findings.length + evidenceRows.length;

  return (
    <main className="mx-auto min-h-screen w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-zinc-500">
          <Search className="h-3.5 w-3.5" />
          Search results
        </div>
        <h1 className="mt-2 text-2xl font-semibold text-zinc-50">
          &ldquo;{q}&rdquo;
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          {total === 0 ? "No results found." : `${total} result${total !== 1 ? "s" : ""} across investigations, findings and evidence.`}
          {" "}
          <Link
            href={`/search?q=${encodeURIComponent(q)}${includeArchived ? "" : "&archived=include"}`}
            className="text-teal-400 hover:text-teal-300"
          >
            {includeArchived ? "Hide archived" : "Include archived"}
          </Link>
        </p>
      </div>

      {total === 0 && (
        <div className="flex flex-col items-center gap-3 py-20 text-center">
          <FileSearch className="h-10 w-10 text-zinc-700" />
          <p className="text-sm text-zinc-500">Try a different query — IPs, hashes, process names, or URLs work well.</p>
        </div>
      )}

      <div className="grid gap-8">
        {/* Investigations */}
        {investigations.length > 0 && (
          <Section title="Investigations" count={investigations.length} icon={<Monitor className="h-4 w-4" />}>
            <div className="grid gap-2">
              {investigations.map((inv) => (
                <Link
                  key={inv.id}
                  href={`/investigations/${inv.id}`}
                  className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950/55 px-4 py-3 hover:border-teal-400/30 hover:bg-zinc-900/40"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium text-zinc-100">{inv.title}</p>
                    <p className="mt-0.5 text-xs text-zinc-500">
                      {inv.hostname ?? "Unknown host"} · {formatDateTime(inv.createdAt)}
                    </p>
                  </div>
                  <div className="ml-4 flex flex-wrap gap-1">
                    {inv.tags.slice(0, 3).map((t) => (
                      <span key={t} className="rounded-full border border-teal-400/20 bg-teal-400/8 px-2 py-0.5 text-[10px] text-teal-400">
                        {t}
                      </span>
                    ))}
                  </div>
                </Link>
              ))}
            </div>
          </Section>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <Section title="Findings" count={findings.length} icon={<AlertCircle className="h-4 w-4" />}>
            <div className="grid gap-2">
              {findings.map((f) => (
                <Link
                  key={f.id}
                  href={`/investigations/${f.investigationId}?finding=${f.id}`}
                  className="flex items-center gap-4 rounded-lg border border-zinc-800 bg-zinc-950/55 px-4 py-3 hover:border-teal-400/30 hover:bg-zinc-900/40"
                >
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium text-zinc-100">{f.findingType}</p>
                    <p className="mt-0.5 text-xs text-zinc-500">
                      {f.investigation.title} · {f.category} · {f.sourceCategory ?? "—"}
                    </p>
                  </div>
                </Link>
              ))}
            </div>
          </Section>
        )}

        {/* Evidence */}
        {evidenceRows.length > 0 && (
          <Section title="Evidence" count={evidenceRows.length} icon={<Fingerprint className="h-4 w-4" />}>
            <div className="overflow-hidden rounded-lg border border-zinc-800">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-950/80">
                    <Th>Type</Th>
                    <Th>IOC / Value</Th>
                    <Th>Host · User</Th>
                    <Th>Investigation</Th>
                    <Th>Time</Th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceRows.map((ev) => (
                    <tr
                      key={ev.id}
                      className="border-b border-zinc-800/50 hover:bg-zinc-900/40"
                    >
                      <Td>
                        <Link href={`/evidence/${ev.id}`} className="text-teal-300 hover:underline">
                          {ev.type}
                        </Link>
                      </Td>
                      <Td>
                        <IocValue ev={ev} query={q} />
                      </Td>
                      <Td className="text-zinc-400">
                        {[ev.hostname, ev.username].filter(Boolean).join(" · ") || "—"}
                      </Td>
                      <Td>
                        <Link href={`/investigations/${ev.investigationId}`} className="text-zinc-300 hover:text-teal-300">
                          {ev.investigation.title}
                        </Link>
                      </Td>
                      <Td className="text-zinc-500">
                        {ev.timestamp ? formatDateTime(ev.timestamp) : "—"}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}
      </div>
    </main>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function Section({
  title,
  count,
  icon,
  children,
}: {
  title: string;
  count: number;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="mb-3 flex items-center gap-2">
        <span className="text-zinc-500">{icon}</span>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">{title}</h2>
        <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500">{count}</span>
      </div>
      {children}
    </section>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">{children}</th>;
}
function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={`px-4 py-2.5 ${className ?? "text-zinc-200"}`}>{children}</td>;
}

type EvidenceRow = {
  url: string | null;
  ip: string | null;
  domain: string | null;
  hash: string | null;
  processName: string | null;
  commandLine: string | null;
};

function IocValue({ ev, query }: { ev: EvidenceRow; query: string }) {
  const value =
    ev.url ?? ev.ip ?? ev.domain ?? ev.hash ?? ev.processName ??
    (ev.commandLine ? ev.commandLine.slice(0, 80) : null);

  if (!value) return <span className="text-zinc-600">—</span>;

  const isIoc = !!ev.url || !!ev.ip || !!ev.domain || !!ev.hash;

  if (isIoc) {
    return (
      <Link
        href={`/intelligence/ioc/${encodeURIComponent(value)}`}
        className="font-mono text-xs text-amber-300 hover:underline"
      >
        {value.length > 60 ? `${value.slice(0, 60)}…` : value}
      </Link>
    );
  }

  return (
    <span className="font-mono text-xs text-zinc-300">
      {value.length > 60 ? `${value.slice(0, 60)}…` : value}
    </span>
  );
}
