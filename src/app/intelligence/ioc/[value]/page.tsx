import { Crosshair } from "lucide-react";
import Link from "next/link";
import { prisma } from "@/lib/db/prisma";
import { BackButton } from "@/components/ui/back-button";
import { EnrichIocButton } from "@/components/intelligence/enrich-ioc-button";
import { CopyIocButton } from "@/components/intelligence/copy-ioc-button";
import { IocActionBar } from "@/components/intelligence/ioc-action-bar";
import { SeverityOverrideBadge } from "@/components/findings/severity-override-badge";
import { summarizeVendorVerdict, VERDICT_STYLE, PROVIDER_LABEL } from "@/lib/intelligence/verdict";
import { extractForensicContext } from "@/lib/intelligence/forensic-context";
import { formatDateTime } from "@/lib/utils";

export const dynamic = "force-dynamic";

type Props = {
  params: Promise<{ value: string }>;
  searchParams: Promise<{ page?: string }>;
};

const LIMIT = 50;

export default async function IocPage(props: Props) {
  const params = await props.params;
  const searchParams = await props.searchParams;
  const ioc = decodeURIComponent(params.value).trim();
  const page = Math.max(1, Number(searchParams.page ?? 1));

  // Determine best-match IOC fields.
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(ioc);
  const isHash = /^[0-9a-fA-F]{32,64}$/.test(ioc);
  const isUrl = ioc.startsWith("http://") || ioc.startsWith("https://");

  const iocWhere = isIp
    ? [{ ip: { contains: ioc, mode: "insensitive" as const } }]
    : isHash
    ? [{ hash: { contains: ioc, mode: "insensitive" as const } }]
    : isUrl
    ? [{ url: { contains: ioc, mode: "insensitive" as const } }]
    : [
        { url: { contains: ioc, mode: "insensitive" as const } },
        { ip: { contains: ioc, mode: "insensitive" as const } },
        { domain: { contains: ioc, mode: "insensitive" as const } },
        { hash: { contains: ioc, mode: "insensitive" as const } },
        { processName: { contains: ioc, mode: "insensitive" as const } },
        { username: { contains: ioc, mode: "insensitive" as const } },
        { hostname: { contains: ioc, mode: "insensitive" as const } },
        { commandLine: { contains: ioc, mode: "insensitive" as const } },
        { searchableText: { contains: ioc, mode: "insensitive" as const } },
      ];

  const [total, rows, stats] = await Promise.all([
    prisma.evidence.count({ where: { OR: iocWhere } }),
    prisma.evidence.findMany({
      where: { OR: iocWhere },
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
        raw: true,
        investigationId: true,
        investigation: { select: { id: true, title: true } },
        finding: { select: { id: true, findingType: true, severity: true } },
      },
      orderBy: { timestamp: "desc" },
      skip: (page - 1) * LIMIT,
      take: LIMIT,
    }),
    prisma.evidence.aggregate({
      where: { OR: iocWhere },
      _min: { timestamp: true },
      _max: { timestamp: true },
    }),
  ]);

  const pages = Math.ceil(total / LIMIT);
  const uniqueInvestigationIds = [...new Set(rows.map((r) => r.investigationId))];
  const uniqueHostnames = [...new Set(rows.map((r) => r.hostname).filter((h): h is string => Boolean(h)))];
  const uniqueFindingIds = [...new Set(rows.map((r) => r.finding?.id).filter((id): id is string => Boolean(id)))];

  // Cases this indicator's evidence traces back to (via each investigation's
  // single, nullable Case link) — used so the action bar can attach a
  // remediation task to the right case.
  const investigationsWithCase = await prisma.investigation.findMany({
    where: { id: { in: uniqueInvestigationIds } },
    select: { case: { select: { id: true, title: true, caseSeq: true } } },
  });
  const linkedCases = [...new Map(
    investigationsWithCase
      .map((i) => i.case)
      .filter((c): c is NonNullable<typeof c> => Boolean(c))
      .map((c) => [c.id, c] as const)
  ).values()];

  // Look up enrichment record for this IOC value
  const iocRecord = await prisma.iocRecord.findUnique({
    where: { value: ioc },
    include: { enrichments: { orderBy: { enrichedAt: "desc" } } },
  });

  const iocType = isIp ? "ip" as const : isHash ? "hash" as const : isUrl ? "url" as const : "domain" as const;

  return (
    <main className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-zinc-500">
            <Crosshair className="h-3.5 w-3.5" />
            IOC Intelligence
          </div>
          <div className="mt-2 flex items-center gap-2">
            <h1 className="break-all font-mono text-xl font-semibold text-amber-300">{ioc}</h1>
            <CopyIocButton value={ioc} />
          </div>

          {/* Compact horizontal metadata bar — replaces the old 4-tile KPI grid */}
          <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-1.5 text-sm">
            <span className="text-zinc-400">{iocLabel(isIp, isHash, isUrl)}</span>
            <MetaItem label="Total hits" value={total.toLocaleString()} />
            <MetaItem label="Investigations" value={uniqueInvestigationIds.length.toLocaleString()} />
            <MetaItem label="First seen" value={stats._min.timestamp ? formatDateTime(stats._min.timestamp) : "—"} />
            <MetaItem label="Last seen" value={stats._max.timestamp ? formatDateTime(stats._max.timestamp) : "—"} />
          </div>
        </div>
      </section>

      <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <BackButton />

        {/* Threat intelligence enrichment */}
        <div className="mb-6 rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Threat Intelligence</h2>
          {iocRecord ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-4 text-sm">
                {iocRecord.reputation != null && (
                  <div>
                    <span
                      className="text-xs text-zinc-500 underline decoration-dotted underline-offset-2"
                      title="Reputation is a 0–100 aggregate malicious-confidence score derived across all enrichment providers — higher means more likely malicious, not a measure of query success."
                    >
                      Reputation (malicious confidence)
                    </span>{" "}
                    <span className={`font-semibold ${iocRecord.reputation >= 70 ? "text-red-400" : iocRecord.reputation >= 40 ? "text-yellow-400" : "text-green-400"}`}>
                      {iocRecord.reputation}%
                    </span>
                  </div>
                )}
                {iocRecord.malwareFamily && (
                  <div>
                    <span className="text-xs text-zinc-500">Family </span>
                    <span className="font-medium text-orange-300">{iocRecord.malwareFamily}</span>
                  </div>
                )}
                {iocRecord.threatType && (
                  <div>
                    <span className="text-xs text-zinc-500">Threat type </span>
                    <span className="font-medium text-zinc-300">{iocRecord.threatType}</span>
                  </div>
                )}
              </div>
              {iocRecord.enrichments.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {iocRecord.enrichments.map((e) => {
                    const verdict = summarizeVendorVerdict(e.provider, e.status, e.response);
                    return (
                      <span
                        key={e.provider}
                        title={`Raw API status: ${e.status}`}
                        className={`rounded border px-2 py-0.5 text-xs font-medium ${VERDICT_STYLE[verdict.verdict]}`}
                      >
                        <span className="font-semibold">{PROVIDER_LABEL[e.provider] ?? e.provider}:</span> {verdict.label}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-zinc-500">Not yet enriched.</p>
          )}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <EnrichIocButton
              value={ioc}
              type={iocType}
              lastEnriched={iocRecord?.enrichedAt?.toISOString() ?? null}
            />
            <IocActionBar
              value={ioc}
              initialBlocklisted={iocRecord?.blocklisted ?? false}
              hostnames={uniqueHostnames}
              findingIds={uniqueFindingIds}
              cases={linkedCases}
            />
          </div>
        </div>

        {total === 0 ? (
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-12 text-center">
            <p className="text-sm text-zinc-500">No evidence found containing this IOC.</p>
          </div>
        ) : (
          <>
            <div className="overflow-hidden rounded-lg border border-zinc-800">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-950/80">
                    <Th>Type</Th>
                    <Th>Forensic Context</Th>
                    <Th>Host · User</Th>
                    <Th>Finding</Th>
                    <Th>Investigation</Th>
                    <Th>Time</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => {
                    const context = extractForensicContext(row.raw, 2);
                    return (
                      <tr key={row.id} className="border-b border-zinc-800/40 hover:bg-zinc-900/40">
                        <Td>
                          <Link href={`/evidence/${row.id}`} className="text-teal-300 hover:underline text-xs">
                            {row.type}
                          </Link>
                        </Td>
                        <Td className="text-xs text-zinc-300">
                          {context.length > 0 ? (
                            <div className="space-y-0.5">
                              {context.map((f) => (
                                <div key={f.key}>
                                  <span className="text-zinc-500">{f.key}: </span>
                                  <span className="font-mono text-zinc-200">
                                    {f.value.length > 40 ? `${f.value.slice(0, 40)}…` : f.value}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : "—"}
                        </Td>
                        <Td className="text-xs text-zinc-400">
                          {[row.hostname, row.username].filter(Boolean).join(" · ") || "—"}
                        </Td>
                        <Td>
                          {row.finding ? (
                            <div className="flex items-center gap-2">
                              <SeverityOverrideBadge findingId={row.finding.id} severity={row.finding.severity} />
                              <Link
                                href={`/investigations/${row.investigationId}?finding=${row.finding.id}`}
                                className="text-xs text-zinc-400 hover:text-teal-300"
                              >
                                {row.finding.findingType}
                              </Link>
                            </div>
                          ) : "—"}
                        </Td>
                        <Td>
                          <Link
                            href={`/investigations/${row.investigationId}`}
                            className="text-xs text-zinc-300 hover:text-teal-300"
                          >
                            {row.investigation.title}
                          </Link>
                        </Td>
                        <Td className="text-xs text-zinc-500">
                          {row.timestamp ? formatDateTime(row.timestamp) : "—"}
                        </Td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pages > 1 && (
              <div className="mt-4 flex items-center justify-between">
                {page > 1 ? (
                  <Link
                    href={`/intelligence/ioc/${encodeURIComponent(ioc)}?page=${page - 1}`}
                    className="inline-flex items-center gap-1 rounded border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:text-teal-200"
                  >
                    ← Prev
                  </Link>
                ) : <div />}
                <span className="text-xs text-zinc-600">{page} / {pages}</span>
                {page < pages ? (
                  <Link
                    href={`/intelligence/ioc/${encodeURIComponent(ioc)}?page=${page + 1}`}
                    className="inline-flex items-center gap-1 rounded border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:text-teal-200"
                  >
                    Next →
                  </Link>
                ) : <div />}
              </div>
            )}
          </>
        )}
      </div>
    </main>
  );
}

function iocLabel(isIp: boolean, isHash: boolean, isUrl: boolean) {
  if (isIp) return "IP Address";
  if (isHash) return "File Hash";
  if (isUrl) return "URL";
  return "IOC / Indicator";
}

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <span>
      <span className="text-xs uppercase tracking-wide text-zinc-500">{label} </span>
      <span className="font-mono text-zinc-200">{value}</span>
    </span>
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
  return <td className={`px-4 py-2.5 ${className ?? "text-zinc-200"}`}>{children}</td>;
}
