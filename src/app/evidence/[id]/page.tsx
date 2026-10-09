import {
  ArrowLeft,
  ArrowRight,
  CalendarClock,
  ChevronLeft,
  ExternalLink,
  Fingerprint,
  Globe,
  Hash,
  Monitor,
  Terminal,
  User,
} from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { prisma } from "@/lib/db/prisma";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { CopyButton } from "@/components/ui/copy-button";
import { formatDateTime } from "@/lib/utils";

export const dynamic = "force-dynamic";

type Props = { params: Promise<{ id: string }> };

export default async function EvidencePage(props: Props) {
  const params = await props.params;
  const ev = await prisma.evidence.findUnique({
    where: { id: params.id },
    include: {
      investigation: { select: { id: true, title: true, hostname: true } },
      finding: {
        select: {
          id: true,
          findingId: true,
          findingType: true,
          category: true,
          severity: true,
          riskScore: true,
          sourceCategory: true,
        },
      },
    },
  });

  if (!ev) notFound();

  // Prev / next within the same finding (by timestamp).
  const [prev, next] = await Promise.all([
    prisma.evidence.findFirst({
      where: {
        findingId: ev.findingId,
        id: { not: ev.id },
        ...(ev.timestamp ? { timestamp: { lt: ev.timestamp } } : {}),
      },
      orderBy: { timestamp: "desc" },
      select: { id: true, type: true, timestamp: true, processName: true, url: true, ip: true },
    }),
    prisma.evidence.findFirst({
      where: {
        findingId: ev.findingId,
        id: { not: ev.id },
        ...(ev.timestamp ? { timestamp: { gt: ev.timestamp } } : {}),
      },
      orderBy: { timestamp: "asc" },
      select: { id: true, type: true, timestamp: true, processName: true, url: true, ip: true },
    }),
  ]);

  const raw = ev.raw as Record<string, unknown>;

  return (
    <main className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-5 sm:px-6 lg:px-8">
          <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
            <Fingerprint className="h-3.5 w-3.5" />
            <Link href={`/investigations/${ev.investigationId}`} className="hover:text-teal-300">
              {ev.investigation.title}
            </Link>
            <span>/</span>
            <Link href={`/investigations/${ev.investigationId}/artifacts`} className="hover:text-teal-300">
              Evidence
            </Link>
            <span>/</span>
            <span className="text-zinc-400">{ev.type}</span>
          </div>
          <h1 className="mt-2 text-xl font-semibold text-zinc-50">{ev.type}</h1>
          {ev.timestamp && (
            <p className="mt-1 text-sm text-zinc-400">{formatDateTime(ev.timestamp)}</p>
          )}
        </div>
      </section>

      <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <Link
          href={`/investigations/${ev.investigationId}/artifacts`}
          className="mb-6 inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-teal-200"
        >
          <ChevronLeft className="h-4 w-4" />
          Back to artifacts
        </Link>

        {/* Prev / Next navigation */}
        <div className="mb-6 flex items-center justify-between gap-4">
          {prev ? (
            <Link
              href={`/evidence/${prev.id}`}
              className="inline-flex items-center gap-1.5 rounded border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:border-teal-400/30 hover:text-teal-200"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              {prev.processName ?? prev.url ?? prev.ip ?? prev.type}
            </Link>
          ) : <div />}
          {next ? (
            <Link
              href={`/evidence/${next.id}`}
              className="inline-flex items-center gap-1.5 rounded border border-zinc-800 px-3 py-1.5 text-xs text-zinc-400 hover:border-teal-400/30 hover:text-teal-200"
            >
              {next.processName ?? next.url ?? next.ip ?? next.type}
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          ) : <div />}
        </div>

        <div className="grid gap-5 lg:grid-cols-[1fr_26rem]">
          {/* ── Left: metadata + raw JSON ── */}
          <div className="grid gap-5">
            {/* Key fields */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-5">
              <h2 className="mb-4 text-xs font-medium uppercase tracking-wide text-zinc-500">
                Evidence Fields
              </h2>
              <div className="grid gap-3 sm:grid-cols-2">
                {ev.hostname && <Field icon={<Monitor className="h-3.5 w-3.5" />} label="Hostname" value={ev.hostname} />}
                {ev.username && <Field icon={<User className="h-3.5 w-3.5" />} label="Username" value={ev.username} />}
                {ev.ip && (
                  <Field
                    icon={<Globe className="h-3.5 w-3.5" />}
                    label="IP Address"
                    value={ev.ip}
                    href={`/intelligence/ioc/${encodeURIComponent(ev.ip)}`}
                  />
                )}
                {ev.domain && (
                  <Field
                    icon={<Globe className="h-3.5 w-3.5" />}
                    label="Domain"
                    value={ev.domain}
                    href={`/intelligence/ioc/${encodeURIComponent(ev.domain)}`}
                  />
                )}
                {ev.url && (
                  <Field
                    icon={<ExternalLink className="h-3.5 w-3.5" />}
                    label="URL"
                    value={ev.url}
                    href={`/intelligence/ioc/${encodeURIComponent(ev.url)}`}
                    mono
                    truncate
                  />
                )}
                {ev.hash && (
                  <Field
                    icon={<Hash className="h-3.5 w-3.5" />}
                    label="Hash"
                    value={ev.hash}
                    href={`/intelligence/ioc/${encodeURIComponent(ev.hash)}`}
                    mono
                    truncate
                  />
                )}
                {ev.processName && (
                  <Field
                    icon={<Terminal className="h-3.5 w-3.5" />}
                    label="Process"
                    value={ev.processName}
                    href={`/intelligence/ioc/${encodeURIComponent(ev.processName)}`}
                  />
                )}
                {ev.timestamp && (
                  <Field
                    icon={<CalendarClock className="h-3.5 w-3.5" />}
                    label="Timestamp"
                    value={formatDateTime(ev.timestamp)}
                  />
                )}
              </div>

              {/* Command line — full width */}
              {ev.commandLine && (
                <div className="mt-4">
                  <p className="mb-1.5 flex items-center gap-1.5 text-xs uppercase tracking-wide text-zinc-500">
                    <Terminal className="h-3.5 w-3.5" /> Command Line
                  </p>
                  <pre className="overflow-x-auto rounded bg-zinc-900 p-3 font-mono text-xs text-teal-200 whitespace-pre-wrap break-all">
                    {ev.commandLine}
                  </pre>
                </div>
              )}
            </div>

            {/* Raw JSON viewer */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-5">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Raw Evidence</h2>
                <CopyButton text={JSON.stringify(raw, null, 2)} />
              </div>
              <pre className="max-h-[32rem] overflow-auto rounded bg-zinc-900 p-4 font-mono text-xs text-zinc-300 whitespace-pre leading-relaxed">
                {JSON.stringify(raw, null, 2)}
              </pre>
            </div>
          </div>

          {/* ── Right: related context ── */}
          <div className="grid gap-5 self-start">
            {/* Source Finding */}
            {ev.finding && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-5">
                <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-zinc-500">Source Finding</h2>
                <Link
                  href={`/investigations/${ev.investigationId}?finding=${ev.finding.id}`}
                  className="block rounded border border-zinc-800 p-3 hover:border-teal-400/30"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-zinc-100">{ev.finding.findingType}</span>
                    <SeverityBadge severity={ev.finding.severity} />
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">
                    {ev.finding.category} · {ev.finding.sourceCategory ?? "—"}
                  </p>
                </Link>
              </div>
            )}

            {/* Investigation */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-5">
              <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-zinc-500">Investigation</h2>
              <Link
                href={`/investigations/${ev.investigationId}`}
                className="block rounded border border-zinc-800 p-3 hover:border-teal-400/30"
              >
                <p className="text-sm font-medium text-zinc-100">{ev.investigation.title}</p>
                <p className="mt-0.5 text-xs text-zinc-500">{ev.investigation.hostname ?? "Unknown host"}</p>
              </Link>
            </div>

            {/* IOC pivot links */}
            {(ev.ip || ev.domain || ev.url || ev.hash) && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-5">
                <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-zinc-500">IOC Pivot</h2>
                <div className="grid gap-2">
                  {([
                    { label: "IP", value: ev.ip },
                    { label: "Domain", value: ev.domain },
                    { label: "URL", value: ev.url },
                    { label: "Hash", value: ev.hash },
                  ] as { label: string; value: string | null }[])
                    .filter((f) => f.value)
                    .map(({ label, value }) => (
                      <Link
                        key={label}
                        href={`/intelligence/ioc/${encodeURIComponent(value!)}`}
                        className="flex items-center justify-between rounded border border-amber-400/20 bg-amber-400/5 px-3 py-2 text-xs text-amber-300 hover:border-amber-400/40"
                      >
                        <span className="font-medium text-zinc-500">{label}</span>
                        <span className="font-mono">{value!.length > 35 ? `${value!.slice(0, 35)}…` : value}</span>
                      </Link>
                    ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function Field({
  icon,
  label,
  value,
  href,
  mono = false,
  truncate = false,
}: {
  icon?: React.ReactNode;
  label: string;
  value: string;
  href?: string;
  mono?: boolean;
  truncate?: boolean;
}) {
  const textClass = `mt-1 text-sm text-zinc-200 ${mono ? "font-mono text-xs" : ""} ${truncate ? "truncate" : ""}`;
  return (
    <div className="rounded border border-zinc-800 bg-zinc-900/50 p-3">
      <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-zinc-500">
        {icon}
        {label}
      </div>
      {href ? (
        <Link href={href} className={`${textClass} text-amber-300 hover:underline`}>
          {value}
        </Link>
      ) : (
        <p className={textClass}>{value}</p>
      )}
    </div>
  );
}

