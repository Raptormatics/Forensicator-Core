import { Activity, AlertTriangle, ArrowDown, ArrowUp, Download, FileText, Shield, ShieldAlert, TrendingUp } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { prisma } from "@/lib/db/prisma";
import { getServerSession } from "@/lib/auth/session";
import { normalizeSeverity, severityRank, HIGH_SEVERITY_LABELS, type SeverityLabel } from "@/lib/severity";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { RelativeTime } from "@/components/dashboard/relative-time";
import { notArchived } from "@/lib/cases/archive";

export const dynamic = "force-dynamic";

const SEVERITY_COLOR: Record<SeverityLabel, string> = {
  Important:     "text-red-400",
  Notable:       "text-orange-400",
  Interesting:   "text-yellow-400",
  Informational: "text-green-400",
};

const STATUS_COLOR: Record<string, string> = {
  new:           "bg-zinc-700 text-zinc-200",
  under_review:  "bg-blue-900/50 text-blue-300",
  confirmed:     "bg-red-900/50 text-red-300",
  false_positive:"bg-zinc-800 text-zinc-400 line-through",
  escalated:     "bg-orange-900/50 text-orange-300",
  resolved:      "bg-green-900/50 text-green-400",
};

const STATUS_LABEL: Record<string, string> = {
  new:           "New",
  under_review:  "Under Review",
  confirmed:     "Confirmed",
  false_positive:"False Positive",
  escalated:     "Escalated",
  resolved:      "Resolved",
};

const REPORT_STATUS_DOT: Record<string, string> = {
  queued:     "bg-zinc-500",
  generating: "bg-yellow-400 animate-pulse",
  ready:      "bg-teal-400",
  failed:     "bg-red-400",
};

/** Delta badge from a (current, previous) 24h-window pair — always a real
 * timestamp-based comparison, never a fabricated/estimated trend. */
function Trend({ current, previous }: { current: number; previous: number }) {
  if (current === 0 && previous === 0) return null;
  if (previous === 0) {
    return <span className="inline-flex items-center gap-0.5 text-xs font-medium text-orange-400"><ArrowUp className="h-3 w-3" />{current} new</span>;
  }
  const pct = Math.round(((current - previous) / previous) * 100);
  if (pct === 0) return <span className="text-xs text-zinc-600">±0% vs. prior 24h</span>;
  const up = pct > 0;
  return (
    <span className={`inline-flex items-center gap-0.5 text-xs font-medium ${up ? "text-orange-400" : "text-teal-400"}`}>
      {up ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />}
      {Math.abs(pct)}% vs. prior 24h
    </span>
  );
}

export default async function DashboardPage() {
  const session = await getServerSession();
  if (!session?.user) redirect("/login");

  const { id: userId } = session.user;

  // Load actor + org memberships
  const actor = await prisma.user.findUniqueOrThrow({
    where: { id: userId },
    include: {
      orgMemberships: { select: { organizationId: true } },
    },
  });
  const orgIds = actor.orgMemberships.map((m) => m.organizationId);

  // Core is single-user/single-org — scope everything to the sole org.
  const orgScope: { organizationId?: { in: string[] } } = { organizationId: { in: orgIds } };

  // Working set: investigations not archived (on their own or through an
  // archived case) — the dashboard tracks active work; archived records are
  // on the Archive page.
  const activeInvScope = { ...orgScope, ...notArchived() };

  // Finding count scope: scoped to active investigations in org
  const findingInvScope = { investigation: activeInvScope };

  // Activity feed scope: activity on org investigations (or own)
  const activityWhere = {
    OR: [
      { userId: actor.id },
      { investigation: orgScope },
    ],
  };

  const reportScope = { OR: [{ investigation: orgScope }, { case: orgScope }] };

  // Trend windows — every delta badge on this page is a real count of
  // timestamped events in the last 24h vs. the 24h before that, never an
  // invented or estimated figure.
  const now = new Date();
  const last24hStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const prior24hStart = new Date(now.getTime() - 48 * 60 * 60 * 1000);

  const [
    myFindings,
    highRiskInvestigations,
    recentReports,
    recentActivity,
    totalInvestigations,
    newFindings,
    escalatedFindings,
    invLast24h, invPrior24h,
    findingsLast24h, findingsPrior24h,
    escalationEvents,
  ] = await Promise.all([
    // My assigned findings — always personal. `severity` is free-text
    // (Important/Notable/...), so DB orderBy would sort alphabetically —
    // fetch a larger candidate set ordered by recency, then rank+slice in JS.
    prisma.finding.findMany({
      where: { assigneeId: actor.id, workflowStatus: { notIn: ["resolved", "false_positive"] }, investigation: notArchived() },
      orderBy: { createdAt: "desc" },
      take: 50,
      select: {
        id: true, findingType: true, category: true, severity: true, workflowStatus: true, createdAt: true,
        investigation: { select: { id: true, title: true, hostname: true, case: { select: { id: true, title: true, caseSeq: true } } } },
      },
    }).then((rows) => rows.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)).slice(0, 10)),
    // High risk investigations — org-scoped
    prisma.investigation.findMany({
      where: { ...activeInvScope, findings: { some: { severity: { in: HIGH_SEVERITY_LABELS } } } },
      orderBy: { createdAt: "desc" },
      take: 5,
      select: {
        id: true, title: true, hostname: true, tags: true, createdAt: true, detectionStats: true,
        case: { select: { id: true, title: true, caseSeq: true } },
        _count: { select: { findings: true } },
      },
    }),
    // Recent reports — org-scoped
    prisma.report.findMany({
      where: reportScope,
      orderBy: { createdAt: "desc" },
      take: 5,
      select: {
        id: true, type: true, format: true, status: true, createdAt: true,
        investigation: { select: { id: true, title: true } },
        case: { select: { id: true, title: true, caseSeq: true } },
        generatedBy: { select: { name: true, email: true } },
      },
    }),
    // Activity feed — scoped to the sole org
    prisma.activityLog.findMany({
      where: activityWhere,
      orderBy: { createdAt: "desc" },
      take: 20,
      include: { user: { select: { name: true, email: true } } },
    }),
    // Stats — org-scoped
    prisma.investigation.count({ where: activeInvScope }),
    prisma.finding.count({ where: { ...findingInvScope, workflowStatus: "new" } }),
    prisma.finding.count({ where: { ...findingInvScope, workflowStatus: "escalated" } }),
    // Trend pairs
    prisma.investigation.count({ where: { ...orgScope, createdAt: { gte: last24hStart } } }),
    prisma.investigation.count({ where: { ...orgScope, createdAt: { gte: prior24hStart, lt: last24hStart } } }),
    prisma.finding.count({ where: { ...findingInvScope, createdAt: { gte: last24hStart } } }),
    prisma.finding.count({ where: { ...findingInvScope, createdAt: { gte: prior24hStart, lt: last24hStart } } }),
    prisma.activityLog.findMany({
      where: {
        action: "status_change", entityType: "finding", createdAt: { gte: prior24hStart },
        investigation: orgScope,
      },
      select: { createdAt: true, metadata: true },
    }),
  ]);

  let escalatedLast24h = 0, escalatedPrior24h = 0;
  for (const log of escalationEvents) {
    if ((log.metadata as Record<string, unknown> | null)?.to !== "escalated") continue;
    if (log.createdAt >= last24hStart) escalatedLast24h++;
    else escalatedPrior24h++;
  }

  return (
    <main className="min-h-screen">
      {/* Header */}
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-zinc-500">
            <TrendingUp className="h-3.5 w-3.5" />
            Analyst Dashboard
          </div>
          <h1 className="mt-2 text-2xl font-semibold text-zinc-50">
            Welcome back, {actor.name ?? actor.email}
            {orgIds.length === 0 && (
              <span className="ml-3 text-sm font-normal text-yellow-500">(No organization assigned)</span>
            )}
          </h1>
        </div>
      </section>

      <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8 space-y-8">

        {/* Stat tiles — each links to a pre-filtered view of exactly what it counts */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          {[
            { label: "My Investigations", value: totalInvestigations, icon: Shield, color: "text-teal-400", href: "/investigations", trend: <Trend current={invLast24h} previous={invPrior24h} /> },
            { label: "New Findings",   value: newFindings,       icon: AlertTriangle, color: "text-yellow-400", href: "/findings?status=new", trend: <Trend current={findingsLast24h} previous={findingsPrior24h} /> },
            { label: "Escalated",      value: escalatedFindings, icon: ShieldAlert,   color: "text-orange-400", href: "/findings?status=escalated", trend: <Trend current={escalatedLast24h} previous={escalatedPrior24h} /> },
          ].map(({ label, value, icon: Icon, color, href, trend }) => (
            <Link key={label} href={href} className="block rounded-lg border border-zinc-800 bg-zinc-900 p-4 hover:border-zinc-600 transition-colors">
              <div className={`flex items-center gap-2 text-xs uppercase tracking-wide ${color}`}>
                <Icon className="h-3.5 w-3.5" />
                {label}
              </div>
              <p className={`mt-2 text-3xl font-bold ${color}`}>{value.toLocaleString()}</p>
              <div className="mt-1 h-4">{trend}</div>
            </Link>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2 items-start">
          {/* Column 1 — personal/actionable */}
          <div className="space-y-8">
            {/* My Assigned Findings */}
            <section>
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
                My Assigned Findings
                <span className="ml-2 font-normal normal-case text-zinc-600">(personal)</span>
              </h2>
              {myFindings.length === 0 ? (
                <div className="rounded-lg border border-dashed border-zinc-800 p-4 text-center">
                  <p className="text-sm text-zinc-500 mb-3">No findings assigned to you.</p>
                  <Link
                    href="/findings?assignee=unassigned&severity=Important,Notable"
                    className="inline-flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-500"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" /> View Unassigned Critical Findings
                  </Link>
                </div>
              ) : (
                <div className="space-y-2">
                  {myFindings.map((f) => (
                    <Link
                      key={f.id}
                      href={`/investigations/${f.investigation.id}`}
                      className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 hover:border-zinc-700"
                    >
                      <span className={`text-xs font-semibold ${SEVERITY_COLOR[normalizeSeverity(f.severity)]}`}>
                        {normalizeSeverity(f.severity)}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-zinc-200">{f.findingType}</p>
                        <p className="truncate text-xs text-zinc-500">
                          {f.investigation.title}
                          {f.investigation.case && (
                            <span className="ml-1.5 font-mono text-zinc-600">{formatCaseNumber(f.investigation.case.caseSeq)}</span>
                          )}
                        </p>
                      </div>
                      <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${STATUS_COLOR[f.workflowStatus] ?? "bg-zinc-700 text-zinc-300"}`}>
                        {STATUS_LABEL[f.workflowStatus] ?? f.workflowStatus}
                      </span>
                    </Link>
                  ))}
                </div>
              )}
            </section>

            {/* Recent Reports */}
            <section>
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
                Recent Reports
              </h2>
              {recentReports.length === 0 ? (
                <p className="text-sm text-zinc-500">No reports generated yet.</p>
              ) : (
                <div className="space-y-2">
                  {recentReports.map((r) => (
                    <div key={r.id} className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2">
                      <FileText className="h-4 w-4 shrink-0 text-zinc-500" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-zinc-200">
                          {r.type} · {r.format.toUpperCase()} — {r.case ? `${formatCaseNumber(r.case.caseSeq)} ${r.case.title}` : r.investigation?.title ?? "—"}
                        </p>
                        <p className="text-xs text-zinc-500">{r.generatedBy.name ?? r.generatedBy.email}</p>
                      </div>
                      <span className={`h-2 w-2 rounded-full shrink-0 ${REPORT_STATUS_DOT[r.status] ?? "bg-zinc-600"}`} title={r.status} />
                      {r.status === "ready" && (
                        <Link
                          href={`/api/reports/${r.id}/download`}
                          title="Download"
                          className="shrink-0 text-zinc-500 hover:text-teal-300"
                          prefetch={false}
                        >
                          <Download className="h-4 w-4" />
                        </Link>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>

          {/* Column 2 — situational/intel */}
          <div className="space-y-8">
            {/* High Risk Investigations */}
            <section>
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
                High Risk Investigations
              </h2>
              <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
                {highRiskInvestigations.map((inv) => {
                  const ds = inv.detectionStats as Record<string, number> | null;
                  const borderColor = (ds?.critical_detections ?? 0) > 0 ? "border-l-red-500" : (ds?.high_detections ?? 0) > 0 ? "border-l-orange-500" : "border-l-zinc-700";
                  return (
                    <Link
                      key={inv.id}
                      href={`/investigations/${inv.id}`}
                      className={`flex items-center gap-3 rounded-lg border border-zinc-800 border-l-4 ${borderColor} bg-zinc-900 px-3 py-2 hover:border-zinc-700`}
                    >
                      <ShieldAlert className="h-4 w-4 shrink-0 text-orange-400" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-zinc-200">{inv.title}</p>
                        <p className="flex items-center gap-1.5 text-xs text-zinc-500">
                          <span className="font-mono shrink-0">{inv.hostname ?? "Unknown host"}</span>
                          <span className="shrink-0">· {inv._count.findings} findings</span>
                          {inv.case && (
                            <span className="shrink-0 font-mono text-zinc-600">· {formatCaseNumber(inv.case.caseSeq)}</span>
                          )}
                        </p>
                      </div>
                      <span className="shrink-0 text-xs text-zinc-500">{new Date(inv.createdAt).toLocaleDateString()}</span>
                    </Link>
                  );
                })}
              </div>
            </section>
          </div>
        </div>

        {/* Activity Feed */}
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
            Organization Activity
          </h2>
          <div className="max-h-[480px] overflow-y-auto divide-y divide-zinc-800 rounded-lg border border-zinc-800 bg-zinc-900">
            {recentActivity.length === 0 ? (
              <p className="px-4 py-3 text-sm text-zinc-500">No activity yet.</p>
            ) : (
              recentActivity.map((log) => (
                <div key={log.id} className="flex items-start gap-3 px-4 py-3">
                  <Activity className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-600" />
                  <div className="min-w-0 flex-1">
                    <span className="text-sm text-zinc-300">
                      <span className="font-bold text-zinc-100">{log.user.name ?? log.user.email}</span>
                      {" "}
                      <span className="font-semibold text-zinc-300">{formatAction(log.action)}</span>
                      {" "}
                      <span className="font-mono text-xs text-zinc-500">{log.entityType}/{log.entityId.slice(0, 8)}</span>
                    </span>
                  </div>
                  <RelativeTime date={log.createdAt} className="shrink-0 text-xs text-zinc-600" />
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </main>
  );
}

function formatAction(action: string): string {
  return action.replace(/_/g, " ");
}
