import { ArrowLeft, Activity } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { FindingDetail } from "@/components/findings/finding-detail";
import { KeyValueGrid } from "@/components/findings/key-value-grid";
import { DatabaseError } from "@/components/investigation/database-error";
import { FindingsSidebar } from "@/components/investigation/findings-sidebar";
import { StatStrip, SeverityAndCategoryPanel, type SeverityCounts } from "@/components/investigation/investigation-dashboard";
import { InvestigationHeader } from "@/components/investigation/investigation-header";
import { InvestigationOverview } from "@/components/investigation/investigation-overview";
import { InvestigationTabs } from "@/components/investigation/investigation-tabs";
import { Badge } from "@/components/ui/badge";
import { Collapsible } from "@/components/ui/collapsible";
import { NotesPanel } from "@/components/ui/notes-panel";
import { getInvestigation } from "@/lib/db/investigations";
import { coerceFindingJson } from "@/lib/schemas/finding";
import { normalizeSeverity, severityRank } from "@/lib/severity";
import { prisma } from "@/lib/db/prisma";

export const dynamic = "force-dynamic";

type InvestigationPageProps = {
  params: Promise<{
    id: string;
  }>;
  searchParams?: Promise<{
    finding?: string;
    category?: string;
  }>;
};

const SOURCE_CATEGORIES_IOC = new Set(["ioc", "hash"]);
const SOURCE_CATEGORIES_SIGMA = new Set(["sigma", "detections"]);

export default async function InvestigationPage(props: InvestigationPageProps) {
  const searchParams = await props.searchParams;
  const params = await props.params;
  let investigation: Awaited<ReturnType<typeof getInvestigation>>;

  try {
    investigation = await getInvestigation(params.id);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to query investigation.";
    return (
      <main className="mx-auto min-h-screen w-full max-w-[1800px] px-4 py-6 sm:px-6 lg:px-8">
        <DatabaseError message={message} />
      </main>
    );
  }

  if (!investigation) {
    notFound();
  }

  const [parsedFindingsAll, investigationNotes] = await Promise.all([
    Promise.resolve(
      investigation.findings
        .flatMap((row) => {
          const finding = coerceFindingJson(row.data);
          return finding ? [{ row, finding }] : [];
        })
        .sort((left, right) => {
          const severityDelta = severityRank(right.row.severity) - severityRank(left.row.severity);
          return severityDelta || (right.row.riskScore ?? 0) - (left.row.riskScore ?? 0);
        })
    ),
    prisma.note.findMany({
      where: { investigationId: params.id },
      orderBy: { createdAt: "desc" },
      include: { author: { select: { id: true, name: true, email: true } } },
    }),
  ]);

  // ── Dashboard stats — always computed from the FULL, unfiltered finding set
  // (the raw persisted rows, not just the ones that parsed into renderable
  // JSON), so counts stay authoritative regardless of category filtering below.
  const severityCounts: SeverityCounts = { Important: 0, Notable: 0, Interesting: 0, Informational: 0 };
  const categoryTally = new Map<string, number>();
  let iocCount = 0;
  let sigmaCount = 0;
  let evidenceCount = 0;

  for (const row of investigation.findings) {
    severityCounts[normalizeSeverity(row.severity)]++;

    categoryTally.set(row.category, (categoryTally.get(row.category) ?? 0) + 1);

    const sourceCategory = (row.sourceCategory ?? "").toLowerCase();
    if (SOURCE_CATEGORIES_IOC.has(sourceCategory)) iocCount++;
    if (SOURCE_CATEGORIES_SIGMA.has(sourceCategory)) sigmaCount++;
    evidenceCount += row.evidenceCount;
  }

  const categories = Array.from(categoryTally.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  const activeCategory = searchParams?.category ?? null;
  const parsedFindings = activeCategory
    ? parsedFindingsAll.filter(({ row }) => row.category === activeCategory)
    : parsedFindingsAll;

  const selectedFindingId = searchParams?.finding ?? parsedFindings[0]?.row.id ?? null;
  const selected = parsedFindings.find((item) => item.row.id === selectedFindingId) ?? parsedFindings[0] ?? null;

  // ── Context fields sourced from the raw collector metadata blob — these
  // never got promoted to dedicated columns, but they're real chain-of-custody
  // detail (when collection actually ran, who ran it, what collector version).
  const rawMetadata = (investigation.metadata ?? {}) as Record<string, unknown>;
  // Everything linked to a closed case is read-only, and so is an archived
  // investigation with no case (src/lib/cases/case-lock.ts).
  const caseClosed = investigation.case?.status === "closed" || !!investigation.archivedAt;
  const collectionStartTime = typeof rawMetadata.collection_start_time === "string" ? rawMetadata.collection_start_time : null;
  const operator = typeof rawMetadata.operator === "string" ? rawMetadata.operator : null;
  const collectorVersion = typeof rawMetadata.collector_version === "string" ? rawMetadata.collector_version : null;

  return (
    <main className="min-h-screen">
      <InvestigationHeader
        title={investigation.title}
        hostname={investigation.hostname}
        status={investigation.status}
        findingCount={investigation.findingCount || investigation.findings.length}
        createdAt={investigation.createdAt}
        uploadedBy={investigation.uploadedBy}
        caseRef={investigation.case}
        investigationId={investigation.id}
        archivedAt={investigation.archivedAt}
      />

      <div className="mx-auto w-full max-w-[1800px] px-4 py-6 sm:px-6 lg:px-8">
        <Link href="/investigations" className="mb-5 inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-teal-200">
          <ArrowLeft className="h-4 w-4" />
          Investigations
        </Link>

        {/* ── Tab navigation ── */}
        <InvestigationTabs investigationId={investigation.id} />

        {/* ── Always-visible compact stat strip ── */}
        <StatStrip
          totalFindings={investigation.findings.length}
          severityCounts={severityCounts}
          iocCount={iocCount}
          sigmaCount={sigmaCount}
          evidenceCount={evidenceCount}
        />

        {/* ── Everything secondary to findings/evidence lives behind this toggle ── */}
        <Collapsible label="Case Details">
          <div className="space-y-5">
            <SeverityAndCategoryPanel
              investigationId={investigation.id}
              totalFindings={investigation.findings.length}
              severityCounts={severityCounts}
              categories={categories}
              activeCategory={activeCategory}
            />
            <InvestigationOverview
              username={(investigation as { username?: string | null }).username ?? null}
              investigationSourceId={
                (investigation as { investigationSourceId?: string | null }).investigationSourceId ?? null
              }
              osInfo={
                (investigation as { osInfo?: unknown }).osInfo as {
                  platform?: string;
                  version?: string;
                  build?: string;
                } | null
              }
              tags={((investigation as { tags?: string[] }).tags) ?? []}
              archiveSha256={(investigation as { archiveSha256?: string | null }).archiveSha256 ?? null}
              collectionStartTime={collectionStartTime}
              operator={operator}
              collectorVersion={collectorVersion}
            />
          </div>
        </Collapsible>

        {/* ── Findings — filtered by category chip above, if any ── */}
        {parsedFindings.length === 0 ? (
          <div className="mb-6 rounded-lg border border-zinc-800 bg-zinc-950/55 p-8 text-center">
            <Badge className="border-amber-400/40 bg-amber-400/10 text-amber-100">
              {activeCategory ? "No findings in this category" : "No renderable findings"}
            </Badge>
            <p className="mt-3 text-sm text-zinc-400">
              {activeCategory
                ? "Try a different category, or clear the filter above."
                : "Stored finding JSON could not be validated for rendering."}
            </p>
          </div>
        ) : (
          <div className="mb-6 grid gap-5 lg:grid-cols-[24rem_minmax(0,1fr)]">
            <FindingsSidebar
              investigationId={investigation.id}
              selectedFindingId={selected?.row.id ?? null}
              findings={parsedFindings.map(({ row }) => ({
                id: row.id,
                findingId: row.findingId,
                findingType: row.findingType,
                category: row.category,
                severity: row.severity,
                riskScore: row.riskScore,
                evidenceCount: row.evidenceCount
              }))}
            />
            {selected ? (
              <FindingDetail
                key={selected.row.id}
                finding={selected.finding}
                findingDbId={selected.row.id}
                assigneeId={(selected.row as { assigneeId?: string | null }).assigneeId ?? null}
                workflowStatus={(selected.row as { workflowStatus?: string }).workflowStatus ?? "new"}
                aiStatus={(selected.row as { aiStatus?: string }).aiStatus ?? "not_queued"}
                aiSummary={(selected.row as { aiSummary?: string | null }).aiSummary ?? null}
                aiConfidence={(selected.row as { aiConfidence?: number | null }).aiConfidence ?? null}
                aiModel={(selected.row as { aiModel?: string | null }).aiModel ?? null}
                readOnly={caseClosed}
              />
            ) : null}
          </div>
        )}

        {/* ── Analyst notes + Metadata — side by side ── */}
        <div className="mb-6 grid gap-5 lg:grid-cols-[minmax(0,1fr)_26rem]">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <NotesPanel
              initialNotes={investigationNotes.map((n) => ({
                id: n.id,
                content: n.content,
                createdAt: n.createdAt.toISOString(),
                author: { name: n.author.name, email: n.author.email },
              }))}
              investigationId={investigation.id}
              readOnly={caseClosed}
            />
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/55">
            <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-3 text-sm font-semibold text-zinc-100">
              <span className="text-teal-300">
                <Activity className="h-4 w-4" />
              </span>
              Metadata
            </div>
            <div className="p-4">
              <KeyValueGrid
                data={{
                  collected_by: operator,
                  collection_time: collectionStartTime,
                  collector_version: collectorVersion,
                }}
              />
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
