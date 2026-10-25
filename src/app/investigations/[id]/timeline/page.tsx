import { ArrowLeft, Clock } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { TimelineExplorer } from "@/components/investigation/timeline-explorer";
import { BackfillButton } from "@/components/artifacts/backfill-button";
import { prisma } from "@/lib/db/prisma";
import { getPageActor, orgWhere } from "@/lib/auth/api-guard";
import { canAccessOrg, investigationOrgWhere } from "@/lib/auth/org-access";

export const dynamic = "force-dynamic";

type Props = { params: Promise<{ id: string }> };

export default async function TimelinePage(props: Props) {
  const params = await props.params;
  const investigation = await prisma.investigation.findUnique({
    where: { id: params.id },
    select: { id: true, title: true, hostname: true, organizationId: true },
  });

  const viewer = await getPageActor();
  if (!investigation || !viewer || !canAccessOrg(viewer, investigation.organizationId)) notFound();

  const eventCount = await prisma.timelineEvent.count({
    where: { investigationId: params.id },
  });

  return (
    <main className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto w-full max-w-5xl px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-zinc-500">
            <Clock className="h-3.5 w-3.5" />
            Timeline
          </div>
          <h1 className="mt-2 text-2xl font-semibold text-zinc-50">{investigation.title}</h1>
          <p className="mt-1 text-sm text-zinc-400">
            {investigation.hostname ?? "Unknown host"} · {eventCount.toLocaleString()} timeline event
            {eventCount !== 1 ? "s" : ""}
          </p>
        </div>
      </section>

      <div className="mx-auto w-full max-w-5xl px-4 py-6 sm:px-6 lg:px-8">
        <Link
          href={`/investigations/${params.id}`}
          className="mb-5 inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-teal-200"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to investigation
        </Link>

        {eventCount === 0 ? (
          <BackfillButton investigationId={params.id} />
        ) : (
          <Suspense fallback={<div className="py-12 text-center text-sm text-zinc-500">Loading timeline…</div>}>
            <TimelineExplorer investigationId={params.id} />
          </Suspense>
        )}
      </div>
    </main>
  );
}
