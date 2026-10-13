import { Database, Upload } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { DatabaseError } from "@/components/investigation/database-error";
import { InvestigationFilter } from "@/components/investigation/investigation-filter";
import { Card, CardContent } from "@/components/ui/card";
import { getInvestigations } from "@/lib/db/investigations";
import { getServerSession } from "@/lib/auth/session";
import { prisma } from "@/lib/db/prisma";

export const dynamic = "force-dynamic";

export default async function InvestigationsPage() {
  const session = await getServerSession();
  if (!session?.user) redirect("/login");

  const { id: userId } = session.user;

  // Build org scope — Core has exactly one org. Returns nothing if the
  // user somehow has no org yet (prevents leaking data).
  const memberships = await prisma.organizationMember.findMany({
    where: { userId },
    select: { organizationId: true },
  });
  const orgIds = memberships.map((m) => m.organizationId);
  const orgWhere: { organizationId?: { in: string[] } } = { organizationId: { in: orgIds } };

  let investigations: Awaited<ReturnType<typeof getInvestigations>> = [];
  let databaseError: string | null = null;

  try {
    investigations = await getInvestigations(orgWhere);
  } catch (error) {
    databaseError = error instanceof Error ? error.message : "Unable to query investigations.";
  }

  return (
    <main className="min-h-screen">
      <section className="border-b border-zinc-800 bg-zinc-950/40">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-8 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm text-teal-200">
                <Database className="h-4 w-4" />
                Forensicator Enterprise
              </div>
              <h1 className="mt-3 text-3xl font-semibold tracking-normal text-zinc-50">
                Investigations
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
                Uploaded collector archives are stored as investigations, with every finding preserved as searchable JSON.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/investigations/upload"
                className="flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
              >
                <Upload className="h-4 w-4" />
                Upload Investigation
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        {databaseError ? (
          <DatabaseError message={databaseError} />
        ) : (
          <div className="grid gap-5">
            <Card>
              <CardContent className="grid gap-4 sm:grid-cols-3">
                <Metric label="Investigations" value={investigations.length.toLocaleString()} />
                <Metric
                  label="Findings"
                  value={investigations
                    .reduce((total, investigation) => total + (investigation._count?.findings ?? 0), 0)
                    .toLocaleString()}
                />
                <Metric
                  label="Hosts"
                  value={new Set(investigations.map((investigation) => investigation.hostname).filter(Boolean)).size.toLocaleString()}
                />
              </CardContent>
            </Card>
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <InvestigationFilter investigations={investigations as any} />
          </div>
        )}
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-normal text-zinc-500">{label}</p>
      <p className="mt-1 font-mono text-2xl font-semibold text-zinc-100">{value}</p>
    </div>
  );
}
