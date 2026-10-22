import Link from "next/link";
import { Lock } from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { ArchivedPill } from "@/components/cases/archive-button";

export type CaseRef = { id: string; caseSeq: number; title: string; status: string; archivedAt?: string | Date | null };

/**
 * The case an investigation or upload belongs to, with a "Case Closed" badge
 * when that case is closed — everything linked to a closed case is
 * read-only (see src/lib/cases/case-lock.ts).
 */
export function CaseBadge({ kase, showTitle = false }: { kase: CaseRef | null; showTitle?: boolean }) {
  if (!kase) return null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <Link href={`/cases/${kase.id}`} className="font-mono text-blue-400 hover:text-blue-300" title={kase.title}>
        {formatCaseNumber(kase.caseSeq)}{showTitle ? ` · ${kase.title}` : ""}
      </Link>
      {kase.status === "closed" && <CaseClosedPill />}
      {kase.archivedAt && <ArchivedPill />}
    </span>
  );
}

export function CaseClosedPill() {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-amber-600/50 bg-amber-900/30 px-2 py-0.5 text-xs font-medium text-amber-300"
      title="This case is closed — everything linked to it is read-only until it's reopened."
    >
      <Lock className="h-3 w-3" /> Case Closed
    </span>
  );
}
