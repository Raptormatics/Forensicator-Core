import { CalendarClock, Server, UserCircle } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { CaseBadge, type CaseRef } from "@/components/cases/case-badge";
import { formatDateTime } from "@/lib/utils";

type InvestigationHeaderProps = {
  title: string;
  hostname: string | null;
  status: string;
  findingCount: number;
  createdAt: Date;
  uploadedBy: {
    email: string;
    name: string | null;
  };
  caseRef?: CaseRef | null;
};

export function InvestigationHeader({
  title,
  hostname,
  status,
  findingCount,
  createdAt,
  uploadedBy,
  caseRef = null
}: InvestigationHeaderProps) {
  return (
    <header className="border-b border-zinc-800 bg-zinc-950/40">
      <div className="mx-auto flex w-full max-w-[1800px] flex-col gap-5 px-4 py-6 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className="border-zinc-700 bg-zinc-900 text-zinc-300">{status}</Badge>
              <Badge className="border-teal-400/30 bg-teal-400/10 text-teal-100">
                {findingCount.toLocaleString()} findings
              </Badge>
              {caseRef && <span className="text-xs"><CaseBadge kase={caseRef} showTitle /></span>}
            </div>
            <h1 className="mt-3 text-3xl font-semibold tracking-normal text-zinc-50">{title}</h1>
          </div>
          <div className="grid gap-2 text-sm text-zinc-400 sm:grid-cols-3 lg:min-w-[32rem]">
            <Meta icon={<Server className="h-4 w-4" />} label="Host" value={hostname ?? "Unknown"} />
            <Meta icon={<CalendarClock className="h-4 w-4" />} label="Uploaded" value={formatDateTime(createdAt)} />
            <Meta icon={<UserCircle className="h-4 w-4" />} label="Analyst" value={uploadedBy.name ?? uploadedBy.email} />
          </div>
        </div>
      </div>
    </header>
  );
}

function Meta({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3">
      <div className="flex items-center gap-2 text-xs uppercase tracking-normal text-zinc-500">
        {icon}
        {label}
      </div>
      <p className="mt-1 truncate text-sm text-zinc-200">{value}</p>
    </div>
  );
}
