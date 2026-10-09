import { ChevronRight, Clock3, Monitor, Server, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/utils";

type OsInfo = { platform?: string; version?: string } | null;
type DetectionStats = { total_detections?: number; ioc_detections?: number } | null;

type InvestigationListItem = {
  id: string;
  title: string;
  hostname: string | null;
  username: string | null;
  status: string;
  findingCount: number;
  tags: string[];
  osInfo: OsInfo;
  detectionStats: DetectionStats;
  createdAt: Date;
  uploadedBy: {
    email: string;
    name: string | null;
  };
  _count?: {
    findings: number;
  };
};

type InvestigationListProps = {
  investigations: InvestigationListItem[];
};

export function InvestigationList({ investigations }: InvestigationListProps) {
  if (investigations.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center">
          <p className="text-sm text-zinc-400">No investigations uploaded yet.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {investigations.map((inv) => {
        const os = inv.osInfo as OsInfo;
        const stats = inv.detectionStats as DetectionStats;
        const totalDetections = stats?.total_detections ?? 0;
        const iocDetections = stats?.ioc_detections ?? 0;
        const findingCount = inv._count?.findings ?? inv.findingCount;

        return (
          <Link
            key={inv.id}
            href={`/investigations/${inv.id}`}
            className="group block rounded-lg border border-zinc-800 bg-zinc-950/55 p-4 transition hover:border-teal-400/40 hover:bg-zinc-900/45"
          >
            <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
              {/* ── Left: title + meta ── */}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className="border-zinc-700 bg-zinc-900 text-zinc-300">{inv.status}</Badge>
                  <span className="text-xs text-zinc-500">
                    {inv.uploadedBy.name ?? inv.uploadedBy.email}
                  </span>
                </div>

                <h2 className="mt-2 truncate text-lg font-semibold text-zinc-50">{inv.title}</h2>

                <div className="mt-2 flex flex-wrap items-center gap-4 text-sm text-zinc-500">
                  <span className="inline-flex items-center gap-1.5">
                    <Server className="h-4 w-4" />
                    {inv.hostname ?? "Unknown host"}
                  </span>
                  {os?.platform && (
                    <span className="inline-flex items-center gap-1.5">
                      <Monitor className="h-4 w-4" />
                      {os.version ?? os.platform}
                    </span>
                  )}
                  <span className="inline-flex items-center gap-1.5">
                    <Clock3 className="h-4 w-4" />
                    {formatDateTime(inv.createdAt)}
                  </span>
                </div>

                {/* Investigation tags */}
                {inv.tags.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {inv.tags.map((tag) => (
                      <span
                        key={tag}
                        className="inline-flex items-center rounded-full border border-teal-400/25 bg-teal-400/8 px-2 py-0.5 text-[11px] font-medium text-teal-300"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* ── Right: stats ── */}
              <div className="flex shrink-0 items-center justify-between gap-5 md:justify-end">
                <div className="flex gap-4">
                  {totalDetections > 0 && (
                    <div className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                        <p className="font-mono text-lg font-semibold text-rose-300">
                          {totalDetections.toLocaleString()}
                        </p>
                      </div>
                      <p className="text-xs uppercase tracking-normal text-zinc-500">
                        {iocDetections > 0 ? `${iocDetections} IOC` : "Detections"}
                      </p>
                    </div>
                  )}
                  <div className="text-right">
                    <p className="font-mono text-lg font-semibold text-zinc-100">
                      {findingCount.toLocaleString()}
                    </p>
                    <p className="text-xs uppercase tracking-normal text-zinc-500">Findings</p>
                  </div>
                </div>
                <ChevronRight className="h-5 w-5 text-zinc-600 transition group-hover:text-teal-300" />
              </div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}
