import {
  CalendarClock,
  Cpu,
  GitBranch,
  Hash,
  Monitor,
  ShieldCheck,
  User,
  UserCog,
} from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { CopyButton } from "@/components/ui/copy-button";
import { formatDateTime } from "@/lib/utils";

// ── types ────────────────────────────────────────────────────────────────────

type OsInfo = {
  platform?: string;
  version?: string;
  build?: string;
} | null;

export type InvestigationOverviewProps = {
  username: string | null;
  investigationSourceId: string | null;
  osInfo: OsInfo;
  tags: string[];
  archiveSha256: string | null;
  /** From metadata.collection_start_time — when the collector ran on the endpoint, distinct from when it was uploaded here. */
  collectionStartTime: string | null;
  operator: string | null;
  collectorVersion: string | null;
};

// ── component ────────────────────────────────────────────────────────────────

export function InvestigationOverview({
  username,
  investigationSourceId,
  osInfo,
  tags,
  archiveSha256,
  collectionStartTime,
  operator,
  collectorVersion,
}: InvestigationOverviewProps) {
  const os = osInfo as OsInfo;

  return (
    <Card className="mb-6">
      <CardHeader className="pb-3">
        <p className="text-sm font-medium uppercase tracking-wide text-zinc-500">Investigation Context</p>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <MetaField icon={<User className="h-4 w-4" />} label="Username" value={username ?? "Unknown"} />
          {os?.version && (
            <MetaField
              icon={<Monitor className="h-4 w-4" />}
              label="Operating System"
              value={os.build ? `${os.version} (Build ${os.build})` : os.version}
            />
          )}
          {os?.platform && !os.version && (
            <MetaField icon={<Cpu className="h-4 w-4" />} label="Platform" value={os.platform} />
          )}
          {collectionStartTime && (
            <MetaField
              icon={<CalendarClock className="h-4 w-4" />}
              label="Collection Time"
              value={formatDateTime(collectionStartTime)}
            />
          )}
          {investigationSourceId && (
            <MetaField
              icon={<Hash className="h-4 w-4" />}
              label="Investigation ID"
              value={investigationSourceId}
              mono
            />
          )}
          {operator && (
            <MetaField icon={<UserCog className="h-4 w-4" />} label="Operator" value={operator} />
          )}
          {collectorVersion && (
            <MetaField icon={<GitBranch className="h-4 w-4" />} label="Collector Version" value={collectorVersion} />
          )}
        </div>

        {/* Archive integrity — full width, not truncated, since the whole
            64-char hash needs to be visible for manual comparison against
            the hash the collector reported at collection time. */}
        {archiveSha256 && (
          <div className="mt-3 rounded-md border border-zinc-800 bg-zinc-950/50 p-3">
            <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-zinc-500">
              <ShieldCheck className="h-4 w-4" />
              Archive SHA-256
              <span className="ml-auto">
                <CopyButton text={archiveSha256} />
              </span>
            </div>
            <p className="mt-1 break-all font-mono text-sm text-zinc-200">{archiveSha256}</p>
          </div>
        )}

        {/* Tags */}
        {tags.length > 0 && (
          <div className="mt-5">
            <p className="mb-2 text-xs uppercase tracking-wide text-zinc-500">
              Investigation Tags
            </p>
            <div className="flex flex-wrap gap-1.5">
              {tags.map((tag) => (
                <InvestigationTag key={tag} tag={tag} />
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── sub-components ────────────────────────────────────────────────────────────

function MetaField({
  icon,
  label,
  value,
  mono = false,
}: {
  icon?: ReactNode;
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950/50 p-3">
      <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-zinc-500">
        {icon}
        {label}
      </div>
      <p className={`mt-1 truncate text-sm text-zinc-200 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

type TagColor = "teal" | "rose" | "amber" | "purple" | "sky";

const TAG_COLOR_MAP: Record<string, TagColor> = {
  "lateral-movement": "sky",
  "credential-access": "rose",
  persistence: "amber",
  ransomware: "rose",
  "defense-evasion": "purple",
  "privilege-escalation": "amber",
  "data-exfiltration": "rose",
  "insider-threat": "purple",
  "usb-activity": "teal",
  malware: "rose",
  "live-response": "teal",
  "network-recon": "sky",
};

const TAG_CLASSES: Record<TagColor, string> = {
  teal: "border-teal-400/30 bg-teal-400/10 text-teal-300",
  rose: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  amber: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  purple: "border-purple-400/30 bg-purple-400/10 text-purple-300",
  sky: "border-sky-400/30 bg-sky-400/10 text-sky-300",
};

function InvestigationTag({ tag }: { tag: string }) {
  const color: TagColor = TAG_COLOR_MAP[tag] ?? "teal";
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${TAG_CLASSES[color]}`}
    >
      {tag}
    </span>
  );
}
