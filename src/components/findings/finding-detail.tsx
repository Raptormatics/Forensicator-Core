"use client";

import { Clock3, Database, Fingerprint, ShieldAlert, UserCheck2 } from "lucide-react";
import type { ReactNode } from "react";
import { EvidenceTable } from "@/components/tables/evidence-table";
import { Badge } from "@/components/ui/badge";
import { KeyValueGrid } from "@/components/findings/key-value-grid";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { AssigneeWorkflowPanel } from "@/components/findings/assignee-workflow-panel";
import { AiAnalysisPanel } from "@/components/findings/ai-analysis-panel";
import { formatDateTime, humanizeKey, jsonValueToDisplay } from "@/lib/utils";
import type { FindingJson } from "@/types/findings";
import type { JsonObject, JsonValue } from "@/types/json";

type FindingDetailProps = {
  finding: FindingJson;
  /** DB UUID of the Finding row — needed for assign / status mutations */
  findingDbId: string;
  /** Current assignee user ID (nullable) */
  assigneeId: string | null;
  /** Current workflow status */
  workflowStatus: string;
  /** Forensicator AI state — from the Finding row's own ai* columns */
  aiStatus: string;
  aiSummary: string | null;
  aiConfidence: number | null;
  aiModel: string | null;
};

export function FindingDetail({ finding, findingDbId, assigneeId, workflowStatus, aiStatus, aiSummary, aiConfidence, aiModel }: FindingDetailProps) {
  const title = stringValue(finding.summary?.title) ?? finding.finding_type;
  const description = stringValue(finding.summary?.description);
  const riskScore = numberValue(finding.risk?.score);
  const riskLevel = stringValue(finding.risk?.level);
  const riskReason = stringValue(finding.risk?.reason);

  return (
    <article className="space-y-5">
      <header className="rounded-lg border border-zinc-800 bg-zinc-950/55 p-5 shadow-analyst">
        <div className="flex flex-col gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity ?? "Informational"} />
              <Badge className="border-zinc-700 bg-zinc-900 text-zinc-300">{finding.category}</Badge>
              <Badge className="border-teal-400/30 bg-teal-400/10 text-teal-100">
                {finding.finding_id}
              </Badge>
            </div>
            <h1 className="mt-3 text-2xl font-semibold tracking-normal text-zinc-50">{title}</h1>
            {description ? <p className="mt-2 max-w-4xl text-sm leading-6 text-zinc-400">{description}</p> : null}
          </div>
          <div className="grid grid-cols-3 gap-2 text-xs text-zinc-400 sm:max-w-md">
            <Metric label="Evidence" value={finding.evidence.length.toLocaleString()} />
            <Metric label="MITRE" value={(finding.mitre?.length ?? 0).toLocaleString()} />
            <Metric label="Timeline" value={(finding.timeline?.length ?? 0).toLocaleString()} />
          </div>
        </div>
      </header>

      {/* ── Primary content — Evidence, Timeline, MITRE — full width, most important first ── */}
      <EvidenceTable rows={finding.evidence} />

      <Panel title="Timeline" icon={<Clock3 className="h-4 w-4" />}>
        <TimelineList timeline={finding.timeline ?? []} />
      </Panel>

      {(finding.mitre?.length ?? 0) > 0 && (
        <Panel title="MITRE" icon={<Fingerprint className="h-4 w-4" />}>
          <MitreList mitre={finding.mitre ?? []} />
        </Panel>
      )}

      {/* ── Secondary — analyst workflow, AI, risk, source — below the forensic content ── */}
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
        <Panel title="Analyst" icon={<UserCheck2 className="h-4 w-4" />}>
          <AssigneeWorkflowPanel
            findingId={findingDbId}
            initialAssigneeId={assigneeId}
            initialStatus={workflowStatus as "new" | "under_review" | "confirmed" | "false_positive" | "escalated" | "resolved"}
          />
        </Panel>

        <AiAnalysisPanel
          findingDbId={findingDbId}
          initialStatus={aiStatus}
          initialSummary={aiSummary}
          initialConfidence={aiConfidence}
          initialModel={aiModel}
          initialAnalysis={asAiAnalysis(finding.ai_analysis)}
        />

        <RiskMeter level={riskLevel ?? finding.severity} score={riskScore} reason={riskReason} />

        {finding.source ? (
          <Panel title="Source" icon={<Database className="h-4 w-4" />}>
            <KeyValueGrid data={finding.source} />
          </Panel>
        ) : null}
      </div>
    </article>
  );
}

function RiskMeter({ level, score, reason }: { level?: string; score?: number; reason?: string }) {
  return (
    <Panel title="Risk" icon={<ShieldAlert className="h-4 w-4" />}>
      <div className="space-y-3">
        <div className="flex items-end justify-between">
          <div>
            <p className="text-xs uppercase tracking-normal text-zinc-500">Level</p>
            <p className="text-lg font-semibold text-zinc-100">{level}</p>
          </div>
          <p className="font-mono text-3xl font-semibold text-teal-200">{score ?? "-"}</p>
        </div>
        {typeof score === "number" ? (
          <div className="h-2 overflow-hidden rounded-full bg-zinc-900">
            <div className="h-full bg-teal-300" style={{ width: `${Math.max(0, Math.min(100, score))}%` }} />
          </div>
        ) : null}
        {reason ? <p className="text-sm leading-6 text-zinc-400">{reason}</p> : null}
      </div>
    </Panel>
  );
}

function Panel({
  title,
  icon,
  children
}: {
  title: string;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-950/55">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-3 text-sm font-semibold text-zinc-100">
        <span className="text-teal-300">{icon}</span>
        {title}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950/55 p-3">
      <p className="text-xs uppercase tracking-normal text-zinc-500">{label}</p>
      <p className="mt-1 font-mono text-lg text-zinc-100">{value}</p>
    </div>
  );
}

function MitreList({ mitre }: { mitre: JsonObject[] }) {
  if (mitre.length === 0) {
    return <p className="text-sm text-zinc-500">No mappings.</p>;
  }

  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
      {mitre.map((mapping, index) => {
        const techniqueId = stringValue(mapping.technique_id) ?? stringValue(mapping.tactic);
        const technique = stringValue(mapping.technique) ?? stringValue(mapping.description);
        const extras = Object.entries(mapping).filter(
          ([key]) => key !== "technique_id" && key !== "technique" && key !== "tactic"
        );

        return (
          <div key={index} className="rounded-md border border-zinc-800 bg-zinc-950/45 p-2.5" title={extras.map(([k, v]) => `${humanizeKey(k)}: ${jsonValueToDisplay(v)}`).join("\n")}>
            <div className="flex flex-wrap items-center gap-1.5">
              {techniqueId ? (
                <Badge className="border-teal-400/30 bg-teal-400/10 text-teal-100">{techniqueId}</Badge>
              ) : null}
              {technique ? <p className="truncate text-xs font-medium text-zinc-100">{technique}</p> : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TimelineList({ timeline }: { timeline: JsonObject[] }) {
  if (timeline.length === 0) {
    return <p className="text-sm text-zinc-500">No timeline entries.</p>;
  }

  return (
    <ol className="space-y-3">
      {timeline.map((item, index) => {
        const timestamp = stringValue(item.timestamp) ?? stringValue(item.time) ?? stringValue(item.created_at);
        const event = stringValue(item.event) ?? stringValue(item.description) ?? JSON.stringify(item);

        return (
          <li key={index} className="grid gap-3 rounded-md border border-zinc-800 bg-zinc-950/45 p-3 sm:grid-cols-[12rem_1fr]">
            <time className="font-mono text-xs text-zinc-500">{formatDateTime(timestamp)}</time>
            <p className="text-sm leading-6 text-zinc-300">{event}</p>
          </li>
        );
      })}
    </ol>
  );
}

function stringValue(value: JsonValue | undefined) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: JsonValue | undefined) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asAiAnalysis(value: object | undefined) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const obj = value as JsonObject;
  return {
    why_flagged: typeof obj.why_flagged === "string" ? obj.why_flagged : null,
    investigation_questions: Array.isArray(obj.investigation_questions)
      ? obj.investigation_questions.filter((v): v is string => typeof v === "string")
      : [],
    recommended_next_steps: Array.isArray(obj.recommended_next_steps)
      ? obj.recommended_next_steps.filter((v): v is string => typeof v === "string")
      : [],
    error: typeof obj.error === "string" ? obj.error : undefined,
  };
}
