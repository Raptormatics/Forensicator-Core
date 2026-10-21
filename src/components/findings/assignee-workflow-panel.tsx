"use client";
/**
 * AssigneeWorkflowPanel
 * Client component rendered inside the FindingDetail aside.
 * Lets analysts update a finding's triage workflow status, and (via the
 * shared AssigneePanel) assign the finding itself to any org user — all
 * without a page reload. Finding assignment is a separate, per-finding
 * triage concept from Case assignment (see AssigneePanel's doc comment).
 */
import { useEffect, useState, useTransition } from "react";
import { Loader2 } from "lucide-react";
import { AssigneePanel } from "@/components/shared/assignee-panel";

type WorkflowStatus =
  | "new"
  | "under_review"
  | "confirmed"
  | "false_positive"
  | "escalated"
  | "resolved";

const STATUS_OPTIONS: { value: WorkflowStatus; label: string; color: string }[] = [
  { value: "new",           label: "New",           color: "border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-zinc-500" },
  { value: "under_review",  label: "Under Review",  color: "border-blue-400/30 bg-blue-400/10 text-blue-200 hover:border-blue-400/60" },
  { value: "confirmed",     label: "Confirmed",     color: "border-red-400/40 bg-red-400/10 text-red-200 hover:border-red-400/60" },
  { value: "false_positive",label: "False Positive",color: "border-zinc-600 bg-zinc-800 text-zinc-400 hover:border-zinc-500" },
  { value: "escalated",     label: "Escalated",     color: "border-orange-400/40 bg-orange-400/10 text-orange-200 hover:border-orange-400/60" },
  { value: "resolved",      label: "Resolved",      color: "border-teal-400/30 bg-teal-400/10 text-teal-200 hover:border-teal-400/60" },
];

const ACTIVE_EXTRA = "ring-1 ring-offset-1 ring-offset-zinc-950";

interface Props {
  findingId: string;        // DB UUID of the Finding row
  initialAssigneeId: string | null;
  initialStatus: WorkflowStatus;
  /** The finding's case is closed — status and assignee are frozen. */
  readOnly?: boolean;
}

export function AssigneeWorkflowPanel({ findingId, initialAssigneeId, initialStatus, readOnly = false }: Props) {
  const [status, setStatus] = useState<WorkflowStatus>(initialStatus);
  useEffect(() => { setStatus(initialStatus); }, [initialStatus]);
  const [statusPending, startStatusTransition] = useTransition();
  const [statusError, setStatusError] = useState<string | null>(null);

  // ── Status change ──────────────────────────────────────────────────────────
  function handleStatusChange(next: WorkflowStatus) {
    if (next === status) return;
    setStatusError(null);
    startStatusTransition(async () => {
      try {
        const res = await fetch(`/api/findings/${findingId}/status`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: next }),
        });
        if (!res.ok) throw new Error("Failed");
        setStatus(next);
      } catch {
        setStatusError("Could not update status.");
      }
    });
  }

  async function handleAssign(userId: string | null) {
    const res = await fetch(`/api/findings/${findingId}/assign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assigneeId: userId }),
    });
    if (!res.ok) throw new Error("Failed");
  }

  return (
    <div className="space-y-4">
      {/* ── Workflow Status ── */}
      <div>
        <p className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">Status</p>
        <div className="flex flex-wrap gap-1.5">
          {STATUS_OPTIONS.map((opt) => {
            const isActive = status === opt.value;
            return (
              <button
                key={opt.value}
                onClick={() => handleStatusChange(opt.value)}
                disabled={statusPending || readOnly}
                className={[
                  "rounded border px-2.5 py-1 text-xs font-medium transition-all",
                  opt.color,
                  isActive ? ACTIVE_EXTRA : "opacity-70",
                  statusPending && isActive ? "opacity-50" : "",
                ].join(" ")}
              >
                {isActive && statusPending ? (
                  <span className="flex items-center gap-1.5">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    {opt.label}
                  </span>
                ) : (
                  opt.label
                )}
              </button>
            );
          })}
        </div>
        {statusError && <p className="mt-1.5 text-xs text-red-400">{statusError}</p>}
      </div>

      {/* ── Assignee ── */}
      <AssigneePanel
        assigneeId={initialAssigneeId}
        onAssign={handleAssign}
        disabled={readOnly}
        disabledReason="This finding's case is closed — reopen the case to change it."
      />
    </div>
  );
}
