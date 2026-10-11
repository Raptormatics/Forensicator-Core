"use client";

import { useState } from "react";
import { ShieldOff, ShieldBan, CircleSlash } from "lucide-react";
import { QuickTaskModal, type QuickTaskDetails } from "@/components/intelligence/quick-task-modal";

type CaseOption = { id: string; title: string; caseSeq: number };

type Props = {
  value: string;
  initialBlocklisted: boolean;
  hostnames: string[];
  findingIds: string[];
  cases: CaseOption[];
};

export function IocActionBar({ value, initialBlocklisted, hostnames, findingIds, cases }: Props) {
  const [blocklisted, setBlocklisted] = useState(initialBlocklisted);
  const [busy, setBusy] = useState<"blocklist" | "isolate" | "falsePositive" | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [modal, setModal] = useState<"blocklist" | "isolate" | null>(null);

  async function createCaseTask(caseId: string, details: Omit<QuickTaskDetails, "caseId">) {
    const res = await fetch(`/api/cases/${caseId}/tasks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        title: details.title,
        notes: details.notes || undefined,
        priority: details.priority,
        ...(details.dueAt ? { dueAt: details.dueAt } : {}),
        ...(details.ownerId ? { ownerId: details.ownerId } : {}),
      }),
    });
    if (!res.ok) throw new Error("task_create_failed");
  }

  function removeFromBlocklist() {
    setBusy("blocklist");
    setMsg(null);
    fetch(`/api/ioc/${encodeURIComponent(value)}`, {
      method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ blocklisted: false }),
    })
      .then((res) => { if (res.ok) { setBlocklisted(false); setMsg("Removed from blocklist recommendation."); } })
      .finally(() => setBusy(null));
  }

  async function submitBlocklistTask(details: QuickTaskDetails) {
    setBusy("blocklist");
    setMsg(null);
    try {
      await Promise.all([
        fetch(`/api/ioc/${encodeURIComponent(value)}`, {
          method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ blocklisted: true }),
        }),
        createCaseTask(details.caseId, details),
      ]);
      setBlocklisted(true);
      setModal(null);
      setMsg("Marked for blocklisting and added a task to the case.");
    } finally {
      setBusy(null);
    }
  }

  async function submitIsolateTask(details: QuickTaskDetails) {
    setBusy("isolate");
    setMsg(null);
    try {
      await Promise.all([
        ...hostnames.map((h) =>
          fetch(`/api/hosts/${encodeURIComponent(h)}`, {
            method: "PATCH", headers: { "content-type": "application/json" },
            body: JSON.stringify({ isolationStatus: "quarantined", isolationNote: `Quarantined from IOC ${value}` }),
          })
        ),
        createCaseTask(details.caseId, details),
      ]);
      setModal(null);
      setMsg(`Marked ${hostnames.length} host${hostnames.length !== 1 ? "s" : ""} quarantined and added a task to the case.`);
    } finally {
      setBusy(null);
    }
  }

  async function markFalsePositive() {
    setBusy("falsePositive");
    setMsg(null);
    try {
      await Promise.all(findingIds.map((id) =>
        fetch(`/api/findings/${id}/status`, {
          method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status: "false_positive" }),
        })
      ));
      setMsg(`Marked ${findingIds.length} linked finding${findingIds.length !== 1 ? "s" : ""} as false positive.`);
    } finally {
      setBusy(null);
    }
  }

  const noCaseLinked = cases.length === 0;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        onClick={() => (blocklisted ? removeFromBlocklist() : setModal("blocklist"))}
        disabled={busy !== null || (!blocklisted && noCaseLinked)}
        title={
          !blocklisted && noCaseLinked
            ? "No case is linked to this indicator's investigation — a task needs a case to belong to"
            : "Analyst-tracked recommendation only — no firewall/proxy integration exists to actually enforce this"
        }
        className={`inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium disabled:opacity-50 ${
          blocklisted ? "bg-red-900/40 text-red-300 hover:bg-red-900/60" : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
        }`}
      >
        <ShieldBan className="h-3.5 w-3.5" />
        {busy === "blocklist" ? "Working…" : blocklisted ? "Blocklisted" : "Add to Blocklist"}
      </button>

      <button
        onClick={() => setModal("isolate")}
        disabled={busy !== null || hostnames.length === 0 || noCaseLinked}
        title={
          hostnames.length === 0
            ? "No host associated with this indicator"
            : noCaseLinked
            ? "No case is linked to this indicator's investigation — a task needs a case to belong to"
            : "Manually tracked containment — not a live network action"
        }
        className="inline-flex items-center gap-1.5 rounded bg-orange-900/30 px-3 py-1.5 text-xs font-medium text-orange-300 hover:bg-orange-900/50 disabled:opacity-50"
      >
        <ShieldOff className="h-3.5 w-3.5" />
        {busy === "isolate" ? "Working…" : `Isolate Host${hostnames.length !== 1 ? "s" : ""}`}
      </button>

      <button
        onClick={markFalsePositive}
        disabled={busy !== null || findingIds.length === 0}
        title={findingIds.length === 0 ? "No linked findings" : "Marks every finding tied to this indicator as a false positive"}
        className="inline-flex items-center gap-1.5 rounded bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700 disabled:opacity-50"
      >
        <CircleSlash className="h-3.5 w-3.5" />
        {busy === "falsePositive" ? "Updating…" : "Mark as False Positive"}
      </button>

      {msg && <p className="text-xs text-zinc-500 basis-full">{msg}</p>}

      {modal === "blocklist" && (
        <QuickTaskModal
          heading="Create blocklist task"
          defaultTitle={`Block indicator at the perimeter: ${value}`}
          defaultNotes={`Recommended by IOC Intelligence for ${value}. This platform has no firewall/proxy integration — someone needs to action this manually.`}
          defaultPriority="high"
          cases={cases}
          onClose={() => setModal(null)}
          onSubmit={submitBlocklistTask}
        />
      )}
      {modal === "isolate" && (
        <QuickTaskModal
          heading="Create host isolation task"
          defaultTitle={`Isolate host${hostnames.length !== 1 ? "s" : ""}: ${hostnames.join(", ")}`}
          defaultNotes={`Triggered from IOC ${value}. This platform has no EDR/agent integration — someone needs to action containment manually.`}
          defaultPriority="critical"
          cases={cases}
          onClose={() => setModal(null)}
          onSubmit={submitIsolateTask}
        />
      )}
    </div>
  );
}
