"use client";

import { Zap } from "lucide-react";
import { useState } from "react";

type IocType = "ip" | "hash" | "url" | "domain" | "email";

type Props = {
  value: string;
  type: IocType;
  lastEnriched?: string | null;
};

export function EnrichIocButton({ value, type, lastEnriched }: Props) {
  const [state, setState] = useState<"idle" | "queuing" | "queued" | "error">("idle");
  const [msg, setMsg] = useState<string | null>(null);

  async function enrich(force = false) {
    setState("queuing");
    setMsg(null);
    try {
      const res = await fetch("/api/ioc/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value, type, force }),
      });
      const json = await res.json();
      if (!res.ok) { setState("error"); setMsg(json.message ?? "Enrichment failed."); return; }
      if (json.queued) {
        setState("queued");
        setMsg("Enrichment queued. Refresh in a moment.");
      } else {
        setState("queued");
        setMsg(`Recently enriched (${json.reason}). Use force to re-enrich.`);
      }
    } catch (e) {
      setState("error");
      setMsg(e instanceof Error ? e.message : "Unexpected error.");
    }
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <button
        onClick={() => enrich(false)}
        disabled={state === "queuing"}
        className="inline-flex items-center gap-1.5 rounded bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700 disabled:opacity-50"
      >
        <Zap className="h-3.5 w-3.5 text-teal-400" />
        {state === "queuing" ? "Queuing…" : "Enrich IOC"}
      </button>
      {(state === "queued" || state === "error") && (
        <button
          onClick={() => enrich(true)}
          disabled={false}
          className="text-xs text-zinc-500 hover:text-zinc-300"
        >
          Force re-enrich
        </button>
      )}
      {msg && (
        <p className={`text-xs ${state === "error" ? "text-red-400" : "text-teal-400"}`}>{msg}</p>
      )}
      {lastEnriched && state === "idle" && (
        <p className="text-xs text-zinc-500">Last enriched: {new Date(lastEnriched).toLocaleString()}</p>
      )}
    </div>
  );
}
