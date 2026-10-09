"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Play, RefreshCw, ChevronRight } from "lucide-react";
import { normalizeSeverity, type SeverityLabel } from "@/lib/severity";

type Stage = {
  stage: number;
  label: string;
  tactic: string;
  findings: { id: string; title: string; severity: string; category: string }[];
};

type AttackPath = {
  id: string;
  status: string;
  summary: string | null;
  generatedAt: string | null;
  stages: Stage[];
};

const SEV_BADGE: Record<SeverityLabel, string> = {
  Important:     "bg-red-900/40 text-red-300 border-red-800",
  Notable:       "bg-orange-900/40 text-orange-300 border-orange-800",
  Interesting:   "bg-yellow-900/40 text-yellow-300 border-yellow-800",
  Informational: "bg-green-900/40 text-green-300 border-green-800",
};

export default function AttackPathPage() {
  const { id } = useParams<{ id: string }>();
  const [path, setPath]         = useState<AttackPath | null>(null);
  const [loading, setLoading]   = useState(true);
  const [generating, setGen]    = useState(false);
  const [notFound, setNotFound] = useState(false);

  async function load() {
    setLoading(true);
    const res = await fetch(`/api/investigations/${id}/attack-path`);
    if (res.ok) {
      setPath(await res.json().then((d) => d.attackPath));
      setNotFound(false);
    } else {
      setNotFound(true);
    }
    setLoading(false);
  }

  async function generate() {
    setGen(true);
    await fetch(`/api/investigations/${id}/attack-path/generate`, { method: "POST" });
    setGen(false);
    load();
  }

  useEffect(() => { if (id) load(); }, [id]);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <Link href={`/investigations/${id}`} className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 mb-4">
        <ArrowLeft className="h-4 w-4" /> Investigation
      </Link>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Attack Path</h1>
          <p className="text-sm text-zinc-500 mt-0.5">Reconstructed attack chain from finding categories</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} disabled={loading} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-200 disabled:opacity-40">
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button onClick={generate} disabled={generating} className="flex items-center gap-1.5 rounded-md bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50">
            <Play className="h-4 w-4" /> {generating ? "Generating…" : "Generate / Refresh"}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-16 text-zinc-600">Loading…</div>
      ) : notFound || !path ? (
        <div className="text-center py-16 text-zinc-600">
          <p>No attack path generated yet.</p>
          <button onClick={generate} disabled={generating} className="mt-4 rounded-md bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-600">
            {generating ? "Generating…" : "Generate Now"}
          </button>
        </div>
      ) : (
        <>
          {path.summary && (
            <div className="rounded-xl border border-teal-800/50 bg-teal-900/20 px-4 py-3 mb-6 text-sm text-teal-200">
              {path.summary}
            </div>
          )}

          {/* Timeline */}
          <div className="relative">
            {/* Connector line */}
            <div className="absolute left-6 top-8 bottom-8 w-0.5 bg-zinc-800" />

            <div className="space-y-4">
              {path.stages.map((stage, i) => (
                <div key={stage.stage} className="relative flex gap-4">
                  {/* Stage number bubble */}
                  <div className="shrink-0 w-12 h-12 rounded-full border-2 border-teal-700 bg-zinc-950 flex items-center justify-center z-10">
                    <span className="text-sm font-bold text-teal-400">{i + 1}</span>
                  </div>

                  <div className="flex-1 rounded-xl border border-zinc-800 bg-zinc-900 p-4 mb-2">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <span className="font-semibold text-zinc-200">{stage.label}</span>
                        <span className="ml-2 text-xs text-zinc-600 font-mono">{stage.tactic}</span>
                      </div>
                      <span className="text-xs text-zinc-600">{stage.findings.length} finding{stage.findings.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="grid gap-1.5">
                      {stage.findings.slice(0, 6).map((f) => (
                        <div key={f.id} className="flex items-center gap-2 text-sm">
                          <ChevronRight className="h-3.5 w-3.5 text-zinc-600 shrink-0" />
                          <span className="text-zinc-300 text-xs">{f.title}</span>
                          <span className={`ml-auto text-xs px-1.5 py-0.5 rounded border ${SEV_BADGE[normalizeSeverity(f.severity)]}`}>
                            {normalizeSeverity(f.severity)}
                          </span>
                        </div>
                      ))}
                      {stage.findings.length > 6 && (
                        <p className="text-xs text-zinc-600 pl-5">+{stage.findings.length - 6} more…</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {path.generatedAt && (
            <p className="text-xs text-zinc-700 mt-4 text-center">
              Generated {new Date(path.generatedAt).toLocaleString()}
            </p>
          )}
        </>
      )}
    </div>
  );
}
