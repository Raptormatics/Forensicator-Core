"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Archive, RefreshCw } from "lucide-react";
import { formatCaseNumber } from "@/lib/cases/case-number";
import { ArchiveButton } from "@/components/cases/archive-button";
import { dispositionLabel } from "@/components/cases/case-closure-dialog";
import { ArchiveItemEnterpriseActions } from "@/components/enterprise-slots/archive-item-actions";

type ArchivedBy = { email: string; name: string | null } | null;
type ArchivedCase = {
  id: string; caseSeq: number; title: string; severity: string; closureDisposition: string | null;
  closedAt: string | null; archivedAt: string; archivedBy: ArchivedBy;
  _count: { investigations: number; logUploads: number; pcapUploads: number; ramUploads: number; windowsArtifactUploads: number };
};
type ArchivedItem = {
  id: string; archivedAt: string; archivedBy: ArchivedBy; createdAt: string; findingCount: number;
  title?: string; filename?: string; hostname?: string | null;
};
type UploadType = "log" | "pcap" | "ram" | "windows-artifacts";
type ArchiveData = {
  cases: ArchivedCase[];
  investigations: ArchivedItem[];
  uploads: Record<UploadType, ArchivedItem[]>;
};

const UPLOAD_META: Record<UploadType, { label: string; href: (id: string) => string }> = {
  log:                 { label: "Log Analysis",   href: (id) => `/log-analysis/${id}` },
  pcap:                { label: "PCAP Analysis",  href: (id) => `/pcap-analysis/${id}` },
  ram:                 { label: "RAM Analysis",   href: (id) => `/ram-analysis/${id}` },
  "windows-artifacts": { label: "Host Artifacts", href: (id) => `/host-artifacts/${id}` },
};

const TABS = ["cases", "investigations", "uploads"] as const;
type Tab = (typeof TABS)[number];

function by(u: ArchivedBy) { return u ? ` by ${u.name ?? u.email}` : ""; }

export default function ArchivePage() {
  const [data, setData] = useState<ArchiveData | null>(null);
  const [tab, setTab] = useState<Tab>("cases");

  async function load() {
    const res = await fetch("/api/archive");
    if (res.ok) setData(await res.json());
  }
  useEffect(() => { load(); }, []);

  const uploads = data
    ? (Object.keys(UPLOAD_META) as UploadType[]).flatMap((t) => data.uploads[t].map((u) => ({ ...u, type: t })))
        .sort((a, b) => b.archivedAt.localeCompare(a.archivedAt))
    : [];
  const counts: Record<Tab, number> = {
    cases: data?.cases.length ?? 0,
    investigations: data?.investigations.length ?? 0,
    uploads: uploads.length,
  };

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-start justify-between gap-4 mb-2">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2"><Archive className="h-5 w-5 text-zinc-400" /> Archive</h1>
          <p className="mt-1 text-sm text-zinc-500 max-w-2xl">
            Closed cases archived with everything they contain, and investigations or uploads archived on their own because they
            belong to no case. Archived records are read-only and hidden from the working lists, dashboard and search, but still
            count in host profiles. Restoring a case returns it as closed; reopen it from the case page.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-md border border-zinc-800 text-zinc-500 hover:text-zinc-300">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      <div className="flex gap-1 border-b border-zinc-800 mb-4 mt-4">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm capitalize border-b-2 -mb-px ${tab === t ? "border-teal-500 text-zinc-100" : "border-transparent text-zinc-500 hover:text-zinc-300"}`}
          >
            {t} <span className="text-xs text-zinc-600">({counts[t]})</span>
          </button>
        ))}
      </div>

      {!data ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : tab === "cases" ? (
        data.cases.length === 0 ? <Empty text="No archived cases. Close a case, then archive it from its page." /> : (
          <div className="grid gap-3">
            {data.cases.map((c) => {
              const uploadCount = c._count.logUploads + c._count.pcapUploads + c._count.ramUploads + c._count.windowsArtifactUploads;
              return (
                <div key={c.id} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <Link href={`/cases/${c.id}`} className="text-base font-semibold text-zinc-100 hover:text-teal-300">
                      <span className="text-zinc-500 font-mono text-sm mr-1.5">{formatCaseNumber(c.caseSeq)}</span>{c.title}
                    </Link>
                    <p className="mt-1 text-xs text-zinc-400">
                      {dispositionLabel(c.closureDisposition)} · {c._count.investigations} investigation{c._count.investigations !== 1 ? "s" : ""} · {uploadCount} upload{uploadCount !== 1 ? "s" : ""}
                    </p>
                    <p className="mt-0.5 text-xs text-zinc-600">
                      {c.closedAt ? `Closed ${new Date(c.closedAt).toLocaleDateString()} · ` : ""}Archived {new Date(c.archivedAt).toLocaleString()}{by(c.archivedBy)}
                    </p>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    <ArchiveButton type="case" id={c.id} action="restore" onDone={load} />
                    <ArchiveItemEnterpriseActions type="case" id={c.id} onChanged={load} />
                  </div>
                </div>
              );
            })}
          </div>
        )
      ) : tab === "investigations" ? (
        data.investigations.length === 0 ? <Empty text="No archived investigations. Investigations in a case are archived with their case." /> : (
          <ItemList
            rows={data.investigations.map((i) => ({ ...i, type: "investigation" as const, kind: "Investigation", href: `/investigations/${i.id}`, name: i.title ?? i.hostname ?? i.id }))}
            onDone={load}
          />
        )
      ) : uploads.length === 0 ? <Empty text="No archived uploads. Uploads in a case are archived with their case." /> : (
        <ItemList
          rows={uploads.map((u) => ({ ...u, kind: UPLOAD_META[u.type].label, href: UPLOAD_META[u.type].href(u.id), name: u.filename ?? u.hostname ?? u.id }))}
          onDone={load}
        />
      )}
    </div>
  );
}

function ItemList({ rows, onDone }: {
  rows: (ArchivedItem & { type: "investigation" | UploadType; kind: string; href: string; name: string })[];
  onDone: () => void;
}) {
  return (
    <div className="grid gap-2">
      {rows.map((r) => (
        <div key={`${r.type}-${r.id}`} className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs text-zinc-500">{r.kind}{r.hostname && r.name !== r.hostname ? ` · ${r.hostname}` : ""}</p>
            <Link href={r.href} className="text-sm font-medium text-zinc-200 hover:text-teal-300 break-all">{r.name}</Link>
            <p className="text-xs text-zinc-600">
              {r.findingCount} finding{r.findingCount !== 1 ? "s" : ""} · Archived {new Date(r.archivedAt).toLocaleString()}{by(r.archivedBy)}
            </p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <ArchiveButton type={r.type} id={r.id} action="restore" onDone={onDone} />
            <ArchiveItemEnterpriseActions type={r.type} id={r.id} onChanged={onDone} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="rounded-xl border border-dashed border-zinc-800 px-4 py-8 text-center text-sm text-zinc-600">{text}</p>;
}
