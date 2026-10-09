"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Search, X } from "lucide-react";
import { normalizeSeverity, type SeverityLabel } from "@/lib/severity";
import { formatDateTime } from "@/lib/utils";
import { BookmarkButton } from "@/components/ui/bookmark-button";

type TimelineEvent = {
  id: string;
  timestamp: string;
  title: string;
  description: string | null;
  category: string;
  severity: string;
  sourceType: string;
  evidenceId: string | null;
  findingId: string | null;
};

type TimelineResponse = {
  events: TimelineEvent[];
  nextCursor: string | null;
  hasMore: boolean;
  categories: string[];
  total: number;
  collectionTimeCount: number;
};

const SEV_DOT: Record<SeverityLabel, string> = {
  Important: "bg-red-500",
  Notable: "bg-orange-500",
  Interesting: "bg-yellow-500",
  Informational: "bg-green-500",
};

const SEV_BADGE: Record<SeverityLabel, string> = {
  Important: "bg-red-900/40 text-red-300 border-red-800",
  Notable: "bg-orange-900/40 text-orange-300 border-orange-800",
  Interesting: "bg-yellow-900/40 text-yellow-300 border-yellow-800",
  Informational: "bg-green-900/40 text-green-300 border-green-800",
};

const SEVERITY_OPTIONS: SeverityLabel[] = ["Important", "Notable", "Interesting", "Informational"];

export function TimelineExplorer({ investigationId }: { investigationId: string }) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [categories, setCategories] = useState<string[]>([]);
  const [total, setTotal] = useState(0);
  const [collectionTimeCount, setCollectionTimeCount] = useState(0);

  const [query, setQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState("");
  const [activeSeverity, setActiveSeverity] = useState("");
  const [realOnly, setRealOnly] = useState(true);

  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchPage = useCallback(
    async (opts: { reset: boolean; cursor?: string | null }) => {
      const params = new URLSearchParams({ limit: "40" });
      if (query) params.set("q", query);
      if (activeCategory) params.set("category", activeCategory);
      if (activeSeverity) params.set("severity", activeSeverity);
      if (realOnly) params.set("realOnly", "true");
      if (opts.cursor) params.set("cursor", opts.cursor);

      if (opts.reset) setLoading(true);
      else setLoadingMore(true);

      const res = await fetch(`/api/investigations/${investigationId}/timeline?${params}`);
      if (res.ok) {
        const data: TimelineResponse = await res.json();
        setEvents((prev) => (opts.reset ? data.events : [...prev, ...data.events]));
        setCursor(data.nextCursor);
        setHasMore(data.hasMore);
        setCategories(data.categories);
        setTotal(data.total);
        setCollectionTimeCount(data.collectionTimeCount);
      }
      setLoading(false);
      setLoadingMore(false);
    },
    [investigationId, query, activeCategory, activeSeverity, realOnly]
  );

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      fetchPage({ reset: true });
    }, 300);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, activeCategory, activeSeverity, realOnly]);

  function loadMore() {
    if (cursor) fetchPage({ reset: false, cursor });
  }

  const groups = groupByDay(events);

  return (
    <div className="grid gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] max-w-md flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search timeline…"
            className="w-full rounded-md border border-zinc-800 bg-zinc-900/60 py-2 pl-8 pr-8 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-teal-400/50 focus:ring-1 focus:ring-teal-400/20"
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <select
          value={activeSeverity}
          onChange={(e) => setActiveSeverity(e.target.value)}
          className="rounded-md border border-zinc-800 bg-zinc-900/60 px-2.5 py-2 text-xs text-zinc-300 outline-none focus:border-teal-400/50"
        >
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        {collectionTimeCount > 0 && (
          <label className="flex select-none items-center gap-1.5 text-xs text-zinc-400">
            <input
              type="checkbox"
              checked={realOnly}
              onChange={(e) => setRealOnly(e.target.checked)}
              className="accent-teal-500"
            />
            Hide collection-time noise ({collectionTimeCount.toLocaleString()})
          </label>
        )}
      </div>

      {/* Category pills */}
      {categories.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          <CategoryPill label="All" active={!activeCategory} onClick={() => setActiveCategory("")} />
          {categories.map((c) => (
            <CategoryPill key={c} label={c} active={activeCategory === c} onClick={() => setActiveCategory(c)} />
          ))}
        </div>
      )}

      {/* Count */}
      <p className="text-xs text-zinc-500">
        {total.toLocaleString()} event{total !== 1 ? "s" : ""} total
        {realOnly && collectionTimeCount > 0
          ? ` · ${collectionTimeCount.toLocaleString()} collection-time entr${collectionTimeCount !== 1 ? "ies" : "y"} hidden`
          : ""}
      </p>

      {/* Timeline */}
      {loading ? (
        <div className="py-16 text-center text-sm text-zinc-500">Loading…</div>
      ) : events.length === 0 ? (
        <div className="py-16 text-center text-sm text-zinc-500">No timeline events match these filters.</div>
      ) : (
        <div className="space-y-6">
          {groups.map((group) => (
            <div key={group.day}>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">{group.day}</div>
              <div className="space-y-2 border-l border-zinc-800 pl-4">
                {group.events.map((ev) => {
                  const sev = normalizeSeverity(ev.severity);
                  return (
                    <div key={ev.id} className="relative">
                      <div
                        className={`absolute -left-[21px] top-3.5 h-2 w-2 rounded-full ring-4 ring-zinc-950 ${SEV_DOT[sev]}`}
                      />
                      <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm text-zinc-200">{ev.title}</p>
                            {ev.description && <p className="mt-1 text-xs text-zinc-500">{ev.description}</p>}
                          </div>
                          <div className="flex shrink-0 items-center gap-2">
                            <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${SEV_BADGE[sev]}`}>
                              {sev}
                            </span>
                            <BookmarkButton
                              entityType="timeline"
                              entityId={ev.id}
                              timelineEventId={ev.id}
                              investigationId={investigationId}
                              findingId={ev.findingId ?? undefined}
                              label={ev.title}
                            />
                          </div>
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-zinc-600">
                          <span className="font-mono">{formatDateTime(ev.timestamp)}</span>
                          <span className="rounded-full border border-zinc-700 px-2 py-0.5 text-zinc-400">
                            {ev.category}
                          </span>
                          {ev.findingId && (
                            <Link
                              href={`/investigations/${investigationId}?finding=${ev.findingId}`}
                              className="text-teal-400 hover:underline"
                            >
                              View finding →
                            </Link>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Load more */}
      {hasMore && (
        <div className="text-center">
          <button
            onClick={loadMore}
            disabled={loadingMore}
            className="rounded-md border border-zinc-800 px-4 py-2 text-xs text-zinc-400 hover:text-zinc-100 disabled:opacity-40"
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}

function CategoryPill({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
        active
          ? "border-teal-400/50 bg-teal-400/15 text-teal-200"
          : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-teal-400/30 hover:text-zinc-200"
      }`}
    >
      {label}
    </button>
  );
}

function groupByDay(events: TimelineEvent[]): { day: string; events: TimelineEvent[] }[] {
  const groups: { day: string; events: TimelineEvent[] }[] = [];
  for (const ev of events) {
    const day = new Date(ev.timestamp).toLocaleDateString(undefined, {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
    });
    const last = groups[groups.length - 1];
    if (last && last.day === day) {
      last.events.push(ev);
    } else {
      groups.push({ day, events: [ev] });
    }
  }
  return groups;
}
