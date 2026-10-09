"use client";

import { Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { InvestigationList } from "@/components/investigation/investigation-list";

type Investigation = React.ComponentProps<typeof InvestigationList>["investigations"][number];

type InvestigationFilterProps = {
  investigations: Investigation[];
};

export function InvestigationFilter({ investigations }: InvestigationFilterProps) {
  const [query, setQuery] = useState("");
  const [activeTag, setActiveTag] = useState<string | null>(null);

  // Collect the full set of unique tags across all investigations.
  const allTags = useMemo(() => {
    const set = new Set<string>();
    for (const inv of investigations) {
      for (const tag of inv.tags) set.add(tag);
    }
    return Array.from(set).sort();
  }, [investigations]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim();

    return investigations.filter((inv) => {
      // Tag filter
      if (activeTag && !inv.tags.includes(activeTag)) return false;

      // Text filter across title, hostname, OS version
      if (q) {
        const os = inv.osInfo as { version?: string; platform?: string } | null;
        const searchable = [
          inv.title,
          inv.hostname ?? "",
          os?.version ?? "",
          os?.platform ?? "",
        ]
          .join(" ")
          .toLowerCase();
        if (!searchable.includes(q)) return false;
      }

      return true;
    });
  }, [investigations, query, activeTag]);

  return (
    <div className="grid gap-4">
      {/* Search + tag filter bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        {/* Text search */}
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            placeholder="Search by title, hostname, OS…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full rounded-md border border-zinc-800 bg-zinc-950/60 py-2 pl-9 pr-4 text-sm text-zinc-100 placeholder-zinc-500 outline-none ring-0 transition focus:border-teal-400/50 focus:ring-1 focus:ring-teal-400/30"
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
      </div>

      {/* Tag pills */}
      {allTags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {allTags.map((tag) => (
            <button
              key={tag}
              onClick={() => setActiveTag(activeTag === tag ? null : tag)}
              className={`rounded-full border px-2.5 py-0.5 text-xs font-medium transition ${
                activeTag === tag
                  ? "border-teal-400/60 bg-teal-400/20 text-teal-200"
                  : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:border-teal-400/40 hover:text-teal-300"
              }`}
            >
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* Result count */}
      {(query || activeTag) && (
        <p className="text-xs text-zinc-500">
          {filtered.length} of {investigations.length} investigation{investigations.length !== 1 ? "s" : ""}
        </p>
      )}

      <InvestigationList investigations={filtered} />
    </div>
  );
}
