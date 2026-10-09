"use client";

import { BookmarkIcon } from "lucide-react";
import { useState } from "react";

type Props = {
  entityType: "investigation" | "finding" | "evidence" | "ioc" | "timeline";
  entityId: string;
  initialBookmarked?: boolean;
  investigationId?: string;
  findingId?: string;
  timelineEventId?: string;
  label?: string;
};

export function BookmarkButton({
  entityType,
  entityId,
  initialBookmarked = false,
  investigationId,
  findingId,
  timelineEventId,
  label,
}: Props) {
  const [bookmarked, setBookmarked] = useState(initialBookmarked);
  const [loading, setLoading] = useState(false);

  async function toggle() {
    setLoading(true);
    try {
      const res = await fetch("/api/bookmarks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ entityType, entityId, label, investigationId, findingId, timelineEventId }),
      });
      const json = await res.json();
      if (res.ok) setBookmarked(json.bookmarked as boolean);
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={toggle}
      disabled={loading}
      title={bookmarked ? "Remove bookmark" : "Add bookmark"}
      className={`inline-flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors disabled:opacity-50 ${
        bookmarked
          ? "bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20"
          : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
      }`}
    >
      <BookmarkIcon className={`h-3.5 w-3.5 ${bookmarked ? "fill-yellow-400" : ""}`} />
      {bookmarked ? "Bookmarked" : "Bookmark"}
    </button>
  );
}
