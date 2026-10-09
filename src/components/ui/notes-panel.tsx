"use client";

import { useState } from "react";
import { Send, Trash2 } from "lucide-react";

type Note = {
  id: string;
  content: string;
  createdAt: string;
  author: { name: string | null; email: string };
};

type Props = {
  initialNotes: Note[];
  investigationId?: string;
  findingId?: string;
  evidenceId?: string;
};

export function NotesPanel({ initialNotes, investigationId, findingId, evidenceId }: Props) {
  const [notes, setNotes] = useState<Note[]>(initialNotes);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!draft.trim()) return;
    setSaving(true);
    try {
      const res = await fetch("/api/notes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: draft, investigationId, findingId, evidenceId }),
      });
      const json = await res.json();
      if (res.ok) {
        setNotes((prev) => [json.note as Note, ...prev]);
        setDraft("");
      }
    } finally {
      setSaving(false);
    }
  }

  async function deleteNote(id: string) {
    const res = await fetch(`/api/notes/${id}`, { method: "DELETE" });
    if (res.ok) setNotes((prev) => prev.filter((n) => n.id !== id));
  }

  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Analyst Notes</h3>

      {/* Composer */}
      <form onSubmit={submit} className="flex gap-2">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Add a note (markdown supported)…"
          rows={2}
          className="flex-1 resize-none rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:border-teal-600 focus:outline-none"
        />
        <button
          type="submit"
          disabled={saving || !draft.trim()}
          className="self-end rounded bg-teal-600 px-3 py-2 text-white hover:bg-teal-500 disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
        </button>
      </form>

      {/* Notes list */}
      {notes.length === 0 ? (
        <p className="text-xs text-zinc-500">No notes yet.</p>
      ) : (
        <div className="space-y-2">
          {notes.map((note) => (
            <div key={note.id} className="group rounded border border-zinc-800 bg-zinc-900/60 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-zinc-500">
                  {note.author.name ?? note.author.email} · {new Date(note.createdAt).toLocaleString()}
                </span>
                <button
                  onClick={() => deleteNote(note.id)}
                  className="invisible text-zinc-600 hover:text-red-400 group-hover:visible"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
              <p className="mt-1 whitespace-pre-wrap text-sm text-zinc-300">{note.content}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
