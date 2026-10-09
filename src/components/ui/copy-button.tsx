"use client";

export function CopyButton({ text }: { text: string }) {
  return (
    <button
      onClick={() => navigator.clipboard.writeText(text).catch(() => {})}
      className="rounded border border-zinc-800 px-2.5 py-1 text-xs text-zinc-400 hover:border-teal-400/30 hover:text-teal-200"
    >
      Copy
    </button>
  );
}
