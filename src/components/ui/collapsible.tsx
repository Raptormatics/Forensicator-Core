"use client";
import { useState, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";

export function Collapsible({
  label,
  defaultOpen = false,
  children,
}: {
  label: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="mb-6 rounded-lg border border-zinc-800 bg-zinc-950/50">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-xs font-medium uppercase tracking-wide text-zinc-400 hover:text-zinc-200"
      >
        {label}
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && <div className="border-t border-zinc-800 p-4">{children}</div>}
    </div>
  );
}
