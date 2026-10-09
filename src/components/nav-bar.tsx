"use client";

import { Search, Shield } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";

export function NavBar() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = query.trim();
    if (q) {
      router.push(`/search?q=${encodeURIComponent(q)}`);
      setQuery("");
      inputRef.current?.blur();
    }
  }

  return (
    <nav className="sticky top-0 z-40 border-b border-zinc-800 bg-zinc-950/90 backdrop-blur-sm">
      <div className="mx-auto flex w-full max-w-7xl items-center gap-4 px-4 py-3 sm:px-6 lg:px-8">
        {/* Logo */}
        <Link
          href="/investigations"
          className="flex shrink-0 items-center gap-2 text-sm font-semibold text-teal-300 hover:text-teal-200"
        >
          <Shield className="h-5 w-5" />
          <span className="hidden sm:inline">Forensicator</span>
        </Link>

        {/* Nav links */}
        <div className="hidden items-center gap-1 sm:flex">
          <NavLink href="/dashboard">Dashboard</NavLink>
          <NavLink href="/investigations">Investigations</NavLink>
        </div>

        {/* Global search */}
        <form onSubmit={handleSearch} className="ml-auto flex-1 max-w-md">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search IPs, hashes, processes, URLs…"
              className="w-full rounded-md border border-zinc-800 bg-zinc-900/60 py-1.5 pl-8 pr-3 text-sm text-zinc-100 placeholder-zinc-600 outline-none transition focus:border-teal-400/50 focus:ring-1 focus:ring-teal-400/20"
            />
          </div>
        </form>
      </div>
    </nav>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="rounded px-3 py-1.5 text-sm text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100"
    >
      {children}
    </Link>
  );
}
