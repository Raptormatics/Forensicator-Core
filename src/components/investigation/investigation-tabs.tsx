"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type Tab = { label: string; href: string };

export function InvestigationTabs({ investigationId }: { investigationId: string }) {
  const pathname = usePathname();
  const base = `/investigations/${investigationId}`;

  const tabs: Tab[] = [
    { label: "Overview",     href: base },
    { label: "Artifacts",    href: `${base}/artifacts` },
    { label: "Timeline",     href: `${base}/timeline` },
    { label: "Graph",        href: `${base}/graph` },
    { label: "Attack Path",  href: `${base}/attack-path` },
  ];

  return (
    <div className="flex gap-1 border-b border-zinc-800 mb-6">
      {tabs.map((tab) => {
        const active = tab.href === base
          ? pathname === base
          : pathname.startsWith(tab.href);

        return (
          <Link
            key={tab.href}
            href={tab.href}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              active
                ? "border-teal-400 text-teal-300"
                : "border-transparent text-zinc-500 hover:text-zinc-200 hover:border-zinc-600"
            }`}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}
