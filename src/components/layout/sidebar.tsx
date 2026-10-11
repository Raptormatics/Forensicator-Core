"use client";

import {
  Activity,
  BookOpen,
  ChevronDown,
  ChevronRight,
  Crosshair,
  FileText,
  Folder,
  Globe,
  LayoutDashboard,
  LogOut,
  Menu,
  Monitor,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Sparkles,
  UserCircle,
  X,
} from "lucide-react";
import Link from "next/link";
import { useSession, signOut } from "next-auth/react";
import { usePathname, useRouter } from "next/navigation";
import { useRef, useState } from "react";

// ── Nav tree ─────────────────────────────────────────────────────────────────
//
// The Enterprise overlay replaces this file with an extended version that
// adds its own remaining Pro-only nav groups (PCAP Analysis, RAM Analysis,
// Developers) and Pro-only items nested inside Platform/Settings (Webhooks,
// Retention, SIEM Integrations, Single Sign-On, License) — Intelligence
// (and, soon, Log Analysis) used to be overlay-only too, now native to
// Core. Unlike most of the files the overlay touches, this one's hardcoded
// href strings aren't a safety boundary — dynamic-import tricks don't
// apply to a nav list — so a 404 on a stripped route would be the actual
// failure mode if any Pro href leaked back in here. Keep this list in sync
// with the actual app route list on every change, both directions.

type NavItem =
  | { kind: "link";  label: string; href: string; icon: React.ElementType; allowedRoles?: string[] }
  | { kind: "group"; label: string; icon: React.ElementType; children: { label: string; href: string; allowedRoles?: string[] }[] };

const NAV: NavItem[] = [
  { kind: "link",  label: "Dashboard",      href: "/dashboard",       icon: LayoutDashboard },
  { kind: "link",  label: "Cases",           href: "/cases",           icon: Folder },
  { kind: "link",  label: "Findings Triage", href: "/findings",        icon: ShieldAlert },
  {
    kind: "group",
    label: "Investigations",
    icon: BookOpen,
    children: [
      { label: "All Investigations", href: "/investigations" },
      { label: "Upload Investigation", href: "/investigations/upload" },
    ],
  },
  { kind: "link",  label: "Hosts",           href: "/hosts",           icon: Monitor },
  {
    kind: "group",
    label: "Intelligence",
    icon: Crosshair,
    children: [
      { label: "IOCs",             href: "/intelligence/iocs" },
      { label: "Sigma Detections", href: "/intelligence/sigma" },
      { label: "Correlations",     href: "/intelligence/correlations" },
      { label: "Threat Intel",     href: "/intelligence/threat-intel" },
    ],
  },
  { kind: "link",  label: "Reports",         href: "/reports",         icon: FileText },
  {
    kind: "group",
    label: "Platform",
    icon: Globe,
    children: [
      { label: "Organizations", href: "/organizations", allowedRoles: ["platform_admin", "org_admin"] },
      { label: "Users",         href: "/users",         allowedRoles: ["platform_admin", "org_admin"] },
      { label: "Updates",       href: "/settings/updates", allowedRoles: ["platform_admin", "org_admin"] },
      { label: "Audit Log",     href: "/audit" },
    ],
  },
  { kind: "group",  label: "Settings",  icon: Settings, children: [
    { label: "Profile",  href: "/settings/profile" },
    { label: "Security", href: "/settings/security" },
    { label: "API Keys",           href: "/settings/keys" },
    { label: "AI Analysis",        href: "/settings/ai", allowedRoles: ["platform_admin", "org_admin"] },
    { label: "Threat Intel Providers", href: "/settings/threat-intel" },
    { label: "General",            href: "/settings" },
  ]},
  { kind: "link",  label: "Enterprise",       href: "/enterprise",      icon: Sparkles },
];

// ── Sidebar ───────────────────────────────────────────────────────────────────

const AUTH_PATHS = ["/login", "/setup", "/forgot-password", "/reset-password"];

export function Sidebar() {
  const pathname = usePathname();
  const router   = useRouter();
  const { data: session } = useSession();
  const [open, setOpen] = useState(false);          // mobile drawer open
  const [query, setQuery] = useState("");
  const [expandedGroups, setExpandedGroups] = useState<string[]>(["Investigations"]);
  const inputRef = useRef<HTMLInputElement>(null);

  // Logs the audit entry while the session is still valid, then signs out
  // — see src/app/api/auth/logout/route.ts for why this can't just be a
  // NextAuth events.signOut hook. Best-effort: a logging failure
  // shouldn't block someone from actually signing out.
  async function handleSignOut() {
    try { await fetch("/api/auth/logout", { method: "POST" }); } catch { /* sign out regardless */ }
    signOut({ callbackUrl: "/login" });
  }

  // Hide sidebar on auth pages — AFTER all hooks
  if (AUTH_PATHS.includes(pathname)) return null;

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = query.trim();
    if (q) {
      router.push(`/search?q=${encodeURIComponent(q)}`);
      setQuery("");
      setOpen(false);
    }
  }

  function toggleGroup(label: string) {
    setExpandedGroups((prev) =>
      prev.includes(label) ? prev.filter((g) => g !== label) : [...prev, label]
    );
  }

  function isActive(href: string) {
    return pathname === href || pathname.startsWith(`${href}/`);
  }

  const sidebarContent = (
    <div className="flex h-full flex-col">
      {/* Logo */}
      <div className="flex shrink-0 items-center gap-2 border-b border-zinc-800 px-4 py-4">
        <Shield className="h-5 w-5 text-teal-400" />
        <span className="text-sm font-semibold tracking-wide text-zinc-100">Forensicator</span>
        <span className="ml-auto rounded bg-teal-900/50 px-1.5 py-0.5 text-[10px] font-medium text-teal-400">
          CORE
        </span>
        {/* Mobile close button */}
        <button
          onClick={() => setOpen(false)}
          className="ml-1 rounded p-1 text-zinc-500 hover:text-zinc-200 lg:hidden"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Search */}
      <div className="shrink-0 border-b border-zinc-800 px-3 py-3">
        <form onSubmit={handleSearch}>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search…"
              className="w-full rounded-md border border-zinc-800 bg-zinc-900 py-1.5 pl-8 pr-3 text-sm text-zinc-200 placeholder-zinc-600 outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/20"
            />
          </div>
        </form>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-0.5">
        {NAV.map((item) => {
          const role = session?.user?.role ?? "";

          if (item.kind === "link") {
            if (item.allowedRoles && !item.allowedRoles.includes(role)) return null;
            const active = isActive(item.href);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setOpen(false)}
                className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  active
                    ? "bg-teal-900/30 text-teal-300"
                    : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                }`}
              >
                <Icon className={`h-4 w-4 shrink-0 ${active ? "text-teal-400" : "text-zinc-500"}`} />
                {item.label}
                {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-teal-400" />}
              </Link>
            );
          }

          // Group with children — filter children by allowedRoles
          const visibleChildren = item.children.filter(
            (c) => !c.allowedRoles || c.allowedRoles.includes(role)
          );
          if (visibleChildren.length === 0) return null;

          const isExpanded = expandedGroups.includes(item.label);
          const anyChildActive = visibleChildren.some((c) => isActive(c.href));
          const Icon = item.icon;

          return (
            <div key={item.label}>
              <button
                onClick={() => toggleGroup(item.label)}
                className={`flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  anyChildActive
                    ? "text-teal-300"
                    : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                }`}
              >
                <Icon className={`h-4 w-4 shrink-0 ${anyChildActive ? "text-teal-400" : "text-zinc-500"}`} />
                {item.label}
                <span className="ml-auto">
                  {isExpanded
                    ? <ChevronDown className="h-3.5 w-3.5 text-zinc-600" />
                    : <ChevronRight className="h-3.5 w-3.5 text-zinc-600" />}
                </span>
              </button>
              {isExpanded && (
                <div className="ml-4 mt-0.5 space-y-0.5 border-l border-zinc-800 pl-3">
                  {visibleChildren.map((child) => {
                    const childActive = isActive(child.href);
                    return (
                      <Link
                        key={child.href}
                        href={child.href}
                        onClick={() => setOpen(false)}
                        className={`flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors ${
                          childActive
                            ? "text-teal-300 font-medium"
                            : "text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
                        }`}
                      >
                        {childActive && <span className="h-1.5 w-1.5 rounded-full bg-teal-400 shrink-0" />}
                        {child.label}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* User menu */}
      <div className="shrink-0 border-t border-zinc-800 px-3 py-3">
        {session?.user ? (
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-teal-800 text-xs font-semibold text-teal-200">
              {(session.user.name ?? session.user.email ?? "?")[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium text-zinc-300">{session.user.name ?? session.user.email}</p>
              <p className="truncate text-[10px] text-zinc-600">{session.user.role}</p>
            </div>
            <div className="flex gap-1">
              <Link href="/settings/profile" className="rounded p-1 text-zinc-600 hover:text-zinc-300" title="Profile">
                <UserCircle className="h-4 w-4" />
              </Link>
              <button onClick={handleSignOut} className="rounded p-1 text-zinc-600 hover:text-red-400" title="Sign out">
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs text-zinc-600">
            <Activity className="h-3.5 w-3.5" />
            <span>Forensicator Core</span>
            <Globe className="ml-auto h-3.5 w-3.5" />
          </div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop sidebar — always visible */}
      <aside className="hidden lg:flex lg:w-56 lg:shrink-0 lg:flex-col border-r border-zinc-800 bg-zinc-950 h-screen sticky top-0">
        {sidebarContent}
      </aside>

      {/* Mobile: hamburger button */}
      <button
        onClick={() => setOpen(true)}
        className="fixed left-3 top-3 z-50 rounded-md border border-zinc-800 bg-zinc-950 p-2 text-zinc-400 shadow-lg lg:hidden"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Mobile drawer */}
      {open && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/60 lg:hidden"
            onClick={() => setOpen(false)}
          />
          <aside className="fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-zinc-800 bg-zinc-950 lg:hidden">
            {sidebarContent}
          </aside>
        </>
      )}
    </>
  );
}
