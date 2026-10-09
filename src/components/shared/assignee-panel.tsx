"use client";
/**
 * AssigneePanel
 * Reusable "who owns this" picker — current-assignee card, quick "assign to
 * me" action, and a searchless dropdown of org users. The caller supplies
 * onAssign() to PATCH/POST wherever the assignee actually lives (a Case, a
 * Finding, ...); this component only owns the picker UI and its own
 * optimistic local state. Originally built for per-finding triage
 * assignment (src/components/findings/assignee-workflow-panel.tsx), now
 * shared with Case assignment.
 */
import { useEffect, useState } from "react";
import { UserCheck, ChevronDown, Loader2 } from "lucide-react";
import { useSession } from "next-auth/react";

type OrgUser = { id: string; name: string | null; email: string };

interface AssigneePanelProps {
  assigneeId: string | null;
  onAssign: (userId: string | null) => Promise<void>;
  label?: string;
  /** When set, the current assignee still displays but "Assign to me" and
   * the change dropdown are hidden — e.g. a closed Case, which shouldn't
   * accept reassignment until reopened. */
  disabled?: boolean;
  disabledReason?: string;
}

export function AssigneePanel({ assigneeId: initialAssigneeId, onAssign, label = "Assignee", disabled = false, disabledReason }: AssigneePanelProps) {
  const { data: session } = useSession();
  const currentUserId = session?.user?.id as string | undefined;

  const [assigneeId, setAssigneeId] = useState<string | null>(initialAssigneeId);
  const [users, setUsers] = useState<OrgUser[]>([]);

  // Sync local state whenever the parent swaps to a different case/finding
  useEffect(() => { setAssigneeId(initialAssigneeId); }, [initialAssigneeId]);

  const [loadingUsers, setLoadingUsers] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ── Fetch org users once on mount ──────────────────────────────────────────
  useEffect(() => {
    setLoadingUsers(true);
    fetch("/api/users")
      .then((r) => r.json())
      .then((data) => {
        const list: OrgUser[] = Array.isArray(data.users)
          ? data.users.map((u: { id: string; name: string | null; email: string }) => ({
              id: u.id,
              name: u.name,
              email: u.email,
            }))
          : [];
        setUsers(list);
      })
      .catch(() => setUsers([]))
      .finally(() => setLoadingUsers(false));
  }, []);

  async function handleAssign(userId: string | null) {
    setError(null);
    setDropdownOpen(false);
    if (userId === assigneeId) return;
    setPending(true);
    try {
      await onAssign(userId);
      setAssigneeId(userId);
    } catch {
      setError("Could not update assignee.");
    } finally {
      setPending(false);
    }
  }

  const assignedUser = users.find((u) => u.id === assigneeId) ?? null;
  const isSelf = assigneeId === currentUserId;

  return (
    <div>
      <p className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">{label}</p>

      {/* Current assignee display + quick "assign to me" */}
      <div className="mb-2 flex items-center gap-2">
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950/55 px-3 py-2">
          <UserCheck className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
          {pending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-zinc-400" />
          ) : assignedUser ? (
            <span className="truncate text-sm text-zinc-200">
              {assignedUser.name ?? assignedUser.email}
              {isSelf && <span className="ml-1.5 text-xs text-teal-400">(you)</span>}
            </span>
          ) : (
            <span className="text-sm text-zinc-500">Unassigned</span>
          )}
        </div>
        {!disabled && currentUserId && !isSelf && (
          <button
            onClick={() => handleAssign(currentUserId)}
            disabled={pending}
            className="shrink-0 rounded border border-teal-400/30 bg-teal-400/10 px-2.5 py-2 text-xs text-teal-200 transition hover:border-teal-400/60 hover:bg-teal-400/20 disabled:opacity-50"
          >
            Assign to me
          </button>
        )}
      </div>

      {disabled ? (
        <p className="text-xs text-zinc-600">{disabledReason ?? "Reassignment is disabled."}</p>
      ) : (
        <>
          {/* Dropdown selector */}
          <div className="relative">
            <button
              onClick={() => setDropdownOpen((v) => !v)}
              disabled={loadingUsers || pending}
              className="flex w-full items-center justify-between rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 transition hover:border-zinc-600 disabled:opacity-50"
            >
              <span>{loadingUsers ? "Loading users…" : "Change assignee"}</span>
              <ChevronDown className={`h-4 w-4 text-zinc-500 transition-transform ${dropdownOpen ? "rotate-180" : ""}`} />
            </button>

            {dropdownOpen && (
              <div className="absolute left-0 right-0 top-full z-50 mt-1 max-h-52 overflow-y-auto rounded-md border border-zinc-700 bg-zinc-900 py-1 shadow-xl">
                <button
                  onClick={() => handleAssign(null)}
                  className="flex w-full items-center px-3 py-2 text-sm text-zinc-400 hover:bg-zinc-800"
                >
                  <span className="italic">Unassign</span>
                </button>
                {users.map((u) => (
                  <button
                    key={u.id}
                    onClick={() => handleAssign(u.id)}
                    className={[
                      "flex w-full flex-col px-3 py-2 text-sm hover:bg-zinc-800",
                      u.id === assigneeId ? "bg-zinc-800/70 text-teal-200" : "text-zinc-200",
                    ].join(" ")}
                  >
                    <span className="font-medium">{u.name ?? u.email}</span>
                    {u.name && <span className="text-xs text-zinc-500">{u.email}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
          {error && <p className="mt-1.5 text-xs text-red-400">{error}</p>}
        </>
      )}
    </div>
  );
}
