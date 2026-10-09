"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, ChevronRight, ExternalLink, RefreshCw, Search, Shield, X,
} from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { normalizeSeverity, type SeverityLabel } from "@/lib/severity";

// --- Priority mapping --------------------------------------------------------
const PRIORITY_COLOR: Record<SeverityLabel, { border: string; text: string; badge: string }> = {
  Important:     { border: "#f87171", text: "#fca5a5", badge: "bg-red-900/40 text-red-300 border-red-700" },
  Notable:       { border: "#fb923c", text: "#fdba74", badge: "bg-orange-900/40 text-orange-300 border-orange-700" },
  Interesting:   { border: "#facc15", text: "#fde047", badge: "bg-yellow-900/40 text-yellow-300 border-yellow-700" },
  Informational: { border: "#4ade80", text: "#86efac", badge: "bg-green-900/40 text-green-300 border-green-700" },
};

function priorityColor(severity: string) {
  return PRIORITY_COLOR[normalizeSeverity(severity)];
}
function priorityLabel(severity: string) {
  return normalizeSeverity(severity);
}

// --- Types -------------------------------------------------------------------
interface FindingData {
  id: string;
  name: string;
  category: string;
  severity: string;
  riskScore: number | null;
  evidenceCount: number;
  workflowStatus: string;
  description: string | null;
  mitre: Record<string, unknown>[];
  timeline: Record<string, unknown>[];
}

interface InvNodeData extends Record<string, unknown> {
  label: string;
  nodeType: "investigation";
}

interface CatNodeData extends Record<string, unknown> {
  label: string;
  count: number;
  expanded: boolean;
  loading: boolean;
  highlighted: boolean;
  nodeType: "category";
  onToggle: (id: string) => void;
}

interface FindingNodeData extends Record<string, unknown> {
  label: string;
  severity: string;
  riskScore: number | null;
  highlighted: boolean;
  nodeType: "finding";
  findingData: FindingData;
  onSelect: (f: FindingData) => void;
}

// --- Custom Nodes ------------------------------------------------------------
function InvestigationNode({ data }: NodeProps) {
  const d = data as InvNodeData;
  return (
    <div className="rounded-xl px-5 py-3 font-bold text-sm"
      style={{ background: "#134e4a", border: "2px solid #2dd4bf", color: "#f0fdfa", minWidth: 160, textAlign: "center" }}>
      {d.label}
      <Handle type="source" position={Position.Bottom} style={{ background: "#2dd4bf" }} />
    </div>
  );
}

function CategoryNode({ id, data }: NodeProps) {
  const d = data as CatNodeData;
  return (
    <div
      onClick={() => d.onToggle(id)}
      className="cursor-pointer select-none rounded-lg px-4 py-3 transition-all"
      style={{
        background: d.highlighted ? "#1e3a5f" : "#1e293b",
        border: `1px solid ${d.highlighted ? "#60a5fa" : d.expanded ? "#2dd4bf" : "#475569"}`,
        color: d.highlighted ? "#93c5fd" : d.expanded ? "#99f6e4" : "#94a3b8",
        minWidth: 160,
        textAlign: "center",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: "#475569" }} />
      <div className="text-sm font-semibold">{d.label}</div>
      <div className="mt-1 flex items-center justify-center gap-1.5 text-xs opacity-70">
        {d.loading
          ? <span className="animate-pulse">Loading...</span>
          : <><span>{d.count} findings</span><ChevronRight className={`h-3 w-3 transition-transform ${d.expanded ? "rotate-90" : ""}`} /></>}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: "#475569" }} />
    </div>
  );
}

function FindingNode({ data }: NodeProps) {
  const d = data as FindingNodeData;
  const colors = priorityColor(d.severity);
  const label  = priorityLabel(d.severity);
  return (
    <div
      onClick={() => d.onSelect(d.findingData)}
      className="cursor-pointer select-none rounded-md px-3 py-2 transition-all"
      style={{
        background: d.highlighted ? "#1a2a3a" : "#0f172a",
        border: `1px solid ${d.highlighted ? "#60a5fa" : colors.border}`,
        minWidth: 140,
        maxWidth: 180,
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: colors.border }} />
      <div className="mb-1">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${colors.badge}`}>{label}</span>
      </div>
      <div className="text-xs font-medium leading-4" style={{ color: colors.text, wordBreak: "break-word" }}>{d.label}</div>
      <Handle type="source" position={Position.Bottom} style={{ background: colors.border }} />
    </div>
  );
}

const NODE_TYPES = { investigation: InvestigationNode, category: CategoryNode, finding: FindingNode };

// --- Fast tree layout (synchronous, no deps) ---------------------------------
const NODE_W: Record<string, number> = { investigation: 190, category: 175, finding: 190 };
const NODE_H: Record<string, number> = { investigation: 52,  category: 68,  finding: 72  };
const H_GAP = 60;
const V_GAP = 100;

function treeLayout(nodes: Node[], edges: Edge[]): Node[] {
  const children = new Map<string, string[]>();
  const hasParent = new Set<string>();
  for (const e of edges) {
    if (!children.has(e.source)) children.set(e.source, []);
    children.get(e.source)!.push(e.target);
    hasParent.add(e.target);
  }
  const roots = nodes.filter((n) => !hasParent.has(n.id));
  const posMap = new Map<string, { x: number; y: number }>();

  function subtreeWidth(id: string): number {
    const kids = children.get(id) ?? [];
    if (kids.length === 0) return (NODE_W.finding ?? 190) + H_GAP;
    return kids.reduce((sum, k) => sum + subtreeWidth(k), 0);
  }

  function place(id: string, cx: number, depth: number) {
    const type = nodes.find((n) => n.id === id)?.type ?? "finding";
    const y = depth * ((NODE_H[type] ?? 72) + V_GAP);
    posMap.set(id, { x: cx - (NODE_W[type] ?? 190) / 2, y });
    const kids = children.get(id) ?? [];
    if (kids.length === 0) return;
    const totalW = kids.reduce((s, k) => s + subtreeWidth(k), 0);
    let curX = cx - totalW / 2;
    for (const kid of kids) {
      const sw = subtreeWidth(kid);
      place(kid, curX + sw / 2, depth + 1);
      curX += sw;
    }
  }

  let offsetX = 0;
  for (const root of roots) {
    const sw = subtreeWidth(root.id);
    place(root.id, offsetX + sw / 2, 0);
    offsetX += sw + H_GAP * 2;
  }

  return nodes.map((n) => {
    const pos = posMap.get(n.id);
    return pos ? { ...n, position: pos } : n;
  });
}

// --- Finding Detail Sidebar --------------------------------------------------
function FindingSidebar({ finding, invId, onClose }: { finding: FindingData; invId: string; onClose: () => void }) {
  const colors = priorityColor(finding.severity);
  const label  = priorityLabel(finding.severity);
  return (
    <aside className="flex h-full w-80 shrink-0 flex-col overflow-y-auto border-l border-zinc-800 bg-zinc-950">
      <div className="flex shrink-0 items-center justify-between border-b border-zinc-800 px-4 py-3">
        <span className="text-sm font-semibold text-zinc-200">Finding Detail</span>
        <button onClick={onClose} className="rounded p-1 text-zinc-500 hover:text-zinc-200">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="space-y-4 p-4">
        <div>
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${colors.badge}`}>{label}</span>
        </div>
        <h2 className="text-sm font-semibold leading-5" style={{ color: colors.text }}>{finding.name}</h2>
        {finding.description && (
          <p className="text-xs leading-5 text-zinc-400">{finding.description}</p>
        )}
        <div className="grid grid-cols-2 gap-2">
          <Stat label="Risk Score" value={finding.riskScore !== null ? String(finding.riskScore) : "---"} />
          <Stat label="Evidence"   value={String(finding.evidenceCount)} />
          <Stat label="Category"   value={finding.category} />
          <Stat label="Status"     value={finding.workflowStatus.replace(/_/g, " ")} />
        </div>
        {finding.mitre.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">MITRE ATT&amp;CK</p>
            <div className="space-y-1.5">
              {finding.mitre.slice(0, 6).map((m, i) => {
                const tid   = String(m.technique_id ?? m.tactic ?? "");
                const tname = String(m.technique   ?? m.description ?? "");
                return (
                  <div key={i} className="rounded border border-zinc-800 bg-zinc-900/60 px-2.5 py-1.5">
                    {tid   && <span className="mr-1.5 rounded border border-teal-400/30 bg-teal-400/10 px-1.5 py-0.5 text-[10px] text-teal-300">{tid}</span>}
                    {tname && <span className="text-xs text-zinc-300">{tname}</span>}
                  </div>
                );
              })}
            </div>
          </div>
        )}
        {finding.timeline.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">Timeline ({finding.timeline.length})</p>
            <div className="space-y-1.5">
              {finding.timeline.slice(0, 5).map((t, i) => {
                const ts = String(t.timestamp ?? t.time ?? t.created_at ?? "");
                const ev = String(t.event ?? t.description ?? JSON.stringify(t));
                return (
                  <div key={i} className="rounded border border-zinc-800 bg-zinc-900/60 px-2.5 py-1.5">
                    {ts && <div className="mb-0.5 font-mono text-[10px] text-zinc-600">{ts}</div>}
                    <div className="line-clamp-2 text-xs leading-4 text-zinc-300">{ev}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        <Link
          href={`/investigations/${invId}?finding=${finding.id}`}
          className="flex items-center gap-1.5 rounded border border-teal-400/30 bg-teal-400/10 px-3 py-2 text-xs font-medium text-teal-300 transition-colors hover:bg-teal-400/20"
        >
          <ExternalLink className="h-3.5 w-3.5" />
          Open in Investigation
        </Link>
      </div>
    </aside>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2">
      <div className="text-[10px] uppercase tracking-wider text-zinc-600">{label}</div>
      <div className="mt-0.5 capitalize text-xs font-medium text-zinc-200">{value}</div>
    </div>
  );
}

// --- Main Page ----------------------------------------------------------------
export default function InvestigationGraphPage() {
  const { id } = useParams<{ id: string }>();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [loading, setLoading] = useState(true);
  const [meta, setMeta] = useState<{ hostname: string; categoryCount: number; findingCount: number } | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingData | null>(null);
  const [search, setSearch] = useState("");

  // Stable refs so callbacks in node data never hold stale closures
  const nodesRef    = useRef<Node[]>([]);
  const edgesRef    = useRef<Edge[]>([]);
  const expandedRef = useRef<Set<string>>(new Set());
  const cacheRef    = useRef<Map<string, { nodes: Node[]; edges: Edge[] }>>(new Map());

  useEffect(() => { nodesRef.current = nodes; }, [nodes]);
  useEffect(() => { edgesRef.current = edges; }, [edges]);

  // Commit both states together so React batches a single render
  const relayout = useCallback((nextNodes: Node[], nextEdges: Edge[]) => {
    const laid = treeLayout(nextNodes, nextEdges);
    nodesRef.current = laid;
    edgesRef.current = nextEdges;
    setNodes(laid);
    setEdges(nextEdges);
  }, [setNodes, setEdges]);

  // Stable select callback via ref
  const selectRef = useRef((f: FindingData) => setSelectedFinding(f));
  selectRef.current = (f: FindingData) => setSelectedFinding(f);

  // Toggle implemented directly on a ref so the stable wrapper never changes
  // identity and never causes useEffect re-runs.
  const toggleImpl = useRef(async (_catId: string) => {});
  toggleImpl.current = async (catId: string) => {
    if (expandedRef.current.has(catId)) {
      // Collapse
      expandedRef.current.delete(catId);
      const stored     = cacheRef.current.get(catId);
      const removeIds  = new Set(stored?.nodes.map((n) => n.id) ?? []);
      const removeEIds = new Set(stored?.edges.map((e) => e.id) ?? []);
      relayout(
        nodesRef.current
          .filter((n) => !removeIds.has(n.id))
          .map((n) => n.id === catId ? { ...n, data: { ...n.data, expanded: false } } : n),
        edgesRef.current.filter((e) => !removeEIds.has(e.id)),
      );
      return;
    }

    // Expand — show spinner
    expandedRef.current.add(catId);
    setNodes((prev) => prev.map((n) =>
      n.id === catId ? { ...n, data: { ...n.data, loading: true } } : n
    ));

    // Fetch if not cached
    if (!cacheRef.current.has(catId)) {
      const catName = catId.replace(`cat-${id}-`, "");
      let catFindings: FindingData[] = [];
      try {
        const res  = await fetch(`/api/graphs/investigation/${id}/category/${encodeURIComponent(catName)}`);
        const json = await res.json();
        catFindings = json.findings ?? [];
      } catch { /* ignore */ }

      cacheRef.current.set(catId, {
        nodes: catFindings.map((f) => ({
          id: `f-${f.id}`,
          type: "finding",
          position: { x: 0, y: 0 },
          data: {
            label: f.name,
            severity: f.severity,
            riskScore: f.riskScore,
            highlighted: false,
            nodeType: "finding",
            findingData: f,
            onSelect: (fd: FindingData) => selectRef.current(fd),
          } as FindingNodeData,
        })),
        edges: catFindings.map((f) => ({
          id: `e-${catId}-f-${f.id}`,
          source: catId,
          target: `f-${f.id}`,
          style: { stroke: "#475569", strokeWidth: 1 },
        })),
      });
    }

    const { nodes: fNodes, edges: fEdges } = cacheRef.current.get(catId)!;
    relayout(
      nodesRef.current
        .map((n) => n.id === catId ? { ...n, data: { ...n.data, loading: false, expanded: true } } : n)
        .concat(fNodes),
      [...edgesRef.current, ...fEdges],
    );
  };

  const stableToggle = useCallback((catId: string) => { toggleImpl.current(catId); }, []);

  // Initial load
  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setSelectedFinding(null);
    expandedRef.current = new Set();
    cacheRef.current    = new Map();

    const res = await fetch(`/api/investigations/${id}/graph`);
    if (!res.ok) { setLoading(false); return; }
    const data = await res.json();

    const invNode: Node = {
      id: `inv-${id}`,
      type: "investigation",
      position: { x: 0, y: 0 },
      data: { label: data.meta?.hostname ?? id, nodeType: "investigation" } as InvNodeData,
    };

    const catNodes: Node[] = (data.categories as { id: string; label: string; count: number }[]).map((c) => ({
      id: c.id,
      type: "category",
      position: { x: 0, y: 0 },
      data: {
        label: c.label,
        count: c.count,
        expanded: false,
        loading: false,
        highlighted: false,
        nodeType: "category",
        onToggle: stableToggle,
      } as CatNodeData,
    }));

    const catEdges: Edge[] = catNodes.map((cn) => ({
      id: `e-inv-${cn.id}`,
      source: `inv-${id}`,
      target: cn.id,
      style: { stroke: "#2dd4bf", strokeWidth: 1.5 },
    }));

    setMeta({ hostname: data.meta?.hostname ?? id, categoryCount: catNodes.length, findingCount: data.meta?.findingCount ?? 0 });
    relayout([invNode, ...catNodes], catEdges);
    setLoading(false);
  }, [id, stableToggle, relayout]);

  useEffect(() => { load(); }, [load]);

  // Search highlight
  useEffect(() => {
    const q = search.trim().toLowerCase();
    setNodes((prev) => prev.map((n) => {
      if (n.type === "category") {
        const d = n.data as CatNodeData;
        return { ...n, data: { ...d, highlighted: q.length > 0 && d.label.toLowerCase().includes(q) } };
      }
      if (n.type === "finding") {
        const d = n.data as FindingNodeData;
        return { ...n, data: { ...d, highlighted: q.length > 0 && d.label.toLowerCase().includes(q) } };
      }
      return n;
    }));
  }, [search, setNodes]);

  return (
    <div className="flex h-screen flex-col">
      <div className="flex shrink-0 items-center gap-4 border-b border-zinc-800 bg-zinc-950 px-6 py-3">
        <Link href={`/investigations/${id}`} className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300">
          <ArrowLeft className="h-4 w-4" /> Back to Investigation
        </Link>
        <div className="flex items-center gap-1.5">
          <Shield className="h-4 w-4 text-teal-400" />
          <span className="text-sm font-semibold text-zinc-200">Evidence Graph</span>
        </div>
        {meta && (
          <span className="text-xs text-zinc-600">
            {meta.hostname} &middot; {meta.categoryCount} categories &middot; {meta.findingCount} findings
          </span>
        )}
        <div className="relative ml-auto w-52">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings..."
            className="w-full rounded border border-zinc-700 bg-zinc-900 py-1.5 pl-8 pr-3 text-xs text-zinc-300 placeholder-zinc-600 outline-none focus:border-teal-500"
          />
          {search && (
            <button onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-300">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        <button onClick={load} disabled={loading} className="rounded border border-zinc-800 p-1.5 text-zinc-500 hover:text-zinc-200 disabled:opacity-40">
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="relative flex-1">
          {loading ? (
            <div className="flex h-full items-center justify-center text-sm text-zinc-600">Building graph...</div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={NODE_TYPES}
              fitView
              colorMode="dark"
              minZoom={0.2}
              maxZoom={2}
            >
              <Background color="#27272a" gap={20} />
              <Controls />
              <MiniMap
                nodeColor={(n) => {
                  if (n.type === "investigation") return "#2dd4bf";
                  if (n.type === "category")      return "#475569";
                  return priorityColor((n.data as { severity?: string }).severity ?? "info").border;
                }}
                style={{ background: "#0f172a", border: "1px solid #27272a" }}
              />
            </ReactFlow>
          )}

          <div className="absolute bottom-4 left-4 space-y-1.5 rounded border border-zinc-800 bg-zinc-950/90 px-3 py-2 text-xs text-zinc-500">
            <div className="mb-1 font-semibold text-zinc-400">Priority</div>
            {(["important","notable","interesting","informational"] as const).map((s) => (
              <div key={s} className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full" style={{ background: priorityColor(s).border }} />
                {priorityLabel(s)}
              </div>
            ))}
            <div className="mt-1 border-t border-zinc-800 pt-1.5 text-zinc-600">Click category to expand</div>
          </div>
        </div>

        {selectedFinding && (
          <FindingSidebar finding={selectedFinding} invId={id} onClose={() => setSelectedFinding(null)} />
        )}
      </div>
    </div>
  );
}