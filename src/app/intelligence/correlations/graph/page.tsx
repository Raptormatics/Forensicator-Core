"use client";

import { useEffect, useCallback, useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, Briefcase, ExternalLink, Loader2, Search, Server, ShieldAlert, X } from "lucide-react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import ELK from "elkjs/lib/elk.bundled.js";
import { miniMapColor, correlationTypeStyle, CORRELATION_TYPE_STYLE } from "@/lib/graph/node-style";
import { formatCaseNumber } from "@/lib/cases/case-number";

// --- Types -------------------------------------------------------------------
type Prevalence = { hosts: number; of: number };
type KnownIoc = { reputation: number | null; threatType: string | null; malwareFamily: string | null };

type CaseData = { label: string; caseId: string; caseSeq: number; severity: string; status: string };
type HostData = { label: string; caseIds: string[] };
type CorrData = {
  label: string; correlationType: string; confidence: number; prevalence: Prevalence | null;
  knownIoc: KnownIoc | null; significant: boolean; hostCount: number; caseIds: string[];
};
type ApiNode =
  | { id: string; type: "case"; data: CaseData }
  | { id: string; type: "host"; data: HostData }
  | { id: string; type: "correlation"; data: CorrData };
type ApiResponse = {
  nodes: ApiNode[]; edges: { id: string; source: string; target: string }[];
  shown: number; totalSignificant: number; totalAll: number; capped: boolean; cap: number;
};

// Shared flags the layout/selection pass sets on every node's data.
type ViewFlags = { dimmed?: boolean; selected?: boolean; matched?: boolean };

// --- Node renderers ----------------------------------------------------------
const NODE_SIZE = {
  case:        { width: 220, height: 48 },
  host:        { width: 180, height: 36 },
  correlation: { width: 260, height: 44 },
} as const;

function ring(flags: ViewFlags): string {
  if (flags.selected) return "ring-2 ring-white";
  if (flags.matched) return "ring-2 ring-amber-400";
  return "";
}

function CaseNode({ data }: NodeProps<Node<CaseData & ViewFlags>>) {
  return (
    <div
      style={{ ...NODE_SIZE.case, opacity: data.dimmed ? 0.15 : 1 }}
      className={`flex items-center gap-2 rounded-xl border-2 border-blue-500 bg-[#1e3a5f] px-3 text-blue-100 ${ring(data)}`}
    >
      <Briefcase className="h-4 w-4 shrink-0 text-blue-300" />
      <div className="min-w-0">
        <div className="font-mono text-[10px] text-blue-300">{formatCaseNumber(data.caseSeq)}</div>
        <div className="truncate text-xs font-semibold" title={data.label}>{data.label}</div>
      </div>
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}

function HostNode({ data }: NodeProps<Node<HostData & ViewFlags>>) {
  return (
    <div
      style={{ ...NODE_SIZE.host, opacity: data.dimmed ? 0.15 : 1 }}
      className={`flex items-center gap-2 rounded-lg border-2 border-teal-500 bg-[#134e4a] px-3 text-teal-50 ${ring(data)}`}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <Server className="h-3.5 w-3.5 shrink-0 text-teal-300" />
      <span className="truncate text-xs" title={data.label}>{data.label}</span>
      {data.caseIds.length > 1 && (
        <span className="ml-auto shrink-0 rounded bg-teal-900 px-1 text-[10px] text-teal-300" title={`In ${data.caseIds.length} cases`}>
          {data.caseIds.length}
        </span>
      )}
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}

function CorrelationNode({ data }: NodeProps<Node<CorrData & ViewFlags>>) {
  const t = correlationTypeStyle(data.correlationType);
  return (
    <div
      style={{ ...NODE_SIZE.correlation, opacity: data.dimmed ? 0.15 : 1, borderColor: data.knownIoc ? "#ef4444" : t.color }}
      className={`flex items-center gap-2 rounded-md border bg-zinc-900 px-2.5 ${data.knownIoc ? "border-2" : ""} ${ring(data)}`}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide" style={{ color: t.color }}>
          {data.knownIoc && <ShieldAlert className="h-3 w-3 text-red-400" />}
          {t.label}
        </div>
        <div className="truncate font-mono text-[11px] text-zinc-200" title={data.label}>{data.label}</div>
      </div>
      <span
        className={`shrink-0 rounded px-1 text-[10px] font-semibold ${data.confidence >= 85 ? "bg-green-500/15 text-green-400" : data.confidence >= 60 ? "bg-amber-500/15 text-amber-400" : "bg-zinc-700/40 text-zinc-400"}`}
        title="Confidence"
      >
        {data.confidence}
      </span>
    </div>
  );
}

const nodeTypes = { case: CaseNode, host: HostNode, correlation: CorrelationNode };

// --- Layout ------------------------------------------------------------------
const elk = new ELK();

type LayoutMode = "columns" | "clusters";

const LAYOUT_OPTIONS: Record<LayoutMode, Record<string, string>> = {
  // Cases -> hosts -> values, left to right; crossings minimised.
  columns: {
    "elk.algorithm": "layered",
    "elk.direction": "RIGHT",
    "elk.layered.spacing.nodeNodeBetweenLayers": "140",
    "elk.spacing.nodeNode": "12",
    "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
    "elk.separateConnectedComponents": "true",
    "elk.spacing.componentComponent": "60",
  },
  // Values sit next to the hosts they tie together.
  clusters: {
    "elk.algorithm": "stress",
    "elk.stress.desiredEdgeLength": "220",
    "elk.separateConnectedComponents": "true",
    "elk.spacing.componentComponent": "80",
  },
};

async function layout(apiNodes: ApiNode[], apiEdges: ApiResponse["edges"], mode: LayoutMode): Promise<Node[]> {
  const graph = await elk.layout({
    id: "root",
    layoutOptions: LAYOUT_OPTIONS[mode],
    children: apiNodes.map((n) => ({ id: n.id, ...NODE_SIZE[n.type] })),
    edges: apiEdges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  });
  const pos = new Map((graph.children ?? []).map((c) => [c.id, { x: c.x ?? 0, y: c.y ?? 0 }]));
  return apiNodes.map((n) => ({ id: n.id, type: n.type, data: { ...n.data }, position: pos.get(n.id) ?? { x: 0, y: 0 } }));
}

// --- Page --------------------------------------------------------------------
const CONF_PRESETS = [
  { label: "Any", value: 0 },
  { label: "60+", value: 60 },
  { label: "85+", value: 85 },
];

const EDGE_STYLE = { stroke: "#3f3f46", strokeWidth: 1 };
const EDGE_STYLE_ACTIVE = { stroke: "#a5b4fc", strokeWidth: 2 };

function CorrelationsGraph() {
  const searchParams = useSearchParams();
  const { fitView } = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [data, setData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const pivot = searchParams.get("q");
  const [type, setType] = useState<string>(searchParams.get("type") ?? "");
  const [minConfidence, setMinConfidence] = useState(0);
  const [showAll, setShowAll] = useState(false);
  const [mode, setMode] = useState<LayoutMode>("columns");
  const [find, setFind] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (pivot) params.set("q", pivot);
    if (type) params.set("type", type);
    if (minConfidence) params.set("minConfidence", String(minConfidence));
    if (showAll) params.set("all", "1");
    const res = await fetch(`/api/correlations/graph?${params}`);
    if (res.ok) {
      const body = (await res.json()) as ApiResponse;
      setSelectedId(null);
      const laidOut = await layout(body.nodes, body.edges, mode);
      setNodes(laidOut);
      setData(body);
      setEdges(body.edges.map((e) => ({ ...e, style: EDGE_STYLE })));
      requestAnimationFrame(() => fitView({ padding: 0.1 }));
    }
    setLoading(false);
  }, [pivot, type, minConfidence, showAll, mode, setNodes, setEdges, fitView]);

  useEffect(() => { load(); }, [load]);

  // Adjacency for neighbourhood highlighting.
  const adjacency = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    for (const e of data?.edges ?? []) {
      if (!adj.has(e.source)) adj.set(e.source, new Set());
      if (!adj.has(e.target)) adj.set(e.target, new Set());
      adj.get(e.source)!.add(e.target);
      adj.get(e.target)!.add(e.source);
    }
    return adj;
  }, [data]);

  const nodeById = useMemo(() => new Map((data?.nodes ?? []).map((n) => [n.id, n])), [data]);

  // Selecting a node lights up what it connects to two steps out along the
  // case -> host -> value chain: a value shows its hosts and their cases, a
  // host its cases and values, a case its hosts and their values.
  const neighbourhood = useMemo(() => {
    if (!selectedId) return null;
    const out = new Set<string>([selectedId]);
    for (const n1 of adjacency.get(selectedId) ?? []) {
      out.add(n1);
      const selType = nodeById.get(selectedId)?.type;
      for (const n2 of adjacency.get(n1) ?? []) {
        if (nodeById.get(n2)?.type !== selType) out.add(n2);
      }
    }
    return out;
  }, [selectedId, adjacency, nodeById]);

  const matches = useMemo(() => {
    const term = find.trim().toLowerCase();
    if (!term) return new Set<string>();
    return new Set((data?.nodes ?? []).filter((n) => n.data.label.toLowerCase().includes(term)).map((n) => n.id));
  }, [find, data]);

  useEffect(() => {
    setNodes((ns) => ns.map((n) => ({
      ...n,
      data: {
        ...n.data,
        selected: n.id === selectedId,
        matched: matches.has(n.id),
        dimmed: neighbourhood ? !neighbourhood.has(n.id) : matches.size > 0 ? !matches.has(n.id) : false,
      },
    })));
    setEdges((es) => es.map((e) => {
      const active = !!neighbourhood && neighbourhood.has(e.source) && neighbourhood.has(e.target);
      return { ...e, style: active ? EDGE_STYLE_ACTIVE : EDGE_STYLE, animated: active, zIndex: active ? 1 : 0 };
    }));
  }, [neighbourhood, matches, selectedId, setNodes, setEdges]);

  const focus = useCallback((id: string) => {
    setSelectedId(id);
    const ids = new Set<string>([id, ...(adjacency.get(id) ?? [])]);
    requestAnimationFrame(() => fitView({ nodes: Array.from(ids).map((n) => ({ id: n })), padding: 0.3, duration: 400, maxZoom: 1.2 }));
  }, [adjacency, fitView]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setSelectedId(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const selected = selectedId ? nodeById.get(selectedId) ?? null : null;
  const matchList = Array.from(matches);
  const typesPresent = useMemo(
    () => Array.from(new Set((data?.nodes ?? []).flatMap((n) => (n.type === "correlation" ? [n.data.correlationType] : [])))),
    [data],
  );

  return (
    <div className="flex h-screen flex-col">
      {/* Header */}
      <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2 border-b border-zinc-800 bg-zinc-950 px-6 py-3">
        <Link href="/intelligence/correlations" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300">
          <ArrowLeft className="h-4 w-4" /> Correlations
        </Link>
        <span className="text-sm font-semibold text-zinc-200">Cross-Case Correlation Graph</span>
        {pivot && (
          <Link href="/intelligence/correlations/graph" className="inline-flex items-center gap-1 rounded border border-teal-700 px-2 py-0.5 text-xs text-teal-400 hover:bg-teal-900/30" title="Clear pivot">
            Pivoted on: {pivot} <X className="h-3 w-3" />
          </Link>
        )}
        {data && (
          <span className="text-xs text-zinc-500">
            {data.shown} {showAll ? "correlations" : "significant correlations"}
            {data.capped && <span className="text-amber-500"> (top {data.cap} of {showAll ? data.totalAll : data.totalSignificant})</span>}
            {!showAll && data.totalAll > data.totalSignificant && <> · {data.totalAll - data.totalSignificant} below threshold hidden</>}
          </span>
        )}
        {loading && <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />}
      </div>

      {/* Toolbar */}
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-zinc-800 bg-zinc-950/60 px-6 py-2 text-xs">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <input
            value={find}
            onChange={(e) => setFind(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && matchList.length > 0) focus(matchList[0]); }}
            placeholder="Find host, case or value…"
            className="w-60 rounded border border-zinc-700 bg-zinc-900 py-1 pl-7 pr-2 text-zinc-200 placeholder:text-zinc-600 focus:border-zinc-500 focus:outline-none"
          />
        </div>
        {find && <span className="text-zinc-500">{matchList.length} match{matchList.length === 1 ? "" : "es"}{matchList.length > 0 && " · Enter to jump"}</span>}

        <select value={type} onChange={(e) => setType(e.target.value)} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-200">
          <option value="">All types</option>
          {Object.entries(CORRELATION_TYPE_STYLE).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>

        <div className="flex overflow-hidden rounded border border-zinc-700">
          {CONF_PRESETS.map((p) => (
            <button
              key={p.value}
              onClick={() => setMinConfidence(p.value)}
              className={`px-2 py-1 ${minConfidence === p.value ? "bg-zinc-700 text-zinc-100" : "text-zinc-400 hover:bg-zinc-800"}`}
            >
              {p.label}
            </button>
          ))}
        </div>

        <label className="inline-flex items-center gap-1.5 text-zinc-400">
          <input type="checkbox" checked={!showAll} onChange={(e) => setShowAll(!e.target.checked)} className="accent-indigo-500" />
          Significant only
        </label>

        <div className="flex overflow-hidden rounded border border-zinc-700">
          {(["columns", "clusters"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-2 py-1 capitalize ${mode === m ? "bg-zinc-700 text-zinc-100" : "text-zinc-400 hover:bg-zinc-800"}`}
            >
              {m}
            </button>
          ))}
        </div>

        <div className="ml-auto flex flex-wrap items-center gap-3 text-zinc-500">
          {typesPresent.map((t) => {
            const s = correlationTypeStyle(t);
            return <span key={t} className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-sm" style={{ background: s.color }} />{s.label}</span>;
          })}
          <span className="inline-flex items-center gap-1"><ShieldAlert className="h-3 w-3 text-red-400" />Known IOC</span>
        </div>
      </div>

      <div className="relative flex flex-1 overflow-hidden">
        <div className="flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={(_, n) => focus(n.id)}
            onPaneClick={() => setSelectedId(null)}
            nodesConnectable={false}
            minZoom={0.05}
            colorMode="dark"
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#27272a" gap={20} />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeColor={(n) => miniMapColor(n.type)} />
          </ReactFlow>
          {!loading && data && data.shown === 0 && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm text-zinc-500">
              {showAll || data.totalAll === 0 ? "No correlations match these filters." : "No significant correlations. Untick “Significant only” to see the rest."}
            </div>
          )}
        </div>

        {selected && (
          <DetailPanel node={selected} nodeById={nodeById} adjacency={adjacency} onSelect={focus} onClose={() => setSelectedId(null)} />
        )}
      </div>
    </div>
  );
}

// --- Detail panel ------------------------------------------------------------
function DetailPanel({ node, nodeById, adjacency, onSelect, onClose }: {
  node: ApiNode;
  nodeById: Map<string, ApiNode>;
  adjacency: Map<string, Set<string>>;
  onSelect: (id: string) => void;
  onClose: () => void;
}) {
  const neighbours = (type: ApiNode["type"]) =>
    Array.from(adjacency.get(node.id) ?? []).map((id) => nodeById.get(id)).filter((n): n is ApiNode => n?.type === type);
  // Cases touching a value are two hops away (value -> host -> case).
  const casesOf = (ids: string[]) => ids.map((id) => nodeById.get(`case-${id}`)).filter((n): n is ApiNode => !!n);

  return (
    <aside className="w-80 shrink-0 overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-4 text-sm">
      <div className="mb-3 flex items-start justify-between gap-2">
        <span className="text-[11px] uppercase tracking-wide text-zinc-500">
          {node.type === "correlation" ? correlationTypeStyle(node.data.correlationType).label : node.type}
        </span>
        <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300" title="Close (Esc)"><X className="h-4 w-4" /></button>
      </div>

      {node.type === "correlation" && (
        <>
          <div className="mb-3 break-all font-mono text-xs text-zinc-100">{node.data.label}</div>
          <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-zinc-500">Confidence</dt><dd className="text-zinc-200">{node.data.confidence}</dd>
            <dt className="text-zinc-500">Hosts</dt><dd className="text-zinc-200">{node.data.hostCount}</dd>
            {node.data.prevalence && (
              <><dt className="text-zinc-500">Seen on</dt><dd className="text-zinc-200">{node.data.prevalence.hosts} of {node.data.prevalence.of} hosts on record</dd></>
            )}
          </dl>
          {node.data.knownIoc && (
            <div className="mb-4 rounded border border-red-800 bg-red-950/40 p-2 text-xs text-red-300">
              Known IOC
              {node.data.knownIoc.threatType && <> · {node.data.knownIoc.threatType}</>}
              {node.data.knownIoc.malwareFamily && <> · {node.data.knownIoc.malwareFamily}</>}
              {node.data.knownIoc.reputation !== null && <> · reputation {node.data.knownIoc.reputation}</>}
            </div>
          )}
          <NodeList title="Hosts" items={neighbours("host")} onSelect={onSelect} />
          <NodeList title="Cases" items={casesOf(node.data.caseIds)} onSelect={onSelect} />
          <Link
            href={`/intelligence/correlations/graph?q=${encodeURIComponent(node.data.label)}&type=${node.data.correlationType}`}
            className="mt-2 inline-flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300"
          >
            Pivot graph on this value
          </Link>
        </>
      )}

      {node.type === "host" && (
        <>
          <div className="mb-4 font-mono text-sm text-zinc-100">{node.data.label}</div>
          <NodeList title="Cases" items={neighbours("case")} onSelect={onSelect} />
          <NodeList title="Shared values" items={neighbours("correlation")} onSelect={onSelect} />
        </>
      )}

      {node.type === "case" && (
        <>
          <div className="mb-1 font-mono text-xs text-zinc-500">{formatCaseNumber(node.data.caseSeq)}</div>
          <div className="mb-2 text-zinc-100">{node.data.label}</div>
          <div className="mb-4 text-xs text-zinc-500">{node.data.severity} · {node.data.status}</div>
          <Link href={`/cases/${node.data.caseId}`} className="mb-4 inline-flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300">
            Open case <ExternalLink className="h-3 w-3" />
          </Link>
          <NodeList title="Hosts" items={neighbours("host")} onSelect={onSelect} />
        </>
      )}
    </aside>
  );
}

function NodeList({ title, items, onSelect }: { title: string; items: ApiNode[]; onSelect: (id: string) => void }) {
  if (items.length === 0) return null;
  return (
    <div className="mb-4">
      <div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">{title} ({items.length})</div>
      <ul className="space-y-0.5">
        {items.map((n) => (
          <li key={n.id}>
            <button onClick={() => onSelect(n.id)} className="flex w-full items-center gap-1.5 rounded px-1.5 py-0.5 text-left text-xs text-zinc-300 hover:bg-zinc-800">
              {n.type === "correlation" && (
                <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: correlationTypeStyle(n.data.correlationType).color }} />
              )}
              <span className="truncate font-mono">{n.type === "case" ? `${formatCaseNumber(n.data.caseSeq)} ${n.data.label}` : n.data.label}</span>
              {n.type === "correlation" && <span className="ml-auto shrink-0 text-zinc-500">{n.data.confidence}</span>}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function CorrelationsGraphPage() {
  return (
    <Suspense>
      <ReactFlowProvider>
        <CorrelationsGraph />
      </ReactFlowProvider>
    </Suspense>
  );
}
