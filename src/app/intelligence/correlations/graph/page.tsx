"use client";

import { useEffect, useCallback, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { nodeStyle, miniMapColor } from "@/lib/graph/node-style";

function CorrelationsGraph() {
  const searchParams = useSearchParams();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [capped, setCapped] = useState<{ capped: boolean; cap: number } | null>(null);

  const load = useCallback(async () => {
    const params = new URLSearchParams();
    const q = searchParams.get("q");
    const type = searchParams.get("type");
    if (q) params.set("q", q);
    if (type) params.set("type", type);
    const res = await fetch(`/api/correlations/graph${params.toString() ? `?${params}` : ""}`);
    if (res.ok) {
      const data = await res.json();
      const styledNodes: Node[] = (data.nodes as Node[]).map((n) => ({
        ...n,
        style: nodeStyle(n.type ?? "", n.data as Record<string, unknown>),
        data: { ...n.data, label: (n.data as Record<string, unknown>).label as string },
      }));
      setNodes(styledNodes);
      setEdges(data.edges as Edge[]);
      setCapped({ capped: data.capped, cap: data.cap });
    }
  }, [setNodes, setEdges, searchParams]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="flex flex-col h-screen">
      <div className="flex items-center gap-4 border-b border-zinc-800 bg-zinc-950 px-6 py-3 shrink-0">
        <Link href="/intelligence/correlations" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300">
          <ArrowLeft className="h-4 w-4" /> Back to Correlations
        </Link>
        <span className="text-sm font-semibold text-zinc-200">Cross-Case Correlation Graph</span>
        {searchParams.get("q") && (
          <span className="text-xs text-teal-400">Pivoted on: {searchParams.get("q")}</span>
        )}
        {capped?.capped && (
          <span className="text-xs text-amber-500">Showing top {capped.cap} correlations by confidence</span>
        )}
      </div>
      <div className="flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          colorMode="dark"
        >
          <Background color="#27272a" gap={20} />
          <Controls />
          <MiniMap nodeColor={(n) => miniMapColor(n.type)} />
        </ReactFlow>
      </div>
    </div>
  );
}

export default function CorrelationsGraphPage() {
  return (
    <Suspense>
      <CorrelationsGraph />
    </Suspense>
  );
}
