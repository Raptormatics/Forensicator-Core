"use client";

import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow
} from "@/components/ui/table";
import { humanizeKey, jsonValueToDisplay } from "@/lib/utils";
import type { EvidenceRow } from "@/types/findings";

type EvidenceTableProps = {
  rows: EvidenceRow[];
  initialQuery?: string;
  maxInitialRows?: number;
};

export function EvidenceTable({ rows, initialQuery = "", maxInitialRows = 250 }: EvidenceTableProps) {
  const [query, setQuery] = useState(initialQuery);
  const columns = useMemo(() => deriveColumns(rows), [rows]);

  const filteredRows = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    if (!normalizedQuery) {
      return rows;
    }

    return rows.filter((row) =>
      Object.values(row).some((value) => jsonValueToDisplay(value).toLowerCase().includes(normalizedQuery))
    );
  }, [query, rows]);

  const visibleRows = filteredRows.slice(0, maxInitialRows);

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-6 text-sm text-zinc-500">
        No evidence rows.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/55">
      <div className="flex flex-col gap-3 border-b border-zinc-800 p-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold text-zinc-100">Evidence</h3>
          <p className="text-xs text-zinc-500">
            {filteredRows.length} of {rows.length} rows
          </p>
        </div>
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search evidence"
            className="pl-9"
          />
        </div>
      </div>
      <div className="analyst-scrollbar max-h-[38rem] overflow-auto">
        <Table className="min-w-max">
          <TableHead className="sticky top-0 z-10">
            <TableRow>
              {columns.map((column) => (
                <TableHeaderCell key={column}>{humanizeKey(column)}</TableHeaderCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {visibleRows.map((row, rowIndex) => (
              <TableRow key={rowIndex} className="hover:bg-zinc-900/60">
                {columns.map((column) => (
                  <TableCell key={column}>
                    <span className="line-clamp-3 break-words font-mono text-xs leading-5">
                      {jsonValueToDisplay(row[column])}
                    </span>
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {filteredRows.length > visibleRows.length ? (
        <div className="border-t border-zinc-800 px-3 py-2 text-xs text-zinc-500">
          Showing first {visibleRows.length} matching rows.
        </div>
      ) : null}
    </div>
  );
}

function deriveColumns(rows: EvidenceRow[]) {
  const order = new Map<string, number>();
  const frequency = new Map<string, number>();

  rows.forEach((row) => {
    Object.keys(row).forEach((key) => {
      if (!order.has(key)) {
        order.set(key, order.size);
      }
      frequency.set(key, (frequency.get(key) ?? 0) + 1);
    });
  });

  return Array.from(order.keys()).sort((left, right) => {
    const frequencyDelta = (frequency.get(right) ?? 0) - (frequency.get(left) ?? 0);
    return frequencyDelta || (order.get(left) ?? 0) - (order.get(right) ?? 0);
  });
}
