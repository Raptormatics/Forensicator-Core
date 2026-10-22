"use client";

import type { ArchiveType } from "@/lib/cases/archive";

/**
 * Enterprise slot on each Archive page row — Core stub, renders nothing.
 * The Enterprise overlay replaces this file with archive storage actions
 * (export to off-site storage, retrieve, export status). Keep the props
 * identical to the overlay's version.
 */
export type ArchiveItemActionsProps = { type: ArchiveType; id: string; onChanged: () => void };

export function ArchiveItemEnterpriseActions(_props: ArchiveItemActionsProps) {
  return null;
}
