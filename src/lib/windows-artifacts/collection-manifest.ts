/**
 * The Live Forensicator collector's CollectionManifest
 * (WindowsArtifacts\CollectionManifest\artifact-collection-manifest.json):
 * one record per attempted acquisition — Collected / Skipped / Failed /
 * Deduplicated / IntegrityMismatch / CollectedHashFailed — with the
 * collector-side SHA-256 of every collected file. Written by PowerShell's
 * Set-Content -Encoding UTF8, so it starts with a BOM.
 *
 * Used two ways at upload time (see the uploads route):
 *   1. Each uploaded file's Core-computed SHA-256 is compared against the
 *      manifest's hash for the same WindowsArtifacts-relative path —
 *      chain-of-custody check that the bytes Core parses are the bytes the
 *      collector acquired.
 *   2. Every non-"Collected" record is kept on the upload, so acquisition
 *      gaps (a hive that failed to save, a locked file, a size-capped dump)
 *      show up next to the results instead of being silently absent.
 */
import { windowsArtifactsRelativePath } from "./collector-layout";

interface RawManifestRecord {
  TimestampUtc?: string;
  Label?: string;
  SourcePath?: string;
  DestinationPath?: string;
  Status?: string;
  SizeBytes?: number;
  SHA256?: string;
  DuplicateOf?: string;
  Note?: string;
}

export interface ManifestIssue {
  status: string;
  label: string;
  sourcePath: string;
  destinationPath: string;
  sizeBytes: number | null;
  duplicateOf: string | null;
  note: string | null;
  timestampUtc: string | null;
}

export interface StoredCollectionManifest {
  totalRecords: number;
  statusCounts: Record<string, number>;
  collectionStartUtc: string | null;
  collectionEndUtc: string | null;
  /** Non-"Collected" records, capped at ISSUE_CAP (issuesTruncated says so). */
  issues: ManifestIssue[];
  issuesTruncated: boolean;
}

export interface ParsedCollectionManifest {
  stored: StoredCollectionManifest;
  /** Lower-cased WindowsArtifacts-relative path -> upper-case SHA-256. */
  hashByPath: Map<string, string>;
}

const ISSUE_CAP = 5000;

export function manifestPathKey(rawPath: string): string | null {
  const rel = windowsArtifactsRelativePath(rawPath);
  return rel ? rel.toLowerCase() : null;
}

export function parseCollectionManifest(buffer: Buffer): ParsedCollectionManifest {
  const text = buffer.toString("utf8").replace(/^﻿/, "");
  const parsed = JSON.parse(text) as unknown;
  // ConvertTo-Json emits a bare object (not a 1-element array) when the
  // manifest holds a single record.
  const records = (Array.isArray(parsed) ? parsed : [parsed]) as RawManifestRecord[];

  const statusCounts: Record<string, number> = {};
  const issues: ManifestIssue[] = [];
  const hashByPath = new Map<string, string>();
  let start: string | null = null;
  let end: string | null = null;

  for (const r of records) {
    if (!r || typeof r !== "object") continue;
    const status = String(r.Status ?? "Unknown");
    statusCounts[status] = (statusCounts[status] ?? 0) + 1;
    const ts = r.TimestampUtc ? String(r.TimestampUtc) : null;
    if (ts) {
      if (!start || ts < start) start = ts;
      if (!end || ts > end) end = ts;
    }

    const key = r.DestinationPath ? manifestPathKey(String(r.DestinationPath)) : null;
    if (status === "Collected" || status === "IntegrityMismatch") {
      if (key && r.SHA256) hashByPath.set(key, String(r.SHA256).toUpperCase());
    }
    if (status !== "Collected" && issues.length < ISSUE_CAP) {
      issues.push({
        status,
        label: String(r.Label ?? ""),
        sourcePath: String(r.SourcePath ?? ""),
        destinationPath: key ?? String(r.DestinationPath ?? ""),
        sizeBytes: typeof r.SizeBytes === "number" && r.SizeBytes > 0 ? r.SizeBytes : null,
        duplicateOf: r.DuplicateOf ? (manifestPathKey(String(r.DuplicateOf)) ?? String(r.DuplicateOf)) : null,
        note: r.Note ? String(r.Note) : null,
        timestampUtc: ts,
      });
    }
  }

  const issueTotal = records.length - (statusCounts["Collected"] ?? 0);
  return {
    stored: {
      totalRecords: records.length,
      statusCounts,
      collectionStartUtc: start,
      collectionEndUtc: end,
      issues,
      issuesTruncated: issueTotal > issues.length,
    },
    hashByPath,
  };
}

export type IntegrityStatus = "verified" | "mismatch" | "not_in_manifest";

export function verifyAgainstManifest(
  manifest: ParsedCollectionManifest | null,
  relPath: string | null,
  sha256: string
): { integrityStatus: IntegrityStatus | null; manifestSha256: string | null } {
  if (!manifest) return { integrityStatus: null, manifestSha256: null };
  const expected = relPath ? manifest.hashByPath.get(relPath.toLowerCase()) : undefined;
  if (!expected) return { integrityStatus: "not_in_manifest", manifestSha256: null };
  return {
    integrityStatus: expected === sha256.toUpperCase() ? "verified" : "mismatch",
    manifestSha256: expected,
  };
}
