import type { z } from "zod";
import type { findingSchema } from "@/lib/schemas/finding";
import type { JsonObject } from "./json";

export type FindingJson = z.infer<typeof findingSchema>;
export type EvidenceRow = JsonObject;

export type ParsedUploadFinding = {
  /** Normalised path inside the ZIP (e.g. investigation/network/dns-cache-finding.json) */
  path: string;
  /**
   * Folder name one level above the file, treated as the evidence category.
   * Populated only when the file lives inside a sub-directory
   * (e.g. "network", "files", "events").
   * Absent for top-level files or when the folder cannot be determined.
   */
  sourceCategory?: string;
  data: FindingJson;
};

export type UploadIssue = {
  path: string;
  message: string;
  issues?: unknown;
};
