import AdmZip from "adm-zip";
import { ZodError } from "zod";
import { findingSchema, normalizeParsedFinding } from "@/lib/schemas/finding";
import { investigationMetadataSchema, uploadMetadataSchema } from "@/lib/schemas/upload";
import type { InvestigationMetadata } from "@/lib/schemas/upload";
import type { JsonObject } from "@/types/json";
import type { ParsedUploadFinding, UploadIssue } from "@/types/findings";
import { convertAdSideFile, isAdSideFile } from "./ad-side-files";

export class UploadValidationError extends Error {
  constructor(
    message: string,
    readonly issues: UploadIssue[] = []
  ) {
    super(message);
    this.name = "UploadValidationError";
  }
}

export type ParsedInvestigationZip = {
  /** Raw JSON object from metadata.json, validated through jsonObjectSchema. */
  metadata: JsonObject;
  /** Typed interpretation of the well-known metadata.json fields. */
  investigationMetadata: InvestigationMetadata;
  findings: ParsedUploadFinding[];
  /**
   * Non-fatal per-file validation warnings — files that failed schema parsing
   * were skipped but the rest of the upload continues.
   */
  skippedFiles: UploadIssue[];
};

export function parseInvestigationZip(buffer: Buffer): ParsedInvestigationZip {
  let zip: AdmZip;

  try {
    zip = new AdmZip(buffer);
  } catch {
    throw new UploadValidationError("Uploaded file is not a readable ZIP archive.", [
      {
        path: "file",
        message: "Expected a valid ZIP archive."
      }
    ]);
  }

  const entries = zip.getEntries().filter((entry) => !entry.isDirectory);

  const metadata = readMetadata(entries);
  const findingEntries = entries.filter((entry) => isFindingJsonPath(entry.entryName));
  // Domain-controller CSV/JSON/text side files (investigation\ad\*), turned
  // into findings after the real finding files so they can borrow a host.
  const adSideEntries = entries.filter((entry) => isAdSideFile(normalizeZipPath(entry.entryName)));

  if (findingEntries.length === 0) {
    throw new UploadValidationError("No finding JSON files were found in the uploaded archive.", [
      {
        path: "investigation/<category>/*.json",
        message:
          "Expected JSON findings inside category sub-folders (e.g. investigation/network/dns-cache-finding.json) " +
          "or files ending in -finding.json anywhere in the archive."
      }
    ]);
  }

  const findings: ParsedUploadFinding[] = [];
  const skippedFiles: UploadIssue[] = [];

  for (const entry of findingEntries) {
    const path = normalizeZipPath(entry.entryName);
    const sourceCategory = extractSourceCategory(path);

    try {
      const json = JSON.parse(entry.getData().toString("utf8")) as unknown;
      const raw  = findingSchema.parse(json);
      const data = normalizeParsedFinding(raw, sourceCategory);
      findings.push({ path, sourceCategory, data });
    } catch (error) {
      // Non-fatal: skip this file and continue with the rest.
      skippedFiles.push({
        path,
        message: error instanceof SyntaxError
          ? `Invalid JSON syntax in ${path}`
          : `Schema validation failed for ${path}: ${error instanceof Error ? error.message : String(error)}`,
        issues: error instanceof ZodError ? error.flatten() : undefined
      });
      console.warn("[zip] Skipping finding file:", path, error instanceof Error ? error.message : error);
    }
  }

  const host = findings.find((f) => f.data.host)?.data.host as JsonObject | undefined;
  for (const entry of adSideEntries) {
    const path = normalizeZipPath(entry.entryName);
    try {
      findings.push(convertAdSideFile(path, entry.getData().toString("utf8"), host));
    } catch (error) {
      skippedFiles.push({ path, message: `Could not convert AD side file ${path}: ${error instanceof Error ? error.message : String(error)}` });
      console.warn("[zip] Skipping AD side file:", path, error instanceof Error ? error.message : error);
    }
  }

  // Only hard-fail when NOTHING could be parsed at all.
  if (findings.length === 0) {
    throw new UploadValidationError(
      skippedFiles.length > 0
        ? "All finding files failed validation — see issues for details."
        : "No finding JSON files were found in the uploaded archive.",
      skippedFiles
    );
  }

  return { metadata, investigationMetadata: readInvestigationMetadata(entries), findings, skippedFiles };
}

function readMetadata(entries: AdmZip.IZipEntry[]): JsonObject {
  const entry = entries.find((candidate) => normalizeZipPath(candidate.entryName).endsWith("metadata.json"));

  if (!entry) {
    return {};
  }

  try {
    return uploadMetadataSchema.parse(JSON.parse(entry.getData().toString("utf8")));
  } catch (error) {
    throw new UploadValidationError("metadata.json failed validation.", [
      {
        path: normalizeZipPath(entry.entryName),
        message: error instanceof SyntaxError ? "Invalid JSON syntax." : "Metadata must be a JSON object.",
        issues: error instanceof ZodError ? error.flatten() : undefined
      }
    ]);
  }
}

/**
 * Parses the metadata.json file using the typed investigationMetadataSchema.
 * Failures are non-fatal — we return an empty object so an imperfect metadata.json
 * doesn't block the entire upload.
 */
function readInvestigationMetadata(entries: AdmZip.IZipEntry[]): InvestigationMetadata {
  const entry = entries.find((candidate) => normalizeZipPath(candidate.entryName).endsWith("metadata.json"));

  if (!entry) {
    return {};
  }

  try {
    const raw = JSON.parse(entry.getData().toString("utf8")) as unknown;
    const parsed = investigationMetadataSchema.safeParse(raw);
    return parsed.success ? parsed.data : {};
  } catch {
    return {};
  }
}

/**
 * Returns true when a ZIP entry looks like a finding JSON file.
 *
 * Accepted paths:
 *   • Any .json file nested (at any depth) under an "investigation/" or "findings/" folder,
 *     EXCEPT metadata.json files (which are ingested separately).
 *   • Any .json file whose name ends with "-finding.json" (backward-compatible flat archives).
 *
 * This deliberately accepts arbitrarily deep structures such as:
 *   HOSTNAME/investigation/network/dns-cache-finding.json
 *   investigation/files/usb.json
 *   findings/sigma-findings.json
 */
function isFindingJsonPath(path: string) {
  const normalized = normalizeZipPath(path);

  if (!normalized.endsWith(".json")) {
    return false;
  }

  // Always skip metadata files regardless of nesting.
  const filename = normalized.split("/").pop() ?? "";
  if (filename === "metadata.json") {
    return false;
  }
  // case-summary.json is the collector's own roll-up of the findings
  // themselves (Core computes its own); AD side files are converted
  // separately (ad-side-files.ts) — neither is a finding-schema object.
  if (filename === "case-summary.json" || isAdSideFile(normalized)) {
    return false;
  }

  const lower = normalized.toLowerCase();
  const parts = lower.split("/");

  // Accept anything inside investigation/ or findings/ at any depth (at least one nesting level).
  for (const pivot of ["investigation", "findings"]) {
    const idx = parts.findIndex((part) => part === pivot);
    if (idx >= 0 && parts.length > idx + 1) {
      return true;
    }
  }

  // Backward-compatible: files whose name ends with -finding.json.
  // Also accept the plural -findings.json — the collector's Sigma output
  // (sigma-findings.json) is the one finding file that uses this form while
  // every other category uses the singular, and a single naming
  // inconsistency shouldn't silently drop an entire finding category.
  return normalized.endsWith("-finding.json") || normalized.endsWith("-findings.json");
}

/**
 * Extracts the immediate parent folder name of a finding file to use as its
 * source category (e.g. "network", "files", "events").
 *
 * Returns undefined for top-level files or when no meaningful folder exists.
 */
function extractSourceCategory(normalizedPath: string): string | undefined {
  const parts = normalizedPath.replace(/\\/g, "/").split("/");

  // Need at least <folder>/<file> — skip paths with no parent folder.
  if (parts.length < 2) {
    return undefined;
  }

  const parentFolder = parts[parts.length - 2];

  // Do not report root-level anchor folders as a category.
  const anchors = new Set(["investigation", "findings", ""]);
  if (anchors.has(parentFolder.toLowerCase())) {
    return undefined;
  }

  return parentFolder;
}

function normalizeZipPath(path: string) {
  return path.replace(/\\/g, "/").replace(/^\/+/, "");
}
