import type { FindingJson } from "@/types/findings";
import type { JsonObject, JsonValue } from "@/types/json";
import { normalizeSeverity } from "@/lib/severity";
import { extractHostname } from "./finding-index";

export function countBy<T extends string>(values: T[]) {
  return values.reduce<Record<T, number>>(
    (counts, value) => {
      counts[value] = (counts[value] ?? 0) + 1;
      return counts;
    },
    {} as Record<T, number>
  );
}

export function deriveInvestigationTitle(metadata: JsonObject, firstFinding: FindingJson | undefined) {
  const explicit =
    metadataString(metadata, "title") ??
    metadataString(metadata, "case_name") ??
    metadataString(metadata, "caseName") ??
    metadataString(metadata, "investigation_name");

  if (explicit) {
    return explicit;
  }

  const hostname = firstFinding ? extractHostname(firstFinding) : undefined;
  const collectedAt =
    (firstFinding ? metadataString(firstFinding.metadata, "collection_time") : undefined) ??
    metadataString(metadata, "collection_time") ??
    metadataString(metadata, "created_at");

  if (hostname && collectedAt) {
    return `${hostname} investigation ${collectedAt}`;
  }

  return hostname ? `${hostname} investigation` : "Forensicator investigation";
}

export function metadataString(metadata: JsonObject | undefined, key: string) {
  if (!metadata) return undefined;
  const value = metadata[key];
  return stringValue(value);
}

export function duplicateFindingIds(findings: FindingJson[]) {
  const seen = new Set<string>();
  const duplicates = new Set<string>();

  for (const finding of findings) {
    const fid = finding.finding_id ?? "";
    if (!fid) continue;
    if (seen.has(fid)) {
      duplicates.add(fid);
    }
    seen.add(fid);
  }

  return Array.from(duplicates);
}

export function severityCounts(findings: FindingJson[]) {
  return countBy(findings.map((finding) => normalizeSeverity(finding.severity ?? "Informational")));
}

export function categoryCounts(findings: FindingJson[]) {
  return countBy(findings.map((finding) => finding.category ?? "unknown"));
}

function stringValue(value: JsonValue | undefined) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
