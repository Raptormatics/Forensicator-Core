import type { FindingJson } from "@/types/findings";
import type { JsonObject, JsonValue } from "@/types/json";
import { normalizeSeverity } from "@/lib/severity";

export function extractHostname(finding: FindingJson) {
  const host = finding.host as JsonObject | undefined;
  return stringValue(host?.hostname) ?? stringValue(host?.host_name) ?? stringValue(finding.metadata?.hostname);
}

export function extractRiskScore(finding: FindingJson) {
  const score = finding.risk?.score;

  if (typeof score === "number" && Number.isFinite(score)) {
    return Math.trunc(score);
  }

  if (typeof score === "string") {
    const parsed = Number.parseInt(score, 10);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

export function buildFindingSearchText(finding: FindingJson) {
  const tokens: string[] = [
    finding.finding_id ?? "",
    finding.finding_type,
    finding.category ?? "",
    normalizeSeverity(finding.severity ?? "Informational"),
    extractHostname(finding) ?? ""
  ];

  // Include finding-level tags (e.g. ["malware", "lateral-movement"])
  const tags = (finding as Record<string, unknown>).findingtags;
  if (Array.isArray(tags)) {
    for (const t of tags) if (typeof t === "string") tokens.push(t);
  }

  collectStrings(finding.summary ?? {}, tokens, 8000);
  collectStrings(finding.risk ?? {}, tokens, 8000);
  collectStrings(finding.mitre ?? [], tokens, 8000);
  collectStrings(finding.timeline ?? [], tokens, 8000);
  collectStrings(finding.evidence, tokens, 50000);

  return Array.from(new Set(tokens.filter(Boolean).map((token) => token.trim())))
    .join(" ")
    .slice(0, 100000);
}

function collectStrings(value: JsonValue, tokens: string[], budget: number) {
  if (budget <= 0) return;

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    tokens.push(String(value).slice(0, budget));
    return;
  }

  if (!value) return;

  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, tokens, budget - tokens.join(" ").length);
      if (tokens.join(" ").length > budget) return;
    }
    return;
  }

  for (const [key, item] of Object.entries(value)) {
    tokens.push(key);
    collectStrings(item, tokens, budget - tokens.join(" ").length);
    if (tokens.join(" ").length > budget) return;
  }
}

function stringValue(value: JsonValue | undefined) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
