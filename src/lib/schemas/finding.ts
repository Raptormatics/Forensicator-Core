import { z } from "zod";
import { jsonObjectSchema, jsonValueSchema } from "./json";
import { normalizeSeverity } from "@/lib/severity";

export const aiAnalysisSchema = z
  .object({
    status: z.string().min(1).optional().nullable(),
    summary: z.string().optional().nullable(),
    anomalies: z.array(jsonValueSchema).optional(),
    confidence: z.number().min(0).max(1).optional().nullable()
  })
  .passthrough();

export const mitreMappingSchema = z.record(jsonValueSchema);
export const timelineEventSchema = z.record(jsonValueSchema);
export const evidenceRowSchema = z.record(jsonValueSchema);

export const findingSchema = z
  .object({
    finding_id:   z.string().min(1).optional(),   // auto-generated if absent
    finding_type: z.string().min(1, "finding_type is required"),
    category:     z.string().min(1).optional(),   // derived from folder name if absent
    severity:     z.string().min(1).optional(),   // derived from risk.level if absent
    host:         jsonObjectSchema.optional(),
    source:       jsonObjectSchema.optional(),
    summary:      jsonObjectSchema.optional(),
    risk:         jsonObjectSchema.optional(),
    mitre:        z.array(mitreMappingSchema).optional(),
    timeline:     z.array(timelineEventSchema).optional(),
    ai_analysis:  aiAnalysisSchema.optional(),
    evidence:     z.array(evidenceRowSchema).default([]),
    metadata:     jsonObjectSchema.optional(),
    // Finding-level tags emitted by the collector (e.g. ["malware", "lateral-movement"])
    findingtags:  z.array(z.string()).optional(),
  })
  .passthrough();

export const findingsArraySchema = z.array(findingSchema);

export function parseFindingJson(input: unknown) {
  return findingSchema.parse(input);
}

export function coerceFindingJson(input: unknown) {
  const parsed = findingSchema.safeParse(input);
  return parsed.success ? parsed.data : null;
}

/**
 * Called by the zip parser to fill in fields that Forensicator collector
 * output files may omit (finding_id, category, severity, etc.).
 */
export function normalizeParsedFinding(
  raw: z.infer<typeof findingSchema>,
  sourceCategory?: string
): z.infer<typeof findingSchema> & {
  finding_id: string;
  category: string;
  severity: string;
  mitre: z.infer<typeof mitreMappingSchema>[];
  timeline: z.infer<typeof timelineEventSchema>[];
  ai_analysis: z.infer<typeof aiAnalysisSchema>;
  evidence: z.infer<typeof evidenceRowSchema>[];
} {
  const risk = raw.risk as Record<string, unknown> | undefined;
  const severityFromRisk = (() => {
    const lvl = risk?.level ?? risk?.Level;
    if (typeof lvl === "string" && lvl.length > 0) return normalizeSeverity(lvl);
    const score = Number(risk?.score ?? risk?.Score ?? 0);
    if (score >= 90) return "Important";
    if (score >= 70) return "Notable";
    if (score >= 40) return "Interesting";
    if (score > 0)   return "Informational";
    return undefined;
  })();

  return {
    ...raw,
    finding_id:  raw.finding_id  ?? `${raw.finding_type.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${Date.now()}`,
    category:    raw.category    ?? sourceCategory ?? "general",
    severity:    raw.severity    ?? severityFromRisk ?? "Informational",
    mitre:       raw.mitre       ?? [],
    timeline:    raw.timeline    ?? [],
    ai_analysis: raw.ai_analysis ?? { status: "pending" },
    evidence:    raw.evidence    ?? [],
    findingtags: raw.findingtags ?? [],
  } as ReturnType<typeof normalizeParsedFinding>;
}
