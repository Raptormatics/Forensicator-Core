/**
 * Builds the analyst-assist prompt from whatever's actually in a Finding's
 * stored JSON, and parses the model's response back into structured fields.
 *
 * Findings collected before the AI.md enrichment work only have the legacy
 * ~8-field shape (summary/mitre/host/source/evidence/severity/ai_analysis/
 * metadata/risk); newly-collected ones carry the full 19-section shape
 * (explanation/risk_scoring/detection/evidence_quality/ioc/relationships/
 * timeline_context/attack_story/threat_intelligence/enrichment/ai/
 * human_context/recommendations/analyst on top of that). This pulls
 * whichever sections are present rather than requiring the full schema, so
 * analysis works on old and new findings alike.
 */
import type { JsonObject, JsonValue } from "@/types/json";

export type AiAnalysisResult = {
  summary: string;
  whyFlagged: string | null;
  investigationQuestions: string[];
  recommendedNextSteps: string[];
  confidence: number | null;
};

const MAX_EVIDENCE_ROWS = 25;
const MAX_PROMPT_CHARS = 12_000;

export function buildFindingPrompt(finding: JsonObject): string {
  const sections: string[] = [];

  sections.push(
    "You are assisting a digital forensics and incident response (DFIR) analyst. " +
      "Analyze the following finding, collected by an endpoint forensic collector, and respond with a JSON object " +
      'containing exactly these keys: "summary" (2-4 sentences explaining what this finding shows and why it matters), ' +
      '"why_flagged" (1-2 sentences on the specific reason this was surfaced), ' +
      '"investigation_questions" (array of 2-5 concrete next questions the analyst should answer), ' +
      '"recommended_next_steps" (array of 2-5 concrete actions), ' +
      '"confidence" (0-100 integer, your confidence in this assessment given the evidence available). ' +
      "Respond with ONLY the JSON object, no markdown fences, no other text.\n" +
      '"Forensicator" is the name of the DFIR collection tool that gathered this evidence (it appears in field ' +
      "names and titles below purely as product branding). It is your own tooling, not a suspect, process, " +
      "attacker, or any entity involved in the incident — never describe Forensicator itself as malicious, " +
      "suspicious, compromised, or an attacker's tool. The actual subject of this finding is whatever artifact, " +
      "account, host, or process is named in the Evidence below."
  );

  sections.push(`\nFinding type: ${str(finding.finding_type) ?? "unknown"}`);
  sections.push(`Category: ${str(finding.category) ?? "unknown"}`);
  sections.push(`Severity: ${str(finding.severity) ?? "unknown"}`);

  const summary = asObject(finding.summary);
  if (summary) {
    if (str(summary.title)) sections.push(`Title: ${stripForensicatorBranding(str(summary.title)!)}`);
    if (str(summary.description)) sections.push(`Description: ${stripForensicatorBranding(str(summary.description)!)}`);
    if (str(summary.why_this_matters)) sections.push(`Why it matters: ${stripForensicatorBranding(str(summary.why_this_matters)!)}`);
  }

  const explanation = asObject(finding.explanation);
  if (explanation) {
    if (str(explanation.what_is_this)) sections.push(`What is this artifact: ${str(explanation.what_is_this)}`);
    if (str(explanation.suspicious_behaviour)) sections.push(`What looks suspicious about it: ${str(explanation.suspicious_behaviour)}`);
    if (str(explanation.common_attack_usage)) sections.push(`Common attack usage: ${str(explanation.common_attack_usage)}`);
  }

  const risk = asObject(finding.risk);
  if (risk) {
    const parts: string[] = [];
    if (risk.score !== undefined) parts.push(`score=${jsonToStr(risk.score)}`);
    if (str(risk.level)) parts.push(`level=${str(risk.level)}`);
    if (str(risk.reason)) parts.push(`reason="${str(risk.reason)}"`);
    if (parts.length) sections.push(`Risk: ${parts.join(", ")}`);
    if (Array.isArray(risk.reasoning) && risk.reasoning.length) {
      sections.push(`Risk reasoning: ${risk.reasoning.map(jsonToStr).join("; ")}`);
    }
  }

  const mitre = finding.mitre;
  if (Array.isArray(mitre) && mitre.length) {
    const lines = mitre
      .map((m) => asObject(m))
      .filter((m): m is JsonObject => !!m)
      .map((m) => `${str(m.technique_id) ?? "?"} ${str(m.technique) ?? ""}`.trim())
      .filter(Boolean);
    if (lines.length) sections.push(`MITRE ATT&CK: ${lines.join("; ")}`);
  }

  const host = asObject(finding.host);
  if (host && (str(host.hostname) || str(host.username))) {
    sections.push(`Host: ${str(host.hostname) ?? "?"} / user: ${str(host.username) ?? "?"}`);
  }

  const detection = asObject(finding.detection);
  if (detection && str(detection.logic)) {
    sections.push(`Detection logic: ${str(detection.logic)}`);
  }

  const ioc = asObject(finding.ioc);
  if (ioc) {
    const iocParts: string[] = [];
    for (const [key, value] of Object.entries(ioc)) {
      if (Array.isArray(value) && value.length) iocParts.push(`${key}: ${value.map(jsonToStr).join(", ")}`);
    }
    if (iocParts.length) sections.push(`IOCs — ${iocParts.join(" | ")}`);
  }

  const evidence = finding.evidence;
  if (Array.isArray(evidence) && evidence.length) {
    const rows = evidence.slice(0, MAX_EVIDENCE_ROWS);
    sections.push(
      `\nEvidence (${evidence.length} row(s) total, showing up to ${MAX_EVIDENCE_ROWS}):\n` +
        rows.map((row) => JSON.stringify(row)).join("\n")
    );
  }

  let prompt = sections.join("\n");
  if (prompt.length > MAX_PROMPT_CHARS) {
    prompt = prompt.slice(0, MAX_PROMPT_CHARS) + "\n[...truncated...]";
  }
  return prompt;
}

/**
 * Parses the model's JSON response. Models — especially small ones — don't
 * always follow "JSON only" instructions perfectly, so this extracts the
 * first {...} block before parsing rather than requiring the whole response
 * to be valid JSON, and falls back to treating the raw text as the summary
 * if structured parsing fails entirely (still useful to an analyst).
 */
export function parseAiResponse(raw: string): AiAnalysisResult {
  const jsonText = extractJsonObject(raw);
  if (jsonText) {
    try {
      const parsed = JSON.parse(jsonText) as Record<string, unknown>;
      return {
        summary: typeof parsed.summary === "string" && parsed.summary.trim() ? parsed.summary.trim() : raw.trim().slice(0, 2000),
        whyFlagged: typeof parsed.why_flagged === "string" ? parsed.why_flagged.trim() : null,
        investigationQuestions: toStringArray(parsed.investigation_questions),
        recommendedNextSteps: toStringArray(parsed.recommended_next_steps),
        confidence: toConfidence(parsed.confidence),
      };
    } catch {
      // fall through to raw-text fallback below
    }
  }
  return {
    summary: raw.trim().slice(0, 2000),
    whyFlagged: null,
    investigationQuestions: [],
    recommendedNextSteps: [],
    confidence: null,
  };
}

function extractJsonObject(text: string): string | null {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  return text.slice(start, end + 1);
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v.trim().length > 0).map((v) => v.trim());
}

function toConfidence(value: unknown): number | null {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function asObject(value: JsonValue | undefined): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : null;
}

function str(value: JsonValue | undefined): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function jsonToStr(value: JsonValue): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/**
 * Older/legacy collector output prefixes finding titles and descriptions
 * with "Forensicator " purely as product branding (e.g. "Forensicator
 * Credential Manager Backup Events"). Sent as-is, small models have
 * misread that as naming Forensicator itself as a party in the incident
 * (e.g. "Forensicator may be used by attackers to exfiltrate credentials")
 * — stripping it here removes the confusion at the source, on top of the
 * explicit instruction in the prompt preamble above.
 */
function stripForensicatorBranding(text: string): string {
  return text.replace(/^Forensicator\s+/i, "").replace(/\bForensicator collected\b/gi, "Collected").trim();
}
