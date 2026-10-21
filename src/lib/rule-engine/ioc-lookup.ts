/**
 * Shared threat-intel lookup for rule engines — lets a Log/PCAP/RAM Analysis
 * rule condition check whether a value (IP, domain, hash, URL) already
 * carries prior enrichment in the global IocRecord table (populated via
 * Settings -> Threat Intel Providers), not just the raw extracted data.
 *
 * Deliberately NOT a live DB call per condition evaluation — rule engines
 * are synchronous, pure functions evaluated per-subject in a tight loop.
 * Callers build an IocLookupMap once per upload (see buildIocLookupMap()),
 * ideally reusing the IocRecord row they already fetched while upserting
 * extracted IOCs, and pass the map into runRules().
 */

export interface IocLookupInfo {
  reputation: number | null;
  threatType: string | null;
  malwareFamily: string | null;
}

export type IocLookupMap = Map<string, IocLookupInfo>;

/** The four rule fields every domain's field vocabulary adds. */
export type IocRuleField = "ioc_known" | "ioc_reputation" | "ioc_threat_type" | "ioc_malware_family";

export const IOC_RULE_FIELDS: IocRuleField[] = [
  "ioc_known",
  "ioc_reputation",
  "ioc_threat_type",
  "ioc_malware_family",
];

export const IOC_FIELD_LABELS: Record<IocRuleField, string> = {
  ioc_known:          "Known IOC (Threat Intel)",
  ioc_reputation:      "IOC Reputation Score",
  ioc_threat_type:     "IOC Threat Type",
  ioc_malware_family:  "IOC Malware Family",
};

/** A row "carries enrichment" once either reputation or threatType has been set. */
export function isEnriched(info: IocLookupInfo | null | undefined): boolean {
  return !!info && (info.reputation !== null || info.threatType !== null);
}

/**
 * Given the ordered list of IOC-candidate values present on a rule subject
 * (e.g. [addr_a, addr_b, tls_sni] for a PCAP conversation), returns the
 * first one found in the lookup map — first match wins, same "any
 * indicator on this subject is known-bad" semantic the built-in "Known IOC
 * observed" heuristics already use.
 */
export function resolveIoc(candidates: (string | null)[], iocMap: IocLookupMap): IocLookupInfo | undefined {
  for (const candidate of candidates) {
    if (!candidate) continue;
    const info = iocMap.get(candidate);
    if (info) return info;
  }
  return undefined;
}

/** Known-bad, per Core's reputation convention (>= 70 malicious, >= 40
 * suspicious, else clean — see the intelligence stats route and IOC page)
 * or an explicit threat type (abuse.ch feed hits carry both, at 95).
 * ioc_known used to be isEnriched(): any looked-up indicator, so a hash a
 * provider had rated clean (reputation 0) made the built-in "Known
 * Threat-Intel IOC" rules fire as critical — 108 such false positives on a
 * single real Windows 11 collection. ioc_reputation still exposes the raw
 * score for rules that want a lower threshold. */
const KNOWN_BAD_REPUTATION = 70;

export function isKnownBad(info: IocLookupInfo | null | undefined): boolean {
  return !!info && (info.threatType !== null || (info.reputation !== null && info.reputation >= KNOWN_BAD_REPUTATION));
}

export function getIocFieldValue(info: IocLookupInfo | undefined, field: IocRuleField): string {
  if (field === "ioc_known") return isKnownBad(info) ? "true" : "false";
  if (!info) return "";
  switch (field) {
    case "ioc_reputation":     return info.reputation !== null ? String(info.reputation) : "";
    case "ioc_threat_type":    return info.threatType ?? "";
    case "ioc_malware_family": return info.malwareFamily ?? "";
    default:                   return "";
  }
}

export function isIocRuleField(field: string): field is IocRuleField {
  return (IOC_RULE_FIELDS as string[]).includes(field);
}
