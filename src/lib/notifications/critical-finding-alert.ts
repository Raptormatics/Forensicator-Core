/**
 * notifyCriticalFindings() — the one hook point every finding-creation
 * call site uses. Findings are created across 2 severity vocabularies:
 * the generic Finding.severity (normalizeSeverity() in src/lib/severity.ts
 * -> "Important"|"Notable"|"Interesting"|"Informational") and
 * LogFinding/PcapFinding/RamFinding's literal "critical"|"high"|"medium"|
 * "low"|"info". isCriticalSeverity() treats "important" and "critical" as
 * the same trigger condition so a single check works across both.
 *
 * Called once per processing run with everything that run created (not
 * once per finding) — RAM analysis alone can create 10+ findings in a
 * single run, and one batched alert is far more useful than a flood.
 *
 * Critical-finding alerting (SMTP email, webhook) is a Forensicator
 * Enterprise feature: Core only decides WHICH findings are alert-worthy and
 * hands them to the overlay's dispatcher, loaded via dynamic import behind
 * a non-literal specifier (same extension-point pattern as upload/route.ts's
 * SIEM dispatch) so this module resolves and no-ops cleanly when the
 * overlay isn't applied, rather than failing the build.
 */

const ALERT_DISPATCH_MODULE = "@/lib/notifications/critical-alert-dispatch";

export interface AlertableFinding {
  title: string;
  severity: string;
  sourceLabel: string; // e.g. "Investigation", "Log Analysis", "PCAP Analysis", "RAM Analysis"
  detailPath?: string; // app-relative path, e.g. `/ram-analysis/<uploadId>`
}

const CRITICAL_EQUIVALENT = new Set(["important", "critical"]);

export function isCriticalSeverity(severity: string): boolean {
  return CRITICAL_EQUIVALENT.has(severity.toLowerCase());
}

export async function notifyCriticalFindings(findings: AlertableFinding[]): Promise<void> {
  const critical = findings.filter((f) => isCriticalSeverity(f.severity));
  if (critical.length === 0) return;

  let dispatch: ((findings: AlertableFinding[]) => Promise<void>) | undefined;
  try {
    ({ dispatchCriticalAlerts: dispatch } = await import(ALERT_DISPATCH_MODULE));
  } catch {
    return; // Overlay not applied — Core has no alert channels.
  }
  if (!dispatch) return;
  try {
    await dispatch(critical);
  } catch (err) {
    console.warn("[notifications] Critical finding alert dispatch failed:", err instanceof Error ? err.message : err);
  }
}
