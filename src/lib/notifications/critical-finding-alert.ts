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
 * single run, and a batched email is far more useful than a flood of
 * one-per-finding messages.
 */
import { getSystemSettings } from "@/lib/settings/system";
import { sendMail } from "./mailer";

// Enterprise-only Slack/Teams/webhook alerting + escalation lives in the
// overlay at this path, not in Core — loaded via dynamic import behind a
// non-literal specifier (same pattern as upload/route.ts's SIEM dispatch)
// so this module resolves and no-ops cleanly when the overlay isn't
// applied, rather than failing the build.
const WEBHOOK_DISPATCH_MODULE = "@/lib/notifications/webhook-dispatch";

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

  const settings = await getSystemSettings();

  if (settings?.criticalFindingAlertsEnabled && settings.notificationEmail) {
    const lines = critical.map((f) => `- [${f.sourceLabel}] ${f.title}${f.detailPath ? ` — ${f.detailPath}` : ""}`);
    const subject = `Forensicator: ${critical.length} critical finding${critical.length !== 1 ? "s" : ""} detected`;
    const text = `The following critical findings were just detected:\n\n${lines.join("\n")}`;

    const result = await sendMail({ to: settings.notificationEmail, subject, text });
    if (!result.ok) {
      console.warn("[notifications] Failed to send critical finding alert:", result.error);
    }
  }

  import(WEBHOOK_DISPATCH_MODULE)
    .then(({ dispatchWebhookAlert }) => dispatchWebhookAlert(critical))
    .catch((e) => console.warn("[notifications] Webhook dispatch skipped:", e instanceof Error ? e.message : e));
}
