/**
 * Extracts IOC / hash values from IOC-flagged findings in a fresh
 * investigation upload and upserts them into IocRecord. Populates the IOC
 * Intelligence page without requiring a separate enrichment step. Newly
 * created (not previously-seen) records are returned so the caller can
 * auto-enrich them — see src/app/api/investigations/upload/route.ts.
 */
import { prisma } from "@/lib/db/prisma";
import type { ParsedUploadFinding } from "@/types/findings";

export type NewIocRecord = { id: string; value: string; type: "ip" | "hash" | "url" | "domain" | "email" };

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/**
 * Returns the IPv4/IPv6 host from a URL if the host is a bare IP address,
 * otherwise returns undefined.
 * e.g. "https://188.21.8.67/path" → "188.21.8.67"
 *      "https://evil.com/path"    → undefined
 */
function extractIpFromUrl(rawUrl: string): string | undefined {
  try {
    const { hostname } = new URL(rawUrl);
    // IPv4: four dot-separated octets
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname;
    // IPv6: URL parser strips the brackets, leaving e.g. "::1" or "2001:db8::1"
    if (hostname.includes(":")) return hostname;
  } catch {
    // Not a valid URL — ignore
  }
  return undefined;
}

export async function extractAndUpsertIocs(
  findingsWithIds: ParsedUploadFinding[]
): Promise<NewIocRecord[]> {
  const newIocRecords: NewIocRecord[] = [];

  const iocFindings = findingsWithIds.filter(({ data, sourceCategory }) => {
    const ft = (data.finding_type ?? "").toLowerCase();
    const sc = (sourceCategory ?? "").toLowerCase();
    return sc === "ioc" || sc === "hash"
      || ft.includes("ioc") || ft.includes("malicious url")
      || ft.includes("malicious hash") || ft.includes("hash match");
  });

  const now = new Date();
  for (const { data, sourceCategory } of iocFindings) {
    const sc = (sourceCategory ?? "").toLowerCase();
    const ft = (data.finding_type ?? "").toLowerCase();
    const isHash = sc === "hash" || ft.includes("hash");

    for (const row of data.evidence as Record<string, unknown>[]) {
      let value: string | undefined;
      let type: "hash" | "url";

      if (isHash) {
        const h =
          str(row.sha256) ?? str(row.md5) ?? str(row.hash) ??
          str(row.SHA256) ?? str(row.MD5) ?? str(row.Hash);
        if (!h) continue;
        value = h.slice(0, 500); // hashes are short but guard anyway
        type = "hash";
      } else {
        const u = str(row.url) ?? str(row.URL);
        if (!u) continue;
        // Postgres btree index limit ~2704 bytes — truncate to 500 chars safely.
        value = u.slice(0, 500);
        type = "url";
      }

      try {
        const rec = await prisma.iocRecord.upsert({
          where:  { value },
          create: { value, type, firstSeen: now, lastSeen: now, threatType: data.finding_type },
          update: { lastSeen: now },
        });
        if (rec.firstSeen?.getTime() === now.getTime()) newIocRecords.push({ id: rec.id, value: rec.value, type });
      } catch (rowErr) {
        console.warn("[upload] IocRecord row skipped:", value?.slice(0, 80), rowErr instanceof Error ? rowErr.message : rowErr);
      }

      // If the URL host is a bare IP address, also upsert the IP as its own
      // ip-type IOC so AbuseIPDB and other IP-only providers can enrich it.
      if (type === "url" && value) {
        const ipFromUrl = extractIpFromUrl(value);
        if (ipFromUrl) {
          try {
            const ipRec = await prisma.iocRecord.upsert({
              where:  { value: ipFromUrl },
              create: { value: ipFromUrl, type: "ip", firstSeen: now, lastSeen: now, threatType: data.finding_type },
              update: { lastSeen: now },
            });
            if (ipRec.firstSeen?.getTime() === now.getTime()) newIocRecords.push({ id: ipRec.id, value: ipRec.value, type: "ip" });
          } catch (ipErr) {
            console.warn("[upload] IP IocRecord row skipped:", ipFromUrl, ipErr instanceof Error ? ipErr.message : ipErr);
          }
        }
      }
    }
  }

  return newIocRecords;
}
