/**
 * IOC enrichment orchestrator.
 * Called by the BullMQ enrichment worker.
 */
import { prisma } from "@/lib/db/prisma";
import { ALL_PROVIDERS } from "./providers";
import { resolveApiKey, isProviderEnabledForOrg } from "./org-providers";

export async function enrichIoc(iocRecordId: string, value: string, type: string, organizationId?: string) {
  const candidates = ALL_PROVIDERS.filter((p) => p.supportsType(type));
  const enabledMask = await Promise.all(
    candidates.map((p) => isProviderEnabledForOrg(organizationId, p.name))
  );
  const providers = candidates.filter((_, i) => enabledMask[i]);

  const results = await Promise.allSettled(
    providers.map(async (p) => {
      try {
        const apiKey = await resolveApiKey(organizationId, p.name);
        const result = await p.lookup(value, type, apiKey);
        await prisma.iocEnrichment.upsert({
          where: { iocId_provider: { iocId: iocRecordId, provider: p.name } },
          create: {
            iocId: iocRecordId,
            provider: p.name,
            status: result.found ? "ok" : "not_found",
            response: result.raw as never,
            enrichedAt: new Date(),
          },
          update: {
            status: result.found ? "ok" : "not_found",
            response: result.raw as never,
            enrichedAt: new Date(),
            errorMsg: null,
          },
        });
        return result;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await prisma.iocEnrichment.upsert({
          where: { iocId_provider: { iocId: iocRecordId, provider: p.name } },
          create: { iocId: iocRecordId, provider: p.name, status: "error", errorMsg: msg },
          update: { status: "error", errorMsg: msg, enrichedAt: new Date() },
        });
        return null;
      }
    })
  );

  // Aggregate reputation (max across providers that returned a score)
  let maxRep: number | undefined;
  let malwareFamily: string | undefined;
  let threatType: string | undefined;
  const providerResults: Record<string, unknown> = {};

  for (let i = 0; i < providers.length; i++) {
    const r = results[i];
    if (r.status === "fulfilled" && r.value) {
      const v = r.value;
      if (v.reputation != null && (maxRep == null || v.reputation > maxRep)) maxRep = v.reputation;
      if (!malwareFamily && v.malwareFamily) malwareFamily = v.malwareFamily;
      if (!threatType && v.threatType) threatType = v.threatType;
      providerResults[providers[i].name] = v.raw;
    }
  }

  await prisma.iocRecord.update({
    where: { id: iocRecordId },
    data: {
      enrichedAt: new Date(),
      reputation: maxRep ?? null,
      malwareFamily: malwareFamily ?? null,
      threatType: threatType ?? null,
      providerResults: providerResults as never,
    },
  });
}
