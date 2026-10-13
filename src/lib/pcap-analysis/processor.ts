/**
 * PCAP Analysis — main processing pipeline. Mirrors
 * log-analysis/processor.ts's processLogUpload(): this function owns the
 * ENTIRE status lifecycle itself (queued -> processing -> ready/failed),
 * called from a thin BullMQ worker (see src/lib/jobs/pcap-worker.ts) rather
 * than doing any status bookkeeping in the worker itself.
 *
 * 1. Wipe any partial rows from a prior failed attempt (BullMQ retry idempotency)
 * 2. Stream the capture through tshark, aggregate into conversations/DNS/credential hits
 * 3. Batch-insert PcapConversation / PcapDnsQuery rows
 * 4. Upsert PcapIoc (per-upload tally) + global IocRecord for public IPs/domains
 * 5. Run built-in heuristics -> PcapFinding rows (ruleId: null)
 * 6. Load enabled PcapAnalysisRule (org-scoped OR global) -> run rule engine -> PcapFinding rows
 * 7. Load enabled PcapYaraRule (org-scoped OR global) -> scan raw capture bytes -> PcapFinding rows
 * 8. Update PcapUpload status + counts
 */
import { prisma } from "@/lib/db/prisma";
import { getTsharkPath, getVolatilityPath } from "@/lib/settings/system";
import { runTsharkFieldExtraction } from "./tshark";
import { aggregate, isPrivateIp } from "./aggregator";
import { runHeuristics } from "./heuristics";
import { buildSubjects, runRules, type StoredPcapRule } from "./rule-engine";
import { isEnriched, type IocLookupMap } from "@/lib/rule-engine/ioc-lookup";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";
import { runYaraScan } from "@/lib/yara/engine";
import { notifyCriticalFindings } from "@/lib/notifications/critical-finding-alert";

const BATCH = 500; // rows per Prisma createMany, same convention as processLogUpload

/** Extracts a bare hostname/domain out of a URL-ish string. Only used here
 * for DNS query names, which are already bare domains — kept trivial. */
function isLikelyDomain(name: string): boolean {
  return /\./.test(name) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(name);
}

export async function processPcapUpload(uploadId: string, filePath: string): Promise<void> {
  const upload = await prisma.pcapUpload.findUnique({ where: { id: uploadId } });
  if (!upload) throw new Error(`PcapUpload ${uploadId} not found`);

  await prisma.pcapUpload.update({ where: { id: uploadId }, data: { status: "processing" } });

  try {
    // 1. Idempotency for BullMQ retries — this job fully re-derives
    // everything from the same file, so wipe any partial rows before redoing the work.
    await prisma.$transaction([
      prisma.pcapConversation.deleteMany({ where: { uploadId } }),
      prisma.pcapDnsQuery.deleteMany({ where: { uploadId } }),
      prisma.pcapFinding.deleteMany({ where: { uploadId } }),
      prisma.pcapIoc.deleteMany({ where: { uploadId } }),
    ]);

    // 2. Parse + aggregate
    const tsharkPath = await getTsharkPath();
    const stream = runTsharkFieldExtraction(tsharkPath, filePath);
    const result = await aggregate(stream);

    // 3. Batch-insert conversations
    const conversations = Array.from(result.conversations.values());
    for (let offset = 0; offset < conversations.length; offset += BATCH) {
      const batch = conversations.slice(offset, offset + BATCH);
      await prisma.pcapConversation.createMany({
        data: batch.map((c) => ({
          uploadId,
          protocol: c.protocol,
          addrA: c.addrA, portA: c.portA ?? undefined,
          addrB: c.addrB, portB: c.portB ?? undefined,
          packetsAtoB: c.packetsAtoB, packetsBtoA: c.packetsBtoA,
          bytesAtoB: BigInt(c.bytesAtoB), bytesBtoA: BigInt(c.bytesBtoA),
          firstSeen: c.firstSeen ?? undefined, lastSeen: c.lastSeen ?? undefined,
          tlsSni: c.tlsSni ?? undefined,
        })),
        skipDuplicates: true,
      });
    }

    // Batch-insert DNS queries
    const dnsQueries = Array.from(result.dnsQueries.values());
    for (let offset = 0; offset < dnsQueries.length; offset += BATCH) {
      const batch = dnsQueries.slice(offset, offset + BATCH);
      await prisma.pcapDnsQuery.createMany({
        data: batch.map((d) => ({
          uploadId,
          queryName: d.queryName,
          queryType: d.queryType ?? undefined,
          responseIps: Array.from(d.responseIps),
          count: d.count,
          firstSeen: d.firstSeen ?? undefined,
          lastSeen: d.lastSeen ?? undefined,
        })),
        skipDuplicates: true,
      });
    }

    // 4. IOC upsert — per-upload PcapIoc tally + global IocRecord (public
    // IPs and DNS query names/SNI domains only). Non-fatal per row, same
    // pattern as the investigation-upload route.
    const now = new Date();
    const iocValues = new Map<string, "ip" | "domain">();

    for (const conv of conversations) {
      for (const ip of [conv.addrA, conv.addrB]) {
        if (!isPrivateIp(ip)) iocValues.set(ip, "ip");
      }
    }
    for (const dns of dnsQueries) {
      if (isLikelyDomain(dns.queryName)) iocValues.set(dns.queryName, "domain");
      for (const ip of dns.responseIps) {
        if (!isPrivateIp(ip)) iocValues.set(ip, "ip");
      }
    }
    for (const conv of conversations) {
      if (conv.tlsSni && isLikelyDomain(conv.tlsSni)) iocValues.set(conv.tlsSni, "domain");
    }

    const knownIocHits: { value: string; type: string }[] = [];
    // Populated from the same `existing` row already fetched below for the
    // "known IOC observed" heuristic — no extra query needed. Passed into
    // the rule engine so a rule condition can check ioc_known/ioc_reputation/
    // ioc_threat_type/ioc_malware_family against the shared threat-intel
    // database, not just this capture's own raw extracted values.
    const iocLookupMap: IocLookupMap = new Map();
    const newIocRecords: NewIocRecord[] = [];
    for (const [value, type] of iocValues) {
      try {
        await prisma.pcapIoc.upsert({
          where: { uploadId_type_value: { uploadId, type, value } },
          create: { uploadId, type, value, count: 1 },
          update: { count: { increment: 1 } },
        });
      } catch (rowErr) {
        console.warn("[pcap-analysis] PcapIoc row skipped:", value, rowErr instanceof Error ? rowErr.message : rowErr);
      }

      try {
        const existing = await prisma.iocRecord.findUnique({ where: { value } });
        if (existing) {
          iocLookupMap.set(value, {
            reputation: existing.reputation,
            threatType: existing.threatType,
            malwareFamily: existing.malwareFamily,
          });
        }
        const rec = await prisma.iocRecord.upsert({
          where: { value },
          create: { value, type, firstSeen: now, lastSeen: now },
          update: { lastSeen: now },
        });
        if (!existing) newIocRecords.push({ id: rec.id, value: rec.value, type });
        // If this value already carried prior enrichment, surface it as a finding.
        if (isEnriched(existing)) {
          knownIocHits.push({ value, type });
        }
      } catch (iocErr) {
        console.warn("[pcap-analysis] IocRecord row skipped:", value, iocErr instanceof Error ? iocErr.message : iocErr);
      }
    }

    if (newIocRecords.length > 0) {
      await autoEnrichNewIocs(newIocRecords, upload.organizationId ?? undefined).catch((err) =>
        console.warn("[pcap-analysis] Auto-enrichment skipped:", err instanceof Error ? err.message : err)
      );
    }

    // 5. Built-in heuristics
    const heuristicFindings = runHeuristics(result);

    const criticalCandidates: { title: string; severity: string; sourceLabel: string; detailPath: string }[] = [];
    const detailPath = `/pcap-analysis/${uploadId}`;

    let findingTotal = 0;
    for (const f of heuristicFindings) {
      await prisma.pcapFinding.create({
        data: {
          uploadId, ruleId: null,
          title: f.title, description: f.description ?? undefined, severity: f.severity,
          matchCount: f.matchCount, firstSeen: f.firstSeen ?? undefined, lastSeen: f.lastSeen ?? undefined,
          matchedField: f.matchedField ?? undefined, matchedValue: f.matchedValue ?? undefined,
        },
      });
      findingTotal++;
      criticalCandidates.push({ title: f.title, severity: f.severity, sourceLabel: "PCAP Analysis", detailPath });
    }

    for (const hit of knownIocHits) {
      await prisma.pcapFinding.create({
        data: {
          uploadId, ruleId: null,
          title: "Known IOC observed in capture",
          description: `${hit.value} has prior threat-intelligence enrichment on record.`,
          severity: "high",
          matchCount: 1,
          matchedField: hit.type, matchedValue: hit.value,
        },
      });
      findingTotal++;
    }

    // 6. Analyst-defined rules (org-scoped OR global)
    const rules = await prisma.pcapAnalysisRule.findMany({
      where: {
        enabled: true,
        OR: [
          ...(upload.organizationId ? [{ organizationId: upload.organizationId }] : []),
          { organizationId: null },
        ],
      },
    });

    if (rules.length > 0) {
      const subjects = buildSubjects(result);
      const matches = runRules(rules as unknown as StoredPcapRule[], subjects, iocLookupMap);

      const byRule = new Map<string, typeof matches>();
      for (const m of matches) {
        const arr = byRule.get(m.ruleId) ?? [];
        arr.push(m);
        byRule.set(m.ruleId, arr);
      }

      for (const [ruleId, hits] of byRule.entries()) {
        const rule = rules.find((r) => r.id === ruleId);
        if (!rule) continue;
        const firstSeens = hits.map((h) => h.subject.firstSeen).filter((d): d is Date => d !== null);
        const lastSeens  = hits.map((h) => h.subject.lastSeen).filter((d): d is Date => d !== null);
        const sample = hits[0];

        await prisma.pcapFinding.create({
          data: {
            uploadId, ruleId,
            title: rule.name, description: rule.description ?? undefined, severity: rule.severity,
            matchCount: hits.length,
            firstSeen: firstSeens.length > 0 ? new Date(Math.min(...firstSeens.map((d) => d.getTime()))) : undefined,
            lastSeen:  lastSeens.length  > 0 ? new Date(Math.max(...lastSeens.map((d) => d.getTime())))  : undefined,
            matchedField: sample.matchedField, matchedValue: sample.matchedValue,
          },
        });
        findingTotal++;
        criticalCandidates.push({ title: rule.name, severity: rule.severity, sourceLabel: "PCAP Analysis", detailPath });

        await prisma.pcapAnalysisRule.update({ where: { id: ruleId }, data: { hitCount: { increment: hits.length } } });
      }
    }

    // 7. Custom Yara signatures — scanned directly against the capture's
    // raw bytes (same shared engine RAM analysis uses). Fully degradable:
    // yara-python not being installed in the venv yet just skips this step.
    const yaraRules = await prisma.pcapYaraRule.findMany({
      where: {
        enabled: true,
        OR: [
          ...(upload.organizationId ? [{ organizationId: upload.organizationId }] : []),
          { organizationId: null },
        ],
      },
    });

    if (yaraRules.length > 0) {
      const volPath = await getVolatilityPath();
      const yaraResult = await runYaraScan(volPath, filePath, yaraRules.map((r) => ({ id: r.id, yaraSource: r.yaraSource })));

      if (yaraResult.status === "ok") {
        for (const err of yaraResult.compileErrors) {
          console.warn(`[pcap-analysis] Yara rule ${err.ruleId} failed to compile at scan time: ${err.message}`);
        }

        const byYaraRule = new Map<string, typeof yaraResult.matches>();
        for (const m of yaraResult.matches) {
          const arr = byYaraRule.get(m.ruleId) ?? [];
          arr.push(m);
          byYaraRule.set(m.ruleId, arr);
        }

        for (const [yaraRuleId, hits] of byYaraRule.entries()) {
          const rule = yaraRules.find((r) => r.id === yaraRuleId);
          if (!rule) continue;

          await prisma.pcapFinding.create({
            data: {
              uploadId, yaraRuleId,
              title: rule.name,
              description: rule.description ?? undefined,
              severity: rule.severity,
              matchCount: hits.length,
              matchedField: hits[0].identifier,
              matchedValue: `offset 0x${hits[0].offset.toString(16)}`,
            },
          });
          findingTotal++;
          criticalCandidates.push({ title: rule.name, severity: rule.severity, sourceLabel: "PCAP Analysis", detailPath });

          await prisma.pcapYaraRule.update({ where: { id: yaraRuleId }, data: { hitCount: { increment: hits.length } } });
        }
      } else if (yaraResult.status === "error") {
        console.warn(`[pcap-analysis] Yara scan failed: ${yaraResult.message}`);
      }
    }

    await notifyCriticalFindings(criticalCandidates).catch((err) =>
      console.warn("[pcap-analysis] Critical finding alert failed:", err instanceof Error ? err.message : err)
    );

    // 8. Final status + counts
    await prisma.pcapUpload.update({
      where: { id: uploadId },
      data: {
        status: "ready",
        packetCount: result.packetCount,
        byteCount: BigInt(result.byteCount),
        captureStart: result.captureStart ?? undefined,
        captureEnd: result.captureEnd ?? undefined,
        conversationCount: conversations.length,
        dnsQueryCount: dnsQueries.length,
        findingCount: findingTotal,
        iocCount: iocValues.size,
        errorMessage: null,
      },
    });
  } catch (err) {
    await prisma.pcapUpload.update({
      where: { id: uploadId },
      data: { status: "failed", errorMessage: err instanceof Error ? err.message : String(err) },
    });
    throw err;
  }
}
