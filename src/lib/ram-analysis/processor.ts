/**
 * RAM Analysis — main processing pipeline. Mirrors pcap-analysis/processor.ts's
 * processPcapUpload(): this function owns the ENTIRE status lifecycle itself
 * (queued -> processing -> ready/failed), called from a thin BullMQ worker
 * (see src/lib/jobs/ram-worker.ts) rather than doing any status bookkeeping
 * in the worker itself.
 *
 * OS-aware: branches on RamUpload.osType to pick the right Volatility3
 * plugin namespace + mapper set (OS_CONFIGS below), but reuses the exact
 * same orchestration for all three OSes. The "OS detection" step differs in
 * fatality: windows.info.Info failing is fatal (Windows has no other way
 * to identify the image), but banners.Banners failing for linux/macos is
 * NOT fatal — it's a best-effort banner-string extraction that still runs
 * even without matching symbols, so pslist stays the real mandatory gate
 * there. Every other plugin (cmdline/connections/malfind-equivalent) is
 * degradable for all three OSes — a failure or timeout is recorded on
 * pluginStatus and processing continues with that plugin's data simply
 * absent, still reaching "ready".
 *
 * 1. Wipe any partial rows from a prior failed attempt (BullMQ retry idempotency)
 * 2. Run the info/banner step (fatal only for Windows) + pslist-equivalent (always fatal) -> processes
 * 3. Run cmdline/connections/malfind-equivalents (degradable) -> enrich/connections/findings
 * 4. Batch-insert RamProcess / RamNetworkConnection rows
 * 5. Upsert RamIoc (per-upload tally) + global IocRecord for public foreign IPs
 * 6. Run built-in heuristics -> RamFinding rows (ruleId: null)
 * 7. Load enabled RamAnalysisRule (org-scoped OR global) -> run rule engine -> RamFinding rows
 * 8. Update RamUpload status + counts
 */
import { prisma } from "@/lib/db/prisma";
import { getVolatilityPath, getVolatilitySymbolsDir } from "@/lib/settings/system";
import { isPrivateIp } from "@/lib/pcap-analysis/aggregator";
import { runVolatilityPlugin, type VolatilityPluginResult } from "./volatility";
import { runYaraScan } from "./yara";
import {
  mapPsListRows, mergeCmdLine, mapNetScanRows, mapMalfindRows, mapInfoRows,
  mapLinuxPsListRows, mergeLinuxPsaux, mapLinuxSockstatRows, mapLinuxMalfindRows,
  mapMacPsListRows, mergeMacPsaux, mapMacNetstatRows, mapMacMalfindRows,
  mapBannerRows,
} from "./mappers";
import { runHeuristics } from "./heuristics";
import { buildSubjects, runRules, type StoredRamRule } from "./rule-engine";
import { isEnriched, type IocLookupMap } from "@/lib/rule-engine/ioc-lookup";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";
import type { RamProcessRow, RamConnectionRow, RamMalfindHit, RamInfoSummary, RamOsType } from "./types";
import type { VolatilityRow } from "./volatility";

const BATCH = 500; // rows per Prisma createMany, same convention as processPcapUpload

type PluginStatusMap = Record<string, "ok" | "error" | "timeout" | "not_installed">;

interface OsPluginConfig {
  infoPlugin: string;
  infoFatal: boolean;
  pslistPlugin: string;
  cmdlinePlugin: string;
  connectionsPlugin: string;
  malfindPlugin: string;
  mapPsList: (rows: VolatilityRow[]) => RamProcessRow[];
  mergeCmdline: (processes: RamProcessRow[], rows: VolatilityRow[]) => RamProcessRow[];
  mapConnections: (rows: VolatilityRow[]) => RamConnectionRow[];
  mapMalfind: (rows: VolatilityRow[]) => RamMalfindHit[];
  mapInfo: (rows: VolatilityRow[]) => RamInfoSummary;
}

// Deliberately the non-deprecated malfind path for every OS — confirmed
// against the installed framework that windows.malfind/linux.malfind are
// deprecated shims already past their stated removal date.
const OS_CONFIGS: Record<RamOsType, OsPluginConfig> = {
  windows: {
    infoPlugin: "windows.info.Info", infoFatal: true,
    pslistPlugin: "windows.pslist.PsList",
    cmdlinePlugin: "windows.cmdline.CmdLine",
    connectionsPlugin: "windows.netscan.NetScan",
    malfindPlugin: "windows.malware.malfind.Malfind",
    mapPsList: mapPsListRows, mergeCmdline: mergeCmdLine,
    mapConnections: mapNetScanRows, mapMalfind: mapMalfindRows, mapInfo: mapInfoRows,
  },
  linux: {
    // banners.Banners needs no symbol table at all (raw regex scan), so it
    // works even when nothing else does — non-fatal, used purely to
    // surface the exact banner text a custom symbol table needs to match
    // if the mandatory pslist step below then fails.
    infoPlugin: "banners.Banners", infoFatal: false,
    pslistPlugin: "linux.pslist.PsList",
    cmdlinePlugin: "linux.psaux.PsAux",
    connectionsPlugin: "linux.sockstat.Sockstat",
    malfindPlugin: "linux.malware.malfind.Malfind",
    mapPsList: mapLinuxPsListRows, mergeCmdline: mergeLinuxPsaux,
    mapConnections: mapLinuxSockstatRows, mapMalfind: mapLinuxMalfindRows, mapInfo: mapBannerRows,
  },
  macos: {
    infoPlugin: "banners.Banners", infoFatal: false,
    pslistPlugin: "mac.pslist.PsList",
    cmdlinePlugin: "mac.psaux.PsAux",
    connectionsPlugin: "mac.netstat.Netstat",
    malfindPlugin: "mac.malfind.Malfind",
    mapPsList: mapMacPsListRows, mergeCmdline: mergeMacPsaux,
    mapConnections: mapMacNetstatRows, mapMalfind: mapMacMalfindRows, mapInfo: mapBannerRows,
  },
};

function describeFailure(pluginName: string, result: VolatilityPluginResult): string {
  const reason = result.status === "timeout" ? "timed out" : result.status === "error" ? result.message : "failed";
  return `${pluginName} ${reason}`;
}

export async function processRamUpload(uploadId: string, filePath: string): Promise<void> {
  const upload = await prisma.ramUpload.findUnique({ where: { id: uploadId } });
  if (!upload) throw new Error(`RamUpload ${uploadId} not found`);

  const osType = (upload.osType as RamOsType) in OS_CONFIGS ? (upload.osType as RamOsType) : "windows";
  const config = OS_CONFIGS[osType];

  await prisma.ramUpload.update({ where: { id: uploadId }, data: { status: "processing" } });

  try {
    // 1. Idempotency for BullMQ retries — re-derive everything from the same file.
    await prisma.$transaction([
      prisma.ramProcess.deleteMany({ where: { uploadId } }),
      prisma.ramNetworkConnection.deleteMany({ where: { uploadId } }),
      prisma.ramFinding.deleteMany({ where: { uploadId } }),
      prisma.ramIoc.deleteMany({ where: { uploadId } }),
    ]);

    const volPath = await getVolatilityPath();
    const symbolsDir = await getVolatilitySymbolsDir();
    const pluginStatus: PluginStatusMap = {};
    const runOpts = { symbolsDir };

    const record = (plugin: string, result: VolatilityPluginResult) => {
      pluginStatus[plugin] = result.status === "ok" ? "ok" : result.status;
    };

    // 2. Info/banner step + mandatory pslist-equivalent.
    const infoResult = await runVolatilityPlugin(volPath, filePath, config.infoPlugin, runOpts);
    record(config.infoPlugin, infoResult);
    if (config.infoFatal && infoResult.status !== "ok") {
      throw new Error(`${describeFailure(config.infoPlugin, infoResult)} — image may be corrupt, wrong OS, or symbols unavailable`);
    }
    const infoSummary: RamInfoSummary = infoResult.status === "ok" ? config.mapInfo(infoResult.rows) : { osBuild: null, osArch: null };

    const pslistResult = await runVolatilityPlugin(volPath, filePath, config.pslistPlugin, runOpts);
    record(config.pslistPlugin, pslistResult);
    if (pslistResult.status !== "ok") {
      const base = describeFailure(config.pslistPlugin, pslistResult);
      if (osType !== "windows" && infoSummary.osBuild) {
        throw new Error(`${base} — no matching symbol table for banner: ${infoSummary.osBuild} — upload a matching one under RAM Analysis → Symbol Tables.`);
      }
      throw new Error(base);
    }
    let processes: RamProcessRow[] = config.mapPsList(pslistResult.rows);

    // 3. Degradable plugins — failure/timeout is recorded, processing continues.
    const cmdlineResult = await runVolatilityPlugin(volPath, filePath, config.cmdlinePlugin, runOpts);
    record(config.cmdlinePlugin, cmdlineResult);
    if (cmdlineResult.status === "ok") {
      processes = config.mergeCmdline(processes, cmdlineResult.rows);
    }

    const connectionsResult = await runVolatilityPlugin(volPath, filePath, config.connectionsPlugin, runOpts);
    record(config.connectionsPlugin, connectionsResult);
    const connections: RamConnectionRow[] = connectionsResult.status === "ok" ? config.mapConnections(connectionsResult.rows) : [];

    const malfindResult = await runVolatilityPlugin(volPath, filePath, config.malfindPlugin, runOpts);
    record(config.malfindPlugin, malfindResult);
    const malfindHits: RamMalfindHit[] = malfindResult.status === "ok" ? config.mapMalfind(malfindResult.rows) : [];

    // 4. Batch-insert processes
    for (let offset = 0; offset < processes.length; offset += BATCH) {
      const batch = processes.slice(offset, offset + BATCH);
      await prisma.ramProcess.createMany({
        data: batch.map((p) => ({
          uploadId,
          pid: p.pid, ppid: p.ppid ?? undefined,
          name: p.name, path: p.path ?? undefined, commandLine: p.commandLine ?? undefined,
          createTime: p.createTime ?? undefined, exitTime: p.exitTime ?? undefined,
          sessionId: p.sessionId ?? undefined, threads: p.threads ?? undefined, handles: p.handles ?? undefined,
        })),
      });
    }

    // Batch-insert connections
    for (let offset = 0; offset < connections.length; offset += BATCH) {
      const batch = connections.slice(offset, offset + BATCH);
      await prisma.ramNetworkConnection.createMany({
        data: batch.map((c) => ({
          uploadId,
          protocol: c.protocol ?? undefined,
          localAddr: c.localAddr ?? undefined, localPort: c.localPort ?? undefined,
          foreignAddr: c.foreignAddr ?? undefined, foreignPort: c.foreignPort ?? undefined,
          state: c.state ?? undefined, pid: c.pid ?? undefined, processName: c.processName ?? undefined,
          created: c.created ?? undefined,
        })),
      });
    }

    // 5. IOC upsert — per-upload RamIoc tally + global IocRecord (public
    // foreign IPs only, from connections). Non-fatal per row, same pattern
    // as the PCAP/investigation upload routes.
    const now = new Date();
    const iocValues = new Set<string>();
    for (const conn of connections) {
      if (conn.foreignAddr && !isPrivateIp(conn.foreignAddr)) iocValues.add(conn.foreignAddr);
    }

    const knownIocHits: string[] = [];
    // Populated from the same `existing` row already fetched below for the
    // "known IOC observed" heuristic — no extra query needed. Passed into
    // the rule engine so a rule condition can check ioc_known/ioc_reputation/
    // ioc_threat_type/ioc_malware_family against the shared threat-intel
    // database, not just this image's own raw extracted connections.
    const iocLookupMap: IocLookupMap = new Map();
    const newIocRecords: NewIocRecord[] = [];
    for (const value of iocValues) {
      try {
        await prisma.ramIoc.upsert({
          where: { uploadId_type_value: { uploadId, type: "ip", value } },
          create: { uploadId, type: "ip", value, count: 1 },
          update: { count: { increment: 1 } },
        });
      } catch (rowErr) {
        console.warn("[ram-analysis] RamIoc row skipped:", value, rowErr instanceof Error ? rowErr.message : rowErr);
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
          create: { value, type: "ip", firstSeen: now, lastSeen: now },
          update: { lastSeen: now },
        });
        if (!existing) newIocRecords.push({ id: rec.id, value: rec.value, type: "ip" });
        if (isEnriched(existing)) {
          knownIocHits.push(value);
        }
      } catch (iocErr) {
        console.warn("[ram-analysis] IocRecord row skipped:", value, iocErr instanceof Error ? iocErr.message : iocErr);
      }
    }

    if (newIocRecords.length > 0) {
      await autoEnrichNewIocs(newIocRecords, upload.organizationId ?? undefined).catch((err) =>
        console.warn("[ram-analysis] Auto-enrichment skipped:", err instanceof Error ? err.message : err)
      );
    }

    // 6. Built-in heuristics
    const { malfindFindings, otherFindings } = runHeuristics(processes, malfindHits, osType);

    let findingTotal = 0;

    // Malfind findings are grouped by process (see heuristics.ts) — one
    // RamFinding per pid, carrying every injected VAD region as a child
    // RamMalfindRegion row instead of one finding per region.
    for (const f of malfindFindings) {
      const finding = await prisma.ramFinding.create({
        data: {
          uploadId, ruleId: null,
          title: f.title, description: f.description ?? undefined, severity: f.severity,
          matchCount: f.matchCount,
          matchedField: f.matchedField ?? undefined, matchedValue: f.matchedValue ?? undefined,
          pid: f.pid ?? undefined, processName: f.processName ?? undefined,
        },
      });
      findingTotal++;

      await prisma.ramMalfindRegion.createMany({
        data: f.regions.map((r) => ({
          findingId: finding.id,
          tag: r.tag ?? undefined,
          protection: r.protection ?? undefined,
          startAddress: r.startAddress ?? undefined,
          endAddress: r.endAddress ?? undefined,
          commitCharge: r.commitCharge ?? undefined,
          privateMemory: r.privateMemory ?? undefined,
          path: r.path ?? undefined,
          previewHex: r.previewHex ?? undefined,
        })),
      });
    }

    for (const f of otherFindings) {
      await prisma.ramFinding.create({
        data: {
          uploadId, ruleId: null,
          title: f.title, description: f.description ?? undefined, severity: f.severity,
          matchCount: f.matchCount,
          matchedField: f.matchedField ?? undefined, matchedValue: f.matchedValue ?? undefined,
          pid: f.pid ?? undefined, processName: f.processName ?? undefined,
        },
      });
      findingTotal++;
    }

    for (const value of knownIocHits) {
      await prisma.ramFinding.create({
        data: {
          uploadId, ruleId: null,
          title: "Known IOC observed in memory image",
          description: `${value} has prior threat-intelligence enrichment on record.`,
          severity: "high",
          matchCount: 1,
          matchedField: "ip", matchedValue: value,
        },
      });
      findingTotal++;
    }

    // 7. Analyst-defined rules (org-scoped OR global)
    const rules = await prisma.ramAnalysisRule.findMany({
      where: {
        enabled: true,
        OR: [
          ...(upload.organizationId ? [{ organizationId: upload.organizationId }] : []),
          { organizationId: null },
        ],
      },
    });

    if (rules.length > 0) {
      const subjects = buildSubjects(processes, connections);
      const matches = runRules(rules as unknown as StoredRamRule[], subjects, iocLookupMap);

      const byRule = new Map<string, typeof matches>();
      for (const m of matches) {
        const arr = byRule.get(m.ruleId) ?? [];
        arr.push(m);
        byRule.set(m.ruleId, arr);
      }

      const MAX_MATCHES_PER_FINDING = 1000;
      for (const [ruleId, hits] of byRule.entries()) {
        const rule = rules.find((r) => r.id === ruleId);
        if (!rule) continue;
        const sample = hits[0];
        const truncated = hits.length > MAX_MATCHES_PER_FINDING;

        const finding = await prisma.ramFinding.create({
          data: {
            uploadId, ruleId,
            title: rule.name,
            // A rule match group can span many different processes (e.g.
            // "LOLBin" matching 57 distinct pids) — there's no single
            // process this finding belongs to, unlike malfind's grouping,
            // so pid/processName stay null here; per-match detail lives in
            // RamFindingMatch below.
            description: [
              rule.description,
              truncated ? `Showing the first ${MAX_MATCHES_PER_FINDING.toLocaleString()} of ${hits.length.toLocaleString()} total matches.` : null,
            ].filter(Boolean).join(" ") || undefined,
            severity: rule.severity,
            matchCount: hits.length,
            matchedField: sample.matchedField, matchedValue: sample.matchedValue,
          },
        });
        findingTotal++;

        await prisma.ramFindingMatch.createMany({
          data: hits.slice(0, MAX_MATCHES_PER_FINDING).map((h) => ({
            findingId: finding.id,
            pid: h.subject.pid ?? undefined,
            processName: h.subject.processName ?? undefined,
            matchedField: h.matchedField,
            matchedValue: h.matchedValue,
          })),
        });

        await prisma.ramAnalysisRule.update({ where: { id: ruleId }, data: { hitCount: { increment: hits.length } } });
      }
    }

    // 7b. Custom Yara signatures — scanned directly against the raw image
    // bytes (no Volatility3 involvement; offsets are raw file offsets, not
    // process-relative). Fully degradable: yara-python not being installed
    // in the venv yet is expected on a fresh box and just skips this step,
    // same as any other degraded plugin.
    const yaraRules = await prisma.ramYaraRule.findMany({
      where: {
        enabled: true,
        OR: [
          ...(upload.organizationId ? [{ organizationId: upload.organizationId }] : []),
          { organizationId: null },
        ],
      },
    });

    if (yaraRules.length > 0) {
      const yaraResult = await runYaraScan(volPath, filePath, yaraRules.map((r) => ({ id: r.id, yaraSource: r.yaraSource })));

      if (yaraResult.status === "ok") {
        pluginStatus["yara"] = "ok";
        for (const err of yaraResult.compileErrors) {
          console.warn(`[ram-analysis] Yara rule ${err.ruleId} failed to compile at scan time: ${err.message}`);
        }

        const byYaraRule = new Map<string, typeof yaraResult.matches>();
        for (const m of yaraResult.matches) {
          const arr = byYaraRule.get(m.ruleId) ?? [];
          arr.push(m);
          byYaraRule.set(m.ruleId, arr);
        }

        const MAX_YARA_MATCHES_PER_FINDING = 1000;
        for (const [yaraRuleId, hits] of byYaraRule.entries()) {
          const rule = yaraRules.find((r) => r.id === yaraRuleId);
          if (!rule) continue;
          const truncated = hits.length > MAX_YARA_MATCHES_PER_FINDING;

          const finding = await prisma.ramFinding.create({
            data: {
              uploadId, yaraRuleId,
              title: rule.name,
              description: [
                rule.description,
                truncated ? `Showing the first ${MAX_YARA_MATCHES_PER_FINDING.toLocaleString()} of ${hits.length.toLocaleString()} total matches.` : null,
              ].filter(Boolean).join(" ") || undefined,
              severity: rule.severity,
              matchCount: hits.length,
              matchedField: hits[0].identifier,
              matchedValue: `offset 0x${hits[0].offset.toString(16)}`,
            },
          });
          findingTotal++;

          await prisma.ramFindingMatch.createMany({
            data: hits.slice(0, MAX_YARA_MATCHES_PER_FINDING).map((h) => ({
              findingId: finding.id,
              matchedField: h.identifier,
              matchedValue: `offset 0x${h.offset.toString(16)} : ${h.matchedDataHex}`,
            })),
          });

          await prisma.ramYaraRule.update({ where: { id: yaraRuleId }, data: { hitCount: { increment: hits.length } } });
        }
      } else {
        pluginStatus["yara"] = yaraResult.status;
      }
    }

    // 8. Final status + counts
    await prisma.ramUpload.update({
      where: { id: uploadId },
      data: {
        status: "ready",
        osBuild: infoSummary.osBuild ?? undefined,
        osArch: infoSummary.osArch ?? undefined,
        pluginStatus: pluginStatus,
        processCount: processes.length,
        connectionCount: connections.length,
        findingCount: findingTotal,
        iocCount: iocValues.size,
        errorMessage: null,
      },
    });
  } catch (err) {
    await prisma.ramUpload.update({
      where: { id: uploadId },
      data: { status: "failed", errorMessage: err instanceof Error ? err.message : String(err) },
    });
    throw err;
  }
}
