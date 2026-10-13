/**
 * Log Analysis — main processing pipeline.
 *
 * Called after a log file has been stored as a LogUpload row.
 * 1. Parse content — tries decoder engine first, falls back to legacy parsers
 * 2. Batch-insert LogEvent rows
 * 3. Extract and upsert LogIoc rows
 * 4. Load enabled rules for the org and run the rule engine
 * 5. Create LogFinding rows for matched rules
 * 6. Update LogUpload status + counts
 */

import { prisma }         from "@/lib/db/prisma";
import { getParser }      from "./parsers/index";
import { extractIocs }    from "./ioc-extractor";
import { runRules }       from "./rule-engine";
import type { ParsedEvent } from "./types";
import { loadDecoders, decodeLogLine } from "./decoder-engine/engine";
import type { NormalizedLogEntry }     from "./decoder-engine/types";
import type { IocLookupMap } from "@/lib/rule-engine/ioc-lookup";
import { autoEnrichNewIocs, type NewIocRecord } from "@/lib/intelligence/auto-enrich";
import { notifyCriticalFindings } from "@/lib/notifications/critical-finding-alert";

const BATCH = 500; // rows per Prisma createMany

// LogIoc's type vocabulary (see ioc-extractor.ts) is broader than the
// global IocRecord table's — only these map onto real, enrichable
// indicator types; process/filepath/username don't and are skipped when
// feeding the shared threat-intel database.
const GLOBAL_IOC_TYPE: Record<string, string | undefined> = {
  ip: "ip",
  domain: "domain",
  url: "url",
  hash_md5: "hash",
  hash_sha1: "hash",
  hash_sha256: "hash",
  email: "email",
};

// ── Decoder → ParsedEvent bridge ─────────────────────────────────────────────

function decoderOutputToParsedEvent(
  entry: NormalizedLogEntry,
  raw: string,
  lineNumber: number,
  sourceApp: string
): ParsedEvent {
  const tsRaw = entry["@timestamp"] as string | undefined;
  let timestamp: Date | null = null;
  if (tsRaw) {
    const d = new Date(tsRaw);
    if (!isNaN(d.getTime())) timestamp = d;
  }

  return {
    lineNumber,
    timestamp,
    sourceApp,
    eventType: (entry["event.kind"] as string | undefined) ?? (entry["event.type"] as string[] | undefined)?.[0] ?? null,
    srcIp:       (entry["source.ip"]      as string  | undefined) ?? null,
    dstIp:       (entry["destination.ip"] as string  | undefined) ?? null,
    srcPort:     (entry["source.port"]      as number | undefined) ?? null,
    dstPort:     (entry["destination.port"] as number | undefined) ?? null,
    username:    (entry["user.name"]      as string  | undefined) ?? null,
    domain:      (entry["source.domain"]  as string  | undefined) ?? (entry["destination.domain"] as string | undefined) ?? null,
    process:     (entry["process.name"]   as string  | undefined) ?? null,
    commandLine: (entry["process.command_line"] as string | undefined) ?? null,
    filePath:    (entry["file.path"]      as string  | undefined) ?? null,
    fileName:    (entry["file.name"]      as string  | undefined) ?? null,
    hashMd5:     (entry["hash.md5"]       as string  | undefined) ?? null,
    hashSha1:    (entry["hash.sha1"]      as string  | undefined) ?? null,
    hashSha256:  (entry["hash.sha256"]    as string  | undefined) ?? null,
    url:         (entry["url.original"]   as string  | undefined) ?? (entry["url.full"] as string | undefined) ?? null,
    httpMethod:  (entry["http.request.method"]         as string  | undefined) ?? null,
    statusCode:  (entry["http.response.status_code"]   as number  | undefined) ?? null,
    userAgent:   null,
    message:     (entry.message           as string  | undefined) ?? raw,
    raw,
    normalized: entry as Record<string, unknown>,
  };
}

/**
 * Parse log content through the decoder engine (primary) then legacy parsers (fallback).
 * Returns an array of ParsedEvent rows ready for DB insert.
 */
async function parseContent(content: string, sourceType: string): Promise<ParsedEvent[]> {
  // Always (re)load decoders so we pick up newly saved custom ones
  await loadDecoders();

  const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);

  // Check if any decoder matches the first non-empty line
  if (lines.length > 0) {
    const decoded = decodeLogLine(lines[0]);
    if (decoded) {
      // Decoder engine matched — process all lines through it
      const events: ParsedEvent[] = [];
      for (let i = 0; i < lines.length; i++) {
        const result = decodeLogLine(lines[i]);
        if (result) {
          events.push(decoderOutputToParsedEvent(result, lines[i], i + 1, sourceType));
        } else {
          // Line didn't match any decoder — add as raw entry
          events.push({
            lineNumber:  i + 1,
            timestamp:   null,
            sourceApp:   sourceType,
            eventType:   null,
            srcIp: null, dstIp: null, srcPort: null, dstPort: null,
            username: null, domain: null, process: null, commandLine: null,
            filePath: null, fileName: null, hashMd5: null, hashSha1: null,
            hashSha256: null, url: null, httpMethod: null, statusCode: null,
            userAgent: null, message: lines[i],
            raw: lines[i],
            normalized: { "event.original": lines[i] },
          });
        }
      }
      return events;
    }
  }

  // Fallback: legacy source-type parsers
  const parser = getParser(sourceType);
  if (parser) return parser(content);

  // Last resort: return raw lines
  return lines.map((line, i) => ({
    lineNumber:  i + 1,
    timestamp:   null,
    sourceApp:   sourceType,
    eventType:   null,
    srcIp: null, dstIp: null, srcPort: null, dstPort: null,
    username: null, domain: null, process: null, commandLine: null,
    filePath: null, fileName: null, hashMd5: null, hashSha1: null,
    hashSha256: null, url: null, httpMethod: null, statusCode: null,
    userAgent: null, message: line,
    raw: line,
    normalized: { "event.original": line },
  }));
}

export async function processLogUpload(uploadId: string, content: string): Promise<void> {
  // 1. Load upload record
  const upload = await prisma.logUpload.findUnique({ where: { id: uploadId } });
  if (!upload) throw new Error(`LogUpload ${uploadId} not found`);

  await prisma.logUpload.update({ where: { id: uploadId }, data: { status: "processing" } });

  try {
    // 2. Parse — decoder engine first, legacy parsers as fallback
    const events: ParsedEvent[] = await parseContent(content, upload.sourceType);

    // 3. Batch-insert events
    for (let offset = 0; offset < events.length; offset += BATCH) {
      const batch = events.slice(offset, offset + BATCH);
      await prisma.logEvent.createMany({
        data: batch.map((ev) => ({
          uploadId,
          lineNumber:  ev.lineNumber,
          timestamp:   ev.timestamp ?? undefined,
          sourceApp:   ev.sourceApp,
          eventType:   ev.eventType ?? undefined,
          srcIp:       ev.srcIp    ?? undefined,
          dstIp:       ev.dstIp    ?? undefined,
          srcPort:     ev.srcPort  ?? undefined,
          dstPort:     ev.dstPort  ?? undefined,
          username:    ev.username  ?? undefined,
          domain:      ev.domain    ?? undefined,
          process:     ev.process   ?? undefined,
          commandLine: ev.commandLine ?? undefined,
          filePath:    ev.filePath  ?? undefined,
          fileName:    ev.fileName  ?? undefined,
          hashMd5:     ev.hashMd5   ?? undefined,
          hashSha1:    ev.hashSha1  ?? undefined,
          hashSha256:  ev.hashSha256 ?? undefined,
          url:         ev.url       ?? undefined,
          httpMethod:  ev.httpMethod ?? undefined,
          statusCode:  ev.statusCode ?? undefined,
          userAgent:   ev.userAgent  ?? undefined,
          message:     ev.message    ?? undefined,
          raw:         ev.raw,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          normalized:  ev.normalized as any,
        })),
        skipDuplicates: true,
      });
    }

    // 4. IOC extraction & upsert — per-upload LogIoc tally (every extracted
    // type, including non-enrichable ones like process/filepath/username)
    // plus the global IocRecord table (ip/domain/url/hash/email only — the
    // set of types threat-intel providers actually enrich), non-fatal per
    // row, same pattern PCAP/RAM/investigation uploads already use. Also
    // builds iocLookupMap for the rule engine below, reusing the `existing`
    // row already fetched here rather than a second query.
    const iocMap = extractIocs(events);
    const now = new Date();
    const iocLookupMap: IocLookupMap = new Map();
    const newIocRecords: NewIocRecord[] = [];
    for (const ioc of iocMap.values()) {
      try {
        await prisma.logIoc.upsert({
          where:  { uploadId_type_value: { uploadId, type: ioc.type, value: ioc.value } },
          create: { uploadId, type: ioc.type, value: ioc.value, count: ioc.count },
          update: { count: { increment: ioc.count } },
        });
      } catch (rowErr) {
        console.warn("[log-analysis] LogIoc row skipped:", ioc.value, rowErr instanceof Error ? rowErr.message : rowErr);
      }

      const globalType = GLOBAL_IOC_TYPE[ioc.type];
      if (!globalType) continue; // process/filepath/username etc. aren't threat-intel-enrichable types

      try {
        const existing = await prisma.iocRecord.findUnique({ where: { value: ioc.value } });
        if (existing) {
          iocLookupMap.set(ioc.value, {
            reputation: existing.reputation,
            threatType: existing.threatType,
            malwareFamily: existing.malwareFamily,
          });
        }
        const rec = await prisma.iocRecord.upsert({
          where:  { value: ioc.value },
          create: { value: ioc.value, type: globalType, firstSeen: now, lastSeen: now },
          update: { lastSeen: now },
        });
        if (!existing) newIocRecords.push({ id: rec.id, value: rec.value, type: globalType as NewIocRecord["type"] });
      } catch (iocErr) {
        console.warn("[log-analysis] IocRecord row skipped:", ioc.value, iocErr instanceof Error ? iocErr.message : iocErr);
      }
    }

    if (newIocRecords.length > 0) {
      await autoEnrichNewIocs(newIocRecords, upload.organizationId ?? undefined).catch((err) =>
        console.warn("[log-analysis] Auto-enrichment skipped:", err instanceof Error ? err.message : err)
      );
    }

    // 5. Load enabled rules scoped to the org (and global rules with no org)
    const rules = await prisma.logAnalysisRule.findMany({
      where: {
        enabled: true,
        OR: [
          ...(upload.organizationId ? [{ organizationId: upload.organizationId }] : []),
          { organizationId: null },
        ],
      },
    });

    // 6. Run rules
    const matches = runRules(
      rules.map((r) => ({ ...r, conditions: r.conditions })),
      events,
      iocLookupMap
    );

    // 7. Create findings (group by ruleId)
    const byRule = new Map<string, typeof matches>();
    for (const m of matches) {
      const arr = byRule.get(m.ruleId) ?? [];
      arr.push(m);
      byRule.set(m.ruleId, arr);
    }

    const criticalCandidates: { title: string; severity: string; sourceLabel: string; detailPath: string }[] = [];

    for (const [ruleId, hits] of byRule.entries()) {
      const rule = rules.find((r) => r.id === ruleId);
      if (!rule) continue;
      const timestamps = hits
        .map((h) => events[h.eventLineNumber - 1]?.timestamp)
        .filter(Boolean) as Date[];
      const firstSeen = timestamps.length > 0 ? new Date(Math.min(...timestamps.map((d) => d.getTime()))) : null;
      const lastSeen  = timestamps.length > 0 ? new Date(Math.max(...timestamps.map((d) => d.getTime()))) : null;
      const sample    = hits[0];

      await prisma.logFinding.create({
        data: {
          uploadId,
          ruleId,
          title:        rule.name,
          description:  rule.description ?? undefined,
          severity:     rule.severity,
          eventCount:   hits.length,
          firstSeen:    firstSeen ?? undefined,
          lastSeen:     lastSeen  ?? undefined,
          matchedField: sample.matchedField,
          matchedValue: sample.matchedValue,
        },
      });

      await prisma.logAnalysisRule.update({
        where: { id: ruleId },
        data:  { hitCount: { increment: hits.length } },
      });

      criticalCandidates.push({ title: rule.name, severity: rule.severity, sourceLabel: "Log Analysis", detailPath: `/log-analysis/${uploadId}` });
    }

    await notifyCriticalFindings(criticalCandidates).catch((err) =>
      console.warn("[log-analysis] Critical finding alert failed:", err instanceof Error ? err.message : err)
    );

    // 8. Update upload status + counts
    await prisma.logUpload.update({
      where: { id: uploadId },
      data: {
        status:       "ready",
        eventCount:   events.length,
        findingCount: byRule.size,
      },
    });
  } catch (err) {
    await prisma.logUpload.update({
      where: { id: uploadId },
      data: {
        status:       "failed",
        errorMessage: err instanceof Error ? err.message : String(err),
      },
    });
    throw err;
  }
}
