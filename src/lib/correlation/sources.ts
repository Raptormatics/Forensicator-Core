/**
 * Correlation sources beyond investigations: PCAP, RAM and log analyses,
 * fed into the correlation engine (CorrelationSourceProvider in engine.ts)
 * so a domain in one host's network capture and in another host's
 * collected evidence is a link too.
 *
 * - PCAP: PcapIoc — public IPs and domains (DNS, TLS SNI, flows).
 * - RAM:  RamIoc — public foreign IPs/domains — and running process names.
 * - Log:  LogIoc — public IPs, domains, URLs, hashes, process names and
 *   usernames. Private IPs are left out: a firewall or DC log names every
 *   internal address, which would link it to nearly every host.
 *
 * An analysis is a host by its hostname, else its asset name, so it merges
 * with that machine's investigations; with neither it is a host of its own.
 * (Not its IP address: host identity is the short name before the first
 * dot.) A log from a firewall, proxy or DC covers many machines but is still
 * one host here — the device that produced it; its lines carry no hostname
 * to split it by. Only finished ("ready") analyses count.
 */
import { prisma } from "@/lib/db/prisma";
import {
  canonicalValue, candidateVariants, hostKey, orgScopeWhere,
  type CorrelationSource, type CorrelationSourceProvider, type ExtraSourceRef, type Observation, type PrevalenceCandidate,
} from "@/lib/correlation/engine";
import { isPrivateIp } from "@/lib/pcap-analysis/aggregator";

const IOC_TYPE: Record<string, string> = { ip: "shared_ip", domain: "shared_domain" };
const LOG_IOC_TYPE: Record<string, string> = {
  ip: "shared_ip", domain: "shared_domain", url: "shared_url",
  hash_md5: "shared_hash", hash_sha1: "shared_hash", hash_sha256: "shared_hash",
  process: "shared_process", username: "shared_account",
};
const logIocTypesFor = (corrType: string) => Object.keys(LOG_IOC_TYPE).filter((t) => LOG_IOC_TYPE[t] === corrType);
/** Log IOCs are regex-extracted from every line, so internal addresses come along too. */
const keepLogIoc = (type: string, value: string) => !!LOG_IOC_TYPE[type] && (type !== "ip" || !isPrivateIp(value));
const UPLOAD_SELECT = { id: true, caseId: true, hostname: true, assetName: true } as const;
type Upload = { id: string; caseId: string | null; hostname: string | null; assetName: string | null };
type Kind = "pcap" | "ram" | "log";

const nameOf = (u: Upload) => u.hostname?.trim() || u.assetName?.trim() || null;
const source = (kind: Kind, u: Upload): CorrelationSource => ({ id: `${kind}:${u.id}`, kind, caseId: u.caseId, hostname: nameOf(u) });

async function collect(caseIds: string[]): Promise<{ sources: CorrelationSource[]; observations: Observation[] }> {
  const where = { caseId: { in: caseIds }, status: "ready" };
  const [pcaps, rams, logs] = await Promise.all([
    prisma.pcapUpload.findMany({ where, select: UPLOAD_SELECT }),
    prisma.ramUpload.findMany({ where, select: UPLOAD_SELECT }),
    prisma.logUpload.findMany({ where, select: UPLOAD_SELECT }),
  ]);
  const pcapIds = pcaps.map((u) => u.id);
  const ramIds = rams.map((u) => u.id);
  const logIds = logs.map((u) => u.id);
  const [pcapIocs, ramIocs, ramProcs, logIocs] = await Promise.all([
    pcapIds.length ? prisma.pcapIoc.findMany({ where: { uploadId: { in: pcapIds } }, select: { uploadId: true, type: true, value: true } }) : [],
    ramIds.length ? prisma.ramIoc.findMany({ where: { uploadId: { in: ramIds } }, select: { uploadId: true, type: true, value: true } }) : [],
    ramIds.length ? prisma.ramProcess.groupBy({ by: ["uploadId", "name"], where: { uploadId: { in: ramIds } } }) : [],
    logIds.length ? prisma.logIoc.findMany({
      where: { uploadId: { in: logIds }, type: { in: Object.keys(LOG_IOC_TYPE) } },
      select: { uploadId: true, type: true, value: true },
    }) : [],
  ]);

  const observations: Observation[] = [];
  for (const i of pcapIocs) if (IOC_TYPE[i.type]) observations.push({ sourceId: `pcap:${i.uploadId}`, type: IOC_TYPE[i.type], raw: i.value });
  for (const i of ramIocs) if (IOC_TYPE[i.type]) observations.push({ sourceId: `ram:${i.uploadId}`, type: IOC_TYPE[i.type], raw: i.value });
  for (const p of ramProcs) if (p.name) observations.push({ sourceId: `ram:${p.uploadId}`, type: "shared_process", raw: p.name });
  for (const i of logIocs) if (keepLogIoc(i.type, i.value)) observations.push({ sourceId: `log:${i.uploadId}`, type: LOG_IOC_TYPE[i.type], raw: i.value });

  return {
    sources: [...pcaps.map((u) => source("pcap", u)), ...rams.map((u) => source("ram", u)), ...logs.map((u) => source("log", u))],
    observations,
  };
}

async function prevalence(candidates: PrevalenceCandidate[], orgIds: (string | null)[]) {
  const scope = { ...orgScopeWhere(orgIds), status: "ready" };
  const [pcaps, rams, logs] = await Promise.all([
    prisma.pcapUpload.findMany({ where: scope, select: UPLOAD_SELECT }),
    prisma.ramUpload.findMany({ where: scope, select: UPLOAD_SELECT }),
    prisma.logUpload.findMany({ where: scope, select: UPLOAD_SELECT }),
  ]);
  const hostOf = new Map<string, string>([
    ...pcaps.map((u) => [`pcap:${u.id}`, hostKey(nameOf(u), `pcap:${u.id}`)] as const),
    ...rams.map((u) => [`ram:${u.id}`, hostKey(nameOf(u), `ram:${u.id}`)] as const),
    ...logs.map((u) => [`log:${u.id}`, hostKey(nameOf(u), `log:${u.id}`)] as const),
  ]);

  const hostsByKey = new Map<string, Set<string>>();
  const note = (type: string, raw: string, sourceId: string) => {
    const host = hostOf.get(sourceId);
    if (!host) return;
    const key = `${type}::${canonicalValue(type, raw)}`;
    let s = hostsByKey.get(key);
    if (!s) hostsByKey.set(key, (s = new Set()));
    s.add(host);
  };

  const byType = (t: string) => candidateVariants(candidates.filter((c) => c.correlationType === t));
  for (const [iocType, corrType] of Object.entries(IOC_TYPE)) {
    const variants = byType(corrType);
    for (let i = 0; i < variants.length; i += 5000) {
      const where = { type: iocType, value: { in: variants.slice(i, i + 5000), mode: "insensitive" as const }, upload: scope };
      const [p, r] = await Promise.all([
        prisma.pcapIoc.groupBy({ by: ["uploadId", "value"], where }),
        prisma.ramIoc.groupBy({ by: ["uploadId", "value"], where }),
      ]);
      for (const row of p) note(corrType, row.value, `pcap:${row.uploadId}`);
      for (const row of r) note(corrType, row.value, `ram:${row.uploadId}`);
    }
  }
  const procs = byType("shared_process");
  for (let i = 0; i < procs.length; i += 5000) {
    const rows = await prisma.ramProcess.groupBy({
      by: ["uploadId", "name"],
      where: { name: { in: procs.slice(i, i + 5000), mode: "insensitive" }, upload: scope },
    });
    for (const row of rows) note("shared_process", row.name, `ram:${row.uploadId}`);
  }
  for (const corrType of new Set(Object.values(LOG_IOC_TYPE))) {
    const variants = byType(corrType);
    for (let i = 0; i < variants.length; i += 5000) {
      const rows = await prisma.logIoc.groupBy({
        by: ["uploadId", "type", "value"],
        where: { type: { in: logIocTypesFor(corrType) }, value: { in: variants.slice(i, i + 5000), mode: "insensitive" }, upload: scope },
      });
      for (const row of rows) if (keepLogIoc(row.type, row.value)) note(corrType, row.value, `log:${row.uploadId}`);
    }
  }

  return { hostsByKey, hosts: new Set(hostOf.values()) };
}

function ref(s: CorrelationSource): ExtraSourceRef {
  return { kind: s.kind, id: s.id.slice(s.kind.length + 1), hostname: s.hostname, caseId: s.caseId };
}

export const analysisSources: CorrelationSourceProvider = { collect, prevalence, ref };
