/**
 * Core's SigmaHQ rule library: downloads a SigmaHQ release package
 * (github.com/SigmaHQ/sigma/releases), compiles every rule
 * (src/lib/sigma/compile.ts) and stores it in SigmaRule. Manual only in
 * Core — an admin clicks "Update rules" in Settings → Threat Intelligence,
 * like the URLhaus and MalwareBazaar feed caches.
 *
 * A rule keeps its enabled/disabled state and hit count across updates;
 * rules dropped from the package are removed (their findings keep their
 * own title and severity).
 */
import AdmZip from "adm-zip";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db/prisma";
import { compileSigmaYaml } from "./compile";
import { logsourceCovered } from "./engine";

export const SIGMA_PACKAGES = {
  "core": { asset: "sigma_core.zip", label: "Core", description: "High and critical rules (stable and test)" },
  "core+": { asset: "sigma_core+.zip", label: "Core+", description: "Core, plus medium rules" },
  "core++": { asset: "sigma_core++.zip", label: "Core++", description: "Core+, plus experimental rules" },
  "all_rules": { asset: "sigma_all_rules.zip", label: "All rules", description: "Everything, including threat-hunting and emerging-threat rules" },
} as const;

export type SigmaPackage = keyof typeof SIGMA_PACKAGES;
export const DEFAULT_SIGMA_PACKAGE: SigmaPackage = "core+";

const RELEASES_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest";
const STATE_ID = "sigmahq";

export function isSigmaPackage(v: unknown): v is SigmaPackage {
  return typeof v === "string" && v in SIGMA_PACKAGES;
}

export async function getSigmaLibraryState() {
  const state = await prisma.sigmaLibraryState.findUnique({ where: { id: STATE_ID } });
  return state ?? { id: STATE_ID, package: DEFAULT_SIGMA_PACKAGE, releaseTag: null, syncedAt: null, ruleCount: 0, supportedCount: 0, coveredCount: 0, lastError: null, updatedAt: new Date(0) };
}

async function latestRelease(asset: string): Promise<{ tag: string; url: string }> {
  const res = await fetch(RELEASES_API, { headers: { Accept: "application/vnd.github+json", "User-Agent": "Forensicator-Core" } });
  if (!res.ok) throw new Error(`GitHub releases lookup failed: ${res.status} ${res.statusText}`);
  const rel = (await res.json()) as { tag_name?: string; assets?: { name: string; browser_download_url: string }[] };
  const a = rel.assets?.find((x) => x.name === asset);
  if (!rel.tag_name || !a) throw new Error(`SigmaHQ release has no ${asset}`);
  return { tag: rel.tag_name, url: a.browser_download_url };
}

export type SigmaSyncResult = {
  package: SigmaPackage; releaseTag: string; total: number; supported: number; covered: number;
  added: number; updated: number; removed: number;
};

export async function syncSigmaRules(pkg?: SigmaPackage): Promise<SigmaSyncResult> {
  const state = await getSigmaLibraryState();
  const chosen: SigmaPackage = pkg ?? (isSigmaPackage(state.package) ? state.package : DEFAULT_SIGMA_PACKAGE);
  try {
    const { tag, url } = await latestRelease(SIGMA_PACKAGES[chosen].asset);
    const res = await fetch(url, { headers: { "User-Agent": "Forensicator-Core" } });
    if (!res.ok) throw new Error(`SigmaHQ package download failed: ${res.status} ${res.statusText}`);
    const zip = new AdmZip(Buffer.from(await res.arrayBuffer()));

    type Row = Prisma.SigmaRuleCreateManyInput;
    const rows = new Map<string, Row>();
    for (const entry of zip.getEntries()) {
      if (entry.isDirectory || !/\.ya?ml$/i.test(entry.entryName)) continue;
      const text = entry.getData().toString("utf8");
      const r = compileSigmaYaml(text);
      const m = r.meta;
      if (!m?.sigmaId || rows.has(m.sigmaId)) continue;
      rows.set(m.sigmaId, {
        sigmaId: m.sigmaId, title: m.title, description: m.description, status: m.status, level: m.level, author: m.author,
        tags: m.tags, references: m.references, falsePositives: m.falsePositives,
        product: m.product, category: m.category, service: m.service, path: entry.entryName, yaml: text,
        compiled: r.ok ? (r.compiled as unknown as Prisma.InputJsonValue) : undefined,
        supported: r.ok, covered: logsourceCovered(m.product, m.category, m.service),
        unsupportedReason: r.ok ? null : r.reason, source: "sigmahq",
      });
    }
    if (rows.size === 0) throw new Error("the package contained no Sigma rules");

    const existing = new Map((await prisma.sigmaRule.findMany({ where: { source: "sigmahq" }, select: { id: true, sigmaId: true } }))
      .map((r) => [r.sigmaId, r.id]));
    let added = 0, updated = 0;
    const toCreate: Row[] = [];
    for (const [sigmaId, row] of rows) {
      const id = existing.get(sigmaId);
      if (id) {
        // enabled and hitCount are the user's / history's, not the package's.
        await prisma.sigmaRule.update({ where: { id }, data: row });
        updated++;
      } else {
        toCreate.push(row);
      }
    }
    for (let i = 0; i < toCreate.length; i += 500) {
      const batch = toCreate.slice(i, i + 500);
      await prisma.sigmaRule.createMany({ data: batch, skipDuplicates: true });
      added += batch.length;
    }
    const gone = [...existing.keys()].filter((k) => !rows.has(k));
    if (gone.length) await prisma.sigmaRule.deleteMany({ where: { source: "sigmahq", sigmaId: { in: gone } } });

    const all = [...rows.values()];
    const result: SigmaSyncResult = {
      package: chosen, releaseTag: tag, total: all.length,
      supported: all.filter((r) => r.supported).length,
      covered: all.filter((r) => r.supported && r.covered).length,
      added, updated, removed: gone.length,
    };
    const data = { package: chosen, releaseTag: tag, syncedAt: new Date(), ruleCount: result.total, supportedCount: result.supported, coveredCount: result.covered, lastError: null };
    await prisma.sigmaLibraryState.upsert({ where: { id: STATE_ID }, create: { id: STATE_ID, ...data }, update: data });
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await prisma.sigmaLibraryState.upsert({
      where: { id: STATE_ID },
      create: { id: STATE_ID, package: chosen, lastError: message },
      update: { lastError: message },
    }).catch(() => undefined);
    throw err;
  }
}
