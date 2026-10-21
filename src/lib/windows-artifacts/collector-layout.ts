/**
 * Maps a file's path inside the Live Forensicator collector's
 * `artifacts\WindowsArtifacts\` output folder to the Windows Artifact role
 * Core parses it as — the single source of truth for the "Collector folder"
 * upload mode, shared by the upload page (to show the analyst what will be
 * uploaded before anything is sent) and the upload route (which re-derives
 * everything from the same relative path rather than trusting the client's
 * classification).
 *
 * Pure string logic, no Node imports — this file is bundled into the
 * client-side upload page.
 *
 * Folder layout mirrored from the collector's -WINARTIFACTS section
 * (collector/live-forensicator/Windows/Forensicator.ps1):
 *   Registry\{SYSTEM,SOFTWARE,SECURITY,SAM,DEFAULT,Amcache.hve}[.LOG1|.LOG2]
 *   Registry\<profile>\{NTUSER.DAT,UsrClass.dat}[.LOG1|.LOG2]
 *   Registry\Historical\<Windows.old|RegBack>\<HIVE>[.LOG1|.LOG2]
 *   Registry\RestorePoints\<shadow id>\...\_REGISTRY_{MACHINE,USER}_<name>
 *   Prefetch\*.pf, LNK\<profile>\...\*.lnk
 *   JumpLists\{Automatic,Custom}\<profile>\*
 *   NTFS\{$MFT,$J,UsnJournal_Metadata.txt,$LogFile}, NTFS\Volumes\<tag>\{$MFT,$J}, NTFS\Memory\*
 *   SRUM\SRUDB.dat, Search\{Windows.edb,Windows.db,Windows-gather.db[-wal|-shm]}
 *   Defender\Quarantine\{Entries,ResourceData}\..., Defender\{DetectionHistory,Support}\...
 *   WER\<System|profile>\..., RecycleBin\<SID>\{$I*,$R*}
 *   Notifications\<profile>\{wpndatabase.db,appdb.dat}, BITS\{qmgr0.dat,qmgr1.dat,qmgr.db}
 *   Timeline\<profile>\<cdp id>\ActivitiesCache.db
 *   WMI\PermanentSubscriptions.json, WMI\Repository\...
 *   ApplicationArtifacts\<target>\<profile|System>\...
 *   CollectionManifest\artifact-collection-manifest.json
 *
 * plus the collector's other artifacts\<folder> outputs next to
 * WindowsArtifacts: LOG4J\*.txt, GroupPolicy\GPOReport.html and the RAM\
 * HTML/clipboard extras (parsed here as collector_extra), and EVTX\,
 * IISLogs\, TomCatLogs\, PCAP\ and RAM images, which belong to the Log /
 * PCAP / RAM Analysis uploads and are reported as such.
 *
 * Every path handled here is relative to the host's `artifacts` folder:
 * "WindowsArtifacts/Registry/SYSTEM", "LOG4J/log4j.txt", ...
 */
import type { WinArtifactFileRole } from "./types";

export type CollectorClassification =
  /** A parseable artifact — becomes one WindowsArtifactFile. */
  | {
      kind: "artifact";
      role: WinArtifactFileRole;
      /** Pairs a hive with its .LOG1/.LOG2 sidecars and $J with its
       * fsutil metadata — the sidecar's `attachTo` equals this. */
      groupKey: string;
      profileName: string | null;
      provenance: string | null;
    }
  /** Rides along on another artifact's WindowsArtifactFile row. */
  | { kind: "sidecar"; sidecar: "log1" | "log2" | "usn_metadata"; attachTo: string }
  /** The collector's own CollectionManifest JSON — verified against, not parsed as an artifact. */
  | { kind: "manifest" }
  /** Recognized collector output that Core doesn't parse (yet) — listed, not uploaded. */
  | { kind: "unsupported"; label: string }
  /** Not collector output Core cares about (CSV copy of the manifest, WER attachments, ...). */
  | { kind: "ignored"; reason: string };

/** Roles the collector-folder intake currently uploads. A role recognized by
 * classifyCollectorPath() but absent here is reported as "unsupported". */
export const SUPPORTED_COLLECTOR_ROLES: ReadonlySet<WinArtifactFileRole> = new Set<WinArtifactFileRole>([
  "system_hive", "software_hive", "security_hive", "sam_hive", "default_hive", "ntuser_hive", "amcache_hive", "usrclass_hive",
  "prefetch", "lnk", "jumplist_automatic", "jumplist_custom", "mft", "usnjrnl", "srum_db",
  "wer_report", "wer_dump", "recycle_bin", "notification_db", "search_edb",
  "quarantine_entry", "quarantine_resource", "bits_queue", "timeline_db",
  "search_sqlite", "bits_ese", "wmi_subscriptions", "wbem_repository", "defender_detection_history",
  "defender_support_log", "app_artifact", "logfile", "recycle_payload", "memory_file", "collector_extra",
]);

const MACHINE_HIVES: Record<string, WinArtifactFileRole> = {
  system: "system_hive",
  software: "software_hive",
  security: "security_hive",
  sam: "sam_hive",
  default: "default_hive",
  "amcache.hve": "amcache_hive",
};

const PROFILE_HIVES: Record<string, WinArtifactFileRole> = {
  "ntuser.dat": "ntuser_hive",
  "usrclass.dat": "usrclass_hive",
};

/** Normalizes a browser webkitRelativePath / zip entry / Windows path to
 * forward-slash segments starting just below `WindowsArtifacts`. Returns
 * null when the path isn't inside a WindowsArtifacts folder at all. */
export function windowsArtifactsRelativePath(rawPath: string): string | null {
  const parts = rawPath.replace(/\\/g, "/").split("/").filter(Boolean);
  const idx = parts.findIndex((p) => p.toLowerCase() === "windowsartifacts");
  if (idx < 0 || idx === parts.length - 1) return null;
  return parts.slice(idx + 1).join("/");
}

/** Path relative to the host's `artifacts` folder — the form every
 * classifier/route function here takes — from whichever folder the analyst
 * picked: the host folder (<host>/artifacts/...), `artifacts` itself, or
 * `WindowsArtifacts` itself. Null when it's none of those. */
export function collectorRelativePath(rawPath: string): string | null {
  const parts = rawPath.replace(/\\/g, "/").split("/").filter(Boolean);
  const lower = parts.map((p) => p.toLowerCase());
  const wa = lower.indexOf("windowsartifacts");
  const art = lower.indexOf("artifacts");
  if (art >= 0 && art < parts.length - 2 && (wa < 0 || wa === art + 1)) return parts.slice(art + 1).join("/");
  if (wa >= 0 && wa < parts.length - 1) return parts.slice(wa).join("/");
  return null;
}

/** The host folder name (e.g. "DESKTOP-FAVOUR") when the analyst picked the
 * collector's per-host folder rather than WindowsArtifacts itself —
 * <host>/artifacts/WindowsArtifacts/... */
export function hostnameFromCollectorPath(rawPath: string): string | null {
  const parts = rawPath.replace(/\\/g, "/").split("/").filter(Boolean);
  const idx = parts.findIndex((p) => p.toLowerCase() === "windowsartifacts");
  if (idx >= 2 && parts[idx - 1].toLowerCase() === "artifacts") return parts[idx - 2];
  return null;
}

function stripLogSuffix(name: string): { base: string; log: "log1" | "log2" | null } {
  const m = name.match(/^(.*)\.(log1|log2)$/i);
  return m ? { base: m[1], log: m[2].toLowerCase() as "log1" | "log2" } : { base: name, log: null };
}

function hive(role: WinArtifactFileRole, groupKey: string, log: "log1" | "log2" | null, profileName: string | null, provenance: string | null): CollectorClassification {
  return log
    ? { kind: "sidecar", sidecar: log, attachTo: groupKey }
    : { kind: "artifact", role, groupKey, profileName, provenance };
}

/** `relPath` is relative to the host's `artifacts` folder (see collectorRelativePath). */
export function classifyCollectorPath(relPath: string): CollectorClassification {
  const all = relPath.replace(/\\/g, "/").split("/").filter(Boolean);
  if ((all[0] ?? "").toLowerCase() !== "windowsartifacts") return classifyHostExtra(all);
  const parts = all.slice(1);
  const lower = parts.map((p) => p.toLowerCase());
  const name = parts[parts.length - 1] ?? "";
  const lname = name.toLowerCase();
  const top = lower[0];
  const dirKey = lower.slice(0, -1).join("/");

  switch (top) {
    case "registry": {
      const { base, log } = stripLogSuffix(name);
      const lbase = base.toLowerCase();
      // Registry\Historical\<label>\<HIVE>
      if (lower[1] === "historical" && parts.length === 4) {
        const role = MACHINE_HIVES[lbase];
        if (role) return hive(role, `${dirKey}/${lbase}`, log, null, `historical:${parts[2]}`);
      }
      // Registry\RestorePoints\<shadow id>\...\_REGISTRY_<MACHINE|USER>_<name>
      if (lower[1] === "restorepoints" && parts.length >= 4) {
        const provenance = `restore_point:${parts[2]}`;
        const machine = lbase.match(/^_registry_machine_(system|software|security|sam)$/);
        if (machine) return hive(MACHINE_HIVES[machine[1]], `${dirKey}/${lbase}`, log, null, provenance);
        if (lbase === "_registry_user_.default") return hive("default_hive", `${dirKey}/${lbase}`, log, null, provenance);
        const user = base.match(/^_REGISTRY_USER_(NTUSER|USRCLASS)_(S-1-[0-9-]+)$/i);
        if (user) return hive(user[1].toUpperCase() === "NTUSER" ? "ntuser_hive" : "usrclass_hive", `${dirKey}/${lbase}`, log, user[2], provenance);
        return { kind: "ignored", reason: "unrecognized restore-point file" };
      }
      // Registry\<HIVE>
      if (parts.length === 2 && MACHINE_HIVES[lbase]) {
        return hive(MACHINE_HIVES[lbase], `registry/${lbase}`, log, null, "live");
      }
      // Registry\<profile>\NTUSER.DAT|UsrClass.dat
      if (parts.length === 3 && PROFILE_HIVES[lbase]) {
        return hive(PROFILE_HIVES[lbase], `${dirKey}/${lbase}`, log, parts[1], "live");
      }
      return { kind: "ignored", reason: "unrecognized registry file" };
    }

    case "prefetch":
      return lname.endsWith(".pf")
        ? { kind: "artifact", role: "prefetch", groupKey: relPath, profileName: null, provenance: null }
        : { kind: "ignored", reason: "not a .pf file" };

    case "lnk":
      return lname.endsWith(".lnk")
        ? { kind: "artifact", role: "lnk", groupKey: relPath, profileName: parts[1] ?? null, provenance: null }
        : { kind: "ignored", reason: "not a .lnk file" };

    case "jumplists":
      if (lname.endsWith(".automaticdestinations-ms")) return { kind: "artifact", role: "jumplist_automatic", groupKey: relPath, profileName: parts[2] ?? null, provenance: null };
      if (lname.endsWith(".customdestinations-ms")) return { kind: "artifact", role: "jumplist_custom", groupKey: relPath, profileName: parts[2] ?? null, provenance: null };
      return { kind: "ignored", reason: "not a Jump List file" };

    case "ntfs": {
      // NTFS\Volumes\<tag>\$MFT|$J — one per additional volume.
      const volume = lower[1] === "volumes" && parts.length === 4 ? parts[2] : null;
      const provenance = volume ? `volume:${volume}` : "live";
      if (lower[1] === "memory") return { kind: "artifact", role: "memory_file", groupKey: relPath, profileName: null, provenance: null };
      if (lname === "$mft") return { kind: "artifact", role: "mft", groupKey: `${dirKey}/$mft`, profileName: null, provenance };
      if (lname === "$j") return { kind: "artifact", role: "usnjrnl", groupKey: `${dirKey}/$j`, profileName: null, provenance };
      if (lname === "usnjournal_metadata.txt") return { kind: "sidecar", sidecar: "usn_metadata", attachTo: `${dirKey}/$j` };
      if (lname === "$logfile") return { kind: "artifact", role: "logfile", groupKey: `${dirKey}/$logfile`, profileName: null, provenance };
      return { kind: "ignored", reason: "unrecognized NTFS file" };
    }

    case "srum":
      return lname === "srudb.dat"
        ? { kind: "artifact", role: "srum_db", groupKey: relPath, profileName: null, provenance: null }
        : { kind: "ignored", reason: "SRUM extensions export (Core reads them from the SOFTWARE hive instead)" };

    case "search":
      if (lname === "windows.edb") return { kind: "artifact", role: "search_edb", groupKey: relPath, profileName: null, provenance: null };
      // Windows 11 SQLite format; -wal/-shm ride along on the database's own
      // row (log1/log2 storage slots) so uncheckpointed frames are applied.
      if (lname === "windows.db" || lname === "windows-gather.db") return { kind: "artifact", role: "search_sqlite", groupKey: `search/${lname}`, profileName: null, provenance: null };
      if (lname.endsWith(".db-wal")) return { kind: "sidecar", sidecar: "log1", attachTo: `search/${lname.slice(0, -4)}` };
      if (lname.endsWith(".db-shm")) return { kind: "sidecar", sidecar: "log2", attachTo: `search/${lname.slice(0, -4)}` };
      return { kind: "ignored", reason: "unrecognized Search file" };

    case "defender":
      if (lower[1] === "quarantine" && lower[2] === "entries" && parts.length >= 4) return { kind: "artifact", role: "quarantine_entry", groupKey: relPath, profileName: null, provenance: null };
      if (lower[1] === "quarantine" && lower[2] === "resourcedata" && parts.length >= 4) return { kind: "artifact", role: "quarantine_resource", groupKey: relPath, profileName: null, provenance: null };
      if (lower[1] === "detectionhistory") return { kind: "artifact", role: "defender_detection_history", groupKey: relPath, profileName: null, provenance: null };
      if (lower[1] === "support") {
        return lname.endsWith(".log")
          ? { kind: "artifact", role: "defender_support_log", groupKey: relPath, profileName: null, provenance: null }
          : { kind: "ignored", reason: "Defender WPP/ETW binary trace (not text)" };
      }
      return { kind: "ignored", reason: "unrecognized Defender file" };

    case "wer":
      if (lname.endsWith(".wer")) return { kind: "artifact", role: "wer_report", groupKey: relPath, profileName: parts[1] && lower[1] !== "system" ? parts[1] : null, provenance: null };
      if (lname.endsWith(".dmp") || lname.endsWith(".hdmp")) return { kind: "artifact", role: "wer_dump", groupKey: relPath, profileName: parts[1] && lower[1] !== "system" ? parts[1] : null, provenance: null };
      return { kind: "ignored", reason: "WER attachment (not a Report.wer or dump)" };

    case "recyclebin": {
      const sid = parts.length === 3 ? parts[1] : null;
      if (lname.startsWith("$i")) return { kind: "artifact", role: "recycle_bin", groupKey: relPath, profileName: sid, provenance: null };
      if (lname.startsWith("$r")) return { kind: "artifact", role: "recycle_payload", groupKey: relPath, profileName: sid, provenance: null };
      return { kind: "ignored", reason: "not a $I/$R file" };
    }

    case "notifications":
      return lname === "wpndatabase.db" || lname === "appdb.dat"
        ? { kind: "artifact", role: "notification_db", groupKey: relPath, profileName: parts[1] ?? null, provenance: null }
        : { kind: "ignored", reason: "unrecognized notification file" };

    case "bits":
      if (lname === "qmgr0.dat" || lname === "qmgr1.dat") return { kind: "artifact", role: "bits_queue", groupKey: relPath, profileName: null, provenance: null };
      if (lname === "qmgr.db") return { kind: "artifact", role: "bits_ese", groupKey: relPath, profileName: null, provenance: null };
      return { kind: "ignored", reason: "unrecognized BITS file" };

    case "timeline":
      return lname === "activitiescache.db"
        ? { kind: "artifact", role: "timeline_db", groupKey: relPath, profileName: parts[1] ?? null, provenance: null }
        : { kind: "ignored", reason: "ActivitiesCache.db sidecar" };

    case "wmi":
      if (lname === "permanentsubscriptions.json") return { kind: "artifact", role: "wmi_subscriptions", groupKey: relPath, profileName: null, provenance: null };
      // OBJECTS.DATA holds the instance data; INDEX.BTR/MAPPING*.MAP are
      // page indexes with nothing to carve.
      if (lower[1] === "repository") {
        return lname === "objects.data"
          ? { kind: "artifact", role: "wbem_repository", groupKey: relPath, profileName: null, provenance: null }
          : { kind: "ignored", reason: "WBEM repository index/mapping file" };
      }
      return { kind: "ignored", reason: "unrecognized WMI file" };

    case "applicationartifacts":
      return parts.length >= 4
        ? { kind: "artifact", role: "app_artifact", groupKey: relPath, profileName: parts[2], provenance: null }
        : { kind: "ignored", reason: "application artifact outside a <target>\\<profile> folder" };

    case "collectionmanifest":
      return lname === "artifact-collection-manifest.json"
        ? { kind: "manifest" }
        : { kind: "ignored", reason: "manifest CSV/summary (the JSON manifest is used)" };

    default:
      return { kind: "ignored", reason: "not a recognized collector artifact folder" };
  }
}

/** The collector's artifacts\<folder> outputs other than WindowsArtifacts. */
function classifyHostExtra(parts: string[]): CollectorClassification {
  const lower = parts.map((p) => p.toLowerCase());
  const lname = lower[lower.length - 1] ?? "";
  const relPath = parts.join("/");
  const extra = (): CollectorClassification => ({ kind: "artifact", role: "collector_extra", groupKey: relPath, profileName: null, provenance: null });
  switch (lower[0]) {
    case "log4j":
      return lname.endsWith(".txt") ? extra() : { kind: "ignored", reason: "not a LOG4J scan result" };
    case "grouppolicy":
      return lname.endsWith(".html") ? extra() : { kind: "ignored", reason: "not a GPResult report" };
    case "ram":
      if (lname.endsWith(".html") || lname === "clipboard.txt") return extra();
      return { kind: "unsupported", label: "Memory image — upload via RAM Analysis" };
    case "evtx":
      return { kind: "unsupported", label: "Event logs — upload via Log Analysis (raw .evtx and LogChannels\\*.log are supported)" };
    case "iislogs":
    case "tomcatlogs":
      return { kind: "unsupported", label: "Web server logs — upload via Log Analysis" };
    case "pcap":
      return { kind: "unsupported", label: "Packet capture — upload via PCAP Analysis" };
    default:
      return { kind: "ignored", reason: "not a recognized collector artifact folder" };
  }
}

/** classifyCollectorPath() for a role Core recognizes but this deployment's
 * intake doesn't upload yet folds into "unsupported" here, so callers never
 * have to consult SUPPORTED_COLLECTOR_ROLES themselves. */
export function classifyForUpload(relPath: string): CollectorClassification {
  const c = classifyCollectorPath(relPath);
  if (c.kind === "artifact" && !SUPPORTED_COLLECTOR_ROLES.has(c.role)) {
    return { kind: "unsupported", label: c.role };
  }
  return c;
}
