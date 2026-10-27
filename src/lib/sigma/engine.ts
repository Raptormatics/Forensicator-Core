/**
 * Evaluates compiled Sigma rules (compile.ts) against Log Analysis events.
 *
 * An event is seen through a SigmaEventView, built from its raw line and
 * decoder output:
 *   - Windows (and Sysmon for Linux) Event XML: the System fields (EventID,
 *     Channel, Provider_Name, Computer, ...) and every EventData/UserData
 *     field under its own name — exactly the field names Sigma's Windows
 *     rules use. Security 4688 also answers to the Sysmon process-creation
 *     names (Image, ParentImage), as in pySigma's windows-audit pipeline.
 *   - Everything else: Sigma's generic field names mapped to the decoder's
 *     ECS fields (CommandLine -> process.command_line, cs-uri-query ->
 *     url.query, ...), the decoder's own field names, every key of a JSON
 *     line (dotted for nested objects — CloudTrail, Okta, Kubernetes audit,
 *     Zeek JSON, ...), and auditd's key=value pairs.
 * Keyword selections search the raw line.
 *
 * Each event also gets the Sigma logsources it belongs to (product,
 * category, service), and only rules for those logsources are evaluated.
 */
import type { CompiledSigmaRule, Cond, FieldTest, ValueTest } from "./compile";

// ── Logsources ──────────────────────────────────────────────────────────

const WINDOWS_CHANNEL_SERVICE: Record<string, string> = {
  "security": "security",
  "system": "system",
  "application": "application",
  "microsoft-windows-sysmon/operational": "sysmon",
  "microsoft-windows-powershell/operational": "powershell",
  "windows powershell": "powershell-classic",
  "microsoft-windows-taskscheduler/operational": "taskscheduler",
  "microsoft-windows-wmi-activity/operational": "wmi",
  "microsoft-windows-windows defender/operational": "windefend",
  "microsoft-windows-bits-client/operational": "bits-client",
  "microsoft-windows-codeintegrity/operational": "codeintegrity-operational",
  "dns server": "dns-server",
  "microsoft-windows-dns-client/operational": "dns-client",
  "microsoft-windows-windows firewall with advanced security/firewall": "firewall-as",
  "microsoft-windows-ntlm/operational": "ntlm",
  "microsoft-windows-terminalservices-localsessionmanager/operational": "terminalservices-localsessionmanager",
  "microsoft-windows-terminalservices-remoteconnectionmanager/operational": "terminalservices-remoteconnectionmanager",
  "microsoft-windows-appxdeploymentserver/operational": "appxdeployment-server",
  "msexchange management": "msexchange-management",
  "microsoft-iis-configuration/operational": "iis-configuration",
  "microsoft-windows-driverframeworks-usermode/operational": "driver-framework",
  "openssh/operational": "openssh",
  "microsoft-windows-smbclient/security": "smbclient-security",
  "microsoft-windows-smbclient/connectivity": "smbclient-connectivity",
  "microsoft-windows-smbserver/security": "smbserver-security",
  "microsoft-windows-shell-core/operational": "shell-core",
  "microsoft-windows-capi2/operational": "capi2",
  "microsoft-windows-lsa/operational": "lsa-server",
  "microsoft-windows-dhcp-server/operational": "dhcp",
  "microsoft-windows-printservice/admin": "printservice-admin",
  "microsoft-windows-printservice/operational": "printservice-operational",
  "microsoft-windows-security-mitigations/kernel mode": "security-mitigations",
  "microsoft-windows-security-mitigations/user mode": "security-mitigations",
  "microsoft-windows-kernel-shimengine/operational": "kernel-shimengine",
  "microsoft-windows-vhdmp-operational": "vhdmp",
  "microsoft-windows-appmodel-runtime/admin": "appmodel-runtime",
  "microsoft-windows-diagnosis-scripted/operational": "diagnosis-scripted",
  "microsoft-windows-certificateservicesclient-lifecycle-system/operational": "certificateservicesclient-lifecycle-system",
  "microsoft-windows-hyper-v-worker-admin": "hyper-v-worker",
  "microsoft-windows-directoryservice/operational": "directoryservice",
  "directory service": "directoryservice",
  "microsoft-windows-sense/operational": "sense",
};

// AppLocker writes to several channels; all are the one Sigma service.
function windowsService(channel: string): string | null {
  const c = channel.toLowerCase();
  if (c.startsWith("microsoft-windows-applocker/")) return "applocker";
  return WINDOWS_CHANNEL_SERVICE[c] ?? null;
}

const SYSMON_CATEGORIES: Record<string, string[]> = {
  "1": ["process_creation"], "2": ["file_change"], "3": ["network_connection"], "4": ["sysmon_status"],
  "5": ["process_termination"], "6": ["driver_load"], "7": ["image_load"], "8": ["create_remote_thread"],
  "9": ["raw_access_thread"], "10": ["process_access"], "11": ["file_event"],
  "12": ["registry_event", "registry_add", "registry_delete"], "13": ["registry_event", "registry_set"],
  "14": ["registry_event", "registry_rename"], "15": ["create_stream_hash"], "16": ["sysmon_status"],
  "17": ["pipe_created"], "18": ["pipe_created"], "19": ["wmi_event"], "20": ["wmi_event"], "21": ["wmi_event"],
  "22": ["dns_query"], "23": ["file_delete"], "24": ["clipboard_capture"], "25": ["process_tampering"],
  "26": ["file_delete", "file_delete_detected"], "27": ["file_block_executable"], "28": ["file_block_shredding"],
  "29": ["file_executable_detected"], "255": ["sysmon_error"],
};

/** Every (product, category, service) combination an event satisfies, as index keys. */
function logsourceKeys(product: string | null, categories: string[], service: string | null): string[] {
  const keys: string[] = [];
  for (const p of product ? [product, ""] : [""]) {
    for (const c of [...categories, ""]) {
      for (const s of service ? [service, ""] : [""]) {
        if (p || c || s) keys.push(`${p}|${c}|${s}`);
      }
    }
  }
  return keys;
}

export function ruleLogsourceKey(product: string | null, category: string | null, service: string | null): string {
  return `${product ?? ""}|${category ?? ""}|${service ?? ""}`;
}

// ── Field access ────────────────────────────────────────────────────────

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };

function decodeXml(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e: string) =>
    e[0] === "#" ? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENTITIES[e.toLowerCase()]);
}

type Fields = Map<string, string[]>;

function add(f: Fields, k: string, v: string) {
  const key = k.toLowerCase();
  const arr = f.get(key);
  if (arr) arr.push(v); else f.set(key, [v]);
}

function parseEventXml(raw: string): Fields {
  const f: Fields = new Map();
  const one = (re: RegExp, name: string) => { const m = raw.match(re); if (m) add(f, name, decodeXml(m[1])); };
  one(/<EventID[^>]*>(\d+)<\/EventID>/, "EventID");
  one(/<Provider\s+Name=['"]([^'"]+)['"]/, "Provider_Name");
  one(/<Channel>([^<]*)<\/Channel>/, "Channel");
  one(/<Computer>([^<]*)<\/Computer>/, "Computer");
  one(/<Level>(\d+)<\/Level>/, "Level");
  one(/<Task>(\d+)<\/Task>/, "Task");
  one(/<Opcode>(\d+)<\/Opcode>/, "Opcode");
  one(/<Keywords>([^<]*)<\/Keywords>/, "Keywords");
  one(/<EventRecordID>(\d+)<\/EventRecordID>/, "EventRecordID");
  one(/<Security\s+UserID=['"]([^'"]+)['"]/, "SecurityUserID");
  for (const m of raw.matchAll(/<Data\s+Name=['"]([^'"]+)['"]\s*(?:\/>|>([\s\S]*?)<\/Data>)/g)) add(f, m[1], decodeXml(m[2] ?? ""));
  for (const m of raw.matchAll(/<Data>([\s\S]*?)<\/Data>/g)) add(f, "Data", decodeXml(m[1]));
  const user = raw.match(/<UserData>([\s\S]*)<\/UserData>/);
  if (user) for (const m of user[1].matchAll(/<(\w+)(?:\s[^>]*)?>([^<]*)<\/\1>/g)) add(f, m[1], decodeXml(m[2]));
  return f;
}

// Security 4688 under Sysmon's process-creation field names.
const SECURITY_4688_ALIASES: Record<string, string> = {
  image: "newprocessname", parentimage: "parentprocessname", user: "subjectusername", logonid: "subjectlogonid",
};

// Sigma generic field names -> ECS fields the decoders fill.
const ECS_ALIASES: Record<string, string[]> = {
  image: ["process.executable", "process.name"],
  commandline: ["process.command_line"],
  parentimage: ["process.parent.executable", "process.parent.name"],
  parentcommandline: ["process.parent.command_line"],
  processid: ["process.pid"],
  user: ["user.name"],
  username: ["user.name"],
  targetfilename: ["file.path"],
  sourceip: ["source.ip"], src_ip: ["source.ip"], "c-ip": ["source.ip"], srcip: ["source.ip"],
  destinationip: ["destination.ip"], dst_ip: ["destination.ip"], dstip: ["destination.ip"],
  sourceport: ["source.port"], src_port: ["source.port"],
  destinationport: ["destination.port"], dst_port: ["destination.port"],
  destinationhostname: ["destination.hostname", "destination.domain"],
  "c-uri": ["url.original"], "cs-uri": ["url.original"],
  // Sigma's webserver rules search the whole request URI under cs-uri-query.
  "c-uri-query": ["url.original", "url.query"], "cs-uri-query": ["url.original", "url.query"],
  "c-uri-stem": ["url.path"], "cs-uri-stem": ["url.path"],
  "c-uri-extension": ["url.extension"],
  "cs-method": ["http.request.method"], method: ["http.request.method"],
  "sc-status": ["http.response.status_code"], status: ["http.response.status_code"],
  "c-useragent": ["user_agent.original"], "cs-user-agent": ["user_agent.original"], useragent: ["user_agent.original"],
  "cs-referer": ["http.request.referrer"], "cs-referrer": ["http.request.referrer"],
  "cs-host": ["url.domain", "destination.domain"], "r-dns": ["url.domain", "destination.domain"],
  query: ["dns.question.name"], queryname: ["dns.question.name"],
  record_type: ["dns.question.type"], answer: ["dns.answers.data"],
  action: ["event.action"],
};

function normalizedValues(normalized: Record<string, unknown>, path: string): string[] | undefined {
  const v = normalized[path];
  if (v === undefined || v === null || v === "") return undefined;
  return Array.isArray(v) ? v.map(String) : [String(v)];
}

function flattenJson(obj: unknown, prefix: string, f: Fields) {
  if (obj === null || obj === undefined) return;
  if (Array.isArray(obj)) {
    for (const x of obj) {
      if (x && typeof x === "object") flattenJson(x, prefix, f);
      else if (prefix) add(f, prefix, String(x));
    }
    return;
  }
  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) flattenJson(v, prefix ? `${prefix}.${k}` : k, f);
    return;
  }
  if (prefix) add(f, prefix, String(obj));
}

export type SigmaInputEvent = { raw: string; normalized: unknown };

export class SigmaEventView {
  readonly raw: string;
  private readonly normalized: Record<string, unknown>;
  private xml: Fields | null = null;
  private json: Fields | null | undefined;
  private kv: Fields | null = null;
  readonly isEventXml: boolean;
  private rawLowerCache: string[] | null = null;
  get rawList(): string[] { return [this.raw]; }
  get rawLowerList(): string[] { return (this.rawLowerCache ??= [this.raw.toLowerCase()]); }
  readonly keys: string[];
  private readonly is4688: boolean;

  constructor(ev: SigmaInputEvent) {
    this.raw = ev.raw ?? "";
    this.normalized = (ev.normalized && typeof ev.normalized === "object" ? ev.normalized : {}) as Record<string, unknown>;
    this.isEventXml = this.raw.includes("<Event") && this.raw.includes("<System>");
    if (this.isEventXml) this.xml = parseEventXml(this.raw);
    const eventId = this.xml?.get("eventid")?.[0] ?? "";
    this.is4688 = eventId === "4688" && (this.xml?.get("channel")?.[0] ?? "").toLowerCase() === "security";
    this.keys = this.computeKeys(eventId);
  }

  private computeKeys(eventId: string): string[] {
    if (this.xml) {
      const channel = this.xml.get("channel")?.[0] ?? "";
      const provider = (this.xml.get("provider_name")?.[0] ?? "").toLowerCase();
      if (provider.startsWith("linux-sysmon") || channel.toLowerCase().startsWith("linux-sysmon")) {
        return logsourceKeys("linux", SYSMON_CATEGORIES[eventId] ?? [], "sysmon");
      }
      const service = windowsService(channel);
      const cats: string[] = [];
      if (service === "sysmon") cats.push(...(SYSMON_CATEGORIES[eventId] ?? []));
      if (service === "security" && eventId === "4688") cats.push("process_creation");
      if (service === "powershell" && eventId === "4103") cats.push("ps_module");
      if (service === "powershell" && eventId === "4104") cats.push("ps_script");
      if (service === "powershell-classic" && eventId === "400") cats.push("ps_classic_start");
      if (service === "powershell-classic" && eventId === "600") cats.push("ps_classic_provider_start");
      if (service === "powershell-classic" && eventId === "800") cats.push("ps_classic_script");
      return logsourceKeys("windows", cats, service);
    }
    const dataset = String(this.normalized["event.dataset"] ?? "").toLowerCase();
    const proc = String(this.normalized["process.name"] ?? "").toLowerCase();
    if (dataset === "system.auth" || dataset === "syslog") {
      const service = dataset === "system.auth" ? "auth" : "syslog";
      const keys = logsourceKeys("linux", [], service);
      for (const s of ["sshd", "sudo", "cron", "vsftpd", "clamav", "guacamole", "su"]) {
        if (proc === s || proc === `${s}-session` || (s === "cron" && proc === "crond")) keys.push(`linux||${s}`);
      }
      if (dataset === "system.auth") keys.push("linux||syslog", "linux|syslog|");
      return keys;
    }
    if (dataset === "auditd") return logsourceKeys("linux", [], "auditd");
    if (/^(apache|nginx|iis)\.access$/.test(dataset)) {
      const keys = logsourceKeys(null, ["webserver"], null);
      if (dataset.startsWith("apache")) keys.push("||apache");
      if (dataset.startsWith("iis")) keys.push("windows|webserver|", "||iis");
      return keys;
    }
    if (dataset.startsWith("zeek.")) {
      const svc = dataset.slice(5);
      const keys = logsourceKeys("zeek", svc === "dns" ? ["dns"] : [], svc);
      if (svc === "dns") keys.push("|dns|");
      return keys;
    }
    if (/firewall|iptables|cisco\.(asa|ftd)|fortinet/.test(dataset)) return logsourceKeys(null, ["firewall"], null);
    if (dataset === "tomcat.catalina") return [...logsourceKeys("jvm", ["application"], null), "spring|application|", "velocity|application|"];
    const j = this.jsonFields();
    if (j) return this.jsonKeys(j);
    return [];
  }

  /** Cloud and SaaS audit logs uploaded as JSON lines. */
  private jsonKeys(j: Fields): string[] {
    const has = (k: string) => j.has(k.toLowerCase());
    const val = (k: string) => (j.get(k.toLowerCase())?.[0] ?? "").toLowerCase();
    if (has("eventSource") && has("eventName") && (has("awsRegion") || has("userIdentity.type"))) return logsourceKeys("aws", [], "cloudtrail");
    if (val("apiVersion").startsWith("audit.k8s.io")) return [...logsourceKeys("kubernetes", [], "audit"), "kubernetes|application|audit"];
    if (has("protoPayload.methodName")) return logsourceKeys("gcp", [], "gcp.audit");
    if (has("eventType") && has("actor.alternateId")) return logsourceKeys("okta", [], "okta");
    if (has("action") && (has("actor") || has("actor_id")) && (has("org") || has("repo") || has("_document_id"))) return logsourceKeys("github", [], "audit");
    if (has("Workload") && has("Operation")) return logsourceKeys("m365", [], "audit");
    if (has("operationName") && has("category")) {
      const c = val("category");
      const svc = c === "signinlogs" ? "signinlogs" : c === "auditlogs" ? "auditlogs" : c === "riskdetection" ? "riskdetection" : "activitylogs";
      return logsourceKeys("azure", [], svc);
    }
    return [];
  }

  private jsonFields(): Fields | null {
    if (this.json !== undefined) return this.json;
    this.json = null;
    const t = this.raw.trimStart();
    if (t.startsWith("{")) {
      try {
        const f: Fields = new Map();
        flattenJson(JSON.parse(t), "", f);
        this.json = f;
      } catch { /* not JSON */ }
    }
    return this.json;
  }

  private kvFields(): Fields {
    if (!this.kv) {
      this.kv = new Map();
      for (const m of this.raw.matchAll(/(?:^|\s)([A-Za-z_][\w-]*)=("[^"]*"|'[^']*'|\S+)/g)) {
        add(this.kv, m[1], m[2].replace(/^["']|["']$/g, ""));
      }
    }
    return this.kv;
  }

  private cache = new Map<string, { v: string[] | undefined; lower?: string[] }>();
  private subHits = new Map<string, Set<number>>();
  table: SubstringTable | null = null;

  /** Ids of every prefilter literal found in a field (or the raw line). */
  substringHits(field: string): Set<number> {
    let h = this.subHits.get(field);
    if (!h) {
      h = this.table ? this.table.scan(field, field === RAW_FIELD ? this.rawLowerList : this.values(field, true)) : new Set();
      this.subHits.set(field, h);
    }
    return h;
  }

  /** get(), memoized per event, with a lowercased copy made once on demand. */
  values(fieldLower: string, lower: boolean): string[] | undefined {
    let c = this.cache.get(fieldLower);
    if (!c) { c = { v: this.get(fieldLower) }; this.cache.set(fieldLower, c); }
    if (!lower || !c.v) return c.v;
    if (!c.lower) c.lower = c.v.map((x) => x.toLowerCase());
    return c.lower;
  }

  /** Every value of a Sigma field, or undefined when the event doesn't have it. */
  get(field: string): string[] | undefined {
    const f = field.toLowerCase();
    if (this.xml) {
      const direct = this.xml.get(f);
      if (direct) return direct;
      if (this.is4688 && SECURITY_4688_ALIASES[f]) return this.xml.get(SECURITY_4688_ALIASES[f]);
      return undefined;
    }
    for (const path of ECS_ALIASES[f] ?? []) {
      const v = normalizedValues(this.normalized, path);
      if (v) return v;
    }
    const n = normalizedValues(this.normalized, field);
    if (n) return n;
    const j = this.jsonFields();
    if (j) return j.get(f);
    if (String(this.normalized["event.dataset"] ?? "") === "auditd") return this.kvFields().get(f);
    return undefined;
  }
}

// ── Substring prefilter ─────────────────────────────────────────────────
// Thousands of rules test the same few fields (CommandLine above all) for
// case-insensitive substrings. Every such literal goes into one
// Aho-Corasick automaton per field, so a field is scanned once per event
// and each "contains" test becomes a set lookup.

class AhoCorasick {
  private next: Map<number, number>[] = [new Map()];
  private fail: number[] = [0];
  private out: number[][] = [[]];

  add(word: string, id: number) {
    let n = 0;
    for (let i = 0; i < word.length; i++) {
      const c = word.charCodeAt(i);
      let m = this.next[n].get(c);
      if (m === undefined) {
        m = this.next.length;
        this.next.push(new Map()); this.fail.push(0); this.out.push([]);
        this.next[n].set(c, m);
      }
      n = m;
    }
    this.out[n].push(id);
  }

  build() {
    const queue: number[] = [];
    for (const m of this.next[0].values()) queue.push(m);
    for (let qi = 0; qi < queue.length; qi++) {
      const r = queue[qi];
      for (const [c, u] of this.next[r]) {
        queue.push(u);
        let v = this.fail[r];
        while (v !== 0 && !this.next[v].has(c)) v = this.fail[v];
        const f = this.next[v].get(c);
        this.fail[u] = f !== undefined && f !== u ? f : 0;
        if (this.out[this.fail[u]].length) this.out[u] = this.out[u].concat(this.out[this.fail[u]]);
      }
    }
  }

  scan(text: string, into: Set<number>) {
    let n = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      let m = this.next[n].get(c);
      while (m === undefined && n !== 0) { n = this.fail[n]; m = this.next[n].get(c); }
      n = m ?? 0;
      const o = this.out[n];
      for (let k = 0; k < o.length; k++) into.add(o[k]);
    }
  }
}

/** Case-insensitive substring literals, by field, shared by every rule in an index. */
export class SubstringTable {
  private fields = new Map<string, { ac: AhoCorasick; ids: Map<string, number> }>();
  private nextId = 0;
  private built = false;

  id(field: string, literal: string): number {
    let f = this.fields.get(field);
    if (!f) { f = { ac: new AhoCorasick(), ids: new Map() }; this.fields.set(field, f); }
    let id = f.ids.get(literal);
    if (id === undefined) { id = this.nextId++; f.ids.set(literal, id); f.ac.add(literal, id); }
    return id;
  }

  build() {
    for (const f of this.fields.values()) f.ac.build();
    this.built = true;
  }

  scan(field: string, lowerValues: string[] | undefined): Set<number> {
    const hits = new Set<number>();
    const f = this.fields.get(field);
    if (f && this.built && lowerValues) for (const v of lowerValues) f.ac.scan(v, hits);
    return hits;
  }
}

const RAW_FIELD = "\u0000raw";

// ── Matching ────────────────────────────────────────────────────────────
// Rules are prepared once (regexes built, field names lowercased) so that
// matching an event does no allocation beyond its own field cache.

type PTest =
  | { t: "eq" | "contains" | "startswith" | "endswith"; s: string; cased: boolean }
  | { t: "sub"; field: string; id: number }
  | { t: "re"; re: RegExp }
  | { t: "cidr"; cidr: string }
  | { t: "num"; op: "gt" | "gte" | "lt" | "lte"; n: number }
  | { t: "exists"; v: boolean }
  | { t: "null" }
  | { t: "fieldref"; field: string; cased: boolean };
type PField = { field: string; tests: PTest[]; all: boolean; needsLower: boolean };
type PSel = { k: "map"; alternatives: PField[][] } | { k: "keywords"; tests: PTest[]; all: boolean };
/** A rule compiled to closures: selection results are memoized per event in `memo` (0 unknown, 1 false, 2 true). */
type PreparedRule = { match: (ev: SigmaEventView) => boolean; gate: [string, number][] | null };

function prepTest(t: ValueTest, field: string, table: SubstringTable | null): PTest {
  if (table && t.t === "contains" && !t.cased && t.s.length > 0) return { t: "sub", field, id: table.id(field, t.s) };
  switch (t.t) {
    case "re": return { t: "re", re: new RegExp(t.re, t.flags) };
    case "eq": case "contains": case "startswith": case "endswith": return { t: t.t, s: t.s, cased: !!t.cased };
    case "fieldref": return { t: "fieldref", field: t.field.toLowerCase(), cased: !!t.cased };
    default: return t;
  }
}

function prepField(ft: FieldTest, table: SubstringTable | null): PField {
  const field = ft.field.toLowerCase();
  const tests = ft.tests.map((t) => prepTest(t, field, table));
  return {
    field, tests, all: ft.all,
    needsLower: tests.some((t) => (t.t === "eq" || t.t === "contains" || t.t === "startswith" || t.t === "endswith") && !t.cased),
  };
}

export function prepareRule(rule: CompiledSigmaRule, table: SubstringTable | null = null): PreparedRule {
  const names = Object.keys(rule.selections);
  const sels: PSel[] = names.map((name) => {
    const sel = rule.selections[name];
    return sel.k === "keywords"
      ? { k: "keywords", tests: sel.tests.map((t) => prepTest(t, RAW_FIELD, table)), all: sel.all }
      : { k: "map", alternatives: sel.alternatives.map((g) => g.map((ft) => prepField(ft, table))) };
  });
  const memo = new Uint8Array(names.length);
  let current: SigmaEventView | null = null;
  const sel = (i: number): boolean => {
    if (memo[i] === 0) memo[i] = testSelection(sels[i], current!) ? 2 : 1;
    return memo[i] === 2;
  };
  const build = (c: Cond): (() => boolean) => {
    switch (c.op) {
      case "and": { const fs = c.args.map(build); return () => fs.every((f) => f()); }
      case "or": { const fs = c.args.map(build); return () => fs.some((f) => f()); }
      case "not": { const f = build(c.arg); return () => !f(); }
      case "sel": { const i = names.indexOf(c.name); return () => sel(i); }
      case "of": {
        const idx = c.names.map((n) => names.indexOf(n));
        return c.quant === "all" ? () => idx.every(sel) : () => idx.some(sel);
      }
    }
  };
  const conds = rule.conditions.map(build);
  const gate = table ? ruleGate(rule, table) : null;
  return {
    gate,
    match: (ev) => {
      current = ev;
      memo.fill(0);
      const r = conds.some((f) => f());
      current = null;
      return r;
    },
  };
}

/**
 * Literal substrings at least one of which every match of the rule must
 * contain, as (field, prefilter id) pairs; null when there's no such set
 * (the rule is then evaluated on every event of its logsource).
 *
 *   selection   every alternative has a field tested only with literals
 *               (an eq/startswith/endswith literal is also a substring)
 *   a and b     the smaller gate of either side
 *   a or b, 1 of   the union of every side's gate (null if one has none)
 *   all of      the smallest gate among them
 *   not a       none
 */
function ruleGate(rule: CompiledSigmaRule, table: SubstringTable): [string, number][] | null {
  type Gate = [string, string][] | null;
  const literal = (t: ValueTest) => (t.t === "eq" || t.t === "contains" || t.t === "startswith" || t.t === "endswith") && !t.cased && t.s.length > 0;
  const selGate = (name: string): Gate => {
    const sel = rule.selections[name];
    if (sel.k === "keywords") return !sel.all && sel.tests.length && sel.tests.every(literal) ? sel.tests.map((t) => [RAW_FIELD, (t as { s: string }).s]) : null;
    const out: [string, string][] = [];
    for (const group of sel.alternatives) {
      let best: [string, string][] | null = null;
      for (const ft of group) {
        if (!ft.tests.length || !ft.tests.every(literal)) continue;
        const atoms = ft.tests.map((t): [string, string] => [ft.field.toLowerCase(), (t as { s: string }).s]);
        if (!best || atoms.length < best.length) best = atoms;
      }
      if (!best) return null;
      out.push(...best);
    }
    return out.length ? out : null;
  };
  const smallest = (gates: Gate[]): Gate => gates.filter((x): x is [string, string][] => !!x).sort((x, y) => x.length - y.length)[0] ?? null;
  const union = (gates: Gate[]): Gate => (gates.some((x) => !x) ? null : gates.flatMap((x) => x!));
  const gateOf = (c: Cond): Gate => {
    switch (c.op) {
      case "sel": return selGate(c.name);
      case "of": return c.quant === "all" ? smallest(c.names.map(selGate)) : union(c.names.map(selGate));
      case "and": return smallest(c.args.map(gateOf));
      case "or": return union(c.args.map(gateOf));
      case "not": return null;
    }
  };
  const g = union(rule.conditions.map(gateOf));
  return g && g.length ? g.map(([field, lit]) => [field, table.id(field, lit)]) : null;
}

function ipToBigInt(ip: string): { v: bigint; bits: number } | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    const p = ip.split(".").map(Number);
    if (p.some((x) => x > 255)) return null;
    return { v: BigInt(((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]), bits: 32 };
  }
  if (ip.includes(":")) {
    const [head, tail] = ip.split("::") as [string, string | undefined];
    const h = head ? head.split(":") : [];
    const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
    if (tail === undefined && h.length !== 8) return null;
    const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
    return { v: groups.reduce((acc, g) => (acc << BigInt(16)) + BigInt(parseInt(g, 16)), BigInt(0)), bits: 128 };
  }
  return null;
}

function inCidr(ip: string, cidr: string): boolean {
  const [net, lenS] = cidr.split("/");
  const a = ipToBigInt(ip.trim()), n = ipToBigInt(net);
  if (!a || !n || a.bits !== n.bits) return false;
  const len = lenS === undefined ? n.bits : Number(lenS);
  const shift = BigInt(n.bits - len);
  return (a.v >> shift) === (n.v >> shift);
}

function testValue(t: PTest, raw: string[] | undefined, lower: string[] | undefined, ev: SigmaEventView): boolean {
  switch (t.t) {
    case "sub": return ev.substringHits(t.field).has(t.id);
    case "null": return !raw || raw.every((v) => v === "");
    case "exists": return t.v === (raw !== undefined && raw.some((v) => v !== ""));
    case "eq": case "contains": case "startswith": case "endswith": {
      const vals = t.cased ? raw : lower;
      if (!vals) return false;
      for (const v of vals) {
        if (t.t === "eq" ? v === t.s : t.t === "contains" ? v.includes(t.s) : t.t === "startswith" ? v.startsWith(t.s) : v.endsWith(t.s)) return true;
      }
      return false;
    }
    case "re": return !!raw && raw.some((v) => t.re.test(v));
    case "cidr": return !!raw && raw.some((v) => inCidr(v, t.cidr));
    case "num": return !!raw && raw.some((v) => {
      const n = Number(v);
      return !Number.isNaN(n) && (t.op === "gt" ? n > t.n : t.op === "gte" ? n >= t.n : t.op === "lt" ? n < t.n : n <= t.n);
    });
    case "fieldref": {
      const other = ev.values(t.field, !t.cased);
      const mine = t.cased ? raw : lower;
      return !!mine && !!other && mine.some((m) => other.includes(m));
    }
  }
}

function testField(ft: PField, ev: SigmaEventView): boolean {
  const raw = ev.values(ft.field, false);
  const lower = ft.needsLower ? ev.values(ft.field, true) : undefined;
  return ft.all ? ft.tests.every((t) => testValue(t, raw, lower, ev)) : ft.tests.some((t) => testValue(t, raw, lower, ev));
}

function testSelection(sel: PSel, ev: SigmaEventView): boolean {
  if (sel.k === "keywords") {
    const raw = ev.rawList, lower = ev.rawLowerList;
    return sel.all ? sel.tests.every((t) => testValue(t, raw, lower, ev)) : sel.tests.some((t) => testValue(t, raw, lower, ev));
  }
  return sel.alternatives.some((group) => group.every((ft) => testField(ft, ev)));
}

export function matchesRule(rule: PreparedRule, ev: SigmaEventView): boolean {
  return rule.match(ev);
}

// ── Rule index ──────────────────────────────────────────────────────────

export type IndexedSigmaRule = { id: string; key: string; compiled: CompiledSigmaRule };

type Entry = { id: string; rule: PreparedRule };
type Bucket = { ungated: Entry[]; byAtom: Map<number, Entry[]>; fields: Set<string> };

/**
 * Rules grouped by logsource key. Within a key, a gated rule (see ruleGate)
 * is reached only through the literals an event actually contains, so an
 * event is evaluated against the ungated rules plus the few gated ones
 * whose literals it has.
 */
export class SigmaRuleIndex {
  private byKey = new Map<string, Bucket>();
  private table = new SubstringTable();
  readonly size: number;
  /** Rules with a literal prefilter — the rest run on every event of their logsource. */
  readonly gated: number;

  constructor(rules: IndexedSigmaRule[]) {
    let n = 0, g = 0;
    for (const r of rules) {
      let prepared: PreparedRule;
      try { prepared = prepareRule(r.compiled, this.table); } catch { continue; }
      let b = this.byKey.get(r.key);
      if (!b) { b = { ungated: [], byAtom: new Map(), fields: new Set() }; this.byKey.set(r.key, b); }
      const entry = { id: r.id, rule: prepared };
      if (prepared.gate) {
        g++;
        for (const [field, id] of prepared.gate) {
          b.fields.add(field);
          const arr = b.byAtom.get(id);
          if (arr) { if (arr[arr.length - 1] !== entry) arr.push(entry); } else b.byAtom.set(id, [entry]);
        }
      } else {
        b.ungated.push(entry);
      }
      n++;
    }
    this.size = n;
    this.gated = g;
    this.table.build();
  }

  /** Ids of every rule that matches the event. */
  match(ev: SigmaEventView): string[] {
    ev.table = this.table;
    const hits: string[] = [];
    for (const key of ev.keys) {
      const b = this.byKey.get(key);
      if (!b) continue;
      const candidates = new Set<Entry>(b.ungated);
      for (const field of b.fields) {
        for (const id of ev.substringHits(field)) {
          const rs = b.byAtom.get(id);
          if (rs) for (const r of rs) candidates.add(r);
        }
      }
      for (const r of candidates) if (r.rule.match(ev)) hits.push(r.id);
    }
    return hits;
  }
}

/**
 * Logsources Core's decoders produce events for — a rule whose logsource is
 * not covered can never match, and is shown as "no log source" rather than
 * run. Windows services/categories come from the channel and Sysmon tables.
 */
export function logsourceCovered(product: string | null, category: string | null, service: string | null): boolean {
  const p = product ?? "", c = category ?? "", s = service ?? "";
  if (p === "windows") {
    const services = new Set([...Object.values(WINDOWS_CHANNEL_SERVICE), "applocker"]);
    const cats = new Set([...Object.values(SYSMON_CATEGORIES).flat(), "ps_module", "ps_script", "ps_classic_start",
      "ps_classic_provider_start", "ps_classic_script", "webserver"]);
    return (!s || services.has(s)) && (!c || cats.has(c));
  }
  if (p === "linux") {
    if (c) return ["process_creation", "network_connection", "file_event", "file_delete", "syslog"].includes(c);
    return s === "" || ["auth", "syslog", "auditd", "sshd", "sudo", "cron", "vsftpd", "clamav", "guacamole", "su", "sysmon"].includes(s);
  }
  if (p === "") {
    if (c === "webserver" || c === "firewall" || c === "dns") return !s;
    if (!c && ["apache", "iis"].includes(s)) return true;
    return false;
  }
  if (p === "zeek") return ["dns", "conn", "http", "kerberos", "ssl", "ssh", "smb_cmd", "intel"].includes(s);
  if (p === "aws") return s === "cloudtrail";
  if (p === "kubernetes") return s === "audit";
  if (p === "gcp") return s === "gcp.audit";
  if (p === "okta") return s === "okta";
  if (p === "github") return s === "audit";
  if (p === "m365") return s === "audit";
  if (p === "azure") return ["signinlogs", "auditlogs", "riskdetection", "activitylogs"].includes(s);
  if (["jvm", "spring", "velocity"].includes(p)) return c === "application";
  return false;
}
