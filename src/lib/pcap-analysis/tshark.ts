/**
 * Streams a .pcap/.pcapng file through `tshark -T fields` and yields one
 * parsed PacketFields object per packet.
 *
 * Deliberately NOT `-T json` (heavier to stream/parse for large captures)
 * or `-z conv`/text-table output (fragile to parse reliably) — plain
 * tab-separated fields, one line per packet, read via readline so memory
 * use is bounded by the aggregation the caller builds on top, not by
 * packet count.
 *
 * `-r <file>` only ever reads a file already on disk — no live-capture
 * privileges (CAP_NET_RAW / dumpcap suid) are needed.
 */
import { spawn } from "child_process";
import * as readline from "readline";
import type { PacketFields } from "./types";

// Order matters — must match the column order this function parses below.
const FIELD_LIST = [
  "frame.time_epoch",
  "frame.len",
  "ip.src",
  "ip.dst",
  "ip.proto",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "dns.qry.name",
  "dns.qry.type",
  "dns.a",
  "dns.aaaa",
  "tls.handshake.extensions_server_name",
  "http.host",
  "http.authorization",
  "ftp.request.command",
  "ftp.request.arg",
] as const;

function parseNum(v: string): number | null {
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function parseStr(v: string): string | null {
  return v ? v : null;
}

function parseLine(line: string): PacketFields {
  const cols = line.split("\t");
  return {
    timeEpoch:          parseNum(cols[0]),
    frameLen:           parseNum(cols[1]),
    ipSrc:              parseStr(cols[2]),
    ipDst:              parseStr(cols[3]),
    ipProto:            parseStr(cols[4]),
    tcpSrcPort:         parseNum(cols[5]),
    tcpDstPort:         parseNum(cols[6]),
    udpSrcPort:         parseNum(cols[7]),
    udpDstPort:         parseNum(cols[8]),
    // tshark can repeat a field on one line (e.g. multiple dns.a answers) —
    // -E occurrence=f keeps only the first, which is all v1 needs.
    dnsQryName:         parseStr(cols[9]),
    dnsQryType:         parseStr(cols[10]),
    dnsA:               parseStr(cols[11]),
    dnsAaaa:            parseStr(cols[12]),
    tlsSni:             parseStr(cols[13]),
    httpHost:           parseStr(cols[14]),
    httpAuthorization:  parseStr(cols[15]),
    ftpRequestCommand:  parseStr(cols[16]),
    ftpRequestArg:      parseStr(cols[17]),
  };
}

export class TsharkError extends Error {}

/**
 * Async generator — yields one PacketFields per packet. Throws TsharkError
 * on a non-zero exit or spawn failure (binary missing, file unreadable),
 * with the actual stderr/error message so it surfaces clearly as
 * PcapUpload.errorMessage rather than a stuck "processing" row.
 */
export async function* runTsharkFieldExtraction(
  tsharkPath: string,
  filePath: string
): AsyncGenerator<PacketFields> {
  const args = ["-r", filePath, "-T", "fields"];
  for (const f of FIELD_LIST) args.push("-e", f);
  args.push("-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=f");

  const child = spawn(tsharkPath, args, { stdio: ["ignore", "pipe", "pipe"] });

  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

  const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });

  const spawnError = new Promise<never>((_, reject) => {
    child.on("error", (err) => reject(new TsharkError(`Failed to run tshark ("${tsharkPath}"): ${err.message}`)));
  });

  const lineIterator = rl[Symbol.asyncIterator]();

  try {
    while (true) {
      const next = await Promise.race([lineIterator.next(), spawnError]);
      if (next.done) break;
      if (next.value.trim().length === 0) continue;
      yield parseLine(next.value);
    }
  } finally {
    rl.close();
  }

  const exitCode: number = await new Promise((resolve) => child.on("close", resolve));
  if (exitCode !== 0) {
    throw new TsharkError(
      `tshark exited with code ${exitCode}${stderr ? `: ${stderr.trim().slice(0, 500)}` : ""}`
    );
  }
}
