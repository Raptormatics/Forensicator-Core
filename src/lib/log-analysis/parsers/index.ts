import { parseApache }       from "./apache";
import { parseNginx }        from "./nginx";
import { parseSyslog }       from "./syslog";
import { parseWindowsEvent } from "./windows-event";
import { parseIIS }          from "./iis";
import { parseFirewall }     from "./firewall";
import { parseCustomJson }   from "./custom-json";
import { parseCustomCsv }    from "./custom-csv";
import type { ParsedEvent }  from "../types";

export type ParserFn = (content: string) => ParsedEvent[];

export const PARSERS: Record<string, ParserFn> = {
  "apache":        parseApache,
  "nginx":         parseNginx,
  "syslog":        parseSyslog,
  "windows-event": parseWindowsEvent,
  "iis":           parseIIS,
  "firewall":      parseFirewall,
  "custom-json":   parseCustomJson,
  "custom-csv":    parseCustomCsv,
};

export function getParser(sourceType: string): ParserFn | null {
  return PARSERS[sourceType] ?? null;
}
