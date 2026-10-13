/**
 * Minimal quoted-CSV line splitter shared by every abuse.ch bulk feed
 * (URLhaus, MalwareBazaar, ...) — handles embedded commas, `""` escaping,
 * and trims each field, since some of these feeds (MalwareBazaar's
 * csv_recent) separate quoted fields with ", " rather than a bare comma.
 */
export function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = false;
      } else {
        cur += c;
      }
    } else {
      if (c === '"') inQuotes = true;
      else if (c === ",") { fields.push(cur.trim()); cur = ""; }
      else cur += c;
    }
  }
  fields.push(cur.trim());
  return fields;
}
