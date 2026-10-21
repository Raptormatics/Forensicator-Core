/**
 * Parses one JSON-lines record from a Windows Artifact parser script.
 *
 * Every parser reads binary formats (ESE, SQLite, registry, $I, ...) where a
 * stray NUL can survive into a decoded string; json.dumps writes it as the
 * escape "\u0000", and Postgres rejects U+0000 in TEXT/JSONB with 22021
 * ("invalid byte sequence for encoding UTF8: 0x00"), failing the whole
 * insert — seen on a real Windows 11 collection for both Recycle Bin $I
 * paths and SRUDB.dat values. Dropping the escape here covers every engine.
 */
// Only a real JSON escape: "\u0000" preceded by an even number of
// backslashes. Text that literally contains backslash-u0000 (indexed source
// code in a Windows Search database, for one) is serialized as "\\u0000"
// and must be left alone — stripping it corrupted those lines' JSON.
const JSON_NUL_ESCAPE = /(?<!\\)((?:\\\\)*)\\u0000/g;

export function parseParserLine(line: string): Record<string, unknown> {
  return JSON.parse(line.replace(JSON_NUL_ESCAPE, "$1")) as Record<string, unknown>;
}
