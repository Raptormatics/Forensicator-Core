/** Formats a Case's autoincrement caseSeq into its human-readable reference, e.g. 7 -> "CASE-0007". */
export function formatCaseNumber(seq: number): string {
  return `CASE-${String(seq).padStart(4, "0")}`;
}
