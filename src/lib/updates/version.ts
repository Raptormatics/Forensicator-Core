/**
 * Plain major.minor.patch comparison — same logic as the downgrade check
 * in deploy/forensicator-update.sh, reimplemented in JS so the Admin UI can
 * tell "update available" from "up to date" without shelling out.
 */
export function isNewerVersion(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na > nb;
  }
  return false;
}
