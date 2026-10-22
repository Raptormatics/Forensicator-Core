/**
 * Legal hold lookup — Core stub. Legal hold is a Forensicator Enterprise
 * feature: the Enterprise overlay replaces this file with one that reads
 * the case's hold. Core never has a hold, so deletions are governed only
 * by the closed-case/archive rules in case-lock.ts.
 *
 * Keep this file's exports identical to the overlay's version.
 */
export type LegalHold = { reason: string; setAt: Date; setByEmail: string | null };

export async function legalHoldForCase(_caseId: string): Promise<LegalHold | null> {
  return null;
}
