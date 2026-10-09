import { prisma } from "@/lib/db/prisma";

// This only ever flips one way, zero -> one, exactly once in an
// instance's lifetime — cache it in-process so completed installs never
// pay a DB round trip for this on every request.
let setupCompleteCache = false;

export async function isSetupComplete(): Promise<boolean> {
  if (setupCompleteCache) return true;
  const count = await prisma.user.count();
  if (count > 0) {
    setupCompleteCache = true;
    return true;
  }
  return false;
}
