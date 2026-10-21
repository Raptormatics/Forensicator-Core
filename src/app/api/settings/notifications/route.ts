import { NextResponse } from "next/server";

// Critical-finding alerting (SMTP email, webhook) is a Forensicator
// Enterprise feature — the overlay replaces this route with the real
// settings API. Kept as a stub (not deleted) so an updated Core install
// overwrites the older working copy instead of keeping it.
function enterpriseOnly() {
  return NextResponse.json(
    { error: "enterprise_feature", message: "Critical finding alerts are available in Forensicator Enterprise." },
    { status: 404 }
  );
}

export const GET = enterpriseOnly;
export const PUT = enterpriseOnly;
