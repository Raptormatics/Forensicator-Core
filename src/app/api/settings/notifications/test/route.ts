import { NextResponse } from "next/server";

// SMTP test email — Forensicator Enterprise only (the overlay replaces this
// route). Stub rather than deletion: see ../route.ts.
export function POST() {
  return NextResponse.json(
    { error: "enterprise_feature", message: "Critical finding alerts are available in Forensicator Enterprise." },
    { status: 404 }
  );
}
