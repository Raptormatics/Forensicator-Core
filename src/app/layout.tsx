import type { Metadata } from "next";
import type { ReactNode } from "react";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { Providers } from "@/components/layout/providers";
import { isSetupComplete } from "@/lib/setup/status";
import "./globals.css";

export const metadata: Metadata = {
  title: "Forensicator",
  description: "DFIR investigation storage and evidence viewer"
};

export default async function RootLayout({
  children
}: Readonly<{
  children: ReactNode;
}>) {
  // Mandatory first step: no user exists until someone completes /setup.
  // Middleware can't check this itself (Edge runtime, no Prisma) — it
  // forwards the current path via x-pathname instead, read here in a
  // Server Component with full Node access. isSetupComplete() is cached
  // in-process after the first true, so this is a no-op DB-wise for the
  // entire remaining lifetime of an already-set-up instance.
  const pathname = (await headers()).get("x-pathname") ?? "";
  const setupDone = await isSetupComplete();
  if (!setupDone && pathname !== "/setup") {
    redirect("/setup");
  }
  if (setupDone && pathname === "/setup") {
    redirect("/login");
  }

  return (
    <html lang="en" className="dark">
      <body className="font-sans antialiased bg-zinc-950 text-zinc-100">
        <Providers>
          <div className="flex min-h-screen">
            <Sidebar />
            <main className="flex-1 min-w-0 overflow-auto">
              {children}
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
