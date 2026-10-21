import Link from "next/link";
import { ArrowLeft, Bell, Sparkles } from "lucide-react";

// Critical-finding alerting (SMTP email and webhook) is a Forensicator
// Enterprise feature — the overlay replaces this page with the real
// settings form.
export default function NotificationSettingsPage() {
  return (
    <div className="mx-auto w-full max-w-3xl px-4 py-8 sm:px-6 lg:px-8">
      <Link href="/settings" className="mb-4 inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300">
        <ArrowLeft className="h-4 w-4" /> Settings
      </Link>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
        <h1 className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
          <Bell className="h-5 w-5 text-teal-400" /> Critical Finding Alerts
        </h1>
        <p className="mt-2 text-sm text-zinc-400">
          Email (SMTP) and webhook alerts when a critical-severity finding is detected are part of Forensicator Enterprise.
          Findings are still detected and shown in Core — only the outbound alerting needs Enterprise.
        </p>
        <Link
          href="/enterprise"
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500"
        >
          <Sparkles className="h-4 w-4" /> Activate Enterprise
        </Link>
      </div>
    </div>
  );
}
