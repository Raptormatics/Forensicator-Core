import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";

export default function InvestigationNotFound() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
      <Card>
        <CardContent>
          <h1 className="text-xl font-semibold text-zinc-100">Investigation not found</h1>
          <p className="mt-2 text-sm text-zinc-400">The requested investigation does not exist.</p>
          <Link href="/investigations" className="mt-5 inline-flex text-sm text-teal-200 hover:text-teal-100">
            Back to investigations
          </Link>
        </CardContent>
      </Card>
    </main>
  );
}
