import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-3xl items-center px-4 py-10 sm:px-6 lg:px-8">
      <Card className="w-full">
        <CardContent>
          <p className="text-sm font-medium text-teal-200">Forensicator</p>
          <h1 className="mt-3 text-2xl font-semibold text-zinc-100">Page not found</h1>
          <p className="mt-2 text-sm leading-6 text-zinc-400">
            The investigation viewer is available at the plural route.
          </p>
          <Link
            href="/investigations"
            className="mt-5 inline-flex text-sm font-medium text-teal-200 hover:text-teal-100"
          >
            Open investigations
          </Link>
        </CardContent>
      </Card>
    </main>
  );
}
