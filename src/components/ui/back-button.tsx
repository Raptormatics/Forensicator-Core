"use client";

import { ArrowLeft } from "lucide-react";
import { useRouter } from "next/navigation";

export function BackButton() {
  const router = useRouter();
  return (
    <button
      onClick={() => router.back()}
      className="mb-6 inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-teal-200"
    >
      <ArrowLeft className="h-4 w-4" />
      Back
    </button>
  );
}
