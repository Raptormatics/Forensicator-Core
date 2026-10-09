import * as React from "react";
import { cn } from "@/lib/utils";

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "ghost" | "outline";
};

export function Button({ className, variant = "default", ...props }: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex h-9 items-center justify-center gap-2 rounded-md px-3 text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-400 disabled:pointer-events-none disabled:opacity-50",
        variant === "default" && "bg-teal-400 text-zinc-950 hover:bg-teal-300",
        variant === "ghost" && "text-zinc-300 hover:bg-zinc-900 hover:text-zinc-50",
        variant === "outline" &&
          "border border-zinc-800 bg-zinc-950/30 text-zinc-200 hover:bg-zinc-900",
        className
      )}
      {...props}
    />
  );
}
