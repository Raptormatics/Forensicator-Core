import { humanizeKey, jsonValueToDisplay } from "@/lib/utils";
import type { JsonObject } from "@/types/json";

type KeyValueGridProps = {
  data: JsonObject;
};

export function KeyValueGrid({ data }: KeyValueGridProps) {
  const entries = Object.entries(data);

  if (entries.length === 0) {
    return <p className="text-sm text-zinc-500">No values.</p>;
  }

  return (
    <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {entries.map(([key, value]) => (
        <div key={key} className="rounded-md border border-zinc-800 bg-zinc-950/45 p-3">
          <dt className="text-xs uppercase tracking-normal text-zinc-500">{humanizeKey(key)}</dt>
          <dd className="mt-1 break-words font-mono text-xs leading-5 text-zinc-200">
            {jsonValueToDisplay(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}
