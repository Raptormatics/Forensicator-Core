import { AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function DatabaseError({ message }: { message: string }) {
  return (
    <Card>
      <CardContent className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-300" />
        <div>
          <h2 className="font-semibold text-zinc-100">Database unavailable</h2>
          <p className="mt-1 text-sm leading-6 text-zinc-400">{message}</p>
        </div>
      </CardContent>
    </Card>
  );
}
