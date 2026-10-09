import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { normalizeSeverity, severityClassName } from "@/lib/severity";

type SeverityBadgeProps = {
  severity: string;
  className?: string;
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <Badge className={cn(severityClassName(severity), className)}>
      {normalizeSeverity(severity)}
    </Badge>
  );
}
