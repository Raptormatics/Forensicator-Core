// Moved to /api/host-artifacts/payloads/[id]/download (see src/lib/http/moved.ts).
import { movedTo } from "@/lib/http/moved";

export const { GET, POST, PUT, PATCH, DELETE } = movedTo("/api/host-artifacts/payloads/[id]/download");
