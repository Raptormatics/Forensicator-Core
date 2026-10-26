// Moved to /api/host-artifacts/uploads/[id] (see src/lib/http/moved.ts).
import { movedTo } from "@/lib/http/moved";

export const { GET, POST, PUT, PATCH, DELETE } = movedTo("/api/host-artifacts/uploads/[id]");
