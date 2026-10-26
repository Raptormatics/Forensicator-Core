// Moved to /api/host-artifacts/uploads/staged/[stagedId]/complete (see src/lib/http/moved.ts).
import { movedTo } from "@/lib/http/moved";

export const { GET, POST, PUT, PATCH, DELETE } = movedTo("/api/host-artifacts/uploads/staged/[stagedId]/complete");
