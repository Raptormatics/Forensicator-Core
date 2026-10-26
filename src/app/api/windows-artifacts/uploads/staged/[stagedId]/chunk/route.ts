// Moved to /api/host-artifacts/uploads/staged/[stagedId]/chunk (see src/lib/http/moved.ts).
import { movedTo } from "@/lib/http/moved";

export const { GET, POST, PUT, PATCH, DELETE } = movedTo("/api/host-artifacts/uploads/staged/[stagedId]/chunk");
