// Moved to /host-artifacts/upload — see ../page.tsx.
import { redirect } from "next/navigation";

export default function WindowsArtifactsUploadRedirect() {
  redirect("/host-artifacts/upload");
}
