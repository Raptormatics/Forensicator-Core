// Moved to /host-artifacts/<id> — see ../page.tsx.
import { redirect } from "next/navigation";

export default async function WindowsArtifactsUploadRedirect(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  redirect(`/host-artifacts/${encodeURIComponent(id)}`);
}
