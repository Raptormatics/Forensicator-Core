// The section moved to /host-artifacts (it holds Windows and Linux
// collections). Kept as a redirect for old links and bookmarks — and because
// updates extract over the existing tree, so the old page must be replaced,
// not just removed.
import { redirect } from "next/navigation";

export default function WindowsArtifactsRedirect() {
  redirect("/host-artifacts");
}
