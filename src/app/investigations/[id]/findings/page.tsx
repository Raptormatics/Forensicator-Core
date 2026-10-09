import { redirect } from "next/navigation";

// /investigations/[id]/findings → redirect to the investigation detail page
// which renders the full findings sidebar + detail view.
export default async function FindingsRedirectPage(props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  redirect(`/investigations/${params.id}`);
}
