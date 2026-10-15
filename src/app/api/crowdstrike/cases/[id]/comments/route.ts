import { addCaseComment } from "@/lib/secops/crowdstrike";

// Posts an investigation report to the case timeline. In production this is the Falcon
// incident-actions endpoint with an add_comment action; here it lands in the demo store.
export async function POST(request: Request, { params }: RouteContext<"/api/crowdstrike/cases/[id]/comments">) {
  const { id } = await params;
  const body = await request.json().catch(() => ({}));
  const text = String(body.body ?? "").trim();
  if (!text) return Response.json({ error: "A comment body is required." }, { status: 400 });

  await new Promise((r) => setTimeout(r, 900)); // simulated API round trip
  const comment = addCaseComment(id, text.slice(0, 60000), "Aleph (AI analyst)");
  if (!comment) return Response.json({ error: `Case ${id} not found.` }, { status: 404 });
  return Response.json({
    comment,
    request: { method: "POST", path: "/incidents/entities/incident-actions/v1", action: "add_comment", caseId: id },
  });
}
