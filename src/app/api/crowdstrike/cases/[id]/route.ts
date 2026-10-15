import { getCase } from "@/lib/secops/crowdstrike";

export async function GET(_request: Request, { params }: RouteContext<"/api/crowdstrike/cases/[id]">) {
  const { id } = await params;
  const found = getCase(id);
  return found ? Response.json({ case: found }) : Response.json({ error: `Case ${id} not found.` }, { status: 404 });
}
