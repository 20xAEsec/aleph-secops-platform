import { discover, isResourceType } from "@/lib/secops/discovery";

const WINDOWS = [24, 168, 720];

// Deterministic log search: no model involved, so it answers synchronously as JSON.
export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  if (!isResourceType(body.type)) return Response.json({ error: "Pick a resource type." }, { status: 400 });
  const value = String(body.value ?? "").slice(0, 300);
  const hoursBack = WINDOWS.includes(body.hoursBack) ? body.hoursBack : 168;

  const result = discover(body.type, value, hoursBack);
  if ("error" in result) return Response.json(result, { status: 400 });
  return Response.json(result);
}
