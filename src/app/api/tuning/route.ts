import { runTuning } from "@/lib/agents/tuning";
import { sseResponse } from "@/lib/sse";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const rulePath = String(body.rulePath ?? "");
  if (!/^rules\/[a-z_]+\/[a-z0-9_]+\.yaral$/.test(rulePath)) {
    return Response.json({ error: "A rule path under rules/ is required." }, { status: 400 });
  }
  const ticketKey = typeof body.ticketKey === "string" && /^[A-Z]+-\d+$/.test(body.ticketKey) ? body.ticketKey : undefined;
  const instructions = (Array.isArray(body.instructions) ? body.instructions : [])
    .filter((s: unknown): s is string => typeof s === "string")
    .slice(-12)
    .map((s: string) => s.slice(0, 2000));
  return sseResponse((emit) => runTuning({ rulePath, ticketKey, instructions }, emit));
}
