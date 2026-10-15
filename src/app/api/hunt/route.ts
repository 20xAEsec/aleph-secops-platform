import { runHunt } from "@/lib/agents/hunt";
import { sseResponse } from "@/lib/sse";

export const maxDuration = 300;

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const hypothesis = String(body.hypothesis ?? "").trim().slice(0, 20000);
  if (!hypothesis) return Response.json({ error: "A hunt hypothesis is required." }, { status: 400 });

  const tier = body.tier === "advanced" ? "advanced" : "basic";
  const lookbackDays = Math.min(90, Math.max(1, Number(body.lookbackDays) || 7));
  return sseResponse((emit) => runHunt({ hypothesis, tier, lookbackDays }, emit));
}
