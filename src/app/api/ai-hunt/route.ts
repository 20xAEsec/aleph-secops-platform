import { runAiHunt } from "@/lib/agents/aiHunt";
import { HUNTS } from "@/lib/aisec/hunts";
import { sseResponse } from "@/lib/sse";

export const maxDuration = 300;

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));

  // A preset id is untrusted input: it must resolve to a known hunt, and the hunt's own hypothesis
  // is used rather than whatever text came with the request.
  const huntId = typeof body.huntId === "string" ? body.huntId : undefined;
  const preset = huntId ? HUNTS.find((h) => h.id === huntId) : undefined;
  if (huntId && !preset) return Response.json({ error: "Unknown hunt." }, { status: 400 });

  const hypothesis = (preset?.hypothesis ?? String(body.hypothesis ?? "")).trim().slice(0, 20000);
  if (!hypothesis) return Response.json({ error: "A hunt hypothesis is required." }, { status: 400 });

  const tier = body.tier === "basic" ? "basic" : "advanced";
  const daysBack = Math.min(30, Math.max(1, Number(body.daysBack) || 30));

  return sseResponse((emit) => runAiHunt({ hypothesis, huntId: preset?.id, tier, daysBack }, emit));
}
