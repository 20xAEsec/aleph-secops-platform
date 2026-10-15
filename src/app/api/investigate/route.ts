import { runInvestigation } from "@/lib/agents/investigate";
import { sseResponse } from "@/lib/sse";

export const maxDuration = 300;

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const ioc = String(body.ioc ?? "").trim().slice(0, 2048);
  if (!ioc) return Response.json({ error: "An indicator is required." }, { status: 400 });
  return sseResponse((emit) => runInvestigation(ioc, emit));
}
