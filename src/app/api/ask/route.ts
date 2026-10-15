import { runAsk, type ChatMessage } from "@/lib/agents/ask";
import { sseResponse } from "@/lib/sse";

export const maxDuration = 120;

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const messages: ChatMessage[] = (Array.isArray(body.messages) ? body.messages : [])
    .filter((m: ChatMessage) => (m?.role === "user" || m?.role === "assistant") && typeof m.content === "string")
    .map((m: ChatMessage) => ({ role: m.role, content: m.content.slice(0, 16000) }));
  if (!messages.length || messages.at(-1)!.role !== "user") {
    return Response.json({ error: "Send at least one user message." }, { status: 400 });
  }
  return sseResponse((emit) => runAsk(messages, emit));
}
