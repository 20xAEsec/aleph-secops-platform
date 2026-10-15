import { runJiraGeneration } from "@/lib/agents/jiraGenerate";
import { sseResponse } from "@/lib/sse";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const key = String(body.key ?? "").trim();
  if (!/^[A-Z]+-\d+$/.test(key)) return Response.json({ error: "A Jira ticket key is required." }, { status: 400 });
  return sseResponse((emit) => runJiraGeneration(key, emit));
}
