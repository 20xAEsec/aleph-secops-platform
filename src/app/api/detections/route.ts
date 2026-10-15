import { runDetectionGenerator } from "@/lib/agents/detections";
import { sseResponse } from "@/lib/sse";

export const maxDuration = 300;

const LANGUAGES = ["YARA-L", "KQL", "SPL"] as const;
const SEVERITIES = ["Low", "Medium", "High", "Critical"];

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const description = String(body.description ?? "").trim().slice(0, 8000);
  if (!description) return Response.json({ error: "Describe what the rule should detect." }, { status: 400 });

  const language = LANGUAGES.includes(body.language) ? body.language : "YARA-L";
  const severity = SEVERITIES.includes(body.severity) ? body.severity : "High";
  return sseResponse((emit) => runDetectionGenerator({ description, language, severity }, emit));
}
