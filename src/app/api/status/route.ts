import { config, isLlmLive, isRagConfigured } from "@/lib/config";
import { retrieveContexts } from "@/lib/rag";

// Integration status for the top bar. `?probe=rag` runs a real retrieval to verify gcloud auth.
export async function GET(request: Request) {
  const probe = new URL(request.url).searchParams.get("probe") === "rag";
  const rag = probe ? await retrieveContexts("MITRE ATT&CK command and control") : null;

  return Response.json({
    llm: { live: isLlmLive(), models: config.models },
    rag: {
      configured: isRagConfigured(),
      location: config.rag.location,
      corpus: config.rag.corpus || null,
      probe: rag && { status: rag.status, passages: rag.contexts.length, error: "error" in rag ? rag.error : undefined },
    },
    secops: { mode: "demo-telemetry" },
  });
}
