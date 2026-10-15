import { GoogleAuth } from "google-auth-library";
import { config, isRagConfigured } from "./config";

// Vertex AI RAG Engine retrieval. On hosts without a filesystem credential (Vercel), set
// GCP_SERVICE_ACCOUNT_KEY to the service account's JSON key. Otherwise auth falls back to
// Application Default Credentials (`gcloud auth application-default login` locally).
// Reads never raise: failures come back as an `unavailable` result the agents record as a data gap.

export type RagContext = { source: string; text: string; distance?: number };
export type RagResult =
  | { status: "ok"; contexts: RagContext[] }
  | { status: "not_configured" | "unavailable"; contexts: []; error: string };

let auth: GoogleAuth | null = null;

function corpusResourceName() {
  const { corpus, projectId, location } = config.rag;
  return corpus.startsWith("projects/")
    ? corpus
    : `projects/${projectId}/locations/${location}/ragCorpora/${corpus}`;
}

export async function retrieveContexts(query: string): Promise<RagResult> {
  if (!isRagConfigured()) {
    return {
      status: "not_configured",
      contexts: [],
      error: "Vertex RAG not configured (set GCP_PROJECT_ID and VERTEX_RAG_CORPUS)",
    };
  }

  try {
    auth ??= new GoogleAuth({
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      ...(config.rag.serviceAccountKey && { credentials: JSON.parse(config.rag.serviceAccountKey) }),
    });
    const token = await auth.getAccessToken();
    const { projectId, location, topK } = config.rag;
    const url = `https://${location}-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${location}:retrieveContexts`;

    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        vertex_rag_store: { rag_resources: [{ rag_corpus: corpusResourceName() }] },
        query: { text: query.slice(0, 2000), rag_retrieval_config: { top_k: topK } },
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      return { status: "unavailable", contexts: [], error: `Vertex RAG ${res.status}: ${(await res.text()).slice(0, 300)}` };
    }

    const data = (await res.json()) as {
      contexts?: { contexts?: { sourceUri?: string; sourceDisplayName?: string; text?: string; distance?: number; score?: number }[] };
    };
    const contexts = (data.contexts?.contexts ?? []).map((c) => ({
      source: c.sourceDisplayName || c.sourceUri || "knowledge-base",
      text: (c.text ?? "").slice(0, 1500),
      distance: c.distance ?? c.score,
    }));
    return { status: "ok", contexts };
  } catch (err) {
    return { status: "unavailable", contexts: [], error: err instanceof Error ? err.message : String(err) };
  }
}
