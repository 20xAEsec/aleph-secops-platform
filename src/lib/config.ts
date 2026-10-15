// Server-side runtime configuration. Everything comes from env vars (see .env.example).

export const config = {
  anthropicKey: process.env.ANTHROPIC_API_KEY ?? "",
  models: {
    // "Sonnet gathers, Opus concludes": fast model for data-gathering / analysis agents,
    // reasoning model for the agents that write conclusions.
    reasoning: process.env.ALEPH_MODEL_REASONING ?? "claude-opus-5-5",
    fast: process.env.ALEPH_MODEL_FAST ?? "claude-sonnet-5-5",
  },
  rag: {
    projectId: process.env.GCP_PROJECT_ID ?? "",
    location: process.env.GCP_LOCATION ?? "us-central1",
    // Either the full resource name (projects/.../ragCorpora/123) or just the corpus id.
    corpus: process.env.VERTEX_RAG_CORPUS ?? "",
    topK: Number(process.env.VERTEX_RAG_TOP_K ?? 6),
    // Service account JSON key (for Vercel). Empty means Application Default Credentials.
    serviceAccountKey: process.env.GCP_SERVICE_ACCOUNT_KEY ?? "",
  },
  maxConcurrentRuns: 5,
};

// Model allowlist: a requested model is untrusted input. Unknown ids fall back to the default.
const ALLOWED_MODELS = new Set([
  "claude-opus-5-5",
  "claude-sonnet-5-5",
  "claude-haiku-5-5",
  config.models.reasoning,
  config.models.fast,
]);

export function resolveModel(requested: string | undefined, fallback: string): string {
  return requested && ALLOWED_MODELS.has(requested) ? requested : fallback;
}

export const isLlmLive = () => config.anthropicKey.length > 0;
export const isRagConfigured = () => Boolean(config.rag.projectId && config.rag.corpus);
