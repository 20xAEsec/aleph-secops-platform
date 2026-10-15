# Aleph: SecOps workspace (demo skeleton)

An interview-demo build of Aleph, an AI security operations workspace. Analysts work in plain
English. Multi-agent pipelines gather, correlate and draft, and a deterministic layer checks
their work.

## Run it

```bash
cp .env.example .env.local   # add ANTHROPIC_API_KEY (optional: GCP vars for RAG)
npm install
npm run dev                  # http://localhost:3000
```

With no API key, the app runs in **demo mode**: every pipeline still runs and streams, and the
report is assembled deterministically from the same tool data. The top bar shows which mode is
active.

## Wire up Vertex AI RAG

```bash
gcloud auth application-default login
gcloud config set project <PROJECT_ID>
# then set GCP_PROJECT_ID, GCP_LOCATION, VERTEX_RAG_CORPUS in .env.local and restart
curl "http://localhost:3000/api/status?probe=rag"   # runs a real retrieval to verify auth
```

The ADC principal needs `roles/aiplatform.user` on the project. The Threat Hunt, IoC
Investigation, Detection Generator and Ask Aleph features all query the knowledge base. If it's
not configured, they record a data gap and carry on.

## Deploy to Vercel

1. Import `20xAEsec/aleph-secops-platform` at vercel.com/new. Next.js is auto-detected, so no
   build settings need changing.
2. Under **Settings → Environment Variables**, add `ANTHROPIC_API_KEY` and, for RAG,
   `GCP_PROJECT_ID`, `GCP_LOCATION` and `VERTEX_RAG_CORPUS`. Also add `GCP_SERVICE_ACCOUNT_KEY`,
   the service account's JSON key on one line. Vercel has no gcloud ADC, so this key replaces it.
3. Deploy. Every push to `main` then deploys to production, and other branches get preview URLs.

With no env vars set, the deployment runs in demo mode. Check `/api/status?probe=rag` once it's live.

## What's live

| Feature | Route | Pipeline |
|---|---|---|
| Threat Hunt | `/hunt` | Telemetry → (Intel) → Knowledge → Investigation → (MITRE → Challenger) → Report → Evidence check |
| IoC Investigation | `/investigate` | Normalize → Enrichment (intel ‖ case history, telemetry, KB) → Analyst → Evidence check |
| Detection Generator | `/detections` | **From Jira:** intake ticket → Log source check → Rule author (mock LLM) → Lint + simulated test. **Describe:** Research (KB + field check) → Rule author → Lint + simulated rule test |
| Detection Tuning | `/tuning` | Repo tree or Jira tuning ticket → Rule loader → Match profiler → Tuning agent (mock LLM) → Validator, with a before/after diff and volume impact |
| Detection Coverage | `/coverage` | ATT&CK heatmap + ranked gaps → one-click draft |
| Ask Aleph | `/ask` | Conversational, routes big deliverables via a fixed target table |

Other features have spec pages at `/features/<slug>`, driven by `src/lib/catalog.ts`.

## Layout

```
src/lib/config.ts          env, model allowlist
src/lib/llm.ts             Claude (Anthropic SDK), prompt caching, demo-mode fallback
src/lib/rag.ts             Vertex AI RAG Engine retrieveContexts (service account key or ADC)
src/lib/sse.ts             SSE response + admission control
src/lib/agents/runtime.ts  resilient pipeline, tool dedup, _unavailable sentinel
src/lib/agents/*.ts        hunt / investigate / detections / ask pipelines
src/lib/secops/*           demo telemetry + intel (the seam a real SIEM client replaces)
src/lib/quality/*          evidence check, YARA-L lint + rule test
src/lib/detections/*       mock Jira queues, mock rules repo, shared YARA-L builder, line diff
src/components/GalaxyBackground.tsx   GetLayers "violet-galaxy-beams" background (see getlayers.json)
```

## Design

The UI uses the GetLayers **Ascend** style and **Violet Galaxy Beams** background. The choices are recorded in
`getlayers.json`. Glass primitives and type treatments live in `src/app/globals.css`, so the
whole app can be restyled from one file.
