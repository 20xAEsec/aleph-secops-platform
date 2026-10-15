# Aleph: SecOps workspace (demo skeleton)

An interview-demo build of Aleph, an AI security operations workspace. Analysts work in plain
English. Multi-agent pipelines gather, correlate and draft, and a deterministic layer checks
their work.

## Run it

```bash
npm install
npm run dev                  # http://localhost:3000
```

No environment variables are needed. The app runs entirely on dummy data: seeded telemetry and
intel, a demo knowledge base, mock Jira and rules repo. Every pipeline still runs and streams,
and reports are assembled deterministically from the same tool data.

## Deploy to Vercel

1. Import `20xAEsec/aleph-secops-platform` at vercel.com/new. Next.js is auto-detected, so no
   build settings or environment variables are needed.
2. Deploy. Every push to `main` then deploys to production, and other branches get preview URLs.

## Optional: live integrations (local only)

The Claude and Vertex AI RAG code paths are still in place. To try them, copy `.env.example` to
`.env.local` and set `ANTHROPIC_API_KEY` and/or the `GCP_*` vars (RAG uses gcloud ADC). The
top bar shows which mode each integration is in.

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
src/lib/rag.ts             Vertex AI RAG Engine retrieveContexts (ADC), demo knowledge base fallback
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
