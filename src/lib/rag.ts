import { GoogleAuth } from "google-auth-library";
import { config, isRagConfigured } from "./config";

// Vertex AI RAG Engine retrieval. Auth uses Application Default Credentials, so once you run
// `gcloud auth application-default login` (or set GOOGLE_APPLICATION_CREDENTIALS) it just works.
// With no corpus configured, a small seeded demo knowledge base answers instead.
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
  if (!isRagConfigured()) return { status: "ok", contexts: demoContexts(query) };

  try {
    auth ??= new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
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

// ---------- demo knowledge base (used when no Vertex corpus is configured) ----------

const DEMO_KB: (RagContext & { keywords: RegExp })[] = [
  {
    source: "runbooks/c2-beaconing.md",
    keywords: /beacon|c2|command and control|jitter|cadence|egress|cobalt/i,
    text: "C2 beaconing triage: look for fixed-interval outbound connections (low jitter, under 20%) to rare or newly registered destinations. Confirm with process lineage on the source host, check the destination against intel, then isolate the host and block the destination at the proxy. MITRE T1071.001, T1573.",
  },
  {
    source: "intel/fin-tempest-profile.md",
    keywords: /fin-tempest|actor|telemetry-sync|threat intel|finance|macro|newly.registered/i,
    text: "FIN-TEMPEST (tracked) is a financially motivated actor targeting finance teams. Initial access is usually a macro-enabled workbook that launches hidden, encoded PowerShell. It then deploys Cobalt Strike beacons to newly registered look-alike domains (e.g. telemetry-sync.net) behind Tor exit infrastructure.",
  },
  {
    source: "detections/powershell-encoded.md",
    keywords: /powershell|encoded|-enc|office|macro|rule|detection|process|lolbin|script/i,
    text: "Detection pattern: Office applications (excel.exe, winword.exe, outlook.exe) spawning powershell.exe with -enc / -EncodedCommand. Key UDM fields: principal.process.file.full_path, target.process.command_line. Tune out signed IT automation parents. MITRE T1059.001, T1204.002.",
  },
  {
    source: "runbooks/anomalous-login.md",
    keywords: /login|logon|auth|sign-in|mfa|travel|foreign|account/i,
    text: "Anomalous login triage: compare the source country against the user's baseline and travel calendar, check for MFA fatigue (repeated push denials), and look for new device registrations. Revoke sessions and reset credentials when the login can't be explained. MITRE T1078.",
  },
  {
    source: "standards/yara-l-style-guide.md",
    keywords: /yara|rule|detection|kql|spl|sigma|query/i,
    text: "YARA-L style guide: name rules <tactic>_<behaviour>, include meta (author, severity, mitre), match over a bounded window (5m to 1h), and add outcome variables for risk scoring. Every rule ships with a positive and a negative test case.",
  },
];

function demoContexts(query: string): RagContext[] {
  const hits = DEMO_KB.filter((d) => d.keywords.test(query));
  return (hits.length ? hits : DEMO_KB.slice(0, 2))
    .slice(0, config.rag.topK)
    .map(({ source, text }, i) => ({ source, text, distance: Number((0.18 + i * 0.07).toFixed(2)) }));
}
