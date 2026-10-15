import PageHeader from "@/components/PageHeader";

const PRINCIPLES = [
  { n: "01", title: "Act as the user", body: "Every model and data call runs under the analyst's identity, so data permissions apply and audit attribution is real. There is no shared service account standing in for a person." },
  { n: "02", title: "One seam to the SIEM", body: "All telemetry access goes through a single typed layer. It enforces argument contracts, tenancy, byte caps and failure semantics in one place." },
  { n: "03", title: "Bounded autonomy in code", body: "Iteration caps, stagnation detection, context guards and bounded recursion are enforced by callbacks, not by asking the model nicely." },
  { n: "04", title: "Evidence over eloquence", body: "Per-claim source markers, a Challenger agent, and a deterministic evidence check that flags any indicator the agents never saw." },
  { n: "05", title: "Never lose the work", body: "A failed stage becomes a labelled gap and the pipeline continues. Runs are detached from the HTTP connection and resumable." },
  { n: "06", title: "Fail closed on security, soft on data", body: "Unknown role means no access. A failed read returns an `_unavailable` sentinel, and the agent records a data gap instead of crashing." },
  { n: "07", title: "Humans own every write", body: "Read-only by construction. Closing alerts, creating exclusions, opening cases: each needs an explicit analyst action behind a permission gate." },
  { n: "08", title: "Readable by design", body: "Flat functions, plain data, explicit inputs and outputs. A security platform that can't be audited by reading it is a liability." },
];

// One card per class of LLM-application risk, in a fixed order (#1–#10). `risk` names the
// threat in plain words; `answer` is the design decision that addresses it; `hint` is a
// deliberately oblique nod to the matching OWASP Top 10 for LLM Applications entry.
const MODEL_RISKS = [
  {
    risk: "Instructions smuggled into the data the model reads",
    title: "Untrusted data stays data",
    hint: "Every cue can carry a needle.",
    answer: "Every tool result is wrapped and labelled as untrusted environment data. Agents are told never to follow instructions inside it, and to flag text that tries. The backstops don't depend on the model obeying: write tools are removed from what the model can call, and query builders reject quotes and control characters.",
    where: "src/lib/agents/prompts.ts · src/lib/agents/runtime.ts",
  },
  {
    risk: "The model revealing data a user shouldn't see",
    title: "Need-to-know, enforced by identity",
    hint: "Tender secrets, spoken aloud.",
    answer: "Model and data calls run as the signed-in analyst, so the SIEM's own data permissions decide what can ever reach a prompt. Sensitive fields are encrypted at rest, and secrets are redacted before error telemetry leaves the app. The chat assistant deliberately has no tool that reads other users' investigations.",
    where: "src/lib/agents/ask.ts · full platform: session + encryption services",
  },
  {
    risk: "Compromised models, packages or third-party components",
    title: "Nothing loaded that can't be verified",
    hint: "Every weak link back to the factory floor.",
    answer: "Models resolve through an allowlist, so a tampered preference can't select an unknown model. Every dependency is bundled same-origin under a strict CSP with no CDNs. Container images are CVE-scanned, every suppression needs a written justification, and an SBOM ships with each build.",
    where: "src/lib/config.ts (resolveModel) · CI security gate",
  },
  {
    risk: "Tainted knowledge the model learns from or retrieves",
    title: "Curated ground truth",
    hint: "A drop of something bitter in the well.",
    answer: "Knowledge-base corpora are curated and role-scoped, not open to arbitrary uploads. Verdict calibration learns from how the SOC actually closed cases, never from the model's own earlier answers. Retrieved passages enter the prompt as reference material, not as instructions.",
    where: "src/lib/rag.ts · src/lib/agents/ask.ts",
  },
  {
    risk: "Trusting what the model outputs without checking it",
    title: "Output is checked before anything uses it",
    hint: "Whatever comes out, caught with bare hands.",
    answer: "Reports pass a deterministic evidence check. Rules are linted and test-run before hand-off. Hand-off buttons come from a fixed route table, so the model never writes a URL. Markdown renders without raw HTML, and generated playbook actions must exist in the live integration catalog.",
    where: "src/lib/quality/* · src/lib/catalog.ts · src/components/Markdown.tsx",
  },
  {
    risk: "Giving the model too much power to act on its own",
    title: "Read-only by construction",
    hint: "Too many keys for one butler.",
    answer: "Agents gather, correlate and draft, but they never act. Alert closures, rule exclusions, cases and tickets sit behind permission-gated routes and an explicit analyst click. Recursion is capped (four sub-hunts, depth one), and the self-healing pipeline opens PRs but has no merge step.",
    where: "Every pipeline ends in a proposal · full platform: seam write guard",
  },
  {
    risk: "Secrets or security controls living inside the system prompt",
    title: "The prompt holds no secrets and no security",
    hint: "Stage directions, dripping through the curtain.",
    answer: "System prompts carry role and evidence rules only: no keys, tokens or tenant IDs. Tenancy is injected by code at the integration seam, and authorization is enforced on the API. A leaked prompt reveals how the agents reason, not how to get in.",
    where: "src/lib/agents/prompts.ts · src/lib/config.ts (keys stay server-side)",
  },
  {
    risk: "Weak spots in retrieval, embeddings and the vector store",
    title: "Retrieval runs as the analyst",
    hint: "Soft spots where meaning becomes direction.",
    answer: "Each retrieval uses the requesting analyst's credentials against corpora scoped to their role, so embeddings can't leak across permission boundaries. Results from parallel corpora are merged by distance and reranked, and a retrieval failure is recorded as a data gap rather than silently skipped.",
    where: "src/lib/rag.ts · full platform: per-user credentials",
  },
  {
    risk: "Confident, fluent answers that aren't true",
    title: "Evidence over eloquence, in code",
    hint: "Rumours told with a straight face.",
    answer: "Every claim carries a [Source:] marker, and a failed tool call is a data gap, not proof of absence. A Challenger agent argues the other side and may only downgrade confidence. Verdicts are calibrated against real SOC closures, and any indicator the agents never actually saw is flagged.",
    where: "src/lib/agents/hunt.ts · src/lib/quality/evidence.ts",
  },
  {
    risk: "Runaway cost, tokens and resource use",
    title: "Budgets enforced in code, not in prompts",
    hint: "An appetite with no edge to the plate.",
    answer: "There are per-agent iteration caps, a memory guard, context compression, and a token ceiling on every call. Each process runs at most five investigations, and the sixth gets an immediate 429. Request sizes are capped and rate-limited per IP. A runaway agent hits a wall, not the bill.",
    where: "src/lib/sse.ts (admission) · src/lib/llm.ts · API input caps",
  },
];

const IN_THIS_DEMO = [
  ["Resilient pipeline runtime", "src/lib/agents/runtime.ts", "Stage failures become labelled gaps; tool calls deduped across agents; failures never cached"],
  ["Streaming contract", "src/lib/sse.ts · src/lib/useRun.ts", "POST + ReadableStream, rAF-batched deltas, always ends with done, never auto-retries, 429 admission control"],
  ["Model layer", "src/lib/llm.ts · src/lib/config.ts", "Claude via Anthropic API, prompt-cached system prompts, model allowlist, Sonnet gathers / Opus concludes"],
  ["Knowledge base", "src/lib/rag.ts", "Vertex AI RAG Engine via gcloud ADC; returns an unavailable result instead of throwing"],
  ["Evidence check", "src/lib/quality/evidence.ts", "Deterministic: extracts IPs/domains/hashes from reports and verifies them against raw payloads"],
  ["Rule validation", "src/lib/quality/yaral.ts", "Required-meta lint, RE2 safety, simulated rule test with DEAD / OK / FP_STORM verdicts"],
  ["Prompt-injection defense", "src/lib/agents/prompts.ts", "Tool results wrapped as untrusted data; shared directives across every agent"],
  ["Fixed route table", "src/lib/catalog.ts", "Ask Aleph hand-offs pick a key; the frontend owns the URL"],
];

export default function EngineeringPage() {
  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader kicker="Engineering" title="How Aleph is built">
        Eight principles explain almost every decision in the codebase. Below them: the ten classes of model risk and how each is
        answered, then a map of where it all lives in this demo.
      </PageHeader>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {PRINCIPLES.map((p, i) => (
          <section key={p.n} className="glass rise p-5" style={{ animationDelay: `${i * 50}ms` }}>
            <div className="font-mono text-[0.66rem] text-accent">{p.n}</div>
            <h3 className="mt-2 text-[0.95rem] font-medium text-ink">{p.title}</h3>
            <p className="mt-2 text-[0.78rem] leading-relaxed text-ink-muted">{p.body}</p>
          </section>
        ))}
      </div>

      <section className="mt-14">
        <div className="grid gap-4 lg:grid-cols-12">
          <div className="kicker pt-1.5 lg:col-span-4">/ Model risk</div>
          <div className="lg:col-span-8">
            <h2 className="text-[clamp(1.4rem,2.6vw,2rem)] font-extralight leading-tight text-ink">Ten risks, ten answers.</h2>
            <p className="copy-shadow mt-3 max-w-xl text-[0.86rem] leading-relaxed text-ink-muted">
              Each card names a class of risk specific to applications built on language models, and the design decision that answers it.
            </p>
          </div>
        </div>

        <ol className="mt-8 grid gap-3 lg:grid-cols-2">
          {MODEL_RISKS.map((r, i) => (
            <li key={r.title} className="group glass glass-hover rise flex gap-4 p-5" style={{ animationDelay: `${i * 40}ms` }}>
              <div className="shrink-0 font-mono text-[1.6rem] font-extralight leading-none text-accent">#{i + 1}</div>
              <div className="min-w-0">
                <div className="font-mono text-[0.6rem] uppercase tracking-[0.14em] text-sev-medium/90">The risk · {r.risk}</div>
                <h3 className="mt-1.5 text-[0.98rem] font-medium text-ink">{r.title}</h3>
                <p className="mt-2 text-[0.78rem] leading-relaxed text-ink-muted">{r.answer}</p>
                <div className="mt-3 truncate font-mono text-[0.64rem] text-glow" title={r.where}>{r.where}</div>
                <p className="mt-2 text-[0.68rem] italic text-ink-subtle opacity-40 transition-opacity duration-300 group-hover:opacity-90">{r.hint}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="glass rise mt-14 overflow-x-auto p-5 sm:p-6">
        <div className="kicker mb-4">In this demo</div>
        <table className="w-full min-w-[40rem] text-left text-[0.8rem]">
          <thead>
            <tr className="font-mono text-[0.62rem] uppercase tracking-wider text-ink-subtle">
              <th className="pb-2 font-normal">Capability</th><th className="pb-2 font-normal">Where</th><th className="pb-2 font-normal">What it shows</th>
            </tr>
          </thead>
          <tbody>
            {IN_THIS_DEMO.map(([cap, where, what]) => (
              <tr key={cap} className="border-t border-white/5 align-top">
                <td className="py-2.5 pr-4 text-ink">{cap}</td>
                <td className="py-2.5 pr-4 font-mono text-[0.7rem] text-glow">{where}</td>
                <td className="py-2.5 text-ink-muted">{what}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
