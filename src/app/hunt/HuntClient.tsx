"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import PageHeader from "@/components/PageHeader";
import PipelineView from "@/components/PipelineView";
import ReportPanel, { EvidenceCard } from "@/components/ReportPanel";
import { CaseCard } from "@/components/FalconCase";
import { useRun, type RunState } from "@/lib/useRun";
import type { CaseComment, FalconCase } from "@/lib/secops/crowdstrike";

const EXAMPLES = [
  "Look for beaconing from finance hosts to newly registered domains over the last 7 days",
  "Hunt for macro-enabled Office documents spawning encoded PowerShell",
  "Find service accounts logging in from unusual countries",
];

const TIERS = {
  basic: { label: "Basic", stages: "Telemetry → Knowledge → Investigation → Report" },
  advanced: { label: "Advanced", stages: "Telemetry → Intel → Knowledge → Investigation → MITRE → Challenger → Report" },
} as const;

export default function HuntClient({ initialHypothesis, caseId }: { initialHypothesis: string; caseId?: string }) {
  const [hypothesis, setHypothesis] = useState(initialHypothesis);
  const [tier, setTier] = useState<keyof typeof TIERS>("advanced");
  const [lookbackDays, setLookback] = useState(7);
  const { state, start } = useRun("/api/hunt");
  const running = state.status === "running";
  const [falconCase, setFalconCase] = useState<FalconCase | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const autoStarted = useRef(false);

  // Case mode: pull the case from Falcon, load it into the form and start the investigation.
  useEffect(() => {
    if (!caseId) return;
    fetch(`/api/crowdstrike/cases/${encodeURIComponent(caseId)}`)
      .then((r) => r.json().then((d) => (r.ok ? (d.case as FalconCase) : Promise.reject(new Error(d.error ?? `HTTP ${r.status}`)))))
      .then((c) => {
        setFalconCase(c);
        setHypothesis(c.hypothesis);
        setTier("advanced");
        setLookback(c.lookbackDays);
        if (!autoStarted.current) {
          autoStarted.current = true;
          start({ hypothesis: c.hypothesis, tier: "advanced", lookbackDays: c.lookbackDays });
        }
      })
      .catch((e) => setCaseError(e.message));
  }, [caseId, start]);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker={caseId ? `Security Investigations · Case ${caseId}` : "Security Investigations · Threat Hunt"} title="Threat Hunt">
        {caseId
          ? "Investigating a CrowdStrike case. The case details were loaded as the hunt hypothesis; when the report is ready, attach it to the case."
          : "Describe a hypothesis in plain English. Agents search telemetry, enrich with intel and the knowledge base, argue the other side, and write a cited, MITRE-mapped report."}
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <div className="flex flex-col gap-5">
          {caseId && (
            <Link href="/cases" className="-mb-2 font-mono text-[0.66rem] uppercase tracking-wider text-ink-subtle transition-colors hover:text-accent">← Case queue</Link>
          )}
          {caseError && <div className="glass rise border-sev-critical/30 p-4 text-[0.8rem] text-sev-critical">Could not load case {caseId}: {caseError}</div>}
          {falconCase && <CaseCard c={falconCase} />}
          <form
            className="glass rise p-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (hypothesis.trim() && !running) start({ hypothesis, tier, lookbackDays });
            }}
          >
            <label htmlFor="hypothesis" className="kicker mb-2 block">Hypothesis</label>
            <textarea
              id="hypothesis"
              className="glass-input h-32 w-full resize-none p-3 text-[0.88rem]"
              placeholder="What are you hunting for?"
              value={hypothesis}
              onChange={(e) => setHypothesis(e.target.value)}
              maxLength={20000}
            />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex) => (
                <button type="button" key={ex} onClick={() => setHypothesis(ex)} className="rounded-full border border-white/8 px-2.5 py-1 text-left text-[0.7rem] text-ink-muted transition-colors hover:border-accent/30 hover:text-ink">
                  {ex.length > 52 ? `${ex.slice(0, 52)}…` : ex}
                </button>
              ))}
            </div>

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <div className="seg" role="group" aria-label="Depth">
                {(Object.keys(TIERS) as (keyof typeof TIERS)[]).map((t) => (
                  <button type="button" key={t} aria-pressed={tier === t} onClick={() => setTier(t)}>{TIERS[t].label}</button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-[0.75rem] text-ink-muted">
                Lookback
                <select value={lookbackDays} onChange={(e) => setLookback(Number(e.target.value))} className="glass-input px-2 py-1 text-[0.75rem]">
                  {[1, 7, 14, 30, 90].map((d) => <option key={d} value={d}>{d}d</option>)}
                </select>
              </label>
            </div>
            <p className="mt-2 font-mono text-[0.62rem] leading-relaxed text-ink-subtle">{TIERS[tier].stages}</p>

            <button type="submit" disabled={!hypothesis.trim() || running} className="btn btn-primary sheen mt-4 w-full">
              {running ? "Hunting…" : "Run hunt"}
            </button>
          </form>

          <PipelineView state={state} />
          <EvidenceCard state={state} />
        </div>

        <ReportPanel
          state={state}
          title="Hunt report"
          empty={<p className="text-[0.85rem] text-ink-subtle">Run a hunt to see the report. Try the first example: the demo environment has a story in it.</p>}
          footer={falconCase && state.status === "done" && state.report ? <AttachToCase c={falconCase} state={state} /> : null}
        />
      </div>
    </div>
  );
}

type Posted = { comment: CaseComment; request: { method: string; path: string; action: string } };

function AttachToCase({ c, state }: { c: FalconCase; state: RunState }) {
  const [phase, setPhase] = useState<"idle" | "posting" | "posted" | "error">("idle");
  const [posted, setPosted] = useState<Posted | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function attach() {
    setPhase("posting");
    setError(null);
    const body = `## Aleph AI investigation report\n\nCase ${c.id} · ${c.alertName}\nGenerated ${new Date().toISOString()}\n\n${state.report}`;
    try {
      const res = await fetch(`/api/crowdstrike/cases/${encodeURIComponent(c.id)}/comments`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error ?? `HTTP ${res.status}`);
      setPosted(d);
      setPhase("posted");
    } catch (e) {
      setError((e as Error).message);
      setPhase("error");
    }
  }

  return (
    <div className="rise mt-6 rounded-xl border border-accent/20 bg-accent/[0.04] p-4">
      {phase === "posted" && posted ? (
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="grid h-5 w-5 place-items-center rounded-full bg-accent text-[0.7rem] font-bold text-accent-ink">✓</span>
            <span className="text-[0.88rem] font-medium text-ink">Report attached to {c.id}</span>
          </div>
          <dl className="mt-3 grid gap-x-6 gap-y-1.5 font-mono text-[0.66rem] sm:grid-cols-[auto_1fr]">
            <dt className="text-ink-subtle">Request</dt>
            <dd className="text-ink-muted">{posted.request.method} {posted.request.path} · action={posted.request.action}</dd>
            <dt className="text-ink-subtle">Comment</dt>
            <dd className="text-ink-muted">{posted.comment.id} · {posted.comment.author} · {new Date(posted.comment.createdAt).toLocaleString()}</dd>
          </dl>
          <Link href="/cases" className="btn btn-ghost mt-4 px-4 py-1.5 text-[0.74rem]">Back to case queue</Link>
        </div>
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="kicker mb-1">CrowdStrike Falcon</div>
            <p className="text-[0.8rem] text-ink-muted">
              Post this report to case <span className="font-mono text-glow">{c.id}</span> as a comment, so it appears on the case timeline.
            </p>
            {error && <p className="mt-1 text-[0.75rem] text-sev-critical">Attach failed: {error}</p>}
          </div>
          <button className="btn btn-primary sheen shrink-0" onClick={attach} disabled={phase === "posting"}>
            {phase === "posting" ? "Posting to Falcon…" : "Attach Report to Case"}
          </button>
        </div>
      )}
    </div>
  );
}
