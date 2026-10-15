"use client";

import { useState } from "react";
import PageHeader from "@/components/PageHeader";
import PipelineView from "@/components/PipelineView";
import ReportPanel from "@/components/ReportPanel";
import { TicketCard, TicketList, useJiraQueue } from "@/components/Jira";
import type { JiraTicket } from "@/lib/detections/jira";
import { useRun } from "@/lib/useRun";

const EXAMPLES = [
  "Detect Office documents with macros spawning hidden, encoded PowerShell",
  "Alert on hosts beaconing to the same domain at a fixed interval",
  "Detect service account logins from outside the US",
];
const LANGUAGES = ["YARA-L", "KQL", "SPL"] as const;
const SEVERITIES = ["Low", "Medium", "High", "Critical"] as const;

type Lint = { name: string; pass: boolean; detail?: string };
type RuleTest = { matches: number; raw?: number; verdict: "DEAD" | "OK" | "FP_STORM" };

const VERDICT_STYLE: Record<RuleTest["verdict"], string> = {
  OK: "text-accent bg-accent/10",
  DEAD: "text-sev-medium bg-sev-medium/10",
  FP_STORM: "text-sev-critical bg-sev-critical/10",
};

export default function DetectionsClient({ initialDescription }: { initialDescription: string }) {
  const [source, setSource] = useState<"jira" | "describe">(initialDescription ? "describe" : "jira");
  const [description, setDescription] = useState(initialDescription);
  const [language, setLanguage] = useState<(typeof LANGUAGES)[number]>("YARA-L");
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>("High");
  const [ticket, setTicket] = useState<JiraTicket | null>(null);

  const queue = useJiraQueue("intake");
  const manual = useRun("/api/detections");
  const fromJira = useRun("/api/jira/generate");
  const { state } = source === "jira" ? fromJira : manual;
  const running = state.status === "running";
  const lint = state.meta.lint as Lint[] | undefined;
  const test = state.meta.ruleTest as RuleTest | undefined;

  const pickTicket = (t: JiraTicket) => {
    setTicket(t);
    fromJira.start({ key: t.key });
  };

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="Detection Engineering · Generator" title="Detection Generator">
        Draft a rule from a Jira detection request, or describe one yourself. A research agent confirms the fields exist, the rule
        author follows team standards, and a validator lints and tests the rule before you see it.
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <div className="flex flex-col gap-5">
          <div className="seg self-start" role="group" aria-label="Source">
            <button type="button" aria-pressed={source === "jira"} onClick={() => setSource("jira")}>From Jira</button>
            <button type="button" aria-pressed={source === "describe"} onClick={() => setSource("describe")}>Describe</button>
          </div>

          {source === "jira" ? (
            <>
              <TicketList title="Jira · Detection intake" tickets={queue.tickets} error={queue.error} selected={ticket?.key} onSelect={pickTicket} disabled={running} />
              {ticket && <TicketCard key={ticket.key} ticket={ticket} />}
            </>
          ) : (
            <form className="glass rise p-4" onSubmit={(e) => { e.preventDefault(); if (description.trim() && !running) manual.start({ description, language, severity }); }}>
              <label htmlFor="desc" className="kicker mb-2 block">What should it detect?</label>
              <textarea id="desc" className="glass-input h-28 w-full resize-none p-3 text-[0.88rem]" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Describe the behaviour…" />
              <div className="mt-2 flex flex-wrap gap-1.5">
                {EXAMPLES.map((ex) => (
                  <button type="button" key={ex} onClick={() => setDescription(ex)} className="rounded-full border border-white/8 px-2.5 py-1 text-left text-[0.7rem] text-ink-muted transition-colors hover:border-accent/30 hover:text-ink">
                    {ex.length > 50 ? `${ex.slice(0, 50)}…` : ex}
                  </button>
                ))}
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <div className="seg" role="group" aria-label="Language">
                  {LANGUAGES.map((l) => <button type="button" key={l} aria-pressed={language === l} onClick={() => setLanguage(l)}>{l}</button>)}
                </div>
                <select value={severity} onChange={(e) => setSeverity(e.target.value as typeof severity)} className="glass-input px-2 py-1.5 text-[0.75rem]" aria-label="Severity">
                  {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
                </select>
              </div>
              <button type="submit" disabled={!description.trim() || running} className="btn btn-primary sheen mt-4 w-full">{running ? "Generating…" : "Generate rule"}</button>
            </form>
          )}

          {(lint || test) && (
            <section className="glass rise p-4">
              <div className="kicker mb-3">Validation</div>
              {test && (
                <div className="mb-3 flex items-center justify-between gap-3 text-[0.8rem]">
                  <span className="text-ink-muted">
                    Rule test · 7d · simulated
                    {test.raw != null && <span className="block font-mono text-[0.64rem] text-ink-subtle">{test.raw} raw → {test.matches} after known-goods</span>}
                  </span>
                  <span className={`shrink-0 rounded-full px-2.5 py-0.5 font-mono text-[0.68rem] ${VERDICT_STYLE[test.verdict]}`}>{test.matches} match · {test.verdict}</span>
                </div>
              )}
              {lint && lint.length > 0 && (
                <ul className="space-y-1">
                  {lint.map((c) => (
                    <li key={c.name} className="flex items-start justify-between gap-3 text-[0.75rem]">
                      <span className={c.pass ? "text-ink-muted" : "text-sev-high"}>{c.pass ? "✓" : "✗"} {c.name}</span>
                      {c.detail && <span className="text-right font-mono text-[0.65rem] text-ink-subtle">{c.detail}</span>}
                    </li>
                  ))}
                </ul>
              )}
              {lint && lint.length === 0 && <p className="text-[0.75rem] text-ink-subtle">Structural lint applies to YARA-L only.</p>}
            </section>
          )}

          <PipelineView state={state} />
        </div>

        <ReportPanel
          state={state}
          title="Generated rule"
          empty={
            <p className="text-[0.85rem] text-ink-subtle">
              {source === "jira" ? "Pick a ticket from the intake queue. Its content is shown on the left and the drafted rule streams here." : "Pick an example, choose a language, and generate."}
            </p>
          }
        />
      </div>
    </div>
  );
}
