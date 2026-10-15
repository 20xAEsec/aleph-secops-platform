"use client";

import type { RunState } from "@/lib/useRun";
import Markdown from "./Markdown";

export function EvidenceCard({ state }: { state: RunState }) {
  const ev = state.evidence;
  if (!ev) return null;
  const clean = ev.unverified.length === 0;
  return (
    <section className={`glass rise p-4 ${clean ? "" : "border-sev-medium/30"}`}>
      <div className="kicker mb-2">Evidence check</div>
      <p className="text-[0.8rem] text-ink-muted">
        {ev.checked} indicator(s) in the report checked against raw tool payloads.{" "}
        {clean ? <span className="text-accent">All verified.</span> : <span className="text-sev-medium">{ev.unverified.length} never appeared in tool results:</span>}
      </p>
      {!clean && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {ev.unverified.map((i) => <code key={i} className="rounded bg-sev-medium/10 px-1.5 py-0.5 font-mono text-[0.7rem] text-sev-medium">{i}</code>)}
        </div>
      )}
      <p className="mt-2 text-[0.68rem] text-ink-subtle">Deterministic. It flags, never edits, and makes no model call.</p>
    </section>
  );
}

export default function ReportPanel({ state, title = "Report", empty, actions, footer }: {
  state: RunState; title?: string; empty: React.ReactNode; actions?: React.ReactNode; footer?: React.ReactNode;
}) {
  const streaming = state.status === "running" && state.stages.some((s) => s.status === "running" && (s.phase === "Report" || s.phase === "Analyze"));
  const exportMd = () => {
    const blob = new Blob([state.report], { type: "text/markdown" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `aleph-${title.toLowerCase().replace(/\s+/g, "-")}.md` });
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <section className="glass min-h-[24rem] p-5 sm:p-7">
      <div className="mb-4 flex items-center justify-between">
        <div className="kicker">{title}</div>
        {state.report && state.status !== "running" && (
          <div className="flex flex-wrap items-center justify-end gap-2">
            {actions}
            <button className="btn btn-ghost px-3 py-1 text-[0.72rem]" onClick={exportMd}>Export .md</button>
          </div>
        )}
      </div>
      {state.error && <div className="mb-4 rounded-lg border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-[0.8rem] text-sev-critical">{state.error}</div>}
      {state.report ? <Markdown text={state.report} streaming={streaming} /> : state.status === "running" ? (
        <div className="flex items-center gap-3 text-[0.82rem] text-ink-muted">
          <span className="spin inline-block h-4 w-4 rounded-full border-2 border-accent/20 border-t-accent" />
          Agents are gathering evidence. The report streams here as soon as it starts.
        </div>
      ) : empty}
      {footer}
    </section>
  );
}
