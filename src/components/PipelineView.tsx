"use client";

import { useEffect, useState } from "react";
import type { RunState, StageState } from "@/lib/useRun";
import Markdown from "./Markdown";

const PHASE_ORDER = ["Gather", "Analyze", "Challenge", "Report", "Verify"];

function Elapsed({ from, to }: { from?: number; to?: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (to) return;
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, [to]);
  if (!from) return null;
  return <span>{(((to ?? now) - from) / 1000).toFixed(1)}s</span>;
}

function StageIcon({ status }: { status: StageState["status"] }) {
  if (status === "running") return <span className="spin inline-block h-3.5 w-3.5 rounded-full border-[1.5px] border-accent/25 border-t-accent" />;
  if (status === "done") return <span className="grid h-3.5 w-3.5 place-items-center rounded-full bg-accent/20 text-[0.55rem] text-accent">✓</span>;
  if (status === "failed") return <span className="grid h-3.5 w-3.5 place-items-center rounded-full bg-sev-critical/20 text-[0.55rem] text-sev-critical">!</span>;
  return <span className="h-3.5 w-3.5 rounded-full border border-white/15" />;
}

function Stage({ stage }: { stage: StageState }) {
  const [open, setOpen] = useState(true);
  const hasBody = stage.tools.length > 0 || stage.text || stage.error;
  return (
    <li className={`rounded-xl border px-3 py-2.5 transition-colors ${stage.status === "running" ? "border-accent/25 bg-accent/[0.03]" : "border-white/5 bg-white/[0.015]"}`}>
      <button className="flex w-full items-center gap-2.5 text-left" onClick={() => setOpen((o) => !o)} disabled={!hasBody}>
        <StageIcon status={stage.status} />
        <span className={`text-[0.82rem] ${stage.status === "pending" ? "text-ink-subtle" : "text-ink"}`}>{stage.name}</span>
        <span className="ml-auto flex items-center gap-2 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">
          <span className="hidden sm:inline">{stage.model}</span>
          {stage.ms != null && <span>{(stage.ms / 1000).toFixed(1)}s</span>}
        </span>
      </button>
      {open && hasBody && (
        <div className="mt-2 space-y-1.5 pl-6">
          {stage.tools.map((t) => (
            <div key={t.id} className="font-mono text-[0.68rem] leading-relaxed">
              <span className="text-glow">→ {t.name}</span>
              {t.cached && <span className="ml-1.5 rounded bg-accent/10 px-1 text-[0.58rem] uppercase text-accent">cached</span>}
              {t.unavailable && <span className="ml-1.5 rounded bg-sev-medium/10 px-1 text-[0.58rem] uppercase text-sev-medium">unavailable</span>}
              {t.ms != null && <span className="ml-1.5 text-ink-subtle">{t.ms}ms</span>}
              {t.summary && <div className="text-ink-muted">{t.summary}</div>}
            </div>
          ))}
          {stage.text && (
            <div className="max-h-56 overflow-y-auto rounded-lg border border-white/5 bg-black/20 px-3 py-2 text-[0.78rem]">
              <Markdown text={stage.text} streaming={stage.status === "running"} />
            </div>
          )}
          {stage.error && <div className="text-[0.75rem] text-sev-critical">Did not complete: {stage.error}. The pipeline continued, and this is recorded as a data gap.</div>}
        </div>
      )}
    </li>
  );
}

export default function PipelineView({ state }: { state: RunState }) {
  if (!state.stages.length && state.status !== "running") return null;
  const phases = PHASE_ORDER.filter((p) => state.stages.some((s) => s.phase === p));
  const current = state.stages.find((s) => s.status === "running")?.phase;

  return (
    <section className="glass rise p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="kicker">Agent pipeline</div>
        <div className="font-mono text-[0.66rem] text-ink-subtle">
          <Elapsed from={state.startedAt} to={state.finishedAt} />
        </div>
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-1.5 font-mono text-[0.6rem] uppercase tracking-wider">
        {phases.map((p, i) => {
          const all = state.stages.filter((s) => s.phase === p);
          const done = all.every((s) => s.status === "done" || s.status === "failed");
          return (
            <span key={p} className="flex items-center gap-1.5">
              <span className={`rounded-full px-2 py-0.5 ${p === current ? "bg-accent/15 text-accent" : done ? "text-ink-muted" : "text-ink-subtle"}`}>{p}</span>
              {i < phases.length - 1 && <span className="text-ink-subtle">›</span>}
            </span>
          );
        })}
      </div>
      <ol className="space-y-1.5">
        {state.stages.map((s) => <Stage key={s.id} stage={s} />)}
      </ol>
      {state.usage && (state.usage.input > 0 || state.usage.output > 0) && (
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 border-t border-white/5 pt-3 font-mono text-[0.62rem] uppercase tracking-wider text-ink-subtle">
          <span>in {state.usage.input.toLocaleString()}</span>
          <span>out {state.usage.output.toLocaleString()}</span>
          <span className="text-accent/80">cache read {state.usage.cacheRead.toLocaleString()}</span>
        </div>
      )}
    </section>
  );
}
