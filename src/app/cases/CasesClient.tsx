"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import PageHeader from "@/components/PageHeader";
import { Assignee, SeverityBadge, StatusLabel, formatTime, timeAgo } from "@/components/FalconCase";
import type { CaseSeverity, FalconCase } from "@/lib/secops/crowdstrike";

const FILTERS = { open: "Open", unassigned: "Unassigned", all: "All" } as const;
type Filter = keyof typeof FILTERS;

const SEV_ORDER: CaseSeverity[] = ["Critical", "High", "Medium", "Low"];
const SEV_TEXT: Record<CaseSeverity, string> = { Critical: "text-sev-critical", High: "text-sev-high", Medium: "text-sev-medium", Low: "text-sev-low" };
const SEV_RAIL: Record<CaseSeverity, string> = { Critical: "bg-sev-critical", High: "bg-sev-high", Medium: "bg-sev-medium", Low: "bg-sev-low" };

const GRID = "lg:grid-cols-[6.5rem_minmax(0,1fr)_9.5rem_7.5rem_8.5rem_7rem_7.5rem]";

export default function CasesClient() {
  const [cases, setCases] = useState<FalconCase[] | null>(null);
  const [syncedAt, setSyncedAt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("open");

  useEffect(() => {
    fetch("/api/crowdstrike/cases")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => { setCases(d.cases); setSyncedAt(d.syncedAt); })
      .catch((e) => setError(e.message));
  }, []);

  const visible = useMemo(() => (cases ?? []).filter((c) =>
    filter === "all" ? true : filter === "open" ? c.status !== "Closed" : c.status !== "Closed" && !c.assignee,
  ), [cases, filter]);

  const open = (cases ?? []).filter((c) => c.status !== "Closed");

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="Security Investigations · Cases" title="Case Investigations">
        The open CrowdStrike Falcon case queue, pulled via the Falcon API. Investigate a case to hand it to the Threat Hunt agents,
        then post the finished report back to the case as a comment.
      </PageHeader>

      {/* Queue summary */}
      <div className="rise mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {SEV_ORDER.map((s) => (
          <div key={s} className="glass px-4 py-3">
            <div className="text-[0.66rem] uppercase tracking-[0.14em] text-ink-subtle">{s}</div>
            <div className={`mt-1 font-mono text-2xl font-light ${SEV_TEXT[s]}`}>{cases ? open.filter((c) => c.severity === s).length : "–"}</div>
          </div>
        ))}
      </div>

      <section className="glass rise overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="kicker">Case queue</span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-white/8 bg-white/[0.03] px-2.5 py-1 font-mono text-[0.6rem] uppercase tracking-wider text-ink-muted">
              <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-accent" />
              CrowdStrike Falcon · API
            </span>
            {syncedAt && <span className="hidden font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle sm:inline">synced {formatTime(syncedAt)}</span>}
          </div>
          <div className="seg" role="group" aria-label="Filter cases">
            {(Object.keys(FILTERS) as Filter[]).map((f) => (
              <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}>{FILTERS[f]}</button>
            ))}
          </div>
        </div>

        <div className={`hidden gap-4 border-b border-white/5 px-4 py-2 text-[0.62rem] uppercase tracking-[0.14em] text-ink-subtle lg:grid ${GRID}`}>
          <span>Severity</span><span>Case · alert</span><span>Alert type</span><span>Status</span><span>Assignee</span><span>Created</span><span />
        </div>

        {error && <p className="px-4 py-6 text-[0.8rem] text-sev-critical">Falcon API unavailable: {error}</p>}
        {!cases && !error && <p className="px-4 py-6 text-[0.8rem] text-ink-subtle">Pulling cases from Falcon…</p>}
        {cases && visible.length === 0 && <p className="px-4 py-6 text-[0.8rem] text-ink-subtle">No cases match this filter.</p>}

        <ul>
          {visible.map((c) => (
            <li key={c.id} className={`relative grid items-center gap-x-4 gap-y-2 border-b border-white/[0.04] px-4 py-3 transition-colors last:border-b-0 hover:bg-white/[0.025] ${GRID} ${c.status === "Closed" ? "opacity-60" : ""}`}>
              <span className={`absolute inset-y-2 left-0 w-0.5 rounded-full ${SEV_RAIL[c.severity]}`} />
              <div><SeverityBadge severity={c.severity} score={c.score} /></div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[0.68rem] text-glow">{c.id}</span>
                  <span className="truncate font-mono text-[0.62rem] text-ink-subtle">{c.host} · {c.user}</span>
                  {c.comments.length > 0 && (
                    <span className="shrink-0 rounded bg-accent/10 px-1.5 font-mono text-[0.56rem] uppercase tracking-wider text-accent">report attached</span>
                  )}
                </div>
                <div className="mt-0.5 truncate text-[0.84rem] text-ink" title={c.alertName}>{c.alertName}</div>
                <div className="truncate text-[0.68rem] text-ink-subtle">{c.tactic} · {c.technique} · {c.detections} detection{c.detections === 1 ? "" : "s"}</div>
              </div>
              <div className="text-[0.76rem] text-ink-muted">{c.alertType}</div>
              <div><StatusLabel status={c.status} /></div>
              <div><Assignee name={c.assignee} /></div>
              <div className="text-[0.74rem]" title={new Date(c.createdAt).toLocaleString()}>
                <div className="text-ink-muted">{timeAgo(c.createdAt)}</div>
                <div className="font-mono text-[0.6rem] text-ink-subtle">{formatTime(c.createdAt)}</div>
              </div>
              <div className="lg:text-right">
                <Link href={`/hunt?case=${encodeURIComponent(c.id)}`} className="btn btn-primary sheen px-4 py-1.5 text-[0.74rem]">Investigate</Link>
              </div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
