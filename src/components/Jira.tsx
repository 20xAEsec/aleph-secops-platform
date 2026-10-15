"use client";

import { useEffect, useState } from "react";
import type { JiraTicket } from "@/lib/detections/jira";

const PRIORITY_STYLE: Record<JiraTicket["priority"], string> = {
  P1: "bg-sev-critical/15 text-sev-critical",
  P2: "bg-sev-high/15 text-sev-high",
  P3: "bg-sev-low/15 text-sev-low",
};

export function useJiraQueue(queue: "intake" | "tuning") {
  const [tickets, setTickets] = useState<JiraTicket[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    fetch(`/api/jira?queue=${queue}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => setTickets(d.tickets))
      .catch((e) => setError(e.message));
  }, [queue]);
  return { tickets, error };
}

export function TicketList({ title, tickets, error, selected, onSelect, disabled }: {
  title: string; tickets: JiraTicket[] | null; error: string | null; selected?: string; onSelect: (t: JiraTicket) => void; disabled?: boolean;
}) {
  return (
    <section className="glass rise p-3">
      <div className="mb-2 flex items-center justify-between px-1">
        <div className="kicker">{title}</div>
        <span className="font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">{tickets ? `${tickets.length} open` : "…"}</span>
      </div>
      {error && <p className="px-1 text-[0.75rem] text-sev-critical">Jira unavailable: {error}</p>}
      {!tickets && !error && <p className="px-1 text-[0.75rem] text-ink-subtle">Loading queue…</p>}
      <ul className="space-y-1">
        {tickets?.map((t) => {
          const active = t.key === selected;
          return (
            <li key={t.key}>
              <button
                onClick={() => onSelect(t)}
                disabled={disabled}
                aria-pressed={active}
                className={`w-full rounded-lg border px-3 py-2 text-left transition-colors disabled:cursor-wait ${
                  active ? "border-accent/30 bg-accent/[0.06]" : "border-transparent hover:border-white/8 hover:bg-white/[0.025]"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[0.66rem] text-glow">{t.key}</span>
                  <span className={`rounded px-1.5 font-mono text-[0.56rem] ${PRIORITY_STYLE[t.priority]}`}>{t.priority}</span>
                  <span className="ml-auto font-mono text-[0.56rem] uppercase tracking-wider text-ink-subtle">{t.status}</span>
                </div>
                <div className={`mt-0.5 text-[0.78rem] ${active ? "text-ink" : "text-ink-muted"}`}>{t.summary}</div>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function TicketCard({ ticket }: { ticket: JiraTicket }) {
  return (
    <section className="glass rise p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="font-mono text-[0.72rem] text-glow">{ticket.key}</span>
        <span className={`rounded px-1.5 font-mono text-[0.58rem] ${PRIORITY_STYLE[ticket.priority]}`}>{ticket.priority}</span>
        <span className="font-mono text-[0.58rem] uppercase tracking-wider text-ink-subtle">{ticket.status} · {ticket.reporter} · {ticket.created}</span>
      </div>
      <dl className="space-y-3 text-[0.8rem]">
        <div>
          <dt className="kicker mb-1">Detection name</dt>
          <dd className="text-ink">{ticket.detectionName}</dd>
        </div>
        <div>
          <dt className="kicker mb-1">Log source</dt>
          <dd className="font-mono text-[0.74rem] text-ink">{ticket.logSource}</dd>
        </div>
        <div>
          <dt className="kicker mb-1">Primary activity of interest</dt>
          <dd className="leading-relaxed text-ink-muted">{ticket.primaryActivity}</dd>
        </div>
        <div>
          <dt className="kicker mb-1">Known-goods to tune out</dt>
          <dd>
            <ul className="space-y-1">
              {ticket.knownGoods.map((k) => (
                <li key={k.label} className="flex gap-2 text-ink-muted">
                  <span className="mt-[0.45rem] h-1 w-1 shrink-0 rounded-full bg-accent" />
                  <span>{k.label}{k.share != null && <span className="ml-1.5 font-mono text-[0.66rem] text-ink-subtle">{Math.round(k.share * 100)}% of matches</span>}</span>
                </li>
              ))}
            </ul>
          </dd>
        </div>
      </dl>
    </section>
  );
}
