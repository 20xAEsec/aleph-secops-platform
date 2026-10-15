"use client";

import type { CaseSeverity, CaseStatus, FalconCase } from "@/lib/secops/crowdstrike";

export const SEVERITY_STYLE: Record<CaseSeverity, string> = {
  Critical: "border-sev-critical/40 bg-sev-critical/12 text-sev-critical",
  High: "border-sev-high/40 bg-sev-high/12 text-sev-high",
  Medium: "border-sev-medium/40 bg-sev-medium/12 text-sev-medium",
  Low: "border-sev-low/40 bg-sev-low/12 text-sev-low",
};

const STATUS_DOT: Record<CaseStatus, string> = {
  New: "bg-glow shadow-[0_0_8px_rgba(58,108,255,0.8)]",
  "In Progress": "bg-sev-medium",
  Reopened: "bg-sev-high",
  Closed: "bg-ink-subtle",
};

export function SeverityBadge({ severity, score }: { severity: CaseSeverity; score: number }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[0.62rem] font-medium uppercase tracking-wider ${SEVERITY_STYLE[severity]}`}>
      {severity}
      <span className="opacity-70">{score}</span>
    </span>
  );
}

export function StatusLabel({ status }: { status: CaseStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[0.76rem] text-ink-muted">
      <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[status]}`} />
      {status}
    </span>
  );
}

export function Assignee({ name }: { name: string | null }) {
  if (!name) return <span className="text-[0.76rem] italic text-ink-subtle">Unassigned</span>;
  const initials = name.split(/[\s.]+/).filter(Boolean).map((p) => p[0]).join("").slice(0, 2);
  return (
    <span className="inline-flex items-center gap-2 text-[0.76rem] text-ink-muted">
      <span className="grid h-5 w-5 place-items-center rounded-full border border-white/10 bg-white/[0.05] font-mono text-[0.55rem] text-ink">{initials}</span>
      {name}
    </span>
  );
}

export function timeAgo(iso: string) {
  const m = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60_000));
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ${m % 60}m ago` : `${Math.floor(h / 24)}d ago`;
}

export function formatTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// Compact case summary shown above the Threat Hunt form when a case is being investigated.
export function CaseCard({ c }: { c: FalconCase }) {
  return (
    <section className="glass rise p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="kicker">CrowdStrike case</span>
        <span className="font-mono text-[0.72rem] text-glow">{c.id}</span>
        <span className="ml-auto"><SeverityBadge severity={c.severity} score={c.score} /></span>
      </div>
      <div className="text-[0.92rem] font-medium text-ink">{c.alertName}</div>
      <p className="mt-1.5 text-[0.78rem] leading-relaxed text-ink-muted">{c.description}</p>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-[0.72rem]">
        <div><dt className="text-ink-subtle">Host · user</dt><dd className="font-mono text-ink">{c.host} · {c.user}</dd></div>
        <div><dt className="text-ink-subtle">ATT&CK</dt><dd className="text-ink">{c.technique}</dd></div>
        <div><dt className="text-ink-subtle">Status</dt><dd><StatusLabel status={c.status} /></dd></div>
        <div><dt className="text-ink-subtle">Assignee</dt><dd><Assignee name={c.assignee} /></dd></div>
      </dl>
    </section>
  );
}
