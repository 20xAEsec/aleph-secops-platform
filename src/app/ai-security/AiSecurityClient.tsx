"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import PipelineView from "@/components/PipelineView";
import ReportPanel, { EvidenceCard } from "@/components/ReportPanel";
import { useRun } from "@/lib/useRun";
import { HUNTS, type HuntDef } from "@/lib/aisec/hunts";
import { CATEGORY_LABEL, CATEGORY_SEVERITY, type ViolationCategory } from "@/lib/aisec/taxonomy";
import type { ArmorStats, PromptLog } from "@/lib/aisec/modelArmor";

type Posture = {
  id: string; name: string; owner: string; audience: string; template: string; enforcement: string;
  records: number; violations: number; unblocked: number; mcpAllow: number; skillAllow: number;
};
type Row = PromptLog & { violations: ViolationCategory[] };
type Sev = "Critical" | "High" | "Medium" | "Low";

const SEV_CHIP: Record<Sev, string> = {
  Critical: "border-sev-critical/30 bg-sev-critical/10 text-sev-critical",
  High: "border-sev-high/30 bg-sev-high/10 text-sev-high",
  Medium: "border-sev-medium/30 bg-sev-medium/10 text-sev-medium",
  Low: "border-sev-low/30 bg-sev-low/10 text-sev-low",
};
const fmt = (n: number) => n.toLocaleString("en-US");
const mb = (b: number) => (b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.round(b / 1e3)} KB`);
const time = (iso: string) => new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" });

export default function AiSecurityClient({ stats, posture, corpus }: { stats: ArmorStats; posture: Posture[]; corpus: number }) {
  const { state, start } = useRun("/api/ai-hunt");
  const running = state.status === "running";

  const [hypothesis, setHypothesis] = useState("");
  const [activeHunt, setActiveHunt] = useState<HuntDef | null>(null);
  const [tier, setTier] = useState<"basic" | "advanced">("advanced");
  const [daysBack, setDaysBack] = useState(30);
  const resultsRef = useRef<HTMLDivElement>(null);

  const launch = useCallback((hunt: HuntDef | null, text?: string) => {
    if (running) return;
    setActiveHunt(hunt);
    if (hunt) setHypothesis(hunt.hypothesis);
    start(hunt ? { huntId: hunt.id, tier, daysBack } : { hypothesis: text ?? hypothesis, tier, daysBack });
    requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }, [running, start, tier, daysBack, hypothesis]);

  const started = state.status !== "idle";

  return (
    <>
      {/* ---------- Posture overview ---------- */}
      <div className="rise mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Prompt records · 30d" value={fmt(corpus)} note={`${fmt(stats.sessions)} sessions · ${stats.apps} apps`} />
        <Kpi label="Filter matches" value={fmt(stats.matched)} note={`${((stats.matched / corpus) * 100).toFixed(2)}% of traffic`} />
        <Kpi label="Blocked" value={fmt(stats.blocked)} note="enforcement prevented delivery" />
        <Kpi label="Not blocked" value={fmt(stats.unblockedViolations)} note="reached provider or destination" tone="alert" live />
        <Kpi label="Unsanctioned MCP" value={fmt(stats.unsanctionedMcp.reduce((n, b) => n + b.value, 0))} note={`${stats.unsanctionedMcp.length} server(s) off allowlist`} tone={stats.unsanctionedMcp.length ? "alert" : undefined} />
        <Kpi label="Unapproved models" value={fmt(stats.shadowModels.reduce((n, b) => n + b.value, 0))} note={`${stats.shadowModels.length} model(s) ungoverned`} tone={stats.shadowModels.length ? "alert" : undefined} />
      </div>

      <div className="mb-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_23rem]">
        <Timeline stats={stats} />
        <section className="glass rise p-5" style={{ animationDelay: "80ms" }}>
          <div className="kicker mb-1">Violation classes</div>
          <p className="mb-4 text-[0.72rem] text-ink-subtle">Matched records by class · last 30 days</p>
          <HBars bars={stats.byCategory} unit="records" />
        </section>
      </div>

      <div className="mb-5 grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,22rem)]">
        <PostureTable posture={posture} />
        <section className="glass rise p-5" style={{ animationDelay: "160ms" }}>
          <div className="kicker mb-1">Egress destinations</div>
          <p className="mb-4 text-[0.72rem] text-ink-subtle">Outbound transfers to destinations outside the corporate estate</p>
          {stats.egress.length === 0 ? (
            <p className="text-[0.8rem] text-ink-subtle">No outbound transfer to a non-corporate destination in this window.</p>
          ) : (
            <ul className="space-y-2.5">
              {stats.egress.map((e) => (
                <li key={e.destination} className="rounded-lg border border-white/5 bg-white/[0.015] px-3 py-2">
                  <div className="flex items-baseline justify-between gap-2">
                    <code className="truncate font-mono text-[0.74rem] text-sev-high">{e.destination}</code>
                    <span className="shrink-0 font-mono text-[0.72rem] text-ink">{mb(e.bytes)}</span>
                  </div>
                  <div className="mt-1 truncate font-mono text-[0.62rem] text-ink-subtle">{e.calls} call(s) · {e.principal}</div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {/* ---------- Hunt ---------- */}
      <div ref={resultsRef} className="scroll-mt-20">
        <div className="hairline mb-6 w-full opacity-40" />
        <div className="grid gap-5 xl:grid-cols-[minmax(0,27rem)_minmax(0,1fr)]">
          <div className="flex flex-col gap-5">
            <HuntLauncher
              hunts={HUNTS} activeId={activeHunt?.id} running={running}
              hypothesis={hypothesis} setHypothesis={setHypothesis}
              tier={tier} setTier={setTier} daysBack={daysBack} setDaysBack={setDaysBack}
              onLaunch={launch}
            />
            {started && <PipelineView state={state} />}
            <EvidenceCard state={state} />
          </div>

          <ReportPanel
            state={state}
            title="AI security hunt report"
            empty={
              <div className="text-[0.85rem] text-ink-subtle">
                <p>Pick a hunt above, or write your own hypothesis. The agents search the prompt logs, resolve the policy that governed each record, and write a cited report.</p>
                <p className="mt-3">Try <span className="text-ink-muted">&ldquo;Violations that enforcement let through&rdquo;</span> first: the demo corpus has applications running on an <code className="font-mono text-[0.78rem]">INSPECT_ONLY</code> template.</p>
              </div>
            }
          />
        </div>
      </div>

      {/* ---------- Log explorer ---------- */}
      <div className="hairline my-8 w-full opacity-40" />
      <LogExplorer />
    </>
  );
}

// ---------------------------------------------------------------- KPI

function Kpi({ label, value, note, tone, live }: { label: string; value: string; note: string; tone?: "alert"; live?: boolean }) {
  return (
    <div className={`glass px-4 py-3.5 ${tone === "alert" ? "ring-1 ring-sev-high/25" : ""}`}>
      <div className="flex items-center gap-1.5 text-[0.62rem] uppercase tracking-[0.14em] text-ink-subtle">
        {live && <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-sev-high" />}
        {label}
      </div>
      <div className={`mt-1.5 font-mono text-[1.65rem] font-light leading-none ${tone === "alert" ? "text-sev-high" : "text-ink"}`}>{value}</div>
      <div className="mt-2 text-[0.68rem] text-ink-muted">{note}</div>
    </div>
  );
}

// ---------------------------------------------------------------- horizontal bars

function HBars({ bars, unit }: { bars: { label: string; value: number }[]; unit: string }) {
  if (!bars.length) return <p className="text-[0.8rem] text-ink-subtle">Nothing recorded in this window.</p>;
  const max = Math.max(...bars.map((b) => b.value));
  return (
    <ul className="space-y-2.5">
      {bars.slice(0, 10).map((b) => (
        <li key={b.label}>
          <div className="mb-1 flex items-baseline justify-between gap-3">
            <span className="truncate text-[0.76rem] text-ink-muted">{b.label}</span>
            <span className="shrink-0 font-mono text-[0.72rem] text-ink">{fmt(b.value)}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
            <div className="h-full rounded-full bg-accent/70" style={{ width: `${Math.max(2, (b.value / max) * 100)}%` }} />
          </div>
        </li>
      ))}
      <li className="pt-1 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">{unit}</li>
    </ul>
  );
}

// ---------------------------------------------------------------- timeline

// Sized so the chart panel stands roughly as tall as the violation-class list beside it, rather
// than leaving the grid row to stretch it with dead space.
const W = 720, H = 300, PAD = { l: 40, r: 12, t: 14, b: 26 };
const METRICS = { total: "All records", matched: "Filter matches", blocked: "Blocked" } as const;
type Metric = keyof typeof METRICS;

function Timeline({ stats }: { stats: ArmorStats }) {
  const [metric, setMetric] = useState<Metric>("matched");
  const [hover, setHover] = useState<number | null>(null);

  const data = stats.timeline;
  const values = data.map((d) => d[metric]);
  const rawMax = Math.max(...values, 1);
  const step = 10 ** Math.floor(Math.log10(rawMax));
  const max = Math.max(step, Math.ceil((rawMax * 1.1) / step) * step);
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const x = (i: number) => PAD.l + (data.length === 1 ? iw / 2 : (i / (data.length - 1)) * iw);
  const y = (v: number) => PAD.t + ih - (v / max) * ih;

  const line = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(values.length - 1).toFixed(1)},${PAD.t + ih}L${x(0).toFixed(1)},${PAD.t + ih}Z`;
  const total = values.reduce((a, b) => a + b, 0);
  const h = hover !== null ? data[hover] : null;

  return (
    <section className="glass rise p-5" style={{ animationDelay: "40ms" }}>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="kicker mb-1">{METRICS[metric]}</div>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-xl font-light text-ink">{fmt(total)}</span>
            <span className="text-[0.72rem] text-ink-subtle">over {data.length} days</span>
          </div>
        </div>
        <div className="seg" role="group" aria-label="Metric">
          {(Object.keys(METRICS) as Metric[]).map((m) => (
            <button key={m} type="button" aria-pressed={metric === m} onClick={() => setMetric(m)}>{METRICS[m]}</button>
          ))}
        </div>
      </div>

      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" onPointerLeave={() => setHover(null)}
        onPointerMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const px = ((e.clientX - rect.left) / rect.width) * W;
          setHover(Math.max(0, Math.min(data.length - 1, Math.round(((px - PAD.l) / iw) * (data.length - 1)))));
        }}>
        <defs>
          <linearGradient id="armor-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgb(93,240,168)" stopOpacity="0.28" />
            <stop offset="100%" stopColor="rgb(93,240,168)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <g key={f}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(max * f)} y2={y(max * f)} stroke="rgba(170,190,255,0.08)" strokeWidth="1" />
            <text x={PAD.l - 8} y={y(max * f) + 3} textAnchor="end" className="fill-[#6b7796] font-mono text-[9px]">{Math.round(max * f)}</text>
          </g>
        ))}
        <path d={area} fill="url(#armor-area)" />
        <path d={line} fill="none" stroke="rgb(93,240,168)" strokeWidth="1.6" strokeLinejoin="round" />
        {data.map((d, i) => i % 5 === 0 && (
          <text key={d.date} x={x(i)} y={H - 8} textAnchor="middle" className="fill-[#6b7796] font-mono text-[9px]">
            {d.date.slice(5).replace("-", "/")}
          </text>
        ))}
        {hover !== null && h && (
          <g>
            <line x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={PAD.t + ih} stroke="rgba(93,240,168,0.4)" strokeWidth="1" />
            <circle cx={x(hover)} cy={y(h[metric])} r="3.5" fill="rgb(93,240,168)" />
          </g>
        )}
      </svg>
      <div className="mt-1 h-4 font-mono text-[0.66rem] text-ink-muted">
        {h ? `${h.date} · ${h.total} records · ${h.matched} match(es) · ${h.blocked} blocked` : ""}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- enforcement posture

function PostureTable({ posture }: { posture: Posture[] }) {
  return (
    <section className="glass rise p-5" style={{ animationDelay: "120ms" }}>
      <div className="kicker mb-1">Enforcement posture by application</div>
      <p className="mb-4 text-[0.72rem] text-ink-subtle">
        An application on <code className="font-mono">INSPECT_ONLY</code> records violations without preventing them. That column is the gap.
      </p>
      <div className="-mx-2 overflow-x-auto">
        <table className="w-full min-w-[40rem] border-collapse text-[0.78rem]">
          <thead>
            <tr className="text-left font-mono text-[0.6rem] uppercase tracking-[0.1em] text-ink-subtle">
              <th className="px-2 pb-2 font-medium">Application</th>
              <th className="px-2 pb-2 font-medium">Template</th>
              <th className="px-2 pb-2 text-right font-medium">Records</th>
              <th className="px-2 pb-2 text-right font-medium">Violations</th>
              <th className="px-2 pb-2 text-right font-medium">Not blocked</th>
              <th className="px-2 pb-2 text-right font-medium">Allowlists</th>
            </tr>
          </thead>
          <tbody>
            {posture.map((a) => (
              <tr key={a.id} className="border-t border-white/[0.06]">
                <td className="px-2 py-2.5">
                  <div className="text-ink">{a.name}</div>
                  <div className="font-mono text-[0.62rem] text-ink-subtle">{a.owner} · {a.audience}</div>
                </td>
                <td className="px-2 py-2.5">
                  <code className="font-mono text-[0.68rem] text-ink-muted">{a.template}</code>
                  <div className={`font-mono text-[0.6rem] ${a.enforcement === "INSPECT_ONLY" ? "text-sev-high" : "text-accent"}`}>{a.enforcement}</div>
                </td>
                <td className="px-2 py-2.5 text-right font-mono text-ink-muted">{fmt(a.records)}</td>
                <td className="px-2 py-2.5 text-right font-mono text-ink">{a.violations || "—"}</td>
                <td className={`px-2 py-2.5 text-right font-mono ${a.unblocked ? "text-sev-high" : "text-ink-subtle"}`}>{a.unblocked || "—"}</td>
                <td className="px-2 py-2.5 text-right font-mono text-[0.68rem] text-ink-subtle">{a.mcpAllow} MCP · {a.skillAllow} skills</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- hunt launcher

const GROUPS = ["Agent integrity", "Data protection", "Governance"] as const;

function HuntLauncher({ hunts, activeId, running, hypothesis, setHypothesis, tier, setTier, daysBack, setDaysBack, onLaunch }: {
  hunts: HuntDef[]; activeId?: string; running: boolean;
  hypothesis: string; setHypothesis: (s: string) => void;
  tier: "basic" | "advanced"; setTier: (t: "basic" | "advanced") => void;
  daysBack: number; setDaysBack: (n: number) => void;
  onLaunch: (hunt: HuntDef | null, text?: string) => void;
}) {
  const [custom, setCustom] = useState(false);

  return (
    <section className="glass rise p-4">
      <div className="mb-1 flex items-center justify-between gap-3">
        <div className="kicker">Hunts</div>
        <button type="button" onClick={() => setCustom((c) => !c)} className="font-mono text-[0.64rem] uppercase tracking-wider text-ink-subtle transition-colors hover:text-accent">
          {custom ? "← predefined" : "custom hypothesis →"}
        </button>
      </div>

      {custom ? (
        <form className="mt-3" onSubmit={(e) => { e.preventDefault(); if (hypothesis.trim() && !running) onLaunch(null); }}>
          <label htmlFor="ai-hypothesis" className="mb-2 block text-[0.72rem] text-ink-subtle">
            Describe what you are hunting for in the prompt logs. Wording that names a violation class reaches it through the taxonomy; a principal, destination or infoType is matched literally.
          </label>
          <textarea
            id="ai-hypothesis" value={hypothesis} onChange={(e) => setHypothesis(e.target.value)} maxLength={20000}
            placeholder="e.g. customer records leaving through an agent to a personal email address"
            className="glass-input h-28 w-full resize-none p-3 text-[0.88rem]"
          />
          <button type="submit" disabled={!hypothesis.trim() || running} className="btn btn-primary sheen mt-3 w-full">
            {running ? "Hunting…" : "Run hunt"}
          </button>
        </form>
      ) : (
        <>
          <p className="mb-3 text-[0.72rem] text-ink-subtle">Each hunt is a vetted structured query over the log corpus. Click to run it.</p>
          <div className="space-y-4">
            {GROUPS.map((g) => (
              <div key={g}>
                <div className="mb-1.5 font-mono text-[0.6rem] uppercase tracking-[0.16em] text-ink-subtle">{g}</div>
                <div className="space-y-1.5">
                  {hunts.filter((h) => h.group === g).map((h) => (
                    <button
                      key={h.id} type="button" disabled={running} onClick={() => onLaunch(h)}
                      className={`group w-full rounded-xl border px-3 py-2.5 text-left transition-all disabled:opacity-50 ${
                        activeId === h.id ? "border-accent/40 bg-accent/[0.06]" : "border-white/[0.07] bg-white/[0.015] hover:border-accent/25 hover:bg-white/[0.03]"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-[0.82rem] leading-snug text-ink">{h.title}</span>
                        <span className={`shrink-0 rounded-full border px-1.5 py-0.5 font-mono text-[0.56rem] uppercase tracking-wider ${SEV_CHIP[h.severity]}`}>{h.severity}</span>
                      </div>
                      <p className="mt-1 text-[0.7rem] leading-relaxed text-ink-subtle">{h.blurb}</p>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-white/5 pt-3">
        <div className="seg" role="group" aria-label="Depth">
          <button type="button" aria-pressed={tier === "basic"} onClick={() => setTier("basic")}>Basic</button>
          <button type="button" aria-pressed={tier === "advanced"} onClick={() => setTier("advanced")}>Advanced</button>
        </div>
        <label className="flex items-center gap-2 text-[0.75rem] text-ink-muted">
          Window
          <select value={daysBack} onChange={(e) => setDaysBack(Number(e.target.value))} className="glass-input px-2 py-1 text-[0.75rem]">
            {[1, 7, 14, 30].map((d) => <option key={d} value={d}>{d}d</option>)}
          </select>
        </label>
      </div>
      <p className="mt-2 font-mono text-[0.62rem] leading-relaxed text-ink-subtle">
        {tier === "advanced"
          ? "Logs → Policy → Knowledge → Investigation → OWASP/ATLAS → Challenger → Report → Evidence"
          : "Logs → Policy → Investigation → Report → Evidence"}
      </p>
    </section>
  );
}

// ---------------------------------------------------------------- log explorer

const STATES = { all: "All", violations: "Violations", matched: "Filter match", unblocked: "Not blocked", blocked: "Blocked" } as const;
const CATS = Object.keys(CATEGORY_LABEL) as ViolationCategory[];

function LogExplorer() {
  const [q, setQ] = useState("");
  const [cats, setCats] = useState<ViolationCategory[]>([]);
  const [logState, setLogState] = useState<keyof typeof STATES>("violations");
  const [days, setDays] = useState(30);
  const [page, setPage] = useState(0);
  const [data, setData] = useState<{ logs: Row[]; total: number; page: number; pageSize: number; hasMore: boolean } | null>(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<string | null>(null);

  const params = useMemo(() => {
    const p = new URLSearchParams({ state: logState, days: String(days), page: String(page) });
    if (q.trim()) p.set("q", q.trim());
    if (cats.length) p.set("cats", cats.join(","));
    return p.toString();
  }, [q, cats, logState, days, page]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    const id = setTimeout(() => {
      fetch(`/api/ai-logs?${params}`, { signal: controller.signal })
        .then((r) => r.json())
        .then((d) => { setData(d); setLoading(false); })
        .catch((e) => { if (e.name !== "AbortError") setLoading(false); });
    }, 220);
    return () => { clearTimeout(id); controller.abort(); };
  }, [params]);

  // Any filter change invalidates the current page offset.
  useEffect(() => { setPage(0); }, [q, cats, logState, days]);

  const toggleCat = (c: ViolationCategory) => setCats((xs) => (xs.includes(c) ? xs.filter((x) => x !== c) : [...xs, c]));

  return (
    <section className="glass rise p-5">
      <div className="mb-1 flex flex-wrap items-baseline justify-between gap-3">
        <div className="kicker">Prompt log explorer</div>
        <span className="font-mono text-[0.66rem] text-ink-subtle">
          {loading ? "searching…" : `${fmt(data?.total ?? 0)} record(s) match`}
        </span>
      </div>
      <p className="mb-4 text-[0.72rem] text-ink-subtle">
        Search the raw corpus directly. Bodies that tripped a filter are withheld by log policy; the verdict, the infoType counts and the tool context are retained.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <input
          value={q} onChange={(e) => setQ(e.target.value)} maxLength={200}
          placeholder="principal, app, session, MCP server, destination, infoType…"
          className="glass-input min-w-[16rem] flex-1 px-3 py-1.5 text-[0.8rem]"
        />
        <div className="seg" role="group" aria-label="Record state">
          {(Object.keys(STATES) as (keyof typeof STATES)[]).map((s) => (
            <button key={s} type="button" aria-pressed={logState === s} onClick={() => setLogState(s)}>{STATES[s]}</button>
          ))}
        </div>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="glass-input px-2 py-1.5 text-[0.78rem]">
          {[1, 7, 14, 30].map((d) => <option key={d} value={d}>last {d}d</option>)}
        </select>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {CATS.map((c) => (
          <button
            key={c} type="button" onClick={() => toggleCat(c)}
            className={`rounded-full border px-2.5 py-1 text-[0.68rem] transition-colors ${
              cats.includes(c) ? SEV_CHIP[CATEGORY_SEVERITY[c]] : "border-white/8 text-ink-muted hover:border-accent/30 hover:text-ink"
            }`}
          >
            {CATEGORY_LABEL[c]}
          </button>
        ))}
        {cats.length > 0 && (
          <button type="button" onClick={() => setCats([])} className="rounded-full px-2.5 py-1 font-mono text-[0.62rem] uppercase tracking-wider text-ink-subtle hover:text-accent">clear</button>
        )}
      </div>

      <div className="mt-4 space-y-1.5">
        {!loading && data?.logs.length === 0 && (
          <p className="py-6 text-center text-[0.82rem] text-ink-subtle">No records match these filters.</p>
        )}
        {data?.logs.map((l) => (
          <LogRow key={l.insertId} log={l} open={open === l.insertId} onToggle={() => setOpen(open === l.insertId ? null : l.insertId)} />
        ))}
      </div>

      {data && (data.page > 0 || data.hasMore) && (
        <div className="mt-4 flex items-center justify-between gap-3 border-t border-white/5 pt-3">
          <button type="button" disabled={page === 0} className="btn btn-ghost px-3 py-1 text-[0.72rem]" onClick={() => setPage((n) => Math.max(0, n - 1))}>← Previous</button>
          <span className="font-mono text-[0.64rem] text-ink-subtle">page {page + 1} of {Math.max(1, Math.ceil((data.total || 1) / data.pageSize))}</span>
          <button type="button" disabled={!data.hasMore} className="btn btn-ghost px-3 py-1 text-[0.72rem]" onClick={() => setPage((n) => n + 1)}>Next →</button>
        </div>
      )}
    </section>
  );
}

function LogRow({ log, open, onToggle }: { log: Row; open: boolean; onToggle: () => void }) {
  const bad = log.violations.length > 0;
  const worst = bad ? log.violations.map((c) => CATEGORY_SEVERITY[c]).sort((a, b) => ["Critical", "High", "Medium"].indexOf(a) - ["Critical", "High", "Medium"].indexOf(b))[0] : null;

  return (
    // Rows carry their own opaque fill: the explorer is tall enough to sit over the brightest part
    // of the backdrop, and a dense log table has to stay readable there.
    <div className={`rounded-xl border transition-colors ${open ? "border-accent/25 bg-[rgba(6,14,34,0.9)]" : bad ? "border-sev-high/20 bg-[rgba(4,8,22,0.85)] hover:border-sev-high/40" : "border-white/[0.07] bg-[rgba(4,8,22,0.85)] hover:border-white/20"}`}>
      <button type="button" onClick={onToggle} className="flex w-full items-center gap-3 px-3 py-2 text-left">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${log.blocked ? "bg-accent" : bad ? "bg-sev-high" : "bg-white/20"}`} />
        <span className="shrink-0 font-mono text-[0.68rem] text-ink-subtle">{time(log.timestamp)}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-[0.72rem] text-ink-muted">{log.principal}</span>
        <span className="hidden shrink-0 font-mono text-[0.66rem] text-ink-subtle sm:inline">{log.app}</span>
        {worst && <span className={`shrink-0 rounded-full border px-1.5 py-0.5 font-mono text-[0.54rem] uppercase tracking-wider ${SEV_CHIP[worst]}`}>{worst}</span>}
        <span className={`shrink-0 font-mono text-[0.6rem] uppercase ${log.blocked ? "text-accent" : bad ? "text-sev-high" : "text-ink-subtle"}`}>
          {log.blocked ? "blocked" : bad ? "allowed" : "clean"}
        </span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-white/5 px-3 py-3">
          <p className="rounded-lg bg-black/25 px-3 py-2 text-[0.78rem] leading-relaxed text-ink-muted">{log.content}</p>

          <dl className="grid gap-x-5 gap-y-1 font-mono text-[0.66rem] sm:grid-cols-2">
            <Field k="operation" v={log.operation} />
            <Field k="contentRole" v={log.contentRole} />
            <Field k="template" v={log.template.split("/").pop()!} />
            <Field k="enforcement" v={log.enforcement} tone={log.enforcement === "INSPECT_ONLY" ? "warn" : undefined} />
            <Field k="filterMatchState" v={log.filterMatchState} />
            <Field k="model" v={log.model} />
            <Field k="client" v={log.client} />
            <Field k="session" v={`${log.sessionId} · turn ${log.turn}`} />
            <Field k="source" v={`${log.sourceIp} · ${log.geo}`} />
            <Field k="insertId" v={log.insertId} />
          </dl>

          {log.violations.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {log.violations.map((c) => (
                <span key={c} className={`rounded-full border px-2 py-0.5 text-[0.66rem] ${SEV_CHIP[CATEGORY_SEVERITY[c]]}`}>{CATEGORY_LABEL[c]}</span>
              ))}
            </div>
          )}

          {(log.filters.pi_jailbreak || log.filters.sdp || log.filters.malicious_uris || log.filters.rai) && (
            <div className="rounded-lg border border-white/5 bg-black/20 px-3 py-2">
              <div className="mb-1.5 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">Model Armor findings</div>
              <ul className="space-y-1 font-mono text-[0.68rem] text-ink-muted">
                {log.filters.pi_jailbreak && <li>prompt_injection_and_jailbreak · confidence {log.filters.pi_jailbreak.confidence}</li>}
                {log.filters.sdp?.findings.map((f) => <li key={f.infoType}>sdp · {f.infoType} × {fmt(f.count)} ({f.likelihood})</li>)}
                {log.filters.malicious_uris?.uris.map((u) => <li key={u} className="break-all">malicious_uris · {u}</li>)}
                {log.filters.rai?.categories.map((c) => <li key={c.type}>rai · {c.type} ({c.confidence})</li>)}
              </ul>
            </div>
          )}

          {log.toolCalls?.length ? (
            <div className="rounded-lg border border-white/5 bg-black/20 px-3 py-2">
              <div className="mb-1.5 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">Tool calls</div>
              <ul className="space-y-1.5 font-mono text-[0.68rem]">
                {log.toolCalls.map((t, i) => (
                  <li key={i} className="break-all">
                    <span className="text-glow">{t.kind}:{t.server ? `${t.server}/` : ""}{t.name}</span>
                    {t.destination && <span className="text-ink-muted"> → {t.destination}</span>}
                    {t.bytes != null && <span className="text-ink-subtle"> · {mb(t.bytes)}</span>}
                    <div className="text-ink-subtle">{t.args}</div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

function Field({ k, v, tone }: { k: string; v: string; tone?: "warn" }) {
  return (
    <div className="flex gap-2 overflow-hidden">
      <dt className="shrink-0 text-ink-subtle">{k}</dt>
      <dd className={`truncate ${tone === "warn" ? "text-sev-high" : "text-ink-muted"}`}>{v}</dd>
    </div>
  );
}
