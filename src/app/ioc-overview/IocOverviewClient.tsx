"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { IocEntry, IocKind, IocSeverity, TrendPoint, iocStats } from "@/lib/secops/iocInventory";

type Stats = ReturnType<typeof iocStats>;
type Bar = { label: string; value: number; sub?: string };

const SEV_RANK: Record<IocSeverity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SEV_BG: Record<IocSeverity, string> = { Critical: "bg-sev-critical", High: "bg-sev-high", Medium: "bg-sev-medium", Low: "bg-sev-low" };
const SEV_CHIP: Record<IocSeverity, string> = {
  Critical: "border-sev-critical/30 bg-sev-critical/10 text-sev-critical",
  High: "border-sev-high/30 bg-sev-high/10 text-sev-high",
  Medium: "border-sev-medium/30 bg-sev-medium/10 text-sev-medium",
  Low: "border-sev-low/30 bg-sev-low/10 text-sev-low",
};
const KIND_LABEL: Record<IocKind, string> = { ipv4: "IPv4", domain: "Domain", url: "URL", sha256: "SHA-256", md5: "MD5", email: "Email" };
const TLP_STYLE: Record<IocEntry["tlp"], string> = {
  RED: "text-sev-critical border-sev-critical/30",
  AMBER: "text-sev-high border-sev-high/30",
  GREEN: "text-accent border-accent/30",
  CLEAR: "text-ink-muted border-white/15",
};

const fmt = (n: number) => n.toLocaleString("en-US");
const shortDate = (iso: string) => new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
const truncHash = (v: string, k: IocKind) => (k === "sha256" || k === "md5" ? `${v.slice(0, 12)}…${v.slice(-6)}` : v);

export default function IocOverviewClient({ iocs, trend, stats, actors, countries, kinds, asOf }: {
  iocs: IocEntry[]; trend: TrendPoint[]; stats: Stats; actors: Bar[]; countries: Bar[]; kinds: Bar[]; asOf: string;
}) {
  const delta = stats.detections7d - stats.detectionsPrev7d;
  const deltaPct = stats.detectionsPrev7d ? Math.round((delta / stats.detectionsPrev7d) * 100) : 0;

  return (
    <>
      {/* KPI row */}
      <div className="rise mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Indicators" value={fmt(stats.total)} note={`${stats.active} active · ${stats.total - stats.active} other`} />
        <Kpi label="Threat actors" value={fmt(stats.actors)} note={`${stats.countries} origin countries`} />
        <Kpi label="Open detections w/ IoC" value={fmt(stats.openDetections)} note={`${stats.linkedIocs} indicators involved`} tone="accent" live />
        <Kpi label="Detections · 7d" value={fmt(stats.detections7d)} note={`${delta >= 0 ? "▲" : "▼"} ${Math.abs(deltaPct)}% vs prior 7d`} noteTone={delta > 0 ? "up" : "down"} />
        <Kpi label="Detections · 30d" value={fmt(stats.detections30d)} note={`${fmt(stats.alerts30d)} matched alerts`} />
        <Kpi label="Matched alerts · 7d" value={fmt(stats.alerts7d)} note={`${Math.round((stats.alerts7d / stats.alerts30d) * 100)}% of 30-day volume`} />
      </div>

      <div className="mb-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <TrendPanel trend={trend} />
        <section className="glass rise p-5" style={{ animationDelay: "80ms" }}>
          <div className="kicker mb-1">Indicator mix</div>
          <p className="mb-4 text-[0.72rem] text-ink-subtle">Repository indicators by type</p>
          <HBars bars={kinds} unit="indicators" />
        </section>
      </div>

      <div className="mb-5 grid gap-5 lg:grid-cols-2">
        <section className="glass rise p-5" style={{ animationDelay: "120ms" }}>
          <div className="kicker mb-1">Most active threat actors</div>
          <p className="mb-4 text-[0.72rem] text-ink-subtle">IoC matches attributed to each actor · last 30 days</p>
          <HBars bars={actors} unit="matches" />
        </section>
        <section className="glass rise p-5" style={{ animationDelay: "160ms" }}>
          <div className="kicker mb-1">Attributed origin</div>
          <p className="mb-4 text-[0.72rem] text-ink-subtle">Indicators by the assessed country of the attributed actor</p>
          <HBars bars={countries} unit="indicators" />
        </section>
      </div>

      <Inventory iocs={iocs} asOf={asOf} />
    </>
  );
}

// ---------------------------------------------------------------- KPI tile

function Kpi({ label, value, note, tone, noteTone, live }: { label: string; value: string; note: string; tone?: "accent"; noteTone?: "up" | "down"; live?: boolean }) {
  return (
    <div className={`glass px-4 py-3.5 ${tone === "accent" ? "ring-1 ring-accent/20" : ""}`}>
      <div className="flex items-center gap-1.5 text-[0.62rem] uppercase tracking-[0.14em] text-ink-subtle">
        {live && <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-accent" />}
        {label}
      </div>
      <div className={`mt-1.5 font-mono text-[1.65rem] font-light leading-none ${tone === "accent" ? "text-accent" : "text-ink"}`}>{value}</div>
      <div className={`mt-2 text-[0.68rem] ${noteTone === "up" ? "text-sev-high" : noteTone === "down" ? "text-accent" : "text-ink-muted"}`}>{note}</div>
    </div>
  );
}

// ---------------------------------------------------------------- Trend chart

const W = 720;
const H = 230;
const PAD = { l: 38, r: 12, t: 14, b: 26 };

function niceMax(v: number) {
  const step = 10 ** Math.floor(Math.log10(v));
  return Math.ceil(v / step) * step;
}

function TrendPanel({ trend }: { trend: TrendPoint[] }) {
  const [metric, setMetric] = useState<"alerts" | "detections">("alerts");
  const [range, setRange] = useState<14 | 30>(30);
  const [hover, setHover] = useState<number | null>(null);

  const data = trend.slice(-range);
  const values = data.map((d) => d[metric]);
  const max = niceMax(Math.max(...values) * 1.08);
  const iw = W - PAD.l - PAD.r;
  const ih = H - PAD.t - PAD.b;
  const x = (i: number) => PAD.l + (data.length === 1 ? iw / 2 : (i / (data.length - 1)) * iw);
  const y = (v: number) => PAD.t + ih - (v / max) * ih;

  const line = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(values.length - 1).toFixed(1)},${PAD.t + ih}L${x(0).toFixed(1)},${PAD.t + ih}Z`;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(max * f));
  const labelEvery = range === 30 ? 5 : 2;
  const total = values.reduce((a, b) => a + b, 0);
  const peak = values.indexOf(Math.max(...values));
  const h = hover !== null ? data[hover] : null;

  function onMove(e: React.PointerEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = Math.round(((px - PAD.l) / iw) * (data.length - 1));
    setHover(Math.max(0, Math.min(data.length - 1, i)));
  }

  return (
    <section className="glass rise p-5" style={{ animationDelay: "40ms" }}>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="kicker mb-1">{metric === "alerts" ? "IoC-matched alert trend" : "Detections with IoC matches"}</div>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-xl font-light text-ink">{fmt(total)}</span>
            <span className="text-[0.72rem] text-ink-subtle">{metric} · last {range} days</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <div className="seg" role="group" aria-label="Metric">
            <button aria-pressed={metric === "alerts"} onClick={() => setMetric("alerts")}>Alerts</button>
            <button aria-pressed={metric === "detections"} onClick={() => setMetric("detections")}>Detections</button>
          </div>
          <div className="seg" role="group" aria-label="Range">
            <button aria-pressed={range === 14} onClick={() => setRange(14)}>14D</button>
            <button aria-pressed={range === 30} onClick={() => setRange(30)}>30D</button>
          </div>
        </div>
      </div>

      <div className="relative">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="block h-auto w-full touch-none select-none"
          role="img"
          aria-label={`Daily ${metric} over the last ${range} days, total ${total}`}
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
        >
          <defs>
            <linearGradient id="ioc-area" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--gl-accent)" stopOpacity="0.28" />
              <stop offset="100%" stopColor="var(--gl-accent)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} stroke="rgba(170,190,255,0.07)" strokeDasharray={t ? "2 4" : undefined} />
              <text x={PAD.l - 8} y={y(t) + 3} textAnchor="end" className="fill-ink-subtle font-mono" fontSize="9">{t}</text>
            </g>
          ))}
          {data.map((d, i) => (i % labelEvery === (data.length - 1) % labelEvery ? (
            <text key={d.date} x={x(i)} y={H - 8} textAnchor={i === data.length - 1 ? "end" : "middle"} className="fill-ink-subtle font-mono" fontSize="9">{shortDate(d.date)}</text>
          ) : null))}
          <path d={area} fill="url(#ioc-area)" />
          <path d={line} fill="none" stroke="var(--gl-accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" style={{ filter: "drop-shadow(0 0 6px rgba(93,240,168,0.35))" }} />
          {/* Direct label on the peak only */}
          {hover === null && (
            <g>
              <circle cx={x(peak)} cy={y(values[peak])} r="4" fill="var(--gl-accent)" stroke="var(--gl-bg)" strokeWidth="2" />
              <text x={Math.min(x(peak), W - PAD.r - 30)} y={y(values[peak]) - 10} textAnchor="middle" className="fill-ink font-mono" fontSize="10">peak {values[peak]}</text>
            </g>
          )}
          {h && hover !== null && (
            <g pointerEvents="none">
              <line x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={PAD.t + ih} stroke="rgba(170,190,255,0.25)" />
              <circle cx={x(hover)} cy={y(values[hover])} r="4.5" fill="var(--gl-accent)" stroke="var(--gl-bg)" strokeWidth="2" />
            </g>
          )}
        </svg>
        {h && hover !== null && (
          <div
            className="pointer-events-none absolute top-1 z-10 rounded-lg border border-white/10 bg-[#070c1c]/95 px-3 py-2 shadow-xl backdrop-blur"
            style={{ left: `${(x(hover) / W) * 100}%`, transform: `translateX(${hover > data.length / 2 ? "calc(-100% - 12px)" : "12px"})` }}
          >
            <div className="font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">{shortDate(h.date)}</div>
            <div className="mt-1 flex items-center gap-2 text-[0.74rem] text-ink">
              <span className="h-2 w-2 rounded-full bg-accent" />{fmt(h.alerts)} alerts
            </div>
            <div className="text-[0.72rem] text-ink-muted">{fmt(h.detections)} detections</div>
          </div>
        )}
      </div>
      <p className="mt-2 text-[0.68rem] text-ink-subtle">
        The rise over the last six days tracks the FIN-TEMPEST beacon from fin-ws-014 (CS-24816 / CS-24817).
      </p>
    </section>
  );
}

// ---------------------------------------------------------------- Horizontal bars (single series)

function HBars({ bars, unit }: { bars: Bar[]; unit: string }) {
  const max = Math.max(...bars.map((b) => b.value), 1);
  const [hover, setHover] = useState<string | null>(null);
  return (
    <ul className="space-y-2.5">
      {bars.map((b) => (
        <li
          key={b.label}
          className="group"
          onPointerEnter={() => setHover(b.label)}
          onPointerLeave={() => setHover(null)}
          title={`${b.label}: ${fmt(b.value)} ${unit}`}
        >
          <div className="mb-1 flex items-center justify-between gap-3 text-[0.74rem]">
            <span className="flex min-w-0 items-center gap-2 text-ink">
              {b.sub && <CountryCode code={b.sub} />}
              <span className="truncate">{b.label}</span>
            </span>
            <span className={`font-mono text-[0.7rem] ${hover === b.label ? "text-ink" : "text-ink-muted"}`}>{fmt(b.value)}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.04]">
            <div
              className={`h-full rounded-full transition-opacity duration-150 ${hover && hover !== b.label ? "opacity-40" : "opacity-100"}`}
              style={{ width: `${Math.max(2, (b.value / max) * 100)}%`, background: "linear-gradient(90deg, rgba(93,240,168,0.45), var(--gl-accent))" }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

function CountryCode({ code }: { code: string }) {
  return (
    <span className="inline-grid h-[1.15rem] min-w-[1.6rem] shrink-0 place-items-center rounded border border-white/10 bg-white/[0.04] px-1 font-mono text-[0.58rem] tracking-wider text-ink-muted">
      {code}
    </span>
  );
}

// ---------------------------------------------------------------- Sparkline

function Spark({ data }: { data: number[] }) {
  const w = 64, h = 20;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => `${((i / (data.length - 1)) * w).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(" ");
  const flat = data.every((v) => v === 0);
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden className="shrink-0">
      <polyline points={pts} fill="none" stroke={flat ? "rgba(170,190,255,0.2)" : "var(--gl-accent)"} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ---------------------------------------------------------------- Inventory

const FILTERS = { all: "All", open: "Open detections", active: "Active", expired: "Expired" } as const;
type Filter = keyof typeof FILTERS;

function sortIocs(a: IocEntry, b: IocEntry) {
  if (!!a.openDetection !== !!b.openDetection) return a.openDetection ? -1 : 1;
  if (a.openDetection && b.openDetection) {
    const s = SEV_RANK[a.openDetection.severity] - SEV_RANK[b.openDetection.severity];
    if (s) return s;
  }
  return SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.hits30d - a.hits30d;
}

function Inventory({ iocs, asOf }: { iocs: IocEntry[]; asOf: string }) {
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [kind, setKind] = useState<IocKind | "all">("all");
  const [copied, setCopied] = useState<string | null>(null);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return iocs
      .filter((i) => (filter === "all" ? true : filter === "open" ? !!i.openDetection : i.status === filter))
      .filter((i) => (kind === "all" ? true : i.kind === kind))
      .filter((i) => !needle || [i.value, i.actor.name, ...i.actor.aliases, i.actor.countryName, i.technique, i.source, ...i.tags, i.openDetection?.caseId ?? ""]
        .some((s) => s.toLowerCase().includes(needle)))
      .sort(sortIocs);
  }, [iocs, q, filter, kind]);

  const pinned = rows.filter((r) => r.openDetection);
  const rest = rows.filter((r) => !r.openDetection);

  function copy(v: string) {
    navigator.clipboard?.writeText(v).then(() => { setCopied(v); setTimeout(() => setCopied(null), 1400); }).catch(() => {});
  }

  return (
    <section className="glass rise overflow-hidden" style={{ animationDelay: "200ms" }}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 px-4 py-3">
        <div className="flex items-center gap-3">
          <span className="kicker">IoC inventory</span>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/8 bg-white/[0.03] px-2.5 py-1 font-mono text-[0.6rem] uppercase tracking-wider text-ink-muted">
            <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-accent" />
            ThreatQ → SIEM data table · synced {shortDate(asOf)}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search indicator, actor, tag, case…"
            aria-label="Search inventory"
            className="glass-input w-60 px-3 py-1.5 text-[0.78rem]"
          />
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as IocKind | "all")}
            aria-label="Indicator type"
            className="glass-input px-2.5 py-1.5 text-[0.78rem]"
          >
            <option value="all">All types</option>
            {(Object.keys(KIND_LABEL) as IocKind[]).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
          </select>
          <div className="seg" role="group" aria-label="Filter">
            {(Object.keys(FILTERS) as Filter[]).map((f) => (
              <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>{FILTERS[f]}</button>
            ))}
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[66rem] table-fixed border-collapse text-left">
          <colgroup>
            <col className="w-[23%]" /><col className="w-[14%]" /><col className="w-[10%]" /><col className="w-[10%]" />
            <col className="w-[11%]" /><col className="w-[12%]" /><col className="w-[11%]" /><col className="w-[9%]" />
          </colgroup>
          <thead>
            <tr className="border-b border-white/5 text-[0.6rem] uppercase tracking-[0.12em] text-ink-subtle">
              <th className="py-2.5 pl-5 pr-3 font-medium">Indicator</th>
              <th className="px-3 py-2.5 font-medium">Threat actor / APT</th>
              <th className="px-3 py-2.5 font-medium">Origin</th>
              <th className="px-3 py-2.5 font-medium">Severity · Confidence</th>
              <th className="px-3 py-2.5 font-medium">Matches 7d / 30d</th>
              <th className="px-3 py-2.5 font-medium">Technique</th>
              <th className="px-3 py-2.5 font-medium">Source · Seen</th>
              <th className="py-2.5 pl-3 pr-5 text-right font-medium"><span className="sr-only">Action</span></th>
            </tr>
          </thead>
          <tbody>
            {pinned.length > 0 && <GroupRow label="Linked to an open detection" count={pinned.length} accent />}
            {pinned.map((i) => <IocRow key={i.id} ioc={i} copied={copied === i.value} onCopy={copy} />)}
            {rest.length > 0 && <GroupRow label="Repository" count={rest.length} />}
            {rest.map((i) => <IocRow key={i.id} ioc={i} copied={copied === i.value} onCopy={copy} />)}
            {rows.length === 0 && (
              <tr><td colSpan={8} className="px-5 py-12 text-center text-[0.82rem] text-ink-muted">No indicators match these filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function GroupRow({ label, count, accent }: { label: string; count: number; accent?: boolean }) {
  return (
    <tr>
      <td colSpan={8} className={`px-5 pb-1.5 pt-4 text-[0.62rem] font-semibold uppercase tracking-[0.14em] ${accent ? "text-accent" : "text-ink-subtle"}`}>
        {label} <span className="ml-1 font-mono font-normal text-ink-subtle">{count}</span>
      </td>
    </tr>
  );
}

function IocRow({ ioc: i, copied, onCopy }: { ioc: IocEntry; copied: boolean; onCopy: (v: string) => void }) {
  const od = i.openDetection;
  const muted = i.status === "expired";
  return (
    <tr className={`group relative border-b border-white/[0.04] align-top transition-colors hover:bg-white/[0.025] ${od ? "bg-accent/[0.025]" : ""} ${muted ? "opacity-60" : ""}`}>
      <td className="relative py-3 pl-5 pr-3">
        {od && <span className={`absolute inset-y-2 left-0 w-[3px] rounded-r ${SEV_BG[od.severity]}`} aria-hidden />}
        <div className="flex items-center gap-2">
          <span className="shrink-0 rounded border border-white/10 bg-white/[0.04] px-1.5 py-px font-mono text-[0.56rem] uppercase tracking-wider text-ink-muted">{KIND_LABEL[i.kind]}</span>
          <span className="min-w-0 truncate font-mono text-[0.76rem] text-ink" title={i.value}>{truncHash(i.value, i.kind)}</span>
          <button
            onClick={() => onCopy(i.value)}
            className="shrink-0 rounded px-1 font-mono text-[0.6rem] text-ink-subtle opacity-0 transition-opacity hover:text-accent focus-visible:opacity-100 group-hover:opacity-100"
            aria-label={`Copy ${i.value}`}
          >
            {copied ? "copied" : "copy"}
          </button>
        </div>
        {od ? (
          <Link href="/cases" className="mt-1.5 inline-flex max-w-full items-center gap-1.5 rounded-full border border-accent/25 bg-accent/[0.06] px-2 py-0.5 text-[0.64rem] text-accent transition-colors hover:bg-accent/10" title={od.alertName}>
            <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-accent" />
            <span className="font-mono">{od.caseId}</span>
            <span className="truncate text-ink-muted">· {od.status} · {od.host}</span>
          </Link>
        ) : (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {i.tags.slice(0, 3).map((t) => (
              <span key={t} className="rounded-full bg-white/[0.04] px-1.5 py-px font-mono text-[0.56rem] text-ink-subtle">{t}</span>
            ))}
          </div>
        )}
      </td>
      <td className="px-3 py-3">
        <div className="text-[0.78rem] text-ink">{i.actor.name}</div>
        <div className="mt-0.5 truncate text-[0.66rem] text-ink-subtle" title={i.actor.aliases.join(", ")}>{i.actor.aliases.join(" · ")}</div>
        <div className="mt-1 text-[0.6rem] uppercase tracking-wider text-ink-muted">{i.actor.motivation}</div>
      </td>
      <td className="px-3 py-3">
        <div className="flex items-center gap-2">
          <CountryCode code={i.actor.country} />
          <span className="text-[0.74rem] text-ink-muted">{i.actor.countryName}</span>
        </div>
      </td>
      <td className="px-3 py-3">
        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[0.66rem] ${SEV_CHIP[i.severity]}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${SEV_BG[i.severity]}`} />{i.severity}
        </span>
        <div className="mt-2 flex items-center gap-2">
          <div className="h-1 w-16 overflow-hidden rounded-full bg-white/[0.06]">
            <div className="h-full rounded-full bg-ink-muted" style={{ width: `${i.confidence}%` }} />
          </div>
          <span className="font-mono text-[0.62rem] text-ink-muted">{i.confidence}</span>
        </div>
      </td>
      <td className="px-3 py-3">
        <div className="flex items-center gap-3">
          <Spark data={i.spark} />
          <div className="font-mono text-[0.72rem] leading-tight">
            <div className="text-ink">{fmt(i.hits7d)}</div>
            <div className="text-ink-subtle">{fmt(i.hits30d)}</div>
          </div>
        </div>
        <div className="mt-1 text-[0.6rem] text-ink-subtle">{i.rules} rule{i.rules === 1 ? "" : "s"} reference it</div>
      </td>
      <td className="px-3 py-3">
        <div className="font-mono text-[0.66rem] text-ink-muted">{i.technique.split(" ")[0]}</div>
        <div className="text-[0.7rem] leading-snug text-ink-subtle">{i.technique.split(" ").slice(1).join(" ")}</div>
      </td>
      <td className="px-3 py-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[0.72rem] text-ink-muted">{i.source}</span>
          <span className={`rounded border px-1 font-mono text-[0.54rem] tracking-wider ${TLP_STYLE[i.tlp]}`}>TLP:{i.tlp}</span>
        </div>
        <div className="mt-1 font-mono text-[0.62rem] text-ink-subtle">{shortDate(i.firstSeen)} → {shortDate(i.lastSeen)}</div>
        <div className={`mt-0.5 text-[0.6rem] uppercase tracking-wider ${i.status === "active" ? "text-accent" : i.status === "monitoring" ? "text-sev-medium" : "text-ink-subtle"}`}>{i.status}</div>
      </td>
      <td className="py-3 pl-3 pr-5 text-right">
        <Link
          href={`/investigate?q=${encodeURIComponent(i.value)}`}
          className={`btn sheen whitespace-nowrap px-3 py-1.5 text-[0.7rem] ${od ? "btn-primary" : "btn-ghost"}`}
        >
          Investigate
        </Link>
      </td>
    </tr>
  );
}
