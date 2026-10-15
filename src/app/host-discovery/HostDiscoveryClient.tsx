"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import PageHeader from "@/components/PageHeader";
import type { DiscoveryResult, HostProfile, ResourceType } from "@/lib/secops/discovery";
import type { UdmEvent } from "@/lib/secops/telemetry";

export type TypeOption = { id: ResourceType; label: string; hint: string; placeholder: string; examples: string[] };

const WINDOWS = [{ h: 24, label: "24h" }, { h: 168, label: "7d" }, { h: 720, label: "30d" }] as const;
const GLYPH: Record<ResourceType, string> = { hostname: "HN", ip: "IP", cidr: "/n", domain: "DN", user: "US", mac: "MA", process: "PR" };
const EVENT_LABEL: Record<UdmEvent["type"], string> = { NETWORK_DNS: "DNS", NETWORK_CONNECTION: "Connection", PROCESS_LAUNCH: "Process", USER_LOGIN: "Login" };
const EVENT_TONE: Record<UdmEvent["type"], string> = {
  NETWORK_DNS: "text-sev-low border-sev-low/25",
  NETWORK_CONNECTION: "text-accent border-accent/25",
  PROCESS_LAUNCH: "text-sev-medium border-sev-medium/25",
  USER_LOGIN: "text-ink-muted border-white/15",
};

const fmt = (n: number) => n.toLocaleString("en-US");
const when = (iso: string) => new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });

export default function HostDiscoveryClient({ options, initialType, initialValue }: { options: TypeOption[]; initialType: ResourceType; initialValue: string }) {
  const [type, setType] = useState<ResourceType>(initialType);
  const [value, setValue] = useState(initialValue);
  const [hoursBack, setHoursBack] = useState<number>(168);
  const [result, setResult] = useState<DiscoveryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const opt = options.find((o) => o.id === type)!;

  async function run(t = type, v = value, h = hoursBack) {
    if (!v.trim()) { setError("Enter a value to search for."); inputRef.current?.focus(); return; }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/discovery", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type: t, value: v, hoursBack: h }) });
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? `Search failed (HTTP ${res.status}).`); setResult(null); }
      else setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Search failed.");
    } finally {
      setLoading(false);
    }
  }

  // Deep links (?type=ip&q=…) run immediately.
  const autoRan = useRef(false);
  useEffect(() => {
    if (!autoRan.current && initialValue) { autoRan.current = true; run(initialType, initialValue, 168); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function pickType(t: ResourceType) {
    setType(t);
    setError(null);
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="Security Investigations · Discovery" title="Host Discovery">
        Choose what you&apos;re looking for, give it a value, and Aleph searches the logs for it. Every host it touches is profiled with its
        address, ownership, users and outbound peers, alongside the raw matching events.
      </PageHeader>

      {/* Search menu */}
      <form className="glass rise relative z-20 p-5" onSubmit={(e) => { e.preventDefault(); if (!loading) run(); }}>
        <div className="flex flex-wrap items-end gap-3">
          <div className="w-full sm:w-60">
            <div className="kicker mb-2">Resource type</div>
            <ResourceSelect options={options} value={type} onChange={pickType} />
          </div>
          <div className="min-w-0 flex-1 basis-72">
            <label htmlFor="discovery-value" className="kicker mb-2 block">{opt.label}</label>
            <input
              id="discovery-value"
              ref={inputRef}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={opt.placeholder}
              spellCheck={false}
              autoComplete="off"
              aria-invalid={!!error}
              aria-describedby="discovery-hint"
              className="glass-input h-11 w-full px-3.5 font-mono text-[0.86rem]"
            />
          </div>
          <div>
            <div className="kicker mb-2">Window</div>
            <div className="seg h-11 items-center" role="group" aria-label="Lookback window">
              {WINDOWS.map((w) => (
                <button type="button" key={w.h} aria-pressed={hoursBack === w.h} onClick={() => setHoursBack(w.h)}>{w.label}</button>
              ))}
            </div>
          </div>
          <button type="submit" disabled={loading} className="btn btn-primary sheen h-11 px-6">
            {loading ? <><span className="spin h-3.5 w-3.5 rounded-full border-2 border-accent-ink/30 border-t-accent-ink" />Searching…</> : "Discover"}
          </button>
        </div>
        <div id="discovery-hint" className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
          {error ? (
            <span className="text-[0.74rem] text-sev-critical">{error}</span>
          ) : (
            <span className="text-[0.74rem] text-ink-subtle">{opt.hint}.</span>
          )}
          {opt.examples.length > 0 && <span className="text-[0.62rem] uppercase tracking-[0.14em] text-ink-subtle">Try</span>}
          {opt.examples.map((ex) => (
            <button
              type="button"
              key={ex}
              onClick={() => { setValue(ex); run(type, ex); }}
              className="rounded-full border border-white/8 px-2.5 py-1 font-mono text-[0.68rem] text-ink-muted transition-colors hover:border-accent/30 hover:text-ink"
            >
              {ex}
            </button>
          ))}
        </div>
      </form>

      <div className={`mt-5 transition-opacity duration-200 ${loading ? "opacity-50" : ""}`}>
        {result ? <Results r={result} label={options.find((o) => o.id === result.type)!.label} /> : <Intro options={options} onPick={pickType} />}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- Custom dropdown (listbox)

function ResourceSelect({ options, value, onChange }: { options: TypeOption[]; value: ResourceType; onChange: (t: ResourceType) => void }) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const current = options.find((o) => o.id === value)!;

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (!root.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    list.current?.focus();
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  function openMenu() {
    setActive(options.findIndex((o) => o.id === value));
    setOpen(true);
  }

  function choose(i: number) {
    onChange(options[i].id);
    setOpen(false);
  }

  function onListKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => (a + 1) % options.length); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a - 1 + options.length) % options.length); }
    else if (e.key === "Home") { e.preventDefault(); setActive(0); }
    else if (e.key === "End") { e.preventDefault(); setActive(options.length - 1); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(active); }
    else if (e.key === "Escape" || e.key === "Tab") { setOpen(false); }
  }

  return (
    <div ref={root} className="relative">
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={(e) => { if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); openMenu(); } }}
        className={`glass-input flex h-11 w-full items-center gap-2.5 px-3 text-left ${open ? "border-accent/50" : ""}`}
      >
        <Glyph id={value} />
        <span className="flex-1 truncate text-[0.84rem] text-ink">{current.label}</span>
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden className={`shrink-0 text-ink-subtle transition-transform duration-200 ${open ? "rotate-180" : ""}`}>
          <path d="M2.5 4.5 6 8l3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <ul
          ref={list}
          role="listbox"
          tabIndex={-1}
          aria-label="Resource type"
          aria-activedescendant={`rt-${options[active].id}`}
          onKeyDown={onListKey}
          className="absolute left-0 top-[calc(100%+6px)] z-30 w-[min(22rem,calc(100vw-3rem))] overflow-hidden rounded-xl border border-white/10 bg-[#070c1c]/95 p-1.5 shadow-[0_20px_50px_rgba(0,0,0,0.6)] outline-none backdrop-blur-xl"
        >
          {options.map((o, i) => (
            <li
              key={o.id}
              id={`rt-${o.id}`}
              role="option"
              aria-selected={o.id === value}
              onMouseEnter={() => setActive(i)}
              onClick={() => choose(i)}
              className={`flex cursor-pointer items-center gap-3 rounded-lg px-2.5 py-2 transition-colors ${i === active ? "bg-white/[0.06]" : ""}`}
            >
              <Glyph id={o.id} selected={o.id === value} />
              <div className="min-w-0 flex-1">
                <div className="text-[0.8rem] text-ink">{o.label}</div>
                <div className="truncate text-[0.66rem] text-ink-subtle">{o.hint}</div>
              </div>
              {o.id === value && (
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden className="shrink-0 text-accent">
                  <path d="M2.5 6.2 5 8.5l4.5-5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Glyph({ id, selected }: { id: ResourceType; selected?: boolean }) {
  return (
    <span className={`grid h-6 w-7 shrink-0 place-items-center rounded-md border font-mono text-[0.58rem] tracking-wider ${selected ? "border-accent/35 bg-accent/10 text-accent" : "border-white/10 bg-white/[0.04] text-ink-muted"}`}>
      {GLYPH[id]}
    </span>
  );
}

// ---------------------------------------------------------------- Before the first search

function Intro({ options, onPick }: { options: TypeOption[]; onPick: (t: ResourceType) => void }) {
  return (
    <section className="glass rise p-5" style={{ animationDelay: "80ms" }}>
      <div className="kicker mb-1">What can be discovered</div>
      <p className="mb-4 text-[0.76rem] text-ink-subtle">Each resource type is matched against the fields that carry it in the logs.</p>
      <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
        {options.map((o) => (
          <button
            key={o.id}
            type="button"
            onClick={() => onPick(o.id)}
            className="glass-hover flex items-start gap-3 rounded-xl border border-white/6 bg-white/[0.015] p-3 text-left"
          >
            <Glyph id={o.id} />
            <div className="min-w-0">
              <div className="text-[0.8rem] text-ink">{o.label}</div>
              <div className="mt-0.5 text-[0.68rem] leading-snug text-ink-subtle">{o.hint}</div>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- Results

function Results({ r, label }: { r: DiscoveryResult; label: string }) {
  const [filter, setFilter] = useState<UdmEvent["type"] | "all">("all");
  const span = WINDOWS.find((w) => w.h === r.hoursBack)?.label ?? `${r.hoursBack}h`;

  if (r.matched === 0) {
    return (
      <section className="glass rise p-8 text-center">
        <div className="kicker mb-2">No matches</div>
        <p className="mx-auto max-w-lg text-[0.84rem] text-ink-muted">
          No logs in the last {span} reference {label.toLowerCase()} <span className="font-mono text-ink">{r.normalized}</span>.
          Searched {fmt(r.scanned)} events. Try a wider window, a wildcard, or a CIDR range around it.
        </p>
      </section>
    );
  }

  const events = filter === "all" ? r.events : r.events.filter((e) => e.type === filter);
  const types = Object.entries(r.byType).sort((a, b) => b[1] - a[1]) as [UdmEvent["type"], number][];
  const maxType = Math.max(...types.map(([, n]) => n));

  return (
    <div className="space-y-5">
      {/* Summary */}
      <div className="rise grid grid-cols-2 gap-3 md:grid-cols-4">
        <Tile label="Matched events" value={fmt(r.matched)} note={`of ${fmt(r.scanned)} scanned · last ${span}`} accent />
        <Tile label="Hosts" value={fmt(r.hosts.length)} note={`${r.hosts.filter((h) => h.flags.length).length} with findings`} />
        <Tile label="User accounts" value={fmt(r.users.length)} note={r.users.slice(0, 3).join(", ") + (r.users.length > 3 ? "…" : "")} />
        <Tile label="External peers" value={fmt(r.externalPeers.length)} note={r.externalPeers[0]?.dest ?? "none outside the network"} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_20rem]">
        {/* Host profiles */}
        <section className="glass rise p-5" style={{ animationDelay: "60ms" }}>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <div className="kicker">Discovered hosts</div>
            <span className="rounded-full border border-white/8 bg-white/[0.03] px-2.5 py-1 font-mono text-[0.62rem] text-ink-muted">
              {label}: <span className="text-ink">{r.normalized}</span>
            </span>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {r.hosts.map((h) => <HostCard key={h.host} h={h} />)}
          </div>
        </section>

        {/* Side breakdowns */}
        <div className="space-y-5">
          <section className="glass rise p-5" style={{ animationDelay: "100ms" }}>
            <div className="kicker mb-3">Matched by event type</div>
            <ul className="space-y-2.5">
              {types.map(([t, n]) => (
                <li key={t}>
                  <div className="mb-1 flex justify-between text-[0.74rem]"><span className="text-ink">{EVENT_LABEL[t]}</span><span className="font-mono text-ink-muted">{fmt(n)}</span></div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.04]">
                    <div className="h-full rounded-full" style={{ width: `${Math.max(3, (n / maxType) * 100)}%`, background: "linear-gradient(90deg, rgba(93,240,168,0.45), var(--gl-accent))" }} />
                  </div>
                </li>
              ))}
            </ul>
          </section>
          <section className="glass rise p-5" style={{ animationDelay: "140ms" }}>
            <div className="kicker mb-3">External peers</div>
            {r.externalPeers.length ? (
              <ul className="space-y-1.5">
                {r.externalPeers.map((p) => (
                  <li key={p.dest} className="flex items-center justify-between gap-3">
                    <span className="truncate font-mono text-[0.7rem] text-ink-muted" title={p.dest}>{p.dest}</span>
                    <span className="shrink-0 font-mono text-[0.68rem] text-ink-subtle">{fmt(p.count)}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="text-[0.74rem] text-ink-subtle">No connections leave the internal network.</p>}
          </section>
        </div>
      </div>

      {/* Raw log hits */}
      <section className="glass rise overflow-hidden" style={{ animationDelay: "180ms" }}>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="kicker">Matching log events</span>
            <span className="font-mono text-[0.62rem] text-ink-subtle">{r.truncated ? `newest ${fmt(r.events.length)} of ${fmt(r.matched)}` : `${fmt(r.matched)} events`}</span>
          </div>
          <div className="seg" role="group" aria-label="Event type">
            <button aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All</button>
            {types.map(([t]) => <button key={t} aria-pressed={filter === t} onClick={() => setFilter(t)}>{EVENT_LABEL[t]}</button>)}
          </div>
        </div>
        <div className="max-h-[32rem] overflow-auto">
          <table className="w-full min-w-[54rem] border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-[#080d1f]/95 backdrop-blur">
              <tr className="text-[0.6rem] uppercase tracking-[0.12em] text-ink-subtle">
                <th className="py-2.5 pl-5 pr-3 font-medium">Time</th>
                <th className="px-3 py-2.5 font-medium">Event</th>
                <th className="px-3 py-2.5 font-medium">Host</th>
                <th className="px-3 py-2.5 font-medium">User</th>
                <th className="px-3 py-2.5 font-medium">Source → Destination</th>
                <th className="py-2.5 pl-3 pr-5 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody className="font-mono text-[0.7rem]">
              {events.map((e, i) => (
                <tr key={`${e.ts}-${i}`} className="border-t border-white/[0.04] align-top transition-colors hover:bg-white/[0.025]">
                  <td className="whitespace-nowrap py-2 pl-5 pr-3 text-ink-subtle">{when(e.ts)}</td>
                  <td className="px-3 py-2"><span className={`rounded border px-1.5 py-px text-[0.6rem] ${EVENT_TONE[e.type]}`}>{EVENT_LABEL[e.type]}</span></td>
                  <td className="px-3 py-2 text-ink">{e.host}</td>
                  <td className="px-3 py-2 text-ink-muted">{e.user}</td>
                  <td className="px-3 py-2 text-ink-muted">{e.src_ip}{e.dst_ip && <> <span className="text-ink-subtle">→</span> {e.dst_ip}</>}</td>
                  <td className="max-w-[24rem] py-2 pl-3 pr-5 text-ink-muted">
                    <span className="block truncate" title={e.cmdline ?? e.domain}>
                      {e.type === "PROCESS_LAUNCH" ? e.cmdline : e.type === "USER_LOGIN" ? `login · ${e.country}` : e.domain}
                      {e.bytes !== undefined && <span className="text-ink-subtle"> · {fmt(e.bytes)} B</span>}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Tile({ label, value, note, accent }: { label: string; value: string; note: string; accent?: boolean }) {
  return (
    <div className={`glass px-4 py-3.5 ${accent ? "ring-1 ring-accent/20" : ""}`}>
      <div className="text-[0.62rem] uppercase tracking-[0.14em] text-ink-subtle">{label}</div>
      <div className={`mt-1.5 font-mono text-[1.6rem] font-light leading-none ${accent ? "text-accent" : "text-ink"}`}>{value}</div>
      <div className="mt-2 truncate text-[0.68rem] text-ink-muted" title={note}>{note}</div>
    </div>
  );
}

function HostCard({ h }: { h: HostProfile }) {
  const hot = h.flags.length > 0;
  return (
    <article className={`relative overflow-hidden rounded-xl border p-4 ${hot ? "border-sev-high/25 bg-sev-high/[0.03]" : "border-white/6 bg-white/[0.015]"}`}>
      {hot && <span className="absolute inset-y-3 left-0 w-[3px] rounded-r bg-sev-high" aria-hidden />}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-mono text-[0.9rem] text-ink">{h.host}</div>
          <div className="mt-0.5 text-[0.68rem] text-ink-subtle">{h.os} · {h.department}</div>
        </div>
        <Link href={`/hunt?q=${encodeURIComponent(`Profile host ${h.host} (${h.ip}): review its processes, logins and outbound connections over the last 7 days and flag anything anomalous.`)}`} className="shrink-0 rounded-full border border-accent/25 px-2.5 py-1 text-[0.66rem] text-accent transition-colors hover:bg-accent/10">
          Hunt →
        </Link>
      </div>
      {hot && (
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {h.flags.map((f) => <span key={f} className="rounded-full border border-sev-high/30 bg-sev-high/10 px-2 py-0.5 text-[0.62rem] text-sev-high">{f}</span>)}
        </div>
      )}
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-[0.7rem]">
        <Field k="IP address" v={h.ip} mono />
        <Field k="MAC" v={h.mac} mono />
        <Field k="Primary user" v={h.owner} mono />
        <Field k="Events in window" v={fmt(h.events)} mono />
        <Field k="First seen" v={when(h.firstSeen)} />
        <Field k="Last seen" v={when(h.lastSeen)} />
      </dl>
      <div className="mt-3 border-t border-white/5 pt-2.5">
        <div className="mb-1 text-[0.58rem] uppercase tracking-[0.14em] text-ink-subtle">Users seen · {h.users.length}</div>
        <div className="truncate font-mono text-[0.66rem] text-ink-muted" title={h.users.join(", ")}>{h.users.join(", ")}</div>
      </div>
      {h.topDestinations.length > 0 && (
        <div className="mt-2.5">
          <div className="mb-1 text-[0.58rem] uppercase tracking-[0.14em] text-ink-subtle">Top destinations</div>
          <ul className="space-y-0.5">
            {h.topDestinations.map((d) => (
              <li key={d.dest} className="flex justify-between gap-3 font-mono text-[0.66rem]">
                <span className="truncate text-ink-muted">{d.dest}</span><span className="text-ink-subtle">{d.count}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

function Field({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[0.58rem] uppercase tracking-[0.14em] text-ink-subtle">{k}</dt>
      <dd className={`mt-0.5 truncate text-ink ${mono ? "font-mono" : ""}`} title={v}>{v}</dd>
    </div>
  );
}
