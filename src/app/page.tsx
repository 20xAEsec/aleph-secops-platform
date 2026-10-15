import Link from "next/link";
import { FEATURES, PILLARS } from "@/lib/catalog";
import { rankGaps } from "@/lib/coverage";

// Command Deck. Hero follows GetLayers composition "gring-x-hero" (headline high; bottom band
// splits description + CTAs left, eyebrow + metrics right, scene breathing through the middle).
// Pillars follow "vexon-showcase" (label 4 | statement 8, over an even triptych).

const METRICS = [
  { label: "Agent pipelines", value: "6", note: "live in this demo" },
  { label: "Features mapped", value: String(FEATURES.length), note: "across 3 pillars" },
  { label: "Coverage gaps", value: String(rankGaps().length), note: "ranked by priority" },
  { label: "Writes without a human", value: "0", note: "by construction" },
];

const PILLAR_MOTIF: Record<string, string> = {
  investigations: "M4 40 L18 22 L30 30 L44 10 L58 24",
  detection: "M6 12 H58 M6 24 H44 M6 36 H52 M6 48 H34",
  intel: "M32 6 L56 20 V44 L32 58 L8 44 V20 Z M32 6 V58 M8 20 L56 44 M56 20 L8 44",
};

export default function Home() {
  return (
    <div className="mx-auto max-w-6xl">
      {/* ---------- Hero ---------- */}
      <section className="flex min-h-[calc(100vh-9rem)] flex-col justify-between gap-10 pb-6">
        <div className="rise max-w-3xl pt-4 sm:pt-10">
          <div className="kicker mb-5">AI security operations workspace</div>
          <h1 className="hero-title text-[clamp(2.4rem,6vw,4.6rem)] font-extralight leading-[1.02] tracking-[-0.01em]">
            Ask in plain English.
            <br />
            Get evidence, not eloquence.
          </h1>
        </div>

        {/* open space: the background shows through here */}

        <div className="grid gap-6 lg:grid-cols-12 lg:items-end">
          <div className="rise lg:col-span-6" style={{ animationDelay: "200ms" }}>
            <p className="copy-shadow max-w-lg text-[0.95rem] leading-relaxed text-ink-muted">
              Aleph puts Claude on top of SIEM telemetry, threat intel and the team&apos;s knowledge base. Single-purpose agents gather, correlate
              and draft; a deterministic layer checks their work; an analyst makes every decision.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link href="/hunt" className="btn btn-primary sheen">Start a threat hunt →</Link>
              <Link href="/ask" className="btn btn-ghost sheen">Ask Aleph</Link>
            </div>
          </div>
          <div className="rise lg:col-span-6" style={{ animationDelay: "350ms" }}>
            <div className="mb-3 font-mono text-[0.62rem] uppercase tracking-[0.24em] text-ink-subtle">Workspace at a glance</div>
            <div className="grid grid-cols-2 gap-3">
              {METRICS.map((m) => (
                <div key={m.label} className="glass glass-hero px-4 py-3">
                  <div className="text-[1.7rem] font-extralight text-ink">{m.value}</div>
                  <div className="text-[0.75rem] text-ink-muted">{m.label}</div>
                  <div className="font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">{m.note}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ---------- Pillars ---------- */}
      <section className="py-16">
        <div className="grid gap-6 lg:grid-cols-12">
          <div className="kicker pt-2 lg:col-span-4">/ Three pillars</div>
          <div className="lg:col-span-8">
            <h2 className="text-[clamp(1.6rem,3.4vw,2.6rem)] font-extralight leading-tight text-ink">
              One request fans out across every connected source.
            </h2>
            <p className="copy-shadow mt-4 max-w-xl text-[0.92rem] leading-relaxed text-ink-muted">
              Each pillar is a set of purpose-built pipelines. Live features run end to end in this demo. Spec features document how they
              work in the full platform.
            </p>
          </div>
        </div>

        <div className="mt-12 grid gap-4 md:grid-cols-3">
          {PILLARS.map((p, i) => {
            const features = FEATURES.filter((f) => f.pillar === p.id);
            const first = features.find((f) => f.status === "live") ?? features[0];
            return (
              <Link key={p.id} href={first.href} className="glass glass-hover rise group relative flex min-h-[25rem] flex-col overflow-hidden p-5" style={{ animationDelay: `${i * 80}ms` }}>
                {/* corner brackets */}
                <span className="pointer-events-none absolute left-2 top-2 h-3 w-3 border-l border-t border-accent/40" />
                <span className="pointer-events-none absolute right-2 top-2 h-3 w-3 border-r border-t border-accent/40" />
                <span className="pointer-events-none absolute bottom-2 left-2 h-3 w-3 border-b border-l border-accent/40" />
                <span className="pointer-events-none absolute bottom-2 right-2 h-3 w-3 border-b border-r border-accent/40" />

                <div className="font-mono text-[0.66rem] text-accent">[{p.kicker}]</div>
                <svg viewBox="0 0 64 64" className="mx-auto my-8 h-24 w-24 text-glow opacity-80 transition-opacity group-hover:opacity-100" aria-hidden>
                  <path d={PILLAR_MOTIF[p.id]} fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
                </svg>
                <ul className="mb-6 space-y-1.5">
                  {features.map((f) => (
                    <li key={f.slug} className="flex items-center justify-between text-[0.78rem] text-ink-muted">
                      {f.title}
                      <span className={`font-mono text-[0.56rem] uppercase tracking-wider ${f.status === "live" ? "text-accent" : "text-ink-subtle"}`}>
                        {f.status === "live" ? "● live" : "spec"}
                      </span>
                    </li>
                  ))}
                </ul>
                <div className="mt-auto -mx-5 -mb-5 bg-gradient-to-t from-black/50 to-transparent px-5 pb-5 pt-8">
                  <div className="text-[1.05rem] font-light text-ink">{p.title}</div>
                  <p className="mt-1.5 text-[0.78rem] leading-relaxed text-ink-muted">{p.blurb}</p>
                </div>
              </Link>
            );
          })}
        </div>
      </section>
    </div>
  );
}
