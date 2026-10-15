import Link from "next/link";
import PageHeader from "@/components/PageHeader";
import { TACTICS, rankGaps } from "@/lib/coverage";

function cellStyle(rules: number, dormant: number) {
  if (rules >= 4) return "bg-accent/30 text-ink border-accent/40";
  if (rules >= 2) return "bg-accent/15 text-ink border-accent/25";
  if (rules === 1) return "bg-accent/[0.07] text-ink-muted border-accent/15";
  if (dormant > 0) return "bg-sev-medium/[0.07] text-sev-medium border-sev-medium/25 border-dashed";
  return "bg-sev-critical/[0.06] text-ink-muted border-sev-critical/25";
}

export default function CoveragePage() {
  const gaps = rankGaps();
  const total = TACTICS.flatMap((t) => t.techniques).length;
  const covered = TACTICS.flatMap((t) => t.techniques).filter((t) => t.rules > 0).length;

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="Detection Engineering · Coverage" title="Detection Coverage">
        Active rules mapped onto MITRE ATT&CK. Blind spots are ranked by a transparent formula rather than gut feel, and each gap can be
        drafted into a rule in one click.
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <section className="glass rise overflow-x-auto p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div className="kicker">ATT&CK heatmap</div>
            <div className="font-mono text-[0.66rem] text-ink-muted">{covered}/{total} techniques covered · {Math.round((covered / total) * 100)}%</div>
          </div>
          <div className="grid min-w-[52rem] grid-cols-7 gap-2">
            {TACTICS.map((tactic) => (
              <div key={tactic.id} className="flex flex-col gap-2">
                <div className="min-h-[2.4rem] border-b border-white/8 pb-2">
                  <div className="text-[0.74rem] font-medium text-ink">{tactic.name}</div>
                  <div className="font-mono text-[0.58rem] text-ink-subtle">{tactic.id}</div>
                </div>
                {tactic.techniques.map((t) => (
                  <div key={t.id} className={`rounded-lg border p-2 ${cellStyle(t.rules, t.dormant)}`} title={`${t.rules} active, ${t.dormant} dormant`}>
                    <div className="font-mono text-[0.6rem] opacity-80">{t.id}</div>
                    <div className="text-[0.7rem] leading-tight">{t.name}</div>
                    <div className="mt-1 font-mono text-[0.58rem] opacity-70">{t.rules ? `${t.rules} rule${t.rules > 1 ? "s" : ""}` : t.dormant ? "dormant only" : "no coverage"}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-4 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">
            <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded bg-accent/30" />4+ rules</span>
            <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded bg-accent/[0.07] ring-1 ring-accent/20" />1 rule</span>
            <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded border border-dashed border-sev-medium/50" />dormant</span>
            <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded bg-sev-critical/20" />blind</span>
          </div>
        </section>

        <section className="glass rise p-5" style={{ animationDelay: "120ms" }}>
          <div className="kicker mb-1">Ranked gaps</div>
          <p className="mb-4 font-mono text-[0.62rem] leading-relaxed text-ink-subtle">priority = 0.45·prevalence + 0.35·telemetry fit + 0.20·tactic weakness</p>
          <ol className="space-y-2">
            {gaps.slice(0, 9).map((g) => (
              <li key={g.id} className="flex items-center gap-3 rounded-lg border border-white/5 bg-white/[0.015] px-3 py-2">
                <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-md font-mono text-[0.72rem] ${g.priority >= 8 ? "bg-sev-critical/15 text-sev-critical" : g.priority >= 6 ? "bg-sev-high/15 text-sev-high" : "bg-sev-medium/15 text-sev-medium"}`}>{g.priority}</span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[0.78rem] text-ink">{g.name}</div>
                  <div className="font-mono text-[0.6rem] text-ink-subtle">{g.id} · {g.tactic}</div>
                </div>
                <Link
                  href={`/detections?q=${encodeURIComponent(`Detect ${g.name} (MITRE ${g.id}, tactic ${g.tactic}).`)}`}
                  className="shrink-0 rounded-full border border-accent/25 px-2 py-0.5 text-[0.66rem] text-accent transition-colors hover:bg-accent/10"
                >
                  Draft
                </Link>
              </li>
            ))}
          </ol>
        </section>
      </div>
    </div>
  );
}
