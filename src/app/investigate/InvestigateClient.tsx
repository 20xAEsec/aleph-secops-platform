"use client";

import { useState } from "react";
import PageHeader from "@/components/PageHeader";
import PipelineView from "@/components/PipelineView";
import ReportPanel, { EvidenceCard } from "@/components/ReportPanel";
import { useRun } from "@/lib/useRun";

const EXAMPLES = ["hxxps://telemetry-sync[.]net/api", "185.220.101[.]47", "cdn-updates-msft.com", "github.com"];

type IocMeta = { value: string; type: string; pivot: string; wasDefanged: boolean };

export default function InvestigateClient({ initialIoc }: { initialIoc: string }) {
  const [ioc, setIoc] = useState(initialIoc);
  const { state, start } = useRun("/api/investigate");
  const running = state.status === "running";
  const meta = state.meta.ioc as IocMeta | undefined;

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="Security Investigations · IoC" title="IoC Investigation">
        Paste an IP, domain, URL or hash. Defanged input is fine. Aleph normalizes it, checks intel and prior SOC decisions in parallel,
        searches 30 days of telemetry, and writes a verdict.
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <div className="flex flex-col gap-5">
          <form className="glass rise p-4" onSubmit={(e) => { e.preventDefault(); if (ioc.trim() && !running) start({ ioc }); }}>
            <label htmlFor="ioc" className="kicker mb-2 block">Indicator</label>
            <input id="ioc" className="glass-input w-full px-3 py-2.5 font-mono text-[0.85rem]" placeholder="e.g. 185.220.101[.]47" value={ioc} onChange={(e) => setIoc(e.target.value)} />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex) => (
                <button type="button" key={ex} onClick={() => setIoc(ex)} className="rounded-full border border-white/8 px-2.5 py-1 font-mono text-[0.68rem] text-ink-muted transition-colors hover:border-accent/30 hover:text-ink">{ex}</button>
              ))}
            </div>
            <button type="submit" disabled={!ioc.trim() || running} className="btn btn-primary sheen mt-4 w-full">{running ? "Investigating…" : "Investigate"}</button>
          </form>

          {meta && (
            <section className="glass rise grid grid-cols-2 gap-3 p-4 text-[0.78rem]">
              <div><div className="kicker mb-1">Type</div><div className="font-mono text-ink">{meta.type}</div></div>
              <div><div className="kicker mb-1">Pivot</div><div className="truncate font-mono text-ink">{meta.pivot}</div></div>
              <div className="col-span-2 text-ink-muted">{meta.wasDefanged ? "Input was defanged and has been refanged for search." : "Input used as-is."}</div>
            </section>
          )}

          <PipelineView state={state} />
          <EvidenceCard state={state} />
        </div>

        <ReportPanel state={state} title="Investigation report" empty={<p className="text-[0.85rem] text-ink-subtle">Pick an example. Compare a known-bad indicator with <code className="font-mono">github.com</code>.</p>} />
      </div>
    </div>
  );
}
