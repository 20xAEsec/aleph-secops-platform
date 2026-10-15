import { config } from "../config";
import { retrieveContexts } from "../rag";
import { searchUdmEvents, type UdmEvent } from "../secops/telemetry";
import { lookupIndicator, lookupCaseHistory } from "../secops/intel";
import { normalizeIoc } from "../secops/ioc";
import { evidenceCheck } from "../quality/evidence";
import type { Emit } from "../sse";
import { agentSystem, toolResultsBlock } from "./prompts";
import { callTool, runPipeline, type Stage } from "./runtime";
import { runAgent } from "./llmStage";

export async function runInvestigation(rawIoc: string, emit: Emit) {
  const { fast } = config.models;
  const ioc = normalizeIoc(rawIoc);
  const gathered: Record<string, unknown> = {};

  const normalize: Stage = {
    id: "normalize", name: "IOC Normalizer", phase: "Gather",
    async run(ctx, id) {
      ctx.emit({ type: "meta", ioc });
      ctx.emit({ type: "stage_text", stage: id, delta: `Classified as **${ioc.type}**${ioc.wasDefanged ? " (refanged from defanged input)" : ""}. Pivot value: \`${ioc.pivot}\`.` });
      if (ioc.type === "unknown") throw new Error("could not classify the indicator");
    },
  };

  const enrich: Stage = {
    id: "enrich", name: "Enrichment Agent", phase: "Gather",
    async run(ctx, id) {
      // Case history and intel in parallel, before anything gets flagged.
      const [intel, cases] = await Promise.all([
        callTool(ctx, id, "lookup_indicator", { indicator: ioc.pivot }, () => lookupIndicator(ioc.pivot),
          (r) => ("found" in r ? "no threat intel match" : `score ${r.score} · ${r.tags.join(", ")}`)),
        callTool(ctx, id, "lookup_case_history", { indicator: ioc.pivot }, () => lookupCaseHistory(ioc.pivot),
          (r) => (r.length ? `${r.length} prior case(s): ${r.map((c) => `${c.caseId} ${c.closedAs}`).join(", ")}` : "no prior SOC cases")),
      ]);
      const udm = await callTool(ctx, id, "search_udm_events", { indicator: ioc.pivot, hours_back: 720 },
        () => {
          const { events } = searchUdmEvents({ query: ioc.pivot, hours_back: 720, indicators: [ioc.pivot] });
          const hits = events.filter((e: UdmEvent) => e.domain === ioc.pivot || e.dst_ip === ioc.pivot || e.src_ip === ioc.pivot);
          return { matched: hits.length, hosts: [...new Set(hits.map((h) => h.host))], first: hits[0]?.ts, last: hits.at(-1)?.ts, sample: hits.slice(0, 15) };
        },
        (r) => `${r.matched} matching event(s) across ${r.hosts.length} host(s)`);
      const kb = await callTool(ctx, id, "search_knowledge_base", { query: ioc.pivot }, () => retrieveContexts(`threat intelligence about ${ioc.pivot}`),
        (r) => (r.status === "ok" ? `${r.contexts.length} passage(s)` : r.status));
      Object.assign(gathered, { lookup_indicator: intel, lookup_case_history: cases, search_udm_events: udm, search_knowledge_base: kb });
    },
  };

  const analyst: Stage = {
    id: "report", name: "IOC Analyst", phase: "Report", model: fast,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: fast, maxTokens: 2200, toReport: true,
        system: agentSystem("IOC Analyst", `Write an indicator investigation report in Markdown:
## Verdict (MALICIOUS / SUSPICIOUS / BENIGN / INCONCLUSIVE, with confidence)
## IOC Details
## Activity in the Environment
## Threat Intelligence
## Prior SOC Decisions
## Recommendations (P1-P4)
## Data Gaps
If prior SOC cases closed this indicator as a false positive, weigh that explicitly.`),
        prompt: `Indicator: ${ioc.value} (type ${ioc.type}, pivot ${ioc.pivot})\n\n${toolResultsBlock(gathered)}`,
        mock: mockReport(ioc.pivot, gathered),
      });
    },
  };

  const evidence: Stage = {
    id: "evidence", name: "Evidence Check", phase: "Verify",
    async run(ctx) {
      ctx.emit({ type: "evidence", ...evidenceCheck(ctx.notes.report ?? "", [...ctx.rawPayloads, ioc.value, ioc.pivot, rawIoc]) });
    },
  };

  await runPipeline([normalize, enrich, analyst, evidence], emit);
}

function mockReport(pivot: string, g: Record<string, unknown>) {
  const intel = g.lookup_indicator as { score?: number; tags?: string[]; actor?: string; found?: false } | undefined;
  const cases = (g.lookup_case_history as { caseId: string; closedAs: string; summary: string }[] | undefined) ?? [];
  const udm = g.search_udm_events as { matched: number; hosts: string[] } | undefined;
  const known = intel && intel.found !== false;
  const verdict = known && (intel.score ?? 0) >= 70 ? "MALICIOUS (High)" : known ? "SUSPICIOUS (Medium)" : udm?.matched ? "INCONCLUSIVE (Low)" : "BENIGN / NO ACTIVITY (Low)";
  return `> _Demo mode: assembled deterministically from tool results. Set \`ANTHROPIC_API_KEY\` for the live analyst._

## Verdict
**${verdict}**

## IOC Details
- Indicator: \`${pivot}\`
- Intel score: ${known ? intel.score : "n/a"} ${known ? `· tags: ${intel.tags?.join(", ")}` : ""} [Source: lookup_indicator]
${known && intel.actor ? `- Associated actor: ${intel.actor}` : ""}

## Activity in the Environment
${udm?.matched ? `${udm.matched} event(s) on ${udm.hosts.join(", ")} in the last 30 days. [Source: search_udm_events]` : "No matching events in the last 30 days. [Source: search_udm_events]"}

## Prior SOC Decisions
${cases.length ? cases.map((c) => `- ${c.caseId}: **${c.closedAs}**. ${c.summary}`).join("\n") : "- No prior cases. [Source: lookup_case_history]"}

## Recommendations
${known ? "- **P1**: Block at egress and hunt for related infrastructure.\n- **P2**: Review the affected hosts' process telemetry." : "- **P4**: Add to the watchlist; no action warranted on current evidence."}

## Data Gaps
- Endpoint telemetry not queried in this tier.`;
}
