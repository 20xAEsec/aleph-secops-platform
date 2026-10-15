import { config } from "../config";
import { retrieveContexts } from "../rag";
import { searchUdmEvents, sampleForModel, type CoverageStats, type UdmEvent } from "../secops/telemetry";
import { lookupIndicator, lookupCaseHistory } from "../secops/intel";
import { extractIndicators } from "../secops/ioc";
import { evidenceCheck } from "../quality/evidence";
import type { Emit } from "../sse";
import { agentSystem, toolResultsBlock } from "./prompts";
import { callTool, runPipeline, type Stage } from "./runtime";
import { runAgent } from "./llmStage";

export type HuntInput = { hypothesis: string; tier: "basic" | "advanced"; lookbackDays: number };

type HuntState = { events?: UdmEvent[]; stats?: CoverageStats; intel?: unknown[]; kb?: unknown };

export async function runHunt(input: HuntInput, emit: Emit) {
  const { fast, reasoning } = config.models;
  const state: HuntState = {};

  const telemetry: Stage = {
    id: "udm", name: "Telemetry Agent", phase: "Gather",
    async run(ctx, id) {
      const res = await callTool(ctx, id, "search_udm_events",
        { query: input.hypothesis.slice(0, 200), hours_back: input.lookbackDays * 24 },
        () => searchUdmEvents({ query: input.hypothesis, hours_back: input.lookbackDays * 24, indicators: extractIndicators(input.hypothesis) }),
        (r) => `${r.stats.total} events · ${r.stats.beaconCandidates.length} beacon candidate(s) · ${r.stats.rareDomains.length} rare domain(s)`);
      if ("_unavailable" in res) throw new Error(res.error);
      state.events = res.events;
      state.stats = res.stats;
      ctx.emit({ type: "stage_text", stage: id, delta: `Coverage statistics computed over all ${res.stats.total} events; ${Math.min(40, res.stats.total)} representative events forwarded to analysis agents.` });
    },
  };

  const intel: Stage = {
    id: "intel", name: "Intel Collector", phase: "Gather",
    async run(ctx, id) {
      const s = state.stats;
      if (!s) throw new Error("no telemetry to enrich");
      const candidates = [...new Set([
        ...s.beaconCandidates.map((b) => b.dst),
        ...s.rareDomains.map(([d]) => d),
        ...s.highEntropyDomains.map((d) => d.domain),
        ...extractIndicators(input.hypothesis),
      ])].slice(0, 8);
      const out: unknown[] = [];
      for (const ind of candidates) {
        const rec = await callTool(ctx, id, "lookup_indicator", { indicator: ind }, () => lookupIndicator(ind),
          (r) => ("found" in r ? `${ind}: no intel` : `${ind}: score ${r.score} [${r.tags.join(", ")}]`));
        const cases = await callTool(ctx, id, "lookup_case_history", { indicator: ind }, () => lookupCaseHistory(ind),
          (r) => (r.length ? `${r.length} prior case(s): ${r.map((c) => c.closedAs).join(", ")}` : "no prior cases"));
        out.push({ indicator: ind, intel: rec, caseHistory: cases });
      }
      // Re-query the beacon destination on purpose: the dedup cache serves it without a second call.
      if (s.beaconCandidates[0]) {
        const d = s.beaconCandidates[0].dst;
        await callTool(ctx, id, "lookup_indicator", { indicator: d }, () => lookupIndicator(d), () => "served from cross-agent cache");
      }
      state.intel = out;
    },
  };

  const knowledge: Stage = {
    id: "kb", name: "Knowledge Base", phase: "Gather",
    async run(ctx, id) {
      const res = await callTool(ctx, id, "search_knowledge_base", { query: input.hypothesis.slice(0, 200) },
        () => retrieveContexts(input.hypothesis),
        (r) => (r.status === "ok" ? `${r.contexts.length} passage(s) from the knowledge base` : `${r.status}: ${"error" in r ? r.error : ""}`));
      if (!("_unavailable" in res) && res.status !== "ok") ctx.gaps.push(`Knowledge base: ${res.error}`);
      state.kb = res;
    },
  };

  const dataBlock = () => toolResultsBlock({
    search_udm_events: state.stats ? { stats: state.stats, sample_events: sampleForModel(state.events ?? [], state.stats) } : { _unavailable: true },
    intel_and_case_history: state.intel ?? { _unavailable: true },
    knowledge_base: state.kb ?? { _unavailable: true },
  });

  const analysis: Stage = {
    id: "analysis", name: "Investigation Agent", phase: "Analyze", model: fast,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: fast, maxTokens: 1500,
        system: agentSystem("Investigation Agent", "Analyze the hunt data against the hypothesis. Output concise findings as a bullet list, each with severity (Critical/High/Medium/Low), the entities involved, and [Source:] markers. Under 250 words."),
        prompt: `Hypothesis: ${input.hypothesis}\nLookback: ${input.lookbackDays} days\n\n${dataBlock()}`,
        mock: mockFindings(state.stats),
      });
    },
  };

  const mitre: Stage = {
    id: "mitre", name: "MITRE Mapper", phase: "Analyze", model: fast,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: fast, maxTokens: 800,
        system: agentSystem("MITRE ATT&CK Mapper", "Map each finding to ATT&CK technique IDs. Output a compact list: technique ID, name, the finding it maps to. Under 150 words."),
        prompt: `Findings:\n${ctx.notes.analysis ?? "(none)"}`,
        mock: "- **T1071.004** Application Layer Protocol: DNS → periodic lookups of telemetry-sync.net\n- **T1059.001** PowerShell → encoded `-enc` launch on fin-ws-014\n- **T1566.001** Spearphishing Attachment → macro workbook Q3_Vendor_Invoice.xlsm\n- **T1583.001** Acquire Infrastructure: Domains → typosquat cdn-updates-msft.com",
      });
    },
  };

  const challenger: Stage = {
    id: "challenger", name: "Challenger", phase: "Challenge", model: fast,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: fast, maxTokens: 900,
        system: agentSystem("Challenger (devil's advocate)", "You have no tools. Argue the other side: benign explanations, missed pivots, evidence gaps, and any confidence that is inflated. You may only DOWNGRADE confidence, never upgrade. Under 200 words."),
        prompt: `Hypothesis: ${input.hypothesis}\n\nFindings under review:\n${ctx.notes.analysis ?? "(none)"}\n\nMITRE mapping:\n${ctx.notes.mitre ?? "(not run)"}`,
        mock: "- The 300s cadence could be a legitimate telemetry agent; confirm whether `telemetry-sync.net` matches any sanctioned software inventory before escalating.\n- The typosquat was previously closed as **FALSE_POSITIVE** (CASE-42210); the earlier analyst may have had context we lack. Keep at **Medium** until payload content is reviewed.\n- No endpoint process tree was collected for fin-ws-014: the link from the macro workbook to PowerShell to the beacon is inferred from timing only.",
      });
    },
  };

  const report: Stage = {
    id: "report", name: "Report Synthesizer", phase: "Report", model: reasoning,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: reasoning, maxTokens: 3000, toReport: true,
        system: agentSystem("Report Synthesizer", `Write the final threat hunt report in Markdown with these sections:
## Executive Summary
## Key Findings (table: Severity | Finding | Entities | Source)
## Attack Narrative
## MITRE ATT&CK Mapping
## Recommended Actions (P1-P4, each needs a human to execute)
## Data Gaps
Apply every downgrade the Challenger raised. Never upgrade confidence beyond what the evidence supports.`),
        prompt: `Hypothesis: ${input.hypothesis}\nTier: ${input.tier}\n\nInvestigation findings:\n${ctx.notes.analysis ?? "(missing)"}\n\nMITRE mapping:\n${ctx.notes.mitre ?? "(not run at this tier)"}\n\nChallenger review:\n${ctx.notes.challenger ?? "(not run at this tier)"}\n\nKnown data gaps: ${ctx.gaps.join("; ") || "none"}\n\n${dataBlock()}`,
        mock: mockReport(input, state.stats, ctx.gaps),
      });
    },
  };

  const evidence: Stage = {
    id: "evidence", name: "Evidence Check", phase: "Verify",
    async run(ctx) {
      const result = evidenceCheck(ctx.notes.report ?? "", [...ctx.rawPayloads, input.hypothesis]);
      ctx.emit({ type: "evidence", ...result });
    },
  };

  const stages = input.tier === "advanced"
    ? [telemetry, intel, knowledge, analysis, mitre, challenger, report, evidence]
    : [telemetry, knowledge, analysis, report, evidence];

  await runPipeline(stages, emit);
}

// ---------- demo-mode content (used only when no ANTHROPIC_API_KEY is set) ----------

function mockFindings(s?: CoverageStats) {
  if (!s) return "- No telemetry available; cannot assess hypothesis. [Source: search_udm_events: _unavailable]";
  const b = s.beaconCandidates[0];
  return [
    b && `- **High**: ${b.host} contacts **${b.dst}** every ~${b.meanIntervalSec}s with ${b.jitterPct}% jitter across ${b.events} connections, which looks like beaconing. [Source: search_udm_events]`,
    s.suspiciousCommands[0] && `- **High**: Encoded hidden PowerShell on ${s.suspiciousCommands.find((c) => /-enc/.test(c.cmdline))?.host ?? "a finance host"} shortly after a macro-enabled workbook opened. [Source: search_udm_events]`,
    `- **Medium**: Rare domains contacted: ${s.rareDomains.map(([d]) => d).slice(0, 3).join(", ")}. [Source: search_udm_events]`,
    s.foreignLogins[0] && `- **Medium**: Login for ${s.foreignLogins[0].user} from ${s.foreignLogins[0].country} via ${s.foreignLogins[0].host}. [Source: search_udm_events]`,
  ].filter(Boolean).join("\n");
}

function mockReport(input: HuntInput, s: CoverageStats | undefined, gaps: string[]) {
  const b = s?.beaconCandidates[0];
  return `> _Demo data: this report was assembled deterministically from the same tool data the agents saw._

## Executive Summary
The hunt for **"${input.hypothesis.slice(0, 140)}"** found a likely command-and-control beacon on **${b?.host ?? "fin-ws-014"}** to **${b?.dst ?? "telemetry-sync.net"}**. The destination is a newly registered domain linked to a tracked financially-motivated actor. Confidence: **High** for beaconing, **Medium** for initial access via a macro document.

## Key Findings
| Severity | Finding | Entities | Source |
|---|---|---|---|
| High | Periodic outbound connections, ~${b?.meanIntervalSec ?? 300}s cadence, ${b?.jitterPct ?? 2}% jitter | ${b?.host ?? "fin-ws-014"}, ${b?.dst ?? "telemetry-sync.net"}, 185.220.101.47 | search_udm_events, lookup_indicator |
| High | Hidden, encoded PowerShell launched by m.chen | fin-ws-014 | search_udm_events |
| Medium | Two finance hosts contacted typosquat cdn-updates-msft.com | fin-ws-011, fin-ws-022 | search_udm_events, lookup_case_history |
| Medium | svc_backup login from RU | vpn-gw-01, 91.219.236.18 | search_udm_events |

## Attack Narrative
1. \`EXCEL.EXE "Q3_Vendor_Invoice.xlsm"\` opens on fin-ws-014 (macro-enabled).
2. Two minutes later, \`powershell.exe -nop -w hidden -enc …\` runs under the same user.
3. Beaconing to telemetry-sync.net / 185.220.101.47 begins and continues at a fixed ~5-minute interval.

## MITRE ATT&CK Mapping
T1566.001 · T1059.001 · T1071 · T1583.001

## Recommended Actions
- **P1**: Isolate fin-ws-014 and collect a memory image *(requires analyst approval)*.
- **P1**: Block telemetry-sync.net and 185.220.101.47 at egress.
- **P2**: Reopen CASE-42210; the typosquat closure as FP looks premature.
- **P3**: Rotate svc_backup credentials and review VPN geo-policy.

## Data Gaps
${gaps.length ? gaps.map((g) => `- ${g}`).join("\n") : "- None recorded."}
- No endpoint process tree collected; the macro → PowerShell link is inferred from timing.`;
}
