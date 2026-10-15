import { config } from "../config";
import { retrieveContexts } from "../rag";
import { evidenceCheck } from "../quality/evidence";
import {
  APPS, CATEGORY_LABEL, CATEGORY_SEVERITY, TEMPLATES, allLogs, categoriesFromText, classify, isViolation,
  sampleForModel, searchLogs, statsFor, type ArmorStats, type LogQuery, type PromptLog, type ViolationCategory,
} from "../aisec/modelArmor";
import { HUNTS } from "../aisec/hunts";
import { OWASP_MAP } from "../aisec/taxonomy";
import type { Emit } from "../sse";
import { agentSystem, toolResultsBlock } from "./prompts";
import { callTool, runPipeline, type Stage } from "./runtime";
import { runAgent } from "./llmStage";

export type AiHuntInput = { hypothesis: string; huntId?: string; tier: "basic" | "advanced"; daysBack: number };

type State = { logs?: PromptLog[]; stats?: ArmorStats; cats?: ViolationCategory[]; policy?: unknown; kb?: unknown };

export async function runAiHunt(input: AiHuntInput, emit: Emit) {
  const { fast, reasoning } = config.models;
  const state: State = {};
  const preset = input.huntId ? HUNTS.find((h) => h.id === input.huntId) : undefined;

  // A preset carries a vetted structured query. Free text is routed through the taxonomy instead.
  const query: LogQuery = preset
    ? { ...preset.query, daysBack: input.daysBack }
    : { text: input.hypothesis, categories: categoriesFromText(input.hypothesis), violationsOnly: true, daysBack: input.daysBack };

  const search: Stage = {
    id: "logs", name: "Prompt Log Search", phase: "Gather",
    async run(ctx, id) {
      const res = await callTool(ctx, id, "search_model_armor_logs",
        { days_back: input.daysBack, categories: query.categories ?? [], text: query.text ?? null, unblocked_only: query.unblockedOnly ?? false },
        () => {
          const logs = searchLogs(query);
          return { logs, stats: statsFor(logs), corpus: allLogs().length };
        },
        (r) => `${r.logs.length} of ${r.corpus} records match · ${r.stats.matched} filter match(es) · ${r.stats.unblockedViolations} not blocked · ${r.stats.sessions} session(s)`);
      if ("_unavailable" in res) throw new Error(res.error);
      if (res.logs.length === 0) throw new Error("no prompt-log records matched this hunt in the selected window");

      state.logs = res.logs;
      state.stats = res.stats;
      state.cats = [...new Set(res.logs.flatMap(classify))];
      ctx.emit({ type: "stage_text", stage: id, delta: `Aggregates computed over all ${res.logs.length} matching records; ${Math.min(60, res.logs.length)} representative records forwarded to the analysis agents.\n\nViolation classes present: ${state.cats.map((c) => CATEGORY_LABEL[c]).join(", ") || "none"}.` });
    },
  };

  // Which template governed each record, and what the application was actually allowed to do.
  // Deterministic: the model is told the allowlists rather than guessing them.
  const policy: Stage = {
    id: "policy", name: "Policy Context", phase: "Gather",
    async run(ctx, id) {
      const logs = state.logs;
      if (!logs) throw new Error("no records to resolve policy for");
      const apps = [...new Set(logs.map((l) => l.app))];
      const res = await callTool(ctx, id, "get_armor_policy", { apps },
        () => apps.map((a) => {
          const p = APPS[a];
          const t = TEMPLATES[p.template];
          const recs = logs.filter((l) => l.app === a);
          return {
            app: a, name: p.name, owner: p.owner, audience: p.audience, template: p.template,
            enforcement: t.enforcement, filters: { prompt_injection: t.pi, sdp: t.sdp, responsible_ai: t.rai, malicious_uris: t.uris },
            mcp_allowlist: p.mcpAllow, skill_allowlist: p.skillAllow,
            records: recs.length, violations: recs.filter(isViolation).length, unblocked: recs.filter((l) => isViolation(l) && !l.blocked).length,
          };
        }),
        (r) => `${r.length} application(s) · ${r.filter((a) => a.enforcement === "INSPECT_ONLY").length} on INSPECT_ONLY · ${r.reduce((n, a) => n + a.unblocked, 0)} unblocked violation(s)`);
      state.policy = res;
    },
  };

  const knowledge: Stage = {
    id: "kb", name: "Knowledge Base", phase: "Gather",
    async run(ctx, id) {
      const q = preset ? `${preset.title}. ${preset.hypothesis}` : input.hypothesis;
      const res = await callTool(ctx, id, "search_knowledge_base", { query: q.slice(0, 200) },
        () => retrieveContexts(q),
        (r) => (r.status === "ok" ? `${r.contexts.length} passage(s) from the knowledge base` : `${r.status}: ${"error" in r ? r.error : ""}`));
      if (!("_unavailable" in res) && res.status !== "ok") ctx.gaps.push(`Knowledge base: ${res.error}`);
      state.kb = res;
    },
  };

  const dataBlock = () => toolResultsBlock({
    search_model_armor_logs: state.stats
      ? { stats: { ...state.stats, timeline: state.stats.timeline.slice(-14) }, sample_records: sampleForModel(state.logs ?? []) }
      : { _unavailable: true },
    get_armor_policy: state.policy ?? { _unavailable: true },
    knowledge_base: state.kb ?? { _unavailable: true },
  });

  const analysis: Stage = {
    id: "analysis", name: "Investigation Agent", phase: "Analyze", model: fast,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: fast, maxTokens: 1600,
        system: agentSystem("AI Security Investigation Agent", `You analyse GCP Model Armor prompt logs joined with AI gateway context. Output concise findings as a bullet list, each with severity (Critical/High/Medium/Low), the principal and application involved, and [Source:] markers. Under 280 words.

Two rules specific to this data:
- A record's body is often withheld by log policy. The verdict, the infoType counts and the tool/destination context ARE the evidence; do not treat a withheld body as missing evidence.
- A violation that was not blocked has already reached the model provider or the external destination. Say so explicitly, and never describe an unblocked violation as prevented.`),
        prompt: `Hunt: ${preset?.title ?? "Custom hunt"}\nHypothesis: ${input.hypothesis}\nWindow: last ${input.daysBack} days\n\n${dataBlock()}`,
        mock: mockFindings(state.stats, state.cats),
      });
    },
  };

  const mapping: Stage = {
    id: "mapping", name: "OWASP / ATLAS Mapper", phase: "Analyze", model: fast,
    async run(ctx, id) {
      const present = (state.cats ?? []).map((c) => `${CATEGORY_LABEL[c]} → ${OWASP_MAP[c].owasp} · ${OWASP_MAP[c].atlas}`);
      await runAgent(ctx, id, {
        model: fast, maxTokens: 800,
        system: agentSystem("OWASP LLM / MITRE ATLAS Mapper", "Map each finding onto the frameworks. The authoritative mapping for every violation class present is supplied below: use those IDs verbatim and never invent an ID or add a class that is not in the findings. Output a compact list: framework ID, name, the finding it maps to. Under 160 words."),
        prompt: `Findings:\n${ctx.notes.analysis ?? "(none)"}\n\nAuthoritative mapping for the classes present in this hunt:\n${present.join("\n") || "(none)"}`,
        mock: present.map((p) => `- ${p}`).join("\n") || "- No violation classes present to map.",
      });
    },
  };

  const challenger: Stage = {
    id: "challenger", name: "Challenger", phase: "Challenge", model: fast,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: fast, maxTokens: 900,
        system: agentSystem("Challenger (devil's advocate)", `You have no tools. Argue the other side: benign explanations, missed pivots, evidence gaps, and any confidence that is inflated. You may only DOWNGRADE confidence, never upgrade. Under 220 words.

Consider in particular: a filter verdict is a classifier output and can be a false positive; an infoType count is a pattern match, not confirmed regulated data; bulk reads are normal for some roles; a service account acting at 03:00 may simply be a scheduled queue worker; and a withheld body means nobody has actually read what was sent.`),
        prompt: `Hypothesis: ${input.hypothesis}\n\nFindings under review:\n${ctx.notes.analysis ?? "(none)"}\n\nFramework mapping:\n${ctx.notes.mapping ?? "(not run)"}`,
        mock: mockChallenge(state.stats),
      });
    },
  };

  const report: Stage = {
    id: "report", name: "Report Synthesizer", phase: "Report", model: reasoning,
    async run(ctx, id) {
      await runAgent(ctx, id, {
        model: reasoning, maxTokens: 3200, toReport: true,
        system: agentSystem("Report Synthesizer", `Write the final AI security hunt report in Markdown with these sections:
## Executive Summary
## Key Findings (table: Severity | Finding | Principal / App | Blocked? | Source)
## Incident Narrative
## OWASP LLM / MITRE ATLAS Mapping
## Policy and Enforcement Gaps
## Recommended Actions (P1-P4, each needs a human to execute)
## Data Gaps
Apply every downgrade the Challenger raised. Never upgrade confidence beyond what the evidence supports. In the Blocked? column write "No — reached provider/destination" for any unblocked violation.`),
        prompt: `Hunt: ${preset?.title ?? "Custom hunt"}\nHypothesis: ${input.hypothesis}\nTier: ${input.tier}\nWindow: last ${input.daysBack} days\n\nInvestigation findings:\n${ctx.notes.analysis ?? "(missing)"}\n\nFramework mapping:\n${ctx.notes.mapping ?? "(not run at this tier)"}\n\nChallenger review:\n${ctx.notes.challenger ?? "(not run at this tier)"}\n\nKnown data gaps: ${ctx.gaps.join("; ") || "none"}\n\n${dataBlock()}`,
        mock: mockReport(input, preset?.title, state.stats, state.cats, ctx.gaps),
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
    ? [search, policy, knowledge, analysis, mapping, challenger, report, evidence]
    : [search, policy, analysis, report, evidence];

  await runPipeline(stages, emit);
}

// ---------- demo-mode content (used when no ANTHROPIC_API_KEY is set) ----------

const pct = (n: number, d: number) => (d ? Math.round((n / d) * 100) : 0);

function mockFindings(s?: ArmorStats, cats?: ViolationCategory[]) {
  if (!s) return "- No prompt-log records available; cannot assess the hypothesis. [Source: search_model_armor_logs: _unavailable]";
  const top = s.byPrincipal[0];
  const eg = s.egress[0];
  return [
    `- **${s.unblockedViolations ? "Critical" : "High"}**: ${s.violations} violation(s) across ${s.sessions} session(s) and ${s.principals} principal(s), of which ${s.matched} carry a Model Armor filter match; **${s.unblockedViolations} were not blocked** (${pct(s.unblockedViolations, s.violations)}%), so that content reached the provider or destination. [Source: search_model_armor_logs]`,
    top && `- **High**: ${top.label} accounts for ${top.value} matched record(s), the highest of any principal in the window. [Source: search_model_armor_logs]`,
    eg && `- **High**: ${(eg.bytes / 1e6).toFixed(1)} MB sent to **${eg.destination}** over ${eg.calls} call(s), attributed to ${eg.principal}. [Source: search_model_armor_logs]`,
    s.unsanctionedMcp[0] && `- **High**: MCP server **${s.unsanctionedMcp[0].label}** used ${s.unsanctionedMcp[0].value} time(s) and is not in the calling application's allowlist. [Source: get_armor_policy]`,
    s.shadowModels[0] && `- **Medium**: unapproved model **${s.shadowModels[0].label}** seen ${s.shadowModels[0].value} time(s). [Source: get_armor_policy]`,
    s.byInfoType[0] && `- **Medium**: most frequent sensitive type is **${s.byInfoType[0].label}** (${s.byInfoType[0].value} record(s)). [Source: search_model_armor_logs]`,
    cats?.length && `- Violation classes present: ${cats.map((c) => CATEGORY_LABEL[c]).join(", ")}. [Source: search_model_armor_logs]`,
  ].filter(Boolean).join("\n");
}

function mockChallenge(s?: ArmorStats) {
  return [
    "- Model Armor verdicts are classifier outputs. A `MEDIUM_AND_ABOVE` injection verdict on retrieved content can fire on quoted documentation or a support macro; without the withheld body, nobody has confirmed intent.",
    s?.egress[0] && `- The transfer to ${s.egress[0].destination} is sized from tool metadata, not a payload inspection. Confirm the destination is genuinely unsanctioned before treating volume as loss.`,
    s?.offHours ? `- ${s.offHours} record(s) are outside business hours, but a service account working an overnight queue is expected behaviour and is not by itself suspicious.` : null,
    "- infoType counts are pattern matches. A `CREDIT_CARD_NUMBER` hit can be a Luhn-valid test number, and a `PERSON_NAME` count is not evidence of a regulated record.",
    "- Keep anything resting on a single verdict with a withheld body at **Medium** until a reviewer with access to the retained content confirms it.",
  ].filter(Boolean).join("\n");
}

function mockReport(input: AiHuntInput, title: string | undefined, s: ArmorStats | undefined, cats: ViolationCategory[] | undefined, gaps: string[]) {
  if (!s) return "> _Demo mode._\n\n## Executive Summary\nNo prompt-log records matched this hunt in the selected window.";
  const rows = s.byCategoryDetail.slice(0, 7).map((d) => {
    const blocked = d.unblocked === 0 ? "Yes" : d.unblocked === d.records ? "**No — reached provider/destination**" : `Partly — ${d.unblocked} of ${d.records} allowed`;
    return `| ${CATEGORY_SEVERITY[d.category]} | ${d.label} — ${d.records} record(s) | ${d.topPrincipal} · ${d.apps.join(", ")} | ${blocked} | search_model_armor_logs |`;
  }).join("\n");
  const eg = s.egress[0];

  return `> _Demo data: this report was assembled deterministically from the same tool data the agents saw._

## Executive Summary
The hunt **"${title ?? input.hypothesis.slice(0, 120)}"** returned **${s.total} record(s)** over the last ${input.daysBack} days, of which **${s.violations}** are policy violations (**${s.matched}** carry a Model Armor filter match) and **${s.unblockedViolations}** were not blocked. ${s.unblockedViolations ? `Because ${s.unblockedViolations} violation(s) were recorded under an \`INSPECT_ONLY\` template, that content has already reached the model provider or an external destination and cannot be recalled.` : "Enforcement blocked every match in this window."} Confidence: **${s.matched > 4 ? "High" : "Medium"}** on the volumetrics, **Medium** on intent, because matched bodies are withheld by log policy.

## Key Findings
| Severity | Finding | Principal / App | Blocked? | Source |
|---|---|---|---|---|
${rows || "| Medium | No violation classes present | — | — | search_model_armor_logs |"}

## Incident Narrative
${s.byPrincipal[0] ? `${s.byPrincipal[0].label} accounts for the largest share of matched records (${s.byPrincipal[0].value}).` : "No single principal dominates the matched records."} ${eg ? `The largest outbound transfer in the window is ${(eg.bytes / 1e6).toFixed(1)} MB to ${eg.destination} across ${eg.calls} call(s), attributed to ${eg.principal}.` : "No outbound transfer to a non-corporate destination appears in these records."} ${s.unsanctionedMcp[0] ? `An MCP server outside the allowlist (${s.unsanctionedMcp[0].label}) was used ${s.unsanctionedMcp[0].value} time(s).` : ""}

## OWASP LLM / MITRE ATLAS Mapping
${(cats ?? []).map((c) => `- **${OWASP_MAP[c].owasp}** · ${OWASP_MAP[c].atlas} → ${CATEGORY_LABEL[c]}`).join("\n") || "- No violation classes present to map."}

## Policy and Enforcement Gaps
- ${s.unblockedViolations} of ${s.violations} violation(s) were recorded without being blocked (${pct(s.unblockedViolations, s.violations)}%). Applications on \`ma-agent-pilot\` are \`INSPECT_ONLY\` by design; that design is the gap.
- ${s.shadowModels.length} unapproved model(s) and ${s.unsanctionedMcp.length} unsanctioned MCP server(s) appear in this window, neither of which any template governs.

## Recommended Actions
- **P1**: Move \`ma-agent-pilot\` to \`INSPECT_AND_BLOCK\` for the SDP and prompt-injection filters *(requires platform owner approval)*.
- **P1**: Treat every secret in an unblocked record as exposed and rotate it.
${eg ? `- **P1**: Block ${eg.destination} at egress and confirm whether the transfer completed.\n` : ""}- **P2**: Review the MCP and skill allowlists for the affected applications; remove capability that is not needed.
- **P3**: Register or retire the unregistered gateway traffic so a template governs it.

## Data Gaps
${gaps.length ? gaps.map((g) => `- ${g}`).join("\n") : "- None recorded."}
- Matched bodies are withheld by log policy, so intent cannot be confirmed from these records alone.`;
}
