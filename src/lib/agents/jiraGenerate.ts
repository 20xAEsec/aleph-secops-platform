import { buildYaraL } from "../detections/builder";
import { getTicket, type JiraTicket } from "../detections/jira";
import { extractLastCodeBlock, lintYaraL } from "../quality/yaral";
import type { Emit } from "../sse";
import { agentSystem } from "./prompts";
import { callTool, runPipeline, type Stage } from "./runtime";
import { runAgent } from "./llmStage";

// Jira intake ticket → drafted YARA-L rule. The rule-author turn is a MOCK LLM call: it streams
// a deterministic response composed from the ticket's own fields (primary activity becomes the
// events section, every known-good becomes an exclusion).

const MOCK_MODEL = "mock-llm";

export async function runJiraGeneration(key: string, emit: Emit) {
  let ticket: JiraTicket | undefined;

  const intake: Stage = {
    id: "jira", name: "Jira Intake", phase: "Gather",
    async run(ctx, id) {
      const t = await callTool(ctx, id, "fetch_jira_ticket", { key }, () => {
        const found = getTicket(key);
        if (!found || found.queue !== "intake") throw new Error(`ticket ${key} not found in the intake queue`);
        return found;
      }, (t) => `${t.key} · ${t.priority} · ${t.knownGoods.length} known-good(s) · ${t.logSource}`);
      if ("_unavailable" in t) throw new Error(t.error);
      ticket = t;
      ctx.emit({ type: "meta", ticket: t.key });
    },
  };

  const fields: Stage = {
    id: "fields", name: "Log Source Check", phase: "Gather",
    async run(ctx, id) {
      if (!ticket?.spec) throw new Error("no ticket loaded");
      const used = [...new Set(ticket.spec.events.join(" ").match(/\$[a-z]+\.[a-z_.]+(?:\["[A-Za-z]+"\])?/g) ?? [])]
        .map((f) => f.replace(/^\$[a-z]+\./, ""));
      await callTool(ctx, id, "check_udm_fields", { log_source: ticket.logSource, fields: used.length },
        () => ({ logSource: ticket!.logSource, populated: used }),
        (r) => `${r.populated.length} UDM field(s) populated for ${r.logSource}`);
    },
  };

  const author: Stage = {
    id: "author", name: "Rule Author (mock LLM)", phase: "Analyze", model: MOCK_MODEL,
    async run(ctx, id) {
      if (!ticket?.spec) throw new Error("no ticket loaded");
      const rule = buildYaraL(ticket.spec, ticket.knownGoods, { status: "experimental", version: "1.0", ticket: ticket.key });
      await runAgent(ctx, id, {
        model: MOCK_MODEL, mockOnly: true, toReport: true, maxTokens: 3000,
        system: agentSystem("YARA-L Detection Engineer"),
        prompt: JSON.stringify(ticket),
        mock: `**${ticket.key}: ${ticket.detectionName}**

${ticket.primaryActivity}

The rule keys on **${ticket.logSource}** and implements that activity in the \`events\` section. Each of the ticket's ${ticket.knownGoods.length} known-good(s) is written as a scoped exclusion, so the noise is removed at the source and not hidden later in triage:
${ticket.knownGoods.map((k) => `- ${k.label}`).join("\n")}

\`\`\`yaral
${rule}
\`\`\`

**Tuning notes**
- Status is \`experimental\` until it has run for 7 days without an unexpected volume spike.
- Severity **${ticket.spec.severity}** maps to risk score per team standard; revisit after the first week of triage outcomes.
- Exclusions are named, so they show up in review. If a known-good stops being benign, delete its line.`,
      });
    },
  };

  const validate: Stage = {
    id: "validate", name: "Validator & Rule Test", phase: "Verify",
    async run(ctx, id) {
      if (!ticket) throw new Error("no ticket loaded");
      const rule = extractLastCodeBlock(ctx.notes.author ?? "");
      if (!rule) throw new Error("no rule code block was produced");
      const lint = lintYaraL(rule);
      const sim = ticket.simulated ?? { raw: 0, afterKnownGoods: 0 };
      await callTool(ctx, id, "run_rule_test", { window_days: 7, mode: "simulated" }, () => sim,
        (s) => `${s.raw} raw match(es) → ${s.afterKnownGoods} after known-good exclusions`);
      const verdict = sim.afterKnownGoods > 1000 ? "FP_STORM" : sim.afterKnownGoods === 0 ? "DEAD" : "OK";
      ctx.emit({ type: "meta", lint, ruleTest: { matches: sim.afterKnownGoods, raw: sim.raw, verdict } });
    },
  };

  await runPipeline([intake, fields, author, validate], emit);
}
