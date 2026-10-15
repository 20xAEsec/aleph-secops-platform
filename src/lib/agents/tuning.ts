import { buildYaraL, bumpVersion, type KnownGood } from "../detections/builder";
import { planIsEmpty, planTuning, type TuningPlan } from "../detections/instructions";
import { getTicket, type JiraTicket } from "../detections/jira";
import { getRule, type RepoRule } from "../detections/repo";
import { lintYaraL } from "../quality/yaral";
import type { Emit } from "../sse";
import { agentSystem } from "./prompts";
import { callTool, runPipeline, type Stage } from "./runtime";
import { runAgent } from "./llmStage";

// Detection tuning: repo rule (+ optional Jira ticket, + optional analyst instructions) → tuned
// rule with a before/after. Baseline exclusions come from the ticket's known-goods; with no
// ticket and no instructions, the agent proposes every profile value holding ≥15% of matches.
// The analyst's chat instructions are applied on top. The tuning turn is a MOCK LLM call.

const MOCK_MODEL = "mock-llm";
const CANDIDATE_SHARE = 0.15;
const TODAY = "2026-10-15";

export type TuningInput = { rulePath: string; ticketKey?: string; instructions?: string[] };

export async function runTuning(input: TuningInput, emit: Emit) {
  const instructions = (input.instructions ?? []).map((s) => s.trim()).filter(Boolean);
  let rule: RepoRule | undefined;
  let ticket: JiraTicket | undefined;
  let plan: TuningPlan | undefined;

  const stages: Stage[] = [];

  if (input.ticketKey) {
    stages.push({
      id: "jira", name: "Jira Intake", phase: "Gather",
      async run(ctx, id) {
        const t = await callTool(ctx, id, "fetch_jira_ticket", { key: input.ticketKey }, () => {
          const found = getTicket(input.ticketKey!);
          if (!found || found.queue !== "tuning") throw new Error(`ticket ${input.ticketKey} not found in the tuning queue`);
          return found;
        }, (t) => `${t.key} · ${t.knownGoods.length} known-good(s) to tune out`);
        if ("_unavailable" in t) throw new Error(t.error);
        ticket = t;
      },
    });
  }

  stages.push({
    id: "load", name: "Rule Loader", phase: "Gather",
    async run(ctx, id) {
      const res = await callTool(ctx, id, "get_rule", { path: input.rulePath }, () => {
        const found = getRule(input.rulePath);
        if (!found) throw new Error(`rule not found: ${input.rulePath}`);
        return found;
      }, (r) => `${r.file} v${r.version} · ${r.text.split("\n").length} lines`);
      if ("_unavailable" in res) throw new Error(res.error);
      rule = res;
    },
  });

  stages.push({
    id: "profile", name: "Match Profiler", phase: "Gather",
    async run(ctx, id) {
      if (!rule) throw new Error("no rule loaded");
      await callTool(ctx, id, "profile_rule_matches", { rule: rule.spec.ruleName, window_days: 7 },
        () => ({ perDay: rule!.perDay, topValues: rule!.noise.map(({ field, value, share }) => ({ field, value, share })) }),
        (p) => `${p.perDay}/day · top value ${Math.round((p.topValues[0]?.share ?? 0) * 100)}% of matches`);
    },
  });

  stages.push({
    id: "tune", name: "Tuning Agent (mock LLM)", phase: "Analyze", model: MOCK_MODEL,
    async run(ctx, id) {
      if (!rule) throw new Error("no rule loaded");
      const baseline: KnownGood[] = ticket
        ? ticket.knownGoods
        : instructions.length ? [] : rule.noise.filter((n) => (n.share ?? 0) >= CANDIDATE_SHARE);
      plan = planTuning(rule, baseline, instructions);

      if (planIsEmpty(plan)) {
        const reply = clarification(rule, instructions, plan);
        await runAgent(ctx, id, { model: MOCK_MODEL, mockOnly: true, toReport: true, system: agentSystem("Detection Tuning Engineer"), prompt: instructions.join("\n"), mock: reply });
        ctx.emit({ type: "meta", chatReply: "I couldn't map that to a change to this rule. See my note for what I can do." });
        return;
      }

      const spec = {
        ...rule.spec,
        severity: plan.severity?.to ?? rule.spec.severity,
        condition: plan.threshold ? rule.spec.condition!.replace(/(#\w+\s*>=\s*)\d+/, `$1${plan.threshold.to}`) : rule.spec.condition,
      };
      const toVersion = bumpVersion(rule.version);
      const after = buildYaraL(spec, plan.exclusions, { version: toVersion, ticket: ticket?.key, lastTuned: TODAY });

      const removedShare = Math.min(0.97, plan.exclusions.reduce((a, k) => a + (k.share ?? 0), 0));
      const thresholdFactor = plan.threshold ? Math.min(1, (plan.threshold.from / plan.threshold.to) ** 1.5) : 1;
      const afterPerDay = Math.max(1, Math.round(rule.perDay * (1 - removedShare) * thresholdFactor));

      await runAgent(ctx, id, {
        model: MOCK_MODEL, mockOnly: true, toReport: true,
        system: agentSystem("Detection Tuning Engineer"),
        prompt: JSON.stringify({ rule: rule.path, ticket: ticket?.key, instructions }),
        mock: tuningRationale(rule, ticket, instructions, plan, afterPerDay),
      });

      ctx.emit({
        type: "meta",
        tuning: {
          path: rule.path, before: rule.text, after, fromVersion: rule.version, toVersion,
          beforePerDay: rule.perDay, afterPerDay,
          exclusions: plan.exclusions.map(({ label, share }) => ({ label, share })),
          blastRadius7d: Math.round(rule.perDay * 7 * (1 - (1 - removedShare) * thresholdFactor)),
        },
        chatReply: `${plan.understood.length ? plan.understood.map((u) => `• ${u.replace(/\*\*/g, "")}`).join("\n") : "Applied the ticket's known-goods."}\n→ ${rule.perDay.toLocaleString()}/day becomes ~${afterPerDay.toLocaleString()}/day (v${toVersion}).${plan.unmapped.length ? `\nCouldn't map: ${plan.unmapped.join(", ")}` : ""}`,
      });
      ctx.notes.after = after;
    },
  });

  stages.push({
    id: "validate", name: "Validator", phase: "Verify",
    async run(ctx, id) {
      if (!rule || !plan) throw new Error("no tuning plan");
      if (!ctx.notes.after) {
        ctx.emit({ type: "stage_text", stage: id, delta: "Nothing to validate: no change was proposed." });
        return;
      }
      const lint = lintYaraL(ctx.notes.after);
      const removed = plan.exclusions.reduce((a, k) => a + (k.share ?? 0), 0);
      await callTool(ctx, id, "estimate_blast_radius", { window_days: 7, exclusions: plan.exclusions.length },
        () => ({ excludedEvents: Math.round(rule!.perDay * 7 * removed), overTuned: removed >= 0.99 }),
        (b) => `${b.excludedEvents.toLocaleString()} detections excluded over 7d${b.excludedEvents > 5000 ? " (above 5,000 warning threshold)" : ""} · ${b.overTuned ? "over-tuned" : "not over-tuned"}`);
      ctx.emit({ type: "meta", lint });
    },
  });

  await runPipeline(stages, emit);
}

function residualRisk(k: KnownGood): string {
  const f = k.field ?? "";
  if (/hostname/.test(f)) return "attacker activity *from these hosts* will no longer alert, so make sure they're covered by host-hardening and EDR alerts";
  if (/process|command_line|registry/.test(f)) return "a malicious binary masquerading at the same path would be missed; pair with a signer or hash check if the rule is promoted";
  if (/ip|carrier/.test(f)) return "logins genuinely originating from this range are now invisible to the rule; review the range quarterly";
  if (/userid/.test(f)) return "compromise of this account will not trigger the rule; it should be on the privileged-account watchlist";
  return "the excluded value is no longer monitored by this rule";
}

function tuningRationale(rule: RepoRule, ticket: JiraTicket | undefined, instructions: string[], plan: TuningPlan, afterPerDay: number): string {
  const pct = (n?: number) => `${Math.round((n ?? 0) * 100)}%`;
  const source = instructions.length
    ? `Following your instructions${ticket ? `, on top of **${ticket.key}**'s known-goods` : ""}.`
    : ticket ? `Working **${ticket.key}** (${ticket.summary}).` : "No instructions or ticket: tuning proposed from the 7-day match profile.";

  return `## Summary
${source} \`${rule.spec.title}\` fires **${rule.perDay.toLocaleString()}/day**. The tuned version should drop to about **${afterPerDay.toLocaleString()}/day**.
${instructions.length ? `
## Your instructions
${instructions.map((i) => `> ${i}`).join("\n>\n")}

## How I applied them
${plan.understood.map((u) => `- ${u}`).join("\n") || "- No changes beyond the ticket's known-goods."}
${plan.unmapped.length ? `\n**Couldn't map:** ${plan.unmapped.join(", ")}. Try naming a source from the match profile, a host, user, \`.exe\`, IP/CIDR, a severity, or a threshold.` : ""}
` : ""}
## Primary activity preserved
${ticket?.primaryActivity ?? rule.spec.description}. The \`events\` logic is unchanged${plan.threshold ? `, apart from the count threshold (${plan.threshold.from} → ${plan.threshold.to})` : ""}.

## Exclusions
${plan.exclusions.length ? plan.exclusions.map((k) => `- **${k.label}**: ${k.label.match(/^(host|user|process|network) /) ? "custom, share estimated" : `${pct(k.share)} of matches`} · \`${k.field ?? "field"}\``).join("\n") : "- None."}
${plan.severity ? `\n## Severity\n${plan.severity.from} → **${plan.severity.to}**, so the risk score changes with it.\n` : ""}
## Residual risk
${plan.exclusions.map((k) => `- *${k.label}*: ${residualRisk(k)}.`).join("\n") || "- No exclusions added."}${plan.threshold ? `\n- A slower beacon (fewer than ${plan.threshold.to} lookups per hour) will no longer trigger.` : ""}

## Next step
Raise the change as a PR against \`${rule.path}\`. Nothing deploys until a detection engineer approves it.`;
}

function clarification(rule: RepoRule, instructions: string[], plan: TuningPlan): string {
  return `## I couldn't turn that into a change
${instructions.length ? `I read: ${instructions.map((i) => `"${i}"`).join(", ")}. None of it mapped to \`${rule.spec.title}\`${plan.unmapped.length ? ` (${plan.unmapped.join(", ")})` : ""}.` : "There was nothing to apply."}

## What I can do for this rule
- Exclude a source from the match profile: ${rule.noise.map((n) => `*${n.label}*`).join(", ")}
- Exclude a specific **host**, **user**, **.exe** or **IP/CIDR** (e.g. "exclude host it-admin-01")
- Change the **severity** (e.g. "set severity to Low")
${/#\w+\s*>=/.test(rule.spec.condition ?? "") ? "- Change the **count threshold** (e.g. \"raise the threshold to 20\")" : ""}`;
}
