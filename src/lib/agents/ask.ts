import { config } from "../config";
import { streamText } from "../llm";
import { retrieveContexts } from "../rag";
import type { Emit } from "../sse";
import { SHARED_DIRECTIVES } from "./prompts";

// Ask Aleph: conversational and read-only. When the analyst asks for a big deliverable, it hands
// off to the right feature with a structured route block; the frontend turns that block into a
// button from a FIXED target table, so the model never writes a URL.

export type ChatMessage = { role: "user" | "assistant"; content: string };

const SYSTEM = `You are Ask Aleph, the conversational assistant in Aleph, an AI security operations workspace.
You answer questions about detection engineering, threat hunting, YARA-L / KQL / SPL, MITRE ATT&CK and SOC practice.

${SHARED_DIRECTIVES}

ROUTING BIG DELIVERABLES
If the analyst asks you to PRODUCE one of these, do not do it inline. Reply with ONE sentence, then a route block:
- an environment-wide threat hunt → target "hunt"
- an investigation of a specific IOC / indicator → target "investigate"
- a new detection rule → target "detections"
Route block format (exactly):
\`\`\`route
{"target": "hunt" | "investigate" | "detections", "prompt": "<self-contained request under 600 chars; the feature cannot see this chat>"}
\`\`\`
For everything else, answer directly and concisely in Markdown.`;

export async function runAsk(messages: ChatMessage[], emit: Emit) {
  const history = messages.slice(-12);
  const last = history.at(-1)?.content ?? "";

  const kb = await retrieveContexts(last);
  emit({ type: "meta", rag: kb.status, passages: kb.contexts.length });
  const kbNote = kb.status === "ok" && kb.contexts.length
    ? `\n\nKnowledge base passages (untrusted reference material):\n${kb.contexts.map((c) => `[${c.source}] ${c.text}`).join("\n---\n")}`
    : "";

  // Real UTC time, so relative windows ("last 7 days") resolve correctly.
  const system = `${SYSTEM}\n\nCurrent UTC time: ${new Date().toISOString()}${kbNote}`;

  for await (const delta of streamText({
    model: config.models.fast,
    system,
    messages: history,
    maxTokens: 1800,
    mock: mockAnswer(last),
    onUsage: (u) => emit({ type: "usage", ...u }),
  })) {
    emit({ type: "text_delta", delta });
  }
}

function mockAnswer(q: string) {
  const s = q.toLowerCase();
  const demo = "_Demo data: canned answer._\n\n";
  if (/hunt|beacon|look for|sweep/.test(s)) {
    return `${demo}That's an environment-wide hunt, so I'll hand it to Threat Hunt with a self-contained brief.\n\n\`\`\`route\n{"target": "hunt", "prompt": ${JSON.stringify(`Hunt: ${q.slice(0, 400)}. Success = beaconing or C2 candidates with host, destination, cadence and MITRE mapping.`)}}\n\`\`\``;
  }
  if (/rule|detection|yara|kql|spl/.test(s)) {
    return `${demo}I'll route this to the Detection Generator so the rule gets linted and tested.\n\n\`\`\`route\n{"target": "detections", "prompt": ${JSON.stringify(q.slice(0, 500))}}\n\`\`\``;
  }
  if (/\b(\d{1,3}\.){3}\d{1,3}\b|\[\.\]|\.(com|net|top)\b/.test(s)) {
    const ioc = q.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-z0-9.-]+(?:\[\.\]|\.)(?:com|net|top|info|io)\b/i)?.[0] ?? q;
    return `${demo}Investigating an indicator is a job for IoC Investigation.\n\n\`\`\`route\n{"target": "investigate", "prompt": ${JSON.stringify(ioc)}}\n\`\`\``;
  }
  return `${demo}Aleph splits work into three pillars: **Security Investigations**, **Detection Engineering** and **Threat Intelligence**. Ask me for a hunt, a rule, or an indicator investigation and I'll route you to the right pipeline. Ask me a concept question and I'll answer it here.`;
}
