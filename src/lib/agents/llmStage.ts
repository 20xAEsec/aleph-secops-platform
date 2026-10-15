import { streamText } from "../llm";
import type { RunContext } from "./runtime";

// Run one LLM-backed agent turn inside a pipeline stage. Intermediate agents stream into their
// own stage panel (`stage_text`); the final report agent streams into the report (`text_delta`).
export async function runAgent(
  ctx: RunContext,
  stageId: string,
  opts: { model: string; system: string; prompt: string; mock: string; maxTokens?: number; toReport?: boolean; mockOnly?: boolean },
): Promise<string> {
  let out = "";
  for await (const delta of streamText({
    model: opts.model,
    system: opts.system,
    messages: [{ role: "user", content: opts.prompt }],
    maxTokens: opts.maxTokens,
    mock: opts.mock,
    forceMock: opts.mockOnly,
    onUsage: ctx.addUsage,
  })) {
    out += delta;
    ctx.emit(opts.toReport ? { type: "text_delta", delta } : { type: "stage_text", stage: stageId, delta });
  }
  ctx.notes[stageId] = out;
  return out;
}
