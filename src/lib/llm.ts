import Anthropic from "@anthropic-ai/sdk";
import { config, isLlmLive } from "./config";

// Model layer. One place that talks to Claude. When no API key is configured the app runs in
// demo mode: callers supply a deterministic `mock` string that is streamed back instead, so the
// UI and pipelines behave identically with or without a key.

export type Usage = { input: number; output: number; cacheRead: number; cacheWrite: number };

export type LlmRequest = {
  model: string;
  system: string;
  messages: { role: "user" | "assistant"; content: string }[];
  maxTokens?: number;
  mock: string;
  // Always stream `mock`, even when a key is configured (used by the Jira-driven mock agents).
  forceMock?: boolean;
  onUsage?: (u: Usage) => void;
};

let client: Anthropic | null = null;
function getClient() {
  if (!client) client = new Anthropic({ apiKey: config.anthropicKey });
  return client;
}

export async function* streamText(req: LlmRequest): AsyncGenerator<string> {
  if (req.forceMock || !isLlmLive()) {
    yield* mockStream(req.mock);
    return;
  }

  const stream = getClient().messages.stream({
    model: req.model,
    max_tokens: req.maxTokens ?? 2000,
    // Cache breakpoint on the system prompt: the shared directives are identical across stages.
    system: [{ type: "text", text: req.system, cache_control: { type: "ephemeral" } }],
    messages: req.messages,
  });

  for await (const event of stream) {
    if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
      yield event.delta.text;
    }
  }

  const final = await stream.finalMessage();
  req.onUsage?.({
    input: final.usage.input_tokens,
    output: final.usage.output_tokens,
    cacheRead: final.usage.cache_read_input_tokens ?? 0,
    cacheWrite: final.usage.cache_creation_input_tokens ?? 0,
  });
}

export async function completeText(req: LlmRequest): Promise<string> {
  let out = "";
  for await (const chunk of streamText(req)) out += chunk;
  return out;
}

async function* mockStream(text: string): AsyncGenerator<string> {
  // Word-sized chunks with a small delay so demo mode still "streams".
  const parts = text.match(/\S+\s*|\s+/g) ?? [];
  for (const part of parts) {
    yield part;
    await new Promise((r) => setTimeout(r, 8));
  }
}
