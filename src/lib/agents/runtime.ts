import type { Emit } from "../sse";
import type { Usage } from "../llm";

// Agent runtime: a resilient sequential pipeline. A stage that throws becomes a labelled
// "did not complete" gap and the pipeline continues, instead of the whole run dying.
// Tools go through `callTool`, which dedups identical calls across the whole pipeline and
// turns exceptions into `_unavailable` results (a failed read is a data gap, not evidence of absence).

export type Phase = "Gather" | "Analyze" | "Challenge" | "Report" | "Verify";

export type RunContext = {
  emit: Emit;
  rawPayloads: string[]; // every tool result, for the evidence check
  notes: Record<string, string>; // stage outputs handed to later stages
  gaps: string[];
  state: Record<string, unknown>;
  usage: Usage;
  addUsage: (u: Usage) => void;
};

export type Stage = {
  id: string;
  name: string;
  phase: Phase;
  model?: string; // shown in the UI; "deterministic" stages have none
  run: (ctx: RunContext, stageId: string) => Promise<void>;
};

const toolCache = new WeakMap<RunContext, Map<string, unknown>>();

export async function callTool<T>(
  ctx: RunContext,
  stageId: string,
  name: string,
  args: Record<string, unknown>,
  fn: () => Promise<T> | T,
  summarize: (result: T) => string,
): Promise<T | { _unavailable: true; error: string }> {
  const cache = toolCache.get(ctx) ?? new Map();
  toolCache.set(ctx, cache);
  const key = `${name}:${JSON.stringify(args)}`;
  const callId = `${stageId}-${name}-${cache.size}-${Math.random().toString(36).slice(2, 6)}`;
  ctx.emit({ type: "tool_call", stage: stageId, id: callId, name, args });

  if (cache.has(key)) {
    const cached = cache.get(key) as T;
    ctx.emit({ type: "tool_result", stage: stageId, id: callId, ms: 0, cached: true, summary: summarize(cached) });
    return cached;
  }

  const started = performance.now();
  try {
    const result = await fn();
    cache.set(key, result); // only successes are cached, so retries really re-run
    ctx.rawPayloads.push(JSON.stringify(result));
    ctx.emit({ type: "tool_result", stage: stageId, id: callId, ms: Math.round(performance.now() - started), summary: summarize(result) });
    return result;
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    ctx.gaps.push(`${name}: ${error}`);
    ctx.emit({ type: "tool_result", stage: stageId, id: callId, ms: Math.round(performance.now() - started), unavailable: true, summary: error });
    return { _unavailable: true, error };
  }
}

export async function runPipeline(stages: Stage[], emit: Emit, state: Record<string, unknown> = {}): Promise<RunContext> {
  const ctx: RunContext = {
    emit,
    rawPayloads: [],
    notes: {},
    gaps: [],
    state,
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    addUsage(u) {
      ctx.usage = {
        input: ctx.usage.input + u.input,
        output: ctx.usage.output + u.output,
        cacheRead: ctx.usage.cacheRead + u.cacheRead,
        cacheWrite: ctx.usage.cacheWrite + u.cacheWrite,
      };
      emit({ type: "usage", ...ctx.usage });
    },
  };

  emit({ type: "plan", stages: stages.map(({ id, name, phase, model }) => ({ id, name, phase, model: model ?? "deterministic" })) });

  for (const stage of stages) {
    const started = performance.now();
    emit({ type: "stage_start", id: stage.id });
    try {
      await stage.run(ctx, stage.id);
      emit({ type: "stage_done", id: stage.id, ms: Math.round(performance.now() - started) });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      ctx.gaps.push(`${stage.name} did not complete: ${message}`);
      ctx.notes[stage.id] = `_${stage.name} did not complete (${message}). Treat its output as a data gap._`;
      emit({ type: "agent_failure", id: stage.id, message, ms: Math.round(performance.now() - started) });
    }
  }
  return ctx;
}
