"use client";

import { useCallback, useRef, useState } from "react";

// Client side of the streaming contract: POST + ReadableStream (not EventSource, which can't
// send a body), parsed into events and reduced into run state. Text deltas are batched to at
// most one render per animation frame regardless of token rate.

export type ToolCall = { id: string; name: string; args: Record<string, unknown>; ms?: number; summary?: string; cached?: boolean; unavailable?: boolean };
export type StageState = {
  id: string; name: string; phase: string; model: string;
  status: "pending" | "running" | "done" | "failed";
  tools: ToolCall[]; text: string; ms?: number; error?: string;
};
export type Evidence = { checked: number; verified: string[]; unverified: string[] };
export type Usage = { input: number; output: number; cacheRead: number; cacheWrite: number };

export type RunState = {
  status: "idle" | "running" | "done" | "error";
  stages: StageState[];
  report: string;
  evidence?: Evidence;
  usage?: Usage;
  meta: Record<string, unknown>;
  error?: string;
  startedAt?: number;
  finishedAt?: number;
};

const initial: RunState = { status: "idle", stages: [], report: "", meta: {} };

type Ev = { type: string; [k: string]: unknown };

export function useRun(endpoint: string) {
  const [state, setState] = useState<RunState>(initial);
  const pending = useRef<{ report: string; stage: Record<string, string> }>({ report: "", stage: {} });
  const rafId = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const flush = useCallback(() => {
    rafId.current = null;
    const { report, stage } = pending.current;
    pending.current = { report: "", stage: {} };
    if (!report && !Object.keys(stage).length) return;
    setState((s) => ({
      ...s,
      report: s.report + report,
      stages: s.stages.map((st) => (stage[st.id] ? { ...st, text: st.text + stage[st.id] } : st)),
    }));
  }, []);

  const schedule = useCallback(() => {
    if (rafId.current == null) rafId.current = requestAnimationFrame(flush);
  }, [flush]);

  const apply = useCallback((e: Ev) => {
    if (e.type === "text_delta") {
      pending.current.report += e.delta as string;
      return schedule();
    }
    if (e.type === "stage_text") {
      const id = e.stage as string;
      pending.current.stage[id] = (pending.current.stage[id] ?? "") + (e.delta as string);
      return schedule();
    }
    flush();
    setState((s) => {
      const patchStage = (id: string, patch: (st: StageState) => StageState) => ({
        ...s, stages: s.stages.map((st) => (st.id === id ? patch(st) : st)),
      });
      switch (e.type) {
        case "plan":
          return { ...s, stages: (e.stages as Omit<StageState, "status" | "tools" | "text">[]).map((st) => ({ ...st, status: "pending", tools: [], text: "" })) };
        case "stage_start":
          return patchStage(e.id as string, (st) => ({ ...st, status: "running" }));
        case "stage_done":
          return patchStage(e.id as string, (st) => ({ ...st, status: "done", ms: e.ms as number }));
        case "agent_failure":
          return patchStage(e.id as string, (st) => ({ ...st, status: "failed", ms: e.ms as number, error: e.message as string }));
        case "tool_call":
          return patchStage(e.stage as string, (st) => ({ ...st, tools: [...st.tools, { id: e.id as string, name: e.name as string, args: e.args as Record<string, unknown> }] }));
        case "tool_result":
          return patchStage(e.stage as string, (st) => ({
            ...st,
            tools: st.tools.map((t) => (t.id === e.id ? { ...t, ms: e.ms as number, summary: e.summary as string, cached: Boolean(e.cached), unavailable: Boolean(e.unavailable) } : t)),
          }));
        case "evidence":
          return { ...s, evidence: { checked: e.checked as number, verified: e.verified as string[], unverified: e.unverified as string[] } };
        case "usage":
          return { ...s, usage: { input: e.input as number, output: e.output as number, cacheRead: e.cacheRead as number, cacheWrite: e.cacheWrite as number } };
        case "meta": {
          const { type: _t, t: _ts, ...rest } = e;
          return { ...s, meta: { ...s.meta, ...rest } };
        }
        case "error":
          return { ...s, error: e.message as string };
        case "done":
          return { ...s, status: s.error ? "error" : "done", finishedAt: Date.now() };
        default:
          return s;
      }
    });
  }, [flush, schedule]);

  const start = useCallback(async (body: unknown) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    pending.current = { report: "", stage: {} };
    setState({ ...initial, status: "running", startedAt: Date.now() });

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        const msg = await res.json().then((j) => j.error).catch(() => res.statusText);
        setState((s) => ({ ...s, status: "error", error: msg || `HTTP ${res.status}` }));
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split("\n\n");
        buffer = frames.pop() ?? "";
        for (const frame of frames) {
          const line = frame.split("\n").find((l) => l.startsWith("data: "));
          if (line) apply(JSON.parse(line.slice(6)));
        }
      }
      // Never auto-retry the POST: that would silently start a second run.
      flush();
      setState((s) => (s.status === "running" ? { ...s, status: "done", finishedAt: Date.now() } : s));
    } catch (err) {
      if ((err as Error).name === "AbortError") return;
      setState((s) => ({ ...s, status: "error", error: (err as Error).message }));
    }
  }, [endpoint, apply, flush]);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(initial);
  }, []);

  return { state, start, reset };
}
