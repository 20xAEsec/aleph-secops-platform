"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import Markdown from "@/components/Markdown";
import PageHeader from "@/components/PageHeader";
import { ROUTE_TARGETS } from "@/lib/catalog";

type Msg = { role: "user" | "assistant"; content: string };

const SUGGESTIONS = [
  "What's the difference between beaconing and normal polling traffic?",
  "Hunt for hosts beaconing to newly registered domains this week",
  "Write a YARA-L rule for LSASS memory access",
  "Is 185.220.101[.]47 something I should worry about?",
];

// Split an assistant message into prose and route hand-offs. The button comes from the fixed
// ROUTE_TARGETS table; the model only supplies a key and a prompt.
function parseRoutes(text: string) {
  const routes: { target: string; prompt: string }[] = [];
  const prose = text.replace(/```route\s*([\s\S]*?)```/g, (_, body) => {
    try {
      const r = JSON.parse(body);
      if (ROUTE_TARGETS[r.target] && typeof r.prompt === "string") routes.push({ target: r.target, prompt: r.prompt.slice(0, 1500) });
    } catch { /* incomplete while streaming */ }
    return "";
  }).replace(/```route[\s\S]*$/, "");
  return { prose, routes };
}

export default function AskPage() {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  async function send(text: string) {
    if (!text.trim() || busy) return;
    const next: Msg[] = [...messages, { role: "user", content: text.trim() }];
    setMessages([...next, { role: "assistant", content: "" }]);
    setInput("");
    setBusy(true);
    try {
      const res = await fetch("/api/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ messages: next }) });
      if (!res.ok || !res.body) throw new Error((await res.json().catch(() => ({}))).error ?? `HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split("\n\n");
        buffer = frames.pop() ?? "";
        for (const f of frames) {
          const line = f.split("\n").find((l) => l.startsWith("data: "));
          if (!line) continue;
          const ev = JSON.parse(line.slice(6));
          if (ev.type === "text_delta" || ev.type === "error") {
            const add = ev.type === "error" ? `\n\n_Error: ${ev.message}_` : ev.delta;
            setMessages((m) => [...m.slice(0, -1), { role: "assistant", content: m.at(-1)!.content + add }]);
          }
        }
      }
    } catch (err) {
      setMessages((m) => [...m.slice(0, -1), { role: "assistant", content: `_Error: ${(err as Error).message}_` }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[calc(100vh-8rem)] max-w-4xl flex-col">
      <PageHeader kicker="Ask Aleph" title="Ask Aleph">
        A read-only conversational assistant. Concept questions are answered here. Big deliverables (a hunt, a rule, an indicator
        investigation) are handed to the right pipeline with a self-contained brief.
      </PageHeader>

      <div className="flex-1 space-y-4 pb-4">
        {messages.length === 0 && (
          <div className="grid gap-2 sm:grid-cols-2">
            {SUGGESTIONS.map((s, i) => (
              <button key={s} onClick={() => send(s)} className="glass glass-hover rise p-4 text-left text-[0.82rem] text-ink-muted" style={{ animationDelay: `${i * 60}ms` }}>{s}</button>
            ))}
          </div>
        )}
        {messages.map((m, i) => {
          if (m.role === "user") {
            return (
              <div key={i} className="flex justify-end">
                <div className="max-w-[80%] rounded-2xl rounded-br-md border border-accent/20 bg-accent/[0.07] px-4 py-2.5 text-[0.88rem] text-ink">{m.content}</div>
              </div>
            );
          }
          const { prose, routes } = parseRoutes(m.content);
          const streaming = busy && i === messages.length - 1;
          return (
            <div key={i} className="glass max-w-[92%] px-5 py-4">
              {prose.trim() ? <Markdown text={prose} streaming={streaming} /> : streaming && <span className="spin inline-block h-4 w-4 rounded-full border-2 border-accent/20 border-t-accent" />}
              {routes.map((r, j) => (
                <div key={j} className="mt-3 rounded-xl border border-accent/20 bg-accent/[0.04] p-3">
                  <div className="mb-2 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">Hand-off brief</div>
                  <p className="mb-3 text-[0.78rem] text-ink-muted">{r.prompt}</p>
                  <Link href={ROUTE_TARGETS[r.target].href(r.prompt)} className="btn btn-primary sheen px-4 py-1.5 text-[0.78rem]">{ROUTE_TARGETS[r.target].label} →</Link>
                </div>
              ))}
            </div>
          );
        })}
        <div ref={endRef} />
      </div>

      <form className="glass sticky bottom-4 flex items-end gap-2 p-2" onSubmit={(e) => { e.preventDefault(); send(input); }}>
        <textarea
          rows={1}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }}
          placeholder="Ask about detections, hunts, ATT&CK…"
          className="max-h-40 min-h-[2.6rem] flex-1 resize-none bg-transparent px-3 py-2.5 text-[0.88rem] text-ink placeholder:text-ink-subtle focus:outline-none"
        />
        <button type="submit" disabled={!input.trim() || busy} className="btn btn-primary px-4">Send</button>
      </form>
    </div>
  );
}
