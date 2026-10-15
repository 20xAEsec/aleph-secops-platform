"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import DiffView from "@/components/DiffView";
import PageHeader from "@/components/PageHeader";
import PipelineView from "@/components/PipelineView";
import ReportPanel from "@/components/ReportPanel";
import { TicketCard, TicketList, useJiraQueue } from "@/components/Jira";
import type { JiraTicket } from "@/lib/detections/jira";
import type { KnownGood } from "@/lib/detections/builder";
import { useRun } from "@/lib/useRun";

type TreeRule = { path: string; file: string; title: string; severity: string; perDay: number; version: string };
type Tree = { folder: string; rules: TreeRule[] }[];
type RuleDetail = TreeRule & { dataSource: string; technique: string; text: string; noise: KnownGood[]; suggestions: string[] };
type ChatMsg = { role: "user" | "agent"; text: string };
type TuningResult = {
  path: string; before: string; after: string; fromVersion: string; toVersion: string;
  beforePerDay: number; afterPerDay: number; blastRadius7d: number; exclusions: { label: string; share?: number }[];
};

const volumeColor = (perDay: number) => (perDay >= 500 ? "bg-sev-critical" : perDay >= 100 ? "bg-sev-high" : "bg-accent");

function Chevron({ open }: { open: boolean }) {
  return <span className={`inline-block w-3 text-[0.6rem] text-ink-subtle transition-transform ${open ? "rotate-90" : ""}`}>▶</span>;
}

function RuleTree({ tree, selected, ticketByPath, onSelect }: {
  tree: Tree | null; selected?: string; ticketByPath: Record<string, string>; onSelect: (path: string) => void;
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  // Expand the folder that holds the selected rule (e.g. after picking a Jira ticket).
  useEffect(() => {
    if (selected) setOpen((o) => ({ ...o, [selected.split("/")[1]]: true }));
  }, [selected]);

  return (
    <section className="glass rise p-3">
      <div className="mb-2 flex items-center justify-between px-1">
        <div className="kicker">Rules repo</div>
        <span className="font-mono text-[0.58rem] text-ink-subtle">detection-rules/main</span>
      </div>
      {!tree && <p className="px-1 text-[0.75rem] text-ink-subtle">Loading repository…</p>}
      <div className="font-mono text-[0.72rem]">
        <div className="px-1 py-1 text-ink-subtle">▾ rules/</div>
        {tree?.map(({ folder, rules }) => (
          <div key={folder} className="ml-2">
            <button
              onClick={() => setOpen((o) => ({ ...o, [folder]: !o[folder] }))}
              aria-expanded={!!open[folder]}
              className="flex w-full items-center gap-1.5 rounded-md px-1.5 py-1 text-left text-ink-muted transition-colors hover:bg-white/[0.03] hover:text-ink"
            >
              <Chevron open={!!open[folder]} />
              <span className="text-sev-medium/80">▣</span>
              {folder}/
              <span className="ml-auto text-[0.6rem] text-ink-subtle">{rules.length}</span>
            </button>
            {open[folder] && (
              <ul className="ml-4 border-l border-white/6 pl-2">
                {rules.map((r) => {
                  const active = r.path === selected;
                  return (
                    <li key={r.path}>
                      <button
                        onClick={() => onSelect(r.path)}
                        aria-current={active ? "true" : undefined}
                        title={`${r.title} · ${r.perDay}/day`}
                        className={`flex w-full items-center gap-1.5 rounded-md px-1.5 py-1 text-left transition-colors ${
                          active ? "bg-accent/10 text-accent" : "text-ink-muted hover:bg-white/[0.03] hover:text-ink"
                        }`}
                      >
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${volumeColor(r.perDay)}`} />
                        <span className="truncate">{r.file}</span>
                        {ticketByPath[r.path] && <span className="ml-auto shrink-0 rounded bg-glow/15 px-1 text-[0.54rem] text-glow">{ticketByPath[r.path]}</span>}
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        ))}
      </div>
      <div className="mt-3 flex gap-3 border-t border-white/5 px-1 pt-2 font-mono text-[0.56rem] uppercase tracking-wider text-ink-subtle">
        <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-sev-critical" />500+/day</span>
        <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-sev-high" />100+</span>
        <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-accent" />quiet</span>
      </div>
    </section>
  );
}

function MatchProfile({ rule }: { rule: RuleDetail }) {
  const other = Math.max(0, 1 - rule.noise.reduce((a, n) => a + (n.share ?? 0), 0));
  const rows = [...rule.noise.map((n) => ({ label: n.label, share: n.share ?? 0, field: n.field, candidate: (n.share ?? 0) >= 0.15 })), { label: "Everything else", share: other, field: undefined, candidate: false }];
  return (
    <section className="glass rise p-5">
      <div className="kicker mb-1">Match profile · last 7 days</div>
      <p className="mb-4 font-mono text-[0.62rem] text-ink-subtle">{rule.perDay.toLocaleString()} detections/day · values ≥15% are tuning candidates</p>
      <ul className="space-y-3">
        {rows.map((r) => (
          <li key={r.label}>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-[0.76rem]">
              <span className={r.candidate ? "text-ink" : "text-ink-muted"}>{r.label}</span>
              <span className="shrink-0 font-mono text-[0.66rem] text-ink-subtle">{Math.round(r.share * 100)}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-white/5">
              <div className={`h-full rounded-full ${r.candidate ? "bg-sev-high/70" : "bg-white/15"}`} style={{ width: `${Math.max(2, r.share * 100)}%` }} />
            </div>
            {r.field && <div className="mt-0.5 font-mono text-[0.58rem] text-ink-subtle">{r.field}</div>}
          </li>
        ))}
      </ul>
    </section>
  );
}

function TuneChat({ messages, draft, setDraft, suggestions, fallback, running, onTune, onClear }: {
  messages: ChatMsg[]; draft: string; setDraft: (s: string) => void; suggestions: string[]; fallback: string;
  running: boolean; onTune: () => void; onClear: () => void;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = endRef.current?.parentElement;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  return (
    <section className="glass rise flex flex-col p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="kicker">Tuning instructions</div>
        {messages.length > 0 && (
          <button onClick={onClear} disabled={running} className="font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle transition-colors hover:text-ink disabled:opacity-40">Clear</button>
        )}
      </div>

      <div className="mb-3 max-h-72 space-y-2 overflow-y-auto pr-1">
        {messages.length === 0 && (
          <p className="text-[0.78rem] leading-relaxed text-ink-subtle">
            Tell the agent how this rule should be tuned: which sources to exclude or keep, hosts, users, processes, severity or
            thresholds. Leave it blank to tune from {fallback}.
          </p>
        )}
        {messages.map((m, i) =>
          m.role === "user" ? (
            <div key={i} className="flex justify-end">
              <div className="max-w-[88%] rounded-2xl rounded-br-md border border-accent/20 bg-accent/[0.07] px-3 py-2 text-[0.8rem] text-ink">{m.text}</div>
            </div>
          ) : (
            <div key={i} className="flex gap-2">
              <span className="mt-1 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-glow/20 font-mono text-[0.55rem] text-glow">AI</span>
              <div className="max-w-[88%] whitespace-pre-line rounded-2xl rounded-tl-md border border-white/8 bg-white/[0.03] px-3 py-2 text-[0.76rem] leading-relaxed text-ink-muted">{m.text}</div>
            </div>
          ),
        )}
        {running && (
          <div className="flex items-center gap-2 text-[0.74rem] text-ink-subtle">
            <span className="spin inline-block h-3 w-3 rounded-full border-[1.5px] border-accent/25 border-t-accent" /> Tuning agent is working…
          </div>
        )}
        <div ref={endRef} />
      </div>

      <div className="mb-2 flex flex-wrap gap-1.5">
        {suggestions.map((s) => (
          <button key={s} type="button" disabled={running} onClick={() => setDraft(draft ? `${draft.replace(/[.\s]*$/, "")}. ${s}` : s)}
            className="rounded-full border border-white/8 px-2.5 py-1 text-left text-[0.68rem] text-ink-muted transition-colors hover:border-accent/30 hover:text-ink disabled:opacity-40">
            {s}
          </button>
        ))}
      </div>
      <label htmlFor="tune-draft" className="sr-only">How should this rule be tuned?</label>
      <textarea
        id="tune-draft"
        rows={3}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        disabled={running}
        placeholder="e.g. Exclude the Teams updater but keep Zoom, and lower the severity"
        className="glass-input w-full resize-none p-3 text-[0.82rem] disabled:opacity-60"
      />
      <button onClick={onTune} disabled={running} className="btn btn-primary sheen mt-3 w-full">
        {running ? "Tuning…" : "Tune Detection"}
      </button>
    </section>
  );
}

function Impact({ t }: { t: TuningResult }) {
  const drop = Math.round((1 - t.afterPerDay / t.beforePerDay) * 100);
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {[
        { k: "Before", v: `${t.beforePerDay.toLocaleString()}/day`, c: "text-ink" },
        { k: "After", v: `${t.afterPerDay.toLocaleString()}/day`, c: "text-accent" },
        { k: "Reduction", v: `${drop}%`, c: "text-accent" },
        { k: "Excluded · 7d", v: t.blastRadius7d.toLocaleString(), c: t.blastRadius7d > 5000 ? "text-sev-medium" : "text-ink" },
      ].map((m) => (
        <div key={m.k} className="rounded-xl border border-white/6 bg-white/[0.02] px-4 py-3">
          <div className={`text-[1.35rem] font-extralight ${m.c}`}>{m.v}</div>
          <div className="font-mono text-[0.58rem] uppercase tracking-wider text-ink-subtle">{m.k}</div>
        </div>
      ))}
    </div>
  );
}

export default function TuningClient() {
  const [tree, setTree] = useState<Tree | null>(null);
  const [rules, setRules] = useState<Record<string, RuleDetail>>({});
  const [selectedPath, setSelectedPath] = useState<string>();
  const [ticket, setTicket] = useState<JiraTicket | null>(null);
  const [threads, setThreads] = useState<Record<string, ChatMsg[]>>({});
  const [draft, setDraft] = useState("");
  const runFor = useRef<string | null>(null);
  const queue = useJiraQueue("tuning");
  const { state, start, reset } = useRun("/api/tuning");
  const running = state.status === "running";
  const result = state.meta.tuning as TuningResult | undefined;
  const rule = selectedPath ? rules[selectedPath] : undefined;

  useEffect(() => {
    fetch("/api/rules").then((r) => r.json()).then((d) => { setTree(d.tree); setRules(d.rules); }).catch(() => setTree([]));
  }, []);

  const ticketByPath = useMemo(
    () => Object.fromEntries((queue.tickets ?? []).map((t) => [t.rulePath!, t.key])),
    [queue.tickets],
  );

  // Post the agent's reply into the conversation of the rule the run was for.
  useEffect(() => {
    const path = runFor.current;
    if (!path || (state.status !== "done" && state.status !== "error")) return;
    runFor.current = null;
    const reply = state.error ? `Tuning failed: ${state.error}` : (state.meta.chatReply as string | undefined) ?? "Done. See the rationale and diff.";
    setThreads((t) => ({ ...t, [path]: [...(t[path] ?? []), { role: "agent", text: reply }] }));
  }, [state.status, state.error, state.meta.chatReply]);

  const runTuning = (path: string, ticketKey: string | undefined, thread: ChatMsg[]) => {
    runFor.current = path;
    start({ rulePath: path, ticketKey, instructions: thread.filter((m) => m.role === "user").map((m) => m.text) });
  };

  const selectRule = (path: string) => {
    if (running) return;
    setSelectedPath(path);
    if (ticket?.rulePath !== path) setTicket(null);
    reset();
  };

  const pickTicket = (t: JiraTicket) => {
    setTicket(t);
    setSelectedPath(t.rulePath);
    runTuning(t.rulePath!, t.key, threads[t.rulePath!] ?? []);
  };

  const tune = () => {
    if (!selectedPath || running) return;
    const text = draft.trim();
    const thread = [...(threads[selectedPath] ?? []), ...(text ? [{ role: "user" as const, text }] : [])];
    setThreads((t) => ({ ...t, [selectedPath]: thread }));
    setDraft("");
    runTuning(selectedPath, ticket?.rulePath === selectedPath ? ticket.key : undefined, thread);
  };

  const clearThread = () => {
    if (!selectedPath || running) return;
    setThreads((t) => ({ ...t, [selectedPath]: [] }));
    reset();
  };

  return (
    <div className="mx-auto max-w-[90rem]">
      <PageHeader kicker="Detection Engineering · Tuning" title="Detection Tuning">
        Browse the rules repo or pick a Jira tuning request, then tell the tuning agent how you want the rule tuned. It reads the
        rule&apos;s match profile, writes scoped exclusions, and shows exactly what changed and what it does to alert volume.
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-[19rem_minmax(0,1fr)]">
        <div className="flex flex-col gap-5">
          <RuleTree tree={tree} selected={selectedPath} ticketByPath={ticketByPath} onSelect={selectRule} />
          <TicketList title="Jira · Tuning queue" tickets={queue.tickets} error={queue.error} selected={ticket?.key} onSelect={pickTicket} disabled={running} />
        </div>

        <div className="flex min-w-0 flex-col gap-5">
          {!rule ? (
            <section className="glass rise grid min-h-[22rem] place-items-center p-8 text-center">
              <div>
                <div className="kicker mb-3">No rule loaded</div>
                <p className="max-w-sm text-[0.85rem] text-ink-subtle">Open a folder in the repo tree and pick a rule, or click a ticket in the tuning queue to load its rule and tune it straight away.</p>
              </div>
            </section>
          ) : (
            <>
              <section className="glass rise flex flex-wrap items-center gap-4 p-4">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[0.68rem] text-glow">{rule.path}</div>
                  <div className="mt-0.5 text-[1.05rem] font-light text-ink">{rule.title}</div>
                  <div className="mt-1 flex flex-wrap gap-x-3 font-mono text-[0.6rem] uppercase tracking-wider text-ink-subtle">
                    <span>v{rule.version}</span><span>{rule.severity}</span><span>{rule.technique}</span><span>{rule.dataSource}</span>
                    <span className="flex items-center gap-1"><span className={`h-1.5 w-1.5 rounded-full ${volumeColor(rule.perDay)}`} />{rule.perDay.toLocaleString()}/day</span>
                  </div>
                </div>
                <span className={`rounded-full px-3 py-1 font-mono text-[0.62rem] uppercase tracking-wider ${running ? "bg-accent/10 text-accent" : result ? "bg-glow/15 text-glow" : "bg-white/5 text-ink-subtle"}`}>
                  {running ? "Tuning…" : result ? `Tuned · v${result.toVersion}` : "Not tuned"}
                </span>
              </section>

              {ticket && ticket.rulePath === rule.path && <TicketCard key={ticket.key} ticket={ticket} />}

              <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_25rem]">
                <div className="flex min-w-0 flex-col gap-5">
                  {state.status === "idle" ? (
                    <section className="glass rise min-w-0 p-5">
                      <div className="kicker mb-3">Current rule</div>
                      <pre className="max-h-[38rem] overflow-auto rounded-xl border border-white/6 bg-[rgba(2,4,12,0.7)] p-4 font-mono text-[0.7rem] leading-[1.6] text-[#c9d6f5]">{rule.text}</pre>
                    </section>
                  ) : (
                    <ReportPanel state={state} title="Tuning rationale" empty={null} />
                  )}
                </div>
                <div className="order-first flex min-w-0 flex-col gap-5 2xl:order-none">
                  <TuneChat
                    messages={threads[rule.path] ?? []}
                    draft={draft}
                    setDraft={setDraft}
                    suggestions={rule.suggestions}
                    fallback={ticket?.rulePath === rule.path ? `${ticket.key}'s known-goods` : "the match profile (values ≥15%)"}
                    running={running}
                    onTune={tune}
                    onClear={clearThread}
                  />
                  {state.status === "idle" ? <MatchProfile rule={rule} /> : <PipelineView state={state} />}
                </div>
              </div>

              {result && (
                <section className="glass rise p-5">
                  <div className="kicker mb-4">Before / after</div>
                  <Impact t={result} />
                  <div className="mt-5">
                    <DiffView before={result.before} after={result.after} fromVersion={result.fromVersion} toVersion={result.toVersion} />
                  </div>
                </section>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
