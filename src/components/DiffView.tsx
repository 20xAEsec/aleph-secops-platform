"use client";

import { useMemo } from "react";
import { diffLines, type DiffLine } from "@/lib/detections/diff";

const LINE_STYLE: Record<DiffLine["kind"], string> = {
  same: "text-[#c9d6f5]",
  added: "bg-accent/[0.09] text-accent shadow-[inset_2px_0_0_rgba(93,240,168,0.8)]",
  removed: "bg-sev-critical/[0.09] text-sev-critical shadow-[inset_2px_0_0_rgba(255,93,115,0.8)]",
};

function Pane({ title, lines, sign }: { title: React.ReactNode; lines: DiffLine[]; sign: "+" | "-" }) {
  return (
    <div className="min-w-0 overflow-hidden rounded-xl border border-white/6 bg-[rgba(2,4,12,0.7)]">
      <div className="border-b border-white/6 px-3 py-2 font-mono text-[0.62rem] uppercase tracking-wider text-ink-subtle">{title}</div>
      <pre className="max-h-[32rem] overflow-auto py-2 font-mono text-[0.7rem] leading-[1.6]">
        {lines.map((l, i) => (
          <div key={i} className={`flex px-3 ${LINE_STYLE[l.kind]}`}>
            <span className="w-4 shrink-0 select-none opacity-60">{l.kind === "same" ? " " : sign}</span>
            <span className="whitespace-pre">{l.text || " "}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

export default function DiffView({ before, after, fromVersion, toVersion }: { before: string; after: string; fromVersion: string; toVersion: string }) {
  const diff = useMemo(() => diffLines(before, after), [before, after]);
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-3 font-mono text-[0.64rem] uppercase tracking-wider">
        <span className="text-accent">+{diff.added} added</span>
        <span className="text-sev-critical">-{diff.removed} removed</span>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Pane title={<>Before · v{fromVersion}</>} lines={diff.before} sign="-" />
        <Pane title={<>After · v{toVersion}</>} lines={diff.after} sign="+" />
      </div>
    </div>
  );
}
