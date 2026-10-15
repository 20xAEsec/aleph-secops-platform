"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { ASK_ALEPH, FEATURES, PILLARS } from "@/lib/catalog";

type Status = { llm: { live: boolean; models: { reasoning: string; fast: string } }; rag: { configured: boolean } };

function AlephMark({ className = "" }: { className?: string }) {
  // Aleph (ℵ) drawn as a constellation: a diagonal stroke with two arms, stars at the joints.
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <g stroke="currentColor" strokeOpacity="0.45" strokeWidth="1.1" strokeLinecap="round" fill="none">
        <path d="M8 6 L24 26 M21 6 Q23 12 17 15 M11 26 Q9 20 14 18" />
      </g>
      <g fill="currentColor">
        <circle cx="8" cy="6" r="1.6" /><circle cx="24" cy="26" r="1.7" />
        <circle cx="21" cy="6" r="1.3" /><circle cx="11" cy="26" r="1.3" />
        <circle cx="16" cy="16" r="1.4" />
      </g>
    </svg>
  );
}

function NavLink({ href, label, live, active }: { href: string; label: string; live: boolean; active: boolean }) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={`group flex items-center justify-between rounded-lg px-3 py-1.5 text-[0.8rem] transition-colors ${
        active ? "bg-accent/10 text-accent shadow-[inset_0_0_0_1px_rgba(93,240,168,0.25)]" : "text-ink-muted hover:bg-white/[0.03] hover:text-ink"
      }`}
    >
      <span className="truncate">{label}</span>
      {live ? (
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${active ? "bg-accent" : "bg-accent/60"}`} title="Live in demo" />
      ) : (
        <span className="shrink-0 font-mono text-[0.58rem] uppercase tracking-wider text-ink-subtle opacity-0 transition-opacity group-hover:opacity-100">spec</span>
      )}
    </Link>
  );
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [status, setStatus] = useState<Status | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    fetch("/api/status").then((r) => r.json()).then(setStatus).catch(() => setStatus(null));
  }, []);
  useEffect(() => setOpen(false), [pathname]);

  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  const nav = (
    <nav className="flex h-full flex-col gap-5 overflow-y-auto px-3 pb-5 pt-5">
      <Link href="/" className="flex items-center gap-2.5 px-2">
        <AlephMark className="h-7 w-7 text-accent drop-shadow-[0_0_8px_rgba(93,240,168,0.5)]" />
        <span className="text-[0.95rem] font-light uppercase tracking-[0.42em] text-ink">Aleph</span>
      </Link>

      <div className="flex flex-col gap-0.5">
        <NavLink href="/" label="Command Deck" live active={isActive("/")} />
        <NavLink href={ASK_ALEPH.href} label={ASK_ALEPH.title} live active={isActive(ASK_ALEPH.href)} />
      </div>

      {PILLARS.map((p) => (
        <div key={p.id} className="flex flex-col gap-0.5">
          <div className="nav-group px-3 pb-2">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-[0.62rem] font-medium tracking-[0.18em] text-accent drop-shadow-[0_0_6px_rgba(93,240,168,0.55)]">{p.kicker}</span>
              <span className="nav-group-title">{p.title}</span>
            </div>
            <div className="hairline mt-1.5 opacity-60" />
          </div>
          <div className="ml-3 flex flex-col gap-0.5 border-l border-white/[0.06] pl-1.5">
            {FEATURES.filter((f) => f.pillar === p.id).map((f) => (
              <NavLink key={f.slug} href={f.href} label={f.title} live={f.status === "live"} active={isActive(f.href)} />
            ))}
          </div>
        </div>
      ))}

      <div className="mt-auto flex flex-col gap-0.5 border-t border-white/5 pt-4">
        <NavLink href="/engineering" label="Engineering" live active={isActive("/engineering")} />
      </div>
    </nav>
  );

  return (
    <div className="relative z-10 flex min-h-screen">
      {/* Desktop sidebar */}
      <aside className="glass sticky top-0 hidden h-screen w-60 shrink-0 rounded-none border-y-0 border-l-0 lg:block">{nav}</aside>

      {/* Mobile drawer */}
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/60" />
          <aside className="glass absolute inset-y-0 left-0 w-64 rounded-none" onClick={(e) => e.stopPropagation()}>{nav}</aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-white/5 bg-[rgba(4,6,15,0.55)] px-4 backdrop-blur-xl sm:px-6">
          <button className="btn btn-ghost px-3 py-1.5 lg:hidden" onClick={() => setOpen(true)} aria-label="Open navigation">☰</button>
          <div className="hidden font-mono text-[0.68rem] uppercase tracking-[0.22em] text-ink-subtle sm:block">SecOps workspace · demo tenant</div>
          <div className="flex items-center gap-2 font-mono text-[0.66rem] uppercase tracking-wider">
            <StatusPill
              ok={status?.llm.live || null}
              label={status ? (status.llm.live ? "Claude · live" : "Claude · demo") : "Claude · …"}
              title={status ? `Reasoning: ${status.llm.models.reasoning} · Fast: ${status.llm.models.fast}` : ""}
            />
            <StatusPill ok={status?.rag.configured || null} label={status ? (status.rag.configured ? "Vertex RAG · on" : "Knowledge base · demo") : "RAG · …"} title={status?.rag.configured ? "Knowledge base via Vertex AI RAG Engine" : "Seeded demo knowledge base stands in for Vertex AI RAG"} />
            <StatusPill ok={null} label="Telemetry · demo" title="Seeded demo telemetry stands in for Chronicle" />
          </div>
        </header>
        <main className="flex-1 px-4 py-6 sm:px-8 sm:py-8">{children}</main>
      </div>
    </div>
  );
}

function StatusPill({ ok, label, title }: { ok: boolean | null | undefined; label: string; title?: string }) {
  const color = ok === true ? "bg-accent" : ok === false ? "bg-sev-medium" : "bg-sev-low";
  return (
    <span title={title} className="hidden items-center gap-1.5 rounded-full border border-white/8 bg-white/[0.03] px-2.5 py-1 text-ink-muted md:inline-flex">
      <span className={`h-1.5 w-1.5 rounded-full ${color} ${ok ? "pulse-dot" : ""}`} />
      {label}
    </span>
  );
}
