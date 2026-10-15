import Link from "next/link";
import { notFound } from "next/navigation";
import PageHeader from "@/components/PageHeader";
import { FEATURES, PILLARS } from "@/lib/catalog";

export function generateStaticParams() {
  return FEATURES.filter((f) => f.status === "blueprint").map((f) => ({ slug: f.slug }));
}

export default async function FeatureBlueprint({ params }: PageProps<"/features/[slug]">) {
  const { slug } = await params;
  const feature = FEATURES.find((f) => f.slug === slug);
  if (!feature) notFound();
  const pillar = PILLARS.find((p) => p.id === feature.pillar)!;
  const siblings = FEATURES.filter((f) => f.pillar === feature.pillar && f.slug !== feature.slug);

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader kicker={`${pillar.title} · Spec`} title={feature.title}>{feature.summary}</PageHeader>

      <div className="grid gap-5 md:grid-cols-2">
        <section className="glass rise p-6">
          <div className="kicker mb-4">How it works</div>
          <ul className="space-y-3">
            {feature.how.map((h) => (
              <li key={h} className="flex gap-3 text-[0.86rem] leading-relaxed text-ink-muted">
                <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-glow" />{h}
              </li>
            ))}
          </ul>
        </section>
        <section className="glass rise p-6" style={{ animationDelay: "100ms" }}>
          <div className="kicker mb-4">What&apos;s clever</div>
          <ul className="space-y-3">
            {feature.clever.map((c) => (
              <li key={c} className="flex gap-3 text-[0.86rem] leading-relaxed text-ink-muted">
                <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-accent" />{c}
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="glass rise mt-5 flex flex-wrap items-center justify-between gap-4 p-5" style={{ animationDelay: "200ms" }}>
        <p className="max-w-xl text-[0.82rem] text-ink-muted">
          This feature runs in the full Aleph platform. In this demo it&apos;s documented rather than wired. It reuses the same pipeline
          runtime, tool seam and evidence check as the live features.
        </p>
        <div className="flex flex-wrap gap-2">
          {siblings.filter((s) => s.status === "live").map((s) => (
            <Link key={s.slug} href={s.href} className="btn btn-ghost sheen text-[0.78rem]">Try {s.title} →</Link>
          ))}
        </div>
      </section>
    </div>
  );
}
