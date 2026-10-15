export default function PageHeader({ kicker, title, children }: { kicker: string; title: string; children?: React.ReactNode }) {
  return (
    <div className="rise mb-7 max-w-3xl">
      <div className="kicker mb-3">{kicker}</div>
      <h1 className="hero-title text-[clamp(1.6rem,3.2vw,2.4rem)] font-extralight tracking-[0.06em]">{title}</h1>
      <div className="hairline mt-4 w-28" />
      {children && <p className="copy-shadow mt-4 text-[0.92rem] leading-relaxed text-ink-muted">{children}</p>}
    </div>
  );
}
