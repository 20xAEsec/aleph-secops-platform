import type { KnownGood, Severity } from "./builder";
import type { RepoRule } from "./repo";

// Turns the analyst's free-text tuning instructions into concrete rule changes. Deterministic,
// so the mock tuning agent honours what was typed. Messages are applied in order, so a later
// "keep Chrome" undoes an earlier "exclude all updaters".

export type TuningPlan = {
  exclusions: KnownGood[];
  severity?: { from: Severity; to: Severity };
  threshold?: { from: number; to: number };
  understood: string[]; // human-readable actions, shown in chat and rationale
  unmapped: string[]; // sentences that produced no change
};

const SEVERITIES: Severity[] = ["Low", "Medium", "High", "Critical"];
const STOP = new Set([
  "microsoft", "windows", "update", "updater", "auto", "client", "sync", "desktop", "start", "corporate", "service",
  "account", "agent", "scanning", "cloud", "from", "with", "process", "servers", "server", "hosts", "host", "requires",
  "legacy", "team", "per-user", "users", "mobile", "refresh", "management", "extension", "files", "program",
  "auto-start", "autostart", "startup", "background", "drift", "requests",
]);
const EXCLUDE_RE = /\b(exclude|excluding|tune out|ignore|suppress|filter|allow ?list|whitelist|drop|remove|known[- ]good|benign|stop alerting|silence)\b/;
const KEEP_RE = /\b(keep|don'?t exclude|do not exclude|still alert|include|stop excluding|monitor)\b/;

function keywords(n: KnownGood): string[] {
  const words = `${n.label} ${n.value ?? ""} ${n.id ?? ""}`.toLowerCase().match(/[a-z][a-z0-9_.-]{3,}/g) ?? [];
  return [...new Set(words.map((w) => w.replace(/\.(exe|com|net)$/, "")).filter((w) => !STOP.has(w)))];
}

const mentions = (sentence: string, word: string) => new RegExp(`(^|[^a-z0-9])${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9]|$)`).test(sentence);

export function planTuning(rule: RepoRule, baseline: KnownGood[], messages: string[]): TuningPlan {
  const v = rule.spec.countVar ?? (rule.spec.events[0].match(/^(?:not\s+)?(\$[a-z]+)\./)?.[1] ?? "$e");
  const chosen = new Map<string, KnownGood>(baseline.map((k) => [k.label, k]));
  const plan: TuningPlan = { exclusions: [], understood: [], unmapped: [] };
  let severity = rule.spec.severity;
  const counter = rule.spec.condition?.match(/#\w+\s*>=\s*(\d+)/);
  let threshold = counter ? Number(counter[1]) : undefined;

  // Split on sentence ends only: a "." inside an IP, CIDR or file name must survive.
  const sentences = messages.flatMap((m) => m.split(/[;\n]+|\.(?=\s|$)|\bbut\b|\bhowever\b/i)).map((s) => s.trim()).filter(Boolean);

  for (const raw of sentences) {
    const s = raw.toLowerCase();
    const keep = KEEP_RE.test(s);
    const before = plan.understood.length;

    // 1. Sources from the rule's own match profile
    const all = /\b(all|every|everything)\b.*\b(noise|noisy|known[- ]goods?|benign|candidates?|sources?)\b/.test(s);
    const hits = rule.noise.filter((n) => all || keywords(n).some((k) => mentions(s, k)));
    for (const n of hits) {
      if (keep && chosen.delete(n.label)) plan.understood.push(`Keep alerting on **${n.label}** (exclusion removed)`);
      else if (keep) plan.understood.push(`Keep alerting on **${n.label}** (no change needed)`);
      else if (!chosen.has(n.label)) { chosen.set(n.label, n); plan.understood.push(`Exclude **${n.label}** (${Math.round((n.share ?? 0) * 100)}% of matches)`); }
    }

    // 2. Custom entities not in the profile
    if (!keep && (EXCLUDE_RE.test(s) || hits.length === 0)) {
      const add = (label: string, clause: string, field: string, value: string) => {
        if (rule.noise.some((n) => `${n.label} ${n.value ?? ""}`.toLowerCase().includes(value.toLowerCase()))) return;
        if (!chosen.has(label)) { chosen.set(label, { label, clause, field, value, share: 0.03 }); plan.understood.push(`Exclude **${label}** (custom; volume share estimated)`); }
      };
      for (const m of s.matchAll(/\b(?:host(?:name)?s?|machines?|servers?|workstations?)\s+(?:named\s+|called\s+)?([a-z0-9][a-z0-9*-]*[a-z0-9*])/g)) {
        const h = m[1];
        if (STOP.has(h) || /^(and|or|the|that|from)$/.test(h)) continue;
        const clause = h.includes("*")
          ? `not ${v}.principal.hostname = /^${h.replace(/\*/g, ".*")}$/ nocase`
          : `not ${v}.principal.hostname = "${h}" nocase`;
        add(`host ${h}`, clause, "principal.hostname", h);
      }
      for (const m of s.matchAll(/\b(?:user|account|service account)\s+([a-z0-9_.\\-]{3,})/g)) {
        add(`user ${m[1]}`, `not ${v}.principal.user.userid = "${m[1]}" nocase`, "principal.user.userid", m[1]);
      }
      for (const m of raw.matchAll(/\b([A-Za-z0-9_.-]+\.exe)\b/g)) {
        const exe = m[1];
        add(`process ${exe}`, `not ${v}.principal.process.file.full_path = /\\\\${exe.replace(/\./g, "\\.")}$/ nocase`, "principal.process.file.full_path", exe);
      }
      for (const m of s.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})(\/\d{1,2})?\b/g)) {
        const cidr = m[2] ? `${m[1]}${m[2]}` : `${m[1]}/32`;
        add(`network ${cidr}`, `not net.ip_in_range_cidr(${v}.principal.ip, "${cidr}")`, "principal.ip", m[1]);
      }
    }

    // 3. Severity
    const sev = s.match(/severity\s+(?:to\s+|=\s*|as\s+)?(low|medium|high|critical)\b/) ?? s.match(/\b(low|medium|high|critical)\s+severity\b/);
    if (sev) severity = (sev[1][0].toUpperCase() + sev[1].slice(1)) as Severity;
    else if (/\b(lower|downgrade|reduce|decrease)\b.*\bseverity\b/.test(s)) severity = SEVERITIES[Math.max(0, SEVERITIES.indexOf(severity) - 1)];
    else if (/\b(raise|upgrade|increase)\b.*\bseverity\b/.test(s)) severity = SEVERITIES[Math.min(3, SEVERITIES.indexOf(severity) + 1)];
    if (severity !== (plan.severity?.to ?? rule.spec.severity)) plan.understood.push(`Set severity to **${severity}**`);

    // 4. Count threshold
    const th = s.match(/\b(?:threshold|at least|minimum|min|more than|over)\D{0,14}(\d{1,4})/) ?? s.match(/\b(\d{1,4})\s*\+?\s*(?:or more\s+)?(?:times|events|lookups|hits|queries)\b/);
    if (th) {
      if (threshold === undefined) plan.unmapped.push(`"${raw}": this rule has no count threshold to change`);
      else if (Number(th[1]) !== threshold) { threshold = Number(th[1]); plan.understood.push(`Raise the count threshold to **${threshold}**`); }
    }

    if (plan.understood.length === before && !plan.unmapped.some((u) => u.startsWith(`"${raw}"`))) plan.unmapped.push(`"${raw}"`);
    if (severity !== rule.spec.severity) plan.severity = { from: rule.spec.severity, to: severity };
    else delete plan.severity;
  }

  if (counter && threshold !== undefined && threshold !== Number(counter[1])) plan.threshold = { from: Number(counter[1]), to: threshold };
  plan.exclusions = [...chosen.values()];
  return plan;
}

export function planIsEmpty(p: TuningPlan) {
  return p.exclusions.length === 0 && !p.severity && !p.threshold;
}

// Suggested prompts for the chat, built from the rule's own profile.
export function suggestions(rule: Pick<RepoRule, "noise" | "spec">): string[] {
  const top = [...rule.noise].sort((a, b) => (b.share ?? 0) - (a.share ?? 0));
  const short = (n: KnownGood) => n.label.replace(/\s*\(.*\)$/, "");
  const out = [
    top[0] && `Exclude ${short(top[0])}`,
    top.length > 1 && `Exclude all noisy known-goods but keep ${short(top[top.length - 1])}`,
    /#\w+\s*>=/.test(rule.spec.condition ?? "") ? "Raise the threshold to 20 events per hour" : "Exclude host it-admin-01",
    "Lower the severity",
  ];
  return out.filter((x): x is string => Boolean(x));
}
