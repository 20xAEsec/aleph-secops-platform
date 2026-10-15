import type { UdmEvent } from "../secops/telemetry";

// Structural lint for generated YARA-L rules against the team's standards, plus a simulated
// rule test over demo telemetry. In production the rule test is Chronicle's own validator.

export const REQUIRED_META = [
  "author", "team", "rule_name", "description", "severity", "data_source",
  "mitre_tactic", "mitre_technique", "mitre_subtechnique", "type", "status",
];

export type LintCheck = { name: string; pass: boolean; detail?: string };

export function extractLastCodeBlock(text: string): string {
  const blocks = [...text.matchAll(/```[a-z-]*\n([\s\S]*?)```/gi)];
  return blocks.length ? blocks[blocks.length - 1][1].trim() : "";
}

export function lintYaraL(rule: string): LintCheck[] {
  const meta = rule.match(/meta:\s*([\s\S]*?)\n\s*(events|match|outcome|condition):/)?.[1] ?? "";
  const missing = REQUIRED_META.filter((f) => !new RegExp(`\\b${f}\\s*=`).test(meta));
  return [
    { name: "rule declaration", pass: /\brule\s+[a-z0-9_]+\s*\{/i.test(rule) },
    { name: "meta section", pass: meta.length > 0 },
    { name: "required meta fields", pass: missing.length === 0, detail: missing.length ? `missing: ${missing.join(", ")}` : `${REQUIRED_META.length}/${REQUIRED_META.length}` },
    { name: "events section", pass: /\bevents:/.test(rule) },
    { name: "condition section", pass: /\bcondition:/.test(rule) },
    { name: "$risk_score outcome", pass: /\$risk_score\s*=/.test(rule) },
    { name: "$event_count outcome", pass: /\$event_count\s*=/.test(rule) },
    { name: "no regex lookarounds (RE2)", pass: !/\(\?[=!<]/.test(rule) },
  ];
}

export type RuleTest = { matches: number; verdict: "DEAD" | "OK" | "FP_STORM"; terms: string[] };

// Simulated test: count demo events containing the rule's quoted literals.
export function simulateRuleTest(rule: string, events: UdmEvent[]): RuleTest {
  // Only literals from the events section; skip UDM enum values like "NETWORK_DNS".
  const eventsSection = rule.match(/events:([\s\S]*?)(?:match:|outcome:|condition:)/)?.[1] ?? "";
  const terms = [...eventsSection.matchAll(/"([^"\n]{3,80})"/g)]
    .map((m) => m[1])
    .filter((t) => !/^[A-Z_]+$/.test(t))
    .map((t) => t.toLowerCase().replace(/\\\\/g, "\\"))
    .slice(0, 12);
  const regexes = [...eventsSection.matchAll(/=\s*\/(.+?)\/\s*(nocase)?/g)].flatMap((m) => {
    try {
      return [new RegExp(m[1], m[2] ? "i" : "")];
    } catch {
      return [];
    }
  });
  const matches = terms.length || regexes.length
    ? events.filter((e) => {
        const blob = JSON.stringify(e);
        return terms.some((t) => blob.toLowerCase().includes(t)) || regexes.some((r) => r.test(blob));
      }).length
    : 0;
  return { matches, verdict: matches === 0 ? "DEAD" : matches > 1000 ? "FP_STORM" : "OK", terms: [...terms, ...regexes.map((r) => r.source)] };
}
