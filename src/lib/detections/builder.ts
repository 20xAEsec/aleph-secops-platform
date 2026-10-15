// Shared YARA-L builder. Repo rules, Jira-generated rules and tuned rules all come out of the
// same function, so a tuned rule differs from its original only by the exclusions added.

export type Severity = "Low" | "Medium" | "High" | "Critical";
export const RISK_SCORE: Record<Severity, number> = { Low: 35, Medium: 50, High: 75, Critical: 100 };

export type RuleSpec = {
  ruleName: string;
  title: string;
  description: string;
  severity: Severity;
  dataSource: string;
  tactic: string;
  technique: string;
  subtechnique: string;
  events: string[];
  match: string;
  condition?: string; // default "$e"
  countVar?: string; // event variable for $event_count, default "$e"
  outcome?: string[]; // extra outcome lines
};

// A known-good: something benign the rule should stop firing on.
export type KnownGood = {
  id?: string;
  label: string;
  clause: string; // the YARA-L exclusion
  field?: string; // for match-profile display
  value?: string;
  share?: number; // fraction of current detections it accounts for
};

export type BuildMeta = { status?: string; version?: string; ticket?: string; lastTuned?: string };

export function buildYaraL(spec: RuleSpec, exclusions: KnownGood[] = [], meta: BuildMeta = {}): string {
  const lines: (string | false | undefined)[] = [
    `rule ${spec.ruleName} {`,
    `  meta:`,
    `    author = "Aleph Detection Engineering"`,
    `    team = "detection-engineering"`,
    `    rule_name = "${spec.title}"`,
    `    description = "${spec.description}"`,
    `    severity = "${spec.severity}"`,
    `    data_source = "${spec.dataSource}"`,
    `    mitre_tactic = "${spec.tactic}"`,
    `    mitre_technique = "${spec.technique}"`,
    `    mitre_subtechnique = "${spec.subtechnique}"`,
    `    type = "alert"`,
    `    status = "${meta.status ?? "active"}"`,
    `    version = "${meta.version ?? "1.0"}"`,
    meta.ticket && `    jira = "${meta.ticket}"`,
    meta.lastTuned && `    last_tuned = "${meta.lastTuned}"`,
    ``,
    `  events:`,
    ...spec.events.map((l) => `    ${l}`),
    ...(exclusions.length
      ? [``, ...exclusions.flatMap((x) => [`    // known-good: ${x.label}`, `    ${x.clause}`])]
      : []),
    ``,
    `  match:`,
    `    ${spec.match}`,
    ``,
    `  outcome:`,
    `    $risk_score = max(${RISK_SCORE[spec.severity]})`,
    `    $event_count = count_distinct(${spec.countVar ?? "$e"}.metadata.id)`,
    ...(spec.outcome ?? []).map((l) => `    ${l}`),
    ``,
    `  condition:`,
    `    ${spec.condition ?? "$e"}`,
    `}`,
  ];
  return lines.filter((l): l is string => typeof l === "string").join("\n");
}

export function bumpVersion(v: string): string {
  const [major, minor = "0"] = v.split(".");
  return `${major}.${Number(minor) + 1}`;
}
