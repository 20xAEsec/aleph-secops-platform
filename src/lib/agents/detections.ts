import { config } from "../config";
import { retrieveContexts } from "../rag";
import { searchUdmEvents } from "../secops/telemetry";
import { extractLastCodeBlock, lintYaraL, simulateRuleTest } from "../quality/yaral";
import type { Emit } from "../sse";
import { agentSystem, toolResultsBlock } from "./prompts";
import { callTool, runPipeline, type Stage } from "./runtime";
import { runAgent } from "./llmStage";

export type DetectionInput = { description: string; language: "YARA-L" | "KQL" | "SPL"; severity: string };

const UDM_FIELDS: Record<string, string[]> = {
  NETWORK_DNS: ["principal.hostname", "principal.ip", "network.dns.questions.name", "network.dns.answers.data"],
  NETWORK_CONNECTION: ["principal.hostname", "target.ip", "target.hostname", "network.sent_bytes", "network.application_protocol"],
  PROCESS_LAUNCH: ["principal.hostname", "principal.user.userid", "target.process.file.full_path", "target.process.command_line", "principal.process.file.full_path"],
  USER_LOGIN: ["target.user.userid", "principal.ip", "principal.location.country_or_region", "security_result.action"],
};

export async function runDetectionGenerator(input: DetectionInput, emit: Emit) {
  const { reasoning } = config.models;
  const research: Record<string, unknown> = {};

  const researcher: Stage = {
    id: "research", name: "Rule Research Agent", phase: "Gather",
    async run(ctx, id) {
      const d = input.description.toLowerCase();
      const types = Object.keys(UDM_FIELDS).filter((t) =>
        (t === "NETWORK_DNS" && /dns|domain|lookup/.test(d)) ||
        (t === "NETWORK_CONNECTION" && /beacon|connect|c2|egress|exfil|network/.test(d)) ||
        (t === "PROCESS_LAUNCH" && /process|powershell|command|exec|macro|lolbin|script/.test(d)) ||
        (t === "USER_LOGIN" && /login|logon|auth|sign-in|mfa/.test(d)));
      const eventTypes = types.length ? types : ["PROCESS_LAUNCH", "NETWORK_CONNECTION"];
      const [kb, fields] = await Promise.all([
        callTool(ctx, id, "search_knowledge_base", { query: input.description.slice(0, 200) }, () => retrieveContexts(`detection rule examples: ${input.description}`),
          (r) => (r.status === "ok" ? `${r.contexts.length} reference passage(s)` : r.status)),
        callTool(ctx, id, "check_udm_fields", { event_types: eventTypes }, () => Object.fromEntries(eventTypes.map((t) => [t, UDM_FIELDS[t]])),
          (r) => `${Object.values(r).flat().length} populated fields across ${eventTypes.join(", ")}`),
      ]);
      Object.assign(research, { search_knowledge_base: kb, check_udm_fields: fields });
    },
  };

  const author: Stage = {
    id: "author", name: `${input.language} Rule Author`, phase: "Analyze", model: reasoning,
    async run(ctx, id) {
      const standards = input.language === "YARA-L"
        ? `Team standards for YARA-L 2.0:
- meta must include: author, team, rule_name, description, severity, data_source, mitre_tactic, mitre_technique, mitre_subtechnique, type, status
- severity to risk score: Low 35, Medium 50, High 75, Critical 100
- outcome must define $risk_score and $event_count
- Chronicle regex is RE2: no lookarounds
- use only the UDM fields confirmed by check_udm_fields`
        : `Write idiomatic ${input.language}. Include a header comment with description, severity and MITRE mapping.`;
      await runAgent(ctx, id, {
        model: reasoning, maxTokens: 3000, toReport: true,
        system: agentSystem(`${input.language} Detection Engineer`, `${standards}

Output format:
1. One short paragraph on detection logic and expected false positives.
2. The complete rule in ONE fenced code block.
3. A "Tuning notes" bullet list.`),
        prompt: `Detection request: ${input.description}\nSeverity: ${input.severity}\n\n${toolResultsBlock(research)}`,
        mock: mockRule(input),
      });
    },
  };

  const validator: Stage = {
    id: "validate", name: "Validator & Rule Test", phase: "Verify",
    async run(ctx, id) {
      const rule = extractLastCodeBlock(ctx.notes.author ?? "");
      if (!rule) throw new Error("no rule code block was produced");
      const lint = input.language === "YARA-L" ? lintYaraL(rule) : [];
      const test = await callTool(ctx, id, "run_rule_test", { window_days: 7, mode: "simulated" },
        () => simulateRuleTest(rule, searchUdmEvents({ query: "rule-test", hours_back: 168 }).events),
        (r) => `${r.matches} match(es) → ${r.verdict}`);
      ctx.emit({ type: "meta", lint, ruleTest: test });
    },
  };

  await runPipeline([researcher, author, validator], emit);
}

function mockRule(input: DetectionInput) {
  const risk = { Low: 35, Medium: 50, High: 75, Critical: 100 }[input.severity] ?? 75;
  if (input.language !== "YARA-L") {
    return `> _Demo data: canned rule._\n\nDetects hidden, encoded PowerShell spawned by Office applications.\n\n\`\`\`${input.language.toLowerCase()}\n// Office spawning encoded PowerShell. Severity: ${input.severity}. MITRE T1059.001\nDeviceProcessEvents\n| where InitiatingProcessFileName in~ ("excel.exe","winword.exe","outlook.exe")\n| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-enc","-encodedcommand")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n\`\`\`\n\n**Tuning notes**\n- Exclude signed IT automation parents if they use encoded commands.`;
  }
  return `> _Demo data: canned rule._

Flags hidden, encoded PowerShell on a host that opened a macro-enabled Office document in the previous 10 minutes. False positives come from IT automation that uses \`-enc\`; scope those out by parent process.

\`\`\`yaral
rule office_macro_to_encoded_powershell {
  meta:
    author = "Aleph Detection Engineering"
    team = "detection-engineering"
    rule_name = "Office Macro to Encoded PowerShell"
    description = "Macro-enabled document followed by hidden encoded PowerShell on the same host"
    severity = "${input.severity}"
    data_source = "EDR process telemetry"
    mitre_tactic = "TA0002"
    mitre_technique = "T1059"
    mitre_subtechnique = "T1059.001"
    type = "alert"
    status = "experimental"

  events:
    $doc.metadata.event_type = "PROCESS_LAUNCH"
    $doc.target.process.command_line = /\\.xlsm|\\.docm/ nocase
    $doc.principal.hostname = $host

    $ps.metadata.event_type = "PROCESS_LAUNCH"
    $ps.target.process.file.full_path = /powershell\\.exe/ nocase
    $ps.target.process.command_line = /-enc|-encodedcommand/ nocase
    $ps.principal.hostname = $host

    $doc.metadata.event_timestamp.seconds < $ps.metadata.event_timestamp.seconds

  match:
    $host over 10m

  outcome:
    $risk_score = max(${risk})
    $event_count = count_distinct($ps.metadata.id)

  condition:
    $doc and $ps
}
\`\`\`

**Tuning notes**
- If volume is high, exclude known automation parents via a reference list.
- Consider raising severity when the host later beacons (pair with a network rule).`;
}
