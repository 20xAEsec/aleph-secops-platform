import PageHeader from "@/components/PageHeader";
import { APPS, TEMPLATES, allLogs, isViolation, statsFor } from "@/lib/aisec/modelArmor";
import AiSecurityClient from "./AiSecurityClient";

export default function AiSecurityPage() {
  const logs = allLogs();
  const stats = statsFor(logs);

  // Enforcement posture per application: the gap this dashboard exists to surface is an app that
  // records violations without blocking them.
  const posture = Object.entries(APPS)
    .map(([id, p]) => {
      const recs = logs.filter((l) => l.app === id);
      const violations = recs.filter(isViolation);
      return {
        id, name: p.name, owner: p.owner, audience: p.audience, template: p.template,
        enforcement: TEMPLATES[p.template].enforcement,
        records: recs.length,
        violations: violations.length,
        unblocked: violations.filter((l) => !l.blocked).length,
        mcpAllow: p.mcpAllow.length,
        skillAllow: p.skillAllow.length,
      };
    })
    .filter((a) => a.records > 0)
    .sort((a, b) => b.unblocked - a.unblocked || b.violations - a.violations);

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="AI Security · Model Armor Prompt Logs" title="AI Prompt Hunt">
        Every prompt, response and tool result crossing the AI gateway is sanitized by GCP Model Armor and logged with its
        verdict. This hunts that corpus the way the threat hunt works on endpoint telemetry: pick a hypothesis, agents search
        the logs, weigh the policy that governed each record, argue the other side, and write a cited report.
      </PageHeader>
      <AiSecurityClient stats={stats} posture={posture} corpus={logs.length} />
    </div>
  );
}
