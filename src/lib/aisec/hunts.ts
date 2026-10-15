// Predefined AI-security hunts. Each one is a named hypothesis bound to a structured query, so a
// click runs a real search instead of hoping free text lands. The hypothesis text is what the
// agents receive; the query is what the deterministic search layer executes.

import type { LogQuery } from "./modelArmor";

export type HuntDef = {
  id: string;
  title: string;
  blurb: string;
  group: "Agent integrity" | "Data protection" | "Governance";
  severity: "Critical" | "High" | "Medium";
  hypothesis: string;
  query: LogQuery;
};

export const HUNTS: HuntDef[] = [
  {
    id: "indirect-injection", title: "Agent hijacked by content it retrieved", group: "Agent integrity", severity: "Critical",
    blurb: "Injection verdicts on tool results or retrieved context — the agent was steered by data, not by its user.",
    hypothesis: "An autonomous or semi-autonomous agent was steered by instructions embedded in content it retrieved (a ticket, document or web page) rather than by its operator. Identify the affected applications, sessions and service accounts, what the agent did in the same session after the injection verdict, and whether enforcement stopped it.",
    query: { categories: ["prompt_injection"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "jailbreak", title: "Users trying to talk an app out of its policy", group: "Agent integrity", severity: "Medium",
    blurb: "Injection/jailbreak verdicts on user prompts, including repeat attempts inside one session.",
    hypothesis: "Users are attempting to evade application guardrails. Identify who is attempting it, which applications they target, whether attempts escalate within a session, and whether any attempt was not blocked.",
    query: { categories: ["jailbreak"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "shadow-mcp", title: "Unsanctioned MCP servers", group: "Governance", severity: "High",
    blurb: "Agents calling MCP servers that are not in the application's allowlist.",
    hypothesis: "Agents are reaching MCP servers outside their approved allowlist, putting source code or business data in front of an unreviewed third party. Identify the servers, the principals, the destinations and the volume transferred, and whether the pattern is growing.",
    query: { categories: ["unsanctioned_mcp"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "unauthorized-skill", title: "Unauthorized skill and tool use", group: "Governance", severity: "High",
    blurb: "Skills invoked outside the application's approved skill set, including shell execution.",
    hypothesis: "Applications are invoking skills outside their approved set, which means the agent has more capability than its registration grants. Identify the skills, the applications and the principals, and assess what each skill could reach.",
    query: { categories: ["unauthorized_skill"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "shadow-ai", title: "Shadow AI: unregistered apps and unapproved models", group: "Governance", severity: "High",
    blurb: "Gateway traffic with no registered application, or a model outside the approved list.",
    hypothesis: "Company data is being sent to models and applications that are not registered or approved, so no template governs them. Identify the principals, the models, how much traffic is involved and what classes of data appear in it.",
    query: { categories: ["shadow_model", "unregistered_app"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "credentials", title: "Credentials and API keys in prompts", group: "Data protection", severity: "Critical",
    blurb: "SDP findings for service-account keys, API keys, passwords and private keys.",
    hypothesis: "Secrets are being pasted into AI applications. Identify every principal and application involved, which secret types appeared, and crucially which of these were NOT blocked, because an unblocked secret has reached the model provider and must be treated as exposed and rotated.",
    query: { categories: ["credential_exposure"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "pii-egress", title: "Customer records leaving through an agent", group: "Data protection", severity: "Critical",
    blurb: "Bulk PII findings paired with an outbound call to a destination outside the corporate estate.",
    hypothesis: "Customer or employee records are being moved out of the estate through an AI application: a bulk read followed by an outbound transfer. Correlate the read volume with the destination and the principal, establish whether the transfer completed or was blocked, and assess insider risk versus compromise.",
    query: { categories: ["data_egress", "data_leakage"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "egress", title: "Egress to non-corporate destinations", group: "Data protection", severity: "High",
    blurb: "Any agent tool call sending bytes to a destination outside the corporate estate.",
    hypothesis: "Agents are transferring data to destinations outside the corporate estate. Rank the destinations by volume, attribute each to a principal and application, and separate sanctioned third parties from unknown ones.",
    query: { categories: ["data_egress"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "regulated-data", title: "Payment card, SSN and restricted datasets", group: "Data protection", severity: "Critical",
    blurb: "PCI and SSN findings, and agent reads of datasets marked restricted.",
    hypothesis: "Regulated data is entering AI applications or being read by agents from restricted datasets. Identify the data classes, the applications and the principals, and state the compliance exposure for each — including whether enforcement blocked it.",
    query: { categories: ["payment_card_exposure", "restricted_dataset"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "malicious-uri", title: "Agents reaching flagged URLs", group: "Agent integrity", severity: "High",
    blurb: "Malicious-URI verdicts on content an agent fetched on a user's behalf.",
    hypothesis: "Agents with browsing capability fetched URLs the filter flagged. Identify the URLs, the principals, whether the fetched content was then summarised back to a user, and whether the same host appears more than once.",
    query: { categories: ["malicious_uri"], violationsOnly: true, daysBack: 30 },
  },
  {
    id: "enforcement-gap", title: "Violations that enforcement let through", group: "Governance", severity: "Critical",
    blurb: "Every recorded violation that was not blocked — usually an INSPECT_ONLY template.",
    hypothesis: "Some applications record violations without blocking them. Identify every unblocked violation, group it by application and template, and state plainly which templates need to move from INSPECT_ONLY to INSPECT_AND_BLOCK and what has already passed through them.",
    query: { unblockedOnly: true, daysBack: 30 },
  },
  {
    id: "rai", title: "Responsible-AI verdicts on internal use", group: "Governance", severity: "Medium",
    blurb: "Harassment, hate-speech and dangerous-content verdicts from internal applications.",
    hypothesis: "Internal users are generating content that trips responsible-AI filters. Summarise the categories and confidence levels by department, and note that these are conduct matters for HR rather than security incidents.",
    query: { categories: ["rai_violation"], violationsOnly: true, daysBack: 30 },
  },
];
