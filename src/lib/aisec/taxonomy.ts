// AI-security violation taxonomy and its framework mapping. Kept free of any dependency on the log
// corpus so client components can import the labels without pulling the generator into the bundle.

export type ViolationCategory =
  | "prompt_injection" | "jailbreak" | "data_leakage" | "credential_exposure" | "payment_card_exposure"
  | "unsanctioned_mcp" | "unauthorized_skill" | "shadow_model" | "unregistered_app"
  | "data_egress" | "malicious_uri" | "rai_violation" | "restricted_dataset";

export const CATEGORY_LABEL: Record<ViolationCategory, string> = {
  prompt_injection: "Indirect prompt injection",
  jailbreak: "Jailbreak / policy evasion",
  data_leakage: "Sensitive data in prompt or response",
  credential_exposure: "Credential or key exposure",
  payment_card_exposure: "Payment card data",
  unsanctioned_mcp: "Unsanctioned MCP server",
  unauthorized_skill: "Unauthorized skill use",
  shadow_model: "Unapproved model",
  unregistered_app: "Unregistered application",
  data_egress: "Egress to non-corporate destination",
  malicious_uri: "Malicious URI",
  rai_violation: "Responsible-AI violation",
  restricted_dataset: "Restricted dataset access",
};

export const CATEGORY_SEVERITY: Record<ViolationCategory, "Critical" | "High" | "Medium"> = {
  prompt_injection: "Critical",
  jailbreak: "Medium",
  data_leakage: "High",
  credential_exposure: "Critical",
  payment_card_exposure: "Critical",
  unsanctioned_mcp: "High",
  unauthorized_skill: "High",
  shadow_model: "High",
  unregistered_app: "High",
  data_egress: "High",
  malicious_uri: "High",
  rai_violation: "Medium",
  restricted_dataset: "Critical",
};

// Deterministic framework mapping. Agents explain the mapping; they never invent the IDs.
// OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS.
export const OWASP_MAP: Record<ViolationCategory, { owasp: string; atlas: string }> = {
  prompt_injection: { owasp: "LLM01:2025 Prompt Injection", atlas: "AML.T0051.001 LLM Prompt Injection: Indirect" },
  jailbreak: { owasp: "LLM01:2025 Prompt Injection", atlas: "AML.T0054 LLM Jailbreak" },
  data_leakage: { owasp: "LLM02:2025 Sensitive Information Disclosure", atlas: "AML.T0057 LLM Data Leakage" },
  credential_exposure: { owasp: "LLM02:2025 Sensitive Information Disclosure", atlas: "AML.T0057 LLM Data Leakage" },
  payment_card_exposure: { owasp: "LLM02:2025 Sensitive Information Disclosure", atlas: "AML.T0057 LLM Data Leakage" },
  restricted_dataset: { owasp: "LLM02:2025 Sensitive Information Disclosure", atlas: "AML.T0057 LLM Data Leakage" },
  unsanctioned_mcp: { owasp: "LLM03:2025 Supply Chain", atlas: "AML.T0010 AI Supply Chain Compromise" },
  unauthorized_skill: { owasp: "LLM06:2025 Excessive Agency", atlas: "AML.T0053 LLM Plugin Compromise" },
  shadow_model: { owasp: "LLM03:2025 Supply Chain", atlas: "AML.T0010 AI Supply Chain Compromise" },
  unregistered_app: { owasp: "LLM03:2025 Supply Chain", atlas: "AML.T0010 AI Supply Chain Compromise" },
  data_egress: { owasp: "LLM02:2025 Sensitive Information Disclosure", atlas: "AML.T0025 Exfiltration via Cyber Means" },
  malicious_uri: { owasp: "LLM05:2025 Improper Output Handling", atlas: "AML.T0051 LLM Prompt Injection" },
  rai_violation: { owasp: "LLM09:2025 Misinformation", atlas: "AML.T0048 External Harms" },
};
