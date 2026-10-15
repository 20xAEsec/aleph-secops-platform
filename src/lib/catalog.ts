// Single source of truth for features: drives the sidebar, the home pillars and the blueprint
// pages, so they can't drift. `live` features run in this demo; `blueprint` features are
// documented with how they work in the full platform.

export type PillarId = "investigations" | "detection" | "intel";

export type Feature = {
  slug: string;
  title: string;
  pillar: PillarId;
  status: "live" | "blueprint";
  href: string;
  summary: string;
  how: string[];
  clever: string[];
};

export const PILLARS: { id: PillarId; title: string; kicker: string; blurb: string }[] = [
  { id: "investigations", kicker: "01", title: "Security Investigations", blurb: "Hunt hypotheses, investigate indicators and triage cases. Multi-agent pipelines return cited, MITRE-mapped reports." },
  { id: "detection", kicker: "02", title: "Detection Engineering", blurb: "Draft, lint, test and tune rules against real telemetry, and see coverage gaps ranked by risk." },
  { id: "intel", kicker: "03", title: "Threat Intelligence", blurb: "Indicator context, adversary gap analysis and external attack-surface monitoring in one place." },
];

const f = (x: Feature) => x;

export const FEATURES: Feature[] = [
  // ---- Security Investigations
  f({ slug: "threat-hunt", title: "Threat Hunt", pillar: "investigations", status: "live", href: "/hunt",
    summary: "Plain-English hypothesis in, MITRE-mapped hunt report out.",
    how: ["Basic and Advanced tiers compose different agent pipelines", "Coverage statistics run over every event; only a sample reaches the model", "Challenger agent argues the other side before the report is written"],
    clever: ["Pipelines degrade instead of dying: a failed stage becomes a labelled gap", "Deterministic evidence check flags any indicator the agents never actually saw"] }),
  f({ slug: "ioc-investigation", title: "IoC Investigation", pillar: "investigations", status: "live", href: "/investigate",
    summary: "Investigate an IP, domain, URL or hash, including defanged input.",
    how: ["Refangs and classifies input so tools search for what telemetry stores", "Intel and SOC case history are checked in parallel before anything is flagged"],
    clever: ["Prior SOC verdicts are weighed explicitly, so a past false positive tempers confidence"] }),
  f({ slug: "case-investigations", title: "Case Investigations", pillar: "investigations", status: "live", href: "/cases",
    summary: "AI triage of open SOAR cases ending in a structured verdict and one-click disposition.",
    how: ["Evidence is gathered deterministically before any model runs: case, alerts, entities, source rule, matched events", "Investigation pipeline follows a mandatory tool order"],
    clever: ["If the alert read fails, triage stops. Zero alerts would otherwise read as a novel case", "Dispositions are write-after-confirm and attributed to the analyst"] }),
  f({ slug: "host-discovery", title: "Host Discovery", pillar: "investigations", status: "live", href: "/host-discovery",
    summary: "Profile a host, IP or domain: peers, users, DNS, alerts and ownership.",
    how: ["Telemetry → Investigation pipeline with selectable depth", "Assessment from CLEAN to CONFIRMED COMPROMISED"],
    clever: ["IP↔host mappings are treated as time-bound (DHCP, VPN, NAT), so two machines never merge into one profile"] }),
  f({ slug: "incident-response", title: "Incident Response", pillar: "investigations", status: "blueprint", href: "/features/incident-response",
    summary: "For confirmed incidents: scope the compromise and plan eviction, NIST 800-61 style.",
    how: ["Up to 50 hosts and 100 IOCs, pivoting ±72h around the incident", "Ten always-on sections from scope to recovery, plus optional deep dives"],
    clever: ["The auto-drafted detection states plainly whether it compiles, fails, or is unvalidated"] }),
  f({ slug: "endpoint-analysis", title: "Endpoint Analysis", pillar: "investigations", status: "blueprint", href: "/features/endpoint-analysis",
    summary: "Forensic review of one host from EDR telemetry: processes, network, files, registry, logons.",
    how: ["Seven telemetry categories queried in parallel", "Process trees with LOLBin, encoded-command and persistence flags"],
    clever: ["Flagged events are kept first when results must be trimmed"] }),

  // ---- Detection Engineering
  f({ slug: "detection-generator", title: "Detection Generator", pillar: "detection", status: "live", href: "/detections",
    summary: "Describe a behaviour; get a linted, tested YARA-L, KQL or SPL rule.",
    how: ["Research agent confirms the fields exist before the rule is written", "Rule author follows team standards: required meta, risk scores, RE2-safe regex", "Validator lints structure and runs the rule against telemetry"],
    clever: ["Verdicts DEAD / OK / FP_STORM come from real match counts, not the model's opinion"] }),
  f({ slug: "coverage", title: "Detection Coverage", pillar: "detection", status: "live", href: "/coverage",
    summary: "ATT&CK coverage heatmap with gaps ranked by a transparent priority formula.",
    how: ["Rules mapped onto ATT&CK techniques; active vs dormant separated", "Gap priority = 0.45 × prevalence + 0.35 × telemetry fit + 0.20 × tactic weakness"],
    clever: ["Feeds Recommended Detections, which drops any suggestion that isn't in the gap index"] }),
  f({ slug: "detection-tuning", title: "Detection Tuning", pillar: "detection", status: "live", href: "/tuning",
    summary: "Tune noisy rules from the rules repo or a Jira ticket, with a before/after diff and measured volume impact.",
    how: ["Repo browser loads a rule and its 7-day match profile", "Analyst describes the tuning in a chat; ticket known-goods (or profile values ≥15% share) are the baseline", "Blast-radius estimate and lint before anything is proposed"],
    clever: ["The tuned rule differs from the original only by named exclusions: the detection logic is never rewritten", "Nothing deploys; the output is a reviewable change"] }),
  f({ slug: "rule-consolidation", title: "Rule Consolidation", pillar: "detection", status: "blueprint", href: "/features/rule-consolidation",
    summary: "Find duplicate and overlapping rules to reclaim multi-event quota.",
    how: ["Embed normalized rule text, cluster by cosine similarity", "One LLM call per cluster, compared against 30 days of detections"],
    clever: ["Nothing deploys automatically; the hand-off is a reviewable ticket"] }),
  f({ slug: "playbook-generator", title: "Playbook Generator", pillar: "detection", status: "blueprint", href: "/features/playbook-generator",
    summary: "Import-ready SOAR playbooks grounded in the tenant's live integration catalog.",
    how: ["Every step resolved against ~825 real actions", "Layered validation: deterministic, then schema-aware LLM, then repair"],
    clever: ["The catalog is an anti-hallucination whitelist; the model can't ship an action that doesn't exist"] }),
  f({ slug: "detection-intake", title: "Detection Intake", pillar: "detection", status: "blueprint", href: "/features/detection-intake",
    summary: "The detection-request queue arrives with a drafted rule for each ticket.",
    how: ["Ticket text plus PDF attachments feed the generator pipeline"],
    clever: ["Expired credentials are surfaced explicitly instead of showing an empty queue"] }),

  // ---- Threat Intelligence
  f({ slug: "ioc-overview", title: "IOC Overview", pillar: "intel", status: "live", href: "/ioc-overview",
    summary: "Threat-intel indicators as they exist in the SIEM, with detection counts and drill-down.",
    how: ["Reads the intel-synced data table; detail view adds 30 days of events"],
    clever: ["A last-known-good copy covers moments when the sync legitimately empties the table"] }),
  f({ slug: "apt-gap-analysis", title: "APT Gap Analysis", pillar: "intel", status: "blueprint", href: "/features/apt-gap-analysis",
    summary: "Measure visibility against one adversary's known techniques.",
    how: ["Intel agent gathers the actor's TTPs; investigation agent checks each"],
    clever: ["Each technique is rated VISIBLE / PARTIAL / BLIND / NO PATH"] }),
  f({ slug: "shodan-monitor", title: "Attack Surface Monitor", pillar: "intel", status: "blueprint", href: "/features/shodan-monitor",
    summary: "External exposure: services, vulnerabilities and trends from ingested scan data.",
    how: ["Dashboard reads scan data already in the SIEM; no live API calls per page view"],
    clever: ["Agents can still query the live scanner API through a tool when investigating"] }),
];

export const ASK_ALEPH = { title: "Ask Aleph", href: "/ask", summary: "Conversational, read-only assistant that routes big deliverables to the right pipeline." };

// Fixed route targets for Ask Aleph hand-offs. The model picks a key; it never writes a URL.
export const ROUTE_TARGETS: Record<string, { label: string; href: (prompt: string) => string }> = {
  hunt: { label: "Open in Threat Hunt", href: (p) => `/hunt?q=${encodeURIComponent(p)}` },
  investigate: { label: "Open in IoC Investigation", href: (p) => `/investigate?q=${encodeURIComponent(p)}` },
  detections: { label: "Open in Detection Generator", href: (p) => `/detections?q=${encodeURIComponent(p)}` },
};
