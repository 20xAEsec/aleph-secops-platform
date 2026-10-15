import type { KnownGood, RuleSpec } from "./builder";
import { getRule } from "./repo";

// Demo Jira queues. DETREQ = detection intake (new rules), DETTUNE = tuning requests against
// rules already in the repo. A real Jira client replaces this module; the shapes stay.

export type JiraTicket = {
  key: string;
  queue: "intake" | "tuning";
  summary: string;
  status: "To Do" | "In Progress" | "Ready for Eng";
  priority: "P1" | "P2" | "P3";
  reporter: string;
  created: string;
  labels: string[];
  // The four fields detection engineering asks for on every ticket
  detectionName: string;
  logSource: string;
  knownGoods: KnownGood[];
  primaryActivity: string;
  // intake: the rule shape the agent drafts; tuning: the repo rule to tune
  spec?: RuleSpec;
  rulePath?: string;
  // intake: simulated 7-day match counts before / after known-good exclusions
  simulated?: { raw: number; afterKnownGoods: number };
};

const r = String.raw;

const INTAKE: JiraTicket[] = [
  {
    key: "DETREQ-1042", queue: "intake", summary: "Detect Okta MFA push fatigue", status: "Ready for Eng", priority: "P1",
    reporter: "IR team", created: "2026-10-08", labels: ["identity", "okta", "detection-request"],
    detectionName: "Okta MFA Push Fatigue",
    logSource: "Okta System Log (OKTA)",
    primaryActivity: "A user denies five or more Okta Verify push prompts and then approves one within 10 minutes. This is the push-bombing pattern seen in the September incident (INC-2291).",
    knownGoods: [
      { label: "Help desk MFA test account (svc_okta_helpdesk_test)", clause: `not $deny.target.user.userid = "svc_okta_helpdesk_test"` },
      { label: "Okta Workflows health-check bot (okta_workflows)", clause: `not $deny.principal.user.userid = "okta_workflows"` },
    ],
    spec: {
      ruleName: "okta_mfa_push_fatigue", title: "Okta MFA Push Fatigue", description: "5+ denied Okta Verify pushes followed by an approval within 10 minutes",
      severity: "High", dataSource: "Okta System Log", tactic: "TA0006", technique: "T1621", subtechnique: "T1621",
      events: [
        `$deny.metadata.product_name = "Okta"`,
        `$deny.metadata.product_event_type = "user.authentication.auth_via_mfa"`,
        `$deny.security_result.action = "BLOCK"`,
        `$deny.target.user.userid = $user`,
        `$allow.metadata.product_name = "Okta"`,
        `$allow.metadata.product_event_type = "user.authentication.auth_via_mfa"`,
        `$allow.security_result.action = "ALLOW"`,
        `$allow.target.user.userid = $user`,
        `$deny.metadata.event_timestamp.seconds < $allow.metadata.event_timestamp.seconds`,
      ],
      match: "$user over 10m", condition: "#deny >= 5 and $allow", countVar: "$deny",
    },
    simulated: { raw: 9, afterKnownGoods: 2 },
  },
  {
    key: "DETREQ-1047", queue: "intake", summary: "Certutil used as a download cradle", status: "To Do", priority: "P2",
    reporter: "Threat Intel", created: "2026-10-09", labels: ["lolbin", "edr", "detection-request"],
    detectionName: "Certutil Remote Download",
    logSource: "CrowdStrike FDR → UDM (PROCESS_LAUNCH)",
    primaryActivity: "certutil.exe run with -urlcache, -split or -verifyctl and an http(s) URL on the command line. This LOLBin download pattern appeared in the FIN-TEMPEST intel report.",
    knownGoods: [
      { label: "SCCM site servers enrolling client certificates (sccm-site-01..03)", clause: r`not $e.principal.hostname = /^sccm-site-0[1-3]$/ nocase` },
      { label: "PKI team CRL publishing from pki-ca-01", clause: `not $e.principal.hostname = "pki-ca-01"` },
    ],
    spec: {
      ruleName: "certutil_remote_download", title: "Certutil Remote Download", description: "certutil.exe fetching a remote URL",
      severity: "High", dataSource: "EDR process telemetry", tactic: "TA0011", technique: "T1105", subtechnique: "T1105",
      events: [
        `$e.metadata.event_type = "PROCESS_LAUNCH"`,
        r`$e.target.process.file.full_path = /\\certutil\.exe$/ nocase`,
        `$e.target.process.command_line = /-urlcache|-split|-verifyctl/ nocase`,
        r`$e.target.process.command_line = /https?:\/\// nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 10m",
    },
    simulated: { raw: 41, afterKnownGoods: 3 },
  },
  {
    key: "DETREQ-1051", queue: "intake", summary: "Large uploads to personal cloud storage", status: "In Progress", priority: "P2",
    reporter: "Insider Risk", created: "2026-10-10", labels: ["dlp", "proxy", "detection-request"],
    detectionName: "Bulk Upload to Personal Cloud Storage",
    logSource: "Zscaler web proxy (ZSCALER_WEBPROXY)",
    primaryActivity: "One user uploads more than 500 MB in an hour to personal cloud storage (Dropbox, personal Google Drive, Mega, WeTransfer).",
    knownGoods: [
      { label: "Corporate Box tenant (acme.app.box.com)", clause: r`not $e.target.hostname = /^acme\.(app\.)?box\.com$/ nocase` },
      { label: "Veeam backup servers to Wasabi (bkp-veeam-01/02)", clause: r`not $e.principal.hostname = /^bkp-veeam-0[12]$/ nocase` },
    ],
    spec: {
      ruleName: "bulk_upload_personal_cloud", title: "Bulk Upload to Personal Cloud Storage", description: "500 MB+ uploaded to personal cloud storage by one user within an hour",
      severity: "Medium", dataSource: "Zscaler web proxy", tactic: "TA0010", technique: "T1567", subtechnique: "T1567.002",
      events: [
        `$e.metadata.event_type = "NETWORK_HTTP"`,
        `$e.network.http.method = /POST|PUT/`,
        r`$e.target.hostname = /dropbox(usercontent)?\.com|drive\.google\.com|mega\.nz|wetransfer\.com/ nocase`,
        `$e.principal.user.userid = $user`,
      ],
      match: "$user over 1h",
      outcome: ["$total_bytes = sum($e.network.sent_bytes)"],
      condition: "$e and $total_bytes > 524288000",
    },
    simulated: { raw: 27, afterKnownGoods: 4 },
  },
  {
    key: "DETREQ-1055", queue: "intake", summary: "New local admin account created", status: "To Do", priority: "P2",
    reporter: "SOC Tier 2", created: "2026-10-11", labels: ["windows", "persistence", "detection-request"],
    detectionName: "Local Admin Account Created",
    logSource: "Windows Security Event Log (4720, 4732)",
    primaryActivity: "A local account is created (4720) and added to the local Administrators group (4732) on the same host within 15 minutes.",
    knownGoods: [
      { label: "LAPS-managed account rotation (ACME_LAPS)", clause: `not $add.target.user.userid = "ACME_LAPS"` },
      { label: "Autopilot imaging on the build VLAN (10.40.0.0/22)", clause: `not net.ip_in_range_cidr($create.principal.ip, "10.40.0.0/22")` },
    ],
    spec: {
      ruleName: "local_admin_account_created", title: "Local Admin Account Created", description: "Local account created and added to Administrators within 15 minutes",
      severity: "High", dataSource: "Windows Security Event Log", tactic: "TA0003", technique: "T1136", subtechnique: "T1136.001",
      events: [
        `$create.metadata.product_event_type = "4720"`,
        `$create.target.user.userid = $acct`,
        `$create.principal.hostname = $host`,
        `$add.metadata.product_event_type = "4732"`,
        `$add.target.group.group_display_name = /Administrators/ nocase`,
        `$add.target.user.userid = $acct`,
        `$add.principal.hostname = $host`,
      ],
      match: "$host, $acct over 15m", condition: "$create and $add", countVar: "$add",
    },
    simulated: { raw: 64, afterKnownGoods: 1 },
  },
  {
    key: "DETREQ-1060", queue: "intake", summary: "AWS root account console sign-in", status: "Ready for Eng", priority: "P1",
    reporter: "Cloud Security", created: "2026-10-13", labels: ["aws", "cloudtrail", "detection-request"],
    detectionName: "AWS Root Console Sign-in",
    logSource: "AWS CloudTrail (AWS_CLOUDTRAIL)",
    primaryActivity: "Any successful AWS console sign-in by the root user. Root should only be used through the documented break-glass procedure.",
    knownGoods: [
      { label: "Approved break-glass procedure from the SOC jump IP (203.0.113.10)", clause: `not $e.principal.ip = "203.0.113.10"` },
    ],
    spec: {
      ruleName: "aws_root_console_signin", title: "AWS Root Console Sign-in", description: "Successful AWS console sign-in by the root user",
      severity: "Critical", dataSource: "AWS CloudTrail", tactic: "TA0001", technique: "T1078", subtechnique: "T1078.004",
      events: [
        `$e.metadata.product_name = "AWS CloudTrail"`,
        `$e.metadata.product_event_type = "ConsoleLogin"`,
        `$e.principal.user.userid = "root"`,
        `$e.security_result.action = "ALLOW"`,
        `$e.target.resource.product_object_id = $account`,
      ],
      match: "$account over 5m",
    },
    simulated: { raw: 3, afterKnownGoods: 0 },
  },
];

// Tuning tickets reference repo rules; their known-goods are entries from the rule's match profile.
const TUNING_DEFS: (Omit<JiraTicket, "knownGoods" | "queue" | "logSource" | "detectionName"> & { rulePath: string; knownGoodIds: string[] })[] = [
  {
    key: "DETTUNE-318", summary: "DNS beacon rule firing ~1,450/day", status: "Ready for Eng", priority: "P1", reporter: "SOC Tier 1", created: "2026-10-07",
    labels: ["noisy", "alert-fatigue"], rulePath: "rules/command_and_control/dns_beacon_fixed_interval.yaral", knownGoodIds: ["m365", "cloudsink", "zscaler"],
    primaryActivity: "Workstations repeatedly resolving the same domain at a fixed interval, especially newly registered or low-reputation domains (C2 beaconing).",
  },
  {
    key: "DETTUNE-322", summary: "LSASS access alerts from our own EDR/AV", status: "To Do", priority: "P2", reporter: "SOC Tier 2", created: "2026-10-09",
    labels: ["noisy", "edr"], rulePath: "rules/credential_access/lsass_memory_access.yaral", knownGoodIds: ["defender", "falcon"],
    primaryActivity: "Credential dumping: unsigned or unusual processes (procdump, comsvcs MiniDump, mimikatz) opening lsass.exe.",
  },
  {
    key: "DETTUNE-327", summary: "Kerberoasting rule triggers on svc_sql_legacy", status: "In Progress", priority: "P2", reporter: "Identity Team", created: "2026-10-10",
    labels: ["noisy", "active-directory"], rulePath: "rules/credential_access/kerberoasting_rc4_tgs.yaral", knownGoodIds: ["sqllegacy"],
    primaryActivity: "A single user account requesting RC4 service tickets for many SPNs in a short window (Kerberoasting).",
  },
  {
    key: "DETTUNE-331", summary: "Impossible travel false positives from Zscaler Dublin", status: "To Do", priority: "P3", reporter: "SOC Tier 1", created: "2026-10-11",
    labels: ["noisy", "vpn"], rulePath: "rules/initial_access/vpn_login_impossible_travel.yaral", knownGoodIds: ["zscaler-dub"],
    primaryActivity: "The same user authenticating to VPN from two countries within an hour, which suggests credential theft or session hijack.",
  },
  {
    key: "DETTUNE-335", summary: "Run-key rule: OneDrive and Slack auto-start noise", status: "To Do", priority: "P3", reporter: "SOC Tier 1", created: "2026-10-12",
    labels: ["noisy", "persistence"], rulePath: "rules/persistence/registry_run_key_added.yaral", knownGoodIds: ["onedrive", "slack"],
    primaryActivity: "New Run / RunOnce values pointing at user-writable or unusual paths: persistence for malware loaders.",
  },
];

const TUNING: JiraTicket[] = TUNING_DEFS.map(({ knownGoodIds, ...t }) => {
  const rule = getRule(t.rulePath)!;
  return {
    ...t,
    queue: "tuning",
    detectionName: rule.spec.title,
    logSource: rule.spec.dataSource,
    knownGoods: rule.noise.filter((n) => knownGoodIds.includes(n.id!)),
  };
});

export function listTickets(queue: "intake" | "tuning"): JiraTicket[] {
  return queue === "intake" ? INTAKE : TUNING;
}

export function getTicket(key: string): JiraTicket | undefined {
  return [...INTAKE, ...TUNING].find((t) => t.key === key);
}
