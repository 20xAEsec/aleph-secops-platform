import { buildYaraL, type KnownGood, type RuleSpec } from "./builder";

// Demo detection-rules repository (stands in for the team's GitHub Enterprise repo).
// `noise` is the rule's match profile: benign sources that account for a share of its
// current detections. Tuning turns selected noise entries into exclusions.

export type RepoRule = {
  path: string; // e.g. rules/command_and_control/dns_beacon_fixed_interval.yaral
  folder: string;
  file: string;
  version: string;
  perDay: number; // current detections per day
  spec: RuleSpec;
  noise: KnownGood[];
  text: string; // built rule text
};

const r = String.raw;

type Def = Omit<RepoRule, "path" | "file" | "text">;

const DEFS: Def[] = [
  // ---------------- credential_access
  {
    folder: "credential_access", version: "1.4", perDay: 340,
    spec: {
      ruleName: "lsass_memory_access", title: "LSASS Memory Access", description: "Non-system process opening a handle to lsass.exe",
      severity: "High", dataSource: "EDR process telemetry", tactic: "TA0006", technique: "T1003", subtechnique: "T1003.001",
      events: [
        `$e.metadata.event_type = "PROCESS_OPEN"`,
        r`$e.target.process.file.full_path = /\\lsass\.exe$/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 5m",
    },
    noise: [
      { id: "defender", label: "Microsoft Defender AV scanning (MsMpEng.exe)", field: "principal.process.file.full_path", value: r`...\Windows Defender\Platform\MsMpEng.exe`, share: 0.48, clause: r`not $e.principal.process.file.full_path = /\\Windows Defender\\Platform\\[0-9.\-]+\\MsMpEng\.exe$/ nocase` },
      { id: "falcon", label: "CrowdStrike Falcon sensor (CSFalconService.exe)", field: "principal.process.file.full_path", value: r`C:\Program Files\CrowdStrike\CSFalconService.exe`, share: 0.21, clause: r`not $e.principal.process.file.full_path = /^C:\\Program Files\\CrowdStrike\\CSFalconService\.exe$/ nocase` },
      { id: "splunkd", label: "Splunk forwarder perfmon (splunkd.exe)", field: "principal.process.file.full_path", value: r`C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe`, share: 0.07, clause: r`not $e.principal.process.file.full_path = /\\SplunkUniversalForwarder\\bin\\splunkd\.exe$/ nocase` },
    ],
  },
  {
    folder: "credential_access", version: "1.1", perDay: 95,
    spec: {
      ruleName: "kerberoasting_rc4_tgs", title: "Kerberoasting via RC4 TGS Requests", description: "One account requesting RC4-encrypted service tickets for 3+ services within an hour",
      severity: "High", dataSource: "Windows Security Event Log (4769)", tactic: "TA0006", technique: "T1558", subtechnique: "T1558.003",
      events: [
        `$e.metadata.product_event_type = "4769"`,
        `$e.additional.fields["TicketEncryptionType"] = "0x17"`,
        `$e.target.user.userid = $svc`,
        `$e.principal.user.userid = $requester`,
      ],
      match: "$requester over 1h",
      condition: "$e and #svc >= 3",
    },
    noise: [
      { id: "sqllegacy", label: "Legacy SQL 2008 cluster service account (svc_sql_legacy) requires RC4", field: "principal.user.userid", value: "svc_sql_legacy", share: 0.62, clause: `not $e.principal.user.userid = "svc_sql_legacy"` },
      { id: "citrix", label: "Citrix XenApp brokers (ctx-broker-0x)", field: "principal.hostname", value: "ctx-broker-01..04", share: 0.14, clause: r`not $e.principal.hostname = /^ctx-broker-0[1-4]$/ nocase` },
    ],
  },
  // ---------------- execution
  {
    folder: "execution", version: "2.0", perDay: 14,
    spec: {
      ruleName: "office_spawns_encoded_powershell", title: "Office Spawns Encoded PowerShell", description: "Office application launching PowerShell with an encoded command",
      severity: "High", dataSource: "EDR process telemetry", tactic: "TA0002", technique: "T1059", subtechnique: "T1059.001",
      events: [
        `$e.metadata.event_type = "PROCESS_LAUNCH"`,
        r`$e.principal.process.file.full_path = /\\(winword|excel|outlook|powerpnt)\.exe$/ nocase`,
        r`$e.target.process.file.full_path = /\\powershell\.exe$/ nocase`,
        r`$e.target.process.command_line = /\s-(e|en|enc|encodedcommand)\s/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 10m",
    },
    noise: [
      { id: "adaptive", label: "Finance Excel add-in refresh (AdaptivePlanning.xlam)", field: "principal.process.command_line", value: "EXCEL.EXE … AdaptivePlanning.xlam", share: 0.66, clause: r`not $e.principal.process.command_line = /AdaptivePlanning\.xlam/ nocase` },
    ],
  },
  {
    folder: "execution", version: "1.2", perDay: 210,
    spec: {
      ruleName: "rundll32_without_dll_argument", title: "Rundll32 Without DLL Argument", description: "rundll32.exe executed without a DLL on the command line",
      severity: "Medium", dataSource: "EDR process telemetry", tactic: "TA0005", technique: "T1218", subtechnique: "T1218.011",
      events: [
        `$e.metadata.event_type = "PROCESS_LAUNCH"`,
        r`$e.target.process.file.full_path = /\\rundll32\.exe$/ nocase`,
        r`not $e.target.process.command_line = /\.dll/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 5m",
    },
    noise: [
      { id: "uso", label: "Windows Update orchestrator (parent usoclient.exe)", field: "principal.process.file.full_path", value: r`C:\Windows\System32\usoclient.exe`, share: 0.44, clause: r`not $e.principal.process.file.full_path = /^C:\\Windows\\System32\\usoclient\.exe$/ nocase` },
      { id: "intune", label: "Intune Management Extension agent", field: "principal.process.file.full_path", value: "…IntuneWindowsAgent.exe", share: 0.29, clause: r`not $e.principal.process.file.full_path = /\\Microsoft Intune Management Extension\\Microsoft\.Management\.Services\.IntuneWindowsAgent\.exe$/ nocase` },
    ],
  },
  {
    folder: "execution", version: "1.0", perDay: 22,
    spec: {
      ruleName: "wmic_remote_process_create", title: "WMIC Remote Process Creation", description: "wmic.exe creating a process on a remote node",
      severity: "High", dataSource: "EDR process telemetry", tactic: "TA0002", technique: "T1047", subtechnique: "T1047",
      events: [
        `$e.metadata.event_type = "PROCESS_LAUNCH"`,
        r`$e.target.process.file.full_path = /\\wbem\\wmic\.exe$/ nocase`,
        r`$e.target.process.command_line = /\/node:.+process\s+call\s+create/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 10m",
    },
    noise: [
      { id: "lansweeper", label: "IT asset inventory scanners (it-lansweep-01/02)", field: "principal.hostname", value: "it-lansweep-01, it-lansweep-02", share: 0.71, clause: r`not $e.principal.hostname = /^it-lansweep-0[12]$/ nocase` },
    ],
  },
  // ---------------- command_and_control
  {
    folder: "command_and_control", version: "1.3", perDay: 1450,
    spec: {
      ruleName: "dns_beacon_fixed_interval", title: "DNS Beacon at Fixed Interval", description: "Workstation resolving the same domain 12+ times per hour",
      severity: "Medium", dataSource: "DNS resolver logs", tactic: "TA0011", technique: "T1071", subtechnique: "T1071.004",
      events: [
        `$e.metadata.event_type = "NETWORK_DNS"`,
        `$e.network.dns.questions.name = $domain`,
        r`$e.principal.hostname = /^(fin|eng|hr|ops)-(ws|lt)-/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host, $domain over 1h",
      condition: "#e >= 12",
    },
    noise: [
      { id: "m365", label: "Microsoft 365 telemetry (*.events.data.microsoft.com)", field: "network.dns.questions.name", value: "self.events.data.microsoft.com", share: 0.38, clause: r`not $e.network.dns.questions.name = /\.events\.data\.microsoft\.com$/ nocase` },
      { id: "cloudsink", label: "CrowdStrike cloud (*.cloudsink.net)", field: "network.dns.questions.name", value: "ts01-b.cloudsink.net", share: 0.24, clause: r`not $e.network.dns.questions.name = /\.cloudsink\.net$/ nocase` },
      { id: "zscaler", label: "Zscaler PAC refresh (pac.zscaler.net)", field: "network.dns.questions.name", value: "pac.zscaler.net", share: 0.17, clause: `not $e.network.dns.questions.name = "pac.zscaler.net"` },
    ],
  },
  {
    folder: "command_and_control", version: "1.1", perDay: 640,
    spec: {
      ruleName: "scripted_user_agent_outbound", title: "Scripted User-Agent to External Host", description: "Outbound HTTP from workstations with scripting-library user agents",
      severity: "Low", dataSource: "Zscaler web proxy", tactic: "TA0011", technique: "T1071", subtechnique: "T1071.001",
      events: [
        `$e.metadata.event_type = "NETWORK_HTTP"`,
        `$e.network.http.user_agent = /python-requests|curl\\/|Go-http-client|PowerShell/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 15m",
    },
    noise: [
      { id: "airflow", label: "Data-eng Airflow workers (airflow-wkr-*)", field: "principal.hostname", value: "airflow-wkr-01..12", share: 0.52, clause: r`not $e.principal.hostname = /^airflow-wkr-[0-9]{2}$/ nocase` },
      { id: "chocolatey", label: "Chocolatey package updates (community.chocolatey.org)", field: "target.hostname", value: "community.chocolatey.org", share: 0.16, clause: `not $e.target.hostname = "community.chocolatey.org"` },
    ],
  },
  // ---------------- initial_access
  {
    folder: "initial_access", version: "1.2", perDay: 75,
    spec: {
      ruleName: "vpn_login_impossible_travel", title: "VPN Login Impossible Travel", description: "Same user logs in from two countries within an hour",
      severity: "Medium", dataSource: "Palo Alto GlobalProtect", tactic: "TA0001", technique: "T1078", subtechnique: "T1078.004",
      events: [
        `$a.metadata.event_type = "USER_LOGIN"`,
        `$a.target.user.userid = $user`,
        `$b.metadata.event_type = "USER_LOGIN"`,
        `$b.target.user.userid = $user`,
        `$a.principal.location.country_or_region != $b.principal.location.country_or_region`,
        `$a.metadata.event_timestamp.seconds < $b.metadata.event_timestamp.seconds`,
      ],
      match: "$user over 1h",
      condition: "$a and $b",
      countVar: "$b",
    },
    noise: [
      { id: "zscaler-dub", label: "Corporate Zscaler egress in Dublin (165.225.80.0/20)", field: "principal.ip", value: "165.225.80.0/20 (IE)", share: 0.58, clause: `not net.ip_in_range_cidr($b.principal.ip, "165.225.80.0/20")` },
      { id: "carrier", label: "Mobile carrier geolocation drift (US carriers)", field: "network.carrier_name", value: "T-Mobile / Verizon / AT&T", share: 0.18, clause: `not $b.network.carrier_name = /T-Mobile|Verizon|AT&T/ nocase` },
    ],
  },
  // ---------------- persistence
  {
    folder: "persistence", version: "1.5", perDay: 180,
    spec: {
      ruleName: "scheduled_task_from_user_profile", title: "Scheduled Task Pointing at User Profile", description: "schtasks /create with an action inside a user's AppData folder",
      severity: "Medium", dataSource: "EDR process telemetry", tactic: "TA0003", technique: "T1053", subtechnique: "T1053.005",
      events: [
        `$e.metadata.event_type = "PROCESS_LAUNCH"`,
        r`$e.target.process.file.full_path = /\\schtasks\.exe$/ nocase`,
        r`$e.target.process.command_line = /\/create.+\\Users\\[^\\]+\\AppData\\/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 10m",
    },
    noise: [
      { id: "teams", label: "Microsoft Teams updater (Teams\\Update.exe)", field: "target.process.command_line", value: r`…\AppData\Local\Microsoft\Teams\Update.exe`, share: 0.41, clause: r`not $e.target.process.command_line = /\\AppData\\Local\\Microsoft\\Teams\\Update\.exe/ nocase` },
      { id: "zoom", label: "Zoom auto-update (Zoom\\bin\\Installer.exe)", field: "target.process.command_line", value: r`…\AppData\Roaming\Zoom\bin\Installer.exe`, share: 0.23, clause: r`not $e.target.process.command_line = /\\AppData\\Roaming\\Zoom\\bin\\Installer\.exe/ nocase` },
      { id: "chrome", label: "Chrome per-user updater (GoogleUpdate.exe)", field: "target.process.command_line", value: r`…\AppData\Local\Google\Update\GoogleUpdate.exe`, share: 0.12, clause: r`not $e.target.process.command_line = /\\AppData\\Local\\Google\\Update\\GoogleUpdate\.exe/ nocase` },
    ],
  },
  {
    folder: "persistence", version: "1.1", perDay: 520,
    spec: {
      ruleName: "registry_run_key_added", title: "Registry Run Key Added", description: "New value written under a CurrentVersion\\Run key",
      severity: "Low", dataSource: "EDR registry telemetry", tactic: "TA0003", technique: "T1547", subtechnique: "T1547.001",
      events: [
        `$e.metadata.event_type = "REGISTRY_MODIFICATION"`,
        r`$e.target.registry.registry_key = /\\CurrentVersion\\Run(Once)?$/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 5m",
    },
    noise: [
      { id: "onedrive", label: "OneDrive sync client (OneDrive.exe /background)", field: "target.registry.registry_value_data", value: r`…\Microsoft\OneDrive\OneDrive.exe /background`, share: 0.37, clause: r`not $e.target.registry.registry_value_data = /\\Microsoft\\OneDrive\\OneDrive\.exe" \/background$/ nocase` },
      { id: "slack", label: "Slack desktop auto-start (slack.exe --startup)", field: "target.registry.registry_value_data", value: r`…\slack\slack.exe --process-start-args --startup`, share: 0.19, clause: r`not $e.target.registry.registry_value_data = /\\AppData\\Local\\slack\\slack\.exe.+--startup/ nocase` },
      { id: "spotify", label: "Spotify auto-start", field: "target.registry.registry_value_data", value: r`…\Spotify\Spotify.exe --autostart`, share: 0.08, clause: r`not $e.target.registry.registry_value_data = /\\Spotify\\Spotify\.exe.+--autostart/ nocase` },
    ],
  },
  // ---------------- lateral_movement
  {
    folder: "lateral_movement", version: "1.0", perDay: 31,
    spec: {
      ruleName: "psexec_service_install", title: "PsExec Service Installed", description: "PSEXESVC service created on a host",
      severity: "High", dataSource: "Windows System Event Log (7045)", tactic: "TA0008", technique: "T1569", subtechnique: "T1569.002",
      events: [
        `$e.metadata.event_type = "SERVICE_CREATION"`,
        `$e.target.process.file.full_path = /PSEXESVC/ nocase`,
        `$e.principal.hostname = $host`,
      ],
      match: "$host over 5m",
    },
    noise: [
      { id: "jump", label: "IT admin jump hosts (it-jump-01..04)", field: "src.hostname", value: "it-jump-01..04", share: 0.74, clause: r`not $e.src.hostname = /^it-jump-0[1-4]$/ nocase` },
    ],
  },
];

export const RULES: RepoRule[] = DEFS.map((d) => {
  const file = `${d.spec.ruleName}.yaral`;
  return { ...d, file, path: `rules/${d.folder}/${file}`, text: buildYaraL(d.spec, [], { version: d.version }) };
});

export function getRule(path: string): RepoRule | undefined {
  return RULES.find((x) => x.path === path);
}

// Folder → rules tree for the repo browser.
export function ruleTree() {
  const folders = [...new Set(RULES.map((x) => x.folder))].sort();
  return folders.map((folder) => ({
    folder,
    rules: RULES.filter((x) => x.folder === folder).map(({ path, file, spec, perDay, version }) => ({
      path, file, title: spec.title, severity: spec.severity, perDay, version,
    })),
  }));
}
