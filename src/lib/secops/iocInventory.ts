import { PLANTED } from "./telemetry";

// Demo IoC repository (stands in for the ThreatQ → Chronicle intel-synced data table). Indicators
// tied to the planted telemetry threads link to the open Falcon cases in ./crowdstrike, so the
// dashboard, the case queue and IoC Investigation all tell the same story. Everything is anchored
// to a fixed date so server and client render identically.

export type IocKind = "ipv4" | "domain" | "url" | "sha256" | "md5" | "email";
export type IocSeverity = "Critical" | "High" | "Medium" | "Low";
export type IocStatus = "active" | "monitoring" | "expired";
export type Motivation = "Espionage" | "Financial" | "Destructive" | "Hacktivism" | "Test";

export type ThreatActor = { name: string; aliases: string[]; country: string; countryName: string; motivation: Motivation };

export type OpenDetection = { caseId: string; severity: IocSeverity; status: "New" | "In Progress" | "Reopened"; alertName: string; host: string };

export type IocEntry = {
  id: string;
  value: string;
  kind: IocKind;
  actor: ThreatActor;
  severity: IocSeverity;
  confidence: number; // 0-100
  status: IocStatus;
  source: string;
  tlp: "RED" | "AMBER" | "GREEN" | "CLEAR";
  technique: string;
  tags: string[];
  firstSeen: string; // YYYY-MM-DD
  lastSeen: string;
  rules: number; // detection rules referencing the indicator
  hits7d: number;
  hits30d: number;
  spark: number[]; // last 14 days of matches, oldest first
  openDetection?: OpenDetection;
};

export const AS_OF = "2026-10-15";
const ANCHOR = Date.UTC(2026, 9, 15);
const day = (ago: number) => new Date(ANCHOR - ago * 86_400_000).toISOString().slice(0, 10);

const ACTORS = {
  tempest: { name: "FIN-TEMPEST", aliases: ["tracked cluster", "UNC-4471"], country: "RU", countryName: "Russia (assessed)", motivation: "Financial" },
  apt29: { name: "APT29", aliases: ["Cozy Bear", "Midnight Blizzard"], country: "RU", countryName: "Russia", motivation: "Espionage" },
  apt28: { name: "APT28", aliases: ["Fancy Bear", "Forest Blizzard"], country: "RU", countryName: "Russia", motivation: "Espionage" },
  sandworm: { name: "Sandworm", aliases: ["APT44", "Seashell Blizzard"], country: "RU", countryName: "Russia", motivation: "Destructive" },
  apt41: { name: "APT41", aliases: ["Wicked Panda", "Brass Typhoon"], country: "CN", countryName: "China", motivation: "Espionage" },
  volt: { name: "Volt Typhoon", aliases: ["Vanguard Panda", "BRONZE SILHOUETTE"], country: "CN", countryName: "China", motivation: "Espionage" },
  mustang: { name: "Mustang Panda", aliases: ["TA416", "RedDelta"], country: "CN", countryName: "China", motivation: "Espionage" },
  lazarus: { name: "Lazarus Group", aliases: ["HIDDEN COBRA", "Diamond Sleet"], country: "KP", countryName: "North Korea", motivation: "Financial" },
  kimsuky: { name: "Kimsuky", aliases: ["APT43", "Emerald Sleet"], country: "KP", countryName: "North Korea", motivation: "Espionage" },
  muddy: { name: "MuddyWater", aliases: ["Mango Sandstorm", "TA450"], country: "IR", countryName: "Iran", motivation: "Espionage" },
  apt35: { name: "APT35", aliases: ["Charming Kitten", "Mint Sandstorm"], country: "IR", countryName: "Iran", motivation: "Espionage" },
  fin7: { name: "FIN7", aliases: ["Carbanak", "Sangria Tempest"], country: "RU", countryName: "Russia", motivation: "Financial" },
  spider: { name: "Scattered Spider", aliases: ["UNC3944", "Octo Tempest"], country: "US", countryName: "US / UK", motivation: "Financial" },
  ta505: { name: "TA505", aliases: ["Hive0065", "Lace Tempest"], country: "RU", countryName: "Russia", motivation: "Financial" },
  none: { name: "No attribution", aliases: ["AV test signature"], country: "—", countryName: "n/a", motivation: "Test" },
} satisfies Record<string, ThreatActor>;

// Small deterministic RNG so the mock series are stable across renders.
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// 14-day sparkline that sums to the 7d / 30d hit counts we quote.
function spark(seed: number, hits7d: number, hits30d: number): number[] {
  const r = rng(seed);
  const older = Math.max(0, Math.round(((hits30d - hits7d) * 7) / 23));
  const spread = (total: number, n: number) => {
    const w = Array.from({ length: n }, () => r() + 0.15);
    const sum = w.reduce((a, b) => a + b, 0);
    const out = w.map((x) => Math.floor((x / sum) * total));
    out[n - 1] += total - out.reduce((a, b) => a + b, 0);
    return out;
  };
  return [...spread(older, 7), ...spread(hits7d, 7)];
}

type Seed = Omit<IocEntry, "id" | "spark" | "firstSeen" | "lastSeen"> & { first: number; last: number };

const SEEDS: Seed[] = [
  // ---- Linked to open Falcon cases (pinned to the top of the inventory)
  { value: PLANTED.beaconIp, kind: "ipv4", actor: ACTORS.tempest, severity: "Critical", confidence: 88, status: "active", source: "ThreatQ", tlp: "AMBER",
    technique: "T1071.001 Web Protocols", tags: ["c2", "cobalt-strike", "tor-exit"], first: 43, last: 0, rules: 4, hits7d: 1184, hits30d: 1201,
    openDetection: { caseId: "CS-24816", severity: "High", status: "In Progress", alertName: "Periodic outbound connections to newly registered domain", host: PLANTED.beaconHost } },
  { value: PLANTED.beaconDomain, kind: "domain", actor: ACTORS.tempest, severity: "Critical", confidence: 81, status: "active", source: "ThreatQ", tlp: "AMBER",
    technique: "T1071.001 Web Protocols", tags: ["c2", "newly-registered"], first: 6, last: 0, rules: 3, hits7d: 1190, hits30d: 1190,
    openDetection: { caseId: "CS-24816", severity: "High", status: "In Progress", alertName: "Periodic outbound connections to newly registered domain", host: PLANTED.beaconHost } },
  { value: "9f2c4e71b0d8a3f56e19c7d42ab8e0f3c6d17a95e2b4f80c13d6a7e9b52f1c84", kind: "sha256", actor: ACTORS.tempest, severity: "Critical", confidence: 92, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1566.001 Spearphishing Attachment", tags: ["maldoc", "xlsm", "q3-invoice-lure"], first: 3, last: 0, rules: 2, hits7d: 3, hits30d: 3,
    openDetection: { caseId: "CS-24817", severity: "Critical", status: "New", alertName: "Office application spawned encoded PowerShell", host: PLANTED.beaconHost } },
  { value: "91.219.236.18", kind: "ipv4", actor: ACTORS.apt29, severity: "High", confidence: 72, status: "active", source: "ThreatQ", tlp: "AMBER",
    technique: "T1078.002 Domain Accounts", tags: ["vpn-abuse", "password-spray"], first: 119, last: 0, rules: 2, hits7d: 41, hits30d: 63,
    openDetection: { caseId: "CS-24814", severity: "High", status: "New", alertName: "Service account authenticated from unusual country", host: "vpn-gw-01" } },
  { value: PLANTED.typosquat, kind: "domain", actor: ACTORS.ta505, severity: "High", confidence: 64, status: "active", source: "ThreatQ", tlp: "GREEN",
    technique: "T1583.001 Domains", tags: ["typosquat", "phishing-infra", "msft-lure"], first: 14, last: 1, rules: 2, hits7d: 38, hits30d: 52,
    openDetection: { caseId: "CS-24811", severity: "Medium", status: "Reopened", alertName: "DNS lookups to typosquatted Microsoft domain", host: "fin-ws-011" } },
  { value: PLANTED.typosquatIp, kind: "ipv4", actor: ACTORS.ta505, severity: "Medium", confidence: 57, status: "active", source: "ThreatQ", tlp: "GREEN",
    technique: "T1583.003 Virtual Private Server", tags: ["bulletproof-hosting"], first: 86, last: 1, rules: 1, hits7d: 22, hits30d: 30,
    openDetection: { caseId: "CS-24811", severity: "Medium", status: "Reopened", alertName: "DNS lookups to typosquatted Microsoft domain", host: "fin-ws-022" } },
  { value: PLANTED.dgaDomain, kind: "domain", actor: ACTORS.lazarus, severity: "Medium", confidence: 35, status: "monitoring", source: "OSINT feed", tlp: "CLEAR",
    technique: "T1568.002 Domain Generation Algorithms", tags: ["dga-suspected", "newly-registered"], first: 3, last: 0, rules: 1, hits7d: 4, hits30d: 4,
    openDetection: { caseId: "CS-24809", severity: "Medium", status: "New", alertName: "Possible DGA domain resolution", host: "eng-lt-117" } },
  { value: "44d88612fea8a8f36de82e1278abb02f", kind: "md5", actor: ACTORS.none, severity: "Low", confidence: 95, status: "active", source: "ThreatQ", tlp: "CLEAR",
    technique: "T1027 Obfuscated Files", tags: ["eicar", "test-file"], first: 1018, last: 0, rules: 1, hits7d: 2, hits30d: 5,
    openDetection: { caseId: "CS-24806", severity: "Low", status: "In Progress", alertName: "EICAR test file written to disk", host: "ops-lt-208" } },

  // ---- Repository inventory (no open detection)
  { value: "hxxps://login-microsoftonline.support/oauth2/authorize", kind: "url", actor: ACTORS.apt29, severity: "High", confidence: 84, status: "active", source: "Mandiant Advantage", tlp: "AMBER",
    technique: "T1566.002 Spearphishing Link", tags: ["aitm", "oauth-phish"], first: 22, last: 4, rules: 2, hits7d: 6, hits30d: 19 },
  { value: "cloud-docs-share.com", kind: "domain", actor: ACTORS.apt29, severity: "High", confidence: 77, status: "active", source: "Mandiant Advantage", tlp: "AMBER",
    technique: "T1102 Web Service", tags: ["wineloader", "c2"], first: 61, last: 9, rules: 1, hits7d: 0, hits30d: 7 },
  { value: "194.180.48.112", kind: "ipv4", actor: ACTORS.apt28, severity: "High", confidence: 79, status: "active", source: "CISA AIS", tlp: "GREEN",
    technique: "T1110.003 Password Spraying", tags: ["ntlm-relay", "edge-device"], first: 37, last: 2, rules: 2, hits7d: 14, hits30d: 48 },
  { value: "e5b1a3c09d84f2677a1c3e8b0f94d26c51a7e3b9d0c2f4a68e1b7d35c9f0a2e4", kind: "sha256", actor: ACTORS.apt28, severity: "High", confidence: 86, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1547.001 Registry Run Keys", tags: ["headlace", "loader"], first: 52, last: 18, rules: 1, hits7d: 0, hits30d: 2 },
  { value: "77.91.124.207", kind: "ipv4", actor: ACTORS.sandworm, severity: "Critical", confidence: 90, status: "active", source: "CISA AIS", tlp: "AMBER",
    technique: "T1485 Data Destruction", tags: ["wiper", "industroyer"], first: 140, last: 26, rules: 3, hits7d: 0, hits30d: 1 },
  { value: "203.78.129.45", kind: "ipv4", actor: ACTORS.apt41, severity: "High", confidence: 74, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1190 Exploit Public-Facing App", tags: ["scanner", "citrix-exploit"], first: 29, last: 1, rules: 2, hits7d: 96, hits30d: 311 },
  { value: "update-checker.workers.dev", kind: "domain", actor: ACTORS.apt41, severity: "Medium", confidence: 61, status: "active", source: "OSINT feed", tlp: "CLEAR",
    technique: "T1090.002 External Proxy", tags: ["cloudflare-worker", "c2"], first: 17, last: 3, rules: 1, hits7d: 9, hits30d: 21 },
  { value: "c03e8a1f6b29d47e5a0c8f13b6d29e74", kind: "md5", actor: ACTORS.apt41, severity: "High", confidence: 88, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1574.002 DLL Side-Loading", tags: ["shadowpad", "sideload"], first: 95, last: 33, rules: 2, hits7d: 0, hits30d: 0 },
  { value: "66.85.41.230", kind: "ipv4", actor: ACTORS.volt, severity: "Critical", confidence: 83, status: "active", source: "CISA AIS", tlp: "AMBER",
    technique: "T1133 External Remote Services", tags: ["soho-router", "kv-botnet", "lotl"], first: 48, last: 5, rules: 2, hits7d: 11, hits30d: 37 },
  { value: "45.153.231.119", kind: "ipv4", actor: ACTORS.volt, severity: "High", confidence: 69, status: "monitoring", source: "CISA AIS", tlp: "GREEN",
    technique: "T1090.003 Multi-hop Proxy", tags: ["kv-botnet"], first: 76, last: 12, rules: 1, hits7d: 0, hits30d: 6 },
  { value: "hxxp://news-briefing.org/doc/agenda.zip", kind: "url", actor: ACTORS.mustang, severity: "Medium", confidence: 66, status: "active", source: "Recorded Future", tlp: "GREEN",
    technique: "T1204.002 Malicious File", tags: ["plugx", "lnk-lure"], first: 33, last: 8, rules: 1, hits7d: 0, hits30d: 3 },
  { value: "b81f9d2e4c07a63e5f1a8d90c2b74e6f3a05d18c9e2b7f40a6c3d51e8b9f2a07", kind: "sha256", actor: ACTORS.lazarus, severity: "Critical", confidence: 91, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1195.002 Compromise Software Supply Chain", tags: ["trojanized-npm", "beavertail"], first: 12, last: 2, rules: 2, hits7d: 3, hits30d: 5 },
  { value: "recruit-talentpool.com", kind: "domain", actor: ACTORS.lazarus, severity: "High", confidence: 73, status: "active", source: "Recorded Future", tlp: "GREEN",
    technique: "T1566.003 Spearphishing via Service", tags: ["fake-recruiter", "dream-job"], first: 41, last: 6, rules: 1, hits7d: 2, hits30d: 9 },
  { value: "hr-benefits@naver-mailcenter.com", kind: "email", actor: ACTORS.kimsuky, severity: "Medium", confidence: 68, status: "active", source: "ThreatQ", tlp: "GREEN",
    technique: "T1566.001 Spearphishing Attachment", tags: ["credential-phish", "sender"], first: 27, last: 10, rules: 1, hits7d: 0, hits30d: 4 },
  { value: "5.230.67.184", kind: "ipv4", actor: ACTORS.muddy, severity: "High", confidence: 71, status: "active", source: "CISA AIS", tlp: "GREEN",
    technique: "T1219 Remote Access Software", tags: ["atera", "rmm-abuse"], first: 58, last: 3, rules: 2, hits7d: 7, hits30d: 26 },
  { value: "storage-dropbox-sync.com", kind: "domain", actor: ACTORS.muddy, severity: "Medium", confidence: 58, status: "monitoring", source: "OSINT feed", tlp: "CLEAR",
    technique: "T1567.002 Exfiltration to Cloud Storage", tags: ["exfil", "lookalike"], first: 20, last: 15, rules: 1, hits7d: 0, hits30d: 3 },
  { value: "hxxps://drive-secure-view.info/s/7Kq2", kind: "url", actor: ACTORS.apt35, severity: "Medium", confidence: 63, status: "active", source: "Recorded Future", tlp: "GREEN",
    technique: "T1598.003 Spearphishing for Information", tags: ["cred-harvest", "think-tank-lure"], first: 19, last: 7, rules: 1, hits7d: 1, hits30d: 8 },
  { value: "142.11.199.36", kind: "ipv4", actor: ACTORS.fin7, severity: "High", confidence: 76, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1105 Ingress Tool Transfer", tags: ["carbanak", "powertrash"], first: 67, last: 4, rules: 2, hits7d: 5, hits30d: 22 },
  { value: "okta-sso-helpdesk.com", kind: "domain", actor: ACTORS.spider, severity: "Critical", confidence: 87, status: "active", source: "Mandiant Advantage", tlp: "AMBER",
    technique: "T1621 MFA Request Generation", tags: ["helpdesk-phish", "sso-lure"], first: 9, last: 1, rules: 3, hits7d: 17, hits30d: 23 },
  { value: "3a7d9f0e2c41b86d5e09a7f3c1b2d48e6f0a9c37b5e1d24f8a6c0e3b9d71f5a2", kind: "sha256", actor: ACTORS.spider, severity: "High", confidence: 80, status: "active", source: "Falcon Intel", tlp: "AMBER",
    technique: "T1486 Data Encrypted for Impact", tags: ["alphv", "esxi-encryptor"], first: 44, last: 21, rules: 2, hits7d: 0, hits30d: 1 },
  { value: "185.174.137.80", kind: "ipv4", actor: ACTORS.ta505, severity: "Medium", confidence: 54, status: "expired", source: "ThreatQ", tlp: "GREEN",
    technique: "T1071.001 Web Protocols", tags: ["clop", "moveit"], first: 210, last: 74, rules: 1, hits7d: 0, hits30d: 0 },
  { value: "45.61.136.22", kind: "ipv4", actor: ACTORS.fin7, severity: "Low", confidence: 42, status: "expired", source: "OSINT feed", tlp: "CLEAR",
    technique: "T1583.003 Virtual Private Server", tags: ["retired-c2"], first: 188, last: 92, rules: 0, hits7d: 0, hits30d: 0 },
];

export const IOCS: IocEntry[] = SEEDS.map(({ first, last, ...s }, i) => ({
  ...s,
  id: `IOC-${String(1040 + i).padStart(5, "0")}`,
  firstSeen: day(first),
  lastSeen: day(last),
  spark: spark(i * 7919 + 13, s.hits7d, s.hits30d),
}));

// ---- Trend series: daily IoC-matched alerts and detections (cases with an IoC hit), 30 days.
export type TrendPoint = { date: string; alerts: number; detections: number };

export const TREND: TrendPoint[] = (() => {
  const r = rng(424242);
  return Array.from({ length: 30 }, (_, i) => {
    const ago = 29 - i;
    const weekend = [0, 6].includes(new Date(ANCHOR - ago * 86_400_000).getUTCDay());
    // Baseline drift, a spray wave ~3 weeks back, then the FIN-TEMPEST beacon from day -6.
    const base = 38 + i * 0.6 + (ago >= 18 && ago <= 21 ? 46 : 0) + (ago <= 5 ? 70 + (5 - ago) * 14 : 0);
    const alerts = Math.round(base * (weekend ? 0.62 : 1) * (0.85 + r() * 0.3));
    const detections = Math.max(1, Math.round(alerts / 11 + (r() - 0.5) * 2));
    return { date: day(ago), alerts, detections };
  });
})();

const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);

export function iocStats() {
  const openDetections = new Set(IOCS.flatMap((i) => (i.openDetection ? [i.openDetection.caseId] : [])));
  const actorNames = new Set(IOCS.filter((i) => i.actor.motivation !== "Test").map((i) => i.actor.name));
  const last7 = TREND.slice(-7);
  const prev7 = TREND.slice(-14, -7);
  return {
    total: IOCS.length,
    active: IOCS.filter((i) => i.status === "active").length,
    actors: actorNames.size,
    countries: new Set(IOCS.filter((i) => i.actor.motivation !== "Test").map((i) => i.actor.country)).size,
    openDetections: openDetections.size,
    linkedIocs: IOCS.filter((i) => i.openDetection).length,
    detections7d: sum(last7.map((d) => d.detections)),
    detectionsPrev7d: sum(prev7.map((d) => d.detections)),
    detections30d: sum(TREND.map((d) => d.detections)),
    alerts7d: sum(last7.map((d) => d.alerts)),
    alerts30d: sum(TREND.map((d) => d.alerts)),
  };
}

// Group helper for the breakdown bars (sorted descending).
export function breakdown<K extends string>(key: (i: IocEntry) => K, weight: (i: IocEntry) => number = () => 1) {
  const m = new Map<K, number>();
  for (const i of IOCS) m.set(key(i), (m.get(key(i)) ?? 0) + weight(i));
  return [...m.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
}
