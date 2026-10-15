// Demo telemetry: a deterministic, seeded stand-in for Chronicle UDM search. The shape mirrors
// UDM-style events closely enough that swapping in a real Chronicle client later only changes
// this file. Benign noise varies with the query; a few planted threads (a beacon, a typosquat,
// an encoded PowerShell launch) are always present so hunts have something real to find.

export type UdmEvent = {
  ts: string;
  type: "NETWORK_DNS" | "NETWORK_CONNECTION" | "PROCESS_LAUNCH" | "USER_LOGIN";
  host: string;
  user: string;
  src_ip: string;
  dst_ip?: string;
  domain?: string;
  process?: string;
  cmdline?: string;
  country?: string;
  bytes?: number;
};

export type CoverageStats = {
  total: number;
  byType: Record<string, number>;
  topDomains: [string, number][];
  rareDomains: [string, number][];
  topHosts: [string, number][];
  beaconCandidates: { host: string; dst: string; events: number; meanIntervalSec: number; jitterPct: number }[];
  highEntropyDomains: { domain: string; entropy: number }[];
  suspiciousCommands: { host: string; cmdline: string }[];
  foreignLogins: { user: string; country: string; host: string }[];
};

const BENIGN_DOMAINS = [
  "login.microsoftonline.com", "outlook.office365.com", "slack.com", "github.com",
  "update.googleapis.com", "zoom.us", "teams.microsoft.com", "s3.amazonaws.com",
  "www.google.com", "cdn.jsdelivr.net", "api.salesforce.com", "okta.com",
];
const HOSTS = [
  "fin-ws-011", "fin-ws-014", "fin-ws-022", "eng-lt-104", "eng-lt-117",
  "hr-ws-031", "ops-lt-208", "srv-dc-01", "srv-web-03",
];
const USERS = ["a.patel", "j.romero", "m.chen", "s.okafor", "l.nguyen", "r.haddad", "svc_backup"];
const PROCESSES = [
  ["chrome.exe", "chrome.exe --type=renderer"],
  ["outlook.exe", "OUTLOOK.EXE /recycle"],
  ["teams.exe", "Teams.exe --system-initiated"],
  ["svchost.exe", "svchost.exe -k netsvcs -p"],
  ["excel.exe", "EXCEL.EXE /dde"],
];

// Planted threads (the "story" in the demo environment).
export const PLANTED = {
  beaconHost: "fin-ws-014",
  beaconDomain: "telemetry-sync.net",
  beaconIp: "185.220.101.47",
  typosquat: "cdn-updates-msft.com",
  typosquatIp: "45.137.21.9",
  dgaDomain: "qx7v2k9dlz.top",
};

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

const pick = <T,>(r: () => number, xs: T[]) => xs[Math.floor(r() * xs.length)];
const ipFor = (r: () => number) => `10.${20 + Math.floor(r() * 10)}.${Math.floor(r() * 255)}.${1 + Math.floor(r() * 250)}`;

function generate(query: string, hoursBack: number, extraIndicators: string[]): UdmEvent[] {
  const r = rng(hashString(query.toLowerCase()));
  const now = Date.now();
  const span = hoursBack * 3600_000;
  const events: UdmEvent[] = [];
  const hostIp: Record<string, string> = Object.fromEntries(HOSTS.map((h) => [h, ipFor(r)]));

  // Benign noise
  for (let i = 0; i < 160; i++) {
    const host = pick(r, HOSTS);
    const user = pick(r, USERS);
    const ts = new Date(now - r() * span).toISOString();
    const roll = r();
    if (roll < 0.45) {
      events.push({ ts, type: "NETWORK_DNS", host, user, src_ip: hostIp[host], domain: pick(r, BENIGN_DOMAINS) });
    } else if (roll < 0.75) {
      events.push({ ts, type: "NETWORK_CONNECTION", host, user, src_ip: hostIp[host], dst_ip: `52.${Math.floor(r() * 255)}.${Math.floor(r() * 255)}.${Math.floor(r() * 255)}`, domain: pick(r, BENIGN_DOMAINS), bytes: Math.floor(r() * 90000) });
    } else if (roll < 0.92) {
      const [process, cmdline] = pick(r, PROCESSES);
      events.push({ ts, type: "PROCESS_LAUNCH", host, user, src_ip: hostIp[host], process, cmdline });
    } else {
      events.push({ ts, type: "USER_LOGIN", host, user, src_ip: hostIp[host], country: "US" });
    }
  }

  // Beacon: fin-ws-014 → telemetry-sync.net every ~300s with low jitter, last ~4h.
  const beaconStart = now - Math.min(span, 4 * 3600_000);
  for (let i = 0; i < 44; i++) {
    const ts = new Date(beaconStart + i * 300_000 + (r() - 0.5) * 18_000).toISOString();
    events.push({ ts, type: "NETWORK_DNS", host: PLANTED.beaconHost, user: "m.chen", src_ip: hostIp[PLANTED.beaconHost], domain: PLANTED.beaconDomain });
    events.push({ ts, type: "NETWORK_CONNECTION", host: PLANTED.beaconHost, user: "m.chen", src_ip: hostIp[PLANTED.beaconHost], dst_ip: PLANTED.beaconIp, domain: PLANTED.beaconDomain, bytes: 410 + Math.floor(r() * 60) });
  }

  // Encoded PowerShell on the same host, shortly before the beacon begins.
  events.push({
    ts: new Date(beaconStart - 120_000).toISOString(), type: "PROCESS_LAUNCH", host: PLANTED.beaconHost, user: "m.chen",
    src_ip: hostIp[PLANTED.beaconHost], process: "powershell.exe",
    cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
  });
  events.push({
    ts: new Date(beaconStart - 300_000).toISOString(), type: "PROCESS_LAUNCH", host: PLANTED.beaconHost, user: "m.chen",
    src_ip: hostIp[PLANTED.beaconHost], process: "excel.exe", cmdline: "EXCEL.EXE \"Q3_Vendor_Invoice.xlsm\"",
  });

  // Typosquat contact from two finance hosts.
  for (const host of ["fin-ws-011", "fin-ws-022"]) {
    const ts = new Date(now - r() * span).toISOString();
    events.push({ ts, type: "NETWORK_DNS", host, user: pick(r, USERS), src_ip: hostIp[host], domain: PLANTED.typosquat });
    events.push({ ts, type: "NETWORK_CONNECTION", host, user: pick(r, USERS), src_ip: hostIp[host], dst_ip: PLANTED.typosquatIp, domain: PLANTED.typosquat, bytes: 18234 });
  }

  // One DGA-looking lookup and one foreign login.
  events.push({ ts: new Date(now - r() * span).toISOString(), type: "NETWORK_DNS", host: "eng-lt-117", user: "l.nguyen", src_ip: hostIp["eng-lt-117"], domain: PLANTED.dgaDomain });
  events.push({ ts: new Date(now - r() * span).toISOString(), type: "USER_LOGIN", host: "vpn-gw-01", user: "svc_backup", src_ip: "91.219.236.18", country: "RU" });

  // Anything the analyst explicitly asked about shows up a few times (or not at all), seeded.
  for (const ioc of extraIndicators) {
    const hits = hashString(ioc) % 4;
    for (let i = 0; i < hits; i++) {
      const host = pick(r, HOSTS);
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(ioc);
      events.push({
        ts: new Date(now - r() * span).toISOString(), type: "NETWORK_CONNECTION", host, user: pick(r, USERS),
        src_ip: hostIp[host], ...(isIp ? { dst_ip: ioc } : { domain: ioc }), bytes: Math.floor(r() * 5000),
      });
    }
  }

  return events.sort((a, b) => a.ts.localeCompare(b.ts));
}

function entropy(s: string) {
  const counts: Record<string, number> = {};
  for (const c of s) counts[c] = (counts[c] ?? 0) + 1;
  return -Object.values(counts).reduce((acc, n) => acc + (n / s.length) * Math.log2(n / s.length), 0);
}

const top = (m: Map<string, number>, n: number) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);

// Coverage statistics run over EVERY event; only a sample is shown to the model.
export function computeStats(events: UdmEvent[]): CoverageStats {
  const byType: Record<string, number> = {};
  const domains = new Map<string, number>();
  const hosts = new Map<string, number>();
  const pairs = new Map<string, number[]>();

  for (const e of events) {
    byType[e.type] = (byType[e.type] ?? 0) + 1;
    hosts.set(e.host, (hosts.get(e.host) ?? 0) + 1);
    if (e.domain) domains.set(e.domain, (domains.get(e.domain) ?? 0) + 1);
    if (e.type === "NETWORK_CONNECTION" && (e.dst_ip || e.domain)) {
      const key = `${e.host}→${e.domain ?? e.dst_ip}`;
      pairs.set(key, [...(pairs.get(key) ?? []), Date.parse(e.ts)]);
    }
  }

  const beaconCandidates = [...pairs.entries()].flatMap(([key, times]) => {
    if (times.length < 8) return [];
    const sorted = [...times].sort((a, b) => a - b);
    const gaps = sorted.slice(1).map((t, i) => (t - sorted[i]) / 1000);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const sd = Math.sqrt(gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length);
    const jitter = sd / mean;
    if (jitter > 0.15) return [];
    const [host, dst] = key.split("→");
    return [{ host, dst, events: times.length, meanIntervalSec: Math.round(mean), jitterPct: Math.round(jitter * 1000) / 10 }];
  });

  return {
    total: events.length,
    byType,
    topDomains: top(domains, 6),
    rareDomains: [...domains.entries()].filter(([, n]) => n <= 2),
    topHosts: top(hosts, 5),
    beaconCandidates,
    highEntropyDomains: [...domains.keys()]
      .map((d) => ({ domain: d, entropy: Math.round(entropy(d.split(".")[0]) * 100) / 100 }))
      .filter((d) => d.entropy > 3.2),
    suspiciousCommands: events
      .filter((e) => e.cmdline && /-enc|-nop|hidden|\.xlsm|rundll32|mshta/i.test(e.cmdline))
      .map((e) => ({ host: e.host, cmdline: e.cmdline! })),
    foreignLogins: events
      .filter((e) => e.type === "USER_LOGIN" && e.country && e.country !== "US")
      .map((e) => ({ user: e.user, country: e.country!, host: e.host })),
  };
}

// The sample that reaches the model: suspicious-looking events first, then a slice of the rest.
export function sampleForModel(events: UdmEvent[], stats: CoverageStats, n = 40): UdmEvent[] {
  const flagged = new Set([
    ...stats.rareDomains.map(([d]) => d),
    ...stats.beaconCandidates.map((b) => b.dst),
    ...stats.highEntropyDomains.map((d) => d.domain),
  ]);
  const interesting = events.filter(
    (e) => (e.domain && flagged.has(e.domain)) || (e.cmdline && /-enc|\.xlsm/i.test(e.cmdline)) || (e.country && e.country !== "US"),
  );
  const seen = new Set<string>();
  const dedupedInteresting = interesting.filter((e) => {
    const k = `${e.type}|${e.host}|${e.domain ?? e.cmdline ?? e.country}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const rest = events.filter((e) => !interesting.includes(e)).slice(0, Math.max(0, n - dedupedInteresting.length));
  return [...dedupedInteresting, ...rest].slice(0, n);
}

export function searchUdmEvents(args: { query: string; hours_back: number; indicators?: string[] }) {
  const events = generate(args.query, args.hours_back, args.indicators ?? []);
  return { events, stats: computeStats(events) };
}
