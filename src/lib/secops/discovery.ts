import { searchUdmEvents, type UdmEvent } from "./telemetry";

// Host Discovery: resolve a resource (hostname, IP, CIDR, domain, user, MAC, process) against the
// demo telemetry and profile every host it touches. The log set uses one fixed seed so host↔IP
// mappings stay stable between searches, the way a real SIEM's would within a window. A small
// asset table (stand-in for the CMDB) adds MAC, OS and ownership that logs alone don't carry.

export const RESOURCE_TYPES = {
  hostname: { label: "Hostname", hint: "Exact name, FQDN or wildcard", placeholder: "fin-ws-014  ·  fin-ws-*", examples: ["fin-ws-014", "eng-lt-*", "srv-dc-01.corp.local"] },
  ip: { label: "IP address", hint: "Source or destination IPv4", placeholder: "185.220.101.47", examples: ["185.220.101.47", "91.219.236.18", "45.137.21.9"] },
  cidr: { label: "CIDR range", hint: "Every log inside a subnet", placeholder: "10.20.0.0/16", examples: ["10.20.0.0/16", "10.16.0.0/12", "185.220.101.0/24"] },
  domain: { label: "Domain / FQDN", hint: "DNS lookups and connections, subdomains included", placeholder: "telemetry-sync.net", examples: ["telemetry-sync.net", "cdn-updates-msft.com", "microsoft.com"] },
  user: { label: "User account", hint: "sAMAccountName, DOMAIN\\user or UPN", placeholder: "m.chen", examples: ["m.chen", "CORP\\svc_backup", "l.nguyen@corp.local"] },
  mac: { label: "MAC address", hint: "Resolved to a host through the asset inventory", placeholder: "00:1a:2b:3c:4d:5e", examples: [] as string[] },
  process: { label: "Process / binary", hint: "Image name or a fragment of the command line", placeholder: "powershell.exe", examples: ["powershell.exe", "excel.exe", "-enc"] },
} as const;

export type ResourceType = keyof typeof RESOURCE_TYPES;
export const isResourceType = (t: unknown): t is ResourceType => typeof t === "string" && t in RESOURCE_TYPES;

export type HostProfile = {
  host: string;
  ip: string;
  mac: string;
  os: string;
  department: string;
  owner: string;
  users: string[];
  events: number;
  firstSeen: string;
  lastSeen: string;
  topDestinations: { dest: string; count: number }[];
  flags: string[];
};

export type DiscoveryResult = {
  type: ResourceType;
  query: string;
  normalized: string;
  hoursBack: number;
  scanned: number;
  matched: number;
  byType: Record<string, number>;
  hosts: HostProfile[];
  users: string[];
  externalPeers: { dest: string; count: number }[];
  events: UdmEvent[]; // newest first, capped
  truncated: boolean;
};

const SEED_QUERY = "host-discovery-baseline";
const EVENT_CAP = 250;

// ---------------------------------------------------------------- Asset inventory (CMDB stand-in)

function hash(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

export function macFor(host: string) {
  const h1 = hash(host), h2 = hash(`${host}#mac`);
  const bytes = [0x00, 0x1a, (h1 >>> 16) & 0xff, (h1 >>> 8) & 0xff, h1 & 0xff, h2 & 0xff];
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
}

function assetFor(host: string) {
  const prefix = host.split("-").slice(0, 2).join("-");
  const os =
    host.startsWith("srv-dc") ? "Windows Server 2022" :
    host.startsWith("srv-web") ? "Ubuntu 22.04 LTS" :
    host.startsWith("vpn-gw") ? "PAN-OS 11.1" :
    host.includes("-lt-") ? "Windows 11 Enterprise (laptop)" : "Windows 11 Enterprise";
  const department = { "fin-ws": "Finance", "eng-lt": "Engineering", "hr-ws": "HR", "ops-lt": "IT Operations", "srv-dc": "Infrastructure", "srv-web": "Infrastructure", "vpn-gw": "Network edge" }[prefix] ?? "Unassigned";
  return { os, department };
}

// ---------------------------------------------------------------- Matching

const ipToInt = (ip: string) => ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function parseCidr(v: string) {
  const [ip, bits = "32"] = v.split("/");
  const n = Number(bits);
  if (!IPV4.test(ip) || !Number.isInteger(n) || n < 0 || n > 32) return null;
  const mask = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
  const base = (ipToInt(ip) & mask) >>> 0;
  return { base, mask, label: `${[24, 16, 8, 0].map((s) => (base >>> s) & 255).join(".")}/${n}`, size: 2 ** (32 - n) };
}

const refang = (v: string) => v.trim().replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".").replace(/^hxxp/i, "http");

// Returns a predicate over events plus the normalized query, or an error message for the UI.
function matcher(type: ResourceType, raw: string): { test: (e: UdmEvent) => boolean; normalized: string } | { error: string } {
  const v = refang(raw);
  if (!v) return { error: "Enter a value to search for." };
  switch (type) {
    case "hostname": {
      const name = v.toLowerCase().split(".")[0];
      if (!/^[a-z0-9*?][a-z0-9*?_-]*$/.test(name)) return { error: "Hostnames use letters, digits, hyphens and optional * wildcards." };
      const re = new RegExp(`^${name.replace(/[?]/g, ".").replace(/\*/g, ".*")}$`);
      return { test: (e) => re.test(e.host.toLowerCase()), normalized: name };
    }
    case "ip": {
      if (!IPV4.test(v)) return { error: "That isn't a valid IPv4 address (defanged 1.2.3[.]4 is fine)." };
      return { test: (e) => e.src_ip === v || e.dst_ip === v, normalized: v };
    }
    case "cidr": {
      const c = parseCidr(v);
      if (!c) return { error: "Use CIDR notation, e.g. 10.20.0.0/16." };
      if (c.size > 2 ** 24) return { error: "Ranges wider than /8 are too broad. Narrow the prefix." };
      const inRange = (ip?: string) => !!ip && IPV4.test(ip) && ((ipToInt(ip) & c.mask) >>> 0) === c.base;
      return { test: (e) => inRange(e.src_ip) || inRange(e.dst_ip), normalized: c.label };
    }
    case "domain": {
      let d = v.toLowerCase();
      try { if (/^https?:\/\//.test(d)) d = new URL(d).hostname; } catch { /* fall through to validation */ }
      if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(d)) return { error: "That doesn't look like a domain name." };
      return { test: (e) => !!e.domain && (e.domain === d || e.domain.endsWith(`.${d}`)), normalized: d };
    }
    case "user": {
      const u = v.toLowerCase().replace(/^.*\\/, "").replace(/@.*$/, "");
      if (!/^[a-z0-9._$-]+$/.test(u)) return { error: "Usernames use letters, digits, dots, underscores and hyphens." };
      return { test: (e) => e.user.toLowerCase() === u, normalized: u };
    }
    case "mac": {
      const m = v.toLowerCase().replace(/[^0-9a-f]/g, "");
      if (m.length !== 12) return { error: "MAC addresses have 12 hex digits (aa:bb:cc:dd:ee:ff, aa-bb-… or aabb.ccdd.eeff)." };
      const mac = m.match(/../g)!.join(":");
      return { test: (e) => macFor(e.host) === mac, normalized: mac };
    }
    case "process": {
      const p = v.toLowerCase();
      if (p.length < 2) return { error: "Enter at least two characters of the process name or command line." };
      return { test: (e) => !!e.process && (e.process.toLowerCase() === p || (e.cmdline ?? "").toLowerCase().includes(p)), normalized: p };
    }
  }
}

const isInternal = (ip?: string) => !!ip && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

function topN(m: Map<string, number>, n: number) {
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([dest, count]) => ({ dest, count }));
}

export function discover(type: ResourceType, raw: string, hoursBack: number): DiscoveryResult | { error: string } {
  const m = matcher(type, raw);
  if ("error" in m) return m;

  const { events: all } = searchUdmEvents({ query: SEED_QUERY, hours_back: hoursBack });
  const hits = all.filter(m.test).sort((a, b) => b.ts.localeCompare(a.ts));

  // Profile every host that appears in a hit, using that host's full activity in the window.
  const hostNames = [...new Set(hits.map((e) => e.host))];
  const hosts: HostProfile[] = hostNames.map((host) => {
    const evs = all.filter((e) => e.host === host);
    const userCount = new Map<string, number>();
    const dests = new Map<string, number>();
    for (const e of evs) {
      userCount.set(e.user, (userCount.get(e.user) ?? 0) + 1);
      if (e.type === "NETWORK_CONNECTION") {
        const d = e.domain ?? e.dst_ip;
        if (d) dests.set(d, (dests.get(d) ?? 0) + 1);
      }
    }
    const ts = evs.map((e) => e.ts).sort();
    const flags = [
      evs.some((e) => e.cmdline && /-enc|-nop|hidden/i.test(e.cmdline)) && "Encoded PowerShell",
      evs.some((e) => e.cmdline && /\.xlsm/i.test(e.cmdline)) && "Macro document opened",
      evs.some((e) => e.type === "USER_LOGIN" && e.country && e.country !== "US") && "Foreign login",
      [...dests.values()].some((n) => n >= 20) && "High-frequency destination",
    ].filter(Boolean) as string[];
    return {
      host,
      ip: evs.find((e) => e.src_ip)?.src_ip ?? "unknown",
      mac: macFor(host),
      ...assetFor(host),
      owner: topN(userCount, 1)[0]?.dest ?? "unknown",
      users: [...userCount.keys()].sort(),
      events: evs.length,
      firstSeen: ts[0],
      lastSeen: ts[ts.length - 1],
      topDestinations: topN(dests, 4),
      flags,
    };
  }).sort((a, b) => b.flags.length - a.flags.length || b.events - a.events);

  const byType: Record<string, number> = {};
  const peers = new Map<string, number>();
  for (const e of hits) {
    byType[e.type] = (byType[e.type] ?? 0) + 1;
    if (e.dst_ip && !isInternal(e.dst_ip)) {
      const k = e.domain ? `${e.domain} (${e.dst_ip})` : e.dst_ip;
      peers.set(k, (peers.get(k) ?? 0) + 1);
    }
  }

  return {
    type,
    query: raw,
    normalized: m.normalized,
    hoursBack,
    scanned: all.length,
    matched: hits.length,
    byType,
    hosts,
    users: [...new Set(hits.map((e) => e.user))].sort(),
    externalPeers: topN(peers, 6),
    events: hits.slice(0, EVENT_CAP),
    truncated: hits.length > EVENT_CAP,
  };
}

// A known MAC for the UI's example chips (the asset table is derived, so compute it).
export const EXAMPLE_MACS = [macFor("fin-ws-014"), macFor("eng-lt-117")];
