import { PLANTED } from "./telemetry";

// Demo threat-intel store (stands in for ThreatQ indicators synced into Chronicle) plus SOC case
// history. Real integrations replace these functions; callers only see the shapes.

export type IntelRecord = {
  indicator: string;
  type: "ip" | "domain" | "hash" | "url";
  score: number; // 0-100
  status: "active" | "expired" | "whitelisted";
  tags: string[];
  actor?: string;
  firstSeen: string;
  registeredDaysAgo?: number;
  source: string;
};

const INTEL: IntelRecord[] = [
  { indicator: PLANTED.beaconIp, type: "ip", score: 88, status: "active", tags: ["c2", "tor-exit", "cobalt-strike"], actor: "FIN-TEMPEST (tracked)", firstSeen: "2026-09-02", source: "ThreatQ" },
  { indicator: PLANTED.beaconDomain, type: "domain", score: 81, status: "active", tags: ["c2", "newly-registered"], actor: "FIN-TEMPEST (tracked)", firstSeen: "2026-10-09", registeredDaysAgo: 5, source: "ThreatQ" },
  { indicator: PLANTED.typosquat, type: "domain", score: 64, status: "active", tags: ["typosquat", "phishing-infra"], firstSeen: "2026-10-01", registeredDaysAgo: 13, source: "ThreatQ" },
  { indicator: PLANTED.typosquatIp, type: "ip", score: 57, status: "active", tags: ["bulletproof-hosting"], firstSeen: "2026-07-21", source: "ThreatQ" },
  { indicator: PLANTED.dgaDomain, type: "domain", score: 35, status: "active", tags: ["dga-suspected"], firstSeen: "2026-10-12", registeredDaysAgo: 2, source: "OSINT feed" },
  { indicator: "91.219.236.18", type: "ip", score: 72, status: "active", tags: ["credential-stuffing", "vpn-abuse"], firstSeen: "2026-06-18", source: "ThreatQ" },
  { indicator: "44d88612fea8a8f36de82e1278abb02f", type: "hash", score: 95, status: "active", tags: ["test-file", "eicar"], firstSeen: "2024-01-01", source: "ThreatQ" },
];

export type CaseRecord = { caseId: string; closedAs: "TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN"; date: string; summary: string };

const CASES: Record<string, CaseRecord[]> = {
  [PLANTED.beaconIp]: [
    { caseId: "CASE-41877", closedAs: "TRUE_POSITIVE", date: "2026-09-04", summary: "Cobalt Strike beacon on eng-lt-090, host re-imaged." },
  ],
  [PLANTED.typosquat]: [
    { caseId: "CASE-42210", closedAs: "FALSE_POSITIVE", date: "2026-10-03", summary: "Initial alert closed as FP: assumed Microsoft CDN. Reopened for review." },
  ],
  "91.219.236.18": [
    { caseId: "CASE-40551", closedAs: "TRUE_POSITIVE", date: "2026-06-19", summary: "Password spray against VPN; svc accounts rotated." },
  ],
};

export function lookupIndicator(indicator: string): IntelRecord | { indicator: string; found: false } {
  const hit = INTEL.find((i) => i.indicator.toLowerCase() === indicator.toLowerCase());
  return hit ?? { indicator, found: false };
}

export function lookupCaseHistory(indicator: string): CaseRecord[] {
  return CASES[indicator.toLowerCase()] ?? [];
}
