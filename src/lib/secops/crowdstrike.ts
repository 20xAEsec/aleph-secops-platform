import { PLANTED } from "./telemetry";

// Demo stand-in for the CrowdStrike Falcon cases API. The open cases are tied to the planted
// threads in the demo telemetry, so investigating one finds real evidence. A real client replaces
// listCases / getCase / addCaseComment; callers only see these shapes.

export type CaseSeverity = "Critical" | "High" | "Medium" | "Low";
export type CaseStatus = "New" | "In Progress" | "Reopened" | "Closed";

export type CaseComment = { id: string; author: string; body: string; createdAt: string };

export type FalconCase = {
  id: string;
  severity: CaseSeverity;
  score: number; // Falcon 1-100 severity score
  status: CaseStatus;
  alertName: string;
  alertType: string;
  tactic: string;
  technique: string;
  host: string;
  user: string;
  assignee: string | null;
  createdAt: string;
  detections: number;
  description: string;
  hypothesis: string; // what the Threat Hunt pipeline is asked to investigate
  lookbackDays: number;
  comments: CaseComment[];
};

type Seed = Omit<FalconCase, "createdAt" | "comments"> & { minutesAgo: number };

const SEEDS: Seed[] = [
  {
    id: "CS-24817", severity: "Critical", score: 94, status: "New", minutesAgo: 18, detections: 3,
    alertName: "Office application spawned encoded PowerShell", alertType: "Endpoint Detection",
    tactic: "Execution", technique: "T1059.001 PowerShell", host: PLANTED.beaconHost, user: "m.chen", assignee: null,
    description: `EXCEL.EXE opened Q3_Vendor_Invoice.xlsm and launched powershell.exe -nop -w hidden -enc on ${PLANTED.beaconHost}. Falcon prevention was in detect-only mode for this host group.`,
    hypothesis: `CrowdStrike case CS-24817: Falcon detected EXCEL.EXE (Q3_Vendor_Invoice.xlsm) spawning hidden encoded PowerShell on ${PLANTED.beaconHost}, user m.chen. Reconstruct the process chain and look for follow-on beaconing from finance hosts to newly registered domains over the last 7 days.`,
    lookbackDays: 7,
  },
  {
    id: "CS-24816", severity: "High", score: 82, status: "In Progress", minutesAgo: 47, detections: 2,
    alertName: "Periodic outbound connections to newly registered domain", alertType: "Next-Gen SIEM Correlation",
    tactic: "Command and Control", technique: "T1071.001 Web Protocols", host: PLANTED.beaconHost, user: "m.chen", assignee: "J. Romero",
    description: `Low-jitter HTTPS connections every ~60s from ${PLANTED.beaconHost} to ${PLANTED.beaconDomain} (${PLANTED.beaconIp}). Domain registered 5 days ago.`,
    hypothesis: `CrowdStrike case CS-24816: look for beaconing from finance hosts to newly registered domains over the last 7 days, focusing on ${PLANTED.beaconHost} contacting ${PLANTED.beaconDomain} (${PLANTED.beaconIp}).`,
    lookbackDays: 7,
  },
  {
    id: "CS-24814", severity: "High", score: 76, status: "New", minutesAgo: 132, detections: 1,
    alertName: "Service account authenticated from unusual country", alertType: "Identity Protection",
    tactic: "Initial Access", technique: "T1078.002 Domain Accounts", host: "vpn-gw-01", user: "svc_backup", assignee: null,
    description: "svc_backup completed an interactive VPN login from 91.219.236.18 (RU). The account has no prior logins outside the US.",
    hypothesis: "CrowdStrike case CS-24814: find service accounts logging in from unusual countries, starting with svc_backup authenticating from 91.219.236.18 (RU) via vpn-gw-01. Check for follow-on activity by that account.",
    lookbackDays: 14,
  },
  {
    id: "CS-24811", severity: "Medium", score: 58, status: "Reopened", minutesAgo: 260, detections: 4,
    alertName: "DNS lookups to typosquatted Microsoft domain", alertType: "Next-Gen SIEM Correlation",
    tactic: "Command and Control", technique: "T1583.001 Domains", host: "fin-ws-011", user: "a.patel", assignee: "S. Okafor",
    description: `fin-ws-011 and fin-ws-022 resolved and connected to ${PLANTED.typosquat} (${PLANTED.typosquatIp}). Reopened after a second host was seen.`,
    hypothesis: `CrowdStrike case CS-24811: investigate finance hosts fin-ws-011 and fin-ws-022 contacting the typosquat domain ${PLANTED.typosquat} (${PLANTED.typosquatIp}) over the last 7 days. Determine whether this is phishing infrastructure and which users were involved.`,
    lookbackDays: 7,
  },
  {
    id: "CS-24809", severity: "Medium", score: 49, status: "New", minutesAgo: 395, detections: 1,
    alertName: "Possible DGA domain resolution", alertType: "Endpoint Detection",
    tactic: "Command and Control", technique: "T1568.002 Domain Generation Algorithms", host: "eng-lt-117", user: "l.nguyen", assignee: null,
    description: `eng-lt-117 resolved ${PLANTED.dgaDomain}, a high-entropy .top domain registered 2 days ago. No connection observed yet.`,
    hypothesis: `CrowdStrike case CS-24809: eng-lt-117 (user l.nguyen) resolved the suspected DGA domain ${PLANTED.dgaDomain}. Hunt for other high-entropy domain lookups and any connections that followed over the last 7 days.`,
    lookbackDays: 7,
  },
  {
    id: "CS-24806", severity: "Low", score: 27, status: "In Progress", minutesAgo: 610, detections: 1,
    alertName: "EICAR test file written to disk", alertType: "Endpoint Detection",
    tactic: "Defense Evasion", technique: "T1027 Obfuscated Files", host: "ops-lt-208", user: "r.haddad", assignee: "L. Nguyen",
    description: "EICAR test signature (44d88612fea8a8f36de82e1278abb02f) quarantined on ops-lt-208. Likely an AV validation test by IT.",
    hypothesis: "CrowdStrike case CS-24806: confirm whether the EICAR test file (44d88612fea8a8f36de82e1278abb02f) on ops-lt-208 is a sanctioned AV test, and check the host for anything else unusual over the last day.",
    lookbackDays: 1,
  },
  {
    id: "CS-24802", severity: "Low", score: 21, status: "Closed", minutesAgo: 1460, detections: 2,
    alertName: "Unsigned binary executed from user Downloads", alertType: "Endpoint Detection",
    tactic: "Execution", technique: "T1204.002 Malicious File", host: "hr-ws-031", user: "s.okafor", assignee: "A. Patel",
    description: "Unsigned installer run from Downloads on hr-ws-031. Closed as benign: vendor-supplied payroll utility.",
    hypothesis: "CrowdStrike case CS-24802: review unsigned binaries executed from user Downloads folders on hr-ws-031 over the last 7 days and confirm the benign disposition.",
    lookbackDays: 7,
  },
];

// Comments live in memory (survives dev hot reloads), standing in for the Falcon case timeline.
const store = globalThis as unknown as { __falconComments?: Map<string, CaseComment[]> };
const comments = (store.__falconComments ??= new Map());

function materialize(s: Seed, now: number): FalconCase {
  const { minutesAgo, ...rest } = s;
  return { ...rest, createdAt: new Date(now - minutesAgo * 60_000).toISOString(), comments: comments.get(s.id) ?? [] };
}

export function listCases(): FalconCase[] {
  const now = Date.now();
  return SEEDS.map((s) => materialize(s, now));
}

export function getCase(id: string): FalconCase | null {
  const s = SEEDS.find((c) => c.id === id);
  return s ? materialize(s, Date.now()) : null;
}

export function addCaseComment(id: string, body: string, author: string): CaseComment | null {
  if (!SEEDS.some((c) => c.id === id)) return null;
  const comment: CaseComment = { id: `cmt_${Math.random().toString(36).slice(2, 10)}`, author, body, createdAt: new Date().toISOString() };
  comments.set(id, [...(comments.get(id) ?? []), comment]);
  return comment;
}
