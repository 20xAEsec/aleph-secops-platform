// Demo ATT&CK coverage model. In the full platform this comes from the detection-rules repo
// mapped onto an ATT&CK snapshot; the gap-priority formula is the same.

export type Technique = {
  id: string;
  name: string;
  rules: number; // active rules covering it
  dormant: number;
  prevalence: number; // 0..1, how often adversaries use it
  telemetryFit: number; // 0..1, how well our log sources can see it
};

export type Tactic = { id: string; name: string; techniques: Technique[] };

export const TACTICS: Tactic[] = [
  { id: "TA0001", name: "Initial Access", techniques: [
    { id: "T1566.001", name: "Spearphishing Attachment", rules: 4, dormant: 0, prevalence: 0.95, telemetryFit: 0.9 },
    { id: "T1566.002", name: "Spearphishing Link", rules: 2, dormant: 1, prevalence: 0.9, telemetryFit: 0.8 },
    { id: "T1190", name: "Exploit Public-Facing App", rules: 1, dormant: 0, prevalence: 0.8, telemetryFit: 0.6 },
    { id: "T1133", name: "External Remote Services", rules: 0, dormant: 0, prevalence: 0.7, telemetryFit: 0.85 },
  ]},
  { id: "TA0002", name: "Execution", techniques: [
    { id: "T1059.001", name: "PowerShell", rules: 6, dormant: 1, prevalence: 0.97, telemetryFit: 0.95 },
    { id: "T1059.003", name: "Windows Command Shell", rules: 3, dormant: 0, prevalence: 0.85, telemetryFit: 0.95 },
    { id: "T1204.002", name: "Malicious File", rules: 1, dormant: 0, prevalence: 0.88, telemetryFit: 0.8 },
    { id: "T1047", name: "WMI", rules: 0, dormant: 1, prevalence: 0.6, telemetryFit: 0.7 },
  ]},
  { id: "TA0003", name: "Persistence", techniques: [
    { id: "T1547.001", name: "Registry Run Keys", rules: 2, dormant: 0, prevalence: 0.8, telemetryFit: 0.9 },
    { id: "T1053.005", name: "Scheduled Task", rules: 3, dormant: 0, prevalence: 0.82, telemetryFit: 0.9 },
    { id: "T1136", name: "Create Account", rules: 0, dormant: 0, prevalence: 0.55, telemetryFit: 0.75 },
    { id: "T1505.003", name: "Web Shell", rules: 0, dormant: 0, prevalence: 0.5, telemetryFit: 0.4 },
  ]},
  { id: "TA0006", name: "Credential Access", techniques: [
    { id: "T1003.001", name: "LSASS Memory", rules: 3, dormant: 0, prevalence: 0.9, telemetryFit: 0.85 },
    { id: "T1110.003", name: "Password Spraying", rules: 1, dormant: 0, prevalence: 0.75, telemetryFit: 0.9 },
    { id: "T1558.003", name: "Kerberoasting", rules: 0, dormant: 0, prevalence: 0.7, telemetryFit: 0.8 },
    { id: "T1555", name: "Password Stores", rules: 0, dormant: 1, prevalence: 0.6, telemetryFit: 0.5 },
  ]},
  { id: "TA0008", name: "Lateral Movement", techniques: [
    { id: "T1021.001", name: "RDP", rules: 2, dormant: 0, prevalence: 0.8, telemetryFit: 0.9 },
    { id: "T1021.002", name: "SMB / Admin Shares", rules: 1, dormant: 0, prevalence: 0.78, telemetryFit: 0.85 },
    { id: "T1550.002", name: "Pass the Hash", rules: 0, dormant: 0, prevalence: 0.65, telemetryFit: 0.7 },
    { id: "T1570", name: "Lateral Tool Transfer", rules: 0, dormant: 0, prevalence: 0.55, telemetryFit: 0.6 },
  ]},
  { id: "TA0011", name: "Command & Control", techniques: [
    { id: "T1071.001", name: "Web Protocols", rules: 2, dormant: 0, prevalence: 0.95, telemetryFit: 0.85 },
    { id: "T1071.004", name: "DNS", rules: 0, dormant: 1, prevalence: 0.7, telemetryFit: 0.95 },
    { id: "T1573", name: "Encrypted Channel", rules: 1, dormant: 0, prevalence: 0.8, telemetryFit: 0.5 },
    { id: "T1090.003", name: "Multi-hop Proxy", rules: 0, dormant: 0, prevalence: 0.5, telemetryFit: 0.65 },
  ]},
  { id: "TA0010", name: "Exfiltration", techniques: [
    { id: "T1041", name: "Over C2 Channel", rules: 1, dormant: 0, prevalence: 0.85, telemetryFit: 0.7 },
    { id: "T1567.002", name: "To Cloud Storage", rules: 0, dormant: 0, prevalence: 0.75, telemetryFit: 0.75 },
    { id: "T1048", name: "Alternative Protocol", rules: 0, dormant: 0, prevalence: 0.5, telemetryFit: 0.6 },
    { id: "T1020", name: "Automated Exfiltration", rules: 0, dormant: 0, prevalence: 0.4, telemetryFit: 0.5 },
  ]},
];

export type Gap = Technique & { tactic: string; priority: number; score: number };

// Gap priority = 0.45 × prevalence + 0.35 × telemetry fit + 0.20 × tactic weakness → 1..10
export function rankGaps(): Gap[] {
  const gaps: Gap[] = [];
  for (const tactic of TACTICS) {
    const covered = tactic.techniques.filter((t) => t.rules > 0).length;
    const weakness = 1 - covered / tactic.techniques.length;
    for (const t of tactic.techniques) {
      if (t.rules > 0) continue;
      const score = 0.45 * t.prevalence + 0.35 * t.telemetryFit + 0.2 * weakness;
      gaps.push({ ...t, tactic: tactic.name, score, priority: Math.max(1, Math.min(10, Math.round(score * 10))) });
    }
  }
  return gaps.sort((a, b) => b.score - a.score);
}
