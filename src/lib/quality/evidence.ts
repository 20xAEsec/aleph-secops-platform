import { refang } from "../secops/ioc";

// Deterministic evidence check. After a report is written, extract every IPv4, domain and hash
// it mentions and check each one against the raw tool payloads and the original request.
// It flags, never edits, and makes no model call.

export type EvidenceResult = { checked: number; verified: string[]; unverified: string[] };

const TLDS = "com|net|org|io|top|info|xyz|ru|cn|biz|cc|co|dev|app|us|uk|de";
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = new RegExp(`\\b(?:[a-z0-9-]+\\.)+(?:${TLDS})\\b`, "gi");
const HASH_RE = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;

export function evidenceCheck(report: string, haystacks: string[]): EvidenceResult {
  const text = refang(report.replace(/\[\.\]/g, "."));
  const found = new Set<string>([
    ...(text.match(IP_RE) ?? []),
    ...(text.match(DOMAIN_RE) ?? []).map((d) => d.toLowerCase()),
    ...(text.match(HASH_RE) ?? []).map((h) => h.toLowerCase()),
  ]);
  const corpus = haystacks.join("\n").toLowerCase();

  const verified: string[] = [];
  const unverified: string[] = [];
  for (const indicator of found) {
    (corpus.includes(indicator.toLowerCase()) ? verified : unverified).push(indicator);
  }
  return { checked: found.size, verified, unverified: unverified.slice(0, 25) };
}
