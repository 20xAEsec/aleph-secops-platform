// IOC normalization: refang what analysts paste (hxxp, [.], (.), [:]) so tools search for what
// the telemetry actually stores, then classify the result.

export type IocType = "ipv4" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email" | "unknown";

export function refang(raw: string): string {
  return raw
    .trim()
    .replace(/^hxxp/i, "http")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[at\]|\[@\]/gi, "@");
}

export function classify(value: string): IocType {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ipv4";
  if (/^[a-f0-9]{32}$/i.test(value)) return "md5";
  if (/^[a-f0-9]{40}$/i.test(value)) return "sha1";
  if (/^[a-f0-9]{64}$/i.test(value)) return "sha256";
  if (/^https?:\/\//i.test(value)) return "url";
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(value)) return "email";
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(value)) return "domain";
  return "unknown";
}

export function normalizeIoc(raw: string) {
  const refanged = refang(raw);
  let type = classify(refanged);
  let value = type === "domain" || type === "email" ? refanged.toLowerCase() : refanged;
  let pivot = value;
  if (type === "url") {
    try {
      pivot = new URL(value).hostname.toLowerCase();
    } catch {
      type = "unknown";
    }
  }
  if (type === "md5" || type === "sha1" || type === "sha256") value = pivot = value.toLowerCase();
  return { raw, value, type, pivot, wasDefanged: refanged !== raw.trim() };
}

// Pull any IOCs out of free text (used to seed hunts with indicators the analyst mentioned).
export function extractIndicators(text: string): string[] {
  const t = refang(text);
  const ips = t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
  const domains = t.match(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|top|info|xyz|ru|cn|biz|cc|co|dev|app)\b/gi) ?? [];
  return [...new Set([...ips, ...domains.map((d) => d.toLowerCase())])];
}
