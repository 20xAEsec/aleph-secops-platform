import { CATEGORY_LABEL, classify, searchLogs, statsFor, type LogQuery, type ViolationCategory } from "@/lib/aisec/modelArmor";

// Read-only log explorer. The corpus stays on the server: a page of rows plus the aggregates for
// the current filter are returned, so the client never holds all 5k records.

const PAGE = 50;
const VALID = new Set(Object.keys(CATEGORY_LABEL) as ViolationCategory[]);

export async function GET(request: Request) {
  const p = new URL(request.url).searchParams;

  const cats = (p.get("cats") ?? "").split(",").filter((c): c is ViolationCategory => VALID.has(c as ViolationCategory));
  const state = p.get("state") ?? "all";
  const query: LogQuery = {
    text: p.get("q")?.slice(0, 200) || undefined,
    categories: cats.length ? cats : undefined,
    apps: p.get("app") ? [p.get("app")!] : undefined,
    principals: p.get("principal") ? [p.get("principal")!.slice(0, 120)] : undefined,
    daysBack: Math.min(30, Math.max(1, Number(p.get("days")) || 30)),
    violationsOnly: state === "violations",
    blockedOnly: state === "blocked",
    unblockedOnly: state === "unblocked",
    matchedOnly: state === "matched",
  };

  const all = searchLogs(query);
  const page = Math.max(0, Number(p.get("page")) || 0);
  const rows = all.slice(page * PAGE, page * PAGE + PAGE).map((l) => ({ ...l, violations: classify(l) }));

  return Response.json({
    total: all.length,
    page,
    pageSize: PAGE,
    hasMore: (page + 1) * PAGE < all.length,
    stats: statsFor(all),
    logs: rows,
  });
}
