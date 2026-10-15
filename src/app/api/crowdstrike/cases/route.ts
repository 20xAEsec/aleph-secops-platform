import { listCases } from "@/lib/secops/crowdstrike";

// CrowdStrike seam: GET /api/crowdstrike/cases. A real Falcon API client replaces listCases().
export async function GET() {
  return Response.json({ source: "CrowdStrike Falcon", syncedAt: new Date().toISOString(), cases: listCases() });
}
