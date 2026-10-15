import { listTickets } from "@/lib/detections/jira";

// Jira seam: GET /api/jira?queue=intake|tuning. A real Jira REST client replaces listTickets().
export async function GET(request: Request) {
  const queue = new URL(request.url).searchParams.get("queue") === "tuning" ? "tuning" : "intake";
  return Response.json({ queue, tickets: listTickets(queue) });
}
