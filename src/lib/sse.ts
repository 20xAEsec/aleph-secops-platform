// Server-Sent Events over a POST response. The stream always ends with `done`, even after an
// error, so the client never has a reason to auto-retry (which would start a second run).

export type RunEvent = { type: string } & Record<string, unknown>;
export type Emit = (event: RunEvent) => void;

const MAX_RUNS = 5;
let activeRuns = 0;

export function sseResponse(run: (emit: Emit) => Promise<void>): Response {
  // Admission control: refuse immediately rather than queue silently.
  if (activeRuns >= MAX_RUNS) {
    return Response.json({ error: "All analysis slots are busy. Try again shortly." }, { status: 429 });
  }
  activeRuns++;

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let open = true;
      const emit: Emit = (event) => {
        if (!open) return;
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ ...event, t: Date.now() })}\n\n`));
        } catch {
          open = false; // client went away; keep running so the work isn't lost
        }
      };
      try {
        await run(emit);
      } catch (err) {
        emit({ type: "error", message: err instanceof Error ? err.message : String(err) });
      } finally {
        emit({ type: "done" });
        activeRuns--;
        if (open) controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
