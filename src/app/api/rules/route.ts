import { suggestions } from "@/lib/detections/instructions";
import { RULES, ruleTree } from "@/lib/detections/repo";

// Rules-repo seam: GET /api/rules → folder tree plus each rule's text, match profile and
// suggested tuning prompts. In the full platform this reads the detection-rules repository as the analyst.
export async function GET() {
  return Response.json({
    tree: ruleTree(),
    rules: Object.fromEntries(RULES.map((r) => [r.path, {
      path: r.path, title: r.spec.title, severity: r.spec.severity, version: r.version, perDay: r.perDay,
      dataSource: r.spec.dataSource, technique: r.spec.subtechnique, text: r.text, noise: r.noise, suggestions: suggestions(r),
    }])),
  });
}
