// Line diff (LCS) for the before/after tuning view. Rules are ~40 lines, so O(n·m) is fine.

export type DiffLine = { text: string; kind: "same" | "added" | "removed" };

export function diffLines(before: string, after: string) {
  const a = before.split("\n");
  const b = after.split("\n");
  const dp = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const left: DiffLine[] = [];
  const right: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      left.push({ text: a[i++], kind: "same" });
      right.push({ text: b[j++], kind: "same" });
    } else if (j < b.length && (i >= a.length || dp[i][j + 1] >= dp[i + 1][j])) {
      right.push({ text: b[j++], kind: "added" });
    } else {
      left.push({ text: a[i++], kind: "removed" });
    }
  }
  return {
    before: left,
    after: right,
    added: right.filter((l) => l.kind === "added").length,
    removed: left.filter((l) => l.kind === "removed").length,
  };
}
