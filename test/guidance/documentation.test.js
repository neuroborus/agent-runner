import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("the mapped common guide preserves supervision and recovery contracts without reference-specific advice", async () => {
  const [guide, map, readme, architecture, operator, safety] =
    await Promise.all(
      [
        "docs/OPERATOR_GUIDE.md",
        "docs/README.md",
        "README.md",
        "docs/ARCHITECTURE.md",
        "docs/product/OPERATOR_MODEL.md",
        "docs/product/SAFETY_MODEL.md",
      ].map((path) =>
        readFile(new URL(`../../${path}`, import.meta.url), "utf8"),
      ),
    );
  assert.equal([...map.matchAll(/\]\(OPERATOR_GUIDE\.md\)/gu)].length, 1);
  assert.match(readme, /\]\(docs\/OPERATOR_GUIDE\.md\)/u);
  for (const phrase of [
    "plan-authoring",
    "plan-execution",
    "polishing",
    "independent",
    "lazy",
    "nextActions",
    "respond",
    "resume",
    "start-new-run",
    "run_wait",
    "run_activity",
    "unexpected_issue_report",
    "guidance_read",
    "guidance_update",
    "artifactRoot",
    "SHA-256",
    "chain-of-thought",
  ]) {
    assert.ok(guide.includes(phrase), `Guide must cover ${phrase}`);
  }
  assert.match(guide, /A pause is not completion/u);
  assert.match(guide, /ends only that wait/u);
  assert.match(
    guide,
    /Do not manually finish, validate, rewrite,\s+discard, or commit/u,
  );
  assert.match(guide, /polishing.*never commits/isu);
  assert.match(guide, /uncontaminated worktree/u);
  assert.match(guide, /Never weaken tests/u);
  assert.match(guide, /cannot weaken common safety/u);
  assert.match(guide, /agent-run guidance --project/u);
  assert.match(guide, /agent-run guidance edit --project/u);
  assert.match(guide, /failed or signalled editor cannot publish/u);
  assert.match(readme, /guidance edit/u);
  for (const document of [guide, readme, architecture, operator]) {
    assert.match(document, /guidance_read/u);
    assert.match(document, /guidance_update/u);
    assert.match(document, /expectedHash/u);
    assert.match(document, /idempotencyKey/u);
    assert.match(document, /issue reporting is disabled/u);
  }
  assert.doesNotMatch(
    guide,
    /FASQON|fasqon|BOOSTY|neuroborus|TaskStop|squarefi|utila|Co-authored-by:|\/home\/|~\/Desktop/u,
  );
  for (const document of [architecture, operator, safety]) {
    assert.match(document, /guidance/iu);
    assert.match(document, /receipt/iu);
    assert.match(document, /role prompts|roles do not receive/u);
  }
});
