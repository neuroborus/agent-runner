import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("configuration ownership and defaults are documented", async () => {
  const [
    readme,
    architecture,
    authoringSpecification,
    executionSpecification,
    polishingSpecification,
    agents,
  ] = await Promise.all([
    readFile(new URL("../../README.md", import.meta.url), "utf8"),
    readFile(new URL("../../docs/ARCHITECTURE.md", import.meta.url), "utf8"),
    readFile(
      new URL("../../pipelines/plan-authoring/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../pipelines/plan-execution/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../pipelines/polishing/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../../AGENTS.md", import.meta.url), "utf8"),
  ]);

  assert.match(readme, /roles, configuration settings and defaults/u);
  assert.match(architecture, /\.agent-runner\.json/u);
  assert.match(architecture, /CLI override/u);
  assert.match(architecture, /native default/u);
  assert.match(authoringSpecification, /maxRevisionRounds = 15/u);
  assert.match(authoringSpecification, /stagnationWindowRounds = 3/u);
  assert.match(executionSpecification, /maxFixRoundsPerStep = 5/u);
  assert.match(executionSpecification, /maxDisputesPerFinding = 2/u);
  assert.match(executionSpecification, /maxSameFindingRounds = 3/u);
  assert.match(executionSpecification, /stagnationWindowRounds = 3/u);
  assert.match(polishingSpecification, /maxFixRounds = 5/u);
  assert.match(polishingSpecification, /maxDisputesPerFinding = 2/u);
  assert.match(polishingSpecification, /maxSameFindingRounds = 3/u);
  assert.match(polishingSpecification, /stagnationWindowRounds = 3/u);
  assert.match(agents, /`src\/config\/index\.js`/u);
});
