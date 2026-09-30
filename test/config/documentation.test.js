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
  assert.match(authoringSpecification, /maxRevisionRounds = 20/u);
  assert.match(authoringSpecification, /preferredCommitLineLimit = 900/u);
  for (const document of [readme, architecture, authoringSpecification]) {
    assert.match(document, /preferredCommitLineLimit/u);
    assert.match(document, /additions\s+plus deletions/u);
    assert.match(document, /heuristic/u);
    assert.match(document, /indivisible|cannot be split safely/u);
  }
  assert.match(authoringSpecification, /stagnationWindowRounds = 3/u);
  assert.match(executionSpecification, /maxFixRoundsPerStep = 20/u);
  assert.match(executionSpecification, /maxDisputesPerFinding = 5/u);
  assert.match(executionSpecification, /maxSameFindingRounds = 5/u);
  assert.match(executionSpecification, /stagnationWindowRounds = 3/u);
  assert.match(polishingSpecification, /maxFixRounds = 20/u);
  assert.match(polishingSpecification, /maxDisputesPerFinding = 5/u);
  assert.match(polishingSpecification, /maxSameFindingRounds = 5/u);
  assert.match(polishingSpecification, /stagnationWindowRounds = 3/u);
  assert.match(agents, /`src\/config\/index\.js`/u);
});

test("trusted command timeout contract is documented by every owner", async () => {
  const paths = [
    ".agent-runner.example.json",
    "README.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/ARCHITECTURE.md",
    "docs/product/OPERATOR_MODEL.md",
    "docs/product/VALIDATION_AND_REVIEW.md",
    "docs/product/SAFETY_MODEL.md",
    "pipelines/plan-execution/docs/SPEC.md",
    "pipelines/polishing/docs/SPEC.md",
    "RHYTHM.md",
  ];
  const documents = await Promise.all(
    paths.map((path) =>
      readFile(new URL(`../../${path}`, import.meta.url), "utf8"),
    ),
  );

  for (const [index, document] of documents.entries()) {
    assert.match(document, /trustedCommandTimeoutMs/u, paths[index]);
    assert.match(document, /3600000|one hour|60 minutes/u, paths[index]);
  }
  for (const path of [
    "README.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/ARCHITECTURE.md",
    "docs/product/OPERATOR_MODEL.md",
    "docs/product/VALIDATION_AND_REVIEW.md",
    "docs/product/SAFETY_MODEL.md",
    "pipelines/plan-execution/docs/SPEC.md",
    "pipelines/polishing/docs/SPEC.md",
  ]) {
    const document = documents[paths.indexOf(path)];
    assert.match(document, /2147483647/u, path);
    assert.match(document, /milliseconds?/u, path);
    assert.match(
      document,
      /project.{0,80}(?:overrides|wins|over).{0,80}(?:root|runner)/su,
      path,
    );
    assert.match(document, /CLI.{0,40}MCP|MCP.{0,40}CLI/su, path);
    assert.match(document, /resume/su, path);
    assert.match(document, /stdout|stderr/u, path);
    assert.match(document, /host/u, path);
  }
});
