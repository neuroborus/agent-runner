import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("configuration ownership and defaults are documented", async () => {
  const [
    pipelines,
    pipelineSettings,
    configuration,
    authoringSpecification,
    executionEscalation,
    polishingAdmission,
    agents,
  ] = await Promise.all([
    readFile(new URL("../../docs/user/pipelines.md", import.meta.url), "utf8"),
    readFile(
      new URL("../../docs/user/pipeline-settings.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../docs/architecture/configuration.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../pipelines/plan-authoring/docs/SPEC.md", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL(
        "../../pipelines/plan-execution/docs/escalation.md",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(
      new URL("../../pipelines/polishing/docs/admission.md", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../../AGENTS.md", import.meta.url), "utf8"),
  ]);

  assert.match(pipelines, /roles, configuration settings and defaults/u);
  assert.match(configuration, /\.agent-runner\.json/u);
  assert.match(configuration, /CLI override/u);
  assert.match(configuration, /native default/u);
  assert.match(authoringSpecification, /maxRevisionRounds = 20/u);
  assert.match(authoringSpecification, /preferredCommitLineLimit = 900/u);
  for (const document of [
    pipelineSettings,
    configuration,
    authoringSpecification,
  ]) {
    assert.match(document, /preferredCommitLineLimit/u);
    assert.match(document, /additions\s+plus deletions/u);
    assert.match(document, /heuristic/u);
    assert.match(document, /indivisible|cannot be split safely/u);
  }
  assert.match(authoringSpecification, /stagnationWindowRounds = 3/u);
  assert.match(executionEscalation, /maxFixRoundsPerStep = 20/u);
  assert.match(executionEscalation, /maxDisputesPerFinding = 5/u);
  assert.match(executionEscalation, /maxSameFindingRounds = 5/u);
  assert.match(executionEscalation, /stagnationWindowRounds = 3/u);
  assert.match(polishingAdmission, /maxFixRounds = 20/u);
  assert.match(polishingAdmission, /maxDisputesPerFinding = 5/u);
  assert.match(polishingAdmission, /maxSameFindingRounds = 5/u);
  assert.match(polishingAdmission, /stagnationWindowRounds = 3/u);
  assert.match(agents, /`src\/config\/index\.js`/u);
});

test("trusted command timeout contract is documented by every owner", async () => {
  const paths = [
    ".agent-runner.example.json",
    "docs/user/trusted-validation.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/architecture/configuration.md",
    "docs/product/OPERATOR_MODEL.md",
    "docs/product/VALIDATION_AND_REVIEW.md",
    "docs/product/SAFETY_MODEL.md",
    "pipelines/plan-execution/docs/configuration.md",
    "pipelines/polishing/docs/admission.md",
    "docs/DECISION_HISTORY_2026-09.md",
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
  // Configuration owns deadline resolution; command execution owns
  // isolation and output custody. Inspect both owners without copying contracts.
  const executionOwners = {
    "docs/architecture/configuration.md":
      "docs/architecture/validation/execution.md",
    "pipelines/plan-execution/docs/configuration.md":
      "pipelines/plan-execution/docs/trusted-validation.md",
    "pipelines/polishing/docs/admission.md":
      "pipelines/polishing/docs/finalization.md",
  };
  for (const path of [
    "docs/user/trusted-validation.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/architecture/configuration.md",
    "docs/product/OPERATOR_MODEL.md",
    "docs/product/VALIDATION_AND_REVIEW.md",
    "docs/product/SAFETY_MODEL.md",
    "pipelines/plan-execution/docs/configuration.md",
    "pipelines/polishing/docs/admission.md",
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
    const executionPath = executionOwners[path] ?? path;
    const executionDocument =
      executionPath === path
        ? document
        : await readFile(
            new URL(`../../${executionPath}`, import.meta.url),
            "utf8",
          );
    assert.match(executionDocument, /stdout|stderr/u, executionPath);
    assert.match(executionDocument, /host/u, executionPath);
  }
});
