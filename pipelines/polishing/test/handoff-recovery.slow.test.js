import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { migratePolishingStateV5 } from "../src/index.js";
import { createRealGitFixture, runGit } from "./support/index.js";

test("reconciles a completed version-5 HANDOFF before validation rediscovery", async (t) => {
  const fixture = await createRealGitFixture(t);
  const completed = await fixture.run();
  await runGit(fixture.projectPath, "reset", "-q");
  const preEffect = await fixture.runtime.git.snapshot({
    allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
    projectPath: fixture.projectPath,
  });
  await runGit(fixture.projectPath, "add", "-A");
  const migrated = migratePolishingStateV5({
    pipelineState: {
      ...completed.pipelineState,
      workflowState: "HANDOFF",
      repositoryBaseline: preEffect,
    },
  });
  assert.equal(migrated.validationMigrationPending, true);
  await fixture.persistPipelineState(migrated);
  const roleCalls = Object.values(fixture.calls).flat().length;

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.validationMigrationPending, false);
  assert.equal(Object.values(fixture.calls).flat().length, roleCalls);
  assert.equal(
    (await runGit(fixture.projectPath, "diff", "--name-only")).stdout,
    "",
  );
  assert.notEqual(
    (await runGit(fixture.projectPath, "diff", "--cached", "--name-only"))
      .stdout,
    "",
  );
});

test("fails closed on a partial version-5 HANDOFF effect", async (t) => {
  let polished = false;
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        !polished
      ) {
        polished = true;
        await writeFile(join(projectPath, "tracked.txt"), "polished\n");
      }
    },
  });
  const completed = await fixture.run();
  await runGit(fixture.projectPath, "reset", "-q");
  const preEffect = await fixture.runtime.git.snapshot({
    allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
    projectPath: fixture.projectPath,
  });
  await runGit(fixture.projectPath, "add", "change.txt");
  const migrated = migratePolishingStateV5({
    pipelineState: {
      ...completed.pipelineState,
      workflowState: "HANDOFF",
      repositoryBaseline: preEffect,
    },
  });
  await fixture.persistPipelineState(migrated);
  const roleCalls = Object.values(fixture.calls).flat().length;

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_POLISHING_HANDOFF_CONTAMINATED",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(Object.values(fixture.calls).flat().length, roleCalls);
});
