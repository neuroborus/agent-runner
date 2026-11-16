import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { migratePolishingStateV5 } from "../src/index.js";
import {
  bootstrapCapacityExhausted,
  bootstrapReady,
  clarificationReady,
  createRealGitFixture,
  finalizationPassed,
  polishingCompleted,
  reconciliationResolved,
  runGit,
} from "./support/index.js";

async function createHookFixture(t, options = {}) {
  const fixture = await createRealGitFixture(t, {
    ...options,
    async prepareProject(projectPath) {
      const hooksPath = join(projectPath, "LOCAL_ARTIFACTS", "hooks");
      await mkdir(hooksPath, { recursive: true });
      await writeFile(
        join(hooksPath, "post-index-change"),
        '#!/bin/sh\nprintf "%s\\n" invoked >> ../hook-receipt\n',
        { mode: 0o755 },
      );
      await runGit(
        projectPath,
        "config",
        "core.hooksPath",
        "LOCAL_ARTIFACTS/hooks",
      );
    },
  });
  const receiptPath = join(fixture.projectPath, "..", "hook-receipt");
  // Initial fixture staging proves that ordinary Git activates the hook.
  assert.match(await readFile(receiptPath, "utf8"), /^invoked\n/u);
  await rm(receiptPath);
  const configPath = join(fixture.projectPath, ".git", "config");
  const configuration = await readFile(configPath);
  return Object.assign(fixture, {
    receiptPath,
    async assertHookUnchanged() {
      assert.deepEqual(await readFile(configPath), configuration);
      await assert.rejects(readFile(receiptPath), { code: "ENOENT" });
    },
  });
}

function forbidStaging(fixture) {
  fixture.runtime.git = {
    ...fixture.runtime.git,
    async stagePolishingHandoff() {
      assert.fail("Recovery must inspect without staging.");
    },
  };
}

test("reconciles a completed version-5 HANDOFF before validation rediscovery", async (t) => {
  const fixture = await createHookFixture(t);
  const completed = await fixture.run();
  await fixture.assertHookUnchanged();
  await runGit(fixture.projectPath, "reset", "-q");
  const preEffect = await fixture.runtime.git.snapshot({
    allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
    projectPath: fixture.projectPath,
  });
  await runGit(fixture.projectPath, "add", "-A");
  await rm(fixture.receiptPath);
  const staged = await fixture.runtime.git.snapshot({
    allowedPaths: preEffect.allowedPaths,
    projectPath: fixture.projectPath,
  });
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
  forbidStaging(fixture);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.validationMigrationPending, false);
  assert.equal(Object.values(fixture.calls).flat().length, roleCalls);
  assert.deepEqual(resumed.pipelineState.repositoryBaseline, staged);
  assert.equal(
    (await runGit(fixture.projectPath, "diff", "--name-only")).stdout,
    "",
  );
  assert.notEqual(
    (await runGit(fixture.projectPath, "diff", "--cached", "--name-only"))
      .stdout,
    "",
  );
  await fixture.assertHookUnchanged();
});

test("routes an untouched version-5 HANDOFF through validation rediscovery with hooks configured", async (t) => {
  const fixture = await createHookFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      bootstrapCapacityExhausted("requiredChecks"),
    ],
  });
  const completed = await fixture.run();
  await fixture.assertHookUnchanged();
  await runGit(fixture.projectPath, "reset", "-q");
  await rm(fixture.receiptPath);
  const preEffect = await fixture.runtime.git.snapshot({
    allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
    projectPath: fixture.projectPath,
  });
  await fixture.persistPipelineState(
    migratePolishingStateV5({
      pipelineState: {
        ...completed.pipelineState,
        workflowState: "HANDOFF",
        repositoryBaseline: preEffect,
      },
    }),
  );
  const workerCalls = fixture.calls.worker.length;
  const reviewerCalls = fixture.calls.reviewer.length;
  forbidStaging(fixture);

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "bootstrap_inventory_capacity_exhausted");
  assert.equal(paused.pipelineState.validationMigrationPending, true);
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.equal(fixture.calls.worker.length, workerCalls + 1);
  assert.equal(fixture.calls.reviewer.length, reviewerCalls);
  assert.match(
    fixture.calls.worker.at(-1).prompt,
    /versioned-state migration checkpoint/u,
  );
  assert.deepEqual(
    await fixture.runtime.git.snapshot({
      allowedPaths: preEffect.allowedPaths,
      projectPath: fixture.projectPath,
    }),
    preEffect,
  );
  await fixture.assertHookUnchanged();
});

test("fails closed on a partial version-5 HANDOFF effect", async (t) => {
  let polished = false;
  const fixture = await createHookFixture(t, {
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
  await fixture.assertHookUnchanged();
  await runGit(fixture.projectPath, "reset", "-q");
  const preEffect = await fixture.runtime.git.snapshot({
    allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
    projectPath: fixture.projectPath,
  });
  await runGit(fixture.projectPath, "add", "change.txt");
  await rm(fixture.receiptPath);
  const partial = await fixture.runtime.git.snapshot({
    allowedPaths: preEffect.allowedPaths,
    projectPath: fixture.projectPath,
  });
  const migrated = migratePolishingStateV5({
    pipelineState: {
      ...completed.pipelineState,
      workflowState: "HANDOFF",
      repositoryBaseline: preEffect,
    },
  });
  await fixture.persistPipelineState(migrated);
  const roleCalls = Object.values(fixture.calls).flat().length;
  forbidStaging(fixture);

  await assert.rejects(
    fixture.run(),
    (cause) => cause.code === "ERR_POLISHING_HANDOFF_CONTAMINATED",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(Object.values(fixture.calls).flat().length, roleCalls);
  assert.deepEqual(
    await fixture.runtime.git.snapshot({
      allowedPaths: preEffect.allowedPaths,
      projectPath: fixture.projectPath,
    }),
    partial,
  );
  await fixture.assertHookUnchanged();
});
