import assert from "node:assert/strict";
import { appendFile, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createGitService } from "../../../src/git/index.js";
import {
  migratePolishingStateV5,
  migratePolishingStateV7,
} from "../src/index.js";
import {
  CHECK_AND_FIX_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import {
  SOURCE_SESSION,
  bootstrapReady,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createIntegrationFixture,
  createRealGitFixture,
  finalizationPassed,
  polishingCompleted,
  reconciliationResolved,
  reconsideration,
  resolution,
  reviewApproved,
  reviewFindings,
  runGit,
  versionSevenState,
} from "./support/index.js";

for (const testCase of [
  {
    backend: "codex",
    path: "tracked.txt",
    content: "codex content update\n",
  },
  {
    backend: "claude",
    path: "claude-added.txt",
    content: "claude content addition\n",
  },
]) {
  test(`runner stages a content-only ${testCase.backend} Worker handoff`, async (t) => {
    let changed = false;
    const fixture = await createRealGitFixture(t, {
      roleBackends: {
        worker: testCase.backend,
        reviewer: testCase.backend === "codex" ? "claude" : "codex",
        arbiter: testCase.backend,
      },
      async onRoleRun(role, request, _turn, { projectPath }) {
        if (
          role === "worker" &&
          /Polish the existing local/u.test(request.prompt) &&
          !changed
        ) {
          changed = true;
          assert.equal(
            (await runGit(projectPath, "diff", "--cached", "--name-only"))
              .stdout,
            "",
          );
          await writeFile(join(projectPath, testCase.path), testCase.content);
        }
      },
    });
    const before = await fixture.runtime.git.snapshot({
      projectPath: fixture.projectPath,
    });

    const completed = await fixture.run();
    const after = completed.pipelineState.repositoryBaseline;

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.roles.worker.backend, testCase.backend);
    assert.equal(after.head, before.head);
    assert.equal(after.refsFingerprint, before.refsFingerprint);
    assert.equal(
      after.remoteConfigurationFingerprint,
      before.remoteConfigurationFingerprint,
    );
    assert.equal(after.identityFingerprint, before.identityFingerprint);
    assert.ok(
      fixture.calls.worker.every(({ access }) => access !== "local-commit"),
    );
    assert.match(
      (await runGit(fixture.projectPath, "diff", "--cached", "--name-only"))
        .stdout,
      new RegExp(`^${testCase.path.replace(".", "\\.")}$`, "mu"),
    );
    assert.equal(
      (await runGit(fixture.projectPath, "diff", "--name-only")).stdout,
      "",
    );
    assert.equal(
      (
        await runGit(
          fixture.projectPath,
          "ls-files",
          "--others",
          "--exclude-standard",
        )
      ).stdout,
      "",
    );
  });
}

test("migrates version-7 handoff and terminal states without replay", async (t) => {
  const fixture = await createRealGitFixture(t);
  const completed = await fixture.run();
  await runGit(fixture.projectPath, "reset", "-q");
  const pendingHandoffBaseline = await fixture.runtime.git.snapshot({
    allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
    projectPath: fixture.projectPath,
  });
  const cases = [
    {
      name: "pending HANDOFF",
      state: {
        ...completed.pipelineState,
        workflowState: "HANDOFF",
        repositoryBaseline: pendingHandoffBaseline,
      },
    },
    {
      name: "completed HANDOFF",
      state: { ...completed.pipelineState, workflowState: "HANDOFF" },
    },
    {
      name: "DONE",
      state: completed.pipelineState,
    },
    {
      name: "FAILED",
      state: { ...completed.pipelineState, workflowState: "FAILED" },
    },
  ];

  for (const migrationCase of cases) {
    await t.test(migrationCase.name, () => {
      const legacy = versionSevenState(migrationCase.state);
      const migrated = migratePolishingStateV7({ pipelineState: legacy });

      assert.deepEqual(migrated, {
        ...legacy,
        settings: { ...legacy.settings, mode: "independent" },
        cleanConfirmationFingerprint: null,
        lazySourceForkConsumed: false,
      });
      assert.equal(migrated.workflowState, legacy.workflowState);
      assert.deepEqual(migrated.repositoryBaseline, legacy.repositoryBaseline);
      assert.deepEqual(migrated.finalizationResult, legacy.finalizationResult);
      assert.deepEqual(migrated.reviewResult, legacy.reviewResult);
      assert.doesNotThrow(() => normalizePipelineState(migrated));
    });
  }
});

test("runs lazy polishing with one Worker source fork and no review roles", async (t) => {
  const fixture = await createRealGitFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
  });
  const beforeHead = (await runGit(fixture.projectPath, "rev-parse", "HEAD"))
    .stdout;

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.mode, "lazy");
  assert.equal(result.pipelineState.lazySourceForkConsumed, true);
  assert.equal(
    result.pipelineState.cleanConfirmationFingerprint,
    result.pipelineState.finalizedFingerprint,
  );
  assert.equal(fixture.probes.worker, 1);
  assert.equal(fixture.probes.reviewer, 0);
  assert.equal(fixture.probes.arbiter, 0);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.ok(
    fixture.calls.worker
      .slice(1)
      .every(({ session }) => session?.mode === "continue"),
  );
  assert.equal(
    (await runGit(fixture.projectPath, "rev-parse", "HEAD")).stdout,
    beforeHead,
  );
  assert.notEqual(
    (await runGit(fixture.projectPath, "diff", "--cached", "--name-only"))
      .stdout,
    "",
  );
  assert.equal(
    (await runGit(fixture.projectPath, "diff", "--name-only")).stdout,
    "",
  );
});

test("rejects index mutation during a writable lazy correction", async (t) => {
  let checkTurns = 0;
  const fixture = await createRealGitFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      finalizationPassed(),
      { ...checkAndFix(), status: "INVALID" },
      checkAndFix(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkTurns += 1;
        if (checkTurns === 2) {
          await runGit(projectPath, "add", "change.txt");
        }
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "unexpected_git_index_change");
  assert.equal(paused.pipelineState.pendingLazyCorrection !== null, true);
  assert.equal(paused.pipelineState.cleanConfirmationFingerprint, null);
});

test("rejects Git-index mutation during lazy check/fix", async (t) => {
  const fixture = await createRealGitFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      finalizationPassed(),
      checkAndFix(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        await runGit(projectPath, "add", "change.txt");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_git_index_change");
  assert.equal(result.pipelineState.cleanConfirmationFingerprint, null);
});

test("recovers a verified runner handoff after DONE persistence is interrupted", async (t) => {
  const processLoss = new Error("Runner process stopped after staging.");
  const fixture = await createIntegrationFixture(t);
  const transition = fixture.runtime.transition;
  let interrupt = true;
  fixture.runtime.transition = async (patch, options) => {
    if (
      interrupt &&
      ["DONE", "FAILED"].includes(patch.pipelineState.workflowState)
    ) {
      throw processLoss;
    }
    return transition(patch, options);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "HANDOFF");
  const finalizationCalls = fixture.calls.worker.filter(
    ({ schema }) => schema === FINALIZATION_SCHEMA,
  ).length;
  const confirmationCalls = fixture.calls.reviewer.filter(
    ({ schema }) => schema === REVIEW_SCHEMA,
  ).length;
  assert.equal(finalizationCalls, 1);
  assert.equal(confirmationCalls, 1);
  assert.notEqual(
    fixture.currentRun.pipelineState.repositoryBaseline.indexFingerprint,
    (await fixture.runtime.git.snapshot({ projectPath: fixture.projectPath }))
      .indexFingerprint,
  );

  interrupt = false;
  fixture.runtime.transition = transition;
  await fixture.recover();
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    finalizationCalls,
  );
  assert.equal(
    fixture.calls.reviewer.filter(({ schema }) => schema === REVIEW_SCHEMA)
      .length,
    confirmationCalls,
  );
  assert.equal(
    completed.pipelineState.repositoryBaseline.indexFingerprint,
    (await fixture.runtime.git.snapshot({ projectPath: fixture.projectPath }))
      .indexFingerprint,
  );
  assert.ok(
    fixture.calls.worker.every(({ access }) => access !== "local-commit"),
  );
});

test("reconciles version-5 HANDOFF before completion or validation rediscovery", async (t) => {
  for (const effect of ["complete", "untouched"]) {
    await t.test(effect, async (t) => {
      const fixture = await createRealGitFixture(t, {
        reviewer: [
          bootstrapReady("Reviewer"),
          reviewApproved(),
          bootstrapReady("Migrating Reviewer"),
          reviewApproved(),
        ],
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          reconciliationResolved(),
          polishingCompleted(),
          finalizationPassed(),
          bootstrapReady("Migrating Worker"),
          reconciliationResolved(),
          finalizationPassed(),
        ],
      });
      const completed = await fixture.run();
      await runGit(fixture.projectPath, "reset", "-q");
      const preEffect = await fixture.runtime.git.snapshot({
        allowedPaths: completed.pipelineState.repositoryBaseline.allowedPaths,
        projectPath: fixture.projectPath,
      });
      if (effect === "complete") {
        await runGit(fixture.projectPath, "add", "-A");
      }
      const legacy = {
        ...completed.pipelineState,
        workflowState: "HANDOFF",
        repositoryBaseline: preEffect,
      };
      const migrated = migratePolishingStateV5({ pipelineState: legacy });
      assert.equal(migrated.validationMigrationPending, true);
      assert.doesNotThrow(() => normalizePipelineState(migrated));
      await fixture.persistPipelineState(migrated);
      const roleCalls = Object.values(fixture.calls).flat().length;

      const resumed = await fixture.run();

      assert.equal(resumed.pipelineState.workflowState, "DONE");
      assert.equal(resumed.pipelineState.validationMigrationPending, false);
      const migrationCalls =
        Object.values(fixture.calls).flat().length - roleCalls;
      if (effect === "complete") {
        assert.equal(migrationCalls, 0);
      } else {
        assert.ok(migrationCalls > 0);
      }
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
  }
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

test("accepts staged, unstaged, deleted, and untracked changes as one set", async (t) => {
  const fixture = await createRealGitFixture(t, { dirty: false });
  await writeFile(join(fixture.projectPath, "tracked.txt"), "staged change\n");
  await runGit(fixture.projectPath, "add", "tracked.txt");
  await rm(join(fixture.projectPath, "deleted.txt"));
  await writeFile(join(fixture.projectPath, "untracked.txt"), "untracked\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.repositoryBaseline.clean, false);
});

test("rejects a tracked task input with an index-only change", async (t) => {
  const fixture = await createRealGitFixture(t, {
    taskLocation: "tracked",
    reviewer: [],
    worker: [],
  });
  const taskFile = join(fixture.taskPath, "task.md");
  await appendFile(taskFile, "Staged input change.\n");
  await runGit(fixture.projectPath, "add", "task/task.md");
  await writeFile(taskFile, "# Polish fixture\n");

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "task_input_overlaps_changes");
  assert.match(result.pause.path, /task\.md$/u);
  assert.equal(fixture.calls.worker.length, 0);
});

for (const [name, flag] of [
  ["assume-unchanged", "--assume-unchanged"],
  ["skip-worktree", "--skip-worktree"],
]) {
  test(`rejects tracked task input hidden by ${name}`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      dirty: false,
      taskLocation: "tracked",
      reviewer: [],
      worker: [],
    });
    await runGit(fixture.projectPath, "update-index", flag, "task/task.md");
    await appendFile(join(fixture.taskPath, "task.md"), "Hidden change.\n");

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, "task_input_overlaps_changes");
    assert.match(result.pause.path, /task\.md$/u);
    assert.equal(fixture.calls.worker.length, 0);
  });

  test(`fails closed when ${name} hides handoff content`, async (t) => {
    const fixture = await createRealGitFixture(t, { dirty: false });
    await runGit(fixture.projectPath, "update-index", flag, "tracked.txt");
    await writeFile(
      join(fixture.projectPath, "tracked.txt"),
      "hidden change\n",
    );

    await assert.rejects(
      fixture.run(),
      (error) => error.code === "ERR_POLISHING_HANDOFF_INCOMPLETE",
    );
    assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
    assert.equal(
      (await runGit(fixture.projectPath, "diff", "--cached", "--name-only"))
        .stdout,
      "",
    );
  });
}

test("binds finalization changes and review to one fingerprint without committing", async (t) => {
  let beforeFinalizationFingerprint;
  let beforePolishFingerprint;
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt)
      ) {
        beforePolishFingerprint = await createGitService().contentFingerprint({
          allowedPaths: [],
          projectPath,
        });
        await writeFile(join(projectPath, "tracked.txt"), "polished\n");
      }
      if (
        role === "worker" &&
        /Run the complete project finalization procedure/u.test(request.prompt)
      ) {
        beforeFinalizationFingerprint =
          await createGitService().contentFingerprint({
            allowedPaths: [],
            projectPath,
          });
        await writeFile(join(projectPath, "generated.txt"), "generated\n");
      }
    },
  });
  const beforeHead = (
    await runGit(fixture.projectPath, "rev-parse", "HEAD")
  ).stdout.trim();

  const result = await fixture.run();

  const afterHead = (
    await runGit(fixture.projectPath, "rev-parse", "HEAD")
  ).stdout.trim();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.notEqual(
    result.pipelineState.candidateReviewedFingerprint,
    result.pipelineState.finalizedFingerprint,
  );
  assert.equal(beforeHead, afterHead);
  assert.equal(
    await readFile(join(fixture.projectPath, "generated.txt"), "utf8"),
    "generated\n",
  );
  assert.notEqual(beforePolishFingerprint, beforeFinalizationFingerprint);
  const polishCall = fixture.calls.worker.find(({ prompt }) =>
    /Polish the existing local/u.test(prompt),
  );
  const finalizationCall = fixture.calls.worker.find(({ prompt }) =>
    /Run the complete project finalization procedure/u.test(prompt),
  );
  assert.match(polishCall.prompt, new RegExp(beforePolishFingerprint, "u"));
  assert.match(
    finalizationCall.recoveryPrompt,
    new RegExp(beforeFinalizationFingerprint, "u"),
  );
});

test("rejects index drift from an interrupted content-only correction", async (t) => {
  let interrupted = false;
  const fixture = await createRealGitFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reconsideration("WITHDRAW"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("DISPUTE"),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await runGit(projectPath, "add", "change.txt");
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const interruptedRun = await fixture.run();
  assert.equal(interruptedRun.pause.reason, "unexpected_git_index_change");
  assert.notEqual(interruptedRun.pause.reason, "backend_unavailable");
  assert.equal(interruptedRun.counters.fixRounds, 0);
  assert.equal(interruptedRun.pipelineState.pendingCorrection, false);
});

for (const [name, expectedReason, mutate] of [
  [
    "HEAD",
    "unexpected_git_ref_change",
    async ({ projectPath }) => {
      await runGit(projectPath, "add", "-A");
      await runGit(projectPath, "commit", "-qm", "unauthorized");
    },
  ],
  [
    "refs",
    "unexpected_git_ref_change",
    async ({ projectPath }) => runGit(projectPath, "tag", "unauthorized"),
  ],
  [
    "remotes",
    "unexpected_remote_configuration_change",
    async ({ projectPath }) =>
      runGit(
        projectPath,
        "remote",
        "add",
        "origin",
        "https://example.invalid/polishing.git",
      ),
  ],
  [
    "identity",
    "unexpected_git_identity_change",
    async ({ projectPath }) =>
      runGit(projectPath, "config", "user.name", "Unauthorized Identity"),
  ],
  [
    "index",
    "unexpected_git_index_change",
    async ({ projectPath }) => runGit(projectPath, "add", "change.txt"),
  ],
]) {
  test(`rejects writable Worker ${name} mutations`, async (t) => {
    let mutated = false;
    const fixture = await createRealGitFixture(t, {
      async onRoleRun(role, request, _turn, paths) {
        if (
          role === "worker" &&
          /Polish the existing local/u.test(request.prompt) &&
          !mutated
        ) {
          mutated = true;
          await mutate(paths);
        }
      },
    });

    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.equal(result.pause.reason, expectedReason);
  });
}
