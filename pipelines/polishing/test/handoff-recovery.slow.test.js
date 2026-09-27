import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import {
  migratePolishingStateV5,
  migratePolishingStateV7,
} from "../src/index.js";
import {
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import {
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createIntegrationFixture,
  createRealGitFixture,
  finalizationPassed,
  polishingCompleted,
  reconciliationResolved,
  reviewApproved,
  runGit,
  trustedValidationSnapshot,
  versionSevenState,
} from "./support/index.js";

for (const applied of [true, false]) {
  test(`${applied ? "completed" : "untouched"} handoff recovery checks capabilities only before new effects`, async (t) => {
    const trustedValidation = trustedValidationSnapshot();
    const command = trustedValidation.commands[0].command;
    const requiredChecks = [
      ...finalizationPassed().requiredChecks,
      { id: "C2", command },
    ];
    const finalization = {
      ...finalizationPassed(),
      requiredChecks,
      checks: [
        ...finalizationPassed().checks,
        {
          checkId: "C2",
          command,
          status: "NOT_RUN",
          evidence: ["Reserved for runner execution."],
        },
      ],
    };
    const fixture = await createIntegrationFixture(t, {
      trustedValidation,
      modeSettings: { trustedChecks: ["service-check"] },
      worker: [
        clarificationReady(),
        { ...bootstrapReady("Worker"), requiredChecks },
        reconciliationResolved(),
        polishingCompleted(),
        finalization,
      ],
      reviewer: [
        { ...bootstrapReady("Reviewer"), requiredChecks },
        candidateApproved(),
        reviewApproved(),
      ],
      onTrustedValidation(options) {
        return {
          ...options.bindings,
          commandIdentity: options.commandIdentity,
          status: "PASS",
          exitCode: 0,
          signal: null,
          timedOut: false,
          evidence: ["Fixture trusted check passed."],
        };
      },
    });
    const git = fixture.runtime.git;
    if (!applied)
      fixture.runtime.git = {
        ...git,
        stagePolishingHandoff: async ({ expectedSnapshot }) => expectedSnapshot,
      };
    const transition = fixture.runtime.transition;
    const interruption = new Error("Interrupted after staging");
    fixture.runtime.transition = async (patch, options) => {
      if (["DONE", "FAILED"].includes(patch.pipelineState.workflowState))
        throw interruption;
      return transition(patch, options);
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    assert.equal(fixture.currentRun.pipelineState.workflowState, "HANDOFF");
    fixture.runtime.transition = transition;
    fixture.runtime.git = git;
    fixture.runtime.trustedValidation.preflight = async () => {
      if (applied)
        assert.fail(
          "Completed handoff verification must precede capability checks.",
        );
      throw Object.assign(new Error("Fixture capability unavailable"), {
        code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
      });
    };
    const calls = Object.values(fixture.calls).flat().length;
    let recovered = await fixture.run();
    if (!applied) {
      assert.equal(recovered.pause.reason, "environment_blocked");
      assert.equal(recovered.pause.resumeState, "HANDOFF");
      assert.equal(Object.values(fixture.calls).flat().length, calls);
      fixture.runtime.trustedValidation.preflight = async () => {};
      recovered = await fixture.run();
    }
    assert.equal(recovered.pipelineState.workflowState, "DONE");
    assert.deepEqual(
      recovered.pipelineState.trustedValidation,
      trustedValidation,
    );
    assert.equal(Object.values(fixture.calls).flat().length, calls);
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

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} recovers a verified runner handoff after DONE persistence is interrupted`, async (t) => {
    const processLoss = new Error("Runner process stopped after staging.");
    const fixture = await createIntegrationFixture(t, {
      mode,
      ...(mode !== "independent"
        ? {
            worker: [
              clarificationReady(),
              bootstrapReady("Worker"),
              ...(mode === "combined" ? [reconciliationResolved()] : []),
              polishingCompleted(),
              checkAndFix(),
              candidateClean(),
              finalizationPassed(),
              ...(mode === "lazy" ? [cleanConfirmation()] : []),
            ],
          }
        : {}),
    });
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
    const confirmer = mode === "lazy" ? "worker" : "reviewer";
    const confirmationSchema =
      mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA;
    const confirmationCalls = fixture.calls[confirmer].filter(
      ({ schema }) => schema === confirmationSchema,
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
      fixture.calls.worker.filter(
        ({ schema }) => schema === FINALIZATION_SCHEMA,
      ).length,
      finalizationCalls,
    );
    assert.equal(
      fixture.calls[confirmer].filter(
        ({ schema }) => schema === confirmationSchema,
      ).length,
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
}

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
