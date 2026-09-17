import assert from "node:assert/strict";
import { appendFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "../src/index.js";
import {
  CLEAN_CONFIRM_SCHEMA,
  REVIEW_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import { createLegacyRecoveryFixture } from "./support/index.js";

test("legacy confirmation recovers directly with proven accounting and completed commits", async (t) => {
  for (const options of [
    { mode: "lazy", pendingCorrection: true },
    { mode: "lazy", pendingCorrection: false },
    { mode: "independent", pendingCorrection: false },
    { mode: "independent", pendingCorrection: true, source: true },
    { mode: "lazy", pendingCorrection: true, format: true, source: true },
    { mode: "lazy", pendingCorrection: true, reuseFinalization: true },
    { mode: "lazy", pendingCorrection: true, trusted: true },
  ])
    await t.test(JSON.stringify(options), async (t) => {
      const fixture = await createLegacyRecoveryFixture(t, options);
      const { failed } = fixture;
      assert.equal(
        failed.pipelineState.pendingCorrection,
        options.pendingCorrection,
      );
      assert.equal(failed.pipelineState.finalizationResult.status, "PASS");
      assert.equal(failed.pipelineState.completedCommits.length, 1);
      const bytes = await fixture.bytes();
      assert.deepEqual(await fixture.recoveryAction(), [
        { type: "resume", action: null },
      ]);
      assert.deepEqual(await fixture.bytes(), bytes, "status is read-only");
      const callsBefore = fixture.calls.length;
      const { run } = await fixture
        .openRunner()
        .resume({ runId: fixture.runId });
      assert.equal(run.pipelineState.workflowState, "DONE");
      const calls = fixture.calls.slice(callsBefore);
      assert.equal(calls.length, 2);
      assert.equal(calls[0].access, "read-only");
      assert.equal(
        calls[0].schema,
        options.mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA,
      );
      assert.equal(calls[1].access, "local-commit");
      const { events } = await fixture.history();
      const recovered = events.find(
        ({ activity }) => activity?.kind === "recovered",
      );
      assert.ok(recovered);
      assert.equal(recovered.state.pipelineState.workflowState, "CONFIRM");
      assert.deepEqual(recovered.state.counters, failed.counters);
      assert.deepEqual(recovered.state.sessionLineage, failed.sessionLineage);
      assert.deepEqual(recovered.state.pipelineState, {
        ...failed.pipelineState,
        workflowState: "CONFIRM",
      });
      assert.deepEqual(
        run.pipelineState.completedCommits[0],
        failed.pipelineState.completedCommits[0],
      );
      if (options.trusted)
        assert.equal(
          fixture.trustedExecutions,
          2,
          "retained runner evidence is not re-executed",
        );
      assert.doesNotMatch(
        JSON.stringify(events),
        /PRIVATE_LEGACY_PROVIDER_PAYLOAD/u,
      );
      if (options.source && options.mode === "lazy")
        assert.equal(
          fixture.calls.filter(({ session }) => session?.mode === "fork")
            .length,
          1,
        );
      if (options.source)
        assert.equal(
          calls[0].session,
          undefined,
          "recovery reconstructs without reforking the source",
        );
      const completedCalls = fixture.calls.length;
      await fixture.openRunner().resume({ runId: fixture.runId });
      assert.equal(
        fixture.calls.length,
        completedCalls,
        "completed effects are never replayed",
      );
    });
});

test("legacy confirmation rejects a real pending terminal output correction", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    steps: 1,
    pendingConfirmation: true,
  });
  const calls = fixture.calls.length;
  assert.notEqual(
    fixture.failed.pipelineState.pendingConfirmationCorrection,
    null,
  );
  assert.doesNotThrow(() =>
    planExecutionPipeline.workflow.validateRun(fixture.failed),
  );
  assert.deepEqual(await fixture.recoveryAction(), []);
  assert.deepEqual(
    (await fixture.openRunner().resume({ runId: fixture.runId })).run,
    fixture.failed,
  );
  assert.equal(fixture.calls.length, calls);
});

test("legacy confirmation rejects missing, tampered, and discontinuous journal proof", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  const original = await fixture.bytes();
  const restore = () =>
    Promise.all(
      ["state.json", "events.jsonl", "progress.md"].map((name, index) =>
        writeFile(join(fixture.directoryPath, name), original[index]),
      ),
    );
  for (const [name, mutate] of [
    ["missing journal", () => rm(join(fixture.directoryPath, "events.jsonl"))],
    [
      "gap",
      () =>
        fixture.rewrite(({ events }) => {
          events.splice(5, 1);
        }),
    ],
    [
      "snapshot mismatch",
      async () => {
        const state = JSON.parse(original[0]);
        state.pause.diagnosticClass = "turn_bad_request";
        await writeFile(
          join(fixture.directoryPath, "state.json"),
          JSON.stringify(state),
        );
      },
    ],
    [
      "candidate activity",
      () =>
        fixture.rewrite(({ events }) => {
          events.find(
            ({ activity }) =>
              activity?.phase === "clean-confirm" && activity.kind === "clean",
          ).activity.kind = "migrated";
        }),
    ],
    [
      "unchanged check activity",
      () =>
        fixture.rewrite(({ events }) => {
          events.find(
            ({ activity }) =>
              activity?.phase === "check-and-fix" &&
              activity.kind === "unchanged",
          ).activity.kind = "changed";
        }),
    ],
    [
      "finalization provenance",
      () =>
        fixture.rewrite(({ events }) => {
          events.find(
            ({ activity }) =>
              activity?.phase === "finalization" && activity.kind === "passed",
          ).activity.kind = "migrated";
        }),
    ],
    [
      "confirmation turn provenance",
      () =>
        fixture.rewrite(({ events }) => {
          events.find(
            ({ activity }) =>
              activity?.phase === "confirm" && activity.kind === "turn-started",
          ).activity.kind = "summary";
        }),
    ],
    [
      "unrelated terminal failure",
      () =>
        fixture.rewrite(({ events }) => {
          events.at(-1).state.pause.diagnosticClass = "turn_bad_request";
        }),
    ],
    [
      "changed finalized evidence",
      () =>
        fixture.rewrite(({ events }) => {
          events.at(
            -1,
          ).state.pipelineState.finalizationResult.checks[0].evidence = [
            "Altered attestation",
          ];
        }),
    ],
  ])
    await t.test(name, async () => {
      await mutate();
      const calls = fixture.calls.length;
      try {
        try {
          assert.deepEqual(await fixture.recoveryAction(), []);
        } catch (error) {
          assert.ok(
            ["ERR_INVALID_EVENT_LOG", "ERR_INVALID_RUN_STATE"].includes(
              error.code,
            ),
          );
          assert.doesNotMatch(
            error.message,
            /PRIVATE_LEGACY_PROVIDER_PAYLOAD|Altered attestation/u,
          );
        }
        try {
          await fixture.openRunner().resume({ runId: fixture.runId });
        } catch (error) {
          assert.ok(
            ["ERR_INVALID_EVENT_LOG", "ERR_INVALID_RUN_STATE"].includes(
              error.code,
            ),
          );
        }
        assert.equal(fixture.calls.length, calls);
      } finally {
        await restore();
      }
    });
});

test("legacy confirmation permits only the accounting marker, never pending work", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  const history = await fixture.history();
  for (const [field, value] of [
    ["pendingCommit", { status: "consumed" }],
    ["pendingEdit", {}],
    ["pendingLazyCorrection", {}],
    ["pendingConfirmationCorrection", {}],
    ["pendingFinalizationCorrection", {}],
    ["pendingReviewCorrection", {}],
    ["pendingBootstrapCorrection", {}],
    ["validationMigrationPending", true],
    ["candidateMigrationPending", true],
    ["compatibilityCheckRequired", true],
    ["implementationDirection", {}],
    ["stagnationDirection", {}],
    ["pendingDisputes", [{}]],
    ["findings", [{}]],
    ["reviewReconsideration", ["R1"]],
    [
      "finalizationRecovery",
      { ...history.run.pipelineState.finalizationRecovery, required: true },
    ],
  ])
    await t.test(field, () => {
      const changed = structuredClone(history);
      changed.run.pipelineState[field] = value;
      changed.events.at(-1).state = changed.run;
      planExecutionPipeline.prepareRecovery(changed.run, changed);
      assert.throws(() =>
        planExecutionPipeline.validateResumeAction(changed.run, null),
      );
    });
  const run = structuredClone(history.run);
  planExecutionPipeline.prepareRecovery(run, history);
  assert.doesNotThrow(() =>
    planExecutionPipeline.validateResumeAction(run, null),
  );
  run.revision += 1;
  assert.throws(
    () => planExecutionPipeline.validateResumeAction(run, null),
    "proof cannot survive a changed run object",
  );
});

test("legacy confirmation revalidates inputs, content, infrastructure, and Git controls before any provider", async (t) => {
  for (const [name, drift, options = {}] of [
    ["task", (f) => appendFile(join(f.taskPath, "task.md"), "Changed task\n")],
    ["plan", (f) => appendFile(join(f.taskPath, "plan.md"), "Changed plan\n")],
    [
      "context",
      (f) => writeFile(join(f.taskPath, "context.md"), "Unexpected context\n"),
    ],
    [
      "task clarifications",
      (f) =>
        writeFile(join(f.taskPath, "clarifications.md"), "Changed context\n"),
    ],
    [
      "execution clarifications",
      (f) =>
        appendFile(
          f.failed.pipelineState.clarificationPath,
          "Changed context\n",
        ),
    ],
    [
      "content",
      (f) => appendFile(join(f.projectPath, "feature-1.js"), "// drift\n"),
    ],
    [
      "infrastructure",
      (f) => appendFile(join(f.projectPath, "package.json"), " "),
    ],
    [
      "ignored infrastructure",
      (f) =>
        appendFile(
          join(f.projectPath, "LOCAL_ARTIFACTS", "check-config.json"),
          " ",
        ),
      { ignoredInfrastructure: true },
    ],
    ["index", (f) => f.git("add", "-A")],
    ["HEAD", (f) => f.git("commit", "--allow-empty", "-qm", "test: drift")],
    ["ref", (f) => f.git("branch", "unexpected-ref")],
    [
      "remote",
      (f) => f.git("remote", "add", "example", "https://example.invalid/repo"),
    ],
    ["identity", (f) => f.git("config", "user.name", "Changed")],
    [
      "artifact ignore",
      (f) => writeFile(join(f.projectPath, ".gitignore"), ""),
    ],
  ])
    await t.test(name, async (t) => {
      const fixture = await createLegacyRecoveryFixture(t, {
        steps: 1,
        ...options,
      });
      const calls = fixture.calls.length;
      await drift(fixture);
      const { run } = await fixture
        .openRunner()
        .resume({ runId: fixture.runId });
      assert.equal(run.pipelineState.workflowState, "WAITING_FOR_USER");
      if (name === "HEAD") {
        assert.equal(run.pause.reason, "plan_revision_required");
        assert.deepEqual(
          run.pipelineState.repositoryBaseline,
          fixture.failed.pipelineState.repositoryBaseline,
        );
        assert.deepEqual(
          run.pipelineState.completedCommits,
          fixture.failed.pipelineState.completedCommits,
        );
      } else {
        assert.ok(
          [
            "unsafe_git_state",
            "task_input_changed",
            "clarifications_changed",
          ].includes(run.pause.reason),
        );
      }
      assert.equal(fixture.calls.length, calls);
      assert.equal(
        (await fixture.history()).events.some(
          ({ activity }) => activity?.kind === "recovered",
        ),
        false,
      );
    });
});

test("legacy confirmation survives repeated provider failure and recovery persistence crashes", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  fixture.failAgain(2);
  for (let index = 0; index < 2; index += 1) {
    const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
    assert.deepEqual(run.pause, {
      reason: "backend_unavailable",
      code: "ERR_CODEX_TURN_FAILED",
      resumeState: "CONFIRM",
    });
    assert.deepEqual(run.counters, fixture.failed.counters);
    assert.deepEqual(
      run.pipelineState.finalizationResult,
      fixture.failed.pipelineState.finalizationResult,
    );
  }
  assert.equal(
    (await fixture.openRunner().resume({ runId: fixture.runId })).run
      .pipelineState.workflowState,
    "DONE",
  );
  assert.equal(
    fixture.calls.filter(({ schema }) => schema === FINALIZATION_SCHEMA).length,
    1,
  );
  for (const boundary of [
    "event-appended",
    "state-replaced",
    "progress-replaced",
  ])
    await t.test(boundary, async (t) => {
      const crashed = await createLegacyRecoveryFixture(t, {
        steps: 1,
        source: true,
      });
      const error = new Error("Simulated recovery persistence interruption");
      let armed = true;
      const store = crashed.openStore({
        onTransitionBoundary(phase) {
          if (armed && phase === boundary) {
            armed = false;
            throw error;
          }
        },
      });
      await assert.rejects(
        crashed.openRunner(store).resume({ runId: crashed.runId }),
        (cause) => cause === error,
      );
      assert.equal(
        (await crashed.store.loadRun(crashed.runId)).pipelineState
          .workflowState,
        "CONFIRM",
      );
      assert.equal(
        (await crashed.openRunner().resume({ runId: crashed.runId })).run
          .pipelineState.workflowState,
        "DONE",
      );
      assert.equal(
        crashed.calls.filter(({ session }) => session?.mode === "fork").length,
        1,
      );
      assert.equal(
        (await crashed.history()).events.filter(
          ({ activity }) => activity?.kind === "recovered",
        ).length,
        1,
      );
    });
});

test("legacy confirmation rejects canonical path replacement and unavailable trusted infrastructure", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    steps: 1,
    trusted: true,
  });
  const calls = fixture.calls.length;
  const moved = join(fixture.root, "moved-task");
  await rename(fixture.taskPath, moved);
  await symlink(moved, fixture.taskPath);
  try {
    await assert.rejects(
      fixture.openRunner().resume({ runId: fixture.runId }),
      { code: "ERR_RUN_PATH_CHANGED" },
    );
  } finally {
    await rm(fixture.taskPath);
    await rename(moved, fixture.taskPath);
  }
  const error = Object.assign(
    new Error("Fixture trusted infrastructure unavailable"),
    { code: "ERR_TRUSTED_VALIDATION_UNAVAILABLE" },
  );
  const runner = fixture.openRunner(fixture.openStore(), {
    trustedValidation: {
      async preflight() {
        assert.equal(
          await fixture.store.worktreeLeaseOwner(
            fixture.projectPath,
            fixture.runId,
          ),
          fixture.runId,
        );
        throw error;
      },
      async execute() {
        assert.fail("Recovery must reuse trusted evidence.");
      },
    },
  });
  await assert.rejects(
    runner.resume({ runId: fixture.runId }),
    (cause) => cause === error,
  );
  assert.equal(fixture.calls.length, calls);
  assert.deepEqual(await fixture.store.loadRun(fixture.runId), fixture.failed);

  const replaced = fixture.openRunner(fixture.openStore(), {
    trustedValidation: {
      async preflight() {
        assert.equal(
          await fixture.store.worktreeLeaseOwner(
            fixture.projectPath,
            fixture.runId,
          ),
          fixture.runId,
        );
        await rename(fixture.taskPath, moved);
        await symlink(moved, fixture.taskPath);
      },
      async execute() {
        assert.fail("Recovery must reuse trusted evidence.");
      },
    },
  });
  try {
    await assert.rejects(replaced.resume({ runId: fixture.runId }), {
      code: "ERR_RUN_PATH_CHANGED",
    });
    assert.equal(fixture.calls.length, calls);
    assert.equal(
      (await fixture.history()).events.some(
        ({ activity }) => activity?.kind === "recovered",
      ),
      false,
    );
  } finally {
    await rm(fixture.taskPath);
    await rename(moved, fixture.taskPath);
  }
});

test("legacy confirmation restart rechecks canonical paths under execution leases", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, {
    steps: 1,
    trusted: true,
  });
  const interruption = new Error("Simulated durable recovery interruption");
  const store = fixture.openStore({
    onTransitionBoundary(phase) {
      if (phase === "event-appended") throw interruption;
    },
  });
  await assert.rejects(
    fixture.openRunner(store).resume({ runId: fixture.runId }),
    (cause) => cause === interruption,
  );
  assert.equal(
    (await fixture.store.loadRun(fixture.runId)).pipelineState.workflowState,
    "CONFIRM",
  );
  const calls = fixture.calls.length;
  const moved = join(fixture.root, "moved-task");
  const runner = fixture.openRunner(fixture.openStore(), {
    trustedValidation: {
      async preflight() {
        assert.equal(
          await fixture.store.worktreeLeaseOwner(
            fixture.projectPath,
            fixture.runId,
          ),
          fixture.runId,
        );
        await rename(fixture.taskPath, moved);
        await symlink(moved, fixture.taskPath);
      },
      async execute() {
        assert.fail("Recovery must reuse trusted evidence.");
      },
    },
  });
  try {
    await assert.rejects(runner.resume({ runId: fixture.runId }), {
      code: "ERR_RUN_PATH_CHANGED",
    });
    assert.equal(fixture.calls.length, calls);
  } finally {
    await rm(fixture.taskPath);
    await rename(moved, fixture.taskPath);
  }
});
