import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { normalizeAdapterFailure } from "../../../src/agents/index.js";
import {
  migratePlanExecutionStateV5,
  planExecutionPipeline,
} from "../src/index.js";
import {
  SOURCE_SESSION,
  bootstrapReady,
  clarificationReady,
  finalizationWithTrustedCheck,
  trustedValidationSnapshot,
  createFixture,
  createRealGitFixture,
  executeFile,
  finalizationPassed,
  implementationCompleted,
  migrateVersionOneState,
  reconciliationResolved,
  reviewApproved,
  terminalConfirmation,
  versionOneState,
} from "./support/index.js";

test("carries saved effort through role turns and omits current", async (t) => {
  for (const effort of ["current", "xhigh"]) {
    const fixture = await createFixture(t);
    fixture.currentRun.roles.worker.effort = effort;
    fixture.currentRun.roles.reviewer.effort = "medium";
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "DONE");
    assert.ok(fixture.calls.worker.length > 0);
    assert.ok(fixture.calls.reviewer.length > 0);
    for (const request of fixture.calls.worker) {
      assert.equal(request.effort, effort === "current" ? undefined : effort);
    }
    assert.ok(
      fixture.calls.reviewer.every(({ effort }) => effort === "medium"),
    );
    assert.doesNotMatch(
      JSON.stringify(planExecutionPipeline.projections.status(result)),
      /effort|xhigh|medium/u,
    );
    assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  }
});

test("implements, reviews, finalizes, confirms, and commits one step", async (t) => {
  let initialHead;
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        initialHead ??= (
          await executeFile("git", ["-C", request.cwd, "rev-parse", "HEAD"])
        ).stdout.trim();
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await writeFile(
          join(request.cwd, "generated.js"),
          "export const generated = true;\n",
        );
      }
    },
  });

  const result = await fixture.run();
  const head = (
    await executeFile("git", ["-C", fixture.projectPath, "rev-parse", "HEAD"])
  ).stdout.trim();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.notEqual(head, initialHead);
  assert.equal(result.pipelineState.completedCommits[0], head);
  assert.equal(fixture.calls.worker.at(-3).access, "workspace-write");
  assert.equal(fixture.calls.worker.at(-2).access, "workspace-write");
  assert.equal(fixture.calls.worker.at(-1).access, "local-commit");
  assert.equal(fixture.calls.reviewer.at(-1).access, "read-only");
});

test("creates one verified local commit for every plan step", async (t) => {
  const plan = `## Commit 1: feat(test): add first behavior

Implement the first behavior.

## Commit 2: fix(test): add second behavior

Implement the second behavior.`;
  const fixture = await createRealGitFixture(t, {
    plan,
    sourceSession: SOURCE_SESSION,
    workReviewer: [reviewApproved(), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();
  const { stdout } = await executeFile("git", [
    "-C",
    fixture.projectPath,
    "log",
    "-2",
    "--pretty=%s",
  ]);

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.completedCommits.length, 2);
  assert.deepEqual(stdout.trim().split("\n"), [
    "fix(test): add second behavior",
    "feat(test): add first behavior",
  ]);
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ commit }) => commit.message),
    ["feat(test): add first behavior", "fix(test): add second behavior"],
  );
  const implementationCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Implement the changes described"),
  );
  const reviewCalls = fixture.calls.reviewer.filter(({ prompt }) =>
    prompt.includes("Review the changes and verify"),
  );
  const confirmationCalls = fixture.calls.reviewer.filter(({ prompt }) =>
    prompt.includes("Confirm the finalized changes"),
  );
  assert.equal(implementationCalls.length, 2);
  assert.equal(reviewCalls.length, 2);
  assert.equal(confirmationCalls.length, 2);
  for (const request of [...implementationCalls, ...reviewCalls]) {
    assert.deepEqual(request.session, { mode: "fork", id: SOURCE_SESSION });
    assert.equal(request.prompt, request.recoveryPrompt);
  }
  assert.ok(
    confirmationCalls.every(({ session }) => session?.mode === "continue"),
  );
  const workerCheckpointKeys = result.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .slice(-2)
    .map(({ contextKey }) => contextKey);
  const reviewerCheckpointKeys = result.sessionLineage.children
    .filter(({ role }) => role === "reviewer")
    .slice(-2)
    .map(({ contextKey }) => contextKey);
  assert.notEqual(workerCheckpointKeys[0], workerCheckpointKeys[1]);
  assert.notEqual(reviewerCheckpointKeys[0], reviewerCheckpointKeys[1]);
  assert.deepEqual(fixture.calls.reviewer.at(-1).session, {
    mode: "continue",
    id: result.sessionLineage.children
      .filter(({ role }) => role === "reviewer")
      .at(-1).sessionId,
  });
});

test("accepts a verified commit after an interrupted adapter result", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        request.commit.message,
      ]);
      const error = new Error("Commit result was lost.");
      error.code = "ERR_FAKE_LOCAL_COMMIT_INTERRUPTED";
      error.ambiguous = true;
      throw error;
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("accounts for a verified commit before retaining configuration drift", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        request.commit.message,
      ]);
      const error = new Error("Project configuration changed after commit.");
      error.code = "ERR_PROJECT_CONFIGURATION_CHANGED";
      throw error;
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.deepEqual(result.pause, {
    reason: "project_configuration_changed",
    code: "ERR_PROJECT_CONFIGURATION_CHANGED",
  });
  assert.equal(result.pipelineState.currentStep, null);
  assert.equal(result.pipelineState.pendingCommit, null);
  assert.equal(result.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("renews a policy-rejected commit authorization after Git proves no effect", async (t) => {
  let rejectCommit = true;
  const fixture = await createFixture(t, {
    async onRoleRun(_role, request) {
      if (request.access === "local-commit" && rejectCommit) {
        rejectCommit = false;
        const error = new Error("The adapter rejected the commit request.");
        error.code = "ERR_FAKE_LOCAL_COMMIT_POLICY";
        error.effectStarted = false;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pause.code, "ERR_FAKE_LOCAL_COMMIT_POLICY");
  assert.equal(paused.pause.resumeState, "COMMIT");
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.equal(
    fixture.transitions.findLast(
      ({ options }) => options?.activity?.kind === "authorization-retired",
    ).patch.pipelineState.pendingCommit,
    null,
  );

  const resumed = await fixture.run();
  const commitRequests = fixture.calls.worker.filter(
    ({ access }) => access === "local-commit",
  );

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    commitRequests.map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("preserves pre-effect proof across interrupted Git verification", async (t) => {
  let rejectCommit = true;
  let interruptVerification = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (interruptVerification) {
        interruptVerification = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
    onRoleRun(_role, request) {
      if (request.access === "local-commit" && rejectCommit) {
        rejectCommit = false;
        const error = new Error("The adapter rejected the commit request.");
        error.code = "ERR_FAKE_LOCAL_COMMIT_POLICY";
        error.effectStarted = false;
        throw error;
      }
    },
  });

  const verificationPaused = await fixture.run();

  assert.equal(verificationPaused.pause.reason, "commit_failed");
  assert.equal(verificationPaused.pause.code, "ERR_FAKE_COMMIT_VERIFICATION");
  assert.deepEqual(
    verificationPaused.pipelineState.pendingCommit.preEffectRejection,
    {
      code: "ERR_FAKE_LOCAL_COMMIT_POLICY",
      recoverable: false,
    },
  );

  const rejectionPaused = await fixture.run();

  assert.equal(rejectionPaused.pause.reason, "commit_failed");
  assert.equal(rejectionPaused.pause.code, "ERR_FAKE_LOCAL_COMMIT_POLICY");
  assert.equal(rejectionPaused.pipelineState.pendingCommit, null);

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("re-authorizes after a proven pre-effect Codex overload rejection", async (t) => {
  let backendUnavailable = true;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewApproved(),
      bootstrapReady("Migrating Reviewer"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request) {
      if (request.access === "local-commit" && backendUnavailable) {
        backendUnavailable = false;
        throw normalizeAdapterFailure(
          "codex",
          Object.assign(new Error("provider-native overload secret"), {
            code: "ERR_CODEX_TURN_FAILED",
            diagnosticClass: "turn_server_overloaded",
            recoverable: true,
            ambiguous: false,
            effectStarted: false,
          }),
        );
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CODEX_TURN_FAILED");
  assert.equal(paused.pause.resumeState, "COMMIT");
  assert.equal(paused.pipelineState.pendingCommit, null);
  const rejectedRequest = fixture.calls.worker.findLast(
    ({ access }) => access === "local-commit",
  );
  assert.equal(rejectedRequest.authorizationId, "commit-1");
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /overload secret/u);

  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.pendingCommit, null);
  fixture.persistPipelineState(migrated, { pause: paused.pause });
  const resumed = await fixture.run();
  const commitRequests = fixture.calls.worker.filter(
    ({ access }) => access === "local-commit",
  );

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.completedCommits.length, 1);
  assert.deepEqual(
    commitRequests.map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("does not renew an unmarked provider rejection", async (t) => {
  const fixture = await createFixture(t, {
    onRoleRun(_role, request) {
      if (request.access === "local-commit") {
        const error = new Error("Provider capacity is unavailable.");
        error.code = "ERR_FAKE_PROVIDER_LIMIT";
        error.recoverable = true;
        error.ambiguous = false;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  const resumed = await fixture.run();

  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  assert.equal(resumed.pause.reason, "commit_failed");
  assert.equal(resumed.pipelineState.pendingCommit.status, "consumed");
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("resumes commit verification without replaying the Worker", async (t) => {
  let verificationUnavailable = true;
  const fixture = await createFixture(t, {
    onCommitVerify() {
      if (verificationUnavailable) {
        verificationUnavailable = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  const resumed = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("verifies a consumed version-5 authorization before validation migration", async (t) => {
  let verificationUnavailable = true;
  const trustedValidation = trustedValidationSnapshot();
  const finalization = finalizationWithTrustedCheck(trustedValidation);
  const requiredChecks = finalization.requiredChecks;
  const fixture = await createFixture(t, {
    trustedValidation,
    modeSettings: { trustedChecks: ["service-check"] },
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
    ],
    reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
    workWorker: [implementationCompleted(), finalization],
    onTrustedValidation(options) {
      return {
        ...options.bindings,
        status: "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: 0,
        signal: null,
        timedOut: false,
        evidence: ["Fixture trusted check passed."],
      };
    },
    onCommitVerify() {
      if (verificationUnavailable) {
        verificationUnavailable = false;
        const error = new Error("Git verification was interrupted.");
        error.code = "ERR_FAKE_COMMIT_VERIFICATION";
        throw error;
      }
    },
  });
  const paused = await fixture.run({ trustedChecks: ["service-check"] });
  const roleCallCount = Object.values(fixture.calls).flat().length;
  const migrated = migratePlanExecutionStateV5({
    pipelineState: paused.pipelineState,
    pause: paused.pause,
  });
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.equal(migrated.validationMigrationPending, true);
  fixture.persistPipelineState(migrated, { pause: paused.pause });

  fixture.runtime.trustedValidation.preflight = async () => {
    assert.fail("Consumed commit verification must precede capability checks.");
  };
  const resumed = await fixture.run({ trustedChecks: ["service-check"] });

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pipelineState.validationMigrationPending, false);
  assert.equal(Object.values(fixture.calls).flat().length, roleCallCount);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("prepared commit authority survives an unavailable capability and resumes once", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const finalization = finalizationWithTrustedCheck(trustedValidation);
  const requiredChecks = finalization.requiredChecks;
  const settings = { trustedChecks: ["service-check"] };
  const interruption = new Error(
    "Interrupted after preparing commit authority",
  );
  let interrupt = true;
  const fixture = await createFixture(t, {
    trustedValidation,
    modeSettings: settings,
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
    ],
    reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
    workWorker: [implementationCompleted(), finalization],
    onTrustedValidation(options) {
      return {
        ...options.bindings,
        status: "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: 0,
        signal: null,
        timedOut: false,
        evidence: ["Fixture trusted check passed."],
      };
    },
    onTransition(run) {
      if (interrupt && run.pipelineState.pendingCommit?.status === "prepared") {
        interrupt = false;
        throw interruption;
      }
    },
  });
  await assert.rejects(
    fixture.run(settings),
    (cause) => cause === interruption,
  );
  const prepared = fixture.currentRun.pipelineState.pendingCommit;
  assert.equal(prepared.status, "prepared");
  const calls = Object.values(fixture.calls).flat().length;
  for (const code of [
    "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
    "ERR_TRUSTED_VALIDATION_ISOLATION_UNAVAILABLE",
  ]) {
    fixture.runtime.trustedValidation.preflight = async () => {
      throw Object.assign(new Error("Fixture unavailable capability"), {
        code,
      });
    };
    const paused = await fixture.run(settings);
    assert.equal(paused.pause.reason, "environment_blocked");
    assert.equal(paused.pause.resumeState, "COMMIT");
    assert.deepEqual(paused.pipelineState.pendingCommit, prepared);
    assert.deepEqual(paused.pipelineState.completedCommits, []);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
    assert.throws(() =>
      planExecutionPipeline.workflow.validateRun({
        ...paused,
        pause: { ...paused.pause, code: "ERR_UNRELATED_FAILURE" },
      }),
    );
  }
  fixture.runtime.trustedValidation.preflight = async () => {};
  const completed = await fixture.run(settings);
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.completedCommits.length, 1);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("interrupted safety pauses do not inspect capabilities before recovery is authorized", async (t) => {
  const settings = { trustedChecks: ["service-check"] };
  const fixture = await createFixture(t, {
    trustedValidation: trustedValidationSnapshot(),
    modeSettings: settings,
    onRoleRun(_role, _request, _count, repository) {
      repository.changeRefs();
    },
  });
  const paused = await fixture.run(settings);
  assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
  fixture.repository.changeRefs("fixture-refs");
  fixture.currentRun.activeTurn = { role: "worker", phase: "clarify" };
  fixture.runtime.trustedValidation.preflight = async () => {
    assert.fail("A safety pause must not probe capabilities for new work.");
  };
  const calls = Object.values(fixture.calls).flat().length;
  const result = await fixture.run(settings);
  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, paused.pause.reason);
  assert.equal(Object.values(fixture.calls).flat().length, calls);
});

test("immutable failed execution does not inspect trusted capabilities", async (t) => {
  const failure = new Error("Fixture provider failure");
  const fixture = await createFixture(t, {
    trustedValidation: trustedValidationSnapshot(),
    modeSettings: { trustedChecks: ["service-check"] },
    onRoleRun() {
      throw failure;
    },
  });
  await assert.rejects(
    fixture.run({ trustedChecks: ["service-check"] }),
    (cause) => cause === failure,
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  fixture.currentRun.activeTurn = { role: "worker", phase: "clarify" };
  fixture.runtime.trustedValidation.preflight = async () => {
    assert.fail("Immutable terminal reads must not probe capabilities.");
  };
  const calls = Object.values(fixture.calls).flat().length;
  const result = await fixture.run({ trustedChecks: ["service-check"] });
  assert.equal(result.pipelineState.workflowState, "FAILED");
  assert.equal(Object.values(fixture.calls).flat().length, calls);
});

test("never replays a consumed authorization when no commit was created", async (t) => {
  const fixture = await createFixture(t, {
    onCommitRun() {
      const error = new Error("Commit process was interrupted.");
      error.code = "ERR_FAKE_LOCAL_COMMIT_INTERRUPTED";
      error.ambiguous = true;
      throw error;
    },
  });

  const paused = await fixture.run();
  const migrated = migrateVersionOneState(
    versionOneState(paused.pipelineState),
  );
  assert.equal(migrated.validationMigrationPending, true);
  assert.equal(migrated.pendingCommit.status, "consumed");
  assert.equal(migrated.pendingCommit.preEffectRejection, null);
  fixture.persistPipelineState(migrated, { pause: paused.pause });
  const resumed = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "commit_failed");
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  assert.equal(resumed.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(resumed.pause.reason, "commit_failed");
  assert.ok(resumed.revision > paused.revision);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    1,
  );
});

test("pauses without rewriting a commit that violates its authorization", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onCommitRun(request) {
      await executeFile("git", ["-C", request.cwd, "add", "-A"]);
      await executeFile("git", [
        "-C",
        request.cwd,
        "commit",
        "-qm",
        `${request.commit.message}\n\nCo-authored-by: Other <other@example.com>`,
      ]);
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "commit_contract_violated");
  assert.ok(result.pause.changes.includes("co-author"));
  assert.deepEqual(result.pipelineState.completedCommits, []);
  assert.equal(result.pipelineState.pendingCommit.status, "consumed");
});

test("does not let Claude provider recovery mask a control mutation", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "remote",
          "add",
          "unexpected",
          "https://example.invalid/repository.git",
        ]);
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "unexpected_remote_configuration_change");
  assert.notEqual(paused.pause.reason, "backend_unavailable");
});

test("pauses when a Worker changes Git history outside COMMIT", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "commit",
          "--allow-empty",
          "-qm",
          "test: unauthorized",
        ]);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_git_ref_change");
  assert.equal(result.pipelineState.finalizationResult, null);
});

test("pauses when a Worker changes remote configuration", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await executeFile("git", [
          "-C",
          request.cwd,
          "remote",
          "add",
          "origin",
          "https://example.invalid/repository.git",
        ]);
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unexpected_remote_configuration_change");
});

test("invalidates work when the Reviewer mutates the repository", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.prompt.includes("Review the changes")
      ) {
        await writeFile(join(request.cwd, "source.js"), "reviewer mutation\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.currentStep, null);
});

test("requires Reviewer acceptance for planned validation-infrastructure changes", async (t) => {
  const infrastructurePath = "package.json";
  const accepted = await createFixture(t, {
    onRoleRun: async (role, request) => {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await writeFile(
          join(request.cwd, infrastructurePath),
          '{"scripts":{"test":"node --test --test-reporter=spec"}}\n',
        );
      }
    },
    workReviewer: [terminalConfirmation(reviewApproved("ACCEPTED"))],
  });
  const completed = await accepted.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    completed.pipelineState.reviewResult.validationChange,
    "ACCEPTED",
  );
  const reviewPrompt = accepted.calls.reviewer.find(({ prompt }) =>
    prompt.includes("Confirm the finalized changes"),
  ).prompt;
  assert.match(
    reviewPrompt,
    /Established validation tuple:[\s\S]*Candidate validation tuple and finalization evidence:/u,
  );
  assert.match(
    reviewPrompt,
    /"validationInfrastructureFingerprint": "[a-f0-9]{64}"/u,
  );

  const rejected = await createFixture(t, {
    onRoleRun: async (role, request) => {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes")
      ) {
        await writeFile(
          join(request.cwd, infrastructurePath),
          '{"scripts":{"test":"true"}}\n',
        );
      }
    },
    workReviewer: [
      terminalConfirmation(reviewApproved()),
      terminalConfirmation(reviewApproved()),
    ],
  });
  const paused = await rejected.run();
  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "confirmation_output_invalid");
  assert.deepEqual(paused.pause.evidence, [
    "Reviewer field validationChange violated matches-finalization-change.",
  ]);
});
