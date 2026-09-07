import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import { MAX_DISPUTE_HISTORY_BYTES } from "../src/workflow-contract.js";
import {
  SOURCE_SESSION,
  SETTINGS,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  createFixture,
  createIntegrationFixture,
  createRealGitFixture,
  createRealStoreFixture,
  environmentBlocked,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  findingArbitration,
  invalidProductionFinalization,
  polishingBlocked,
  polishingCompleted,
  reconciliationResolved,
  reconsiderationBatch,
  resolution,
  resolutionBatch,
  reviewApproved,
  reviewFindingBatch,
  reviewFindings,
  runGit,
} from "./support/index.js";

test("reconstructs a persisted bootstrap correction after interruption", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Make one read-only correction") &&
        !interrupted
      ) {
        interrupted = true;
        const error = new Error("Transient provider interruption.");
        error.code = "ERR_TEST_PROVIDER_INTERRUPTED";
        error.recoverable = true;
        throw error;
      }
    },
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: [
          { id: "C1", command: "npm test" },
          { id: "C2", command: "npm test" },
        ],
      },
      bootstrapReady("Corrected Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "BOOTSTRAP");
  assert.deepEqual(
    paused.pipelineState.pendingBootstrapCorrection,
    paused.pipelineState.bootstrapCorrections[0],
  );

  await fixture.recover();
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.pendingBootstrapCorrection, null);
  assert.match(fixture.calls.worker[3].prompt, /Correction diagnostic/u);
});

test("reconciles an interrupted content-changing lazy correction once", async (t) => {
  const processLoss = new Error("Process stopped during lazy correction.");
  let checkTurns = 0;
  let correctionChanged = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      { ...checkAndFix(), status: "INVALID" },
      checkAndFix("CHANGED"),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
        checkTurns += 1;
        if (checkTurns === 2) {
          correctionChanged = true;
          await writeFile(
            join(projectPath, "interrupted-lazy-correction.txt"),
            "fixed\n",
          );
        }
      }
    },
  });
  const git = fixture.runtime.git;
  const snapshot = git.snapshot;
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.git = {
    ...git,
    async snapshot(options) {
      if (
        correctionChanged &&
        !processStopped &&
        fixture.currentRun.activeTurn?.phase === "check-and-fix"
      ) {
        processStopped = true;
        throw processLoss;
      }
      return snapshot(options);
    },
  };
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    return transition(patch, options);
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CHECK_AND_FIX");
  assert.notEqual(fixture.currentRun.pipelineState.pendingLazyCorrection, null);
  assert.equal(fixture.currentRun.counters.fixRounds, 0);

  processStopped = false;
  await fixture.recover();
  fixture.runtime.git = git;
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.pipelineState.lazyCorrections[0].fixRoundCharged, true);
  assert.equal(result.pipelineState.pendingLazyCorrection, null);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CHECK_AND_FIX_SCHEMA)
      .length,
    3,
  );
});

test("resumes a reconciled lazy polishing check without replay", async (t) => {
  const processLoss = new Error(
    "Process stopped during lazy check reconciliation.",
  );
  let changed = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      polishingCompleted(),
      finalizationPassed(),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        request.schema === CHECK_AND_FIX_SCHEMA &&
        !changed
      ) {
        changed = true;
        await writeFile(
          join(projectPath, "interrupted-lazy-fix.txt"),
          "fixed\n",
        );
      }
    },
  });
  const git = fixture.runtime.git;
  const snapshot = git.snapshot;
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.git = {
    ...git,
    async snapshot(options) {
      if (
        changed &&
        !processStopped &&
        fixture.currentRun.activeTurn?.phase === "check-and-fix"
      ) {
        processStopped = true;
        throw processLoss;
      }
      return snapshot(options);
    },
  };
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    return transition(patch, options);
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "worker",
    phase: "check-and-fix",
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CHECK_AND_FIX");
  assert.equal(fixture.currentRun.counters.fixRounds, 0);

  processStopped = false;
  await fixture.recover();
  fixture.runtime.git = git;
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CHECK_AND_FIX_SCHEMA)
      .length,
    2,
  );
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
});

test("resumes a checkpointed unchanged lazy polishing check without replay", async (t) => {
  const processLoss = new Error("Process stopped after lazy check checkpoint.");
  const fixture = await createFixture(t, {
    mode: "lazy",
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
  const transition = fixture.runtime.transition;
  let processStopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    const next = await transition(patch, options);
    if (next.pipelineState.workflowState === "CLEAN_CONFIRM") {
      processStopped = true;
      throw processLoss;
    }
    return next;
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.equal(fixture.currentRun.activeTurn, null);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CLEAN_CONFIRM");
  assert.equal(fixture.currentRun.counters.fixRounds, 1);

  processStopped = false;
  await fixture.recover();
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === CHECK_AND_FIX_SCHEMA)
      .length,
    1,
  );
});

test("reconstructs an ownerless lazy clean confirmation without recounting", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
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
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA &&
        !interrupted
      ) {
        interrupted = true;
        const error = new Error("Provider interrupted during confirmation.");
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CLEAN_CONFIRM");
  await fixture.persistPipelineState(
    { ...paused.pipelineState, workflowState: "CLEAN_CONFIRM" },
    paused.counters,
    null,
  );
  await fixture.runtime.startAgentTurn({
    role: "worker",
    phase: "clean-confirm",
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.counters.correctionRounds, 0);
  assert.equal(
    fixture.calls.worker.filter(
      ({ schema }) => schema === CANDIDATE_CLEAN_CONFIRM_SCHEMA,
    ).length,
    2,
  );
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
});

test("reconstructs finalization correction before and during interruption", async (t) => {
  await t.test("before correction", async (t) => {
    const processLoss = new Error("Process stopped before correction.");
    const fixture = await createFixture(t, {
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });
    const transition = fixture.runtime.transition;
    const startAgentTurn = fixture.runtime.startAgentTurn;
    let stopped = false;
    fixture.runtime.transition = async (patch, options) => {
      if (stopped) {
        throw processLoss;
      }
      const next = await transition(patch, options);
      if (options.activity?.kind === "finalization-correction") {
        stopped = true;
      }
      return next;
    };
    fixture.runtime.startAgentTurn = async (turn) => {
      if (stopped) {
        throw processLoss;
      }
      return startAgentTurn(turn);
    };

    await assert.rejects(fixture.run(), (error) => error === processLoss);
    assert.equal(fixture.currentRun.activeTurn, null);
    assert.notEqual(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection,
      null,
    );

    stopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.startAgentTurn = startAgentTurn;
    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    const correctionCall = fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("one read-only correction"),
    );
    assert.equal(correctionCall.access, "read-only");
    assert.equal(correctionCall.session, undefined);
  });

  await t.test("during correction", async (t) => {
    const processLoss = new Error("Process stopped during correction.");
    let interruptionTriggered = false;
    let processStopped = false;
    const fixture = await createFixture(t, {
      onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("one read-only correction") &&
          !interruptionTriggered
        ) {
          interruptionTriggered = true;
          processStopped = true;
          throw processLoss;
        }
      },
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });
    const transition = fixture.runtime.transition;
    const finishAgentTurn = fixture.runtime.finishAgentTurn;
    fixture.runtime.transition = async (patch, options) => {
      if (processStopped) {
        throw processLoss;
      }
      return transition(patch, options);
    };
    fixture.runtime.finishAgentTurn = async (turn) => {
      if (processStopped) {
        throw processLoss;
      }
      return finishAgentTurn(turn);
    };

    await assert.rejects(fixture.run(), (error) => error === processLoss);
    assert.deepEqual(fixture.currentRun.activeTurn, {
      role: "worker",
      phase: "finalize",
    });
    processStopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.finishAgentTurn = finishAgentTurn;

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    const correctionCalls = fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("one read-only correction"),
    );
    assert.equal(correctionCalls.length, 2);
    assert.ok(correctionCalls.every(({ session }) => session === undefined));
  });
});

test("persists and reconstructs an allowlisted failed Claude read-only turn", async (t) => {
  let interrupted = false;
  const fixture = await createRealStoreFixture(t, {
    async onRoleRun(role) {
      if (role === "worker" && !interrupted) {
        interrupted = true;
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_READ_ONLY_TURN_FAILED";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_READ_ONLY_TURN_FAILED");
  assert.equal(paused.pause.resumeState, "CLARIFY");
  const events = await readFile(
    join(fixture.directoryPath, "events.jsonl"),
    "utf8",
  );
  const eventCount = events.trimEnd().split("\n").length;
  assert.ok(eventCount > 1);
  assert.doesNotMatch(events, /provider-native/u);

  const recovered = await fixture.recover();
  assert.equal(recovered.revision, paused.revision);
  const resumed = await fixture.run();
  const resumedRequest = fixture.calls.worker[1];

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.ok(resumed.revision > recovered.revision);
  assert.equal(resumedRequest.session, undefined);
  assert.equal(resumedRequest.prompt, resumedRequest.recoveryPrompt);
});

test("preserves Worker changes when a valid environment blocker pauses polishing", async (t) => {
  let polishTurns = 0;
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer"), reviewApproved(), reviewApproved()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      polishingBlocked(),
      polishingCompleted(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt)
      ) {
        polishTurns += 1;
        if (polishTurns === 2) {
          await writeFile(
            join(projectPath, "tracked.txt"),
            "safe blocked work\n",
          );
        }
      }
    },
  });

  const completed = await fixture.run();
  const staleFingerprint = completed.pipelineState.finalizedFingerprint;
  await fixture.persistPipelineState({
    ...completed.pipelineState,
    workflowState: "POLISH",
    pendingCorrection: true,
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "POLISH");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.notEqual(
    paused.pipelineState.repositoryBaseline.contentFingerprint,
    staleFingerprint,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe blocked work\n",
  );

  const recovered = await fixture.recover();
  assert.equal(recovered.revision, paused.revision);
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(resumed.pause, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe blocked work\n",
  );
});

test("retries permission-blocked finalization", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationBlocked(
        "The validation process lacks a required permission.",
        "The required validation resource rejected access.",
      ),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.deepEqual(paused.pause.evidence, [
    "The required validation resource rejected access.",
  ]);

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("retries unchanged process-isolation-blocked finding resolution", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationFailed(),
      environmentBlocked(
        "The required process isolation is unavailable.",
        "The validation subprocess could not enter its required isolation profile.",
      ),
      resolution("FIX"),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.finalizationResult.status, "FAIL");

  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("preserves a partial fix before missing-service validation", async (t) => {
  const fixture = await createFixture(t, {
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationFailed(),
      environmentBlocked(
        "A required local validation service is unavailable.",
        "The service health check reported no available endpoint.",
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(join(projectPath, "tracked.txt"), "safe partial fix\n");
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe partial fix\n",
  );

  const recovered = await fixture.recover();
  assert.equal(recovered.pause.reason, "environment_blocked");
  const resumed = await fixture.run();
  assert.equal(resumed.pipelineState.workflowState, "DONE");
});

test("resumes the persisted terminal confirmation without rerunning finalization", async (t) => {
  const processLoss = new Error("Process stopped before confirmation.");
  const fixture = await createFixture(t);
  const transition = fixture.runtime.transition;
  const startAgentTurn = fixture.runtime.startAgentTurn;
  let stopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (stopped) {
      throw processLoss;
    }
    const next = await transition(patch, options);
    if (patch.pipelineState.workflowState === "CONFIRM") {
      stopped = true;
    }
    return next;
  };
  fixture.runtime.startAgentTurn = async (turn, options) => {
    if (stopped && turn.phase === "confirm") {
      throw processLoss;
    }
    return startAgentTurn(turn, options);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.equal(fixture.currentRun.pipelineState.workflowState, "CONFIRM");
  assert.equal(fixture.currentRun.activeTurn, null);

  stopped = false;
  fixture.runtime.transition = transition;
  fixture.runtime.startAgentTurn = startAgentTurn;
  await fixture.recover();
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  assert.equal(
    fixture.calls.reviewer.filter(({ schema }) => schema === REVIEW_SCHEMA)
      .length,
    1,
  );
});

test("preserves maximum concurrent dispute attempts through recovery", async (t) => {
  const findingIds = Array.from({ length: 32 }, (_, index) => `R${index + 1}`);
  const fixture = await createFixture(t, {
    arbiter: findingIds.map(() => findingArbitration("WORKER_CORRECT")),
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindingBatch(findingIds),
      reconsiderationBatch("UPHOLD", findingIds),
      reconsiderationBatch("UPHOLD", findingIds),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolutionBatch(findingIds.map((id) => ({ id, decision: "DISPUTE" }))),
      resolutionBatch(findingIds.map((id) => ({ id, decision: "DISPUTE" }))),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeHistory.length, 64);
  assert.equal(result.pipelineState.findingArbitrations.length, 32);
  assert.ok(
    Buffer.byteLength(JSON.stringify(result.pipelineState.disputeHistory)) <=
      MAX_DISPUTE_HISTORY_BYTES,
  );
  assert.ok(
    result.pipelineState.disputeHistory.every(
      ({ workerReason, workerEvidence, reviewerReason }) =>
        workerReason ===
          "Repository evidence shows the finding is incorrect." &&
        workerEvidence[0] ===
          "The current test covers the reported behavior." &&
        reviewerReason ===
          "The current repository evidence still supports the finding.",
    ),
  );
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 1024 * 1024);
  for (const findingId of findingIds) {
    assert.deepEqual(
      result.pipelineState.disputeHistory
        .filter((entry) => entry.findingId === findingId)
        .map(({ attempt }) => attempt),
      [1, 2],
    );
  }

  const recovered = await fixture.recover();
  assert.equal(recovered.pipelineState.disputeHistory.length, 64);
});

test("preserves safe writable changes across a Claude usage rejection", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(
          join(projectPath, "tracked.txt"),
          "interrupted polish\n",
        );
        const error = new Error("Claude usage capacity is unavailable.");
        error.code = "ERR_CLAUDE_USAGE_LIMIT";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CLAUDE_USAGE_LIMIT");
  assert.equal(paused.pause.resumeState, "POLISH");

  await fixture.recover();
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "interrupted polish\n",
  );
});

test("does not let Claude provider recovery mask a control mutation", async (t) => {
  const fixture = await createRealGitFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt)
      ) {
        await runGit(
          projectPath,
          "remote",
          "add",
          "unexpected",
          "https://example.invalid/repository.git",
        );
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

test("fails closed after an ambiguous writable Claude process failure", async (t) => {
  let interrupted = false;
  const fixture = await createRealStoreFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(
          join(projectPath, "tracked.txt"),
          "interrupted polish\n",
        );
        const error = new Error("provider-native secret text");
        error.code = "ERR_CLAUDE_PROCESS_INTERRUPTED";
        error.ambiguous = true;
        throw error;
      }
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_CLAUDE_PROCESS_INTERRUPTED",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pause.reason, "internal_failure");
  assert.equal(fixture.currentRun.pause.code, "ERR_CLAUDE_PROCESS_INTERRUPTED");
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "interrupted polish\n",
  );
  assert.doesNotMatch(
    await readFile(join(fixture.directoryPath, "events.jsonl"), "utf8"),
    /provider-native/u,
  );
});

test("persists a forbidden-delegation diagnostic without provider data", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_DELEGATED_TURN_DATA";
  const fixture = await createRealStoreFixture(t, {
    onRoleRun(role) {
      if (role === "worker") {
        const error = new Error(sensitiveMarker);
        error.code = "ERR_CODEX_ISOLATION";
        error.diagnosticClass = "operation_multi_agent";
        error.subAgentActivity = sensitiveMarker;
        error.transcript = sensitiveMarker;
        throw error;
      }
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_CODEX_ISOLATION",
  );

  assert.deepEqual(fixture.currentRun.pause, {
    reason: "internal_failure",
    code: "ERR_CODEX_ISOLATION",
    diagnosticClass: "operation_multi_agent",
  });
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(
    await readFile(join(fixture.directoryPath, "events.jsonl"), "utf8"),
    /DO_NOT_PERSIST/u,
  );
});

test("recovers an ownerless writable turn with content-only changes", async (t) => {
  let interrupt = true;
  let recovering = false;
  const fixture = await createIntegrationFixture(t, {
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt)
      ) {
        if (interrupt) {
          interrupt = false;
          const error = new Error("Provider interrupted.");
          error.recoverable = true;
          throw error;
        }
        if (recovering) {
          assert.equal(request.session, undefined);
          assert.equal(request.prompt, request.recoveryPrompt);
          assert.equal(
            await readFile(join(projectPath, "partial.txt"), "utf8"),
            "partial polish\n",
          );
          const staged = await runGit(
            projectPath,
            "diff",
            "--cached",
            "--name-only",
          );
          assert.doesNotMatch(staged.stdout, /^partial\.txt$/mu);
          recovering = false;
        }
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.resumeState, "POLISH");
  await fixture.persistPipelineState(
    { ...paused.pipelineState, workflowState: "POLISH" },
    paused.counters,
    null,
  );
  await fixture.runtime.startAgentTurn({ role: "worker", phase: "polish" });
  await writeFile(join(fixture.projectPath, "partial.txt"), "partial polish\n");
  await fixture.recover();
  recovering = true;

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
  const staged = await runGit(
    fixture.projectPath,
    "diff",
    "--cached",
    "--name-only",
  );
  assert.match(staged.stdout, /^partial\.txt$/mu);
});

test("rejects ownerless writable-turn index drift before replay", async (t) => {
  let interrupt = true;
  const fixture = await createIntegrationFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        interrupt
      ) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.recoverable = true;
        throw error;
      }
    },
  });
  const paused = await fixture.run();
  await fixture.persistPipelineState(
    { ...paused.pipelineState, workflowState: "POLISH" },
    paused.counters,
    null,
  );
  await fixture.runtime.startAgentTurn({ role: "worker", phase: "polish" });
  await writeFile(join(fixture.projectPath, "partial.txt"), "partial polish\n");
  await runGit(fixture.projectPath, "add", "partial.txt");
  await fixture.recover();
  const calls = fixture.calls.worker.length;

  const rejected = await fixture.run();

  assert.equal(rejected.pause.reason, "unexpected_git_index_change");
  assert.deepEqual(rejected.activeTurn, {
    role: "worker",
    phase: "polish",
  });
  assert.equal(fixture.calls.worker.length, calls);
});

test("rejects Git-control drift before recovering an interrupted writable turn", async (t) => {
  let interrupt = true;
  const fixture = await createIntegrationFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        /Polish the existing local/u.test(request.prompt) &&
        interrupt
      ) {
        interrupt = false;
        const error = new Error("Provider interrupted.");
        error.recoverable = true;
        throw error;
      }
    },
  });
  const paused = await fixture.run();
  await fixture.persistPipelineState(
    { ...paused.pipelineState, workflowState: "POLISH" },
    paused.counters,
    null,
  );
  await fixture.runtime.startAgentTurn({ role: "worker", phase: "polish" });
  await runGit(
    fixture.projectPath,
    "remote",
    "add",
    "unexpected",
    "https://example.invalid/repository.git",
  );
  await fixture.recover();
  const calls = fixture.calls.worker.length;

  const rejected = await fixture.run();
  assert.equal(rejected.pause.reason, "unexpected_remote_configuration_change");
  assert.deepEqual(rejected.activeTurn, {
    role: "worker",
    phase: "polish",
  });
  assert.equal(fixture.calls.worker.length, calls);
});

test("accounts for a content-changing interrupted correction before recovery", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxSameFindingRounds: 1 },
    reviewer: [bootstrapReady("Reviewer"), reviewFindings(), reviewFindings()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(join(projectPath, "tracked.txt"), "interrupted fix\n");
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const interruptedRun = await fixture.run();
  assert.equal(interruptedRun.pause.reason, "backend_unavailable");
  assert.equal(interruptedRun.pause.resumeState, "REVIEW");
  assert.equal(interruptedRun.counters.fixRounds, 1);
  assert.equal(interruptedRun.pipelineState.pendingCorrection, true);

  await fixture.recover();
  const resumed = await fixture.run();
  assert.equal(resumed.pause.reason, "no_progress");
  assert.equal(resumed.counters.fixRounds, 1);
  assert.equal(resumed.counters.correctionRounds, 1);
});

test("invalidates retained finalization after content-changing interrupted terminal resolution", async (t) => {
  let interrupted = false;
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewFindings("R1"),
      candidateApproved(),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt) &&
        !interrupted
      ) {
        interrupted = true;
        await writeFile(join(projectPath, "tracked.txt"), "interrupted fix\n");
        const error = new Error("Claude provider is unavailable.");
        error.code = "ERR_CLAUDE_PROVIDER_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
  });

  const interruptedRun = await fixture.run();

  assert.equal(interruptedRun.pause.reason, "backend_unavailable");
  assert.equal(interruptedRun.pause.resumeState, "REVIEW");
  assert.equal(interruptedRun.pipelineState.finalizationResult, null);

  await fixture.recover();
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    2,
  );
});

test("clears a reconciled correction marker without replaying the turn", async (t) => {
  const processLoss = new Error(
    "Process stopped after correction reconciliation.",
  );
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings("R1"),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("FIX", "R1"),
      finalizationPassed(),
    ],
    async onRoleRun(role, request, _turn, { projectPath }) {
      if (
        role === "worker" &&
        /Resolve every current blocker/u.test(request.prompt)
      ) {
        await writeFile(join(projectPath, "tracked.txt"), "reconciled fix\n");
      }
    },
  });
  const transition = fixture.runtime.transition;
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  let processStopped = false;
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    const next = await transition(patch, options);
    if (
      next.activeTurn?.phase === "resolve-findings" &&
      next.pipelineState.workflowState === "REVIEW" &&
      next.pipelineState.pendingCorrection
    ) {
      processStopped = true;
    }
    return next;
  };
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };

  await assert.rejects(fixture.run(), (error) => error === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "worker",
    phase: "resolve-findings",
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "REVIEW");
  assert.equal(fixture.currentRun.pipelineState.pendingCorrection, true);
  assert.equal(fixture.currentRun.counters.fixRounds, 1);
  const resolutionTurns = fixture.calls.worker.filter(({ prompt }) =>
    /Resolve every current blocker/u.test(prompt),
  ).length;

  await fixture.recover();
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.activeTurn, null);
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      /Resolve every current blocker/u.test(prompt),
    ).length,
    resolutionTurns,
  );
});
