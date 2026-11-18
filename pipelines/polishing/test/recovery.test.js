import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";

import {
  ClaudeAdapterError,
  normalizeAdapterFailure,
} from "../../../src/agents/index.js";
import { createRunStore } from "../../../src/state/index.js";
import { polishingPipeline, runPolishing } from "../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINALIZATION_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  POLISH_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import { MAX_DISPUTE_HISTORY_BYTES } from "../src/workflow-contract.js";
import {
  REQUIRED_CHECKS,
  SOURCE_SESSION,
  SETTINGS,
  bootstrapReady,
  arbitrationResolved,
  reconciliationDisagreement,
  candidateApproved,
  candidateClean,
  checkAndFix,
  checkResults,
  clarificationReady,
  clarificationQuestions,
  productDecision,
  hash,
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
  trustedValidationSnapshot,
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

for (const mode of ["lazy", "combined"]) {
  test(`reconciles an already-charged interrupted ${mode} correction at the one-round boundary`, async (t) => {
    const processLoss = new Error("Process stopped during lazy correction.");
    let checkTurns = 0;
    let correctionChanged = false;
    const fixture = await createFixture(t, {
      mode,
      modeSettings: { maxFixRounds: 1 },
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode === "combined" ? [reconciliationResolved()] : []),
        polishingCompleted(),
        { ...checkAndFix(), status: "INVALID" },
        checkAndFix("CHANGED"),
        checkAndFix(),
        candidateClean(),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      async onRoleRun(role, request, _turn, { projectPath }) {
        if (role === "worker" && request.schema === CHECK_AND_FIX_SCHEMA) {
          checkTurns += 1;
          if (checkTurns <= 2) {
            correctionChanged = checkTurns === 2;
            await writeFile(
              join(projectPath, "interrupted-lazy-correction.txt"),
              `Correction ${checkTurns}\n`,
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
    assert.equal(
      fixture.currentRun.pipelineState.workflowState,
      "CHECK_AND_FIX",
    );
    assert.notEqual(
      fixture.currentRun.pipelineState.pendingLazyCorrection,
      null,
    );
    assert.equal(fixture.currentRun.counters.fixRounds, 1);

    processStopped = false;
    await fixture.recover();
    fixture.runtime.git = git;
    const result = await fixture.run();

    assert.equal(result.pipelineState.workflowState, "DONE");
    assert.equal(result.counters.fixRounds, 1);
    assert.equal(result.pipelineState.lazyCorrections[0].fixRoundCharged, true);
    assert.equal(result.pipelineState.pendingLazyCorrection, null);
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === FINALIZATION_SCHEMA,
      ).length,
      1,
    );
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === CHECK_AND_FIX_SCHEMA,
      ).length,
      3,
    );
  });
}

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

test("preserves safe writable changes and invalidates stale evidence after a Codex overload", async (t) => {
  let polishTurns = 0;
  const fixture = await createFixture(t, {
    reviewer: [bootstrapReady("Reviewer"), reviewApproved(), reviewApproved()],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
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
            "safe overloaded work\n",
          );
          throw normalizeAdapterFailure(
            "codex",
            Object.assign(new Error("provider-native overload secret"), {
              code: "ERR_CODEX_TURN_FAILED",
              diagnosticClass: "turn_server_overloaded",
              recoverable: true,
            }),
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
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_CODEX_TURN_FAILED");
  assert.equal(paused.pause.resumeState, "POLISH");
  assert.equal(paused.pipelineState.candidateReviewResult, null);
  assert.equal(paused.pipelineState.candidateReviewedFingerprint, null);
  assert.equal(paused.pipelineState.candidateConfirmationFingerprint, null);
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizedFingerprint, null);
  assert.equal(paused.pipelineState.reviewResult, null);
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.equal(paused.pipelineState.cleanConfirmationFingerprint, null);
  assert.notEqual(
    paused.pipelineState.repositoryBaseline.contentFingerprint,
    staleFingerprint,
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe overloaded work\n",
  );
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /overload secret/u);

  await fixture.recover();
  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    await readFile(join(fixture.projectPath, "tracked.txt"), "utf8"),
    "safe overloaded work\n",
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

test("persists terminal Claude finalization diagnoses without acceptance", async (t) => {
  const marker = "PRIVATE_NATIVE_FRAME";
  for (const [code, diagnosticClass] of [
    ["ERR_CLAUDE_PROTOCOL", "protocol_assistant_after_result"],
    ["ERR_CLAUDE_PROTOCOL", "protocol_record_after_result"],
    ["ERR_CLAUDE_PROTOCOL", undefined],
    ["ERR_CLAUDE_PERMISSION_DENIED", "permission_bash_unclassified"],
    ["ERR_CLAUDE_PERMISSION_DENIED", "permission_bash_required_check"],
    [
      "ERR_CLAUDE_PERMISSION_DENIED",
      "permission_reason_auto_mode_stop_no_verdict",
    ],
  ])
    await t.test(diagnosticClass ?? "unclassified", async (t) => {
      let before;
      const fixture = await createIntegrationFixture(t, {
        roleBackends: {
          worker: "claude",
          reviewer: "claude",
          arbiter: "claude",
        },
        async onRoleRun(role, request, _turn, { projectPath }) {
          if (role !== "worker" || request.schema !== FINALIZATION_SCHEMA)
            return;
          before = {
            head: (await runGit(projectPath, "rev-parse", "HEAD")).stdout,
            state: fixture.currentRun.pipelineState,
          };
          throw normalizeAdapterFailure(
            "claude",
            new ClaudeAdapterError(marker, {
              cause: new Error(marker),
              code,
              diagnosticClass,
            }),
          );
        },
      });

      await assert.rejects(fixture.run(), (error) => {
        assert.equal(error.code, code);
        assert.equal(error.recoverable, false);
        return true;
      });

      const store = createRunStore({
        stateRoot: dirname(dirname(fixture.directoryPath)),
      });
      const run = await store.loadRun(fixture.currentRun.runId);
      const state = run.pipelineState;
      assert.equal(state.workflowState, "FAILED");
      assert.deepEqual(run.pause, {
        reason: "internal_failure",
        code,
        ...(diagnosticClass === undefined ? {} : { diagnosticClass }),
      });
      const projected = polishingPipeline.projections.pause(run);
      assert.equal(
        projected.explanation,
        diagnosticClass === undefined
          ? "Polishing failed."
          : `Polishing failed. Adapter diagnostic: ${diagnosticClass}.`,
      );
      assert.equal(projected.resumeState, null);
      assert.deepEqual(projected.nextActions, []);
      const { activities } = await store.readPublicActivity(run.runId, {
        afterRevision: run.revision - 1,
      });
      assert.equal(
        activities.at(-1).message,
        diagnosticClass === undefined
          ? `Polishing failed: ${code}.`
          : `Polishing failed: ${code} (${diagnosticClass}).`,
      );
      assert.equal(state.finalizationResult, null);
      assert.equal(state.finalizedFingerprint, null);
      assert.equal(state.reviewedFingerprint, before.state.reviewedFingerprint);
      assert.equal(
        state.candidateReviewedFingerprint,
        before.state.candidateReviewedFingerprint,
      );
      assert.equal(
        (await runGit(fixture.projectPath, "rev-parse", "HEAD")).stdout,
        before.head,
      );
      assert.equal(
        (await runGit(fixture.projectPath, "diff", "--cached", "--name-only"))
          .stdout,
        "",
      );
      assert.equal(
        fixture.calls.worker.filter(
          ({ schema }) => schema === FINALIZATION_SCHEMA,
        ).length,
        1,
      );
      assert.doesNotMatch(
        `${JSON.stringify(run)}\n${await readFile(join(fixture.directoryPath, "events.jsonl"), "utf8")}`,
        new RegExp(marker, "u"),
      );
    });
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
      resolution("FIX", "R1"),
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

  // The lost report retains its charged checkpoint and is restated read-only.
  const interruptedRun = await fixture.run();
  assert.equal(interruptedRun.pause.reason, "backend_unavailable");
  assert.equal(interruptedRun.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(interruptedRun.counters.fixRounds, 1);
  assert.equal(interruptedRun.pipelineState.pendingCorrection, true);
  assert.equal(
    interruptedRun.pipelineState.resolutionCorrection.stage,
    "ready",
  );

  await fixture.recover();
  const resumed = await fixture.run();
  assert.equal(resumed.pause.reason, "no_progress");
  assert.equal(resumed.counters.fixRounds, 1);
  assert.equal(resumed.counters.correctionRounds, 1);
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ schema }) => schema === FINDING_RESOLUTION_SCHEMA)
      .map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
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
      resolution("FIX", "R1"),
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
  assert.equal(interruptedRun.pause.resumeState, "RESOLVE_FINDINGS");
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

test("clears a legacy reconciled correction marker without replaying the turn", async (t) => {
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
    const ready = patch.pipelineState.resolutionCorrection?.stage === "ready";
    // Persist the version-19 shape: reconciliation already entered REVIEW
    // and no report checkpoint exists for the retained turn marker.
    const next = await transition(
      ready
        ? {
            ...patch,
            pipelineState: {
              ...patch.pipelineState,
              workflowState: "REVIEW",
              previousFindings: patch.pipelineState.findings,
              findings: [],
              resolutionCorrection: null,
            },
          }
        : patch,
      options,
    );
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

for (const mode of ["independent", "lazy"]) {
  for (const [schema, checkpoint] of [
    [POLISH_SCHEMA, "POLISH"],
    ...(mode === "lazy" ? [[CHECK_AND_FIX_SCHEMA, "CHECK_AND_FIX"]] : []),
    [FINDING_RESOLUTION_SCHEMA, "RESOLVE_FINDINGS"],
  ]) {
    for (const stopKind of [
      "blocked",
      "interrupted",
      ...(checkpoint === "RESOLVE_FINDINGS" ? ["partial-blocked"] : []),
    ]) {
      test(`retains trusted delegation across ${mode} ${checkpoint} ${stopKind} recovery`, async (t) => {
        const command = "npm run test:service";
        const snapshot = trustedValidationSnapshot("service-check", command);
        const requiredChecks = [...REQUIRED_CHECKS, { id: "C2", command }];
        const bootstrap = (role) => ({
          ...bootstrapReady(role),
          requiredChecks,
        });
        const finalization = {
          ...finalizationPassed(),
          requiredChecks,
          checks: [
            ...checkResults("PASS"),
            {
              checkId: "C2",
              command,
              status: "NOT_RUN",
              evidence: ["Reserved for the runner."],
            },
          ],
        };
        const needsResolution = checkpoint === "RESOLVE_FINDINGS";
        const processLoss = new Error(
          "Simulated process loss before a role response.",
        );
        let stopped = false;
        let attempts = 0;
        let trustedCalls = 0;
        const targetCalls = [];
        const fixture = await createFixture(t, {
          mode,
          trustedValidation: snapshot,
          settings: { ...SETTINGS, trustedChecks: ["service-check"] },
          reviewer: [
            bootstrap("Reviewer"),
            candidateApproved(),
            ...(needsResolution ? [candidateApproved()] : []),
            reviewApproved(),
          ],
          worker: [
            clarificationReady(),
            bootstrap("Worker"),
            ...(mode === "independent" ? [reconciliationResolved()] : []),
            polishingCompleted(),
            ...(mode === "lazy" ? [candidateClean()] : []),
            finalization,
            ...(needsResolution
              ? [...(mode === "lazy" ? [candidateClean()] : []), finalization]
              : []),
            ...(mode === "lazy" ? [cleanConfirmation()] : []),
          ],
          onTrustedValidation(options) {
            trustedCalls += 1;
            assert.equal(
              fixture.currentRun.pipelineState.workflowState,
              "FINALIZE",
            );
            assert.deepEqual(options.snapshot, snapshot);
            const failed = needsResolution && trustedCalls === 1;
            return {
              ...options.bindings,
              commandIdentity: options.commandIdentity,
              status: failed ? "FAIL" : "PASS",
              exitCode: failed ? 1 : 0,
              signal: null,
              timedOut: false,
              evidence: ["The runner executed the persisted vector."],
            };
          },
        });
        const runWorker = fixture.runtime.adapters.worker.run;
        fixture.runtime.adapters.worker.run = async (request) => {
          if (request.schema === schema) {
            targetCalls.push(request);
            attempts += 1;
            for (const prompt of [request.prompt, request.recoveryPrompt]) {
              const match =
                /Exact runner-trusted commands reserved for FINALIZE:\n([^\n]+)/u.exec(
                  prompt,
                );
              const delegated = JSON.parse(match?.[1] ?? "[]");
              assert.deepEqual(delegated, [command]);
              assert.ok(!delegated.includes(`${command} -- --generate`));
              assert.ok(!delegated.includes("npm  run test:service"));
              assert.match(
                prompt,
                /work not delegated to a selected runner-trusted command/u,
              );
            }
            if (attempts === 1) {
              fixture.calls.worker.push(request);
              if (stopKind === "interrupted") {
                stopped = true;
                throw processLoss;
              }
              if (stopKind === "partial-blocked") {
                await writeFile(
                  join(request.cwd, "partial-repair.txt"),
                  "safe partial repair\n",
                );
              }
              return {
                sessionId: request.session?.id ?? "blocked-worker",
                structured: {
                  status: "BLOCKED",
                  ...(schema === FINDING_RESOLUTION_SCHEMA
                    ? { decisions: [] }
                    : { summary: "" }),
                  reason:
                    "An additional generation step requires an unavailable local service.",
                  evidence: [
                    `${command} -- --generate is not delegated to the runner.`,
                  ],
                  question: "",
                  whyBlocked: "",
                  options: [],
                },
              };
            }
          }
          if (
            [CHECK_AND_FIX_SCHEMA, FINDING_RESOLUTION_SCHEMA].includes(
              request.schema,
            )
          ) {
            fixture.calls.worker.push(request);
            return {
              sessionId: request.session?.id ?? "recovered-worker",
              structured:
                request.schema === CHECK_AND_FIX_SCHEMA
                  ? checkAndFix()
                  : resolution("FIX", "F1"),
            };
          }
          return runWorker(request);
        };
        const transition = fixture.runtime.transition;
        const finishAgentTurn = fixture.runtime.finishAgentTurn;
        fixture.runtime.transition = async (...args) => {
          if (stopped) throw processLoss;
          return transition(...args);
        };
        fixture.runtime.finishAgentTurn = async (...args) => {
          if (stopped) throw processLoss;
          return finishAgentTurn(...args);
        };

        if (stopKind === "interrupted") {
          await assert.rejects(fixture.run(), (error) => error === processLoss);
          assert.notEqual(fixture.currentRun.activeTurn, null);
          assert.equal(
            fixture.currentRun.pipelineState.workflowState,
            checkpoint,
          );
        } else {
          const paused = await fixture.run();
          assert.equal(paused.pause.reason, "environment_blocked");
          assert.equal(
            paused.pause.resumeState,
            stopKind === "partial-blocked"
              ? mode === "lazy"
                ? "CHECK_AND_FIX"
                : "REVIEW"
              : checkpoint,
          );
          assert.equal(paused.pipelineState.cleanConfirmationFingerprint, null);
          if (stopKind === "partial-blocked") {
            assert.equal(paused.pipelineState.finalizationResult, null);
            assert.equal(
              await readFile(
                join(fixture.projectPath, "partial-repair.txt"),
                "utf8",
              ),
              "safe partial repair\n",
            );
          }
        }
        assert.equal(trustedCalls, needsResolution ? 1 : 0);
        stopped = false;
        fixture.runtime.transition = transition;
        fixture.runtime.finishAgentTurn = finishAgentTurn;

        const completed = await fixture.run();

        assert.equal(completed.pipelineState.workflowState, "DONE");
        assert.deepEqual(completed.pipelineState.trustedValidation, snapshot);
        assert.equal(trustedCalls, needsResolution ? 2 : 1);
        if (stopKind === "interrupted") {
          assert.equal(targetCalls.length, 2);
          if (schema === CHECK_AND_FIX_SCHEMA) {
            assert.equal(targetCalls[1].session?.mode, "continue");
          } else {
            assert.equal(targetCalls[1].session, undefined);
            assert.equal(targetCalls[1].prompt, targetCalls[1].recoveryPrompt);
          }
        }
      });
    }
  }
}

for (const schema of [POLISH_SCHEMA, FINALIZATION_SCHEMA, REVIEW_SCHEMA]) {
  test(`output exhaustion preserves polishing ${schema === POLISH_SCHEMA ? "work" : schema === FINALIZATION_SCHEMA ? "finalization" : "confirmation"}`, async (t) => {
    let failures = 0;
    const fixture = await createFixture(t, {
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (request.schema === schema && failures < 2) {
          failures++;
          if (request.access === "workspace-write") {
            await writeFile(
              join(projectPath, "partial.txt"),
              `Progress ${failures}\n`,
            );
          }
          throw outputExhaustion();
        }
      },
    });
    attachOutputExhaustion(fixture);
    const first = await fixture.run();
    assert.equal(failures, 1);
    assert.equal(first.pause.reason, "output_exhausted");
    assert.equal(first.activeTurn, null);
    assert.equal(first.pipelineState.reviewedFingerprint, null);
    const second = await fixture.run();
    assert.equal(failures, 2);
    assert.deepEqual(second.pause, first.pause);
    assert.deepEqual(second.counters, first.counters);
    const projected = polishingPipeline.projections.pause(second);
    assert.deepEqual(projected.evidence, [
      `Suspended role: ${second.pause.role}.`,
      `Suspended checkpoint: ${second.pause.checkpoint}.`,
    ]);
    assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
    if (schema !== REVIEW_SCHEMA) {
      assert.equal(
        await readFile(join(fixture.projectPath, "partial.txt"), "utf8"),
        "Progress 2\n",
      );
    }
    assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
  });
}

test("combined polishing preserves a charged exhausted correction and reconverges", async (t) => {
  let failures = 0;
  const fixture = await createFixture(t, {
    mode: "combined",
    modeSettings: { maxFixRounds: 1 },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      checkAndFix(),
      candidateClean(),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (request.schema === CHECK_AND_FIX_SCHEMA && failures < 2) {
        failures++;
        await writeFile(
          join(projectPath, "partial.txt"),
          `Correction ${failures}\n`,
        );
        throw outputExhaustion();
      }
    },
  });
  attachOutputExhaustion(fixture);
  for (let attempt = 0; attempt < 2; attempt++) {
    const paused = await fixture.run();
    assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
    assert.equal(paused.counters.fixRounds, 1);
    assert.equal(paused.pipelineState.candidateConfirmationFingerprint, null);
    assert.equal(paused.pipelineState.candidateReviewedFingerprint, null);
    assert.equal(paused.pipelineState.finalizationResult, null);
  }
  await fixture.runtime.transition({
    pipelineState: {
      ...fixture.currentRun.pipelineState,
      workflowState: "CHECK_AND_FIX",
    },
    pause: null,
  });
  await fixture.runtime.startAgentTurn({
    role: "worker",
    phase: "check-and-fix",
  });
  await writeFile(join(fixture.projectPath, "partial.txt"), "Stopped repair\n");
  const calls = fixture.calls.worker.length;
  const stopped = await runPolishing({
    run: fixture.currentRun,
    runtime: fixture.runtime,
    operatorStop: true,
  });
  assert.equal(stopped.counters.fixRounds, 1);
  assert.equal(fixture.calls.worker.length, calls);
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
});

for (const [kind, boundary, mode] of [
  ["questions", "intent", "independent"],
  ["questions", "replacement", "lazy"],
  ["questions", "publication", "combined"],
  ["decision", "intent", "lazy"],
  ["decision", "replacement", "combined"],
  ["decision", "publication", "independent"],
  ["arbitration", "replacement", "independent"],
]) {
  test(`journaled ${kind} append recovers ${boundary} interruption in ${mode}`, async (t) => {
    const interruption = new Error("Append publication interrupted.");
    let interrupted = false;
    const questions = kind === "questions";
    const arbitration = kind === "arbitration";
    const counter = questions ? "clarificationRounds" : "productDecisions";
    const fixture = await createFixture(t, {
      mode,
      ...(arbitration
        ? {
            arbiter: [
              productDecision({
                ...arbitrationResolved(),
                direction: "PRODUCT_DECISION_REQUIRED",
                summary: "",
              }),
            ],
          }
        : {}),
      worker: questions
        ? [clarificationQuestions()]
        : arbitration
          ? [
              clarificationReady(),
              bootstrapReady("Worker"),
              reconciliationDisagreement(),
            ]
          : [
              clarificationReady(),
              productDecision({
                ...bootstrapReady("Worker"),
                status: "PRODUCT_DECISION_REQUIRED",
                summary: "",
                requiredChecks: [],
                validationInfrastructure: [],
                capabilityRequirements: [],
                environmentBlockers: [],
              }),
            ],
    });
    const service = fixture.runtime.clarifications;
    const transition = fixture.runtime.transition;
    let editors = 0;
    fixture.runtime.transition = async (patch, options) => {
      const result = await transition(patch, options);
      if (
        !interrupted &&
        ((boundary === "intent" &&
          patch.pipelineState.pendingClarificationAppend !== null) ||
          (boundary === "publication" &&
            patch.pipelineState.pendingEdit !== null))
      ) {
        interrupted = true;
        throw interruption;
      }
      return result;
    };
    fixture.runtime.clarifications = {
      ...service,
      async [questions ? "appendQuestionRound" : "appendProductDecision"](
        options,
      ) {
        const result =
          await service[
            questions ? "appendQuestionRound" : "appendProductDecision"
          ](options);
        if (!interrupted && boundary === "replacement") {
          interrupted = true;
          throw interruption;
        }
        return result;
      },
      async openEditor(...args) {
        editors++;
        return service.openEditor(...args);
      },
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    const saved = structuredClone(fixture.currentRun);
    const calls = Object.values(fixture.calls).flat().length;
    const path = saved.pipelineState.clarificationPath;
    const bytes = await readFile(path, "utf8");
    if (boundary !== "publication") {
      assert.notEqual(saved.pipelineState.pendingClarificationAppend, null);
      assert.equal(saved.pipelineState.pendingEdit, null);
      assert.equal(saved.counters[counter], 0);
      if (!questions) {
        for (const field of ["decision", "workReport"]) {
          const malformed = structuredClone(saved);
          const append = malformed.pipelineState.pendingClarificationAppend;
          if (field === "decision") append.decision.extra = true;
          else append.checkpoint.workReport = {};
          assert.throws(
            () => polishingPipeline.workflow.validateRun(malformed),
            { code: "ERR_INVALID_POLISHING_STATE" },
          );
        }
      }
      // Stops verify bytes without appending or granting an edit.
      for (let attempt = 0; attempt < 2; attempt++) {
        await runPolishing({
          run: fixture.currentRun,
          runtime: fixture.runtime,
          operatorStop: true,
        });
        assert.equal(await readFile(path, "utf8"), bytes);
        assert.deepEqual(
          fixture.currentRun.pipelineState.pendingClarificationAppend,
          saved.pipelineState.pendingClarificationAppend,
        );
        assert.equal(editors, 0);
      }
    }
    await fixture.recover();
    const paused = await fixture.run();
    assert.equal(
      paused.pause.reason,
      questions
        ? "clarification_answers_required"
        : "product_decision_required",
    );
    assert.equal(paused.pipelineState.pendingClarificationAppend, null);
    assert.equal(paused.counters[counter], 1);
    const resultBytes = await readFile(path, "utf8");
    assert.equal(paused.hashes.executionClarifications, hash(resultBytes));
    assert.equal(Object.values(fixture.calls).flat().length, calls);
    if (arbitration) {
      assert.deepEqual(
        paused.pipelineState.workReports.at(-1),
        saved.pipelineState.pendingClarificationAppend.checkpoint.workReport,
      );
      assert.equal(
        paused.pipelineState.workReports.at(-1).phase,
        "ARBITRATE_BOOTSTRAP",
      );
    }
    const authorization = paused.pipelineState.pendingEdit.id;
    // Unchanged answers renew only the edit window.
    await fixture.recover();
    const repeated = await fixture.run();
    assert.notEqual(repeated.pipelineState.pendingEdit.id, authorization);
    assert.deepEqual(
      repeated.pipelineState.workReports,
      paused.pipelineState.workReports,
    );
    assert.equal(repeated.counters[counter], 1);
    assert.equal(await readFile(path, "utf8"), resultBytes);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
  });
}

for (const change of [
  "prior-bytes",
  "result-bytes",
  "protected-input",
  "controls",
  "infrastructure",
]) {
  test(`pending polishing append rejects ${change} before replay`, async (t) => {
    const interruption = new Error("Retained append intent.");
    const fixture = await createFixture(t, {
      worker: [clarificationQuestions()],
    });
    const service = fixture.runtime.clarifications;
    fixture.runtime.clarifications = {
      ...service,
      async appendQuestionRound(options) {
        if (change === "prior-bytes")
          return service.appendQuestionRound({
            ...options,
            async persistAppend(proof) {
              await options.persistAppend(proof);
              throw interruption;
            },
          });
        await service.appendQuestionRound(options);
        throw interruption;
      },
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    const saved = structuredClone(fixture.currentRun);
    const path = saved.pipelineState.clarificationPath;
    if (change === "protected-input")
      await writeFile(
        join(fixture.taskPath, "context.md"),
        "Changed protected context.\n",
      );
    else if (change === "controls")
      fixture.runtime.git.assertUnchanged = async () => {
        throw Object.assign(new Error("Controls changed."), {
          code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
        });
      };
    else if (change === "infrastructure")
      await writeFile(
        join(fixture.projectPath, ".agents/skills/finalization/SKILL.md"),
        "Changed frozen guidance.\n",
      );
    else
      await writeFile(
        path,
        `${await readFile(path, "utf8")}Unauthorized bytes.\n`,
      );
    const bytes = await readFile(path, "utf8");
    fixture.runtime.clarifications = service;
    const rejected = await fixture.run();
    assert.equal(
      rejected.pause.reason,
      change === "protected-input"
        ? "task_input_changed"
        : ["controls", "infrastructure"].includes(change)
          ? "unsafe_git_state"
          : "clarifications_changed",
    );
    assert.deepEqual(
      rejected.pipelineState.pendingClarificationAppend,
      saved.pipelineState.pendingClarificationAppend,
    );
    assert.equal(rejected.pipelineState.pendingEdit, null);
    assert.equal(rejected.counters.clarificationRounds, 0);
    assert.equal(await readFile(path, "utf8"), bytes);
    fixture.runtime.clarifications = {
      ...service,
      async inspectTranscript() {
        throw Object.assign(new Error("Private read failure."), {
          code: "ERR_CLARIFICATION_READ",
        });
      },
    };
    const stopped = await runPolishing({
      run: rejected,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.deepEqual(stopped.pause, rejected.pause);
    assert.equal(fixture.calls.worker.length, 1);
    assert.deepEqual(
      polishingPipeline.projections.pause(stopped).nextActions,
      [],
    );
  });
}

for (const boundary of ["replacement", "readback", "service-readback"]) {
  test(`polishing append persists a non-resumable ${boundary} rejection`, async (t) => {
    const fixture = await createRealStoreFixture(t, {
      worker: [clarificationQuestions()],
    });
    const service = fixture.runtime.clarifications;
    let rejectedBytes;
    let intent;
    let appends = 0;
    let authorizations = 0;
    let editors = 0;
    fixture.runtime.clarifications = {
      ...service,
      async appendQuestionRound(options) {
        appends++;
        const priorBytes = await readFile(options.transcriptPath, "utf8");
        if (boundary === "replacement")
          return service.appendQuestionRound({
            ...options,
            async persistAppend(proof) {
              await options.persistAppend(proof);
              intent = structuredClone(
                fixture.currentRun.pipelineState.pendingClarificationAppend,
              );
              rejectedBytes = `${priorBytes}Unauthorized bytes.\n`;
              await writeFile(options.transcriptPath, rejectedBytes);
            },
          });
        const result = await service.appendQuestionRound(options);
        intent = structuredClone(
          fixture.currentRun.pipelineState.pendingClarificationAppend,
        );
        rejectedBytes = priorBytes;
        await writeFile(options.transcriptPath, rejectedBytes);
        // Model prior bytes restored before the service's final readback.
        if (boundary === "service-readback")
          return service.inspectTranscript(options);
        return result;
      },
      async prepareEdit(...args) {
        authorizations++;
        return service.prepareEdit(...args);
      },
      async openEditor(...args) {
        editors++;
        return service.openEditor(...args);
      },
    };
    const rejected = await fixture.run();
    assert.equal(rejected.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.deepEqual(rejected.pause, { reason: "clarifications_changed" });
    assert.deepEqual(rejected.pipelineState.pendingClarificationAppend, intent);
    assert.equal(rejected.pipelineState.pendingEdit, null);
    assert.equal(rejected.counters.clarificationRounds, 0);
    assert.equal(rejected.hashes.executionClarifications, intent.expectedHash);
    assert.equal(editors, 0);
    const path = rejected.pipelineState.clarificationPath;
    assert.equal(await readFile(path, "utf8"), rejectedBytes);
    const recovered = await fixture.recover();
    assert.deepEqual(fixture.currentRun.pause, rejected.pause);
    assert.deepEqual(
      fixture.currentRun.pipelineState.pendingClarificationAppend,
      intent,
    );
    assert.deepEqual(await fixture.run(), recovered);
    assert.equal(appends, 1);
    assert.equal(authorizations, 0);
    assert.equal(editors, 0);
    assert.equal(fixture.calls.worker.length, 1);
    assert.equal(await readFile(path, "utf8"), rejectedBytes);
    assert.deepEqual(
      polishingPipeline.projections.pause(fixture.currentRun).nextActions,
      [],
    );
  });
}

for (const failure of ["write", "readback", "editor-preparation"]) {
  test(`polishing append ${failure} failure retains bounded resumable proof`, async (t) => {
    const fixture = await createFixture(t, {
      worker: [clarificationQuestions()],
    });
    const service = fixture.runtime.clarifications;
    let failed = false;
    let failReadback = false;
    const code =
      failure === "write"
        ? "ERR_CLARIFICATION_WRITE"
        : "ERR_CLARIFICATION_READ";
    const fail = () => {
      throw Object.assign(new Error("Private filesystem detail."), { code });
    };
    fixture.runtime.clarifications = {
      ...service,
      async inspectTranscript(options) {
        if (failReadback) {
          failReadback = false;
          fail();
        }
        return service.inspectTranscript(options);
      },
      async prepareEdit(options) {
        if (!failed && failure === "editor-preparation") {
          failed = true;
          fail();
        }
        return service.prepareEdit(options);
      },
      async appendQuestionRound(options) {
        if (!failed && failure !== "editor-preparation") {
          failed = true;
          if (failure === "readback") {
            const result = await service.appendQuestionRound(options);
            failReadback = true;
            return result;
          }
          return service.appendQuestionRound({
            ...options,
            async persistAppend(proof) {
              await options.persistAppend(proof);
              fail();
            },
          });
        }
        return service.appendQuestionRound(options);
      },
    };
    const interrupted = await fixture.run();
    assert.deepEqual(interrupted.pause, {
      reason: "clarification_append_interrupted",
      code,
    });
    assert.equal(interrupted.counters.clarificationRounds, 0);
    assert.equal(interrupted.pipelineState.pendingEdit, null);
    const projection = polishingPipeline.projections.pause(interrupted);
    assert.equal(projection.resumeState, "CLARIFY");
    assert.deepEqual(projection.nextActions, [
      { type: "resume", action: null },
    ]);
    assert.doesNotMatch(JSON.stringify(projection), /Private filesystem/u);
    const recovered = await fixture.run();
    assert.equal(recovered.pause.reason, "clarification_answers_required");
    assert.equal(recovered.counters.clarificationRounds, 1);
    assert.equal(fixture.calls.worker.length, 1);
  });
}

test("failed initial polishing append publication leaves bytes and accounting unchanged", async (t) => {
  const fixture = await createFixture(t, {
    worker: [clarificationQuestions()],
  });
  const transition = fixture.runtime.transition;
  const interruption = new Error("Intent publication failed.");
  fixture.runtime.transition = async (patch, options) => {
    if (patch.pipelineState.pendingClarificationAppend !== null)
      throw interruption;
    return transition(patch, options);
  };
  await assert.rejects(fixture.run(), (cause) => cause === interruption);
  const saved = fixture.currentRun;
  assert.equal(saved.pipelineState.pendingClarificationAppend, null);
  assert.equal(saved.pipelineState.pendingEdit, null);
  assert.equal(saved.counters.clarificationRounds ?? 0, 0);
  assert.doesNotMatch(
    await readFile(saved.pipelineState.clarificationPath, "utf8"),
    /## Round/u,
  );
});

test("polishing append contract rejects malformed proof and changed checkpoint bindings", async (t) => {
  const fixture = await createFixture(t, {
    worker: [clarificationQuestions()],
  });
  const service = fixture.runtime.clarifications;
  const interruption = new Error("Intent retained for validation.");
  fixture.runtime.clarifications = {
    ...service,
    appendQuestionRound(options) {
      return service.appendQuestionRound({
        ...options,
        async persistAppend(proof) {
          await options.persistAppend(proof);
          throw interruption;
        },
      });
    },
  };
  await assert.rejects(fixture.run(), (cause) => cause === interruption);
  const saved = structuredClone(fixture.currentRun);
  polishingPipeline.workflow.validateRun(saved);
  for (const mutate of [
    (_run, append) => {
      append.extra = true;
    },
    (_run, append) => {
      append.resultHash = append.expectedHash;
    },
    (_run, append) => {
      append.number++;
    },
    (_run, append) => {
      append.questions[0].question += " ";
    },
    (_run, append) => {
      append.decision = {};
    },
    (_run, append) => {
      append.checkpoint.extra = true;
    },
    (_run, append) => {
      append.checkpoint.workReport = {};
    },
    (_run, append) => {
      append.checkpoint.suspendedState = "POLISH";
    },
    (_run, append) => {
      append.checkpoint.infrastructureFingerprint = "invalid";
    },
    (run) => {
      run.hashes.task = hash("Different task");
    },
    (run) => {
      run.counters.fixRounds = 1;
    },
    (run) => {
      run.pipelineState.proactiveClarificationComplete = false;
    },
    (run) => {
      run.pipelineState.polishSummary = "Invented summary";
    },
    (run) => {
      run.sessionLineage.children = [];
    },
    (run) => {
      run.activeTurn = { role: "worker", phase: "clarify" };
    },
    (run) => {
      run.pipelineState.workflowState = "WAITING_FOR_USER";
      run.pause = {
        reason: "clarification_append_interrupted",
        code: "PRIVATE_UNSUPPORTED_CODE",
      };
    },
  ]) {
    const malformed = structuredClone(saved);
    mutate(malformed, malformed.pipelineState.pendingClarificationAppend);
    assert.throws(() => polishingPipeline.workflow.validateRun(malformed), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
  }
});

for (const change of ["unchanged", "changed", "missing"]) {
  test(`confirmation append recovery checks ${change} finalization-only infrastructure`, async (t) => {
    const interruption = new Error("Retained confirmation decision.");
    const relativePath = "LOCAL_ARTIFACTS/terminal-check.json";
    const fixture = await createFixture(t, {
      async prepareProject(projectPath) {
        await mkdir(join(projectPath, "LOCAL_ARTIFACTS"));
        await writeFile(join(projectPath, relativePath), "{}\n");
      },
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        reconciliationResolved(),
        polishingCompleted(),
        {
          ...finalizationPassed(),
          validationInfrastructure: [
            ...bootstrapReady("Worker").validationInfrastructure,
            relativePath,
          ],
        },
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        productDecision({
          ...reviewApproved(),
          status: "PRODUCT_DECISION_REQUIRED",
        }),
      ],
    });
    const service = fixture.runtime.clarifications;
    let appends = 0;
    let editors = 0;
    fixture.runtime.clarifications = {
      ...service,
      appendProductDecision(options) {
        appends++;
        return service.appendProductDecision({
          ...options,
          async persistAppend(proof) {
            await options.persistAppend(proof);
            throw interruption;
          },
        });
      },
      openEditor(...args) {
        editors++;
        return service.openEditor(...args);
      },
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    const saved = structuredClone(fixture.currentRun);
    const intent = saved.pipelineState.pendingClarificationAppend;
    assert.equal(intent.checkpoint.workflowState, "CONFIRM");
    assert.equal(
      saved.pipelineState.validationInfrastructure.includes(relativePath),
      false,
    );
    assert.equal(
      saved.pipelineState.finalizationResult.validationInfrastructure.includes(
        relativePath,
      ),
      true,
    );
    const path = saved.pipelineState.clarificationPath;
    const bytes = await readFile(path, "utf8");
    assert.equal(hash(bytes), intent.expectedHash);
    if (change === "missing") await rm(join(fixture.projectPath, relativePath));
    else if (change === "changed")
      await writeFile(
        join(fixture.projectPath, relativePath),
        '{"changed":true}\n',
      );
    fixture.runtime.clarifications.appendProductDecision = (options) => {
      appends++;
      return service.appendProductDecision(options);
    };
    await fixture.recover();
    const result = await fixture.run();
    if (change === "unchanged") {
      assert.equal(result.pause.reason, "product_decision_required");
      assert.equal(result.pipelineState.pendingClarificationAppend, null);
      assert.notEqual(result.pipelineState.pendingEdit, null);
      assert.equal(result.counters.productDecisions, 1);
      assert.equal(appends, 2);
      assert.equal(editors, 1);
    } else {
      assert.equal(result.pause.reason, "unsafe_git_state");
      assert.equal(
        result.pause.code,
        "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
      );
      assert.deepEqual(result.pipelineState.pendingClarificationAppend, intent);
      assert.equal(result.pipelineState.pendingEdit, null);
      assert.equal(result.counters.productDecisions, 0);
      assert.equal(await readFile(path, "utf8"), bytes);
      assert.equal(appends, 1);
      assert.equal(editors, 0);
    }
    assert.equal(fixture.calls.worker.length, 5);
    assert.equal(fixture.calls.reviewer.length, 3);
    assert.equal(fixture.calls.arbiter.length, 0);
  });
}

for (const missing of [false, true]) {
  test(`post-start polishing append rejects ${missing ? "missing" : "changed"} ignored infrastructure`, async (t) => {
    const interruption = new Error("Retained post-start decision.");
    const relativePath = "LOCAL_ARTIFACTS/check.json";
    const infrastructure = [
      ...bootstrapReady("Worker").validationInfrastructure,
      relativePath,
    ];
    const fixture = await createFixture(t, {
      mode: "lazy",
      async prepareProject(projectPath) {
        await mkdir(join(projectPath, "LOCAL_ARTIFACTS"));
        await writeFile(join(projectPath, relativePath), "{}\n");
      },
      worker: [
        clarificationReady(),
        {
          ...bootstrapReady("Worker"),
          validationInfrastructure: infrastructure,
        },
        productDecision({
          ...polishingCompleted(),
          status: "PRODUCT_DECISION_REQUIRED",
          summary: "",
        }),
      ],
    });
    const service = fixture.runtime.clarifications;
    fixture.runtime.clarifications = {
      ...service,
      async appendProductDecision(options) {
        await service.appendProductDecision(options);
        throw interruption;
      },
    };
    await assert.rejects(fixture.run(), (cause) => cause === interruption);
    const intent = structuredClone(
      fixture.currentRun.pipelineState.pendingClarificationAppend,
    );
    assert.equal(intent.checkpoint.workflowState, "POLISH");
    assert.match(
      intent.checkpoint.infrastructureFingerprint,
      /^[a-f0-9]{64}$/u,
    );
    if (missing) await rm(join(fixture.projectPath, relativePath));
    else
      await writeFile(
        join(fixture.projectPath, relativePath),
        '{"changed":true}\n',
      );
    const path = fixture.currentRun.pipelineState.clarificationPath;
    const bytes = await readFile(path, "utf8");
    fixture.runtime.clarifications = service;
    const rejected = await fixture.run();
    assert.equal(rejected.pause.reason, "unsafe_git_state");
    assert.equal(
      rejected.pause.code,
      "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
    );
    assert.equal(rejected.pipelineState.pendingEdit, null);
    assert.equal(rejected.counters.productDecisions, 0);
    assert.deepEqual(rejected.pipelineState.pendingClarificationAppend, intent);
    assert.equal(await readFile(path, "utf8"), bytes);
    assert.equal(fixture.calls.worker.length, 3);
    assert.equal(fixture.calls.reviewer.length, 0);
    assert.equal(fixture.calls.arbiter.length, 0);
  });
}
