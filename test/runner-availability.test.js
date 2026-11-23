import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  initPipeline,
  inspectInitSetup,
  prepareInitTurn,
} from "@agent-runner/init";
import { planAuthoringPipeline } from "@agent-runner/plan-authoring";
import { planExecutionPipeline } from "@agent-runner/plan-execution";
import { polishingPipeline } from "@agent-runner/polishing";

import { createFinalizationGuidanceDecision } from "../pipelines/plan-execution/src/workflow-contract.js";
import {
  AgentBoundaryError,
  AUTHENTICATION_REQUIRED_DISPOSITION,
  CodexAdapterError,
  normalizeAdapterFailure,
  PROVIDER_REGISTRY,
} from "../src/agents/index.js";
import { createRunStore } from "../src/index.js";
import {
  modelCatalogMiss,
  recordCompletedModelTurn,
  recordReadOnlyCatalogMiss,
} from "./support/model-catalog.js";
import { outputExhaustion } from "./support/output-exhaustion.js";
import { createRunner } from "../src/runner/index.js";
import { parseRunnerConfiguration } from "../src/config/index.js";
import { createModelCatalogRecovery } from "../src/runner/model-catalog.js";
import { createAvailabilityCoordinator } from "../src/runner/availability.js";
import { createInactivityCoordinator } from "../src/runner/inactivity.js";
import { runObservedAttempt } from "../src/runner/observations.js";
import {
  createStopMonitor,
  reconcileOperatorStop,
  stopSettlement,
} from "../src/runner/stops.js";
import { projectAvailabilityRetry } from "../src/state/index.js";
import { createWorkspaceService } from "../src/workspace/index.js";

const fingerprint = "a".repeat(64);
function unavailable(backend, overrides = {}) {
  return new AgentBoundaryError(
    { code: "ERR_BACKEND_UNAVAILABLE" },
    {
      failureClass:
        backend === "codex" ? "turn_server_overloaded" : "provider_unavailable",
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "transient",
      availabilityReason: "temporarily_overloaded",
      ...overrides,
    },
  );
}

function authenticationRequired() {
  return new AgentBoundaryError(
    { code: "ERR_CODEX_TURN_FAILED" },
    {
      failureClass: "turn_unauthorized",
      checkpoint: "turn",
      outcome: "rejected",
      effect: "possible",
      retry: "terminal",
      disposition: AUTHENTICATION_REQUIRED_DISPOSITION,
    },
  );
}

function capabilities() {
  return {
    version: "fixture",
    structuredOutput: true,
    readOnly: true,
    autonomousWrite: true,
    gitMetadataWriteBlocked: true,
    workspaceWrite: true,
    localCommit: true,
    remoteWriteBlocked: true,
    nativeSessionContinuation: true,
    nativeSessionFork: true,
  };
}

async function fixture(
  t,
  backend = "codex",
  model,
  {
    pipelineId = "plan-execution",
    pipelineStateVersion = 1,
    pipelineState = { workflowState: "IMPLEMENT" },
    role = "worker",
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "runner-availability-"));

  const projectPath = join(root, "project");
  const taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  let now = Date.parse("2026-09-29T10:00:00.000Z");
  const options = {
    stateRoot: join(root, "state"),
    clock: () => new Date(now),
    resolveStopBoundary: () => ({
      capability: "verified-commit-v1",
      step: 1,
      completedCommits: 0,
      baselineHead: null,
    }),
  };
  let store = createRunStore(options);
  let {
    state: run,
    lease,
    directoryPath,
  } = await store.createRun({
    pipelineId,
    pipelineStateVersion,
    projectPath,
    taskPath,
    roles: { [role]: { backend, ...(model === undefined ? {} : { model }) } },
    pipelineState,
    availabilityPolicy: { initialDelayMs: 5_000, maxDelayMs: 7_000 },
  });
  t.after(async () => {
    await lease.release();
    await rm(root, { recursive: true, force: true });
  });
  const events = [];
  const delays = [];
  let changed = false;
  const parameters = {
    runId: run.runId,
    lease,
    runStore: store,
    providers: PROVIDER_REGISTRY,
    git: {
      async assertUnchanged() {
        assert.equal(changed, false, "unsafe repository");
      },
    },
    publish: async (activity) => events.push(activity),
    validateRun() {},
    monitor: {
      async check() {},
      async wait(operation) {
        return operation(new AbortController().signal);
      },
    },
    clock: () => now,
    wait: async (delay) => {
      delays.push(delay);
      now += delay;
    },
  };
  return {
    get store() {
      return store;
    },
    get lease() {
      return lease;
    },
    run,
    directoryPath,
    events,
    delays,
    parameters,
    async restart() {
      await lease.release();
      store = createRunStore(options);
      lease = await store.acquireRunLease(run.runId);
      return createAvailabilityCoordinator({
        ...parameters,
        lease,
        runStore: store,
      });
    },
    coordinator: createAvailabilityCoordinator(parameters),
    input: {
      role: "worker",
      checkpoint: "implement:1",
      repository: { contentFingerprint: fingerprint },
    },
    reopen: () => createRunStore(options),
    advance: (ms) => {
      now += ms;
    },
    changeRepository: () => {
      changed = true;
    },
  };
}

test("catalog eligibility uses the current receipt, frozen selection and strict effect record", async () => {
  const options = {
    access: "read-only",
    profile: "profile",
    model: "test-model",
    effort: "high",
  };
  const run = {
    pause: null,
    modelCompletionReceipts: {},
    roles: { worker: { ...options, backend: "codex" } },
    activeTurn: { role: "worker", phase: "review" },
    preparation: null,
    executionProcess: null,
    executionResource: null,
  };
  let verified = 0;
  let writableNoEffectTurn = null;
  const policy = createModelCatalogRecovery({
    run,
    providers: PROVIDER_REGISTRY,
    monitor: {
      get writableNoEffectTurn() {
        return writableNoEffectTurn;
      },
      recordWritableNoEffect(turn) {
        writableNoEffectTurn = turn;
      },
    },
    verify: async () => {
      verified++;
    },
  });
  // The initial snapshot is stale. Classification gets the latest durable run.
  const current = { ...run, modelCompletionReceipts: { worker: fingerprint } };
  const readOnlyAttempt = {
    id: 9,
    role: "worker",
    checkpoint: "review:read-only:review",
    status: "failed",
    readOnlyRejection: normalizeAdapterFailure("codex", modelCatalogMiss())
      .failure,
  };
  const observed = (attempt) => ({
    ...current,
    observations: { attempts: [attempt] },
  });
  for (const [request, state, provesRetry] of [
    [{ ...options, access: "workspace-write" }, run, false],
    [{ ...options, session: { mode: "fork", id: "source" } }, current, false],
    [{ ...options, model: "other" }, current, false],
    [{ ...options, profile: "other" }, current, false],
    [{ ...options, effort: "low" }, current, false],
    // A missing terminal observation proves no no-effect rejection.
    [options, current, false],
    [options, observed({ ...readOnlyAttempt, status: "active" }), false],
    [options, observed({ ...readOnlyAttempt, role: "reviewer" }), false],
    [
      options,
      observed({ ...readOnlyAttempt, readOnlyRejection: undefined }),
      false,
    ],
    [options, observed(readOnlyAttempt), true],
  ]) {
    writableNoEffectTurn = null;
    const error = normalizeAdapterFailure("codex", modelCatalogMiss(request));
    await policy.observeFailure(error, "worker", request, state);
    assert.equal(
      policy.hasWritableNoEffect(run.activeTurn),
      request.access === "workspace-write",
    );
    assert.equal(policy.eligible(error), provesRetry);
  }
  const request = { ...options, access: "workspace-write" };
  const checkpoint = "check-and-fix:workspace-write:primary:1";
  const rejection = normalizeAdapterFailure("codex", modelCatalogMiss(request));
  const writableAttempt = {
    id: 10,
    role: "worker",
    checkpoint,
    status: "failed",
  };
  const writableState = (attempt) => ({
    ...current,
    activeTurn: { role: "worker", phase: "check-and-fix" },
    observations: { attempts: [attempt] },
  });
  const pause = policy.details("worker", checkpoint);
  await policy.observeFailure(
    rejection,
    "worker",
    request,
    writableState(writableAttempt),
  );
  assert.equal(policy.eligible(rejection), false);
  assert.equal(policy.writableRejectionFor(pause), undefined);
  await policy.observeFailure(
    rejection,
    "worker",
    request,
    writableState({
      ...writableAttempt,
      writableRejection: rejection.failure,
      writableRetryEligible: true,
    }),
  );
  assert.equal(policy.eligible(rejection), true);
  assert.deepEqual(policy.writableRejectionFor(pause), {
    attemptId: 10,
    failure: rejection.failure,
  });
  assert.equal(
    policy.writableRejectionFor({ ...pause, checkpoint: "other" }),
    undefined,
  );
  const commitRequest = {
    ...options,
    access: "local-commit",
    authorizationId: "commit-1",
  };
  const commitMiss = normalizeAdapterFailure(
    "codex",
    modelCatalogMiss(commitRequest),
  );
  const consumed = {
    status: "consumed",
    authorization: { id: "commit-1" },
    preEffectRejection: null,
  };
  const commitAttempt = {
    id: 11,
    role: "worker",
    checkpoint: "commit:1",
    status: "failed",
  };
  const commitState = (attempt) => ({
    ...current,
    activeTurn: { role: "worker", phase: "commit" },
    pipelineState: { pendingCommit: consumed },
    observations: { attempts: attempt === undefined ? [] : [attempt] },
  });
  const recorded = {
    ...consumed,
    preEffectRejection: {
      code: "ERR_CODEX_MODEL_UNAVAILABLE",
      recoverable: false,
      catalog: { effect: "none", commitExecutor: "not_started" },
    },
  };
  const rejectedAttempt = {
    ...commitAttempt,
    commitRejection: commitMiss.failure,
  };
  for (const [attempt, request] of [
    [undefined, commitRequest],
    [commitAttempt, commitRequest],
    [{ ...rejectedAttempt, status: "completed" }, commitRequest],
    [rejectedAttempt, { ...commitRequest, authorizationId: "other" }],
  ]) {
    await policy.observeFailure(
      commitMiss,
      "worker",
      request,
      commitState(attempt),
    );
    assert.equal(policy.eligible(commitMiss), false);
    assert.equal(policy.commitRejectionFor(recorded), undefined);
  }
  await policy.observeFailure(
    commitMiss,
    "worker",
    commitRequest,
    commitState(rejectedAttempt),
  );
  assert.equal(policy.eligible(commitMiss), true);
  for (const pendingCommit of [
    consumed,
    { ...recorded, authorization: { id: "other" } },
  ])
    assert.equal(policy.commitRejectionFor(pendingCommit), undefined);
  assert.deepEqual(policy.commitRejectionFor(recorded), {
    attemptId: 11,
    failure: commitMiss.failure,
  });
  // Only the one recording transition carries the attempt-bound proof.
  assert.equal(policy.commitRejectionFor(recorded), undefined);

  writableNoEffectTurn = null;
  const possible = normalizeAdapterFailure(
    "codex",
    modelCatalogMiss({ recovery: true }),
  );
  await policy.observeFailure(possible, "worker", options, current);
  assert.equal(policy.hasPossibleEffect(possible), true);
  assert.equal(policy.hasWritableNoEffect(run.activeTurn), false);
  assert.equal(policy.eligible(possible), false);
  assert.equal(verified, 18);
});

for (const pipelineId of ["polishing", "plan-execution"]) {
  test(`${pipelineId} catalog resume survives owner loss until the matching turn starts`, (t) =>
    verifyCatalogResume(t, pipelineId));

  test(`${pipelineId} catalog pause binds the failed read-only restatement and its accounting`, async (t) => {
    const model = "test-model";
    const polishing = pipelineId === "polishing";
    const reservationKey = polishing
      ? "resolutionCorrection"
      : "writableResult";
    const pipelineState = {
      workflowState: "RESOLVE_FINDINGS",
      repositoryBaseline: { contentFingerprint: fingerprint },
      ...(polishing ? {} : { currentStep: 1, pendingCommit: null }),
      [reservationKey]: {
        stage: "correcting",
        ...(polishing
          ? {
              access: "workspace-write",
              candidate: { contentFingerprint: fingerprint },
              diagnostics: [
                { field: "result", constraint: "interrupted-response" },
              ],
            }
          : {
              phase: "RESOLVE_FINDINGS",
              step: 1,
              candidateFingerprint: fingerprint,
            }),
        attempts: 2,
        additionalAttempts: 1,
        productDecision: null,
      },
    };
    const f = await fixture(t, "codex", model, { pipelineId, pipelineState });
    const role = "worker";
    const turn = {
      role,
      phase: polishing ? "resolve-findings" : "writable-result",
    };
    const binding = {
      role,
      checkpoint: polishing
        ? "resolve-findings:read-only:finding-resolution-correction"
        : "writable-result:read-only:commit:1",
      resumeState: "RESOLVE_FINDINGS",
    };
    const activity = {
      actor: role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Worker restatement started.",
    };
    const bootstrap = { role, phase: "bootstrap" };
    await f.store.startAgentTurn(f.lease, bootstrap, {
      activity: { ...activity, phase: bootstrap.phase },
    });
    await recordCompletedModelTurn(f.store, f.lease, bootstrap, { model });
    const retired = await f.store.finishAgentTurn(f.lease, bootstrap);
    const observationCheckpoint = polishing
      ? binding.checkpoint
      : "resolve-findings:workspace-write:commit:1";
    if (!polishing)
      await f.store.scheduleAvailabilityRetry(f.lease, {
        role,
        checkpoint: observationCheckpoint,
        reason: "temporarily_overloaded",
        contentFingerprint: fingerprint,
        expectedRevision: retired.revision,
      });
    const counters = { ...f.run.counters, fixRounds: 3 };
    await f.store.transitionRun(f.lease, { counters });
    const preparePipelineState = (state, revision) => ({
      ...state,
      [reservationKey]: {
        ...state[reservationKey],
        stage: "correcting",
        restatementStartedAfter: revision,
      },
    });
    const start = () =>
      f.store.startAgentTurn(f.lease, turn, { activity, preparePipelineState });
    const pausePatch = (run) => ({
      activeTurn: null,
      pipelineState: {
        ...run.pipelineState,
        workflowState: "WAITING_FOR_USER",
        [reservationKey]: {
          ...run.pipelineState[reservationKey],
          stage: polishing ? "correcting" : "retry-ready",
        },
      },
      pause: {
        code: "ERR_MODEL_CATALOG_RETRY",
        reason: "backend_unavailable",
        ...binding,
      },
    });
    const assertRejectedPause = async (before, patch = pausePatch(before)) => {
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_INVALID_EVENT_LOG",
      });
      await assertRejectedJournalTransition(f, before, patch);
    };

    await start();
    await recordCatalogAttempt(f, role, observationCheckpoint);
    await assertRejectedPause(await f.store.loadRun(f.run.runId));
    await f.store.finishAgentTurn(f.lease, turn);

    const miss = normalizeAdapterFailure("codex", modelCatalogMiss());
    const recordMiss = (checkpoint) =>
      assert.rejects(
        runObservedAttempt({
          runStore: f.store,
          lease: f.lease,
          role,
          checkpoint,
          request: { access: "read-only" },
          operation: async () => {
            throw miss;
          },
        }),
        (failure) => failure === miss,
      );
    await start();
    await recordMiss(`${binding.checkpoint}:other`);
    await assertRejectedPause(await f.store.loadRun(f.run.runId));
    await f.store.finishAgentTurn(f.lease, turn);
    await start();
    await recordMiss(observationCheckpoint);
    await f.store.finishAgentTurn(f.lease, turn);
    await start();
    await assertRejectedPause(await f.store.loadRun(f.run.runId));
    await recordMiss(observationCheckpoint);
    const failed = await f.store.loadRun(f.run.runId);
    const pause = pausePatch(failed);
    const drift = [
      { hashes: { ...failed.hashes, task: "b".repeat(64) } },
      { counters: { ...counters, fixRounds: 0 } },
      ...(polishing ? [] : [{ availabilityRetry: null }]),
      {
        pipelineState: {
          ...pause.pipelineState,
          repositoryBaseline: { contentFingerprint: "b".repeat(64) },
        },
      },
      {
        pipelineState: {
          ...pause.pipelineState,
          [reservationKey]: {
            ...pause.pipelineState[reservationKey],
            additionalAttempts: 2,
          },
        },
      },
    ];
    for (const patch of drift)
      await assertRejectedPause(failed, { ...pause, ...patch });
    const paused = await f.store.transitionRun(f.lease, pause);
    await f.restart();
    const resume = {
      activeTurn: null,
      pipelineState: {
        ...pause.pipelineState,
        workflowState: binding.resumeState,
      },
      pause: null,
    };
    const reset = { counters: { ...counters, fixRounds: 0 } };
    await assert.rejects(
      f.store.transitionRun(f.lease, { ...resume, ...reset }),
      { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
    );
    await assertRejectedJournalTransition(f, paused, {
      ...resume,
      ...reset,
      modelCatalogResume: binding,
    });
    const resumed = await f.store.transitionRun(f.lease, resume);
    const retryState = preparePipelineState(
      resumed.pipelineState,
      resumed.revision,
    );
    await assert.rejects(
      f.store.transitionRun(
        f.lease,
        { ...reset, activeTurn: turn, pipelineState: retryState },
        { activity, catalogCheckpoint: binding.checkpoint },
      ),
      { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
    );
    await assertRejectedJournalTransition(
      f,
      resumed,
      {
        ...reset,
        activeTurn: turn,
        pipelineState: retryState,
        modelCatalogResume: null,
      },
      activity,
      binding.checkpoint,
    );
    await f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: binding.checkpoint,
      preparePipelineState,
    });
    const retried = await f.reopen().loadRun(f.run.runId);
    assert.deepEqual(retried.activeTurn, turn);
    assert.deepEqual(retried.pipelineState, retryState);
    assert.deepEqual(retried.hashes, failed.hashes);
    assert.deepEqual(retried.counters, counters);
    assert.deepEqual(retried.availabilityRetry, failed.availabilityRetry);
  });
}

for (const [pipelineId, checkpoint, step] of [
  [
    "plan-execution",
    "review:read-only:commit:1",
    {
      currentStep: 1,
      customCandidate: { criterion: "C1", evidenceFingerprint: fingerprint },
      customResults: [{ step: 0, resultFingerprint: fingerprint }],
    },
  ],
  ["polishing", "review:read-only:review", {}],
]) {
  test(`${pipelineId} review catalog misses keep the captured infrastructure and history`, async (t) => {
    const model = "test-model";
    const role = "reviewer";
    const pipelineState = {
      workflowState: "REVIEW",
      ...step,
      settings: { mode: "combined" },
      additionalFixRounds: 0,
      reviewCorrection: null,
      pendingReviewCorrection: null,
      workReports: [{ phase: "POLISH", summary: "Accepted work." }],
      disputeHistory: [{ findingId: "R1", decision: "DISPUTE" }],
    };
    const f = await fixture(t, "codex", model, {
      pipelineId,
      pipelineState,
      role,
    });
    const turn = { role, phase: "review" };
    const activity = {
      actor: role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Turn started.",
    };
    await f.store.startAgentTurn(f.lease, turn, { activity });
    await recordCompletedModelTurn(f.store, f.lease, turn, { model });
    await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
      activity,
      checkpoint,
    });
    const binding = { role, checkpoint, resumeState: "REVIEW" };
    const saved = {
      ...pipelineState,
      catalogReviewInfrastructureFingerprint: fingerprint,
    };
    const pauseWith = (state) => ({
      activeTurn: null,
      pipelineState: { ...state, workflowState: "WAITING_FOR_USER" },
      pause: {
        reason: "backend_unavailable",
        code: "ERR_MODEL_CATALOG_RETRY",
        ...binding,
      },
    });
    const assertRejectedPause = async (state) => {
      const before = await f.store.loadRun(f.run.runId);
      const patch = pauseWith(state);
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_INVALID_EVENT_LOG",
      });
      await assertRejectedJournalTransition(f, before, patch);
    };
    // Review prompt history and criterion evidence stay bound to the retry
    // even when the repository baseline and infrastructure are unchanged.
    const replacements = [
      { workReports: [] },
      { disputeHistory: [] },
      ...(pipelineId === "plan-execution"
        ? [
            {
              customCandidate: {
                ...saved.customCandidate,
                evidenceFingerprint: "b".repeat(64),
              },
            },
            { customResults: [] },
          ]
        : []),
    ];
    for (const change of replacements)
      await assertRejectedPause({ ...saved, ...change });
    const paused = await f.store.transitionRun(f.lease, pauseWith(saved));
    for (const change of replacements) {
      const patch = { pipelineState: { ...saved, ...change }, pause: null };
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      });
      await assertRejectedJournalTransition(f, paused, {
        ...patch,
        modelCatalogResume: binding,
      });
    }
    const resumed = await f.store.transitionRun(f.lease, {
      pipelineState: saved,
      pause: null,
    });
    for (const change of replacements) {
      const patch = {
        activeTurn: turn,
        pipelineState: { ...saved, ...change },
      };
      await assert.rejects(
        f.store.transitionRun(f.lease, patch, {
          activity,
          catalogCheckpoint: checkpoint,
        }),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
      await assertRejectedJournalTransition(
        f,
        resumed,
        { ...patch, modelCatalogResume: null },
        activity,
        checkpoint,
      );
    }
    await f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
    });
    await recordCatalogAttempt(f, role, checkpoint, "failed", {
      readOnlyRejection: writableCatalogFailure,
    });
    // A later miss keeps the fingerprint captured by the first inspection.
    await assertRejectedPause({
      ...saved,
      catalogReviewInfrastructureFingerprint: "b".repeat(64),
    });
    for (const change of replacements)
      await assertRejectedPause({ ...saved, ...change });
    const repaused = await f.store.transitionRun(f.lease, pauseWith(saved));
    const recovered = await f.reopen().loadRun(repaused.runId);
    assert.equal(
      recovered.pipelineState.catalogReviewInfrastructureFingerprint,
      fingerprint,
    );
    assert.deepEqual(recovered.pipelineState, {
      ...saved,
      workflowState: "WAITING_FOR_USER",
    });
  });
}

test("a catalog-resumed restatement can use the retained watchdog reconstruction once", async (t) => {
  const model = "test-model";
  const repository = { contentFingerprint: fingerprint };
  const checkpoint = "implement:workspace-write:commit:1";
  const restatement = "writable-result:read-only:commit:1";
  const pipelineState = {
    workflowState: "IMPLEMENT",
    currentStep: 1,
    repositoryBaseline: repository,
    writableResult: {
      phase: "IMPLEMENT",
      step: 1,
      stage: "ready",
      candidateFingerprint: fingerprint,
      attempts: 0,
      additionalAttempts: 0,
      productDecision: null,
    },
  };
  const f = await fixture(t, "codex", model, { pipelineState });
  const role = "worker";
  const bootstrap = { role, phase: "bootstrap" };
  await f.store.startAgentTurn(f.lease, bootstrap, {
    activity: {
      actor: role,
      phase: bootstrap.phase,
      kind: "turn-started",
      message: "Worker bootstrap started.",
    },
  });
  await recordCompletedModelTurn(f.store, f.lease, bootstrap, { model });
  await f.store.finishAgentTurn(f.lease, bootstrap);
  const original = { role, phase: "implement" };
  await f.store.startAgentTurn(f.lease, original, {
    activity: {
      actor: role,
      phase: original.phase,
      kind: "turn-started",
      message: "Worker implementation started.",
    },
  });
  const observed = await f.store.startObservationAttempt(f.lease, {
    role,
    checkpoint,
  });
  const expired = await f.store.recordInactivity(
    f.lease,
    {
      role,
      checkpoint,
      attempt: 1,
      status: "expired",
      configurationFingerprint: f.run.providerInactivityFingerprint,
      contentFingerprint: "b".repeat(64),
    },
    "expired",
  );
  await f.store.recordObservationBatch(
    f.lease,
    { id: observed.observations.attempts.at(-1).id, role, checkpoint },
    [],
    {
      status: "failed",
      writableRejection: writableCatalogFailure,
      writableRetryEligible: true,
    },
  );
  await f.store.transitionRun(f.lease, {
    pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
    activeTurn: null,
    pause: {
      code: "ERR_MODEL_CATALOG_RETRY",
      reason: "backend_unavailable",
      resumeState: "IMPLEMENT",
      role,
      checkpoint: restatement,
    },
  });
  const resumed = await f.store.transitionRun(f.lease, {
    pipelineState,
    pause: null,
  });
  await f.restart();
  const coordinator = createInactivityCoordinator({
    ...f.parameters,
    lease: f.lease,
    runStore: f.store,
    initialRun: resumed,
    monitor: { ...f.parameters.monitor, persist: (write) => write() },
    git: { ...f.parameters.git, snapshot: async () => repository },
  });
  await coordinator.before({
    role,
    checkpoint,
    repository,
    continueEpisode: true,
  });
  const turn = { role, phase: "writable-result" };
  const started = await f.store.startAgentTurn(f.lease, turn, {
    activity: {
      actor: role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Worker restatement started.",
    },
    catalogCheckpoint: restatement,
    preparePipelineState: (current, revision) => ({
      ...current,
      writableResult: {
        ...current.writableResult,
        stage: "correcting",
        attempts: 1,
        restatementStartedAfter: revision,
      },
    }),
  });
  const reconstruction = {
    ...expired.inactivityRecovery,
    status: "reconstructing",
    attempt: 2,
    contentFingerprint: fingerprint,
  };
  await assert.rejects(
    f.store.recordInactivity(f.lease, reconstruction, "reconstructing"),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  const response = await coordinator.invoke(
    role,
    async ({ onFreshSession }) => {
      const observed = await f.store.loadRun(f.run.runId);
      await assertRejectedJournalTransition(
        f,
        observed,
        {
          inactivityRecovery: {
            ...reconstruction,
            reconstructionRevision: observed.revision + 1,
            contentFingerprint: expired.inactivityRecovery.contentFingerprint,
          },
        },
        {
          actor: role,
          phase: "inactivity",
          kind: "reconstructing",
          message: "Worker reconstruction requested.",
        },
      );
      assert.equal(await onFreshSession(), true);
      assert.equal(await onFreshSession(), false);
      const reconstructed = await f.reopen().loadRun(f.run.runId);
      assert.deepEqual(reconstructed.activeTurn, turn);
      assert.deepEqual(reconstructed.pipelineState, started.pipelineState);
      assert.deepEqual(reconstructed.counters, started.counters);
      assert.deepEqual(reconstructed.inactivityRecovery, {
        ...reconstruction,
        reconstructionRevision: reconstructed.revision,
      });
      return { output: "Restated result." };
    },
    { access: "read-only" },
  );
  assert.equal(response.output, "Restated result.");
  assert.equal(
    (await coordinator.completed(role, { repository })).inactivityRecovery,
    null,
  );
});

test("init catalog retry retains its checkpoint across temporary inspection failure", async (t) => {
  const model = "test-model";
  const { createState, validateRun } = initPipeline.workflow;
  const pipelineState = createState({ settings: { mode: "lazy" } });
  const turn = { role: "planner", phase: "clarify" };
  const activity = {
    actor: turn.role,
    phase: turn.phase,
    kind: "turn-started",
    message: "Planner clarification started.",
  };
  const binding = {
    role: turn.role,
    checkpoint: "clarify:read-only:0",
    resumeState: pipelineState.workflowState,
  };
  const f = await fixture(t, "codex", model, {
    pipelineId: "init",
    pipelineStateVersion: initPipeline.stateVersion,
    pipelineState,
    role: turn.role,
  });
  const inspection = await inspectInitSetup(
    {
      projectPath: f.run.projectPath,
      taskPath: f.run.taskPath,
      stateRoot: f.store.rootPath,
      artifactRoot: pipelineState.artifactRoot,
      documents: { instructions: [], checks: [], skills: [], guidance: [] },
    },
    { workspace: createWorkspaceService() },
  );
  const prepared = prepareInitTurn(pipelineState, inspection, fingerprint);
  await f.store.startAgentTurn(f.lease, turn, {
    activity,
    pipelineState: prepared.state,
  });
  await recordCompletedModelTurn(f.store, f.lease, turn, { model });
  await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
    activity,
    checkpoint: "init:planner:CLARIFY:0",
  });
  const suspended = {
    ...prepared.state,
    workflowState: "WAITING_FOR_USER",
    pendingTurn: null,
  };
  await f.store.transitionRun(f.lease, {
    pipelineState: suspended,
    activeTurn: null,
    pause: {
      reason: "provider_interrupted",
      code: "ERR_MODEL_CATALOG_RETRY",
      ...binding,
    },
  });

  const pauseForInspection = (constraint) =>
    f.store.settleCheckpoint(f.lease, ({ pipelineState }) => ({
      patch: {
        pipelineState: {
          ...pipelineState,
          workflowState: "WAITING_FOR_USER",
          pendingTurn: null,
        },
        activeTurn: null,
        pause: {
          reason: "init_inspection_failed",
          code: "ERR_INIT_INSPECTION",
          resumeState: binding.resumeState,
          inspectionFailure: { phase: "preparation", constraint },
        },
      },
    }));

  await pauseForInspection("inspection_unavailable");
  assert.deepEqual(
    (await f.reopen().loadRun(f.run.runId)).modelCatalogResume,
    binding,
  );
  const paused = await f.store.loadRun(f.run.runId);
  const restored = { ...suspended, workflowState: binding.resumeState };
  const substituted = {
    ...restored,
    settings: { ...restored.settings, maxRevisionRounds: 19 },
  };
  const substitution = { pipelineState: substituted, pause: null };
  validateRun({ ...paused, ...substitution });
  await assertRejectedJournalTransition(f, paused, substitution);
  await assert.rejects(f.store.transitionRun(f.lease, substitution), {
    code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
  });
  await f.store.transitionRun(f.lease, {
    pipelineState: restored,
    pause: null,
  });
  await assert.rejects(f.store.startAgentTurn(f.lease, turn, { activity }), {
    code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
  });
  const rebuilt = prepareInitTurn(restored, inspection, fingerprint);
  const resumed = await f.store.transitionRun(f.lease, {
    pipelineState: rebuilt.state,
  });
  assert.equal(rebuilt.request.id, prepared.request.id + 1);
  assert.equal(rebuilt.request.binding, prepared.request.binding);
  const options = { activity, catalogCheckpoint: binding.checkpoint };
  const replaced = { ...rebuilt.state, settings: substituted.settings };
  await assert.rejects(
    f.store.startAgentTurn(f.lease, turn, {
      ...options,
      pipelineState: replaced,
    }),
    { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
  );
  await assertRejectedJournalTransition(
    f,
    resumed,
    { activeTurn: turn, pipelineState: replaced, modelCatalogResume: null },
    activity,
    binding.checkpoint,
  );
  await pauseForInspection("inspection_unavailable");
  const interrupted = await f.reopen().loadRun(f.run.runId);
  assert.deepEqual(interrupted.modelCatalogResume, binding);
  const retry = { ...interrupted.pipelineState, workflowState: "CLARIFY" };
  await f.store.transitionRun(f.lease, { pipelineState: retry, pause: null });
  await f.store.transitionRun(f.lease, {
    pipelineState: prepareInitTurn(retry, inspection, fingerprint).state,
  });
  await f.store.startAgentTurn(f.lease, turn, {
    ...options,
    validate: validateRun,
  });
  const started = await f.reopen().loadRun(f.run.runId);
  assert.deepEqual(started.activeTurn, turn);
  assert.equal(started.modelCatalogResume, null);
});

async function verifyCatalogResume(t, pipelineId) {
  const model = "test-model";
  const polishing = pipelineId === "polishing";
  const reservationKey = polishing ? "resolutionCorrection" : "writableResult";
  const pipelineState = {
    workflowState: "RESOLVE_FINDINGS",
    ...(polishing ? {} : { currentStep: 1 }),
    [reservationKey]: {
      stage: "ready",
      ...(polishing
        ? { access: "workspace-write", diagnostics: [] }
        : {
            phase: "RESOLVE_FINDINGS",
            step: 1,
            candidateFingerprint: fingerprint,
          }),
      attempts: 0,
      additionalAttempts: 0,
      productDecision: null,
    },
  };
  const f = await fixture(t, "codex", model, {
    pipelineId,
    pipelineState,
  });
  const turn = {
    role: "worker",
    phase: polishing ? "resolve-findings" : "writable-result",
  };
  const activity = {
    actor: turn.role,
    phase: turn.phase,
    kind: "turn-started",
    message: "Worker restatement started.",
  };
  const originalTurn = { ...turn, phase: "resolve-findings" };
  await f.store.startAgentTurn(f.lease, originalTurn, {
    activity: { ...activity, phase: originalTurn.phase },
  });
  await recordCompletedModelTurn(f.store, f.lease, originalTurn, { model });
  const checkpoint = polishing
    ? "resolve-findings:read-only:finding-resolution-correction"
    : "writable-result:read-only:commit:1";
  const suspended = { ...pipelineState, workflowState: "WAITING_FOR_USER" };
  const pausePatch = {
    pipelineState: suspended,
    activeTurn: null,
    pause: {
      code: "ERR_MODEL_CATALOG_RETRY",
      reason: "backend_unavailable",
      resumeState: pipelineState.workflowState,
      role: turn.role,
      checkpoint,
    },
  };
  const completed = await f.store.loadRun(f.run.runId);
  await assert.rejects(f.store.transitionRun(f.lease, pausePatch), {
    code: "ERR_INVALID_EVENT_LOG",
  });
  await assertRejectedJournalTransition(f, completed, pausePatch);
  await f.store.finishAgentTurn(f.lease, originalTurn);
  await f.store.startAgentTurn(f.lease, originalTurn, {
    activity: { ...activity, phase: originalTurn.phase },
  });
  await recordWritableCatalogAttempt(
    f,
    originalTurn.role,
    `resolve-findings:workspace-write:${polishing ? "work" : "commit:1"}`,
  );
  const paused = await f.store.transitionRun(f.lease, pausePatch);
  const writableReservation = {
    ...pipelineState,
    [reservationKey]: {
      ...pipelineState[reservationKey],
      stage: "invoking",
      ...(polishing ? {} : { candidateFingerprint: null }),
    },
  };
  await assert.rejects(
    f.store.transitionRun(
      f.lease,
      { activeTurn: turn, pause: null, pipelineState: writableReservation },
      { activity },
    ),
    { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
  );
  const eventPath = join(f.directoryPath, "events.jsonl");
  const pausedHistory = await readFile(eventPath, "utf8");
  const bypass = {
    schemaVersion: paused.schemaVersion,
    runId: paused.runId,
    revision: paused.revision + 1,
    recordedAt: paused.updatedAt,
    activity,
    state: {
      ...paused,
      revision: paused.revision + 1,
      activeTurn: turn,
      pause: null,
      pipelineState: writableReservation,
    },
  };
  try {
    await writeFile(eventPath, pausedHistory + JSON.stringify(bypass) + "\n");
    await assert.rejects(f.reopen().loadRun(f.run.runId), {
      code: "ERR_INVALID_EVENT_LOG",
    });
  } finally {
    await writeFile(eventPath, pausedHistory);
  }
  await f.store.transitionRun(f.lease, {
    pipelineState,
    pause: null,
  });

  await f.restart();

  const blocked = await f.store.transitionRun(f.lease, {
    pipelineState: suspended,
    pause: {
      reason: "environment_blocked",
      code: "ERR_TRUSTED_VALIDATION_CAPABILITY_UNAVAILABLE",
      resumeState: pipelineState.workflowState,
    },
  });
  assert.deepEqual(blocked.modelCatalogResume, {
    role: turn.role,
    checkpoint,
    resumeState: pipelineState.workflowState,
  });
  await f.restart();
  const resumed = await f.store.transitionRun(f.lease, {
    pipelineState,
    pause: null,
  });

  // A miss on the original resolution can resume by consuming the report's
  // one read-only restatement before publishing the actual turn start.
  await f.store.transitionRun(f.lease, {
    pipelineState: {
      ...pipelineState,
      [reservationKey]: {
        ...pipelineState[reservationKey],
        stage: "correcting",
        attempts: 1,
        ...(polishing
          ? {
              diagnostics: [
                { field: "result", constraint: "interrupted-response" },
              ],
            }
          : { restatementStartedAfter: resumed.revision }),
      },
    },
  });

  const recovered = await f.store.loadRun(f.run.runId);
  const policy = createModelCatalogRecovery({
    run: recovered,
    providers: PROVIDER_REGISTRY,
  });
  assert.equal(recovered.activeTurn, null);
  assert.equal(recovered.pause, null);
  assert.equal(policy.claimResume(turn.role, checkpoint), true);
  const wrongPhase = "polish";
  const wrongCheckpoint = `${turn.phase}:read-only:work`;
  await assert.rejects(
    f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: wrongCheckpoint,
    }),
    { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
  );
  await assert.rejects(
    f.store.startAgentTurn(
      f.lease,
      { ...turn, phase: wrongPhase },
      {
        activity: { ...activity, phase: wrongPhase },
        catalogCheckpoint: checkpoint,
      },
    ),
    { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
  );
  const replacedReservation = {
    ...recovered.pipelineState,
    [reservationKey]: {
      ...recovered.pipelineState[reservationKey],
      stage: "invoking",
      ...(polishing ? {} : { attempts: 0, candidateFingerprint: null }),
    },
  };
  await assert.rejects(
    f.store.transitionRun(f.lease, { pipelineState: replacedReservation }),
    { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
  );
  await assert.rejects(
    f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
      pipelineState: replacedReservation,
    }),
    { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
  );
  const stop = polishing
    ? null
    : await f.store.requestOperatorStop({
        runId: f.run.runId,
        kind: "pause_requested",
        timing: "after-current-commit",
        expectedRevision: recovered.revision,
        idempotencyKey: "catalog-restatement-pause",
      });
  const started = await f.store.startAgentTurn(f.lease, turn, {
    activity,
    catalogCheckpoint: checkpoint,
    preparePipelineState: (current, revision) => ({
      ...current,
      [reservationKey]: {
        ...current[reservationKey],
        restatementStartedAfter: revision,
      },
    }),
  });
  assert.equal(
    started.pipelineState[reservationKey].restatementStartedAfter,
    stop?.revision ?? recovered.revision,
  );
  assert.deepEqual(started.activeTurn, turn);
  assert.equal(started.modelCatalogResume, null);
  assert.equal(
    (await f.reopen().loadRun(f.run.runId)).modelCatalogResume,
    null,
  );
  const source = await readFile(eventPath, "utf8");
  const events = source
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  const start = events.at(-1);
  assert.equal(start.catalogCheckpoint, checkpoint);
  try {
    for (const invalidStart of [
      { ...start, catalogCheckpoint: wrongCheckpoint },
      {
        ...start,
        state: { ...start.state, activeTurn: { ...turn, phase: wrongPhase } },
        activity: { ...start.activity, phase: wrongPhase },
      },
      {
        ...start,
        state: { ...start.state, pipelineState: replacedReservation },
      },
    ]) {
      await writeFile(
        eventPath,
        [...events.slice(0, -1), invalidStart]
          .map((event) => JSON.stringify(event))
          .join("\n") + "\n",
      );
      await assert.rejects(f.reopen().loadRun(f.run.runId), {
        code: "ERR_INVALID_EVENT_LOG",
      });
    }
  } finally {
    await writeFile(eventPath, source);
  }
  const preparationIndex = events.length - (stop === null ? 2 : 3);
  try {
    await writeFile(
      eventPath,
      events
        .map((event, index) =>
          index < preparationIndex
            ? event
            : {
                ...event,
                state: { ...event.state, pipelineState: replacedReservation },
              },
        )
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );
    await assert.rejects(f.reopen().loadRun(f.run.runId), {
      code: "ERR_INVALID_EVENT_LOG",
    });
  } finally {
    await writeFile(eventPath, source);
  }
  if (stop !== null) {
    await f.store.settleCheckpoint(f.lease, (latest) =>
      stopSettlement(latest, {
        activeTurn: null,
        pipelineState: latest.pipelineState,
        pause: null,
      }),
    );
  }
}

async function assertRejectedJournalTransition(
  f,
  before,
  patch,
  activity = null,
  catalogCheckpoint,
  writableCatalogRejection,
  commitCatalogRejection,
) {
  const eventPath = join(f.directoryPath, "events.jsonl");
  const history = await readFile(eventPath, "utf8");
  const revision = before.revision + 1;
  const event = {
    schemaVersion: before.schemaVersion,
    runId: before.runId,
    revision,
    recordedAt: before.updatedAt,
    activity,
    ...(catalogCheckpoint === undefined ? {} : { catalogCheckpoint }),
    ...(writableCatalogRejection === undefined
      ? {}
      : { writableCatalogRejection }),
    ...(commitCatalogRejection === undefined ? {} : { commitCatalogRejection }),
    state: { ...before, ...patch, revision },
  };
  try {
    await writeFile(eventPath, history + JSON.stringify(event) + "\n");
    await assert.rejects(f.reopen().loadRun(before.runId), {
      code: "ERR_INVALID_EVENT_LOG",
    });
  } finally {
    await writeFile(eventPath, history);
  }
}

const writableCatalogFailure = normalizeAdapterFailure(
  "codex",
  modelCatalogMiss({ access: "workspace-write" }),
).failure;

async function recordCatalogAttempt(
  f,
  role,
  checkpoint,
  status = "failed",
  rejection = {},
) {
  const started = await f.store.startObservationAttempt(f.lease, {
    role,
    checkpoint,
  });
  const { id } = started.observations.attempts.at(-1);
  await f.store.recordObservationBatch(f.lease, { id, role, checkpoint }, [], {
    status,
    ...rejection,
  });
  return { attemptId: id, failure: writableCatalogFailure };
}

function recordWritableCatalogAttempt(f, role, checkpoint) {
  return recordCatalogAttempt(f, role, checkpoint, "failed", {
    writableRejection: writableCatalogFailure,
    writableRetryEligible: true,
  });
}

test("plan-authoring catalog retry preserves the draft and revision budget", async (t) => {
  const model = "test-model";
  const turn = { role: "planner", phase: "check-and-fix" };
  const activity = {
    actor: turn.role,
    phase: turn.phase,
    kind: "turn-started",
    message: "Draft check and fix started.",
  };
  const binding = {
    role: turn.role,
    checkpoint: "check-and-fix:read-only:planning",
    resumeState: "CHECK_AND_FIX",
  };
  const draftFields = (body) => {
    const draft = `## Commit 1: fix(test): retain retry scope\n\n${body}\n`;
    return {
      draft,
      draftFingerprint: createHash("sha256").update(draft).digest("hex"),
    };
  };
  const { createState, validateRun } = planAuthoringPipeline.workflow;
  const settings = Object.fromEntries(
    Object.entries(planAuthoringPipeline.settings).map(([name, definition]) => [
      name,
      definition.defaultValue,
    ]),
  );
  const f = await fixture(t, "codex", model, {
    pipelineId: planAuthoringPipeline.id,
    pipelineStateVersion: planAuthoringPipeline.stateVersion,
    pipelineState: createState({ settings: { ...settings, mode: "lazy" } }),
    role: turn.role,
  });
  const pipelineState = {
    ...f.run.pipelineState,
    ...draftFields("Preserve the current draft."),
    workflowState: binding.resumeState,
    preflightComplete: true,
    clarificationFrozen: true,
    repositoryBaseline: {
      schemaVersion: 1,
      projectPath: f.run.projectPath,
      allowedPaths: [],
    },
  };
  const counters = { revisionRounds: 2 };
  await f.store.transitionRun(f.lease, {
    pipelineState,
    counters,
    hashes: { task: fingerprint, clarifications: fingerprint, context: null },
  });
  await f.store.startAgentTurn(f.lease, turn, {
    activity,
    validate: validateRun,
  });
  await recordCompletedModelTurn(f.store, f.lease, turn, { model });
  await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
    activity,
    checkpoint: binding.checkpoint,
  });
  const paused = await f.store.transitionRun(f.lease, {
    activeTurn: null,
    pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
    pause: {
      reason: "backend_unavailable",
      code: "ERR_MODEL_CATALOG_RETRY",
      ...binding,
    },
  });
  validateRun(paused);
  const resume = { pipelineState, pause: null };
  const changes = [
    { counters: { revisionRounds: 0 } },
    {
      pipelineState: {
        ...pipelineState,
        ...draftFields("Substitute the draft."),
      },
    },
  ];
  for (const change of changes) {
    const patch = { ...resume, ...change };
    await assert.rejects(f.store.transitionRun(f.lease, patch), {
      code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
    });
    await assertRejectedJournalTransition(f, paused, {
      ...patch,
      modelCatalogResume: binding,
    });
  }
  const resumed = await f.store.transitionRun(f.lease, resume);
  const options = { activity, catalogCheckpoint: binding.checkpoint };
  for (const change of changes) {
    const patch = { ...change, activeTurn: turn };
    await assert.rejects(f.store.transitionRun(f.lease, patch, options), {
      code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
    });
    await assertRejectedJournalTransition(
      f,
      resumed,
      { ...patch, modelCatalogResume: null },
      activity,
      binding.checkpoint,
    );
  }
  await f.store.startAgentTurn(f.lease, turn, options);
  const recovered = await f.reopen().loadRun(paused.runId);
  validateRun(recovered);
  assert.deepEqual(recovered.counters, counters);
  assert.deepEqual(recovered.pipelineState, pipelineState);
  assert.deepEqual(recovered.activeTurn, turn);
  assert.equal(recovered.modelCatalogResume, null);
});

test("initial IMPLEMENT catalog retry requires verified retirement of its active invocation", async (t) => {
  const prepared = {
    phase: "IMPLEMENT",
    step: 1,
    stage: "prepared",
    rework: false,
    budgetExhausted: false,
    beforeFingerprint: fingerprint,
    originalContentFingerprint: fingerprint,
    attempts: 0,
    additionalAttempts: 0,
    productDecision: null,
  };
  const pipelineState = {
    workflowState: "IMPLEMENT",
    currentStep: 1,
    repositoryBaseline: { contentFingerprint: fingerprint },
    writableResult: prepared,
  };
  const model = "test-model";
  const f = await fixture(t, "codex", model, { pipelineState });
  const turn = { role: "worker", phase: "implement" };
  const checkpoint = "implement:workspace-write:commit:1";
  const pausePatch = {
    pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
    activeTurn: null,
    pause: {
      reason: "backend_unavailable",
      code: "ERR_MODEL_CATALOG_RETRY",
      resumeState: "IMPLEMENT",
      role: "worker",
      checkpoint,
    },
  };
  const verified = {
    actor: "runner",
    phase: "implement",
    kind: "catalog-no-effect-verified",
    message: "Catalog lookup had no effect and the workspace is unchanged.",
  };
  const activity = {
    actor: "worker",
    phase: "implement",
    kind: "turn-started",
    message: "Turn started.",
  };
  const bootstrap = { role: "worker", phase: "bootstrap" };
  await f.store.startAgentTurn(f.lease, bootstrap, {
    activity: { ...activity, phase: bootstrap.phase },
  });
  await recordCompletedModelTurn(f.store, f.lease, bootstrap, { model });
  await f.store.finishAgentTurn(f.lease, bootstrap);
  const preparedRun = await f.store.loadRun(f.run.runId);
  await assert.rejects(
    f.store.transitionRun(f.lease, pausePatch, { activity: verified }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  await assertRejectedJournalTransition(f, preparedRun, pausePatch, verified);

  const invocation = {
    ...pipelineState,
    writableResult: { ...prepared, stage: "invoking" },
  };
  const active = await f.store.startAgentTurn(f.lease, turn, {
    activity,
    pipelineState: invocation,
  });
  const writableCatalogRejection = await recordWritableCatalogAttempt(
    f,
    turn.role,
    checkpoint,
  );
  const rejected = await f.store.loadRun(active.runId);
  await assert.rejects(
    f.store.transitionRun(f.lease, pausePatch, {
      writableCatalogRejection,
    }),
    {
      code: "ERR_INVALID_EVENT_LOG",
    },
  );
  await assertRejectedJournalTransition(
    f,
    rejected,
    pausePatch,
    null,
    undefined,
    writableCatalogRejection,
  );
  const changed = {
    ...pausePatch,
    pipelineState: {
      ...pausePatch.pipelineState,
      repositoryBaseline: { contentFingerprint: "b".repeat(64) },
    },
  };
  await assert.rejects(
    f.store.transitionRun(f.lease, changed, {
      activity: verified,
      writableCatalogRejection,
    }),
    { code: "ERR_INVALID_EVENT_LOG" },
  );
  await assertRejectedJournalTransition(
    f,
    rejected,
    changed,
    verified,
    undefined,
    writableCatalogRejection,
  );

  const paused = await f.store.transitionRun(f.lease, pausePatch, {
    activity: verified,
    writableCatalogRejection,
  });
  assert.deepEqual(
    (await f.reopen().loadRun(paused.runId)).pause,
    paused.pause,
  );
  const resumed = await f.store.transitionRun(f.lease, {
    pipelineState,
    pause: null,
  });
  assert.equal(resumed.modelCatalogResume.checkpoint, checkpoint);
  const replacedBaseline = {
    pipelineState: {
      ...pipelineState,
      repositoryBaseline: changed.pipelineState.repositoryBaseline,
    },
  };
  await assert.rejects(f.store.transitionRun(f.lease, replacedBaseline), {
    code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
  });
  await assertRejectedJournalTransition(f, resumed, replacedBaseline);
  await f.store.startAgentTurn(f.lease, turn, {
    activity,
    catalogCheckpoint: checkpoint,
    pipelineState: invocation,
  });
  const recovered = await f.reopen().loadRun(paused.runId);
  assert.equal(recovered.modelCatalogResume, null);
  assert.deepEqual(
    recovered.pipelineState.writableResult,
    invocation.writableResult,
  );
});

for (const [pipelineId, workflowState, checkpoint, correction] of [
  [
    "plan-execution",
    "CHECK_AND_FIX",
    "check-and-fix:workspace-write:primary:1",
    { pendingLazyCorrection: null },
  ],
  [
    "polishing",
    "CHECK_AND_FIX",
    "check-and-fix:workspace-write:lazy-correction:check-and-fix",
    {
      pendingLazyCorrection: {
        phase: "CHECK_AND_FIX",
        attempt: 1,
        fixRoundCharged: true,
      },
    },
  ],
  [
    "polishing",
    "POLISH",
    "polish:workspace-write:work",
    {
      pendingCorrection: true,
    },
  ],
  [
    "polishing",
    "RESOLVE_FINDINGS",
    "resolve-findings:workspace-write:work",
    {
      finalizationResult: { status: "FAIL", issues: [{ id: "F1" }] },
      resolutionCorrection: null,
    },
  ],
]) {
  const [[correctionField, pendingCorrection]] = Object.entries(correction);
  test(`${pipelineId} ${workflowState} catalog retry preserves candidate and fix accounting`, async (t) => {
    const model = "test-model";
    const lazyResolution = workflowState === "RESOLVE_FINDINGS";
    const pipelineState = {
      workflowState,
      settings: lazyResolution
        ? { mode: "lazy", maxFixRounds: 4 }
        : { mode: "combined" },
      ...(lazyResolution ? { additionalFixRounds: 0 } : {}),
      currentStep: 1,
      repositoryBaseline: { contentFingerprint: fingerprint },
      ...correction,
      availabilityCorrectionCharged: !lazyResolution,
    };
    const f = await fixture(t, "codex", model, { pipelineId, pipelineState });
    const turn = {
      role: "worker",
      phase: workflowState.toLowerCase().replaceAll("_", "-"),
    };
    const activity = {
      actor: turn.role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Turn started.",
    };
    const counters = { ...f.run.counters, fixRounds: 3 };
    await f.store.transitionRun(f.lease, { counters });
    await f.store.startAgentTurn(f.lease, turn, { activity });
    await recordCompletedModelTurn(f.store, f.lease, turn, { model });
    const binding = {
      role: turn.role,
      checkpoint,
      resumeState: workflowState,
    };
    const pausePatch = {
      activeTurn: null,
      pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
      pause: {
        reason: "backend_unavailable",
        code: "ERR_MODEL_CATALOG_RETRY",
        ...binding,
      },
    };
    const assertRejectedPause = async (
      before,
      writableCatalogRejection,
      patch = pausePatch,
    ) => {
      await assert.rejects(
        f.store.transitionRun(f.lease, patch, {
          writableCatalogRejection,
        }),
        { code: "ERR_INVALID_EVENT_LOG" },
      );
      await assertRejectedJournalTransition(
        f,
        before,
        patch,
        null,
        undefined,
        writableCatalogRejection,
      );
    };
    const completedAttempt = await recordCatalogAttempt(
      f,
      turn.role,
      checkpoint,
      "completed",
    );
    const completed = await f.store.loadRun(f.run.runId);
    await assertRejectedPause(completed);
    await assertRejectedPause(completed, completedAttempt);
    const laterRejection = await recordWritableCatalogAttempt(
      f,
      turn.role,
      checkpoint,
    );
    await assertRejectedPause(
      await f.store.loadRun(f.run.runId),
      laterRejection,
    );
    await f.store.finishAgentTurn(f.lease, turn);
    await f.store.startAgentTurn(f.lease, turn, { activity });
    const mismatched = await recordWritableCatalogAttempt(
      f,
      turn.role,
      `${checkpoint}:other`,
    );
    await assertRejectedPause(await f.store.loadRun(f.run.runId), mismatched);
    await f.store.finishAgentTurn(f.lease, turn);
    await f.store.startAgentTurn(f.lease, turn, { activity });
    if (workflowState === "POLISH") {
      const request = { access: "workspace-write", session: { mode: "fork" } };
      const failure = normalizeAdapterFailure(
        "codex",
        modelCatalogMiss(request),
      );
      await assert.rejects(
        runObservedAttempt({
          runStore: f.store,
          lease: f.lease,
          role: turn.role,
          checkpoint,
          request,
          operation: async () => {
            throw failure;
          },
        }),
        (cause) => cause === failure,
      );
      const history = await f
        .reopen()
        .loadRunHistory(f.run.runId, { stream: true });
      const attempt = history.run.observations.attempts.at(-1);
      assert.equal(history.hasWritableCatalogRejection, true);
      assert.equal(attempt.writableRetryEligible, undefined);
      await assertRejectedPause(history.run, {
        attemptId: attempt.id,
        failure: failure.failure,
      });
      await f.store.finishAgentTurn(f.lease, turn);
      await f.store.startAgentTurn(f.lease, turn, { activity });
    }
    const writableCatalogRejection = await recordWritableCatalogAttempt(
      f,
      turn.role,
      checkpoint,
    );
    const failed = await f.store.loadRun(f.run.runId);
    await assertRejectedPause(failed);
    await assertRejectedPause(failed, {
      ...writableCatalogRejection,
      failure: { ...writableCatalogRejection.failure, effect: "possible" },
    });
    const reset = { counters: { ...counters, fixRounds: 0 } };
    for (const change of [
      reset,
      { hashes: { ...failed.hashes, task: "b".repeat(64) } },
      {
        pipelineState: {
          ...pausePatch.pipelineState,
          repositoryBaseline: { contentFingerprint: "b".repeat(64) },
        },
      },
    ]) {
      await assertRejectedPause(failed, writableCatalogRejection, {
        ...pausePatch,
        ...change,
      });
    }
    const paused = await f.store.transitionRun(f.lease, pausePatch, {
      writableCatalogRejection,
    });
    const resumePatch = { pipelineState, pause: null };
    await assert.rejects(
      f.store.transitionRun(f.lease, { ...resumePatch, ...reset }),
      {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      },
    );
    await assertRejectedJournalTransition(f, paused, {
      ...resumePatch,
      ...reset,
      modelCatalogResume: binding,
    });

    const resumed = await f.store.transitionRun(f.lease, resumePatch);
    for (const patch of [
      reset,
      {
        pipelineState: {
          ...pipelineState,
          availabilityCorrectionCharged: lazyResolution,
        },
      },
      {
        pipelineState: {
          ...pipelineState,
          repositoryBaseline: { contentFingerprint: "b".repeat(64) },
        },
      },
      ...(pendingCorrection === null
        ? []
        : [
            {
              pipelineState: { ...pipelineState, [correctionField]: null },
            },
          ]),
    ]) {
      await assert.rejects(
        f.store.transitionRun(
          f.lease,
          { ...patch, activeTurn: turn },
          {
            activity,
            catalogCheckpoint: checkpoint,
          },
        ),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
      await assertRejectedJournalTransition(
        f,
        resumed,
        {
          ...patch,
          activeTurn: turn,
          modelCatalogResume: null,
        },
        activity,
        checkpoint,
      );
    }
    await f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
    });
    const recovered = await f.reopen().loadRun(resumed.runId);
    assert.deepEqual(recovered.counters, counters);
    assert.deepEqual(recovered.pipelineState, pipelineState);
    assert.deepEqual(recovered.activeTurn, turn);
    assert.equal(recovered.modelCatalogResume, null);
  });
}

for (const scenario of [
  "discovery",
  "commit",
  "commit stop",
  "commit stop after verification interruption",
  "review",
  "review correction",
  "polishing review correction",
  "clean confirmation",
  "polishing clean confirmation",
  "terminal confirmation",
  "polishing terminal confirmation",
  "finalization",
  "polishing finalization",
]) {
  const stop = scenario.startsWith("commit stop");
  const verificationInterrupted = scenario.endsWith(
    "verification interruption",
  );
  const name = stop
    ? `${scenario} journals a catalog retry after proof publication`
    : `${scenario} catalog resume rejects replacement of its reservation in admission and replay`;
  test(name, async (t) => {
    const audit = scenario === "discovery";
    const commit = scenario === "commit" || stop;
    const polishing = scenario.startsWith("polishing");
    const fixRoundLimit = polishing ? "maxFixRounds" : "maxFixRoundsPerStep";
    const correction = scenario.endsWith("review correction");
    const clean = scenario.endsWith("clean confirmation");
    const terminal = scenario.endsWith("terminal confirmation");
    const finalization = scenario.endsWith("finalization");
    const pipelineId = audit
      ? "audit"
      : polishing
        ? "polishing"
        : "plan-execution";
    const role = audit
      ? "auditor"
      : commit || clean || finalization
        ? "worker"
        : "reviewer";
    const workflowState = audit
      ? "DISCOVER"
      : commit
        ? "COMMIT"
        : clean
          ? "CLEAN_CONFIRM"
          : terminal
            ? "CONFIRM"
            : finalization
              ? "FINALIZE"
              : "REVIEW";
    const review = workflowState === "REVIEW";
    // Review and writable finalization retain spent rounds and their limit.
    const accounted = review || finalization;
    const checkpoint = audit
      ? "discovery:read-only:1"
      : commit
        ? "commit:1"
        : clean
          ? polishing
            ? "clean-confirm:read-only:primary-clean"
            : "clean-confirm:read-only:candidate:1"
          : terminal
            ? polishing
              ? "confirm:read-only:review"
              : "confirm:read-only:commit:1"
            : finalization
              ? polishing
                ? "finalize:workspace-write:work"
                : "finalize:workspace-write:commit:1"
              : polishing
                ? "review:read-only:candidate-review-correction"
                : correction
                  ? "review:read-only:candidate-review-correction:1"
                  : "review:read-only:commit:1";
    const pass = {
      number: 1,
      contextKey: fingerprint,
      outcome: "running",
      reportFingerprint: fingerprint,
      candidateIds: [],
    };
    const reviewCorrection = correction
      ? {
          ...(polishing ? {} : { step: 1 }),
          attempt: 1,
          contentFingerprint: fingerprint,
          validationInfrastructureFingerprint: fingerprint,
          diagnostics: [
            {
              role: "reviewer",
              phase: "review",
              contract: "candidate-review",
              field: "status",
              constraint: "semantic-contract",
            },
          ],
        }
      : null;
    const selectedGuidance = {
      configuredPolicy: "finalize.md",
      selection: "file",
      skillPath: "finalize.md",
      selectedFileFingerprint: fingerprint,
    };
    let pipelineState = audit
      ? {
          workflowState,
          history: [pass],
          settings: { mode: "combined", maxDiscoveryPasses: 4 },
        }
      : {
          workflowState,
          ...(polishing ? {} : { currentStep: 1, pendingCommit: null }),
          ...(clean
            ? { pendingLazyCorrection: null, settings: { mode: "combined" } }
            : {}),
          ...(accounted
            ? {
                additionalFixRounds: 2,
                settings: { mode: "combined", [fixRoundLimit]: 4 },
              }
            : {}),
          ...(terminal || finalization
            ? { validationInfrastructure: ["checks.json"] }
            : {}),
          ...(finalization ? { pendingFinalizationCorrection: null } : {}),
          ...(correction
            ? {
                finalizationGuidance:
                  createFinalizationGuidanceDecision(selectedGuidance),
              }
            : {}),
          reviewCorrection,
          pendingReviewCorrection: reviewCorrection,
        };
    const model = "test-model";
    const f = await fixture(t, "codex", model, {
      pipelineId,
      ...(scenario === "commit" ? { pipelineStateVersion: 45 } : {}),
      pipelineState,
      role,
    });
    const turn = {
      role,
      phase: audit
        ? "discovery"
        : workflowState.toLowerCase().replaceAll("_", "-"),
    };
    const activity = {
      actor: role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Turn started.",
    };
    if (accounted || terminal)
      await f.store.transitionRun(f.lease, {
        hashes: { context: fingerprint },
        ...(accounted ? { counters: { fixRounds: 3 } } : {}),
      });
    await f.store.startAgentTurn(f.lease, turn, { activity });
    await recordCompletedModelTurn(f.store, f.lease, turn, { model });
    let writableCatalogRejection;
    if (review || clean)
      pipelineState = {
        ...pipelineState,
        catalogReviewInfrastructureFingerprint: fingerprint,
      };
    const pausePatch = {
      pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
      activeTurn: null,
      pause: {
        reason: "backend_unavailable",
        code: "ERR_MODEL_CATALOG_RETRY",
        resumeState: workflowState,
        role,
        checkpoint,
      },
    };
    const prepared = {
      status: "prepared",
      authorization: {
        schemaVersion: 1,
        id: "commit-1",
        projectPath: f.run.projectPath,
        expectedHead: "a".repeat(40),
        expectedBranch: "refs/heads/main",
        expectedRefsFingerprint: fingerprint,
        expectedOtherRefsFingerprint: fingerprint,
        expectedContentFingerprint: fingerprint,
        expectedIndexFingerprint: fingerprint,
        expectedRemoteConfigurationFingerprint: fingerprint,
        expectedIdentityFingerprint: fingerprint,
        expectedAuthorIdentityFingerprint: fingerprint,
        expectedCommitterIdentityFingerprint: fingerprint,
        subject: "fix(test): bind commit retries",
      },
      preEffectRejection: null,
    };
    const consumed = { ...prepared, status: "consumed" };
    const retired = {
      actor: "runner",
      phase: "commit",
      kind: "authorization-retired",
      message: "Unused authorization retired.",
    };
    if (commit) {
      // An earlier failure at the same checkpoint cannot prove a later turn.
      await recordCatalogAttempt(f, role, checkpoint);
      await f.store.finishAgentTurn(f.lease, turn);
      if (!stop) {
        const before = await f.store.loadRun(f.run.runId);
        await assert.rejects(
          f.store.transitionRun(f.lease, pausePatch, { activity: retired }),
          { code: "ERR_INVALID_EVENT_LOG" },
        );
        await assertRejectedJournalTransition(f, before, pausePatch, retired);
      }
      for (const pendingCommit of [prepared, consumed]) {
        await f.store.transitionRun(f.lease, {
          pipelineState: { ...pipelineState, pendingCommit },
        });
      }
      if (!stop) {
        await assert.rejects(
          f.store.transitionRun(f.lease, pausePatch, { activity: retired }),
          { code: "ERR_INVALID_EVENT_LOG" },
        );
      }
      await f.store.startAgentTurn(f.lease, turn, { activity });
      const proofPatch = {
        pipelineState: {
          ...pipelineState,
          pendingCommit: {
            ...consumed,
            preEffectRejection: {
              code: "ERR_CODEX_MODEL_UNAVAILABLE",
              recoverable: false,
              catalog: { effect: "none", commitExecutor: "not_started" },
            },
          },
        },
      };
      const proofActivity = {
        ...retired,
        kind: "pre-effect-rejection-recorded",
      };
      const commitFailure = normalizeAdapterFailure(
        "codex",
        modelCatalogMiss({ access: "local-commit" }),
      ).failure;
      const assertRejectedProof = async (commitCatalogRejection) => {
        const before = await f.store.loadRun(f.run.runId);
        await assert.rejects(
          f.store.transitionRun(f.lease, proofPatch, {
            activity: proofActivity,
            commitCatalogRejection,
          }),
          { code: "ERR_INVALID_EVENT_LOG" },
        );
        await assertRejectedJournalTransition(
          f,
          before,
          proofPatch,
          proofActivity,
          undefined,
          undefined,
          commitCatalogRejection,
        );
      };
      // Only a failed attempt of this consumed turn at its checkpoint proves it.
      for (const attempt of [
        null,
        [checkpoint, "completed"],
        ["commit:2", "failed"],
      ]) {
        if (attempt !== null) await recordCatalogAttempt(f, role, ...attempt);
        const latest = await f.store.loadRun(f.run.runId);
        await assertRejectedProof({
          attemptId: latest.observations.attempts.at(-1).id,
          failure: commitFailure,
        });
      }
      // A generic failure at the exact checkpoint cannot adopt a later claim.
      for (const [status, rejection] of [
        ["completed", commitFailure],
        ["failed", { ...commitFailure, effect: "possible" }],
      ])
        await assert.rejects(
          recordCatalogAttempt(f, role, checkpoint, status, {
            commitRejection: rejection,
          }),
          { message: "Run observations are invalid." },
        );
      const generic = await recordCatalogAttempt(f, role, checkpoint);
      await assertRejectedProof({
        attemptId: generic.attemptId,
        failure: commitFailure,
      });
      const { attemptId } = await recordCatalogAttempt(
        f,
        role,
        checkpoint,
        "failed",
        { commitRejection: commitFailure },
      );
      const commitCatalogRejection = { attemptId, failure: commitFailure };
      const { commitExecutor: _, ...startedFailure } = commitFailure;
      for (const evidence of [
        undefined,
        { attemptId, failure: { ...startedFailure, effect: "possible" } },
        { attemptId, failure: { ...commitFailure, failureClass: "other" } },
        { ...commitCatalogRejection, attemptId: attemptId - 1 },
      ])
        await assertRejectedProof(evidence);
      const proof = await f.store.transitionRun(f.lease, proofPatch, {
        activity: proofActivity,
        commitCatalogRejection,
      });
      if (stop) {
        const stoppingFrom = verificationInterrupted
          ? await f.store.transitionRun(f.lease, {
              pipelineState: {
                ...proof.pipelineState,
                workflowState: "WAITING_FOR_USER",
              },
              pause: {
                reason: "commit_failed",
                code: "ERR_COMMIT_VERIFICATION_FAILED",
              },
            })
          : proof;
        await f.store.requestOperatorStop({
          runId: f.run.runId,
          kind: "pause_requested",
          expectedRevision: stoppingFrom.revision,
          idempotencyKey: "catalog-commit-stop",
        });
        const stopped = await f.store.settleCheckpoint(f.lease, (latest) =>
          stopSettlement(latest, pausePatch, retired),
        );
        const recovered = await f.reopen().loadRun(f.run.runId);
        assert.deepEqual(
          recovered.pause.operatorResume.pause,
          pausePatch.pause,
        );
        assert.equal(recovered.pipelineState.pendingCommit, null);
        assert.equal(
          stopped.stopRequest.reconciledRevision,
          recovered.revision,
        );
        return;
      }
      await f.store.finishAgentTurn(f.lease, turn);
      await assert.rejects(
        f.store.transitionRun(f.lease, {
          pipelineState: { ...proof.pipelineState, currentStep: 2 },
        }),
        { code: "ERR_INVALID_EVENT_LOG" },
      );
      await assert.rejects(f.store.transitionRun(f.lease, pausePatch), {
        code: "ERR_INVALID_EVENT_LOG",
      });
      // The proof belongs only to the transition that records the rejection.
      await assert.rejects(
        f.store.transitionRun(f.lease, pausePatch, {
          activity: retired,
          commitCatalogRejection,
        }),
        { code: "ERR_INVALID_EVENT_LOG" },
      );
    }
    if (finalization) {
      // The rejected pause uses the sole failed attempt of a later invocation.
      await f.store.finishAgentTurn(f.lease, turn);
      await f.store.startAgentTurn(f.lease, turn, { activity });
      const genericFailure = await recordCatalogAttempt(f, role, checkpoint);
      const generic = await f.store.loadRun(f.run.runId);
      await assert.rejects(
        f.store.transitionRun(f.lease, pausePatch, {
          writableCatalogRejection: genericFailure,
        }),
        { code: "ERR_INVALID_EVENT_LOG" },
      );
      await assertRejectedJournalTransition(
        f,
        generic,
        pausePatch,
        null,
        undefined,
        genericFailure,
      );
      await f.store.finishAgentTurn(f.lease, turn);
      await f.store.startAgentTurn(f.lease, turn, { activity });
      const started = await f.store.startObservationAttempt(f.lease, {
        role,
        checkpoint,
      });
      const attempt = started.observations.attempts.at(-1);
      const identity = { id: attempt.id, role, checkpoint };
      const possible = { ...writableCatalogFailure, effect: "possible" };
      await assert.rejects(
        f.store.recordObservationBatch(f.lease, identity, [], {
          status: "failed",
          writableRejection: possible,
        }),
        { message: "Run observations are invalid." },
      );
      await assertRejectedJournalTransition(f, started, {
        observations: {
          ...started.observations,
          attempts: [
            ...started.observations.attempts.slice(0, -1),
            { ...attempt, status: "failed", writableRejection: possible },
          ],
        },
      });
      await f.store.recordObservationBatch(f.lease, identity, [], {
        status: "failed",
        writableRejection: writableCatalogFailure,
        writableRetryEligible: true,
      });
      writableCatalogRejection = {
        attemptId: attempt.id,
        failure: writableCatalogFailure,
      };
      // The first pause already publishes the reservation resume preserves.
      const before = await f.store.loadRun(f.run.runId);
      const { pipelineState: waiting } = pausePatch;
      for (const change of [
        { pipelineState: { ...waiting, validationInfrastructure: ["b.json"] } },
        {
          pipelineState: {
            ...waiting,
            pendingFinalizationCorrection: { attempt: 1 },
          },
        },
        { pipelineState: { ...waiting, additionalFixRounds: 3 } },
        {
          pipelineState: {
            ...waiting,
            settings: { ...waiting.settings, [fixRoundLimit]: 5 },
          },
        },
        { counters: { ...before.counters, fixRounds: 0 } },
        { hashes: { ...before.hashes, task: "b".repeat(64) } },
      ]) {
        const patch = { ...pausePatch, ...change };
        await assert.rejects(
          f.store.transitionRun(f.lease, patch, { writableCatalogRejection }),
          { code: "ERR_INVALID_EVENT_LOG" },
        );
        await assertRejectedJournalTransition(
          f,
          before,
          patch,
          null,
          undefined,
          writableCatalogRejection,
        );
      }
    }
    if (review || clean || terminal) {
      // Only this invocation's own recorded rejection retires a read-only gate.
      const assertRejectedReadOnlyPause = async (patch = pausePatch) => {
        const before = await f.store.loadRun(f.run.runId);
        await assert.rejects(f.store.transitionRun(f.lease, patch), {
          code: "ERR_INVALID_EVENT_LOG",
        });
        await assertRejectedJournalTransition(f, before, patch);
      };
      await assertRejectedReadOnlyPause();
      await f.store.finishAgentTurn(f.lease, turn);
      await f.store.startAgentTurn(f.lease, turn, { activity });
      await recordCatalogAttempt(f, role, checkpoint);
      await assertRejectedReadOnlyPause();
      await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
        activity,
        checkpoint: `${checkpoint}:other`,
      });
      await assertRejectedReadOnlyPause();
      // The same label recorded under another phase cannot retire the gate.
      const otherTurn = { role, phase: "validation-migration" };
      await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
        activity,
        checkpoint,
        nextTurn: otherTurn,
      });
      await assertRejectedReadOnlyPause();
      await recordReadOnlyCatalogMiss(f.store, f.lease, otherTurn, {
        activity,
        checkpoint,
        nextTurn: turn,
      });
      // The first pause keeps the inputs and reservation resume preserves.
      const before = await f.store.loadRun(f.run.runId);
      for (const change of [
        { hashes: { ...before.hashes, task: "b".repeat(64) } },
        { counters: { ...before.counters, fixRounds: 7 } },
        {
          pipelineState: {
            ...pausePatch.pipelineState,
            previousFindings: [{ id: "R9" }],
          },
        },
      ])
        await assertRejectedReadOnlyPause({ ...pausePatch, ...change });
    }
    if (audit) {
      // Discovery needs its own failed attempt at the observed audit checkpoint.
      const assertRejectedAuditPause = async () => {
        const before = await f.store.loadRun(f.run.runId);
        await assert.rejects(f.store.transitionRun(f.lease, pausePatch), {
          code: "ERR_INVALID_EVENT_LOG",
        });
        await assertRejectedJournalTransition(f, before, pausePatch);
      };
      await assertRejectedAuditPause();
      await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
        activity,
        checkpoint,
      });
      await assertRejectedAuditPause();
      await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
        activity,
        checkpoint: `audit:${checkpoint}`,
      });
    }
    const paused = await f.store.transitionRun(
      f.lease,
      pausePatch,
      commit ? { activity: retired } : { writableCatalogRejection },
    );
    if (scenario === "commit") {
      const migrated = await f.store.migrateRun(
        f.lease,
        {
          pipelineState: planExecutionPipeline.migrations[45](paused),
          pipelineStateVersion: planExecutionPipeline.stateVersion,
        },
        {
          activity: {
            actor: "runner",
            phase: "runtime",
            kind: "migrated",
            message: "Migrated the paused COMMIT checkpoint.",
          },
        },
      );
      assert.deepEqual(migrated.pause, paused.pause);
      pipelineState = {
        ...pipelineState,
        validationMigrationDisagreement: null,
      };
    }
    if (correction) {
      const changedCorrection = {
        ...reviewCorrection,
        validationInfrastructureFingerprint: "b".repeat(64),
      };
      const patch = {
        pipelineState: {
          ...paused.pipelineState,
          reviewCorrection: changedCorrection,
          pendingReviewCorrection: changedCorrection,
        },
      };
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      });
      await assertRejectedJournalTransition(f, paused, patch);
      const changedGuidance = {
        pipelineState: {
          ...paused.pipelineState,
          finalizationGuidance: createFinalizationGuidanceDecision({
            ...selectedGuidance,
            selectedFileFingerprint: "b".repeat(64),
          }),
        },
      };
      await assert.rejects(f.store.transitionRun(f.lease, changedGuidance), {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      });
      await assertRejectedJournalTransition(f, paused, changedGuidance);
    }
    if (review || clean) {
      const changedScope = {
        pipelineState: {
          ...paused.pipelineState,
          catalogReviewInfrastructureFingerprint: "b".repeat(64),
        },
      };
      await assert.rejects(f.store.transitionRun(f.lease, changedScope), {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      });
      await assertRejectedJournalTransition(f, paused, changedScope);
    }
    const resumePatch = { pipelineState, pause: null };
    const binding = { role, checkpoint, resumeState: workflowState };
    const changedReservation = [];
    if (accounted || terminal) {
      changedReservation.push({
        hashes: { ...paused.hashes, context: "b".repeat(64) },
      });
    }
    if (finalization) {
      changedReservation.push(
        {
          pipelineState: {
            ...pipelineState,
            validationInfrastructure: ["changed.json"],
          },
        },
        {
          pipelineState: {
            ...pipelineState,
            pendingFinalizationCorrection: { attempt: 1 },
          },
        },
      );
    }
    if (accounted) {
      changedReservation.push(
        { counters: { ...paused.counters, fixRounds: 0 } },
        { pipelineState: { ...pipelineState, additionalFixRounds: 3 } },
        {
          pipelineState: {
            ...pipelineState,
            settings: { ...pipelineState.settings, [fixRoundLimit]: 5 },
          },
        },
      );
    }
    if (audit) {
      changedReservation.push({
        pipelineState: {
          ...pipelineState,
          settings: { ...pipelineState.settings, maxDiscoveryPasses: 5 },
        },
      });
    }
    for (const change of changedReservation) {
      const patch = { ...resumePatch, ...change };
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      });
      await assertRejectedJournalTransition(f, paused, {
        ...patch,
        modelCatalogResume: binding,
      });
    }
    const resumed = await f.store.transitionRun(f.lease, resumePatch);
    for (const change of changedReservation) {
      const patch = { activeTurn: turn, ...change };
      await assert.rejects(
        f.store.transitionRun(f.lease, patch, {
          activity,
          catalogCheckpoint: checkpoint,
        }),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
      await assertRejectedJournalTransition(
        f,
        resumed,
        { ...patch, modelCatalogResume: null },
        activity,
        checkpoint,
      );
    }
    const replacement = audit
      ? {
          ...pipelineState,
          history: [
            { ...pass, outcome: "interrupted" },
            { ...pass, number: 2, contextKey: "b".repeat(64) },
          ],
        }
      : clean || terminal || finalization
        ? {
            ...pipelineState,
            validationInfrastructure: ["changed.json"],
          }
        : polishing
          ? {
              ...pipelineState,
              reviewCorrection: null,
              pendingReviewCorrection: null,
            }
          : { ...pipelineState, currentStep: 2 };
    await assert.rejects(
      f.store.transitionRun(f.lease, { pipelineState: replacement }),
      { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
    );
    await assertRejectedJournalTransition(f, resumed, {
      pipelineState: replacement,
    });

    if (!audit && !commit) {
      await assert.rejects(
        f.store.startAgentTurn(f.lease, turn, {
          activity,
          catalogCheckpoint: checkpoint,
          pipelineState: replacement,
        }),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
    }
    if (correction) {
      await assert.rejects(
        f.store.transitionRun(f.lease, {
          pipelineState: { ...pipelineState, pendingReviewCorrection: null },
        }),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
    }
    if (commit) {
      const authorization = { ...prepared.authorization, id: "commit-retry" };
      for (const pendingCommit of [prepared, consumed]) {
        await f.store.transitionRun(f.lease, {
          pipelineState: {
            ...pipelineState,
            pendingCommit: { ...pendingCommit, authorization },
          },
        });
      }
      await assert.rejects(
        f.store.startAgentTurn(f.lease, turn, {
          activity,
          catalogCheckpoint: checkpoint,
          pipelineState: {
            ...pipelineState,
            pendingCommit: {
              ...consumed,
              authorization: { ...consumed.authorization, id: "other" },
            },
          },
        }),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
    }

    const started = await f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
    });
    assert.equal(started.modelCatalogResume, null);
    const recovered = await f.reopen().loadRun(resumed.runId);
    assert.deepEqual(recovered.activeTurn, turn);
    if (accounted || terminal)
      assert.deepEqual(recovered.hashes, paused.hashes);
    if (accounted) {
      assert.deepEqual(recovered.counters, paused.counters);
      assert.equal(recovered.pipelineState.additionalFixRounds, 2);
      assert.deepEqual(
        recovered.pipelineState.settings,
        pipelineState.settings,
      );
    }
  });
}

test("an ordinary catalog pause requires the current failed attempt in admission and replay", async (t) => {
  const model = "test-model";
  const role = "worker";
  const turn = { role, phase: "bootstrap" };
  const pipelineState = { workflowState: "BOOTSTRAP" };
  const f = await fixture(t, "codex", model, { pipelineState, role });
  const activity = {
    actor: role,
    phase: turn.phase,
    kind: "turn-started",
    message: "Worker bootstrap started.",
  };
  const checkpoint = "bootstrap:read-only:bootstrap";
  const patch = {
    pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
    activeTurn: null,
    pause: {
      reason: "backend_unavailable",
      code: "ERR_MODEL_CATALOG_RETRY",
      resumeState: "BOOTSTRAP",
      role,
      checkpoint,
    },
  };
  const rejectPause = async () => {
    const before = await f.store.loadRun(f.run.runId);
    await assert.rejects(f.store.transitionRun(f.lease, patch), {
      code: "ERR_INVALID_EVENT_LOG",
    });
    await assertRejectedJournalTransition(f, before, patch);
  };
  await f.store.startAgentTurn(f.lease, turn, { activity });
  await recordCompletedModelTurn(f.store, f.lease, turn, { model });
  await rejectPause();
  await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
    activity,
    checkpoint: `${checkpoint}:other`,
  });
  await rejectPause();
  await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
    activity,
    checkpoint,
  });
  await f.store.finishAgentTurn(f.lease, turn);
  await f.store.startAgentTurn(f.lease, turn, { activity });
  await recordCatalogAttempt(f, role, checkpoint);
  await rejectPause();
  await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
    activity,
    checkpoint,
  });
  const paused = await f.store.transitionRun(f.lease, patch);
  assert.deepEqual((await f.reopen().loadRun(f.run.runId)).pause, paused.pause);
  await f.store.requestOperatorStop({
    runId: paused.runId,
    kind: "pause_requested",
    expectedRevision: paused.revision,
    idempotencyKey: "retain-catalog-pause",
  });
  await f.store.settleCheckpoint(f.lease, (latest) =>
    stopSettlement(latest, {
      activeTurn: null,
      pipelineState: latest.pipelineState,
      pause: latest.pause,
    }),
  );
  const stopped = await f.reopen().loadRun(paused.runId);
  assert.equal(stopped.pause.reason, "operator_paused");
  assert.deepEqual(stopped.pause.operatorResume.pause, paused.pause);
});

test("matching catalog evidence cannot authorize combined bootstrap arbitration", async (t) => {
  const model = "test-model";
  const role = "arbiter";
  const turn = { role, phase: "bootstrap" };
  const pipelineState = {
    workflowState: "BOOTSTRAP",
    settings: { mode: "combined" },
    bootstrapDisagreement: {
      description: "Different summaries.",
      evidence: ["The reports differ."],
    },
  };
  const f = await fixture(t, "codex", model, { pipelineState, role });
  const activity = {
    actor: role,
    phase: turn.phase,
    kind: "turn-started",
    message: "Arbiter turn started.",
  };
  const checkpoint = "bootstrap:read-only:arbitration";
  await f.store.startAgentTurn(f.lease, turn, { activity });
  await recordCompletedModelTurn(f.store, f.lease, turn, { model });
  const before = await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
    activity,
    checkpoint,
  });
  const patch = {
    activeTurn: null,
    pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
    pause: {
      reason: "backend_unavailable",
      code: "ERR_MODEL_CATALOG_RETRY",
      resumeState: "BOOTSTRAP",
      role,
      checkpoint,
    },
  };
  await assert.rejects(f.store.transitionRun(f.lease, patch), {
    code: "ERR_INVALID_EVENT_LOG",
  });
  await assertRejectedJournalTransition(f, before, patch);
});

// A narrative review observes `plan-context` but resumes its producing turn.
for (const [checkpoint, observed, reviewPhase] of [
  [
    "validation-migration:read-only:validation-migration",
    "validation-migration:read-only:validation-migration",
    "validation-migration",
  ],
  [
    "validation-migration:read-only:plan-context:validation-migration",
    "plan-context:read-only:validation-migration",
    "plan-context",
  ],
]) {
  test(`validation migration catalog retry at ${checkpoint} binds the saved disagreement and correction in the journal`, async (t) => {
    const model = "test-model";
    const role = "arbiter";
    const phase = "validation-migration";
    const pipelineState = {
      workflowState: "REVIEW",
      validationMigrationPending: true,
      validationMigrationDisagreement: {
        description: "Validation requirements differ.",
        evidence: ["The roles assigned different steps to a check."],
      },
      pendingBootstrapCorrection: {
        attempt: 1,
        diagnostics: [
          {
            role,
            phase,
            contract: "bootstrap-arbitration",
            field: "direction",
            constraint: "validation-migration-direction",
          },
        ],
      },
    };
    const f = await fixture(t, "codex", model, {
      pipelineState,
      pipelineStateVersion: planExecutionPipeline.stateVersion,
      role,
    });
    const turn = { role, phase };
    const activity = {
      actor: role,
      phase,
      kind: "turn-started",
      message: "Validation migration arbitration started.",
    };
    await f.store.startAgentTurn(f.lease, turn, { activity });
    await recordCompletedModelTurn(f.store, f.lease, turn, { model });
    const pausePatch = {
      pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
      activeTurn: null,
      pause: {
        reason: "backend_unavailable",
        code: "ERR_MODEL_CATALOG_RETRY",
        resumeState: pipelineState.workflowState,
        role,
        checkpoint,
      },
    };
    // Completion alone is no proof of the failed invocation's rejection.
    const assertRejectedPause = async (patch = pausePatch) => {
      const before = await f.store.loadRun(f.run.runId);
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_INVALID_EVENT_LOG",
      });
      await assertRejectedJournalTransition(f, before, patch);
    };
    await assertRejectedPause();
    const reviewTurn = { role, phase: reviewPhase };
    await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
      activity,
      checkpoint: `${observed}:other`,
      nextTurn: reviewTurn,
    });
    await assertRejectedPause();
    await recordReadOnlyCatalogMiss(f.store, f.lease, reviewTurn, {
      activity,
      checkpoint: observed,
    });
    const failed = await f.store.loadRun(f.run.runId);
    for (const change of [
      { hashes: { ...failed.hashes, task: "b".repeat(64) } },
      { counters: { ...failed.counters, fixRounds: 2 } },
      ...[
        { validationMigrationPending: false },
        { validationMigrationDisagreement: null },
        { pendingBootstrapCorrection: null },
      ].map((change) => ({
        pipelineState: { ...pausePatch.pipelineState, ...change },
      })),
      { pause: { ...pausePatch.pause, resumeState: "FINALIZE" } },
    ])
      await assertRejectedPause({ ...pausePatch, ...change });
    const paused = await f.store.transitionRun(f.lease, pausePatch);
    const replacement = {
      pipelineState: {
        ...pipelineState,
        validationMigrationDisagreement: null,
      },
      pause: null,
    };
    await assert.rejects(f.store.transitionRun(f.lease, replacement), {
      code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
    });
    await assertRejectedJournalTransition(f, paused, replacement);
    const resumed = await f.store.transitionRun(f.lease, {
      pipelineState,
      pause: null,
    });
    const redirectedPause = {
      pipelineState: paused.pipelineState,
      pause: { ...paused.pause, resumeState: "FINALIZE" },
    };
    await assert.rejects(f.store.transitionRun(f.lease, redirectedPause), {
      code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
    });
    await assertRejectedJournalTransition(f, resumed, {
      ...redirectedPause,
      modelCatalogResume: null,
    });
    await f.restart();
    assert.deepEqual(
      (await f.store.loadRun(resumed.runId)).pipelineState,
      pipelineState,
    );
    await assert.rejects(
      f.store.startAgentTurn(f.lease, turn, {
        activity,
        catalogCheckpoint: checkpoint,
        pipelineState: { ...pipelineState, pendingBootstrapCorrection: null },
      }),
      { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
    );
    await f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
    });
    assert.deepEqual(
      (await f.reopen().loadRun(resumed.runId)).activeTurn,
      turn,
    );
    if (reviewPhase === "plan-context") {
      // A miss while rebuilding the prerequisite still observes plan-context.
      await recordCatalogAttempt(f, role, observed, "failed", {
        readOnlyRejection: writableCatalogFailure,
      });
      const pausedAgain = await f.store.transitionRun(f.lease, pausePatch);
      assert.deepEqual(
        (await f.reopen().loadRun(resumed.runId)).pause,
        pausedAgain.pause,
      );
    }
  });
}

// Polishing migration turns keep the suspended phase and share gate prefixes.
for (const [workflowState, role] of [
  ["CHECK_AND_FIX", "worker"],
  ["POLISH", "worker"],
  ["REVIEW", "reviewer"],
]) {
  test(`polishing ${workflowState} validation migration catalog retry keeps its role, phase and correction`, async (t) => {
    const model = "test-model";
    const phase = workflowState.toLowerCase().replaceAll("_", "-");
    const checkpoint = `${phase}:read-only:validation-migration`;
    const pipelineState = {
      workflowState,
      settings: { mode: "combined" },
      validationMigrationPending: true,
      validationMigrationDisagreement: null,
      pendingLazyCorrection: null,
      pendingBootstrapCorrection: {
        attempt: 1,
        diagnostics: [
          {
            role,
            phase: "validation-migration",
            contract: "bootstrap",
            field: "status",
            constraint: "validation-migration-status",
          },
        ],
      },
    };
    const f = await fixture(t, "codex", model, {
      pipelineId: polishingPipeline.id,
      pipelineStateVersion: polishingPipeline.stateVersion,
      pipelineState,
      role,
    });
    const counters = { ...f.run.counters, fixRounds: 2 };
    await f.store.transitionRun(f.lease, { counters });
    const turn = { role, phase };
    const activity = {
      actor: role,
      phase,
      kind: "turn-started",
      message: "Validation rediscovery started.",
    };
    await f.store.startAgentTurn(f.lease, turn, { activity });
    await recordCompletedModelTurn(f.store, f.lease, turn, { model });
    const binding = { role, checkpoint, resumeState: workflowState };
    const pausePatch = {
      pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
      activeTurn: null,
      pause: {
        reason: "backend_unavailable",
        code: "ERR_MODEL_CATALOG_RETRY",
        ...binding,
      },
    };
    // Only this invocation's own recorded rejection can publish the retry.
    const unproven = await f.store.loadRun(f.run.runId);
    await assert.rejects(f.store.transitionRun(f.lease, pausePatch), {
      code: "ERR_INVALID_EVENT_LOG",
    });
    await assertRejectedJournalTransition(f, unproven, pausePatch);
    await recordReadOnlyCatalogMiss(f.store, f.lease, turn, {
      activity,
      checkpoint,
    });
    const paused = await f.store.transitionRun(f.lease, pausePatch);
    const resume = { pipelineState, pause: null };
    for (const change of [
      { pipelineState: { ...pipelineState, pendingBootstrapCorrection: null } },
      { counters: { ...counters, fixRounds: 0 } },
    ]) {
      const patch = { ...resume, ...change };
      await assert.rejects(f.store.transitionRun(f.lease, patch), {
        code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED",
      });
      await assertRejectedJournalTransition(f, paused, {
        ...patch,
        modelCatalogResume: binding,
      });
    }
    const resumed = await f.store.transitionRun(f.lease, resume);
    assert.deepEqual(resumed.modelCatalogResume, binding);
    await f.restart();
    await f.store.startAgentTurn(f.lease, turn, {
      activity,
      catalogCheckpoint: checkpoint,
    });
    const recovered = await f.reopen().loadRun(paused.runId);
    assert.deepEqual(recovered.activeTurn, turn);
    assert.deepEqual(recovered.pipelineState, pipelineState);
    assert.deepEqual(recovered.counters, counters);
    assert.equal(recovered.modelCatalogResume, null);
  });
}

test("availability retries survive restart, repeat a ceiling, and reset only on a provider response", async (t) => {
  for (const backend of ["codex", "claude"]) {
    const f = await fixture(t, backend);
    let coordinator = f.coordinator;
    let episodeId;
    const attempts = backend === "codex" ? 3 : 1;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      const scheduled = await coordinator.schedule({
        ...f.input,
        cause: unavailable(backend),
      });
      episodeId ??= scheduled.availabilityRetry.id;
      assert.equal(scheduled.availabilityRetry.id, episodeId);
      assert.equal(scheduled.availabilityRetry.attempt, attempt);
      assert.equal(scheduled.availabilityRetry.contentFingerprint, fingerprint);
      const recovered = await f.reopen().loadRun(f.run.runId);
      assert.deepEqual(
        recovered.availabilityRetry,
        scheduled.availabilityRetry,
      );
      if (attempt === 1) coordinator = await f.restart();
      await coordinator.before(f.input);
      // Starting and retiring a failed turn is not progress.
      await f.store.startAgentTurn(
        f.lease,
        { role: "worker", phase: "implement" },
        {
          activity: {
            actor: "worker",
            phase: "implement",
            kind: "turn-started",
            message: "Provider turn.",
          },
        },
      );
      await f.store.finishAgentTurn(f.lease, {
        role: "worker",
        phase: "implement",
      });
    }
    assert.deepEqual(f.delays, [5000, 7000, 7000].slice(0, attempts));
    assert.deepEqual(
      f.events.map(({ kind }) => kind),
      Array(attempts).fill(["retry-scheduled", "retry-started"]).flat(),
    );
    await f.store.startAgentTurn(
      f.lease,
      { role: "worker", phase: "implement" },
      {
        activity: {
          actor: "worker",
          phase: "implement",
          kind: "turn-started",
          message: "Provider turn.",
        },
      },
    );
    const responseCheckpoint = await coordinator.completed("worker", {
      patch: {
        pipelineState: { workflowState: "REVIEW" },
        counters: { fixRounds: 1 },
      },
    });
    const completed = await f.reopen().loadRun(f.run.runId);
    assert.deepEqual(responseCheckpoint, completed);
    assert.equal(completed.availabilityRetry, null);
    assert.equal(completed.pipelineState.workflowState, "REVIEW");
    assert.equal(completed.counters.fixRounds, 1);
    await f.store.finishAgentTurn(f.lease, {
      role: "worker",
      phase: "implement",
    });
    const restarted = await coordinator.schedule({
      ...f.input,
      cause: unavailable(backend),
    });
    assert.equal(restarted.availabilityRetry.attempt, 1);
    assert.notEqual(restarted.availabilityRetry.id, episodeId);
    assert.deepEqual(Object.keys(projectAvailabilityRetry(restarted)), [
      "role",
      "checkpoint",
      "reason",
      "attempt",
      "delayMs",
      "nextRetryAt",
    ]);
  }
});

test("deadline interruption preserves the checkpoint; overdue recovery dispatches once and unsafe Git prevents retry", async (t) => {
  const f = await fixture(t);
  await f.coordinator.schedule({ ...f.input, cause: unavailable("codex") });
  const episode = (await f.store.loadRun(f.run.runId)).availabilityRetry;
  const abort = new AbortController();
  const interrupted = createAvailabilityCoordinator({
    ...f.parameters,
    wait: async (_delay, signal) => {
      abort.abort(new Error("Owner stopped"));
      signal.throwIfAborted();
    },
    monitor: {
      async check() {},
      async wait(operation) {
        return operation(abort.signal);
      },
    },
  });
  await assert.rejects(interrupted.before(f.input), {
    code: "ERR_AVAILABILITY_RECOVERY",
  });
  assert.deepEqual(
    (await f.reopen().loadRun(f.run.runId)).availabilityRetry,
    episode,
  );
  f.advance(100_000);
  await f.coordinator.before(f.input);
  assert.deepEqual(f.delays, []);
  assert.equal(
    f.events.filter(({ kind }) => kind === "retry-started").length,
    1,
  );
  f.changeRepository();
  await assert.rejects(f.coordinator.before(f.input), {
    code: "ERR_AVAILABILITY_RECOVERY",
  });
  assert.equal(
    f.events.filter(({ kind }) => kind === "retry-started").length,
    1,
  );
});

test("availability requires finite evidence and commit-executor non-start proof", async (t) => {
  const f = await fixture(t);
  for (const cause of [
    new Error("offline"),
    unavailable("codex", { availabilityReason: undefined }),
    unavailable("codex", { availabilityReason: "not_allowed" }),
    unavailable("codex", { effect: "started" }),
    unavailable("codex", { outcome: "ambiguous" }),
    unavailable("codex", { retry: "terminal" }),
  ]) {
    await assert.rejects(f.coordinator.schedule({ ...f.input, cause }), {
      code: "ERR_AVAILABILITY_RECOVERY",
    });
  }
  assert.equal(f.coordinator.preEffect(unavailable("codex")), null);
  assert.deepEqual(
    f.coordinator.preEffect(
      unavailable("codex", {
        checkpoint: "commit",
        commitExecutor: "not_started",
      }),
    ),
    { reason: "temporarily_overloaded", commitExecutor: "not_started" },
  );
  assert.equal((await f.store.loadRun(f.run.runId)).availabilityRetry, null);
});

test("stop recovery prepares the certified checkpoint after cancellation supersedes a pause", async (t) => {
  const { run, store, lease } = await fixture(t);
  await store.requestOperatorStop({
    runId: run.runId,
    kind: "pause_requested",
    expectedRevision: run.revision,
    idempotencyKey: "pause-before-recovery",
  });
  let prepared;
  let cancellation;
  const stopped = await reconcileOperatorStop({
    run,
    runStore: store,
    lease,
    runtime: { adapters: {} },
    pipeline: {
      async prepareRecovery(current, history) {
        assert.equal(current, history.run);
        assert.equal(current.stopRequest.requestId, cancellation.requestId);
        prepared = current;
      },
      workflow: {
        async run({ run: current, operatorStop }) {
          assert.equal(operatorStop, true);
          assert.equal(current, prepared);
          return current;
        },
      },
    },
    async publish(activity, current) {
      if (activity.kind !== "reconciling") return;
      cancellation = await store.requestOperatorStop({
        runId: run.runId,
        kind: "cancel_requested",
        expectedRevision: current.revision,
        idempotencyKey: "cancel-during-recovery",
      });
    },
  });
  assert.equal(stopped.pause.reason, "operator_canceled");
  assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
  assert.equal(stopped.stopRequest.checkpoint.revision, run.revision);
});

test("a rejected writable attempt cannot guard a later turn at the same checkpoint", async (t) => {
  const f = await fixture(t);
  const { role } = f.input;
  const phase = "implement";
  const checkpoint = "implement:workspace-write:commit:1";
  const turn = { role, phase };
  const activity = {
    actor: role,
    phase,
    kind: "turn-started",
    message: "Started writable turn.",
  };
  await f.store.startAgentTurn(f.lease, turn, { activity });
  await recordWritableCatalogAttempt(f, role, checkpoint);
  await f.store.finishAgentTurn(f.lease, turn);
  await f.store.startAgentTurn(f.lease, turn, { activity });
  await f.restart();
  const before = await f.store.loadRun(f.run.runId);
  await f.store.requestOperatorStop({
    runId: before.runId,
    kind: "pause_requested",
    expectedRevision: before.revision,
    idempotencyKey: "stop-after-replaced-turn",
  });
  const stopped = await reconcileOperatorStop({
    run: before,
    runStore: f.store,
    lease: f.lease,
    runtime: { adapters: {} },
    pipeline: {
      prepareRecovery() {},
      workflow: {
        async run({ run, interruptedWritableNoEffect }) {
          assert.equal(interruptedWritableNoEffect, false);
          return { ...run, activeTurn: null };
        },
      },
    },
    publish: async () => {},
  });
  assert.equal(stopped.pause.reason, "operator_paused");
});

test("failed attempts record only their own no-effect catalog rejection", async () => {
  const commit = { access: "local-commit", authorizationId: "commit-1" };
  const writable = { access: "workspace-write" };
  const readOnly = { access: "read-only" };
  const miss = normalizeAdapterFailure("codex", modelCatalogMiss(commit));
  async function recorded(cause, request) {
    const batches = [];
    const attempt = {
      id: 3,
      role: "worker",
      checkpoint:
        request.access === "local-commit"
          ? "commit:1"
          : `finalize:${request.access}:finalization`,
    };
    const runStore = {
      startObservationAttempt: async () => ({
        observations: {
          attempts: [
            {
              ...attempt,
              status: "active",
              accounting: "incomplete",
              incomplete: false,
              observations: [],
            },
          ],
        },
      }),
      async recordObservationBatch(_lease, _identity, _records, options) {
        batches.push(options);
        return null;
      },
    };
    await assert.rejects(
      runObservedAttempt({
        runStore,
        lease: {},
        role: attempt.role,
        checkpoint: attempt.checkpoint,
        request,
        operation: async () => {
          throw cause;
        },
      }),
      (failure) => failure === cause,
    );
    const { commitRejection, writableRejection, readOnlyRejection } =
      batches.at(-1);
    return commitRejection ?? writableRejection ?? readOnlyRejection;
  }
  assert.deepEqual(await recorded(miss, commit), { ...miss.failure });
  assert.deepEqual(
    await recorded(
      normalizeAdapterFailure("codex", modelCatalogMiss(writable)),
      writable,
    ),
    writableCatalogFailure,
  );
  assert.deepEqual(
    await recorded(
      normalizeAdapterFailure("codex", modelCatalogMiss()),
      readOnly,
    ),
    writableCatalogFailure,
  );
  for (const [cause, request] of [
    [miss, writable],
    [
      normalizeAdapterFailure(
        "codex",
        modelCatalogMiss({ ...writable, recovery: true }),
      ),
      writable,
    ],
    [
      normalizeAdapterFailure("codex", modelCatalogMiss({ recovery: true })),
      readOnly,
    ],
    [
      normalizeAdapterFailure("codex", modelCatalogMiss()),
      { ...readOnly, session: { mode: "fork" } },
    ],
    [
      unavailable("codex", {
        checkpoint: "commit",
        effect: "none",
        commitExecutor: "not_started",
      }),
      commit,
    ],
    [new Error("Generic provider failure."), commit],
    [new Error("Generic provider failure."), writable],
  ])
    assert.equal(await recorded(cause, request), undefined);
});

test("reduced COMMIT stop evidence preserves terminal selection diagnostics without granting catalog retry proof", async () => {
  const monitor = createStopMonitor({
    runId: "run",
    lease: {},
    runStore: {
      async loadRun() {
        return { revision: 1, stopRequest: null };
      },
      waitForRunChange(_runId, { signal }) {
        return new Promise((resolve) => {
          signal.addEventListener("abort", resolve, { once: true });
        });
      },
    },
  });
  const request = { access: "local-commit", authorizationId: "commit-1" };
  async function reject(cause, attempt = request) {
    const error = normalizeAdapterFailure("codex", cause);
    await assert.rejects(
      monitor.invoke(async () => {
        throw error;
      }, attempt),
      (failure) => failure === error,
    );
  }
  try {
    await reject(
      unavailable("codex", {
        checkpoint: "commit",
        effect: "none",
        commitExecutor: "not_started",
      }),
    );
    assert.notEqual(monitor.preEffectRejection, null);
    await reject(modelCatalogMiss(request), {
      ...request,
      authorizationId: "commit-2",
    });
    assert.equal(monitor.preEffectRejection, null);

    for (const [code, diagnosticClass] of [
      ["ERR_CODEX_PROTOCOL", "model_catalog_invalid"],
      ["ERR_UNSUPPORTED_EFFORT", "effort_unsupported"],
    ]) {
      await reject(
        new CodexAdapterError("Model selection failed.", {
          code,
          diagnosticClass,
          effectStarted: false,
        }),
      );
      assert.deepEqual(monitor.preEffectRejection, {
        authorizationId: "commit-1",
        rejection: { code, diagnosticClass, recoverable: false },
      });
    }
  } finally {
    await monitor.close();
  }
});

test("both immediate and deferred operator stops interrupt an availability deadline", async () => {
  for (const effectiveTiming of ["immediate", "after-current-commit"]) {
    const changed = Promise.withResolvers();
    const entered = Promise.withResolvers();
    let current = { revision: 1, stopRequest: null };
    const monitor = createStopMonitor({
      runId: "run",
      lease: {},
      publish: async () => {},
      runStore: {
        async loadRun() {
          return current;
        },
        async waitForRunChange() {
          return changed.promise;
        },
        async recordStopActivity() {
          return current;
        },
      },
    });
    const waiting = monitor.wait(
      (signal) =>
        new Promise((resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
          entered.resolve();
        }),
    );
    await entered.promise;
    current = {
      revision: 2,
      stopRequest: { effectiveTiming, reconciledRevision: null },
    };
    changed.resolve(current);
    await assert.rejects(waiting, { code: "ERR_OPERATOR_STOP_BEFORE_COMMIT" });
    await monitor.close();
  }
});

test("operator stops serialize with adapter resource persistence and cleanup", async () => {
  const changed = Promise.withResolvers();
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const aborted = Promise.withResolvers();
  const events = [];
  let current = { revision: 1, stopRequest: null };
  const monitor = createStopMonitor({
    runId: "run",
    lease: {},
    publish: async () => {},
    runStore: {
      async loadRun() {
        return current;
      },
      async waitForRunChange() {
        return changed.promise;
      },
      async recordStopActivity() {
        events.push("stop");
        return current;
      },
    },
  });
  const execution = monitor.invoke(
    async ({ onResource, signal }) => {
      signal.addEventListener("abort", () => aborted.resolve(), { once: true });
      await onResource({ phase: "allocating" });
      // Cleanup must persist even though the stop has canceled the turn.
      await onResource(null);
    },
    {
      async onResource(value) {
        if (value !== null) {
          entered.resolve();
          await release.promise;
        }
        events.push(value === null ? "cleaned" : "allocated");
      },
    },
  );
  await entered.promise;
  current = {
    revision: 2,
    stopRequest: { effectiveTiming: "immediate", reconciledRevision: null },
  };
  changed.resolve(current);
  await aborted.promise;
  release.resolve();
  await execution;
  await monitor.close();
  assert.deepEqual(events, ["allocated", "stop", "cleaned"]);
});

test("the runner records provider progress before rejecting a malformed response", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "availability-response-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const projectPath = join(root, "project"),
    taskPath = join(root, "task");
  await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
  await writeFile(join(taskPath, "task.md"), "Plan a change.\n");
  let now = Date.parse("2026-09-29T10:00:00.000Z");
  const store = createRunStore({
    stateRoot: join(root, "state"),
    clock: () => new Date(now),
  });
  const events = [];
  let runId,
    calls = 0;
  let reconciledAfterResponse = false;
  const snapshot = ({ allowedPaths }) => ({
    schemaVersion: 1,
    projectPath,
    allowedPaths,
    contentFingerprint: fingerprint,
  });
  const runner = createRunner({
    runStore: store,
    availabilityClock: () => now,
    availabilityWait: async (ms) => {
      now += ms;
    },
    loadConfiguration: async () =>
      parseRunnerConfiguration(
        JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
      ),
    onActivity: async (event) => {
      runId = event.runId;
      events.push(event);
    },
    git: {
      async assertUnchanged() {
        if (calls === 2 && !events.some(({ kind }) => kind === "recovered")) {
          assert.equal(
            (await store.loadRun(runId)).availabilityRetry.attempt,
            1,
          );
          reconciledAfterResponse = true;
        }
      },
      async inspectPath({ path }) {
        return { path, exists: false };
      },
      async snapshot(input) {
        return snapshot(input);
      },
      async preflight(input) {
        return { snapshot: snapshot(input) };
      },
    },
    adapters: {
      codex: {
        async probe() {
          return capabilities();
        },
        async run() {
          if (++calls === 1) throw unavailable("codex");
          assert.equal(
            (await store.loadRun(runId)).availabilityRetry.attempt,
            1,
          );
          return { structured: null };
        },
      },
    },
  });
  await assert.rejects(
    runner.run({
      pipelineId: "plan-authoring",
      projectPath,
      taskPath,
      settingOverrides: { mode: "lazy" },
    }),
    { code: "ERR_INVALID_PLAN_AUTHORING_OUTPUT" },
  );
  assert.equal(reconciledAfterResponse, true);
  assert.equal((await store.loadRun(runId)).availabilityRetry, null);
  assert.deepEqual(
    events
      .filter(({ phase }) => phase === "availability")
      .map(({ kind }) => kind),
    ["retry-scheduled", "retry-started", "recovered"],
  );
});

for (const disposition of ["authentication_required", "output_exhausted"]) {
  test(`the runner retires availability when ${disposition} takes over`, async (t) => {
    const root = await mkdtemp(join(tmpdir(), "availability-authentication-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const projectPath = join(root, "project"),
      taskPath = join(root, "task");
    await Promise.all([mkdir(projectPath), mkdir(taskPath)]);
    await writeFile(join(taskPath, "task.md"), "Plan a change.\n");
    let now = Date.parse("2026-09-29T10:00:00.000Z");
    const store = createRunStore({
      stateRoot: join(root, "state"),
      clock: () => new Date(now),
    });
    const events = [];
    let calls = 0;
    const snapshot = ({ allowedPaths }) => ({
      schemaVersion: 1,
      projectPath,
      allowedPaths,
      contentFingerprint: fingerprint,
    });
    const runner = createRunner({
      runStore: store,
      availabilityClock: () => now,
      availabilityWait: async (ms) => {
        now += ms;
      },
      loadConfiguration: async () =>
        parseRunnerConfiguration(
          JSON.stringify({ schemaVersion: 1, defaultBackend: "codex" }),
        ),
      onActivity: async (event) => events.push(event),
      git: {
        async assertUnchanged() {},
        async inspectPath({ path }) {
          return { path, exists: false };
        },
        async snapshot(input) {
          return snapshot(input);
        },
        async preflight(input) {
          return { snapshot: snapshot(input) };
        },
      },
      adapters: {
        codex: {
          async probe() {
            return capabilities();
          },
          async run() {
            throw ++calls === 1
              ? unavailable("codex")
              : disposition === "output_exhausted"
                ? outputExhaustion()
                : authenticationRequired();
          },
        },
      },
    });

    const paused = await runner.run({
      pipelineId: "plan-authoring",
      projectPath,
      taskPath,
      settingOverrides: { mode: "lazy" },
    });

    assert.equal(paused.run.pause.reason, disposition);
    assert.equal(paused.run.availabilityRetry, null);
    assert.equal(calls, 2);
    assert.deepEqual(
      events
        .filter(({ phase }) => phase === "availability")
        .map(({ kind }) => kind),
      ["retry-scheduled", "retry-started", "recovered"],
    );
  });
}
