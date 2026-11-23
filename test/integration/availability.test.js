import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  planExecutionPipeline,
  runPlanExecution,
} from "@agent-runner/plan-execution";
import { polishingPipeline, runPolishing } from "@agent-runner/polishing";

import {
  CodexAdapterError,
  normalizeAdapterFailure,
  PROVIDER_REGISTRY,
} from "../../src/agents/index.js";
import {
  createMcpControlPlane,
  createRunStore,
  main,
} from "../../src/index.js";
import { createModelCatalogRecovery } from "../../src/runner/model-catalog.js";
import { createAvailabilityCoordinator } from "../../src/runner/availability.js";
import {
  reconcileOperatorStop,
  restoreOperatorPause,
} from "../../src/runner/stops.js";
import { nextCatalogResume } from "../../src/state/model-completion.js";
import {
  attachAuthentication,
  authenticationFailure,
} from "../support/authentication.js";
import { attachInactivity } from "../support/inactivity.js";
import {
  modelCatalogMiss,
  recordCompletedModelTurn,
  recordReadOnlyCatalogMiss,
} from "../support/model-catalog.js";
import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../support/output-exhaustion.js";

import * as execution from "../../pipelines/plan-execution/test/support/index.js";
import * as polishing from "../../pipelines/polishing/test/support/index.js";
import {
  attachAvailability,
  availabilityFailure,
} from "../support/availability.js";

test("catalog-paused initial implementation retries the same reservation", async (t) => {
  const miss = modelCatalogMiss();
  let attempts = 0;
  const fixture = await execution.createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Implement the changes") &&
        ++attempts === 1
      )
        throw miss;
    },
  });
  const code = "ERR_MODEL_CATALOG_RETRY";
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: ({ phase }) => phase === "implement",
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pipelineState.writableResult.stage, "prepared");
  assert.equal(paused.activeTurn, null);
  assert.equal(
    fixture.transitions.find(({ patch }) => patch?.pause?.code === code)
      ?.options.activity.kind,
    "catalog-no-effect-verified",
  );
  const done = await fixture.run();
  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(done.counters.fixRounds, 0);
  assert.equal(attempts, 2);
});

test("a catalog miss alongside a newly journaled expiry retains read-only recovery", async (t) => {
  const miss = modelCatalogMiss();
  let writes = 0;
  const fixture = await execution.createFixture(t, {
    async onRoleRun(role, request) {
      if (role !== "worker") return;
      if (request.prompt.includes("Implement the changes")) {
        assert.equal(request.access, "workspace-write");
        writes++;
        await assert.rejects(inactivity.expire(request), {
          code: "ERR_PROVIDER_INACTIVE",
        });
        throw miss;
      }
    },
  });
  const inactivity = await attachInactivity(fixture);
  const code = "ERR_MODEL_CATALOG_RETRY";
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: ({ phase }) => phase === "implement",
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };
  const paused = await fixture.run();
  assert.equal(paused.pause.checkpoint, "writable-result:read-only:commit:1");
  assert.equal(paused.pipelineState.writableResult.stage, "ready");
  assert.equal(paused.inactivityRecovery.status, "expired");
  assert.equal(paused.counters.fixRounds, 0);
  assert.equal(paused.activeTurn, null);
  assert.equal(writes, 1);
});

test("a lost environment resume acknowledgement preserves the bound catalog review", async (t) => {
  for (const support of [execution, polishing]) {
    const miss = modelCatalogMiss();
    const code = "ERR_MODEL_CATALOG_RETRY";
    let reviewCalls = 0;
    const fixture = await support.createFixture(t, {
      onRoleRun(role, request) {
        if (
          role === "reviewer" &&
          fixture.currentRun.pipelineState.workflowState === "REVIEW"
        ) {
          assert.equal(request.access, "read-only");
          if (++reviewCalls === 1) throw miss;
        }
      },
    });
    fixture.runtime.catalogRetry = {
      code,
      eligible: (cause) => cause === miss,
      hasWritableNoEffect: () => false,
      hasPossibleEffect: () => false,
      details: (role, checkpoint) => ({ code, role, checkpoint }),
      resuming: () => false,
      claimResume(role, checkpoint) {
        const binding = fixture.currentRun.modelCatalogResume;
        if (binding == null) return false;
        assert.equal(role, binding.role);
        assert.equal(checkpoint, binding.checkpoint);
        return true;
      },
    };
    const paused = await fixture.run();
    assert.equal(paused.pause.code, code);
    const { role, checkpoint, resumeState } = paused.pause;
    const binding = { role, checkpoint, resumeState };
    // The common journal retains the accepted binding through this pause.
    const { transition, startAgentTurn } = fixture.runtime;
    await transition({
      modelCatalogResume: binding,
      pause: { reason: "environment_blocked", resumeState },
    });
    const loss = new Error("Environment resume acknowledgement lost.");
    fixture.runtime.transition = async (patch, options) => {
      const next = await transition(patch, options);
      if (patch.pause === null) {
        fixture.runtime.transition = transition;
        throw loss;
      }
      return next;
    };
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    assert.equal(reviewCalls, 1);
    assert.equal(fixture.currentRun.activeTurn, null);
    assert.equal(fixture.currentRun.pause, null);
    assert.deepEqual(fixture.currentRun.modelCatalogResume, binding);

    fixture.runtime.startAgentTurn = async (turn, options) => {
      if (fixture.currentRun.modelCatalogResume != null) {
        assert.equal(turn.role, role);
        assert.equal(options.catalogCheckpoint, checkpoint);
        await transition({ modelCatalogResume: null });
      }
      return startAgentTurn(turn, options);
    };
    const done = await fixture.run();
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.equal(done.modelCatalogResume, null);
    assert.equal(reviewCalls, 2);
    assert.equal(done.counters.fixRounds, paused.counters.fixRounds);
  }
});

test("validation-migration arbitration resumes its correction after a catalog miss", async (t) => {
  const miss = modelCatalogMiss();
  const disagreement = execution.reconciliationDisagreement();
  const code = "ERR_MODEL_CATALOG_RETRY";
  const checkpoint = "validation-migration:read-only:validation-migration";
  let reconciliationCalls = 0;
  let arbitrationCalls = 0;
  const fixture = await execution.prepareValidationMigration(t, {
    workWorker: [
      execution.implementationCompleted(),
      execution.finalizationPassed(),
      execution.bootstrapReady("Migrating Worker"),
      disagreement,
      execution.finalizationPassed(),
    ],
    workReviewer: [
      execution.bootstrapReady("Migrating Reviewer"),
      execution.reviewApproved(),
    ],
    arbiter: [
      execution.arbitrationProductDecision(),
      execution.arbitrationResolved(),
    ],
    onRoleRun(role, request) {
      if (
        request.prompt.includes("Reconcile the independently re-established")
      ) {
        assert.equal(role, "worker");
        reconciliationCalls++;
      }
      if (role === "arbiter") {
        assert.equal(request.access, "read-only");
        if (++arbitrationCalls === 2) throw miss;
      }
    },
  });
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: () => false,
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, code);
  assert.equal(paused.pause.role, "arbiter");
  assert.equal(paused.pause.checkpoint, checkpoint);
  assert.equal(paused.activeTurn, null);
  assert.equal(paused.pipelineState.pendingBootstrapCorrection.attempt, 1);
  assert.deepEqual(paused.pipelineState.validationMigrationDisagreement, {
    description: disagreement.disagreement,
    evidence: disagreement.evidence,
  });

  const { validationMigrationDisagreement: _disagreement, ...legacyState } =
    paused.pipelineState;
  const legacy = {
    ...paused,
    pipelineStateVersion: 45,
    pipelineState: legacyState,
  };
  const migrated = {
    ...legacy,
    pipelineStateVersion: planExecutionPipeline.stateVersion,
    pipelineState: planExecutionPipeline.migrations[45](legacy),
  };
  assert.equal(migrated.pipelineState.validationMigrationDisagreement, null);
  assert.deepEqual(
    planExecutionPipeline.projections.pause(legacy).nextActions,
    [],
  );
  assert.deepEqual(
    planExecutionPipeline.projections.pause(migrated).nextActions,
    [],
  );
  assert.throws(() =>
    planExecutionPipeline.validateResumeAction(migrated, null),
  );

  const reloaded = JSON.parse(JSON.stringify(paused));
  fixture.persistPipelineState(reloaded.pipelineState, {
    pause: reloaded.pause,
  });
  fixture.runtime.catalogRetry = createModelCatalogRecovery({
    run: reloaded,
    providers: PROVIDER_REGISTRY,
  });
  const done = await fixture.run();

  assert.equal(done.pipelineState.workflowState, "DONE");
  assert.equal(reconciliationCalls, 1);
  assert.equal(arbitrationCalls, 3);
  const [, correction, retry] = fixture.calls.arbiter;
  assert.equal(retry.prompt, correction.prompt);
  assert.ok(retry.prompt.includes(disagreement.disagreement));
  assert.ok(retry.prompt.includes("validation-migration-direction"));
  assert.deepEqual(
    done.pipelineState.bootstrapCorrections,
    paused.pipelineState.bootstrapCorrections,
  );
  assert.equal(done.pipelineState.pendingBootstrapCorrection, null);
  assert.equal(done.pipelineState.validationMigrationDisagreement, null);
  assert.equal(done.counters.fixRounds, paused.counters.fixRounds);
});

test("polishing retains validation-migration arbitration after resume acknowledgement loss", async (t) => {
  const miss = modelCatalogMiss();
  const code = "ERR_MODEL_CATALOG_RETRY";
  const checkpoint = "finalize:read-only:validation-migration";
  let arbitrationCalls = 0;
  const fixture = await polishing.createFixture(t, {
    worker: [
      polishing.clarificationReady(),
      polishing.bootstrapReady("Worker"),
      polishing.reconciliationResolved(),
      polishing.polishingCompleted(),
      polishing.finalizationBlocked(
        "Unavailable.",
        "Service refused connection.",
      ),
      polishing.bootstrapReady("Migrating Worker"),
      polishing.reconciliationDisagreement(),
    ],
    reviewer: [
      polishing.bootstrapReady("Reviewer"),
      polishing.candidateApproved(),
      polishing.bootstrapReady("Migrating Reviewer"),
    ],
    arbiter: [{}, polishing.arbitrationResolved()],
    onRoleRun(role, request) {
      if (role !== "arbiter") return;
      assert.equal(request.access, "read-only");
      if (++arbitrationCalls === 2) throw miss;
    },
  });
  const initialPause = await fixture.run();
  const finalizing = fixture.transitions.findLast(
    ({ patch }) => patch.pipelineState?.workflowState === "FINALIZE",
  ).patch.pipelineState;
  await fixture.persistPipelineState(
    {
      ...finalizing,
      validationMigrationPending: true,
      workerValidation: null,
      reviewerValidation: null,
    },
    initialPause.counters,
    null,
  );
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: () => false,
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };
  const paused = await fixture.run();
  assert.equal(paused.pause.code, code);
  assert.equal(paused.pause.checkpoint, checkpoint);
  assert.equal(paused.pipelineState.pendingBootstrapCorrection.attempt, 1);

  const loss = new Error("Resume acknowledgement lost.");
  const transition = fixture.runtime.transition;
  fixture.runtime.transition = async (patch, options) => {
    assert.equal(patch.pause, null);
    const next = { ...paused, ...patch };
    assert.equal(next.pipelineState.workflowState, "FINALIZE");
    await transition(
      { ...patch, modelCatalogResume: nextCatalogResume(paused, next) },
      options,
    );
    throw loss;
  };
  await assert.rejects(fixture.run(), (cause) => cause === loss);
  const recovered = await fixture.recover();
  assert.deepEqual(recovered.modelCatalogResume, {
    role: "arbiter",
    checkpoint,
    resumeState: "FINALIZE",
  });
  assert.equal(recovered.activeTurn, null);
  assert.equal(arbitrationCalls, 2);
  assert.deepEqual(
    recovered.pipelineState.validationMigrationDisagreement,
    paused.pipelineState.validationMigrationDisagreement,
  );
  assert.deepEqual(
    recovered.pipelineState.pendingBootstrapCorrection,
    paused.pipelineState.pendingBootstrapCorrection,
  );
  fixture.runtime.catalogRetry = createModelCatalogRecovery({
    run: recovered,
    providers: PROVIDER_REGISTRY,
  });
  const stopAtDispatch = new Error("Arbiter retry reached dispatch.");
  fixture.runtime.startAgentTurn = async (turn, options) => {
    assert.deepEqual(turn, { role: "arbiter", phase: "finalize" });
    assert.equal(options.catalogCheckpoint, checkpoint);
    throw stopAtDispatch;
  };
  await assert.rejects(fixture.run(), (cause) => cause === stopAtDispatch);
});

for (const [support, pipeline] of [
  [execution, "plan execution"],
  [polishing, "polishing"],
]) {
  for (const [review, when] of [
    ["initial review", "before resume"],
    ["initial review", "before dispatch"],
    ["initial review", "during dispatch"],
    ["initial review", "after owner loss"],
    ["review correction", "before resume"],
    ["review correction", "during dispatch"],
  ]) {
    test(`${pipeline} rejects drift ${when} on catalog retry of ${review}`, async (t) => {
      const miss = modelCatalogMiss();
      const code = "ERR_MODEL_CATALOG_RETRY";
      const missAt = review === "initial review" ? 1 : 2;
      let reviewCalls = 0;
      const changedInfrastructure = () => "c".repeat(64);
      const fixture = await support.createFixture(t, {
        ...(missAt === 1
          ? {}
          : support === execution
            ? {
                workReviewer: [
                  { ...execution.reviewApproved(), status: "FINDINGS" },
                  execution.reviewApproved(),
                ],
              }
            : {
                reviewer: [
                  polishing.bootstrapReady("Reviewer"),
                  { ...polishing.candidateApproved(), status: "FINDINGS" },
                  polishing.candidateApproved(),
                ],
              }),
        onRoleRun(role, request) {
          if (
            role !== "reviewer" ||
            fixture.currentRun.pipelineState.workflowState !== "REVIEW"
          )
            return;
          assert.equal(request.access, "read-only");
          if (++reviewCalls === missAt) throw miss;
          if (reviewCalls !== missAt + 1) return;
          if (when === "after owner loss")
            throw Object.assign(new Error("Review owner lost."), {
              code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
            });
          if (when === "during dispatch") {
            assert.equal(
              fixture.runtime.catalogRetry.resuming(role, checkpoint),
              false,
            );
            fixture.runtime.git.validationInfrastructureFingerprint =
              changedInfrastructure;
          }
        },
      });
      fixture.runtime.catalogRetry = {
        code,
        eligible: (cause) => cause === miss,
        hasWritableNoEffect: () => false,
        hasPossibleEffect: () => false,
        details: (role, checkpoint) => ({ code, role, checkpoint }),
        resuming: () => false,
        claimResume: () => false,
      };

      const paused = await fixture.run();
      const checkpoint = `review:read-only:${
        missAt === 2
          ? `candidate-review-correction${support === execution ? ":1" : ""}`
          : support === execution
            ? "commit:1"
            : "review"
      }`;
      if (missAt === 1)
        assert.equal(paused.pipelineState.pendingReviewCorrection, null);
      assert.equal(paused.pause.checkpoint, checkpoint);
      const reloaded = JSON.parse(JSON.stringify(paused));
      if (support === polishing)
        await fixture.persistPipelineState(
          reloaded.pipelineState,
          reloaded.counters,
          reloaded.pause,
        );
      else
        fixture.persistPipelineState(reloaded.pipelineState, {
          pause: reloaded.pause,
        });
      fixture.runtime.catalogRetry = createModelCatalogRecovery({
        run: reloaded,
        providers: PROVIDER_REGISTRY,
      });
      if (when === "after owner loss") {
        await assert.rejects(fixture.run(), {
          code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        });
        const interrupted = JSON.parse(JSON.stringify(fixture.currentRun));
        assert.deepEqual(interrupted.activeTurn, {
          role: "reviewer",
          phase: "review",
        });
        fixture.runtime.catalogRetry = createModelCatalogRecovery({
          run: interrupted,
          providers: PROVIDER_REGISTRY,
        });
      }
      if (when === "before dispatch") {
        const startAgentTurn = fixture.runtime.startAgentTurn;
        fixture.runtime.startAgentTurn = async (turn, options) => {
          const started = await startAgentTurn(turn, options);
          if (options.catalogCheckpoint === checkpoint)
            fixture.runtime.git.validationInfrastructureFingerprint =
              changedInfrastructure;
          return started;
        };
      } else if (when !== "during dispatch") {
        fixture.runtime.git.validationInfrastructureFingerprint =
          changedInfrastructure;
      }

      const drifted = await fixture.run();
      assert.equal(drifted.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(drifted.pause.reason, "unsafe_git_state");
      assert.equal(
        drifted.pause.code,
        "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
      );
      for (const field of [
        "repositoryBaseline",
        "catalogReviewInfrastructureFingerprint",
        "reviewCorrection",
        "pendingReviewCorrection",
        "candidateReviewResult",
      ]) {
        assert.deepEqual(
          drifted.pipelineState[field],
          paused.pipelineState[field],
        );
      }
      assert.deepEqual(drifted.counters, paused.counters);
      assert.equal(drifted.activeTurn, null);
      assert.equal(
        reviewCalls,
        ["during dispatch", "after owner loss"].includes(when)
          ? missAt + 1
          : missAt,
      );
    });
  }
}

for (const [support, workflow, pipelineId] of [
  [execution, runPlanExecution, "plan-execution"],
  [polishing, runPolishing, "polishing"],
]) {
  for (const when of [
    "before resume",
    "before dispatch",
    "during dispatch",
    "after settlement",
  ]) {
    const settled = when === "after settlement";
    test(`${pipelineId} ${settled ? "allows" : "rejects"} ignored infrastructure drift ${when} on catalog retry of initial CLEAN_CONFIRM`, async (t) => {
      const miss = modelCatalogMiss();
      const stopAtReview = Object.assign(
        new Error("Stop at candidate review dispatch."),
        {
          code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
        },
      );
      const infrastructure = "LOCAL_ARTIFACTS/validation.json";
      const withInfrastructure = (output) => ({
        ...output,
        validationInfrastructure: [
          ...output.validationInfrastructure,
          infrastructure,
        ],
      });
      let confirmations = 0;
      const fixture = await support.createFixture(t, {
        mode: "combined",
        async prepareProject(projectPath) {
          await mkdir(join(projectPath, "LOCAL_ARTIFACTS"), {
            recursive: true,
          });
          await writeFile(join(projectPath, infrastructure), "{}\n");
        },
        worker: [
          support.clarificationReady(),
          withInfrastructure(support.bootstrapReady("Worker")),
          support.reconciliationResolved(),
          ...(support === polishing
            ? [
                polishing.polishingCompleted(),
                polishing.checkAndFix(),
                polishing.candidateClean(),
              ]
            : []),
        ],
        reviewer: [withInfrastructure(support.bootstrapReady("Reviewer"))],
        workWorker: [
          execution.implementationCompleted(),
          execution.checkAndFix(),
        ],
        async onRoleRun(role, request) {
          const { phase } = fixture.currentRun.activeTurn;
          if (phase === "review" && settled) throw stopAtReview;
          assert.notEqual(
            phase,
            "review",
            "Drift must halt before candidate review.",
          );
          if (phase !== "clean-confirm") return;
          assert.equal(role, "worker");
          assert.equal(request.access, "read-only");
          if (++confirmations === 1) throw miss;
          if (when === "during dispatch") await changeInfrastructure();
        },
      });
      const changeInfrastructure = () =>
        writeFile(
          join(fixture.projectPath, infrastructure),
          '{"changed":true}\n',
        );
      const code = "ERR_MODEL_CATALOG_RETRY";
      fixture.runtime.catalogRetry = {
        code,
        eligible: (cause) => cause === miss,
        hasWritableNoEffect: () => false,
        hasPossibleEffect: () => false,
        details: (role, checkpoint) => ({ code, role, checkpoint }),
        resuming: () => false,
        claimResume: () => false,
      };
      const paused = await fixture.run();
      assert.equal(paused.pause.code, code);
      assert.equal(paused.pause.resumeState, "CLEAN_CONFIRM");
      assert.equal(paused.pipelineState.pendingLazyCorrection, null);
      assert.match(
        paused.pipelineState.catalogReviewInfrastructureFingerprint,
        /^[a-f0-9]{64}$/u,
      );
      const reloaded = JSON.parse(JSON.stringify(paused));
      fixture.runtime.catalogRetry = createModelCatalogRecovery({
        run: reloaded,
        providers: PROVIDER_REGISTRY,
      });
      if (when === "before resume") await changeInfrastructure();
      if (when === "before dispatch") {
        const startAgentTurn = fixture.runtime.startAgentTurn;
        fixture.runtime.startAgentTurn = async (turn, options) => {
          const started = await startAgentTurn(turn, options);
          if (options.catalogCheckpoint === paused.pause.checkpoint)
            await changeInfrastructure();
          return started;
        };
      }
      if (settled) {
        const transition = fixture.runtime.transition;
        fixture.runtime.transition = async (patch, options) => {
          const next = await transition(patch, options);
          if (
            options?.activity?.phase === "clean-confirm" &&
            options.activity.kind === "clean"
          )
            await changeInfrastructure();
          return next;
        };
      }

      const resumed = workflow({
        run: reloaded,
        runtime: fixture.runtime,
        settings: reloaded.pipelineState.settings,
      });
      if (settled) {
        await assert.rejects(resumed, stopAtReview);
        assert.equal(confirmations, 2);
        assert.equal(
          fixture.currentRun.pipelineState
            .catalogReviewInfrastructureFingerprint,
          undefined,
        );
        await fixture.runtime.git.assertUnchanged(
          paused.pipelineState.repositoryBaseline,
        );
        return;
      }
      const drifted = await resumed;
      assert.equal(drifted.pause.reason, "unsafe_git_state");
      assert.equal(
        drifted.pause.code,
        "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
      );
      assert.equal(
        drifted.pipelineState.candidateConfirmationFingerprint,
        null,
      );
      assert.deepEqual(
        drifted.pipelineState.repositoryBaseline,
        paused.pipelineState.repositoryBaseline,
      );
      assert.deepEqual(drifted.counters, paused.counters);
      assert.equal(drifted.activeTurn, null);
      assert.equal(confirmations, when === "during dispatch" ? 2 : 1);
      await fixture.runtime.git.assertUnchanged(
        paused.pipelineState.repositoryBaseline,
      );
    });
  }

  test(`${pipelineId} pauses a cold catalog confirmation retry on ignored infrastructure drift`, async (t) => {
    const miss = modelCatalogMiss();
    const infrastructure = "LOCAL_ARTIFACTS/validation.json";
    const withInfrastructure = (output) => ({
      ...output,
      validationInfrastructure: [
        ...output.validationInfrastructure,
        infrastructure,
      ],
    });
    const fixture = await support.createFixture(t, {
      async prepareProject(projectPath) {
        await mkdir(join(projectPath, "LOCAL_ARTIFACTS"), { recursive: true });
        await writeFile(join(projectPath, infrastructure), "{}\n");
      },
      worker: [
        support.clarificationReady(),
        withInfrastructure(support.bootstrapReady("Worker")),
        support.reconciliationResolved(),
        ...(support === polishing
          ? [
              polishing.polishingCompleted(),
              withInfrastructure(polishing.finalizationPassed()),
            ]
          : []),
      ],
      reviewer: [
        withInfrastructure(support.bootstrapReady("Reviewer")),
        ...(support === polishing ? [polishing.candidateApproved()] : []),
      ],
      workWorker: [
        execution.implementationCompleted(),
        withInfrastructure(execution.finalizationPassed()),
      ],
      onRoleRun(role) {
        if (
          role === "reviewer" &&
          fixture.currentRun.pipelineState.workflowState === "CONFIRM"
        )
          throw miss;
      },
    });
    const code = "ERR_MODEL_CATALOG_RETRY";
    fixture.runtime.catalogRetry = {
      code,
      eligible: (cause) => cause === miss,
      hasPossibleEffect: () => false,
      details: (role, checkpoint) => ({ code, role, checkpoint }),
      resuming: () => false,
      claimResume: () => false,
    };
    const paused = await fixture.run();
    assert.equal(paused.pause.code, code);
    assert.equal(paused.pause.resumeState, "CONFIRM");
    const { role, checkpoint, resumeState } = paused.pause;
    const runId = randomUUID();
    const clarificationDirectory = join(
      paused.pipelineState.clarificationRoot,
      paused.pipelineState.artifactRoot,
      "agent-runner",
      runId,
    );
    const clarificationPath = join(clarificationDirectory, "clarifications.md");
    if (support === execution) {
      fixture.runtime.clarifications.writeTranscript(
        clarificationPath,
        fixture.readClarification(),
      );
    } else {
      await mkdir(clarificationDirectory, { recursive: true });
      await copyFile(paused.pipelineState.clarificationPath, clarificationPath);
    }
    const baseline = await fixture.runtime.git.snapshot({
      projectPath: paused.projectPath,
      allowedPaths: [clarificationPath],
    });
    const pipelineState = {
      ...paused.pipelineState,
      repositoryBaseline: baseline,
      clarificationPath,
      workflowState: resumeState,
    };
    const stateRoot = await mkdtemp(join(tmpdir(), "confirmation-retry-"));
    t.after(() => rm(stateRoot, { recursive: true, force: true }));
    const store = createRunStore({ stateRoot });
    const { lease } = await store.createRun({
      runId,
      pipelineId,
      pipelineStateVersion: paused.pipelineStateVersion,
      projectPath: paused.projectPath,
      taskPath: paused.taskPath,
      roles: {
        ...paused.roles,
        [role]: { backend: "codex", model: "test-model" },
      },
      hashes: paused.hashes,
      counters: paused.counters,
      pipelineState,
    });
    try {
      const phase = checkpoint.split(":")[0];
      const activity = {
        actor: role,
        phase,
        kind: "turn-started",
        message: "Started terminal review.",
      };
      await store.startAgentTurn(lease, { role, phase }, { activity });
      await recordCompletedModelTurn(
        store,
        lease,
        { role, phase },
        { model: "test-model" },
      );
      await recordReadOnlyCatalogMiss(
        store,
        lease,
        { role, phase },
        { activity, checkpoint },
      );
      await store.transitionRun(lease, {
        activeTurn: null,
        pause: paused.pause,
        pipelineState: { ...pipelineState, workflowState: "WAITING_FOR_USER" },
      });
      await store.transitionRun(lease, { pause: null, pipelineState });
    } finally {
      await lease.release();
    }

    await writeFile(
      join(fixture.projectPath, infrastructure),
      '{"changed":true}\n',
    );
    await fixture.runtime.git.assertUnchanged(baseline);
    const reopened = createRunStore({ stateRoot });
    const resumedLease = await reopened.acquireRunLease(runId);
    try {
      const recovered = await reopened.recoverRun(resumedLease);
      assert.deepEqual(recovered.modelCatalogResume, {
        role,
        checkpoint,
        resumeState,
      });
      await assert.rejects(
        reopened.transitionRun(resumedLease, {
          pipelineState: {
            ...recovered.pipelineState,
            workflowState: "FINALIZE",
          },
        }),
        { code: "ERR_MODEL_CATALOG_CHECKPOINT_CHANGED" },
      );
      const runtime = {
        ...fixture.runtime,
        catalogRetry: createModelCatalogRecovery({
          run: recovered,
          providers: PROVIDER_REGISTRY,
        }),
        transition: (patch, options) =>
          reopened.transitionRun(resumedLease, patch, options),
        startAgentTurn: () =>
          assert.fail("Scope drift must halt before dispatch."),
      };
      const drifted = await workflow({ run: recovered, runtime });
      assert.equal(drifted.pause.reason, "unsafe_git_state");
      assert.equal(
        drifted.pause.code,
        "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
      );
      assert.equal(drifted.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(drifted.pipelineState.finalizationResult, null);
      assert.deepEqual(
        drifted.pipelineState.candidateReviewResult,
        recovered.pipelineState.candidateReviewResult,
      );
      assert.equal(drifted.modelCatalogResume, null);
      assert.equal(drifted.activeTurn, null);
      assert.deepEqual(drifted.counters, recovered.counters);
      assert.deepEqual(await reopened.loadRun(runId), drifted);
    } finally {
      await resumedLease.release();
    }
  });
}

test("a first-use no-effect catalog miss preserves the baseline and reservation on drift", async (t) => {
  for (const support of [execution, polishing]) {
    const implementing = support === execution;
    const miss = modelCatalogMiss();
    let before;
    const fixture = await support.createFixture(t, {
      ...(implementing
        ? {}
        : {
            reviewer: [
              polishing.bootstrapReady("Reviewer"),
              polishing.reviewFindings("R1"),
            ],
          }),
      async onRoleRun(role, request) {
        if (
          role !== "worker" ||
          request.access !== "workspace-write" ||
          fixture.currentRun.activeTurn.phase !==
            (implementing ? "implement" : "resolve-findings")
        )
          return;
        before = fixture.currentRun;
        await writeFile(join(request.cwd, "concurrent.txt"), "foreign bytes\n");
        throw miss;
      },
    });
    fixture.runtime.catalogRetry = {
      code: "ERR_MODEL_CATALOG_RETRY",
      eligible: () => false,
      hasWritableNoEffect: (turn) => turn.phase === before?.activeTurn.phase,
      hasPossibleEffect: () => false,
      resuming: () => false,
      claimResume: () => false,
    };
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "unsafe_git_state");
    assert.equal(paused.activeTurn, null);
    const field = implementing ? "writableResult" : "resolutionCorrection";
    for (const key of [field, "repositoryBaseline", "candidateReviewResult"]) {
      assert.deepEqual(paused.pipelineState[key], before.pipelineState[key]);
    }
    assert.equal(paused.counters.fixRounds, before.counters.fixRounds);
    assert.equal((await fixture.run()).revision, paused.revision);
    const stop = implementing ? runPlanExecution : runPolishing;
    const stopped = await stop({
      run: fixture.currentRun,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.deepEqual(stopped.pause, paused.pause);
    assert.deepEqual(stopped.pipelineState, paused.pipelineState);
    assert.deepEqual(stopped.counters, paused.counters);
  }
});

for (const [pipeline, support, phase, checkpoint, reservation] of [
  [
    planExecutionPipeline,
    execution,
    "implement",
    "implement:workspace-write:commit:1",
    "writableResult",
  ],
  [
    polishingPipeline,
    polishing,
    "resolve-findings",
    "resolve-findings:workspace-write:work",
    "resolutionCorrection",
  ],
]) {
  for (const operatorStop of [true, false]) {
    test(`${pipeline.id} cold ${operatorStop ? "stop" : "resume"} preserves the candidate after a recorded writable catalog rejection`, async (t) => {
      const miss = modelCatalogMiss();
      let invocation;
      const fixture = await support.createFixture(t, {
        ...(support === polishing
          ? {
              reviewer: [
                polishing.bootstrapReady("Reviewer"),
                polishing.reviewFindings("R1"),
              ],
            }
          : {}),
        onRoleRun() {
          if (fixture.currentRun.activeTurn?.phase === phase) {
            invocation = fixture.currentRun;
            throw miss;
          }
        },
      });
      await assert.rejects(fixture.run(), (cause) => cause === miss);
      const { projectPath, taskPath, roles, hashes, counters, activeTurn } =
        invocation;
      const runId = randomUUID();
      const saved = invocation.pipelineState;
      const clarificationPath = join(
        saved.clarificationRoot,
        saved.artifactRoot,
        "agent-runner",
        runId,
        "clarifications.md",
      );
      if (support === execution) {
        fixture.runtime.clarifications.writeTranscript(
          clarificationPath,
          fixture.readClarification(),
        );
      } else {
        await mkdir(dirname(clarificationPath), { recursive: true });
        await copyFile(saved.clarificationPath, clarificationPath);
      }
      const repositoryBaseline = await fixture.runtime.git.snapshot({
        projectPath,
        allowedPaths: [clarificationPath],
      });
      const stateRoot = await mkdtemp(join(tmpdir(), "catalog-stop-"));
      t.after(() => rm(stateRoot, { recursive: true, force: true }));
      const store = createRunStore({ stateRoot });
      const pipelineState = { ...saved, clarificationPath, repositoryBaseline };
      const { lease } = await store.createRun({
        runId,
        pipelineId: pipeline.id,
        pipelineStateVersion: pipeline.stateVersion,
        projectPath,
        taskPath,
        roles,
        hashes,
        counters,
        pipelineState,
      });
      try {
        const role = activeTurn.role;
        await store.startAgentTurn(lease, activeTurn, {
          activity: {
            actor: role,
            phase,
            kind: "turn-started",
            message: "Started writable turn.",
          },
        });
        const started = await store.startObservationAttempt(lease, {
          role,
          checkpoint,
        });
        const { id } = started.observations.attempts.at(-1);
        const failure = normalizeAdapterFailure("codex", miss).failure;
        await store.recordObservationBatch(
          lease,
          { id, role, checkpoint },
          [],
          {
            status: "failed",
            writableRejection: failure,
          },
        );
      } finally {
        await lease.release();
      }

      await writeFile(join(projectPath, "concurrent.txt"), "foreign bytes\n");
      const reopened = createRunStore({ stateRoot });
      const before = await reopened.loadRun(runId);
      if (operatorStop) {
        await reopened.requestOperatorStop({
          runId,
          kind: "pause_requested",
          expectedRevision: before.revision,
          idempotencyKey: "cold-catalog-stop",
        });
      }
      const recoveredLease = await reopened.acquireRunLease(runId);
      try {
        let paused;
        if (operatorStop) {
          paused = await reconcileOperatorStop({
            run: before,
            pipeline,
            lease: recoveredLease,
            runStore: reopened,
            runtime: fixture.runtime,
            publish: async () => {},
          });
          assert.equal(paused.pause.reason, "operator_paused");
        } else {
          const history = await reopened.loadRunHistory(runId, {
            stream: true,
          });
          await pipeline.prepareRecovery(history.run, history);
          paused = await pipeline.workflow.run({
            run: history.run,
            settings: history.run.pipelineState.settings,
            interruptedWritableNoEffect: history.hasWritableCatalogRejection,
            runtime: {
              ...fixture.runtime,
              transition: (patch, options) =>
                reopened.transitionRun(recoveredLease, patch, options),
              finishAgentTurn: (turn) =>
                reopened.finishAgentTurn(recoveredLease, turn),
              startAgentTurn: () =>
                assert.fail("Drift must halt before dispatch."),
            },
          });
        }
        const blocker = operatorStop
          ? paused.pause.operatorResume.pause
          : paused.pause;
        assert.equal(blocker?.reason, "unsafe_git_state");
        assert.equal(blocker.code, "ERR_MODEL_CATALOG_WORKSPACE_CHANGED");
        assert.equal(paused.activeTurn, null);
        assert.equal(paused.modelCatalogResume, null);
        assert.deepEqual(paused.hashes, before.hashes);
        assert.deepEqual(paused.counters, before.counters);
        for (const field of [reservation, "repositoryBaseline", "findings"]) {
          assert.deepEqual(
            paused.pipelineState[field],
            before.pipelineState[field],
          );
        }
      } finally {
        await recoveredLease.release();
      }
    });
  }
}

for (const [pipeline, support, reservation, phase, checkpoint, outcome] of [
  ...[
    "retry",
    "drift",
    "cancel",
    "before dispatch",
    "during dispatch",
    "cold backoff",
  ].map((outcome) => [
    planExecutionPipeline,
    execution,
    "writableResult",
    "writable-result",
    "writable-result:read-only:commit:1",
    outcome,
  ]),
  [
    polishingPipeline,
    polishing,
    "resolutionCorrection",
    "resolve-findings",
    "resolve-findings:read-only:finding-resolution-correction",
    "retry",
  ],
  [
    polishingPipeline,
    polishing,
    "resolutionCorrection",
    "resolve-findings",
    "resolve-findings:read-only:finding-resolution-correction",
    "cancel",
  ],
]) {
  test(`${pipeline.id} rejects or retains a catalog restatement during stop (${outcome})`, async (t) => {
    const originalMiss = modelCatalogMiss({ recovery: true });
    const lost = Object.assign(
      new Error("Owner lost before pause publication."),
      { code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE" },
    );
    const model = "test-model";
    const code = "ERR_MODEL_CATALOG_RETRY";
    const infrastructure = "LOCAL_ARTIFACTS/validation.json";
    const withInfrastructure = (report) => ({
      ...report,
      validationInfrastructure: [
        ...report.validationInfrastructure,
        infrastructure,
      ],
    });
    const fixture = await support.createFixture(t, {
      ...(support === polishing
        ? {
            reviewer: [
              polishing.bootstrapReady("Reviewer"),
              polishing.reviewFindings("R1"),
            ],
          }
        : {
            worker: [
              execution.clarificationReady(),
              withInfrastructure(execution.bootstrapReady("Worker")),
              execution.reconciliationResolved(),
            ],
            reviewer: [
              withInfrastructure(execution.bootstrapReady("Reviewer")),
            ],
            async prepareProject(projectPath) {
              await mkdir(dirname(join(projectPath, infrastructure)), {
                recursive: true,
              });
              await writeFile(join(projectPath, infrastructure), "{}\n");
            },
          }),
      async onRoleRun(role, request) {
        if (role !== "worker") return;
        if (
          request.access === "workspace-write" &&
          fixture.currentRun.activeTurn.phase ===
            (support === execution ? "implement" : "resolve-findings")
        ) {
          if (support === execution)
            await writeFile(
              join(request.cwd, "package.json"),
              '{"scripts":{"test":"node --test test"}}\n',
            );
          else
            await writeFile(
              join(request.cwd, "repair.txt"),
              "Preserved repair.\n",
            );
          throw originalMiss;
        }
        if (
          request.access === "read-only" &&
          fixture.currentRun.activeTurn.phase === phase
        )
          throw lost;
      },
    });
    fixture.runtime.catalogRetry = {
      code,
      eligible: () => false,
      hasWritableNoEffect: () => false,
      hasPossibleEffect: (cause) => cause === originalMiss,
      resuming: () => false,
      claimResume: () => false,
    };
    await assert.rejects(fixture.run(), (cause) => cause === lost);
    const invocation = fixture.currentRun;
    const { activeTurn, projectPath, taskPath, roles, hashes, counters } =
      invocation;
    assert.deepEqual(activeTurn, { role: "worker", phase });
    const saved = invocation.pipelineState;
    assert.equal(saved[reservation].stage, "correcting");
    if (support === execution) {
      assert.match(
        saved.writableResult.restatementValidationFingerprint,
        /^[a-f0-9]{64}$/u,
      );
      assert.notEqual(
        saved.writableResult.restatementValidationFingerprint,
        saved.validationInfrastructureFingerprint,
      );
    }
    const runId = randomUUID();
    const clarificationPath = join(
      saved.clarificationRoot,
      saved.artifactRoot,
      "agent-runner",
      runId,
      "clarifications.md",
    );
    if (support === execution) {
      fixture.runtime.clarifications.writeTranscript(
        clarificationPath,
        fixture.readClarification(),
      );
    } else {
      await mkdir(dirname(clarificationPath), { recursive: true });
      await copyFile(saved.clarificationPath, clarificationPath);
    }
    const repositoryBaseline = await fixture.runtime.git.snapshot({
      projectPath,
      allowedPaths: [clarificationPath],
    });
    const stateRoot = await mkdtemp(
      join(tmpdir(), "catalog-restatement-stop-"),
    );
    t.after(() => rm(stateRoot, { recursive: true, force: true }));
    const store = createRunStore({ stateRoot });
    const { restatementStartedAfter, ...reserved } = saved[reservation];
    const pipelineState = {
      ...saved,
      clarificationPath,
      repositoryBaseline,
      [reservation]: reserved,
    };
    const role = "worker";
    const { lease } = await store.createRun({
      runId,
      pipelineId: pipeline.id,
      pipelineStateVersion: pipeline.stateVersion,
      projectPath,
      taskPath,
      roles: { ...roles, worker: { ...roles.worker, model } },
      hashes,
      counters,
      pipelineState,
    });
    const bootstrap = { role, phase: "bootstrap" };
    const activity = (turn) => ({
      actor: role,
      phase: turn.phase,
      kind: "turn-started",
      message: "Worker turn started.",
    });
    try {
      await store.startAgentTurn(lease, bootstrap, {
        activity: activity(bootstrap),
      });
      await recordCompletedModelTurn(store, lease, bootstrap, { model });
      await store.finishAgentTurn(lease, bootstrap);
      await store.startAgentTurn(lease, activeTurn, {
        activity: activity(activeTurn),
        preparePipelineState: (state, revision) => ({
          ...state,
          [reservation]: { ...reserved, restatementStartedAfter: revision },
        }),
      });
      const started = await store.startObservationAttempt(lease, {
        role,
        checkpoint,
      });
      const { id } = started.observations.attempts.at(-1);
      await store.recordObservationBatch(lease, { id, role, checkpoint }, [], {
        status: "failed",
        readOnlyRejection: normalizeAdapterFailure("codex", modelCatalogMiss())
          .failure,
      });
    } finally {
      await lease.release();
    }

    const cold = createRunStore({ stateRoot });
    const before = await cold.loadRun(runId);
    if (outcome === "drift") {
      await writeFile(join(projectPath, infrastructure), '{"changed":true}\n');
      await fixture.runtime.git.assertUnchanged(repositoryBaseline);
    }
    await cold.requestOperatorStop({
      runId,
      kind: "pause_requested",
      expectedRevision: before.revision,
      idempotencyKey: "catalog-restatement-stop",
    });
    const recoveredLease = await cold.acquireRunLease(runId);
    try {
      let cancellation;
      const runStore =
        outcome !== "cancel"
          ? cold
          : {
              ...cold,
              async settleCheckpoint(...args) {
                const latest = await cold.loadRun(runId);
                assert.equal(latest.stopRequest.kind, "pause_requested");
                cancellation = await cold.requestOperatorStop({
                  runId,
                  kind: "cancel_requested",
                  expectedRevision: latest.revision,
                  idempotencyKey: "supersede-catalog-restatement-stop",
                });
                return cold.settleCheckpoint(...args);
              },
            };
      const stopped = await reconcileOperatorStop({
        run: before,
        pipeline:
          outcome !== "cancel"
            ? pipeline
            : {
                ...pipeline,
                workflow: {
                  ...pipeline.workflow,
                  async run(options) {
                    const reconciled = await pipeline.workflow.run(options);
                    assert.equal(reconciled.pause.code, code);
                    return reconciled;
                  },
                },
              },
        lease: recoveredLease,
        runStore,
        runtime: fixture.runtime,
        publish: async () => {},
      });
      const savedStop = await createRunStore({ stateRoot }).loadRun(runId);
      assert.deepEqual(savedStop.pause, stopped.pause);
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.pause.operatorResume.activeTurn, null);
      assert.deepEqual(stopped.counters, before.counters);
      assert.deepEqual(stopped.hashes, before.hashes);
      assert.deepEqual(
        stopped.pipelineState.repositoryBaseline,
        before.pipelineState.repositoryBaseline,
      );
      assert.equal(
        stopped.pipelineState.validationInfrastructureFingerprint,
        saved.validationInfrastructureFingerprint,
      );
      if (outcome === "cancel") {
        assert.equal(stopped.pipelineState.workflowState, "CANCELED");
        assert.equal(stopped.pause.reason, "operator_canceled");
        assert.equal(stopped.pause.operatorResume.pause, null);
        assert.equal(stopped.stopRequest.requestId, cancellation.requestId);
        assert.equal(stopped.stopRequest.reconciledRevision, stopped.revision);
        assert.equal(stopped.modelCatalogResume, null);
        assert.deepEqual(
          stopped.pipelineState[reservation],
          before.pipelineState[reservation],
        );
        assert.deepEqual(stopped.observations, before.observations);
        return;
      }
      assert.equal(stopped.pause.reason, "operator_paused");
      if (outcome === "drift") {
        assert.deepEqual(stopped.pause.operatorResume.pause, {
          reason: "unsafe_git_state",
          code: "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
        });
        assert.equal(stopped.modelCatalogResume, null);
        assert.deepEqual(
          stopped.pipelineState[reservation],
          before.pipelineState[reservation],
        );
        return;
      }
      const binding = {
        role,
        checkpoint,
        resumeState: pipelineState.workflowState,
      };
      assert.deepEqual(stopped.pause.operatorResume.pause, {
        reason: "backend_unavailable",
        code,
        ...binding,
      });
      assert.deepEqual(stopped.pipelineState[reservation], {
        ...before.pipelineState[reservation],
        stage: support === execution ? "retry-ready" : "correcting",
      });
      const restored = await cold.transitionRun(
        recoveredLease,
        restoreOperatorPause(stopped),
      );
      const retry = await cold.transitionRun(recoveredLease, {
        pause: null,
        pipelineState: {
          ...restored.pipelineState,
          workflowState: binding.resumeState,
        },
      });
      assert.deepEqual(retry.modelCatalogResume, binding);
      const dispatched = new Error(
        "Explicit retry reached the same restatement.",
      );
      let launched;
      let calls = 0;
      const changeValidation = () =>
        writeFile(join(projectPath, infrastructure), '{"changed":true}\n');
      const transient = availabilityFailure();
      const processLost = new Error("Runner exited during backoff.");
      const availability = (runStore, lease, run, publish) =>
        createAvailabilityCoordinator({
          runId,
          runStore,
          lease,
          initialRun: run,
          providers: PROVIDER_REGISTRY,
          git: fixture.runtime.git,
          validateRun: pipeline.workflow.validateRun,
          publish,
          monitor: {
            async check() {},
            wait: (operation) => operation(new AbortController().signal),
          },
          clock: () =>
            Date.parse(run.availabilityRetry?.nextRetryAt ?? run.updatedAt),
        });
      const retrying = pipeline.workflow.run({
        run: retry,
        settings: retry.pipelineState.settings,
        runtime: {
          ...fixture.runtime,
          catalogRetry: createModelCatalogRecovery({ run: retry }),
          ...(outcome === "cold backoff"
            ? {
                availability: availability(
                  cold,
                  recoveredLease,
                  retry,
                  async ({ kind }) => {
                    assert.equal(kind, "retry-scheduled");
                    throw processLost;
                  },
                ),
              }
            : {}),
          transition: (patch, options) =>
            cold.transitionRun(recoveredLease, patch, options),
          finishAgentTurn: (turn) => cold.finishAgentTurn(recoveredLease, turn),
          recordChildSession: (child, options) =>
            cold.recordChildSession(recoveredLease, child, options),
          adapters: {
            ...fixture.runtime.adapters,
            worker: {
              ...fixture.runtime.adapters.worker,
              async run(request) {
                assert.equal(request.access, "read-only");
                calls++;
                if (outcome === "cold backoff") {
                  const observed = await cold.startObservationAttempt(
                    recoveredLease,
                    { role, checkpoint },
                  );
                  const { id } = observed.observations.attempts.at(-1);
                  await cold.recordObservationBatch(
                    recoveredLease,
                    { id, role, checkpoint },
                    [],
                    { status: "failed" },
                  );
                  throw transient;
                }
                assert.equal(outcome, "during dispatch");
                await changeValidation();
                const sessionId = "restatement-retry";
                await request.onSessionCreated(sessionId);
                return {
                  sessionId,
                  structured: { result: execution.implementationCompleted() },
                };
              },
            },
          },
          async startAgentTurn(turn, options) {
            assert.deepEqual(turn, activeTurn);
            assert.equal(options.catalogCheckpoint, checkpoint);
            launched = await cold.startAgentTurn(recoveredLease, turn, {
              ...options,
              activity: activity(turn),
            });
            assert.deepEqual(launched.counters, before.counters);
            assert.equal(
              launched.pipelineState[reservation].attempts,
              reserved.attempts,
            );
            assert.equal(launched.modelCatalogResume, null);
            if (outcome === "retry") throw dispatched;
            if (outcome === "before dispatch") await changeValidation();
            return launched;
          },
        },
      });
      if (outcome === "retry") {
        await assert.rejects(retrying, (cause) => cause === dispatched);
        return;
      }
      if (outcome === "cold backoff") {
        await assert.rejects(
          retrying,
          (cause) =>
            cause.code === "ERR_AVAILABILITY_RECOVERY" &&
            cause.cause === processLost,
        );
        assert.equal(calls, 1);
        await recoveredLease.release();
        const reopened = createRunStore({ stateRoot });
        const waiting = await reopened.loadRun(runId);
        assert.equal(waiting.modelCatalogResume, null);
        assert.equal(waiting.activeTurn, null);
        assert.equal(waiting.pipelineState.writableResult.stage, "retry-ready");
        assert.equal(waiting.availabilityRetry.checkpoint, checkpoint);
        await changeValidation();
        await fixture.runtime.git.assertUnchanged(repositoryBaseline);

        const lease = await reopened.acquireRunLease(runId);
        try {
          await assert.rejects(
            reopened.transitionRun(lease, {
              pipelineState: {
                ...waiting.pipelineState,
                writableResult: {
                  ...waiting.pipelineState.writableResult,
                  restatementValidationFingerprint: "0".repeat(64),
                },
              },
            }),
            { code: "ERR_INVALID_EVENT_LOG" },
          );
          const paused = await pipeline.workflow.run({
            run: waiting,
            settings: waiting.pipelineState.settings,
            runtime: {
              ...fixture.runtime,
              catalogRetry: createModelCatalogRecovery({ run: waiting }),
              availability: availability(
                reopened,
                lease,
                waiting,
                async () => {},
              ),
              transition: (patch, options) =>
                reopened.transitionRun(lease, patch, options),
              startAgentTurn: () =>
                assert.fail(
                  "A changed validation scope cannot start a new turn.",
                ),
            },
          });
          assert.deepEqual(paused.pause, {
            reason: "unsafe_git_state",
            code: "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
          });
          assert.deepEqual(
            paused.pipelineState.writableResult,
            waiting.pipelineState.writableResult,
          );
          assert.deepEqual(paused.counters, waiting.counters);
          assert.deepEqual(paused.availabilityRetry, waiting.availabilityRetry);
          assert.deepEqual(
            (await createRunStore({ stateRoot }).loadRun(runId)).pipelineState
              .writableResult,
            waiting.pipelineState.writableResult,
          );
        } finally {
          await lease.release();
        }
        return;
      }
      const paused = await retrying;
      assert.equal(calls, outcome === "during dispatch" ? 1 : 0);
      assert.deepEqual(paused.pause, {
        reason: "unsafe_git_state",
        code: "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
      });
      assert.deepEqual(
        paused.pipelineState[reservation],
        launched.pipelineState[reservation],
      );
      assert.deepEqual(
        paused.pipelineState.workReports,
        retry.pipelineState.workReports,
      );
      assert.deepEqual(paused.counters, retry.counters);
      assert.equal(paused.activeTurn, null);
      assert.equal(paused.modelCatalogResume, null);
      await fixture.runtime.git.assertUnchanged(repositoryBaseline);
      assert.deepEqual(
        (await createRunStore({ stateRoot }).loadRun(runId)).pause,
        paused.pause,
      );
    } finally {
      await recoveredLease.release();
    }
  });
}

for (const disposition of [
  "output_exhausted",
  "authentication_required",
  "authentication with stale expiry",
  "availability backoff",
  "inactivity limit",
  "lost invocation",
]) {
  test(`a read-only catalog retry settles correctly after ${disposition}`, async (t) => {
    const lost = modelCatalogMiss({ recovery: true });
    const miss = modelCatalogMiss();
    let writes = 0;
    let restatements = 0;
    const authentication = disposition === "authentication_required";
    const staleExpiry = disposition === "authentication with stale expiry";
    const backoff = disposition === "availability backoff";
    const inactivityLimit = disposition === "inactivity limit";
    const lostInvocation = disposition === "lost invocation";
    const fixture = await execution.createFixture(t, {
      async onRoleRun(role, request) {
        if (role !== "worker") return;
        if (
          request.access === "workspace-write" &&
          request.prompt.includes("Implement the changes")
        ) {
          writes++;
          await writeFile(join(request.cwd, "repair.txt"), "preserved bytes\n");
          if (!inactivityLimit && !staleExpiry)
            assert.equal(await request.onFreshSession(), true);
          throw lost;
        }
        if (request.prompt.includes("Original turn facts (runner data)")) {
          assert.equal(request.access, "read-only");
          restatements++;
          if (restatements === 1) {
            if (staleExpiry)
              await assert.rejects(inactivity.expire(request), {
                code: "ERR_PROVIDER_INACTIVE",
              });
            throw miss;
          }
          if (inactivityLimit && restatements <= 3)
            return inactivity.expire(request);
          if (restatements === 2) {
            if (staleExpiry) throw authenticationFailure();
            if (disposition === "output_exhausted") throw outputExhaustion();
            if (authentication || backoff) throw availabilityFailure();
            throw Object.assign(
              new Error("Owner lost during the invocation."),
              {
                code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
              },
            );
          }
          if (authentication && restatements === 3)
            throw authenticationFailure();
          if (staleExpiry && restatements === 3)
            return inactivity.expire(request);
        }
      },
    });
    const code = "ERR_MODEL_CATALOG_RETRY";
    let catalogBinding;
    fixture.runtime.catalogRetry = {
      code,
      eligible: (cause) => cause === miss,
      hasWritableNoEffect: () => false,
      hasPossibleEffect: (cause) => cause === lost,
      details: (role, checkpoint) => ({ code, role, checkpoint }),
      resuming: (role, checkpoint) =>
        catalogBinding?.role === role &&
        catalogBinding.checkpoint === checkpoint,
      claimResume(role, checkpoint) {
        if (catalogBinding === undefined) return false;
        assert.equal(this.resuming(role, checkpoint), true);
        catalogBinding = undefined;
        return true;
      },
    };
    const inactivity = await attachInactivity(fixture);
    if (disposition === "output_exhausted") attachOutputExhaustion(fixture);
    if (authentication || staleExpiry) attachAuthentication(fixture);
    const availability =
      backoff || authentication
        ? attachAvailability(fixture, {
            onWait() {
              if (backoff) throw new Error("Owner lost during backoff.");
            },
          })
        : null;
    const paused = await fixture.run();
    assert.equal(paused.pause.code, code);
    assert.equal(paused.pipelineState.writableResult.attempts, 1);
    assert.equal(
      paused.inactivityRecovery?.attempt,
      inactivityLimit ? undefined : staleExpiry ? 1 : 2,
    );
    assert.equal(paused.activeTurn, null);
    catalogBinding = paused.pause;
    inactivity.restart();
    if (backoff || lostInvocation) {
      await assert.rejects(fixture.run(), {
        code: lostInvocation
          ? "ERR_EXECUTION_PROCESS_UNVERIFIABLE"
          : "ERR_AVAILABILITY_RECOVERY",
      });
      assert.equal(
        fixture.currentRun.activeTurn?.phase ?? null,
        lostInvocation ? "writable-result" : null,
      );
      if (availability !== null) {
        assert.equal(availability.scheduled.length, 1);
        assert.equal(
          availability.scheduled[0].availabilityRetry.checkpoint,
          paused.inactivityRecovery.checkpoint,
        );
      }
    } else {
      const providerPause = await fixture.run();
      if (inactivityLimit) {
        assert.equal(providerPause.pause.reason, "backend_unavailable");
        assert.equal(providerPause.pause.code, "ERR_PROVIDER_INACTIVE");
        assert.equal(
          providerPause.pipelineState.writableResult.stage,
          "retry-ready",
        );
      } else
        assert.equal(
          providerPause.pause.reason,
          staleExpiry ? "authentication_required" : disposition,
        );
      assert.equal(providerPause.activeTurn, null);
      if (authentication) {
        assert.equal(availability.scheduled.length, 1);
        assert.equal(providerPause.availabilityRetry, null);
      }
      if (disposition === "output_exhausted")
        assert.equal(
          providerPause.pause.checkpoint,
          "writable-result:read-only:commit:1",
        );
    }
    assert.equal(fixture.currentRun.pipelineState.writableResult.attempts, 1);
    assert.equal(
      fixture.currentRun.inactivityRecovery.attempt,
      staleExpiry ? 1 : 2,
    );
    inactivity.restart();
    const done = await fixture.run();
    assert.equal(writes, 1);
    if (lostInvocation) {
      assert.equal(done.pause.reason, "writable_output_invalid");
      assert.equal(restatements, 2);
      return;
    }
    assert.equal(done.pipelineState.workflowState, "DONE");
    assert.equal(done.inactivityRecovery, null);
    assert.equal(done.counters.fixRounds, 0);
    assert.equal(
      restatements,
      authentication || inactivityLimit || staleExpiry ? 4 : 3,
    );
    assert.equal(
      inactivity.events.filter(({ kind }) => kind === "reconstructing").length,
      1,
    );
  });
}

for (const scenario of [
  "first",
  "second",
  "stale",
  "mismatched",
  "first at stop",
  "second at stop",
  "retained at stop",
  "stale at stop",
  "legacy first",
  "legacy first at stop",
  "legacy stale",
  "legacy mismatched",
]) {
  const stopping = scenario.endsWith(" at stop");
  const legacy = scenario.startsWith("legacy ");
  const expiry = scenario.replace(/^legacy /u, "").split(" ")[0];
  test(`plan-execution restatement recovery handles ${scenario} expiry evidence`, async (t) => {
    const miss = modelCatalogMiss({ recovery: true });
    let writes = 0;
    let restatements = 0;
    let inactivity;
    const events = [];
    const loseAt = ["first", "mismatched", "retained"].includes(expiry) ? 1 : 2;
    const lost = new Error("Owner lost before publishing the continuation.");
    const fixture = await execution.createFixture(t, {
      onTransition(run, patch) {
        if (!legacy || run.activeTurn?.phase !== "writable-result") return;
        if (patch.observations?.attempts.at(-1)?.status === "active")
          events.push({ state: run, activity: null });
        if (patch.inactivityRecovery?.expiryRevision === run.revision)
          events.push({
            state: run,
            activity: { actor: "worker", phase: "inactivity", kind: "expired" },
          });
      },
      async onRoleRun(role, request) {
        if (role !== "worker") return;
        if (request.prompt.includes("Implement the changes")) {
          assert.equal(request.access, "workspace-write");
          writes++;
          await writeFile(join(request.cwd, "repair.txt"), "preserved bytes\n");
          if (expiry === "retained")
            assert.equal(await request.onFreshSession(), true);
          throw miss;
        }
        if (!request.prompt.includes("Original turn facts (runner data)"))
          return;
        assert.equal(request.access, "read-only");
        restatements++;
        if (restatements <= loseAt) return inactivity.expire(request);
        if (expiry === "stale")
          throw Object.assign(new Error("Owner lost during the invocation."), {
            code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
          });
      },
    });
    fixture.runtime.catalogRetry = {
      eligible: () => false,
      hasWritableNoEffect: () => false,
      hasPossibleEffect: (cause) => cause === miss,
      resuming: () => false,
      claimResume: () => false,
    };
    let reconstructionAcknowledged = stopping || expiry !== "first";
    inactivity = await attachInactivity(fixture, {
      onRecord(run) {
        if (
          !reconstructionAcknowledged &&
          run.inactivityRecovery.status === "reconstructing"
        ) {
          reconstructionAcknowledged = true;
          throw lost;
        }
      },
    });
    if (legacy) {
      const { startAgentTurn } = fixture.runtime;
      fixture.runtime.startAgentTurn = async (turn, options) => {
        const before = fixture.currentRun;
        const state = await startAgentTurn(turn, options);
        if (turn.phase === "writable-result")
          events.push(
            { state: before, activity: null },
            {
              state,
              activity: {
                actor: turn.role,
                phase: turn.phase,
                kind: "turn-started",
              },
            },
          );
        return state;
      };
    }
    if (expiry !== "stale") {
      const { transition } = fixture.runtime;
      fixture.runtime.transition = async (patch, options) => {
        if (
          restatements === loseAt &&
          patch.activeTurn === null &&
          ["inactivity-ready", "retry-ready"].includes(
            patch.pipelineState?.writableResult?.stage,
          )
        ) {
          fixture.runtime.transition = transition;
          throw lost;
        }
        return transition(patch, options);
      };
    }
    if (expiry === "stale") {
      const paused = await fixture.run();
      assert.equal(paused.pause.code, "ERR_PROVIDER_INACTIVE");
      inactivity.restart();
      await assert.rejects(fixture.run(), {
        code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
      });
    } else {
      await assert.rejects(fixture.run(), (cause) => cause === lost);
    }
    const interrupted = fixture.currentRun;
    assert.equal(interrupted.activeTurn.phase, "writable-result");
    assert.equal(interrupted.inactivityRecovery.status, "expired");
    if (expiry === "retained") {
      assert.equal(
        interrupted.inactivityRecovery.checkpoint,
        "implement:workspace-write:commit:1",
      );
      assert.equal(interrupted.inactivityRecovery.attempt, 2);
    }
    assert.equal(
      interrupted.inactivityRecovery.expiryRevision >
        interrupted.pipelineState.writableResult.restatementStartedAfter,
      expiry !== "stale",
    );
    if (expiry === "mismatched")
      await fixture.runtime.transition({
        inactivityRecovery: {
          ...interrupted.inactivityRecovery,
          checkpoint: "implement:workspace-write:commit:1",
        },
      });
    const prepareLegacyRecovery = async (run) => {
      if (!legacy) return;
      const history = events.map(({ state, activity }) => {
        const {
          restatementStartedAfter,
          restatementValidationFingerprint,
          repair,
          ...writableResult
        } = state.pipelineState.writableResult;
        return {
          activity,
          state: {
            ...state,
            schemaVersion: 27,
            pipelineStateVersion: 44,
            ...(activity?.kind === "expired" && expiry === "mismatched"
              ? { inactivityRecovery: fixture.currentRun.inactivityRecovery }
              : {}),
            pipelineState: {
              ...state.pipelineState,
              writableResult: { ...writableResult, schemaVersion: 1 },
            },
          },
        };
      });
      await planExecutionPipeline.prepareRecovery(run, { events: history });
    };
    if (legacy) {
      const {
        restatementStartedAfter,
        restatementValidationFingerprint,
        ...writableResult
      } = fixture.currentRun.pipelineState.writableResult;
      await fixture.runtime.transition({
        pipelineState: { ...fixture.currentRun.pipelineState, writableResult },
      });
    }
    inactivity.restart();
    if (stopping) {
      const requested = await fixture.runtime.transition({
        stopRequest: { acceptedRevision: fixture.currentRun.revision + 1 },
      });
      await prepareLegacyRecovery(requested);
      const stopped = await runPlanExecution({
        run: requested,
        runtime: fixture.runtime,
        operatorStop: true,
      });
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.pause, null);
      assert.equal(stopped.pipelineState.writableResult.attempts, 1);
      assert.equal(
        stopped.pipelineState.writableResult.stage,
        {
          first: "inactivity-ready",
          second: "retry-ready",
          retained: "retry-ready",
          stale: "correcting",
        }[expiry],
      );
      assert.deepEqual(stopped.counters, interrupted.counters);
      if (legacy)
        assert.equal(
          stopped.pipelineState.writableResult.restatementStartedAfter,
          interrupted.pipelineState.writableResult.restatementStartedAfter,
        );
      assert.equal(restatements, expiry === "stale" ? 3 : loseAt);
      inactivity.restart();
      await prepareLegacyRecovery(fixture.currentRun);
      const resumed = await fixture.run();
      assert.equal(writes, 1);
      assert.equal(restatements, expiry === "stale" ? 3 : loseAt + 1);
      if (expiry === "stale") {
        assert.equal(resumed.pause.reason, "writable_output_invalid");
      } else {
        assert.equal(resumed.pipelineState.workflowState, "DONE");
        assert.equal(resumed.inactivityRecovery, null);
      }
      return;
    }
    await prepareLegacyRecovery(fixture.currentRun);
    if (expiry === "first") {
      await assert.rejects(fixture.run(), { code: "ERR_INACTIVITY_RECOVERY" });
      assert.equal(restatements, 1);
      assert.equal(fixture.currentRun.inactivityRecovery.attempt, 2);
      assert.equal(fixture.currentRun.activeTurn, null);
      assert.equal(
        fixture.currentRun.pipelineState.writableResult.restatementStartedAfter,
        interrupted.pipelineState.writableResult.restatementStartedAfter,
      );
      inactivity.restart();
    }
    const recovered = await fixture.run();
    assert.equal(writes, 1);
    assert.equal(recovered.counters.fixRounds, 0);
    if (expiry === "mismatched") {
      assert.equal(recovered.pause.reason, "writable_output_invalid");
      assert.equal(restatements, 1);
      assert.equal(recovered.pipelineState.writableResult.attempts, 1);
    } else if (expiry === "stale") {
      assert.equal(recovered.pause.reason, "writable_output_invalid");
      assert.equal(restatements, 3);
    } else if (expiry === "second") {
      assert.equal(recovered.pause.code, "ERR_PROVIDER_INACTIVE");
      assert.equal(recovered.pipelineState.writableResult.stage, "retry-ready");
      assert.equal(recovered.pipelineState.writableResult.attempts, 1);
      assert.equal(recovered.activeTurn, null);
      assert.equal(restatements, 2);
      inactivity.restart();
      assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
      assert.equal(restatements, 3);
    } else {
      assert.equal(recovered.pipelineState.workflowState, "DONE");
      assert.equal(restatements, 2);
    }
    assert.equal(writes, 1);
    assert.equal(
      fixture.transitions.filter(
        ({ patch }) => patch?.inactivityRecovery?.status === "reconstructing",
      ).length,
      expiry === "mismatched" ? 0 : 1,
    );
  });
}

for (const legacyMiss of [true, false]) {
  test(`${legacyMiss ? "Legacy catalog miss" : "Invalid catalog response"} offers no fresh COMMIT through CLI, MCP or dispatch`, async (t) => {
    const fixture = await execution.createFixture(t, {
      onCommitRun() {
        if (!legacyMiss)
          throw normalizeAdapterFailure(
            "codex",
            new CodexAdapterError("Codex model catalog response is invalid.", {
              code: "ERR_CODEX_PROTOCOL",
              diagnosticClass: "model_catalog_invalid",
              effectStarted: false,
            }),
          );
        // Retire through the existing pre-effect branch before substituting the legacy pause.
        throw Object.assign(new Error("Readiness rejected."), {
          effectStarted: false,
          code: "ERR_PRE_EFFECT_REJECTED",
        });
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pipelineState.pendingCommit, null);
    const saved = legacyMiss
      ? fixture.persistPipelineState(paused.pipelineState, {
          pause: { ...paused.pause, code: "ERR_CODEX_MODEL_UNAVAILABLE" },
        })
      : paused;
    const runner = {
      async status() {
        return { run: saved, directoryPath: fixture.projectPath };
      },
    };
    const control = createMcpControlPlane({
      runner,
      runStore: {
        async inspectRunLeaseOwner() {
          return null;
        },
      },
    });
    const status = await control.runStatus({ runId: saved.runId });
    assert.deepEqual(status.pause.nextActions, []);
    assert.equal(status.pause.resumeState, null);
    let output = "";
    assert.equal(
      await main(["status", "--run", saved.runId], {
        runner,
        stdout: {
          write: (chunk) => {
            output += chunk;
          },
        },
        stderr: { write: assert.fail },
      }),
      0,
    );
    assert.match(
      output,
      legacyMiss ? /model catalog miss/u : /model_catalog_invalid/u,
    );
    assert.doesNotMatch(output, /Retry with:/u);
    assert.throws(() =>
      planExecutionPipeline.validateResumeAction(saved, null),
    );
    assert.equal((await fixture.run()).revision, saved.revision);
    assert.equal(
      fixture.calls.worker.filter(({ access }) => access === "local-commit")
        .length,
      1,
    );
  });
}

test("lost publication acknowledgement preserves a verified catalog COMMIT pause", async (t) => {
  const miss = modelCatalogMiss({ access: "local-commit" });
  const fixture = await execution.createFixture(t, {
    models: { worker: "test-model" },
    onRoleRun(_role, request) {
      if (request.access === "local-commit") throw miss;
    },
  });
  const code = "ERR_MODEL_CATALOG_RETRY";
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: () => false,
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };
  const transition = fixture.runtime.transition;
  await transition({ modelCompletionReceipts: { worker: "a".repeat(64) } });
  const lost = new Error("Commit pause publication acknowledgement was lost.");
  fixture.runtime.transition = async (patch, options) => {
    const next = await transition(patch, options);
    if (patch.pause?.code === code) throw lost;
    return next;
  };

  await assert.rejects(fixture.run(), (cause) => cause === lost);
  assert.equal(fixture.currentRun.pause.code, code);
  assert.equal(fixture.currentRun.pipelineState.pendingCommit, null);
  assert.equal(fixture.currentRun.pipelineState.completedCommits.length, 0);
});

test("writable pipelines retry exact partial-write checkpoints without recounting lazy corrections", async (t) => {
  for (const support of [execution, polishing]) {
    for (const mode of ["independent", "lazy", "combined"]) {
      let failures = 0;
      const turns = [];
      const fixture = await support.createFixture(t, {
        mode,
        sourceSession: support.SOURCE_SESSION,
        workWorker:
          support === execution
            ? [
                execution.implementationCompleted(),
                execution.checkAndFix(),
                execution.finalizationPassed(),
              ]
            : undefined,
        ...(support === polishing && mode !== "independent"
          ? {
              worker: [
                polishing.clarificationReady(),
                polishing.bootstrapReady("Worker"),
                ...(mode === "combined"
                  ? [polishing.reconciliationResolved()]
                  : []),
                polishing.polishingCompleted(),
                polishing.finalizationPassed(),
                polishing.checkAndFix(),
                polishing.cleanConfirmation(),
              ],
            }
          : {}),
        async onRoleRun(role, request) {
          if (role !== "worker" || request.access !== "workspace-write") return;
          const phase = fixture.currentRun.activeTurn.phase;
          if (
            phase !==
            (mode === "independent"
              ? support === execution
                ? "implement"
                : "polish"
              : "check-and-fix")
          )
            return;
          turns.push(request);
          if (failures++ < 2) {
            await writeFile(
              join(request.cwd, "partial.js"),
              `export const partial = ${failures};\n`,
            );
            throw availabilityFailure();
          }
        },
      });
      const retry = attachAvailability(fixture);
      const result = await fixture.run().catch((error) => {
        error.message += ` (${support === execution ? "execution" : "polishing"}/${mode})`;
        throw error;
      });
      assert.equal(
        result.pipelineState.workflowState,
        "DONE",
        JSON.stringify(result.pause),
      );
      assert.equal(retry.scheduled.length, 2);
      assert.deepEqual(retry.delays, [5000, 7000]);
      assert.equal(
        retry.scheduled[1].availabilityRetry.checkpoint,
        retry.scheduled[0].availabilityRetry.checkpoint,
      );
      assert.equal(
        retry.scheduled[1].counters.fixRounds,
        mode === "independent" ? 0 : 1,
      );
      assert.equal(
        retry.scheduled[1].pipelineState.repositoryBaseline.contentFingerprint,
        retry.scheduled[1].availabilityRetry.contentFingerprint,
      );
      assert.equal(result.availabilityRetry, null);
      assert.equal(result.counters.fixRounds, mode === "independent" ? 0 : 1);
      assert.equal(turns[1].session, undefined);
      assert.equal(turns[2].session, undefined);
      if (mode === "lazy")
        assert.equal(
          fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
            .length,
          1,
        );
    }
  }
});

test("commit readiness proof survives interrupted verification and retires one authorization before retry", async (t) => {
  let reject = true;
  let interruptVerification = true;
  const fixture = await execution.createFixture(t, {
    onRoleRun(_role, request) {
      if (request.access === "local-commit" && reject) {
        reject = false;
        throw availabilityFailure({ commit: true });
      }
    },
    onCommitVerify() {
      if (interruptVerification) {
        interruptVerification = false;
        throw Object.assign(new Error("Interrupted verification"), {
          code: "ERR_TEST_VERIFICATION",
        });
      }
    },
  });
  const retry = attachAvailability(fixture);
  const paused = await fixture.run();
  assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
  assert.deepEqual(
    paused.pipelineState.pendingCommit.preEffectRejection.availability,
    { reason: "temporarily_overloaded", commitExecutor: "not_started" },
  );
  for (const proof of [
    { reason: "transport_unavailable", commitExecutor: "started" },
    { reason: "unknown", commitExecutor: "not_started" },
    {
      reason: "model_busy",
      commitExecutor: "not_started",
      privatePayload: "discard",
    },
  ]) {
    const invalid = structuredClone(paused);
    invalid.pipelineState.pendingCommit.preEffectRejection.availability = proof;
    assert.throws(() => planExecutionPipeline.workflow.validateRun(invalid));
  }
  assert.equal(retry.scheduled.length, 0);
  const result = await fixture.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  assert.equal(retry.scheduled[0].pipelineState.pendingCommit, null);
  assert.deepEqual(retry.delays, [5000]);
  assert.deepEqual(
    fixture.calls.worker
      .filter(({ access }) => access === "local-commit")
      .map(({ authorizationId }) => authorizationId),
    ["commit-1", "commit-2"],
  );
});

test("availability without a new partial write does not reuse an earlier check/fix charge", async (t) => {
  for (const support of [execution, polishing]) {
    let attempts = 0;
    const fixture = await support.createFixture(t, {
      mode: "lazy",
      workWorker: [
        execution.implementationCompleted(),
        execution.checkAndFix("CHANGED"),
        execution.checkAndFix(),
        execution.finalizationPassed(),
      ],
      ...(support === polishing
        ? {
            worker: [
              polishing.clarificationReady(),
              polishing.bootstrapReady("Worker"),
              polishing.polishingCompleted(),
              polishing.finalizationPassed(),
              polishing.checkAndFix("CHANGED"),
              polishing.finalizationPassed(),
              polishing.checkAndFix(),
              polishing.cleanConfirmation(),
            ],
          }
        : {}),
      async onRoleRun(role, request) {
        if (
          role !== "worker" ||
          fixture.currentRun.activeTurn.phase !== "check-and-fix"
        )
          return;
        if (++attempts === 1)
          await writeFile(join(request.cwd, "first-fix.js"), "fixed\n");
        if (attempts === 2) throw availabilityFailure();
      },
    });
    const retry = attachAvailability(fixture);
    const result = await fixture.run();
    assert.equal(
      result.pipelineState.workflowState,
      "DONE",
      JSON.stringify(result.pause),
    );
    assert.equal(retry.scheduled.length, 1);
    assert.equal(
      retry.scheduled[0].pipelineState.availabilityCorrectionCharged,
      false,
    );
    assert.equal(result.counters.fixRounds, 2);
    assert.equal(result.pipelineState.availabilityCorrectionCharged, false);
  }
});

test("owner loss during a delay or response reset preserves the charged correction", async (t) => {
  for (const support of [execution, polishing]) {
    for (const interruption of ["wait", "response"]) {
      let fail = true;
      let interrupt = true;
      const fixture = await support.createFixture(t, {
        mode: "lazy",
        modeSettings:
          support === execution
            ? { maxFixRoundsPerStep: 1 }
            : { maxFixRounds: 1 },
        workWorker: [
          execution.implementationCompleted(),
          ...(interruption === "response" ? [execution.checkAndFix()] : []),
          execution.checkAndFix(),
          execution.finalizationPassed(),
        ],
        ...(support === polishing
          ? {
              worker: [
                polishing.clarificationReady(),
                polishing.bootstrapReady("Worker"),
                polishing.polishingCompleted(),
                polishing.finalizationPassed(),
                ...(interruption === "response"
                  ? [polishing.checkAndFix()]
                  : []),
                polishing.checkAndFix(),
                polishing.cleanConfirmation(),
              ],
            }
          : {}),
        async onRoleRun(role, request) {
          if (
            role === "worker" &&
            fixture.currentRun.activeTurn.phase === "check-and-fix" &&
            fail
          ) {
            fail = false;
            await writeFile(join(request.cwd, "partial.js"), "preserved\n");
            throw availabilityFailure();
          }
        },
      });
      attachAvailability(fixture, {
        onCompleted() {
          if (interrupt && interruption === "response") {
            interrupt = false;
            throw new Error("Owner lost after response reset");
          }
        },
        onWait() {
          if (interrupt && interruption === "wait") {
            interrupt = false;
            throw new Error("Owner lost");
          }
        },
      });
      await assert.rejects(fixture.run(), {
        code: "ERR_AVAILABILITY_RECOVERY",
      });
      assert.equal(fixture.currentRun.counters.fixRounds, 1);
      assert.equal(
        fixture.currentRun.pipelineState.availabilityCorrectionCharged,
        true,
      );
      if (interruption === "response")
        assert.equal(fixture.currentRun.availabilityRetry, null);
      assert.equal(
        fixture.currentRun.pipelineState.workflowState,
        "CHECK_AND_FIX",
      );
      const result = await fixture.run();
      assert.equal(
        result.pipelineState.workflowState,
        "DONE",
        JSON.stringify(result.pause),
      );
      assert.equal(result.counters.fixRounds, 1);
    }
  }
});

test("an exhausted read-only dispute retry never regains write access", async (t) => {
  for (const support of [execution, polishing]) {
    const requests = [];
    const fixture = await support.createFixture(t, {
      modeSettings:
        support === execution
          ? { maxFixRoundsPerStep: 1 }
          : { maxFixRounds: 1 },
      workReviewer: [execution.reviewFindings("R1")],
      ...(support === polishing
        ? {
            reviewer: [
              polishing.bootstrapReady("Reviewer"),
              polishing.reviewFindings("R1"),
            ],
          }
        : {}),
      onRoleRun(role, request) {
        if (
          role !== "worker" ||
          fixture.currentRun.activeTurn.phase !== "resolve-findings"
        )
          return;
        requests.push(request);
        if (requests.length === 1) throw availabilityFailure();
        throw Object.assign(new Error("Separate usage blocker"), {
          code: "ERR_BACKEND_UNAVAILABLE",
          recoverable: true,
        });
      },
    });
    const transition = fixture.runtime.transition;
    fixture.runtime.transition = (patch, options) =>
      transition(
        {
          ...patch,
          ...(patch.pipelineState?.workflowState === "RESOLVE_FINDINGS"
            ? {
                counters: {
                  ...fixture.currentRun.counters,
                  ...patch.counters,
                  fixRounds:
                    patch.pipelineState.settings.maxFixRoundsPerStep ??
                    patch.pipelineState.settings.maxFixRounds,
                },
              }
            : {}),
        },
        options,
      );
    let interrupt = true;
    attachAvailability(fixture, {
      onWait() {
        if (interrupt) {
          interrupt = false;
          throw new Error("Owner lost");
        }
      },
    });
    await assert.rejects(fixture.run(), { code: "ERR_AVAILABILITY_RECOVERY" });
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.deepEqual(
      requests.map(({ access }) => access),
      ["read-only", "read-only"],
    );
    assert.equal(
      result.counters.fixRounds,
      result.pipelineState.settings.maxFixRoundsPerStep ??
        result.pipelineState.settings.maxFixRounds,
    );
  }
});

test("partial availability recovery retains blockers without preserving stale approvals or recounting", async (t) => {
  for (const support of [execution, polishing]) {
    for (const finalization of [false, true]) {
      const id = finalization ? "F1" : "R1";
      let fail = true;
      const fixture = await support.createFixture(t, {
        workReviewer: finalization ? undefined : [execution.reviewFindings(id)],
        workWorker: [
          execution.implementationCompleted(),
          ...(finalization ? [execution.finalizationFailed(id)] : []),
          execution.resolution({ id, decision: "FIX" }),
          execution.finalizationPassed(),
        ],
        ...(support === polishing
          ? {
              ...(finalization
                ? {}
                : {
                    reviewer: [
                      polishing.bootstrapReady("Reviewer"),
                      polishing.reviewFindings(id),
                    ],
                  }),
              worker: [
                polishing.clarificationReady(),
                polishing.bootstrapReady("Worker"),
                polishing.reconciliationResolved(),
                polishing.polishingCompleted(),
                ...(finalization ? [polishing.finalizationFailed()] : []),
                polishing.resolution("FIX", id),
                polishing.finalizationPassed(),
              ],
            }
          : {}),
        async onRoleRun(role, request) {
          if (
            role === "worker" &&
            fixture.currentRun.activeTurn.phase === "resolve-findings" &&
            fail
          ) {
            fail = false;
            await writeFile(join(request.cwd, "partial-fix.js"), "fixed\n");
            throw availabilityFailure();
          }
        },
      });
      const retry = attachAvailability(fixture);
      const result = await fixture.run();
      assert.equal(
        result.pipelineState.workflowState,
        "DONE",
        JSON.stringify(result.pause),
      );
      const pending = retry.scheduled[0].pipelineState;
      assert.equal(pending.workflowState, "RESOLVE_FINDINGS");
      assert.equal(
        pending.finalizationResult?.status ?? null,
        finalization ? "FAIL" : null,
      );
      assert.equal(pending.candidateReviewResult, null);
      assert.equal(pending.reviewResult, null);
      assert.equal(pending.pendingCorrection, true);
      assert.equal(result.counters.fixRounds, 1);
    }
  }
});

test("lazy execution retains confirmation findings across a partial availability retry", async (t) => {
  let fail = true;
  const fixture = await execution.createFixture(t, {
    mode: "lazy",
    workWorker: [
      execution.implementationCompleted(),
      execution.checkAndFix(),
      execution.cleanConfirmationFindings("R1"),
      execution.checkAndFix(),
      execution.finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        fixture.currentRun.activeTurn.phase === "check-and-fix" &&
        fixture.currentRun.pipelineState.findings.length > 0 &&
        fail
      ) {
        fail = false;
        await writeFile(join(request.cwd, "partial-fix.js"), "fixed\n");
        throw availabilityFailure();
      }
    },
  });
  const retry = attachAvailability(fixture);
  const result = await fixture.run();
  assert.equal(
    result.pipelineState.workflowState,
    "DONE",
    JSON.stringify(result.pause),
  );
  const pending = retry.scheduled[0].pipelineState;
  assert.equal(pending.workflowState, "CHECK_AND_FIX");
  assert.deepEqual(
    pending.findings.map(({ id }) => id),
    ["R1"],
  );
  assert.equal(pending.candidateReviewResult, null);
  assert.equal(pending.candidateReviewedFingerprint, null);
  assert.equal(pending.availabilityCorrectionCharged, true);
  const uncharged = structuredClone(retry.scheduled[0]);
  uncharged.pipelineState.availabilityCorrectionCharged = false;
  assert.throws(() => planExecutionPipeline.workflow.validateRun(uncharged), {
    code: "ERR_INVALID_PLAN_EXECUTION_STATE",
  });
  assert.equal(result.counters.fixRounds, 2);
});
