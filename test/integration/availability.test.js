import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "@agent-runner/plan-execution";

import * as execution from "../../pipelines/plan-execution/test/support/index.js";
import * as polishing from "../../pipelines/polishing/test/support/index.js";
import {
  attachAvailability,
  availabilityFailure,
} from "../support/availability.js";

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
