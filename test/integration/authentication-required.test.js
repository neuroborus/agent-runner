import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "@agent-runner/plan-execution";
import { polishingPipeline } from "@agent-runner/polishing";

import * as execution from "../../pipelines/plan-execution/test/support/index.js";
import * as polishing from "../../pipelines/polishing/test/support/index.js";
import {
  attachAuthentication,
  authenticationFailure,
  interruptAuthenticationSettlement,
} from "../support/authentication.js";

test("writable pipelines reconcile authenticated checkpoint content exactly once", async (t) => {
  for (const support of [execution, polishing]) {
    let authenticationRequired = true;
    const fixture = await support.createFixture(t, {
      mode: "lazy",
      workWorker:
        support === execution
          ? [
              execution.implementationCompleted(),
              execution.checkAndFix(),
              execution.finalizationPassed(),
            ]
          : undefined,
      ...(support === polishing
        ? {
            worker: [
              polishing.clarificationReady(),
              polishing.bootstrapReady("Worker"),
              polishing.polishingCompleted(),
              polishing.finalizationPassed(),
              polishing.checkAndFix(),
              polishing.cleanConfirmation(),
            ],
          }
        : {}),
      async onRoleRun(role, request) {
        if (
          role !== "worker" ||
          fixture.currentRun.activeTurn.phase !== "check-and-fix" ||
          !authenticationRequired
        ) {
          return;
        }
        authenticationRequired = false;
        await writeFile(
          join(request.cwd, "authenticated-fix.js"),
          "export const fixed = true;\n",
        );
        throw authenticationFailure();
      },
    });
    attachAuthentication(fixture);

    const paused = await fixture.run();

    assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
    assert.deepEqual(paused.pause, {
      reason: "authentication_required",
      code: "ERR_AUTHENTICATION_REQUIRED",
      resumeState: "CHECK_AND_FIX",
    });
    const invalid = structuredClone(paused);
    invalid.pause.providerMessage = "DO_NOT_RETAIN_PROVIDER_MESSAGE";
    assert.throws(() =>
      (support === execution
        ? planExecutionPipeline
        : polishingPipeline
      ).workflow.validateRun(invalid),
    );
    assert.equal(paused.counters.fixRounds, 1);
    assert.equal(paused.pipelineState.pendingCorrection, true);
    assert.equal(paused.pipelineState.availabilityCorrectionCharged, true);
    assert.equal(
      await readFile(join(fixture.projectPath, "authenticated-fix.js"), "utf8"),
      "export const fixed = true;\n",
    );

    const completed = await fixture.run();

    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.equal(completed.counters.fixRounds, 1);
  }
});

test("authentication preserves the last writable finding-resolution round", async (t) => {
  for (const support of [execution, polishing]) {
    let authenticationFailures = 2;
    const accesses = [];
    const fixture = await support.createFixture(t, {
      modeSettings:
        support === execution
          ? { maxFixRoundsPerStep: 1 }
          : { maxFixRounds: 1 },
      workReviewer: [execution.reviewFindings("R1")],
      workWorker: [
        execution.implementationCompleted(),
        execution.resolution({ id: "R1", decision: "FIX" }),
        execution.finalizationPassed(),
      ],
      ...(support === polishing
        ? {
            reviewer: [
              polishing.bootstrapReady("Reviewer"),
              polishing.reviewFindings("R1"),
            ],
            worker: [
              polishing.clarificationReady(),
              polishing.bootstrapReady("Worker"),
              polishing.reconciliationResolved(),
              polishing.polishingCompleted(),
              polishing.resolution("FIX", "R1"),
              polishing.finalizationPassed(),
            ],
          }
        : {}),
      async onRoleRun(role, request) {
        if (
          role !== "worker" ||
          fixture.currentRun.activeTurn.phase !== "resolve-findings"
        ) {
          return;
        }
        accesses.push(request.access);
        if (authenticationFailures === 0) return;
        authenticationFailures -= 1;
        await writeFile(
          join(request.cwd, "partial-fix.js"),
          `Partial fix ${accesses.length}\n`,
        );
        throw authenticationFailure();
      },
    });
    attachAuthentication(fixture);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const paused = await fixture.run();
      assert.equal(paused.pause.reason, "authentication_required");
      assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
      assert.equal(paused.counters.fixRounds, 1);
    }

    const completed = await fixture.run();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.deepEqual(accesses, [
      "workspace-write",
      "workspace-write",
      "workspace-write",
    ]);
    assert.equal(completed.counters.fixRounds, 1);
  }
});

test("authentication preserves an unrecorded source fork after interrupted pause publication", async (t) => {
  for (const support of [execution, polishing]) {
    let failures = 2;
    const fixture = await support.createFixture(t, {
      sourceSession: support.SOURCE_SESSION,
      onRoleRun(role) {
        if (role === "worker" && failures > 0) {
          failures -= 1;
          throw authenticationFailure({
            effect: failures === 1 ? "possible" : "none",
          });
        }
      },
    });
    attachAuthentication(fixture);
    interruptAuthenticationSettlement(fixture, { beforePublication: true });

    await assert.rejects(fixture.run(), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    assert.equal(fixture.currentRun.activeTurn.role, "worker");

    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "authentication_required");

    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.deepEqual(
      fixture.calls.worker.slice(0, 3).map(({ session }) => session?.mode),
      ["fork", undefined, undefined],
    );
    assert.equal(
      completed.pipelineState.authenticationSourceForkRecovery,
      null,
    );
  }
});

test("source-fork authentication survives turn-retirement interruption without reforking", async (t) => {
  const cases = [
    { support: execution, mode: "independent" },
    { support: polishing, mode: "independent" },
  ];
  for (const { support, mode } of cases) {
    let authenticationRequired = true;
    const fixture = await support.createFixture(t, {
      mode,
      sourceSession: support.SOURCE_SESSION,
      onRoleRun(role, request) {
        if (
          role !== "worker" ||
          request.session?.mode !== "fork" ||
          !authenticationRequired
        ) {
          return;
        }
        authenticationRequired = false;
        throw authenticationFailure();
      },
    });
    attachAuthentication(fixture);
    interruptAuthenticationSettlement(fixture);

    await assert.rejects(fixture.run(), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    const paused = fixture.currentRun;

    assert.equal(paused.pause.reason, "authentication_required");
    const recovery = paused.pipelineState.authenticationSourceForkRecovery;
    assert.deepEqual(Object.keys(recovery).sort(), ["contextKey", "role"]);
    assert.equal(recovery.role, "worker");
    assert.match(recovery.contextKey, /^[a-f0-9]{64}$/u);
    const invalidRecovery = structuredClone(paused);
    invalidRecovery.pipelineState.authenticationSourceForkRecovery.providerData =
      "DO_NOT_RETAIN_PROVIDER_AUTHENTICATION_EVIDENCE";
    assert.throws(() =>
      (support === execution
        ? planExecutionPipeline
        : polishingPipeline
      ).workflow.validateRun(invalidRecovery),
    );
    const invalidRecoveryRole = structuredClone(paused);
    invalidRecoveryRole.pipelineState.authenticationSourceForkRecovery.role =
      "arbiter";
    assert.throws(() =>
      (support === execution
        ? planExecutionPipeline
        : polishingPipeline
      ).workflow.validateRun(invalidRecoveryRole),
    );
    if (mode === "independent") {
      const invalidLazyRecovery = structuredClone(paused);
      invalidLazyRecovery.roles = {
        worker: invalidLazyRecovery.roles.worker,
      };
      invalidLazyRecovery.pipelineState.settings.mode = "lazy";
      invalidLazyRecovery.pipelineState.lazySourceForkConsumed = false;
      assert.throws(
        () =>
          (support === execution
            ? planExecutionPipeline
            : polishingPipeline
          ).workflow.validateRun(invalidLazyRecovery),
        /authentication source-fork recovery/u,
      );
    }

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(fixture.calls.worker[0].session.mode, "fork");
    assert.equal(fixture.calls.worker[1].session, undefined);
    assert.equal(
      completed.pipelineState.authenticationSourceForkRecovery,
      null,
    );
  }
});
