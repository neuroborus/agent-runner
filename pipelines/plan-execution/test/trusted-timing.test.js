import assert from "node:assert/strict";
import test from "node:test";

import { createTrustedValidationService } from "../../../src/trusted-validation/index.js";
import { REVIEW_SCHEMA } from "../src/schemas.js";
import { assertRun } from "../src/workflow-contract.js";
import { validationEvidenceFingerprint } from "../src/validation-schedule.js";
import {
  bootstrapReady,
  clarificationReady,
  createFixture,
  finalizationWithTrustedCheck,
  implementationCompleted,
  reconciliationResolved,
  reviewApproved,
  terminalConfirmation,
  trustedValidationSnapshot,
} from "./support/index.js";

test("a Runner-measured receipt survives reload and binds terminal confirmation without reexecution", async (t) => {
  const trusted = trustedValidationSnapshot();
  const finalization = finalizationWithTrustedCheck(trusted);
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks: finalization.requiredChecks,
  });
  let service;
  let receipt;
  let executions = 0;
  let confirmations = 0;
  const fixture = await createFixture(t, {
    modeSettings: { trustedChecks: [trusted.commands[0].alias] },
    trustedValidation: trusted,
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [implementationCompleted(), finalization],
    workReviewer: [reviewApproved(), terminalConfirmation(reviewApproved())],
    async onTrustedValidation(request) {
      executions++;
      receipt = await service.execute(request);
      return receipt;
    },
    onRoleRun(_role, request) {
      if (request.schema !== REVIEW_SCHEMA) return;
      assert.equal(request.access, "read-only");
      assert.ok(request.prompt.includes(receipt.evidence[1]));
      if (++confirmations === 1)
        throw Object.assign(new Error("Unavailable fixture backend"), {
          code: "ERR_TEST_BACKEND_UNAVAILABLE",
          recoverable: true,
        });
    },
  });
  let now = 0n;
  service = createTrustedValidationService({
    git: fixture.runtime.git,
    monotonicNow: () => {
      const value = now;
      now += 500_000n;
      return value;
    },
    sandboxCommand: (command, { environment }) => ({ command, environment }),
    runCommand: () => ({
      status: "PASS",
      exitCode: 0,
      signal: null,
      timedOut: false,
      reason: "exit",
    }),
  });
  const paused = await fixture.run({
    trustedChecks: [trusted.commands[0].alias],
  });
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CONFIRM");
  const reloaded = JSON.parse(JSON.stringify(paused));
  assert.doesNotThrow(() => assertRun(reloaded));
  const saved = reloaded.pipelineState.finalizationResult;
  assert.deepEqual(saved.checks[1].evidence, receipt.evidence);
  assert.equal(saved.checks[1].commandIdentity, receipt.commandIdentity);
  assert.equal(saved.checks[1].executor, "runner");
  assert.deepEqual(receipt.evidence, [
    "Runner-trusted command service-check exited with code 0.",
    "Runner-measured attempt elapsed time: 0.500 ms (executor invoked).",
  ]);
  assert.deepEqual(
    {
      contentFingerprint: saved.fingerprint,
      validationInfrastructureFingerprint:
        saved.validationInfrastructureFingerprint,
      commandFingerprint: saved.trustedCommandFingerprint,
      configurationFingerprint: saved.trustedConfigurationFingerprint,
    },
    {
      contentFingerprint: receipt.contentFingerprint,
      validationInfrastructureFingerprint:
        receipt.validationInfrastructureFingerprint,
      commandFingerprint: receipt.commandFingerprint,
      configurationFingerprint: receipt.configurationFingerprint,
    },
  );
  fixture.persistPipelineState(reloaded.pipelineState);
  const completed = await fixture.run({}, null);
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(executions, 1);
  assert.equal(confirmations, 2);
  assert.deepEqual(completed.pipelineState.finalizationResult, saved);
  assert.equal(
    completed.pipelineState.reviewResult.validationTupleFingerprint,
    validationEvidenceFingerprint(saved),
  );
  const tampered = structuredClone(completed);
  tampered.pipelineState.finalizationResult.checks[1].evidence[1] =
    "Runner-measured attempt elapsed time: 1.000 ms (executor invoked).";
  assert.throws(
    () => assertRun(tampered),
    /does not bind the exact validation evidence/u,
  );
});
