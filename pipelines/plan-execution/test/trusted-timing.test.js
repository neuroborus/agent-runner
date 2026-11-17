import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createTrustedValidationService } from "../../../src/trusted-validation/index.js";
import { FINALIZATION_SCHEMA, REVIEW_SCHEMA } from "../src/schemas.js";
import { assertRun } from "../src/workflow-contract.js";
import { validationEvidenceFingerprint } from "../src/validation-schedule.js";
import {
  bootstrapReady,
  clarificationReady,
  createFixture,
  finalizationPassed,
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

const ORDER_GUIDANCE =
  "# Finalization\n\nRun the first check (C1) before the second check (C2).\n";

async function serialOrderFixture(t, { selected }) {
  const trusted = trustedValidationSnapshot([
    {
      alias: "first-check",
      command: "npm run check:first",
      executable: "npm",
      arguments: ["run", "check:first"],
    },
    {
      alias: "second-check",
      command: "npm run check:second",
      executable: "npm",
      arguments: ["run", "check:second"],
    },
  ]);
  const requiredChecks = trusted.commands.map(({ command }, index) => ({
    id: `C${index + 1}`,
    command,
  }));
  const finalization = {
    ...finalizationPassed(),
    requiredChecks,
    checks: requiredChecks.map(({ id, command }) => ({
      checkId: id,
      command,
      status: selected ? "NOT_RUN" : "PASS",
      evidence: [
        selected
          ? "Reserved for the runner-trusted executor."
          : "The Worker reports running C1 before C2.",
      ],
    })),
  };
  const bootstrap = (role) => ({ ...bootstrapReady(role), requiredChecks });
  const aliases = selected ? trusted.commands.map(({ alias }) => alias) : [];
  const events = [];
  const reviews = [];
  let service;
  let executions = 0;
  const fixture = await createFixture(t, {
    ...(selected
      ? { modeSettings: { trustedChecks: aliases }, trustedValidation: trusted }
      : {}),
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [implementationCompleted(), finalization],
    workReviewer: [reviewApproved(), terminalConfirmation(reviewApproved())],
    async prepareProject(path) {
      await writeFile(
        join(path, ".agents/skills/finalization/SKILL.md"),
        ORDER_GUIDANCE,
      );
    },
    async onTrustedValidation(request) {
      executions++;
      return service.execute(request);
    },
    onRoleRun(_role, request) {
      if (request.schema === REVIEW_SCHEMA) reviews.push(request);
    },
  });
  const workerRun = fixture.runtime.adapters.worker.run;
  fixture.runtime.adapters.worker.run = async (request) => {
    const response = await workerRun(request);
    if (request.schema === FINALIZATION_SCHEMA) events.push("worker-return");
    return response;
  };
  let active = 0;
  service = createTrustedValidationService({
    git: fixture.runtime.git,
    sandboxCommand: (command, { environment }) => ({ command, environment }),
    async runCommand(command) {
      assert.equal(active++, 0);
      events.push(`start ${command.alias}`);
      await new Promise(setImmediate);
      events.push(`end ${command.alias}`);
      active--;
      return {
        status: "PASS",
        exitCode: 0,
        signal: null,
        timedOut: false,
        reason: "exit",
      };
    },
  });
  const completed = await fixture.run({ trustedChecks: aliases });
  return {
    completed,
    events,
    executions: () => executions,
    fixture,
    reviews,
    trusted,
  };
}

// Scripted role outcomes prove serial execution, persisted attribution and
// terminal evidence delivery, not real-model compliance.
test("Runner-attributed serial trusted order reaches terminal review without an evidence rerun", async (t) => {
  const { completed, events, executions, fixture, reviews, trusted } =
    await serialOrderFixture(t, { selected: true });
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(events, [
    "worker-return",
    "start first-check",
    "end first-check",
    "start second-check",
    "end second-check",
  ]);
  const saved = completed.pipelineState.finalizationResult;
  assert.deepEqual(
    saved.checks.map(({ executor, commandIdentity }) => ({
      executor,
      commandIdentity,
    })),
    trusted.commands.map(({ identity }) => ({
      executor: "runner",
      commandIdentity: identity,
    })),
  );
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  assert.equal(executions(), 2);
  assert.equal(reviews.length, 1);
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "evidence-rejected",
    ).length,
    0,
  );
  for (const prompt of [reviews[0].prompt, reviews[0].recoveryPrompt]) {
    assert.match(prompt, /Runner's serial executor is the only exception/u);
    assert.match(
      prompt,
      /entries whose Runner-owned executor is "runner" therefore establish their relative physical order/u,
    );
    assert.match(
      prompt,
      /Never make an evidence-only rejection solely for missing timing telemetry or for relative order between Runner-attributed entries/u,
    );
  }
  assert.ok(reviews[0].prompt.includes(JSON.stringify(saved, null, 2)));
  const relabeled = structuredClone(completed);
  Object.assign(relabeled.pipelineState.finalizationResult.checks[0], {
    executor: "agent",
    commandIdentity: null,
    exitCode: null,
  });
  assert.throws(
    () => assertRun(relabeled),
    /does not bind the exact validation evidence/u,
  );
});

test("unselected checks keep agent attribution and establish no Runner order", async (t) => {
  const { completed, events, executions } = await serialOrderFixture(t, {
    selected: false,
  });
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.deepEqual(events, ["worker-return"]);
  assert.equal(executions(), 0);
  assert.deepEqual(
    completed.pipelineState.finalizationResult.checks.map(
      ({ executor, commandIdentity }) => ({ executor, commandIdentity }),
    ),
    [
      { executor: "agent", commandIdentity: null },
      { executor: "agent", commandIdentity: null },
    ],
  );
});
