import assert from "node:assert/strict";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  attachAvailability,
  availabilityFailure,
} from "../../../test/support/availability.js";
import { attachInactivity } from "../../../test/support/inactivity.js";
import {
  polishingPipeline,
  RESOLUTION_CORRECTION_INSTRUCTIONS,
  runPolishing,
} from "../src/index.js";
import { FINDING_RESOLUTION_SCHEMA } from "../src/schemas.js";
import {
  SETTINGS,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  createFixture,
  createRealStoreFixture,
  environmentBlocked,
  finalizationPassed,
  polishingCompleted,
  productDecision,
  reconciliationResolved,
  reconsideration,
  resolution,
  reviewApproved,
  reviewFindings,
} from "./support/index.js";

const REJECTED = "rejected-report-marker";
const REASON_EVIDENCE =
  "Worker field decisions[0].reason violated nonempty-plain-text-up-to-4000-characters.";
const LOST_EVIDENCE = "Worker field result violated interrupted-response.";

function invalidResolution(decision = "FIX") {
  const result = resolution(decision, "R1");
  return {
    ...result,
    decisions: result.decisions.map((entry) => ({
      ...entry,
      reason: `First line ${REJECTED}.\nSecond line.`,
    })),
  };
}

// A terminal R1 finding after one passing finalization; `refinalize` adds the
// finalization required after a content-changing correction.
function terminalFindingFlow(mode, resolutions, { refinalize = true } = {}) {
  const converge = mode === "combined" ? [checkAndFix(), candidateClean()] : [];
  return {
    mode,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      ...converge,
      finalizationPassed(),
      ...resolutions,
      ...converge,
      ...(refinalize ? [finalizationPassed()] : []),
    ],
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewFindings("R1"),
      candidateApproved(),
      reviewApproved(),
    ],
  };
}

function resolutionCalls(fixture) {
  return fixture.calls.worker.filter(
    ({ schema }) => schema === FINDING_RESOLUTION_SCHEMA,
  );
}

async function writeRepair(request, projectPath) {
  if (
    request.schema === FINDING_RESOLUTION_SCHEMA &&
    request.access === "workspace-write"
  ) {
    await writeFile(join(projectPath, "repair.txt"), "fixed\n");
  }
}

// Fail every later persistence once `stop()` is called, as a lost process.
function interruptible(fixture) {
  const loss = new Error("Simulated process loss.");
  const { transition, finishAgentTurn } = fixture.runtime;
  let stopped = false;
  fixture.runtime.transition = async (...args) => {
    if (stopped) throw loss;
    return transition(...args);
  };
  fixture.runtime.finishAgentTurn = async (...args) => {
    if (stopped) throw loss;
    return finishAgentTurn(...args);
  };
  return {
    loss,
    stop() {
      stopped = true;
      return loss;
    },
    restore() {
      stopped = false;
      fixture.runtime.transition = transition;
      fixture.runtime.finishAgentTurn = finishAgentTurn;
    },
  };
}

for (const mode of ["independent", "combined"]) {
  test(`${mode} restates an invalid content-changing resolution report once read-only`, async (t) => {
    const fixture = await createFixture(t, {
      ...terminalFindingFlow(mode, [
        invalidResolution(),
        resolution("FIX", "R1"),
      ]),
      onRoleRun: (_role, request, _turn, { projectPath }) =>
        writeRepair(request, projectPath),
    });

    const completed = await fixture.run();

    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    const calls = resolutionCalls(fixture);
    assert.deepEqual(
      calls.map(({ access }) => access),
      ["workspace-write", "read-only"],
    );
    assert.equal(calls[1].session, undefined);
    assert.ok(calls[1].prompt.includes(RESOLUTION_CORRECTION_INSTRUCTIONS));
    assert.match(calls[1].prompt, /"field": "decisions\[0\]\.reason"/u);
    // Combined check/fix convergence charges its own rounds around the repair.
    assert.equal(completed.counters.fixRounds, mode === "combined" ? 3 : 1);
    assert.equal(completed.pipelineState.resolutionCorrection, null);
    assert.equal(
      await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
      "fixed\n",
    );
    assert.ok(!JSON.stringify(fixture.transitions).includes(REJECTED));
  });
}

test("an unchanged restated FIX enters candidate convergence and charges once", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow(
      "independent",
      [invalidResolution(), resolution("FIX", "R1")],
      { refinalize: false },
    ),
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  const settled = fixture.transitions.find(
    ({ patch }) =>
      patch.pipelineState?.workflowState === "REVIEW" &&
      patch.pipelineState.pendingCorrection,
  ).patch.pipelineState;
  assert.equal(settled.resolutionCorrection, null);
  assert.equal(settled.candidateReviewedFingerprint, null);
  assert.equal(settled.reviewResult, null);
  assert.equal(settled.finalizationResult.status, "PASS");
});

test("a dispute-only restatement stays at finding resolution with its dispute", async (t) => {
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings(),
      reconsideration("WITHDRAW"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      invalidResolution("DISPUTE"),
      resolution("DISPUTE"),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 0);
  const settled = fixture.transitions.find(
    ({ patch }) =>
      patch.pipelineState?.pendingDisputes.length > 0 &&
      patch.pipelineState.resolutionCorrection === null,
  ).patch.pipelineState;
  assert.equal(settled.workflowState, "RESOLVE_FINDINGS");
  assert.deepEqual(
    settled.pendingDisputes.map(({ findingId }) => findingId),
    ["R1"],
  );
});

for (const lost of ["invoking", "ready"]) {
  test(`a lost ${lost} original report is reconciled once and restated without replay`, async (t) => {
    let process;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [
        ...(lost === "ready" ? [resolution("FIX", "R1")] : []),
        resolution("FIX", "R1"),
      ]),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        await writeRepair(request, projectPath);
        if (
          lost === "invoking" &&
          request.schema === FINDING_RESOLUTION_SCHEMA &&
          request.access === "workspace-write"
        ) {
          throw process.stop();
        }
      },
    });
    process = interruptible(fixture);
    if (lost === "ready") {
      const transition = fixture.runtime.transition;
      fixture.runtime.transition = async (...args) => {
        const next = await transition(...args);
        if (next.pipelineState.resolutionCorrection?.stage === "ready") {
          process.stop();
        }
        return next;
      };
    }

    await assert.rejects(fixture.run(), (error) => error === process.loss);
    assert.equal(fixture.currentRun.activeTurn.phase, "resolve-findings");
    assert.equal(
      fixture.currentRun.pipelineState.resolutionCorrection.stage,
      lost,
    );
    process.restore();
    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.counters.fixRounds, 1);
    const calls = resolutionCalls(fixture);
    assert.deepEqual(
      calls.map(({ access }) => access),
      ["workspace-write", "read-only"],
    );
    assert.match(calls[1].prompt, /"constraint": "interrupted-response"/u);
  });
}

for (const changed of [false, true]) {
  test(`an unclassified recoverable original failure ${changed ? "with" : "without"} changes is restated read-only`, async (t) => {
    let failed = false;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [resolution("FIX", "R1")], {
        refinalize: changed,
      }),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (
          failed ||
          request.schema !== FINDING_RESOLUTION_SCHEMA ||
          request.access !== "workspace-write"
        )
          return;
        failed = true;
        if (changed) await writeRepair(request, projectPath);
        throw Object.assign(new Error("Synthetic interrupted provider."), {
          code: "ERR_SYNTHETIC_PROVIDER_INTERRUPTED",
          recoverable: true,
          ambiguous: true,
        });
      },
    });

    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "backend_unavailable");
    assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(paused.activeTurn, null);
    const correction = paused.pipelineState.resolutionCorrection;
    assert.equal(correction.stage, "ready");
    assert.equal(correction.contentChanged, changed);
    assert.deepEqual(correction.diagnostics, [
      { field: "result", constraint: "interrupted-response" },
    ]);
    assert.deepEqual(
      paused.pipelineState.findings.map(({ id }) => id),
      ["R1"],
    );
    assert.equal(paused.counters.fixRounds, changed ? 1 : 0);

    const completed = await fixture.run();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.equal(completed.counters.fixRounds, 1);
    assert.deepEqual(
      resolutionCalls(fixture).map(({ access }) => access),
      ["workspace-write", "read-only"],
    );
  });
}

test("an unclassified failure during reconstruction after a timeout is restated read-only", async (t) => {
  let inactivity;
  let writable = 0;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [resolution("FIX", "R1")]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (
        request.schema !== FINDING_RESOLUTION_SCHEMA ||
        request.access !== "workspace-write"
      )
        return;
      writable += 1;
      if (writable === 1) return inactivity.expire(request);
      if (writable > 2) return;
      await writeRepair(request, projectPath);
      throw Object.assign(new Error("Synthetic interrupted provider."), {
        code: "ERR_SYNTHETIC_PROVIDER_INTERRUPTED",
        recoverable: true,
        ambiguous: true,
      });
    },
  });
  inactivity = await attachInactivity(fixture);

  const paused = await fixture.run();
  assert.notEqual(paused.inactivityRecovery.expiryRevision, null);
  const correction = paused.pipelineState.resolutionCorrection;
  assert.equal(correction?.stage, "ready", JSON.stringify(paused.pause));
  assert.equal(correction.contentChanged, true);
  assert.deepEqual(correction.diagnostics, [
    { field: "result", constraint: "interrupted-response" },
  ]);
  assert.equal(paused.counters.fixRounds, 1);

  inactivity.restart();
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(completed.counters.fixRounds, 1);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "workspace-write", "read-only"],
  );
});

test("process loss during a reconstructed original keeps the consumed allowance", async (t) => {
  let process;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [resolution("FIX", "R1")]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (
        request.schema !== FINDING_RESOLUTION_SCHEMA ||
        request.access !== "workspace-write"
      )
        return;
      assert.equal(await request.onFreshSession(), true);
      await writeRepair(request, projectPath);
      throw process.stop();
    },
  });
  const inactivity = await attachInactivity(fixture);
  process = interruptible(fixture);

  await assert.rejects(fixture.run(), (error) => error === process.loss);
  assert.equal(fixture.currentRun.inactivityRecovery.status, "reconstructing");
  assert.equal(fixture.currentRun.inactivityRecovery.expiryRevision, null);
  process.restore();
  inactivity.restart();
  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.code, "ERR_PROVIDER_RECONSTRUCTION_EXHAUSTED");
  const correction = paused.pipelineState.resolutionCorrection;
  assert.equal(correction.stage, "correcting");
  assert.equal(correction.fixCharged, true);
  assert.equal(paused.counters.fixRounds, 1);
  assert.equal(resolutionCalls(fixture).length, 1);

  inactivity.restart();
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(completed.inactivityRecovery, null);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
});

test("infrastructure drift during a restatement retains its unsettled checkpoint", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      resolution("FIX", "R1"),
    ]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      await writeRepair(request, projectPath);
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "read-only"
      ) {
        const fingerprint =
          fixture.runtime.git.validationInfrastructureFingerprint;
        fixture.runtime.git.validationInfrastructureFingerprint = async (
          options,
        ) => `${(await fingerprint(options)).slice(0, -1)}0`;
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  const correction = paused.pipelineState.resolutionCorrection;
  assert.equal(correction.stage, "correcting");
  assert.equal(correction.attempts, 1);
  assert.equal(correction.fixCharged, true);
  assert.deepEqual(
    paused.pipelineState.findings.map(({ id }) => id),
    ["R1"],
  );
  assert.equal(paused.pipelineState.pendingDisputes.length, 0);
  assert.equal(paused.counters.fixRounds, 1);
  assert.equal(resolutionCalls(fixture).length, 2);
});

test("operator stops settle the original and consume an interrupted restatement", async (t) => {
  let process;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", []),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (request.schema !== FINDING_RESOLUTION_SCHEMA) return;
      await writeRepair(request, projectPath);
      throw process.stop();
    },
  });
  process = interruptible(fixture);
  const stop = async () => {
    await assert.rejects(fixture.run(), (error) => error === process.loss);
    process.restore();
    const before = Object.values(fixture.calls).flat().length;
    const stopped = await runPolishing({
      run: fixture.currentRun,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.equal(Object.values(fixture.calls).flat().length, before);
    return stopped;
  };

  const original = await stop();
  assert.equal(original.activeTurn, null);
  assert.equal(original.pipelineState.workflowState, "RESOLVE_FINDINGS");
  assert.deepEqual(
    original.pipelineState.findings.map(({ id }) => id),
    ["R1"],
  );
  assert.equal(original.pipelineState.resolutionCorrection.stage, "ready");
  assert.equal(original.counters.fixRounds, 1);

  process = interruptible(fixture);
  const exhausted = await stop();
  assert.equal(exhausted.activeTurn, null);
  assert.equal(exhausted.pipelineState.resolutionCorrection.stage, "exhausted");
  assert.equal(exhausted.pipelineState.resolutionCorrection.attempts, 1);
  assert.equal(exhausted.pause.reason, "resolution_output_invalid");
  assert.deepEqual(exhausted.pause.evidence, [LOST_EVIDENCE]);
  assert.equal(exhausted.counters.fixRounds, 1);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
});

test("a lost restatement without a stop exhausts without invocation", async (t) => {
  let process;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [invalidResolution()]),
    async onRoleRun(_role, request) {
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "read-only"
      ) {
        throw process.stop();
      }
    },
  });
  process = interruptible(fixture);

  await assert.rejects(fixture.run(), (error) => error === process.loss);
  assert.equal(
    fixture.currentRun.pipelineState.resolutionCorrection.stage,
    "correcting",
  );
  process.restore();
  const exhausted = await fixture.run();

  assert.equal(exhausted.pause.reason, "resolution_output_invalid");
  assert.equal(exhausted.activeTurn, null);
  assert.deepEqual(exhausted.pause.evidence, [LOST_EVIDENCE]);
  assert.equal(resolutionCalls(fixture).length, 2);
});

for (const loss of ["lost", "stopped"]) {
  test(`a ${loss} restatement is not reauthorized by retained availability evidence`, async (t) => {
    let process;
    let original = 0;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", []),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (request.schema !== FINDING_RESOLUTION_SCHEMA) return;
        if (request.access === "read-only") throw process.stop();
        original += 1;
        if (original === 1) throw availabilityFailure();
        await writeRepair(request, projectPath);
        throw Object.assign(new Error("Synthetic interrupted provider."), {
          code: "ERR_SYNTHETIC_PROVIDER_INTERRUPTED",
          recoverable: true,
          ambiguous: true,
        });
      },
    });
    attachAvailability(fixture);
    process = interruptible(fixture);

    const ready = await fixture.run();
    assert.equal(ready.pipelineState.resolutionCorrection.stage, "ready");
    const episode = ready.availabilityRetry;
    assert.equal(episode.checkpoint, "resolve-findings:workspace-write:work");
    await assert.rejects(fixture.run(), (error) => error === process.loss);
    process.restore();
    assert.equal(fixture.currentRun.activeTurn.phase, "resolve-findings");
    assert.equal(
      fixture.currentRun.pipelineState.resolutionCorrection.stage,
      "correcting",
    );

    const exhausted =
      loss === "stopped"
        ? await runPolishing({
            run: fixture.currentRun,
            runtime: fixture.runtime,
            operatorStop: true,
          })
        : await fixture.run();
    assert.equal(exhausted.activeTurn, null);
    assert.equal(exhausted.pause.reason, "resolution_output_invalid");
    assert.deepEqual(exhausted.pause.evidence, [LOST_EVIDENCE]);
    const correction = exhausted.pipelineState.resolutionCorrection;
    assert.equal(correction.stage, "exhausted");
    assert.equal(correction.attempts, 1);
    assert.equal(correction.additionalAttempts, 0);
    assert.deepEqual(exhausted.availabilityRetry, episode);
    assert.equal(exhausted.counters.fixRounds, 1);
    assert.deepEqual(
      resolutionCalls(fixture).map(({ access }) => access),
      ["workspace-write", "workspace-write", "read-only"],
    );
  });
}

test("an unclassified interrupted restatement is lost and retried only explicitly", async (t) => {
  let failed = false;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      resolution("FIX", "R1"),
    ]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      await writeRepair(request, projectPath);
      if (
        !failed &&
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "read-only"
      ) {
        failed = true;
        throw Object.assign(new Error("Synthetic interrupted provider."), {
          code: "ERR_SYNTHETIC_PROVIDER_INTERRUPTED",
          recoverable: true,
        });
      }
    },
  });

  const lost = await fixture.run();
  assert.equal(lost.pause.reason, "resolution_output_invalid");
  assert.deepEqual(lost.pause.evidence, [LOST_EVIDENCE]);
  assert.equal(lost.activeTurn, null);
  assert.equal(lost.pipelineState.resolutionCorrection.attempts, 1);
  assert.equal(lost.counters.fixRounds, 1);

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
  );
});

test("a terminal provider rejection of a restatement keeps its failure", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [invalidResolution()]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      await writeRepair(request, projectPath);
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "read-only"
      ) {
        throw Object.assign(new Error("Synthetic rejected provider."), {
          code: "ERR_SYNTHETIC_PROVIDER_REJECTED",
        });
      }
    },
  });

  await assert.rejects(
    fixture.run(),
    ({ code }) => code === "ERR_SYNTHETIC_PROVIDER_REJECTED",
  );
  const failed = fixture.currentRun;
  assert.equal(failed.pipelineState.workflowState, "FAILED");
  assert.equal(failed.pause.reason, "internal_failure");
  assert.equal(failed.pause.code, "ERR_SYNTHETIC_PROVIDER_REJECTED");
  assert.equal(failed.pipelineState.resolutionCorrection.stage, "correcting");
  assert.equal(resolutionCalls(fixture).length, 2);
});

for (const loss of ["returned", "ownerless"]) {
  test(`guidance drift in a ${loss} original resolution retains its reservation`, async (t) => {
    let process;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow(
        "independent",
        loss === "returned" ? [resolution("FIX", "R1")] : [],
      ),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (request.schema !== FINDING_RESOLUTION_SCHEMA) return;
        await writeRepair(request, projectPath);
        await writeFile(
          join(projectPath, ".agents", "skills", "finalization", "SKILL.md"),
          "---\nname: finalization\ndescription: Changed checks.\n---\n",
        );
        if (loss === "ownerless") throw process.stop();
      },
    });
    process = interruptible(fixture);
    if (loss === "ownerless") {
      await assert.rejects(fixture.run(), (error) => error === process.loss);
      process.restore();
    }

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "finalization_skill_invalid");
    assert.equal(paused.activeTurn, null);
    const correction = paused.pipelineState.resolutionCorrection;
    assert.equal(correction.stage, "invoking");
    assert.equal(correction.fixCharged, false);
    assert.deepEqual(
      paused.pipelineState.findings.map(({ id }) => id),
      ["R1"],
    );
    assert.equal(
      paused.pipelineState.repositoryBaseline.contentFingerprint,
      correction.beforeFingerprint,
    );
    assert.equal(paused.counters.fixRounds, 0);

    const stopped = await runPolishing({
      run: paused,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.equal(stopped.pipelineState.resolutionCorrection.stage, "ready");
    assert.equal(stopped.pipelineState.resolutionCorrection.fixCharged, true);
    assert.equal(stopped.counters.fixRounds, 1);
    assert.equal(resolutionCalls(fixture).length, 1);
  });
}

for (const drift of ["input", "guidance"]) {
  test(`${drift} drift during report recovery retains the checkpoint`, async (t) => {
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [
        invalidResolution(),
        invalidResolution(),
      ]),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        await writeRepair(request, projectPath);
        if (
          drift === "input" &&
          request.schema === FINDING_RESOLUTION_SCHEMA &&
          request.access === "read-only"
        ) {
          await appendFile(join(fixture.taskPath, "task.md"), "Drift.\n");
        }
      },
    });

    let paused = await fixture.run();
    if (drift === "guidance") {
      assert.equal(paused.pause.reason, "resolution_output_invalid");
      await writeFile(
        join(
          fixture.projectPath,
          ".agents",
          "skills",
          "finalization",
          "SKILL.md",
        ),
        "---\nname: finalization\ndescription: Changed checks.\n---\n",
      );
      paused = await fixture.run();
    }

    assert.equal(
      paused.pause.reason,
      drift === "input" ? "task_input_changed" : "finalization_skill_invalid",
    );
    const correction = paused.pipelineState.resolutionCorrection;
    assert.equal(
      correction.stage,
      drift === "input" ? "correcting" : "exhausted",
    );
    assert.equal(correction.attempts, 1);
    assert.equal(correction.fixCharged, true);
    assert.deepEqual(
      paused.pipelineState.findings.map(({ id }) => id),
      ["R1"],
    );
    assert.equal(paused.counters.fixRounds, 1);
    assert.equal(resolutionCalls(fixture).length, 2);
  });
}

test("a blocked restatement survives a cold reload and one explicit retry", async (t) => {
  const fixture = await createRealStoreFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      environmentBlocked(
        "The original dispositions cannot be established safely.",
        "The repository does not show which blocker the edit addressed.",
      ),
      resolution("FIX", "R1"),
    ]),
    onRoleRun: (_role, request, _turn, { projectPath }) =>
      writeRepair(request, projectPath),
  });

  const blocked = await fixture.run();
  assert.equal(blocked.pause.reason, "environment_blocked");
  assert.equal(blocked.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(blocked.pipelineState.resolutionCorrection.stage, "blocked");

  const reloaded = await fixture.recover();
  assert.deepEqual(polishingPipeline.projections.pause(reloaded).nextActions, [
    { type: "resume", action: null },
  ]);
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
  );
  const retried = fixture.transitions.find(
    ({ patch }) =>
      patch.pipelineState?.resolutionCorrection?.additionalAttempts === 1,
  ).patch.pipelineState.resolutionCorrection;
  assert.equal(retried.stage, "correcting");
  assert.equal(retried.attempts, 2);
});

test("an interrupted product-decision restatement settles its journaled append", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      productDecision({
        status: "PRODUCT_DECISION_REQUIRED",
        decisions: [],
        reason: "",
      }),
    ]),
  });
  const process = interruptible(fixture);
  const transition = fixture.runtime.transition;
  fixture.runtime.transition = async (patch, options) => {
    if (patch.pause?.reason === "product_decision_required") process.stop();
    return transition(patch, options);
  };

  await assert.rejects(fixture.run(), (error) => error === process.loss);
  const pending =
    fixture.currentRun.pipelineState.resolutionCorrection.productDecision;
  assert.notEqual(pending.resultHash, null);
  process.restore();
  const calls = Object.values(fixture.calls).flat().length;
  const suspended = await fixture.run();

  assert.equal(suspended.pause.reason, "product_decision_required");
  assert.equal(suspended.pipelineState.resolutionCorrection, null);
  assert.equal(suspended.counters.productDecisions, 1);
  assert.equal(suspended.hashes.executionClarifications, pending.resultHash);
  assert.equal(Object.values(fixture.calls).flat().length, calls);
  const transcript = await readFile(
    suspended.pipelineState.clarificationPath,
    "utf8",
  );
  assert.equal(transcript.match(/## Product Decision 1/gu).length, 1);
});

test("infrastructure drift retains an unappended product-decision intent", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      productDecision({
        status: "PRODUCT_DECISION_REQUIRED",
        decisions: [],
        reason: "",
      }),
    ]),
  });
  const process = interruptible(fixture);
  const transition = fixture.runtime.transition;
  fixture.runtime.transition = async (patch, options) => {
    const next = await transition(patch, options);
    if (
      next.pipelineState.resolutionCorrection?.productDecision?.resultHash ===
      null
    )
      process.stop();
    return next;
  };

  await assert.rejects(fixture.run(), (error) => error === process.loss);
  process.restore();
  const transcriptPath = fixture.currentRun.pipelineState.clarificationPath;
  const transcript = await readFile(transcriptPath, "utf8");
  const fingerprint = fixture.runtime.git.validationInfrastructureFingerprint;
  fixture.runtime.git.validationInfrastructureFingerprint = async (options) =>
    `${(await fingerprint(options)).slice(0, -1)}0`;
  const calls = Object.values(fixture.calls).flat().length;
  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.equal(paused.pause.code, "ERR_RESOLUTION_CORRECTION_SCOPE_CHANGED");
  const intent = paused.pipelineState.resolutionCorrection.productDecision;
  assert.equal(intent.resultHash, null);
  assert.equal(paused.counters.productDecisions, 0);
  assert.equal(await readFile(transcriptPath, "utf8"), transcript);
  assert.equal(Object.values(fixture.calls).flat().length, calls);
});

test("a repeated invalid restatement pauses and one explicit retry is consumed", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      invalidResolution(),
      invalidResolution(),
    ]),
  });

  const exhausted = await fixture.run();
  assert.equal(exhausted.pause.reason, "resolution_output_invalid");
  assert.deepEqual(exhausted.pause.evidence, [REASON_EVIDENCE]);
  const projected = polishingPipeline.projections.pause(exhausted);
  assert.deepEqual(projected.evidence, [REASON_EVIDENCE]);
  assert.equal(projected.resumeState, "RESOLVE_FINDINGS");
  assert.deepEqual(projected.nextActions, [{ type: "resume", action: null }]);
  assert.throws(() =>
    polishingPipeline.validateResumeAction(exhausted, {
      type: "extra-fix-rounds",
      amount: 1,
    }),
  );
  assert.equal(resolutionCalls(fixture).length, 2);

  const repeated = await fixture.run();
  assert.equal(repeated.pause.reason, "resolution_output_invalid");
  assert.equal(repeated.pipelineState.resolutionCorrection.attempts, 2);
  assert.equal(
    repeated.pipelineState.resolutionCorrection.additionalAttempts,
    1,
  );
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
  );
  assert.ok(!JSON.stringify(fixture.currentRun).includes(REJECTED));
});

test("content drift before a restatement pauses without invocation", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [invalidResolution()]),
  });
  const transition = fixture.runtime.transition;
  fixture.runtime.transition = async (...args) => {
    const next = await transition(...args);
    if (next.pipelineState.resolutionCorrection?.stage === "ready") {
      await writeFile(join(fixture.projectPath, "drift.txt"), "drift\n");
    }
    return next;
  };

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "unsafe_git_state");
  assert.equal(paused.pipelineState.resolutionCorrection.stage, "ready");
  assert.equal(resolutionCalls(fixture).length, 1);
  assert.deepEqual(polishingPipeline.projections.pause(paused).nextActions, []);
});

test("an exhausted-budget read-only original restated as FIX reaches the fix limit", async (t) => {
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxFixRounds: 1 },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings("R1"),
      reviewFindings("R1"),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      resolution("FIX", "R1"),
      invalidResolution(),
      resolution("FIX", "R1"),
    ],
    onRoleRun: (_role, request, _turn, { projectPath }) =>
      writeRepair(request, projectPath),
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.counters.fixRounds, 1);
  assert.equal(paused.pipelineState.resolutionCorrection, null);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
  );
});

test("a restatement backoff kept at its original checkpoint resumes after process loss", async (t) => {
  let process;
  let original = 0;
  let restated = 0;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [resolution("FIX", "R1")]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (request.schema !== FINDING_RESOLUTION_SCHEMA) return;
      if (request.access === "workspace-write") {
        original += 1;
        if (original === 1) throw availabilityFailure();
        await writeRepair(request, projectPath);
        throw Object.assign(new Error("Synthetic interrupted provider."), {
          code: "ERR_SYNTHETIC_PROVIDER_INTERRUPTED",
          recoverable: true,
          ambiguous: true,
        });
      }
      restated += 1;
      if (restated === 1) throw availabilityFailure();
    },
  });
  attachAvailability(fixture, {
    async onSchedule(next) {
      if (next.pipelineState.resolutionCorrection?.stage === "correcting")
        throw process.stop();
    },
  });
  process = interruptible(fixture);

  const lost = await fixture.run();
  assert.equal(lost.pipelineState.resolutionCorrection.stage, "ready");
  assert.equal(
    lost.availabilityRetry.checkpoint,
    "resolve-findings:workspace-write:work",
  );
  await assert.rejects(fixture.run());
  process.restore();
  const interrupted = fixture.currentRun;
  assert.equal(interrupted.activeTurn, null);
  const consumed = interrupted.pipelineState.resolutionCorrection;
  assert.equal(consumed.stage, "correcting");
  assert.equal(consumed.attempts, 1);
  assert.equal(
    interrupted.availabilityRetry.checkpoint,
    "resolve-findings:workspace-write:work",
  );

  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(completed.availabilityRetry, null);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "workspace-write", "read-only", "read-only"],
  );
});

test("a classified retry settles an earlier partial write as changed content", async (t) => {
  let unavailable = true;
  const fixture = await createFixture(t, {
    reviewer: [
      bootstrapReady("Reviewer"),
      candidateApproved(),
      reviewFindings("R1"),
      candidateApproved(),
      reconsideration("WITHDRAW"),
      reviewApproved(),
    ],
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationResolved(),
      polishingCompleted(),
      finalizationPassed(),
      invalidResolution("DISPUTE"),
      resolution("DISPUTE", "R1"),
      finalizationPassed(),
    ],
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (request.schema === FINDING_RESOLUTION_SCHEMA && unavailable) {
        unavailable = false;
        await writeRepair(request, projectPath);
        throw availabilityFailure();
      }
    },
  });
  attachAvailability(fixture);

  const completed = await fixture.run();

  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(completed.counters.fixRounds, 1);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "workspace-write", "read-only"],
  );
  const settled = fixture.transitions.find(
    ({ patch }) =>
      patch.pipelineState?.pendingDisputes.length > 0 &&
      patch.pipelineState.resolutionCorrection === null,
  ).patch.pipelineState;
  assert.equal(settled.workflowState, "REVIEW");
  assert.equal(settled.pendingCorrection, true);
});
