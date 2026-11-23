import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  reconcileOperatorStop,
  restoreOperatorPause,
} from "../../../src/runner/stops.js";
import { matchesObservedInactivityExpiry } from "../../../src/state/index.js";
import { nextCatalogResume } from "../../../src/state/model-completion.js";
import { beginObservationAttempt } from "../../../src/state/observations.js";
import {
  attachAuthentication,
  authenticationFailure,
} from "../../../test/support/authentication.js";
import {
  attachAvailability,
  availabilityFailure,
} from "../../../test/support/availability.js";
import { attachInactivity } from "../../../test/support/inactivity.js";
import { modelCatalogMiss } from "../../../test/support/model-catalog.js";
import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";
import {
  polishingPipeline,
  RESOLUTION_CORRECTION_INSTRUCTIONS,
  runPolishing,
} from "../src/index.js";
import {
  FINDING_RESOLUTION_SCHEMA,
  FINDING_RECOVERY_SCHEMA,
} from "../src/schemas.js";
import {
  CATALOG_RESOLUTION_DIAGNOSTIC,
  normalizeResolutionResult,
  RESOLUTION_CORRECTION_CHECKPOINT,
} from "../src/workflow-contract.js";
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
  matchesSchemaSubset,
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
const unfinished = () => ({
  status: "UNFINISHED",
  decisions: [],
  reason: "The original repair remains necessary.",
  question: "",
  options: [],
  whyBlocked: "",
  evidence: ["The preserved candidate still contains blocker R1."],
});

test("unfinished is recovery-only and rejects dispositions or unsupported authority claims", () => {
  const normalize = (payload) =>
    normalizeResolutionResult(payload, [{ id: "R1" }], new Set(), {
      recoveryOnly: true,
    });
  assert.doesNotThrow(() => normalize(unfinished()));
  assert.equal(
    matchesSchemaSubset(FINDING_RECOVERY_SCHEMA, unfinished()),
    true,
  );
  assert.equal(
    matchesSchemaSubset(FINDING_RESOLUTION_SCHEMA, unfinished()),
    false,
  );
  assert.throws(() =>
    normalizeResolutionResult(unfinished(), [{ id: "R1" }], new Set()),
  );
  for (const patch of [
    { decisions: resolution("FIX", "R1").decisions },
    { evidence: [] },
    { reason: "" },
    { question: "New question" },
  ]) {
    assert.throws(() => normalize({ ...unfinished(), ...patch }), {
      code: "ERR_INVALID_POLISHING_OUTPUT",
    });
  }
});

test("legacy blocked recovery preserves unfinished bytes until one new repair is authorized", async (t) => {
  let writes = 0;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      environmentBlocked(
        "Required inspection evidence is unavailable.",
        "Resolve the inspection prerequisite before retrying.",
      ),
      unfinished(),
      resolution("FIX", "R1"),
    ]),
    settings: { ...SETTINGS, maxFixRounds: 1 },
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (
        request.schema === FINDING_RESOLUTION_SCHEMA &&
        request.access === "workspace-write"
      ) {
        writes++;
        await writeFile(
          join(projectPath, "repair.txt"),
          writes === 1 ? "unfinished\n" : "fixed\n",
        );
        if (writes === 2) throw availabilityFailure();
      }
    },
  });
  const availability = attachAvailability(fixture);
  const blocked = await fixture.run();
  assert.equal(blocked.pause.reason, "environment_blocked");
  const legacy = structuredClone(blocked.pipelineState);
  legacy.resolutionCorrection.schemaVersion = 1;
  delete legacy.resolutionCorrection.repair;
  delete legacy.resolutionCorrection.factsFingerprint;
  const migrated = polishingPipeline.migrations[24]({ pipelineState: legacy });
  assert.deepEqual(migrated, blocked.pipelineState);
  assert.throws(() => polishingPipeline.migrations[24](blocked));
  await fixture.persistPipelineState(migrated);
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "finding_repair_required");
  assert.equal(paused.activeTurn, null);
  const checkpoint = paused.pipelineState.resolutionCorrection;
  assert.equal(checkpoint.stage, "repair-required");
  assert.equal(checkpoint.blockers[0].id, "R1");
  assert.equal(checkpoint.attempts, 2);
  assert.equal(checkpoint.additionalAttempts, 1);
  assert.equal(paused.counters.fixRounds, 1);
  assert.equal(
    await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
    "unfinished\n",
  );
  assert.deepEqual(polishingPipeline.projections.pause(paused).nextActions, [
    { type: "resume", action: null },
  ]);
  for (const mutate of [
    (run) => {
      run.pipelineState.resolutionCorrection.repair = null;
    },
    (run) => {
      run.pipelineState.resolutionCorrection.attempts--;
    },
    (run) => {
      run.pipelineState.workReports.at(-1).recovery.previous =
        checkpoint.repair;
    },
    (run) => {
      run.pipelineState.requiredChecks[0].command = "node other-check.js";
    },
    (run) => {
      run.activeTurn = { role: "worker", phase: "resolve-findings" };
    },
  ]) {
    const rejected = structuredClone(paused);
    mutate(rejected);
    assert.throws(() => polishingPipeline.workflow.validateRun(rejected), {
      code: "ERR_INVALID_POLISHING_STATE",
    });
  }
  const exhausted = await fixture.run();
  assert.equal(exhausted.pause.reason, "resolution_output_invalid");
  assert.equal(availability.scheduled.length, 1);
  assert.equal(writes, 2);
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.equal(done.counters.fixRounds, 1);
  assert.equal(
    await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
    "fixed\n",
  );
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    [
      "workspace-write",
      "read-only",
      "read-only",
      "workspace-write",
      "read-only",
    ],
  );
  const authorization = fixture.transitions.findIndex(
    ({ patch }) =>
      patch.pipelineState?.resolutionCorrection?.stage === "repair-authorized",
  );
  assert.ok(authorization >= 0);
  const reservation =
    fixture.transitions[authorization].patch.pipelineState.resolutionCorrection;
  assert.equal(reservation.attempts, 2);
  assert.equal(reservation.additionalAttempts, 1);
  assert.equal(fixture.calls.reviewer.length, 5); // Bootstrap, original candidate and terminal, renewed candidate and terminal.
  assert.ok(
    done.pipelineState.workReports.some(
      ({ status }) => status === "UNFINISHED",
    ),
  );
});

for (const [reason, attach, failure] of [
  ["authentication_required", attachAuthentication, authenticationFailure],
  ["output_exhausted", attachOutputExhaustion, outputExhaustion],
  ["resolution_output_invalid", null, modelCatalogMiss],
]) {
  test(`${reason} during a continued repair retains its consumed recovery checkpoint`, async (t) => {
    const catalog = attach === null;
    const failureCause = failure();
    let writes = 0;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [
        invalidResolution(),
        unfinished(),
        resolution("FIX", "R1"),
      ]),
      settings: { ...SETTINGS, maxFixRounds: 1 },
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (!isResolution(request) || request.access !== "workspace-write")
          return;
        writes++;
        if (catalog && writes === 2) throw failureCause;
        await writeFile(
          join(projectPath, "repair.txt"),
          writes === 1 ? "unfinished\n" : "fixed\n",
        );
        if (writes === 2) throw failureCause;
      },
    });
    if (catalog) {
      const code = "ERR_MODEL_CATALOG_RETRY";
      fixture.runtime.catalogRetry = {
        code,
        eligible: (cause) => cause === failureCause,
        hasWritableNoEffect: ({ phase }) => phase === "resolve-findings",
        hasPossibleEffect: () => false,
        resuming: () => false,
        claimResume: () => false,
        details: (role, checkpoint) => ({ code, role, checkpoint }),
      };
    } else attach(fixture);
    const required = await fixture.run();
    assert.equal(required.pause.reason, "finding_repair_required");
    const predecessor = required.pipelineState.resolutionCorrection;

    const paused = await fixture.run();
    assert.equal(paused.pause.reason, reason);
    assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
    assert.equal(paused.activeTurn, null);
    const checkpoint = paused.pipelineState.resolutionCorrection;
    assert.equal(checkpoint?.stage, catalog ? "exhausted" : "ready");
    assert.equal(checkpoint.repair, predecessor.repair);
    assert.deepEqual(checkpoint.blockers, predecessor.blockers);
    assert.equal(checkpoint.attempts, predecessor.attempts);
    assert.equal(checkpoint.additionalAttempts, predecessor.additionalAttempts);
    assert.equal(checkpoint.fixCharged, false); // The pending round was already charged.
    assert.equal(paused.pipelineState.pendingCorrection, true);
    assert.equal(paused.counters.fixRounds, 1);
    assert.equal(
      await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
      catalog ? "unfinished\n" : "fixed\n",
    );

    // The first read-only recovery allowance is still consumed.
    const exhausted = catalog ? paused : await fixture.run();
    assert.equal(exhausted.pause.reason, "resolution_output_invalid");
    assert.deepEqual(
      polishingPipeline.projections.pause(exhausted).nextActions,
      [{ type: "resume", action: null }],
    );
    assert.equal(writes, 2);
    assert.equal(resolutionCalls(fixture).length, 3);
    const completed = await fixture.run();
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.equal(completed.counters.fixRounds, 1);
    assert.deepEqual(
      resolutionCalls(fixture).map(({ access }) => access),
      ["workspace-write", "read-only", "workspace-write", "read-only"],
    );
    assert.equal(fixture.calls.reviewer.length, 5);
    assert.deepEqual(
      completed.pipelineState.workReports.find(
        ({ status }) => status === "UNFINISHED",
      ),
      required.pipelineState.workReports.at(-1),
    );
  });
}

test("lost repair-authorization acknowledgement preserves durable unstarted authority", async (t) => {
  let writes = 0;
  const fixture = await createRealStoreFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      unfinished(),
      resolution("FIX", "R1"),
    ]),
    settings: { ...SETTINGS, maxFixRounds: 1 },
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (!isResolution(request) || request.access !== "workspace-write")
        return;
      writes++;
      await writeFile(
        join(projectPath, "repair.txt"),
        writes === 1 ? "unfinished\n" : "fixed\n",
      );
    },
  });
  const required = await fixture.run();
  assert.equal(required.pause.reason, "finding_repair_required");
  const coldRequired = await fixture.recover();
  assert.deepEqual(coldRequired, required);
  assert.equal(coldRequired.activeTurn, null);
  assert.equal(
    coldRequired.pipelineState.resolutionCorrection.stage,
    "repair-required",
  );
  assert.equal(
    await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
    "unfinished\n",
  );
  const transition = fixture.runtime.transition;
  const loss = new Error("Synthetic authorization acknowledgement loss.");
  let lost = false;
  fixture.runtime.transition = async (...args) => {
    const next = await transition(...args);
    if (
      !lost &&
      next.pipelineState.resolutionCorrection?.stage === "repair-authorized"
    ) {
      lost = true;
      throw loss;
    }
    return next;
  };

  await assert.rejects(fixture.run(), (cause) => cause === loss);
  const reloaded = await fixture.recover();
  assert.equal(reloaded.pipelineState.workflowState, "RESOLVE_FINDINGS");
  assert.equal(reloaded.pause, null);
  assert.equal(reloaded.activeTurn, null);
  assert.equal(
    reloaded.pipelineState.resolutionCorrection.stage,
    "repair-authorized",
  );
  assert.deepEqual(reloaded.pipelineState.resolutionCorrection, {
    ...required.pipelineState.resolutionCorrection,
    stage: "repair-authorized",
  });
  assert.deepEqual(
    reloaded.pipelineState.workReports,
    required.pipelineState.workReports,
  );
  assert.equal(reloaded.counters.fixRounds, 1);
  for (const field of [
    "repositoryBaseline",
    "requiredChecks",
    "validationInfrastructure",
    "pendingCorrection",
  ])
    assert.deepEqual(
      reloaded.pipelineState[field],
      required.pipelineState[field],
      field,
    );
  assert.deepEqual(reloaded.hashes, required.hashes);
  assert.deepEqual(reloaded.roles, required.roles);
  assert.equal(writes, 1);
  const completed = await fixture.run();
  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify(completed.pause),
  );
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(writes, 2);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "workspace-write"],
  );
  assert.equal(fixture.calls.reviewer.length, 5);
  const history = required.pipelineState.workReports.at(-1);
  assert.equal(history.status, "UNFINISHED");
  assert.deepEqual(
    completed.pipelineState.workReports.find(
      ({ status }) => status === "UNFINISHED",
    ),
    history,
  );
  const terminal = fixture.calls.reviewer.at(-1).recoveryPrompt;
  assert.ok(terminal.includes(history.reason));
  assert.ok(terminal.includes(history.evidence[0]));
});

for (const publication of [
  "invocation",
  "reconciliation",
  "retirement",
  "session",
  "restatement",
]) {
  test(`lost repair ${publication} acknowledgement preserves consumed authority for read-only recovery`, async (t) => {
    let writes = 0;
    const fixture = await createRealStoreFixture(t, {
      ...terminalFindingFlow("independent", [
        invalidResolution(),
        unfinished(),
        publication === "invocation"
          ? unfinished()
          : publication === "restatement"
            ? invalidResolution()
            : resolution("FIX", "R1"),
        resolution("FIX", "R1"),
      ]),
      settings: { ...SETTINGS, maxFixRounds: 1 },
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (!isResolution(request) || request.access !== "workspace-write")
          return;
        writes++;
        await writeFile(
          join(projectPath, "repair.txt"),
          writes === 1 ? "unfinished\n" : "fixed\n",
        );
      },
    });
    const required = await fixture.run();
    assert.equal(required.pause.reason, "finding_repair_required");
    const method = {
      invocation: "startAgentTurn",
      reconciliation: "transition",
      retirement: "finishAgentTurn",
      session: "recordChildSession",
      restatement: "startAgentTurn",
    }[publication];
    const publish = fixture.runtime[method];
    const loss = new Error("Synthetic repair acknowledgement loss.");
    const publishedStage = {
      invocation: "invoking",
      reconciliation: "ready",
      retirement: "ready",
      session: "ready",
      restatement: "correcting",
    }[publication];
    fixture.runtime[method] = async (...args) => {
      const next = await publish(...args);
      if (
        next.pipelineState.resolutionCorrection?.repair != null &&
        next.pipelineState.resolutionCorrection.stage === publishedStage
      )
        throw loss;
      return next;
    };
    if (publication === "restatement") {
      const exhausted = await fixture.run();
      assert.equal(exhausted.pause.reason, "resolution_output_invalid");
      assert.equal(writes, 2);
    }
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    const reloaded = await fixture.recover();
    assert.equal(reloaded.pipelineState.workflowState, "RESOLVE_FINDINGS");
    assert.equal(reloaded.pause, null);
    assert.deepEqual(
      reloaded.activeTurn,
      ["invocation", "reconciliation", "restatement"].includes(publication)
        ? { role: "worker", phase: "resolve-findings" }
        : null,
    );
    assert.equal(
      reloaded.pipelineState.resolutionCorrection.stage,
      publishedStage,
    );
    assert.equal(
      reloaded.pipelineState.resolutionCorrection.repair,
      required.pipelineState.resolutionCorrection.repair,
    );
    const consumedRetry = publication === "restatement" ? 1 : 0;
    for (const field of ["attempts", "additionalAttempts"]) {
      assert.equal(
        reloaded.pipelineState.resolutionCorrection[field],
        required.pipelineState.resolutionCorrection[field] + consumedRetry,
      );
    }
    assert.equal(reloaded.counters.fixRounds, 1);
    assert.deepEqual(
      reloaded.pipelineState.resolutionCorrection.blockers,
      required.pipelineState.resolutionCorrection.blockers,
    );
    assert.deepEqual(
      reloaded.pipelineState.workReports,
      required.pipelineState.workReports,
    );
    const expectedWrites = publication === "invocation" ? 1 : 2;
    assert.equal(writes, expectedWrites);
    const exhausted = await fixture.run();
    assert.equal(exhausted.pause.reason, "resolution_output_invalid");
    assert.equal(exhausted.activeTurn, null);
    assert.equal(writes, expectedWrites);
    let completed = await fixture.run();
    if (publication === "invocation") {
      assert.equal(completed.pause.reason, "finding_repair_required");
      assert.equal(writes, expectedWrites);
      assert.equal(
        await readFile(join(fixture.projectPath, "repair.txt"), "utf8"),
        "unfinished\n",
      );
      completed = await fixture.run();
    }
    assert.equal(
      completed.pipelineState.workflowState,
      "DONE",
      JSON.stringify(completed.pause),
    );
    assert.equal(completed.counters.fixRounds, 1);
    assert.equal(writes, 2);
    assert.deepEqual(
      resolutionCalls(fixture).map(({ access }) => access),
      publication === "invocation"
        ? ["workspace-write", "read-only", "read-only", "workspace-write"]
        : ["workspace-write", "read-only", "workspace-write", "read-only"],
    );
    assert.equal(fixture.calls.reviewer.length, 5);
  });
}

test("an uncharged unfinished repair requires only its eligible explicit fix-budget grant", async (t) => {
  const fixture = await createFixture(t, {
    settings: { ...SETTINGS, maxFixRounds: 1 },
    reviewer: [
      bootstrapReady("Reviewer"),
      reviewFindings("R1"),
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
      invalidResolution(),
      unfinished(),
      resolution("FIX", "R1"),
      finalizationPassed(),
    ],
    onRoleRun: (_role, request, _turn, { projectPath }) =>
      writeRepair(request, projectPath),
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(
    paused.pipelineState.resolutionCorrection.stage,
    "repair-required",
  );
  assert.equal(paused.pipelineState.resolutionCorrection.access, "read-only");
  assert.equal(paused.pipelineState.pendingCorrection, false);
  assert.throws(() => polishingPipeline.validateResumeAction(paused, null));
  assert.throws(() =>
    polishingPipeline.validateResumeAction(paused, {
      type: "override-finding",
      findingId: "R1",
    }),
  );
  assert.deepEqual(polishingPipeline.projections.pause(paused).nextActions, [
    { type: "resume", action: { type: "extra-fix-rounds", amount: 1 } },
  ]);
  const done = await fixture.run({ type: "extra-fix-rounds", amount: 1 });
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.equal(done.counters.fixRounds, 2);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only", "workspace-write"],
  );
  assert.equal(
    done.pipelineState.workReports.find(({ status }) => status === "UNFINISHED")
      .recovery.budgetExhausted,
    true,
  );
});

test("unfinished continuation refuses changed infrastructure before any new repair", async (t) => {
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [invalidResolution(), unfinished()]),
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "finding_repair_required");
  await appendFile(join(fixture.projectPath, "package.json"), "\n");
  const stopped = await fixture.run();
  assert.equal(stopped.pause.reason, "unsafe_git_state");
  assert.equal(stopped.activeTurn, null);
  assert.equal(
    stopped.pipelineState.resolutionCorrection.stage,
    "repair-required",
  );
  assert.equal(resolutionCalls(fixture).length, 2);
  assert.equal(stopped.counters.fixRounds, 0);
});

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

const isResolution = ({ schema }) =>
  [FINDING_RESOLUTION_SCHEMA, FINDING_RECOVERY_SCHEMA].includes(schema);

function resolutionCalls(fixture) {
  return fixture.calls.worker.filter(isResolution);
}

async function writeRepair(request, projectPath) {
  if (isResolution(request) && request.access === "workspace-write") {
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
          isResolution(request) &&
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
          !isResolution(request) ||
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
      if (!isResolution(request) || request.access !== "workspace-write")
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
      if (!isResolution(request) || request.access !== "workspace-write")
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

for (const publication of ["reconciliation", "turn retirement"]) {
  test(`a lost catalog ${publication} acknowledgement preserves the original reconstruction`, async (t) => {
    const catalogMiss = new Error(
      "Model catalog lookup failed during recovery.",
    );
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [resolution("FIX", "R1")]),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (!isResolution(request) || request.access !== "workspace-write")
          return;
        assert.equal(await request.onFreshSession(), true);
        await writeRepair(request, projectPath);
        throw catalogMiss;
      },
    });
    fixture.runtime.catalogRetry = {
      eligible: () => false,
      hasWritableNoEffect: () => false,
      hasPossibleEffect: (cause) => cause === catalogMiss,
      resuming: () => false,
      claimResume: () => false,
    };
    const inactivity = await attachInactivity(fixture);
    const loss = new Error(`Resolution ${publication} acknowledgement lost.`);
    const { transition, finishAgentTurn } = fixture.runtime;
    const lostReconciliation = publication === "reconciliation";
    if (lostReconciliation) {
      fixture.runtime.transition = async (...args) => {
        const next = await transition(...args);
        if (next.pipelineState.resolutionCorrection?.stage === "ready") {
          fixture.runtime.transition = transition;
          throw loss;
        }
        return next;
      };
    } else {
      fixture.runtime.finishAgentTurn = async (...args) => {
        const next = await finishAgentTurn(...args);
        if (next.pipelineState.resolutionCorrection?.stage === "ready") {
          fixture.runtime.finishAgentTurn = finishAgentTurn;
          throw loss;
        }
        return next;
      };
    }

    await assert.rejects(fixture.run(), (error) => error === loss);
    assert.equal(fixture.currentRun.pause, null);
    assert.equal(
      fixture.currentRun.pipelineState.resolutionCorrection.stage,
      "ready",
    );
    assert.equal(
      fixture.currentRun.activeTurn?.phase ?? null,
      lostReconciliation ? "resolve-findings" : null,
    );
    assert.equal(fixture.currentRun.counters.fixRounds, 1);
    assert.equal(fixture.currentRun.inactivityRecovery.attempt, 2);
    inactivity.restart();

    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.counters.fixRounds, 1);
    assert.equal(completed.inactivityRecovery, null);
    assert.deepEqual(
      resolutionCalls(fixture).map(({ access }) => access),
      ["workspace-write", "read-only"],
    );
    assert.equal(
      inactivity.events.filter(({ kind }) => kind === "reconstructing").length,
      1,
    );
  });
}

test("a lost no-effect catalog reconciliation retains the spent reconstruction", async (t) => {
  const miss = new Error(
    "Model catalog lookup failed before thread selection.",
  );
  const loss = new Error("Resolution reconciliation acknowledgement lost.");
  let inactivity;
  let writable = 0;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [resolution("FIX", "R1")], {
      refinalize: false,
    }),
    async onRoleRun(_role, request) {
      if (!isResolution(request) || request.access !== "workspace-write")
        return;
      if (++writable === 1) return inactivity.expire(request);
      throw miss;
    },
  });
  const code = "ERR_MODEL_CATALOG_RETRY";
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: () => writable === 2,
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };
  inactivity = await attachInactivity(fixture);
  const { transition } = fixture.runtime;
  fixture.runtime.transition = async (...args) => {
    const next = await transition(...args);
    if (next.pipelineState.resolutionCorrection?.stage === "ready") {
      fixture.runtime.transition = transition;
      throw loss;
    }
    return next;
  };

  await assert.rejects(fixture.run(), (cause) => cause === loss);
  const interrupted = fixture.currentRun;
  assert.equal(interrupted.pause, null);
  assert.equal(interrupted.activeTurn.phase, "resolve-findings");
  assert.equal(interrupted.pipelineState.resolutionCorrection.stage, "ready");
  assert.equal(interrupted.inactivityRecovery.attempt, 2);
  assert.equal(interrupted.counters.fixRounds, 0);
  inactivity.restart();
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
  assert.equal(completed.inactivityRecovery, null);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "workspace-write", "read-only"],
  );
  assert.equal(
    inactivity.events.filter(({ kind }) => kind === "reconstructing").length,
    1,
  );
});

test("a first expiry racing a no-effect catalog miss keeps its episode after a lost acknowledgement", async (t) => {
  const miss = new Error(
    "Model catalog lookup failed before thread selection.",
  );
  const loss = new Error("Resolution reconciliation acknowledgement lost.");
  let inactivity;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [resolution("FIX", "R1")], {
      refinalize: false,
    }),
    async onRoleRun(_role, request) {
      if (!isResolution(request) || request.access !== "workspace-write")
        return;
      // The watchdog journals the first expiry before the miss settles.
      await inactivity.expire(request).catch(() => {});
      throw miss;
    },
  });
  const code = "ERR_MODEL_CATALOG_RETRY";
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: () => true,
    hasPossibleEffect: () => false,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming: () => false,
    claimResume: () => false,
  };
  inactivity = await attachInactivity(fixture);
  const { transition } = fixture.runtime;
  fixture.runtime.transition = async (...args) => {
    const next = await transition(...args);
    if (next.pipelineState.resolutionCorrection?.stage === "ready") {
      fixture.runtime.transition = transition;
      throw loss;
    }
    return next;
  };

  await assert.rejects(fixture.run(), (cause) => cause === loss);
  const interrupted = fixture.currentRun;
  assert.equal(interrupted.pause, null);
  assert.deepEqual(interrupted.pipelineState.resolutionCorrection.diagnostics, [
    CATALOG_RESOLUTION_DIAGNOSTIC,
  ]);
  assert.equal(interrupted.inactivityRecovery.status, "expired");
  assert.equal(interrupted.inactivityRecovery.attempt, 1);
  inactivity.restart();
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.inactivityRecovery, null);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
  assert.equal(
    inactivity.events.filter(({ kind }) => kind === "reconstructing").length,
    0,
  );
});

test("polishing retains a catalog resume after its publication acknowledgement is lost", async (t) => {
  const lostOutput = new Error("Catalog miss during recovery.");
  const miss = new Error("Catalog miss before the read-only retry.");
  const lostAcknowledgement = new Error("Resume acknowledgement lost.");
  const code = "ERR_MODEL_CATALOG_RETRY";
  let reports = 0;
  let binding = null;
  const fixture = await createFixture(t, {
    ...terminalFindingFlow("independent", [resolution("FIX", "R1")]),
    async onRoleRun(_role, request, _turn, { projectPath }) {
      if (!isResolution(request)) return;
      if (request.access === "workspace-write") {
        await writeRepair(request, projectPath);
        throw lostOutput;
      }
      if (++reports === 1) throw miss;
    },
  });
  const resuming = (role, checkpoint) =>
    binding?.role === role && binding.checkpoint === checkpoint;
  fixture.runtime.catalogRetry = {
    code,
    eligible: (cause) => cause === miss,
    hasWritableNoEffect: () => false,
    hasPossibleEffect: (cause) => cause === lostOutput,
    details: (role, checkpoint) => ({ code, role, checkpoint }),
    resuming,
    claimResume: resuming,
  };

  const paused = await fixture.run();
  assert.equal(paused.pause.code, code);
  const transition = fixture.runtime.transition;
  fixture.runtime.transition = async (patch, options) => {
    const next = await transition(patch, options);
    if (patch.pause === null) throw lostAcknowledgement;
    return next;
  };
  await assert.rejects(fixture.run(), (cause) => cause === lostAcknowledgement);
  assert.equal(fixture.currentRun.pause, null);
  assert.equal(fixture.currentRun.activeTurn, null);
  assert.equal(
    fixture.currentRun.pipelineState.resolutionCorrection.attempts,
    1,
  );
  assert.equal(reports, 1);

  // Simulate the common journal's retained binding when reopening the run.
  binding = paused.pause;
  fixture.runtime.transition = transition;
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.deepEqual(
    resolutionCalls(fixture).map(({ access }) => access),
    ["workspace-write", "read-only", "read-only"],
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
      if (isResolution(request) && request.access === "read-only") {
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
      if (!isResolution(request)) return;
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
      if (isResolution(request) && request.access === "read-only") {
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
        if (!isResolution(request)) return;
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
      if (!failed && isResolution(request) && request.access === "read-only") {
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
      if (isResolution(request) && request.access === "read-only") {
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
        if (!isResolution(request)) return;
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
          isResolution(request) &&
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
  const disposition = resolution("FIX", "R1");
  disposition.decisions[0].reason =
    "Retain the historical early execution without validation credit.";
  disposition.decisions[0].evidence = [
    "All later checks remain assigned to FINALIZE.",
  ];
  const fixture = await createRealStoreFixture(t, {
    ...terminalFindingFlow("independent", [
      invalidResolution(),
      environmentBlocked(
        "The original dispositions cannot be established safely.",
        "The repository does not show which blocker the edit addressed.",
      ),
      disposition,
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
  // The blocked restatement report is retained too; select the accepted decisions.
  assert.deepEqual(
    completed.pipelineState.workReports.find(
      ({ decisions }) => decisions !== undefined,
    ).decisions,
    disposition.decisions,
  );
  const terminal = fixture.calls.reviewer.at(-1);
  assert.ok(terminal.recoveryPrompt.includes(disposition.decisions[0].reason));
  assert.ok(
    terminal.recoveryPrompt.includes(disposition.decisions[0].evidence[0]),
  );
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

for (const interruption of [
  "before backoff",
  "after backoff",
  "after terminal rejection retirement",
  "after authentication",
  "after output exhaustion",
]) {
  test(`cold catalog restatement recovery ${interruption} uses only current backoff`, async (t) => {
    const published = interruption === "after backoff";
    const rejected = interruption === "after terminal rejection retirement";
    const unauthenticated = interruption === "after authentication";
    const exhausted = interruption === "after output exhaustion";
    const isProviderPause = unauthenticated || exhausted;
    const miss = new Error("Catalog miss before read-only invocation.");
    const loss = Object.assign(
      new Error("Restatement settlement interrupted."),
      { code: "ERR_AVAILABILITY_RECOVERY" },
    );
    const code = "ERR_MODEL_CATALOG_RETRY";
    let original = 0;
    let restated = 0;
    let binding = null;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [resolution("FIX", "R1")]),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (!isResolution(request)) return;
        if (request.access === "workspace-write") {
          if (++original === 1) {
            if (rejected) await writeRepair(request, projectPath);
            throw availabilityFailure();
          }
          await writeRepair(request, projectPath);
          throw Object.assign(new Error("Synthetic interrupted provider."), {
            recoverable: true,
          });
        }
        if (++restated === 1) throw miss;
        if (restated === 2 || (isProviderPause && restated === 3)) {
          if (rejected) throw new Error("Terminal provider rejection.");
          if (unauthenticated && restated === 2) throw authenticationFailure();
          if (exhausted && restated === 2) throw outputExhaustion();
          throw availabilityFailure();
        }
      },
    });
    const resuming = (role, checkpoint) =>
      binding?.role === role && binding.checkpoint === checkpoint;
    fixture.runtime.catalogRetry = {
      code,
      eligible: (cause) => cause === miss,
      hasWritableNoEffect: () => false,
      hasPossibleEffect: () => false,
      details: (role, checkpoint) => ({ code, role, checkpoint }),
      resuming,
      claimResume(role, checkpoint) {
        if (binding === null) return false;
        assert.equal(resuming(role, checkpoint), true);
        binding = null;
        return true;
      },
    };
    if (unauthenticated) attachAuthentication(fixture);
    if (exhausted) attachOutputExhaustion(fixture);
    const availability = attachAvailability(fixture);

    const lost = await fixture.run();
    assert.equal(lost.pipelineState.resolutionCorrection.stage, "ready");
    const paused = await fixture.run();
    assert.equal(paused.pause.code, code);
    const episode = paused.availabilityRetry;
    assert.equal(episode.checkpoint, "resolve-findings:workspace-write:work");
    assert.equal(episode.attempt, 1);
    if (rejected)
      assert.equal(
        episode.contentFingerprint,
        paused.pipelineState.repositoryBaseline.contentFingerprint,
      );
    binding = paused.pause;

    if (isProviderPause) {
      const suspended = await fixture.run();
      assert.equal(
        suspended.pause.reason,
        exhausted ? "output_exhausted" : "authentication_required",
      );
      assert.equal(suspended.activeTurn, null);
      assert.equal(suspended.pipelineState.resolutionCorrection.attempts, 1);
      assert.deepEqual(suspended.availabilityRetry, exhausted ? episode : null);

      const transition = fixture.runtime.transition;
      fixture.runtime.transition = async (patch, options) => {
        const next = await transition(patch, options);
        if (patch.pause === null) throw loss;
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      fixture.runtime.transition = transition;
      assert.equal(fixture.currentRun.pause, null);
      assert.equal(fixture.currentRun.activeTurn, null);
      assert.equal(restated, 2);

      const recovered = await fixture.run();
      assert.equal(recovered.pipelineState.workflowState, "DONE");
      assert.equal(recovered.counters.fixRounds, 1);
      assert.equal(recovered.availabilityRetry, null);
      assert.equal(original, 2);
      assert.equal(restated, 4);
      assert.deepEqual(availability.delays, [5000, exhausted ? 7000 : 5000]);
      assert.equal(availability.scheduled.length, 2);
      const retry = availability.scheduled[1];
      assert.equal(retry.availabilityRetry.id === episode.id, exhausted);
      assert.equal(
        retry.availabilityRetry.checkpoint,
        exhausted ? episode.checkpoint : RESOLUTION_CORRECTION_CHECKPOINT,
      );
      assert.equal(retry.availabilityRetry.attempt, exhausted ? 2 : 1);
      assert.equal(retry.pipelineState.resolutionCorrection.attempts, 1);
      assert.equal(
        retry.availabilityRetry.contentFingerprint,
        suspended.pipelineState.repositoryBaseline.contentFingerprint,
      );
      return;
    }

    const coordinator = fixture.runtime.availability;
    const finish = fixture.runtime.finishAgentTurn;
    fixture.runtime.availability = {
      ...coordinator,
      async schedule(options) {
        if (published) await coordinator.schedule(options);
        throw loss;
      },
    };
    if (rejected) {
      fixture.runtime.finishAgentTurn = async (...args) => {
        await finish(...args);
        throw loss;
      };
    }
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    fixture.runtime.availability = coordinator;
    fixture.runtime.finishAgentTurn = finish;
    assert.equal(binding, null);
    const interrupted = fixture.currentRun;
    assert.equal(
      interrupted.activeTurn?.phase ?? null,
      published || rejected ? null : "resolve-findings",
    );
    assert.equal(
      interrupted.pipelineState.resolutionCorrection.stage,
      "correcting",
    );
    assert.equal(interrupted.pipelineState.resolutionCorrection.attempts, 1);
    assert.equal(interrupted.availabilityRetry.id, episode.id);
    assert.equal(interrupted.availabilityRetry.checkpoint, episode.checkpoint);
    assert.equal(interrupted.availabilityRetry.attempt, published ? 2 : 1);

    const recovered = await fixture.run();
    assert.equal(recovered.counters.fixRounds, 1);
    assert.equal(restated, published ? 3 : 2);
    if (published) {
      assert.equal(recovered.pipelineState.workflowState, "DONE");
      assert.equal(recovered.availabilityRetry, null);
      assert.deepEqual(availability.delays, [5000, 7000]);
    } else {
      assert.equal(recovered.pause.reason, "resolution_output_invalid");
      assert.deepEqual(recovered.pause.evidence, [LOST_EVIDENCE]);
      assert.deepEqual(recovered.availabilityRetry, episode);
      assert.deepEqual(availability.delays, [5000]);
    }
    assert.equal(availability.scheduled.length, published ? 2 : 1);
    assert.equal(original, 2);
  });
}

async function legacyResolutionEvents(fixture) {
  const path = join(fixture.directoryPath, "events.jsonl");
  const events = (await readFile(path, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  for (const event of events) {
    const { state } = event;
    event.schemaVersion = 27;
    state.schemaVersion = 27;
    state.runtimeCompatibility.runStateVersion = 27;
    delete state.modelCompletionReceipts;
    delete state.modelCatalogResume;
    state.pipelineStateVersion = 24;
    const correction = state.pipelineState.resolutionCorrection;
    if (correction !== null) {
      correction.schemaVersion = 1;
      delete correction.repair;
      delete correction.factsFingerprint;
      delete correction.restatementStartedAfter;
    }
  }
  return events;
}

function appendLegacyEvent(events, patch, activity) {
  const last = events.at(-1);
  const revision = last.revision + 1;
  const state = { ...last.state, ...patch, revision };
  events.push({
    ...last,
    revision,
    recordedAt: state.updatedAt,
    state,
    activity,
  });
}

async function persistLegacyResolutionEvents(fixture, events) {
  await writeFile(
    join(fixture.directoryPath, "events.jsonl"),
    `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
  );
  await writeFile(
    join(fixture.directoryPath, "state.json"),
    `${JSON.stringify(events.at(-1).state)}\n`,
  );
}

async function migrateLegacyResolution(store, lease, legacy) {
  assert.equal(legacy.schemaVersion, 27);
  assert.equal(legacy.pipelineStateVersion, 24);
  const run = await store.migrateRun(
    lease,
    {
      pipelineState: polishingPipeline.migrations[24](legacy),
      pipelineStateVersion: 25,
    },
    {
      activity: {
        actor: "runner",
        phase: "runtime",
        kind: "migrated",
        message: "Migrated common version 27 and polishing version 24.",
      },
    },
  );
  polishingPipeline.workflow.validateRun(run);
  return run;
}

for (const stale of [false, true]) {
  test(`common version 27 restatement backoff is ${stale ? "stale after a later turn" : "resumed after migration"}`, async (t) => {
    const loss = Object.assign(new Error("Owner lost."), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    const unavailable = availabilityFailure();
    let readOnlyCalls = 0;
    let scheduled;
    const fixture = await createRealStoreFixture(t, {
      ...terminalFindingFlow("independent", [invalidResolution()]),
      onRoleRun(_role, request) {
        if (!isResolution(request) || request.access !== "read-only") return;
        if (++readOnlyCalls === 1) throw unavailable;
        throw loss;
      },
    });
    fixture.runtime.availability = {
      eligible: (cause) => cause === unavailable,
      async schedule({ role, checkpoint, repository, reconciledTurn }) {
        await fixture.runtime.finishAgentTurn(reconciledTurn);
        scheduled = { role, checkpoint, repository };
        throw loss;
      },
    };
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    assert.equal(fixture.currentRun.activeTurn, null);
    assert.equal(
      fixture.currentRun.pipelineState.resolutionCorrection.attempts,
      1,
    );

    // Version 27 recorded retirement and backoff separately, without a start marker.
    const events = await legacyResolutionEvents(fixture);
    const retired = events.at(-1);
    const invocation = events.findLast(
      ({ activity }) => activity?.kind === "turn-started",
    );
    const delayMs = 5_000;
    const episode = {
      id: randomUUID(),
      role: scheduled.role,
      checkpoint: scheduled.checkpoint,
      reason: "temporarily_overloaded",
      attempt: 1,
      delayMs,
      scheduledAt: retired.recordedAt,
      nextRetryAt: new Date(
        Date.parse(retired.recordedAt) + delayMs,
      ).toISOString(),
      contentFingerprint: scheduled.repository.contentFingerprint,
      reconciledRevision: retired.revision,
    };
    appendLegacyEvent(
      events,
      { availabilityRetry: episode },
      {
        actor: "worker",
        phase: "availability",
        kind: "retry-scheduled",
        message: "Scheduled read-only restatement backoff.",
      },
    );
    if (stale) {
      appendLegacyEvent(
        events,
        { updatedAt: episode.nextRetryAt },
        {
          actor: "worker",
          phase: "availability",
          kind: "retry-started",
          message: "Completed the recorded backoff.",
        },
      );
      appendLegacyEvent(
        events,
        { activeTurn: invocation.state.activeTurn },
        invocation.activity,
      );
      appendLegacyEvent(events, { activeTurn: null }, null);
    }
    await persistLegacyResolutionEvents(fixture, events);

    await fixture.recover(async (store, lease, legacy) => {
      const run = await migrateLegacyResolution(store, lease, legacy);
      const history = await store.loadRunHistory(run.runId, { stream: true });
      await polishingPipeline.prepareRecovery(run, history);
      return run;
    });
    let backoffCalls = 0;
    fixture.runtime.availability.before = async ({ role, checkpoint }) => {
      assert.equal(role, episode.role);
      assert.equal(checkpoint, episode.checkpoint);
      assert.deepEqual(fixture.currentRun.availabilityRetry, episode);
      backoffCalls++;
      return fixture.currentRun;
    };
    if (stale) {
      const paused = await fixture.run();
      assert.equal(paused.pause.reason, "resolution_output_invalid");
      assert.equal(backoffCalls, 0);
      assert.equal(readOnlyCalls, 1);
    } else {
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      assert.equal(backoffCalls, 1);
      assert.equal(readOnlyCalls, 2);
    }
    assert.deepEqual(fixture.currentRun.availabilityRetry, episode);
    assert.equal(
      fixture.currentRun.pipelineState.resolutionCorrection.attempts,
      1,
    );
  });
}

for (const scenario of ["cold", "stop", "mismatched", "stale"]) {
  test(`common version 27 restatement watchdog expiry handles ${scenario} recovery`, async (t) => {
    const loss = Object.assign(new Error("Owner lost."), {
      code: "ERR_EXECUTION_PROCESS_UNVERIFIABLE",
    });
    let restatements = 0;
    const fixture = await createRealStoreFixture(t, {
      ...terminalFindingFlow("independent", [invalidResolution()]),
      onRoleRun(_role, request) {
        if (!isResolution(request) || request.access !== "read-only") return;
        restatements++;
        throw loss;
      },
    });
    fixture.runtime.matchesObservedInactivityExpiry =
      matchesObservedInactivityExpiry;
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    const events = await legacyResolutionEvents(fixture);
    const invocation = events.at(-1);
    assert.equal(invocation.activity.kind, "turn-started");
    const attempt = {
      role: "worker",
      checkpoint: RESOLUTION_CORRECTION_CHECKPOINT,
    };
    const observations = beginObservationAttempt(invocation.state, attempt);
    appendLegacyEvent(
      events,
      { observations },
      {
        actor: "worker",
        phase: "observations",
        kind: "active",
        message: "Read-only provider attempt started.",
      },
    );
    const expiry = {
      ...attempt,
      checkpoint:
        scenario === "mismatched"
          ? "resolve-findings:workspace-write:work"
          : attempt.checkpoint,
      attempt: 1,
      status: "expired",
      reconstructionRevision: null,
      expiryRevision: events.at(-1).revision + 1,
      configurationFingerprint: invocation.state.providerInactivityFingerprint,
      contentFingerprint:
        invocation.state.pipelineState.repositoryBaseline.contentFingerprint,
    };
    appendLegacyEvent(
      events,
      { inactivityRecovery: expiry },
      {
        actor: "worker",
        phase: "inactivity",
        kind: "expired",
        message: "Provider attempt expired.",
      },
    );
    if (scenario === "stale") {
      appendLegacyEvent(events, { activeTurn: null }, null);
      appendLegacyEvent(
        events,
        { activeTurn: invocation.state.activeTurn },
        invocation.activity,
      );
    }
    await persistLegacyResolutionEvents(fixture, events);

    let interrupted;
    let reconstructions = 0;
    await fixture.recover(async (store, lease, legacy) => {
      const run = await migrateLegacyResolution(store, lease, legacy);
      interrupted = run;
      let ready = run;
      if (scenario === "stop") {
        await store.requestOperatorStop({
          runId: run.runId,
          kind: "pause_requested",
          expectedRevision: run.revision,
          idempotencyKey: "pause-expired-restatement",
        });
        const stopped = await reconcileOperatorStop({
          run,
          pipeline: polishingPipeline,
          lease,
          runStore: store,
          runtime: fixture.runtime,
          publish: async () => {},
        });
        assert.equal(stopped.pause.reason, "operator_paused");
        assert.equal(stopped.pause.operatorResume.pause, null);
        assert.equal(stopped.activeTurn, null);
        assert.equal(
          stopped.pipelineState.resolutionCorrection.stage,
          "correcting",
        );
        assert.equal(restatements, 1);
        ready = await store.transitionRun(lease, restoreOperatorPause(stopped));
      }
      const history = await store.loadRunHistory(run.runId, { stream: true });
      await polishingPipeline.prepareRecovery(ready, history);
      fixture.runtime.inactivity = {
        before({ role, checkpoint, continueEpisode }) {
          assert.equal(role, expiry.role);
          assert.equal(checkpoint, expiry.checkpoint);
          assert.equal(continueEpisode, false);
          assert.deepEqual(fixture.currentRun.inactivityRecovery, expiry);
          reconstructions++;
          return store.recordInactivity(
            lease,
            { ...expiry, attempt: 2, status: "reconstructing" },
            "reconstructing",
          );
        },
      };
      return ready;
    });
    if (scenario === "cold" || scenario === "stop") {
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      assert.equal(reconstructions, 1);
      assert.equal(restatements, 2);
      assert.equal(fixture.currentRun.inactivityRecovery.attempt, 2);
      assert.equal(
        fixture.currentRun.inactivityRecovery.expiryRevision,
        expiry.expiryRevision,
      );
      assert.equal(
        fixture.currentRun.pipelineState.resolutionCorrection.stage,
        "correcting",
      );
    } else {
      const paused = await fixture.run();
      assert.equal(paused.pause.reason, "resolution_output_invalid");
      assert.deepEqual(paused.pause.evidence, [LOST_EVIDENCE]);
      assert.equal(reconstructions, 0);
      assert.equal(restatements, 1);
    }
    assert.deepEqual(fixture.currentRun.counters, interrupted.counters);
    const correction = fixture.currentRun.pipelineState.resolutionCorrection;
    assert.equal(correction.attempts, 1);
    assert.equal(correction.additionalAttempts, 0);
  });
}

for (const scenario of [
  "stale",
  "current",
  "lost reconstruction acknowledgement",
  "lost retirement acknowledgement",
  "repeated",
  "repeated live",
  "stale at stop",
  "mismatched at stop",
  "current at stop",
  "repeated at stop",
]) {
  const stopping = scenario.endsWith(" at stop");
  const expiry = scenario.replace(/ at stop$/u, "");
  const loseReconstruction = expiry === "lost reconstruction acknowledgement";
  const loseRetirement = expiry === "lost retirement acknowledgement";
  const description = loseReconstruction
    ? "catalog restatement resumes a journaled reconstruction after acknowledgement loss"
    : loseRetirement
      ? "catalog restatement reconstructs from the journal after retirement acknowledgement loss"
      : `catalog restatement recovery handles ${scenario} watchdog expiry`;
  test(description, async (t) => {
    const miss = new Error("Catalog miss before read-only invocation.");
    const code = "ERR_MODEL_CATALOG_RETRY";
    let binding = null;
    let restated = 0;
    let process;
    let inactivity;
    const repeated = expiry.startsWith("repeated");
    const live = expiry === "repeated live";
    const reconstructionLoss = new Error(
      "Reconstruction acknowledgement lost.",
    );
    let reconstructions = 0;
    const fixture = await createFixture(t, {
      ...terminalFindingFlow("independent", [
        invalidResolution(),
        resolution("FIX", "R1"),
      ]),
      async onRoleRun(_role, request, _turn, { projectPath }) {
        if (!isResolution(request)) return;
        if (request.access === "workspace-write") {
          await writeRepair(request, projectPath);
          return;
        }
        if (++restated === 1) {
          await assert.rejects(inactivity.expire(request), {
            code: "ERR_PROVIDER_INACTIVE",
          });
          throw miss;
        }
        if (restated === 2) {
          if (expiry === "stale") throw process.stop();
          if (repeated) assert.equal(await request.onFreshSession(), true);
          return inactivity.expire(request);
        }
        if (live || loseReconstruction || loseRetirement)
          assert.equal(await request.onFreshSession(), false);
      },
    });
    fixture.runtime.catalogRetry = {
      code,
      eligible: (cause) => cause === miss,
      details: (role, checkpoint) => ({ code, role, checkpoint }),
      hasPossibleEffect: () => false,
      hasWritableNoEffect: () => false,
      resuming: (role, checkpoint) =>
        binding?.role === role && binding.checkpoint === checkpoint,
      claimResume(role, checkpoint) {
        if (binding === null) return false;
        assert.equal(this.resuming(role, checkpoint), true);
        binding = null;
        return true;
      },
    };
    inactivity = await attachInactivity(fixture, {
      onRecord(run) {
        if (run.inactivityRecovery.status === "reconstructing") {
          reconstructions += 1;
          if (loseReconstruction && reconstructions === 1)
            throw reconstructionLoss;
        }
        if (
          !live &&
          !loseRetirement &&
          restated === 2 &&
          run.inactivityRecovery.status === "expired"
        )
          process.stop();
      },
    });
    process = interruptible(fixture);

    const paused = await fixture.run();
    assert.equal(paused.pause.code, code);
    assert.equal(paused.inactivityRecovery.status, "expired");
    binding = paused.pause;
    const { transition, startAgentTurn } = fixture.runtime;
    fixture.runtime.transition = (patch, options) => {
      const current = fixture.currentRun;
      return transition(
        {
          ...patch,
          modelCatalogResume: nextCatalogResume(current, {
            ...current,
            ...patch,
          }),
        },
        options,
      );
    };
    fixture.runtime.startAgentTurn = async (turn, options) => {
      const retry = fixture.currentRun.modelCatalogResume;
      if (retry != null) {
        assert.equal(turn.role, retry.role);
        assert.equal(options.catalogCheckpoint, retry.checkpoint);
        await transition({ modelCatalogResume: null });
      }
      return startAgentTurn(turn, options);
    };
    inactivity.restart();
    if (live) {
      const suspended = await fixture.run();
      assert.equal(suspended.pause.reason, "backend_unavailable");
      assert.equal(suspended.pause.code, "ERR_PROVIDER_INACTIVE");
      assert.equal(suspended.activeTurn, null);
      assert.equal(suspended.pipelineState.resolutionCorrection.attempts, 1);
      assert.equal(
        suspended.pipelineState.resolutionCorrection.stage,
        "correcting",
      );
      assert.equal(suspended.inactivityRecovery.attempt, 2);
      assert.equal(suspended.inactivityRecovery.status, "expired");

      const loss = new Error("Inactivity resume acknowledgement lost.");
      const transition = fixture.runtime.transition;
      fixture.runtime.transition = async (patch, options) => {
        const next = await transition(patch, options);
        if (patch.pause === null) throw loss;
        return next;
      };
      inactivity.restart();
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      fixture.runtime.transition = transition;
      assert.equal(fixture.currentRun.pause, null);
      assert.equal(fixture.currentRun.activeTurn, null);
      assert.equal(restated, 2);

      inactivity.restart();
      const completed = await fixture.run();
      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.equal(completed.counters.fixRounds, 1);
      assert.equal(completed.inactivityRecovery, null);
      assert.deepEqual(
        resolutionCalls(fixture).map(({ access }) => access),
        ["workspace-write", "read-only", "read-only", "read-only"],
      );
      assert.ok(
        fixture.transitions.every(
          ({ patch }) =>
            (patch.pipelineState?.resolutionCorrection?.attempts ?? 0) <= 1,
        ),
      );
      return;
    }
    if (loseRetirement) {
      // The live first expiry retires its turn durably, then loses the reply.
      const retirementLoss = new Error("Retirement acknowledgement lost.");
      const finish = fixture.runtime.finishAgentTurn;
      fixture.runtime.finishAgentTurn = async (...args) => {
        const next = await finish(...args);
        if (restated === 2) throw retirementLoss;
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === retirementLoss);
      fixture.runtime.finishAgentTurn = finish;
    } else {
      await assert.rejects(fixture.run(), (cause) => cause === process.loss);
    }
    process.restore();
    const interrupted = fixture.currentRun;
    assert.equal(
      interrupted.activeTurn?.phase ?? null,
      loseRetirement ? null : "resolve-findings",
    );
    assert.equal(interrupted.pause, null);
    assert.equal(interrupted.pipelineState.workflowState, "RESOLVE_FINDINGS");
    assert.equal(
      interrupted.pipelineState.resolutionCorrection.stage,
      "correcting",
    );
    assert.equal(interrupted.pipelineState.resolutionCorrection.attempts, 1);
    assert.equal(interrupted.inactivityRecovery.attempt, repeated ? 2 : 1);
    assert.equal(
      interrupted.inactivityRecovery.expiryRevision !==
        paused.inactivityRecovery.expiryRevision,
      expiry !== "stale",
    );

    if (expiry === "mismatched")
      await fixture.runtime.transition({
        inactivityRecovery: {
          ...interrupted.inactivityRecovery,
          checkpoint: "resolve-findings:workspace-write:work",
        },
      });
    inactivity.restart();
    if (stopping) {
      const requested = await fixture.runtime.transition({
        stopRequest: { acceptedRevision: interrupted.revision + 1 },
      });
      const stopped = await runPolishing({
        run: requested,
        runtime: fixture.runtime,
        operatorStop: true,
      });
      assert.equal(stopped.activeTurn, null);
      assert.equal(stopped.pipelineState.resolutionCorrection.attempts, 1);
      assert.deepEqual(stopped.counters, interrupted.counters);
      assert.equal(restated, 2);
      if (["stale", "mismatched"].includes(expiry)) {
        assert.equal(stopped.pause.reason, "resolution_output_invalid");
        assert.deepEqual(stopped.pause.evidence, [LOST_EVIDENCE]);
      } else {
        assert.equal(stopped.pause, null);
        assert.equal(
          stopped.pipelineState.resolutionCorrection.stage,
          repeated ? "retry-ready" : "correcting",
        );
        inactivity.restart();
        const resumed = await fixture.run();
        assert.equal(resumed.pipelineState.workflowState, "DONE");
        assert.equal(resumed.inactivityRecovery, null);
        assert.equal(restated, 3);
        assert.equal(reconstructions, 1);
      }
      return;
    }
    if (loseReconstruction) {
      await assert.rejects(
        fixture.run(),
        (cause) => cause.cause === reconstructionLoss,
      );
      const reconstructed = fixture.currentRun;
      assert.equal(reconstructed.pause, null);
      assert.equal(reconstructed.activeTurn, null);
      assert.equal(reconstructed.inactivityRecovery.attempt, 2);
      assert.equal(reconstructed.inactivityRecovery.status, "reconstructing");
      assert.equal(
        reconstructed.inactivityRecovery.expiryRevision,
        interrupted.inactivityRecovery.expiryRevision,
      );
      assert.equal(
        reconstructed.pipelineState.resolutionCorrection.attempts,
        1,
      );
      assert.equal(restated, 2);
      inactivity.restart();
    }
    const recovered = await fixture.run();
    assert.equal(recovered.counters.fixRounds, 1);
    const continued =
      expiry === "current" || loseReconstruction || loseRetirement;
    assert.equal(restated, continued ? 3 : 2);
    assert.equal(recovered.activeTurn, null);
    if (continued) {
      assert.equal(recovered.pipelineState.workflowState, "DONE");
      assert.equal(recovered.inactivityRecovery, null);
      assert.equal(reconstructions, 1);
      assert.deepEqual(
        resolutionCalls(fixture).map(({ access }) => access),
        ["workspace-write", "read-only", "read-only", "read-only"],
      );
      assert.ok(
        fixture.transitions.every(
          ({ patch }) =>
            (patch.pipelineState?.resolutionCorrection?.attempts ?? 0) <= 1,
        ),
      );
    } else if (repeated) {
      assert.equal(recovered.pause.reason, "backend_unavailable");
      assert.equal(recovered.pause.code, "ERR_PROVIDER_INACTIVE");
      assert.deepEqual(
        recovered.inactivityRecovery,
        interrupted.inactivityRecovery,
      );
    } else {
      assert.equal(recovered.pause.reason, "resolution_output_invalid");
      assert.deepEqual(recovered.pause.evidence, [LOST_EVIDENCE]);
      assert.deepEqual(recovered.inactivityRecovery, paused.inactivityRecovery);
    }
  });
}

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
      if (isResolution(request) && unavailable) {
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
