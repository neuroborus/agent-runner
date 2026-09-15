import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  migratePlanExecutionStateV14,
  planExecutionPipeline,
} from "../src/index.js";
import {
  CANDIDATE_CLEAN_CONFIRM_SCHEMA,
  CANDIDATE_REVIEW_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  FINALIZATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import {
  assertRun,
  normalizeCandidateReviewResult,
  normalizeCleanConfirmationResult,
  normalizeReviewResult,
} from "../src/workflow-contract.js";
import {
  bootstrapReady,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  compatibilityReady,
  createFixture,
  finalizationPassed,
  implementationCompleted,
  implementationProductDecision,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
  terminalConfirmation,
  terminalLazyConfirmation,
} from "./support/index.js";

const ESTABLISHED = ["package.json", "docs/OPERATOR_GUIDE.md"];
const SUBSTITUTED = ["package.json", "docs/ARCHITECTURE.md"];
const EXPANDED = [...ESTABLISHED, "docs/ARCHITECTURE.md"];

function finalized(infrastructure = ESTABLISHED) {
  return { ...finalizationPassed(), validationInfrastructure: infrastructure };
}

function rejected({ mixed = false, ids = ["R1"] } = {}) {
  const findings = reviewFindings(...ids).findings.map((finding) => ({
    ...finding,
    file: "docs/OPERATOR_GUIDE.md",
    problem: "Finalization omitted or substituted established infrastructure.",
    reason: "The reported inventory does not match the established inventory.",
    suggestedAction:
      "Return corrected finalization evidence; no repository edit is required.",
  }));
  return {
    ...reviewFindings(),
    findings: mixed
      ? [...findings, ...reviewFindings("R9").findings]
      : findings,
    validationChange: "REJECTED",
    validationEvidence: ["The inventory change is not authorized."],
    finalizationFindingIds: ids,
  };
}

function insufficientEvidence() {
  const rejection = rejected();
  return {
    ...rejection,
    findings: [
      {
        ...rejection.findings[0],
        problem: "The reported check evidence does not demonstrate execution.",
        reason: "An unchanged inventory does not establish that checks ran.",
        suggestedAction:
          "Run the complete gate and return direct evidence without editing content.",
      },
    ],
    validationEvidence: ["The check evidence remains insufficient."],
  };
}

async function recoveryFixture(
  t,
  {
    mode = "lazy",
    initialFinalization = finalized(SUBSTITUTED),
    replacements = [finalized()],
    rejections = [rejected()],
    work = [],
    ...options
  } = {},
) {
  const terminal =
    mode === "lazy" ? terminalLazyConfirmation : terminalConfirmation;
  const confirms = [
    ...rejections.map(terminal),
    terminal(mode === "lazy" ? cleanConfirmation() : reviewApproved()),
  ];
  return createFixture(t, {
    mode,
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), validationInfrastructure: ESTABLISHED },
      ...(mode === "lazy" ? [] : [reconciliationResolved()]),
    ],
    reviewer: [
      { ...bootstrapReady("Reviewer"), validationInfrastructure: ESTABLISHED },
    ],
    workWorker: [
      implementationCompleted(),
      ...(mode === "lazy" ? [checkAndFix()] : []),
      initialFinalization,
      ...work,
      ...replacements,
      ...(mode === "lazy" ? confirms : []),
    ],
    workReviewer: mode === "lazy" ? [] : confirms,
    async prepareProject(path) {
      await mkdir(join(path, "docs"));
      await writeFile(
        join(path, "docs/OPERATOR_GUIDE.md"),
        "Established guidance.\n",
      );
      await writeFile(join(path, "docs/ARCHITECTURE.md"), "Architecture.\n");
    },
    ...options,
  });
}

function calls(fixture, schema) {
  return Object.values(fixture.calls)
    .flat()
    .filter((request) => request.schema === schema);
}

function rejectionTransitions(fixture) {
  return fixture.transitions.filter(
    ({ options }) => options.activity?.kind === "evidence-rejected",
  );
}

for (const mode of ["independent", "lazy"]) {
  test(`${mode} corrects the exact no-edit infrastructure rejection without candidate or code-fix cycles`, async (t) => {
    const fixture = await recoveryFixture(t, { mode });
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "DONE");
    assert.deepEqual(
      result.pipelineState.validationInfrastructure,
      ESTABLISHED,
    );
    assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 2);
    assert.equal(
      calls(
        fixture,
        mode === "lazy"
          ? CANDIDATE_CLEAN_CONFIRM_SCHEMA
          : CANDIDATE_REVIEW_SCHEMA,
      ).length,
      1,
    );
    assert.equal(
      calls(fixture, CHECK_AND_FIX_SCHEMA).length,
      mode === "lazy" ? 1 : 0,
    );
    const rejection = rejectionTransitions(fixture)[0].patch;
    assert.equal(rejection.pipelineState.finalizationResult, null);
    assert.equal(rejection.pipelineState.workflowState, "FINALIZE");
    assert.deepEqual(result.counters, rejection.counters);
    assert.equal(
      calls(fixture, mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA)
        .length,
      2,
    );
    assert.ok(
      calls(
        fixture,
        mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA,
      ).every(({ access }) => access === "read-only"),
    );
    assert.match(
      calls(fixture, FINALIZATION_SCHEMA)[1].prompt,
      /no repository edit is required/u,
    );
    for (const { prompt, recoveryPrompt } of calls(
      fixture,
      FINALIZATION_SCHEMA,
    )) {
      for (const text of [prompt, recoveryPrompt]) {
        const tuple = JSON.parse(
          /Established validation tuple:\n(\{[\s\S]*?\n\})/u.exec(text)?.[1],
        );
        assert.deepEqual(
          tuple.requiredChecks,
          rejection.pipelineState.requiredChecks,
        );
        assert.deepEqual(tuple.validationInfrastructure, ESTABLISHED);
      }
    }
    assert.equal(
      result.pipelineState.finalizedFingerprint,
      result.pipelineState.reviewedFingerprint,
    );
    if (mode === "lazy") {
      assert.equal(fixture.calls.reviewer.length, 0);
      assert.equal(fixture.calls.arbiter.length, 0);
    }
  });

  test(`${mode} invalidates mixed evidence immediately and routes only content findings to repair`, async (t) => {
    const fixture = await recoveryFixture(t, {
      mode,
      rejections: [rejected({ mixed: true })],
      work:
        mode === "lazy"
          ? [checkAndFix()]
          : [resolution({ id: "R9", decision: "FIX" })],
    });
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "DONE");
    const { pipelineState } = rejectionTransitions(fixture)[0].patch;
    assert.equal(pipelineState.finalizationResult, null);
    assert.deepEqual(
      pipelineState.findings.map(({ id }) => id),
      ["R9"],
    );
    assert.equal(
      pipelineState.workflowState,
      mode === "lazy" ? "CHECK_AND_FIX" : "RESOLVE_FINDINGS",
    );
    assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 2);
    assert.equal(
      calls(
        fixture,
        mode === "lazy"
          ? CANDIDATE_CLEAN_CONFIRM_SCHEMA
          : CANDIDATE_REVIEW_SCHEMA,
      ).length,
      2,
    );
  });

  test(`${mode} exhausts semantic retries at FINALIZE and null retry authorizes exactly one replacement`, async (t) => {
    const fixture = await recoveryFixture(t, {
      mode,
      replacements: [finalized(EXPANDED), finalized(EXPANDED), finalized()],
      rejections: [rejected(), rejected(), rejected()],
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "finalization_evidence_rejected");
    assert.equal(paused.pause.resumeState, "FINALIZE");
    assert.equal(paused.pipelineState.finalizationRecovery.attempts, 2);
    assert.equal(paused.pipelineState.finalizationRecovery.pending, false);
    assert.equal(paused.pipelineState.finalizationResult, null);
    assert.equal(paused.pipelineState.pendingCommit, null);
    assert.deepEqual(
      paused.counters,
      rejectionTransitions(fixture)[0].patch.counters,
    );
    assert.equal(
      fixture.calls.worker.filter(({ access }) => access === "local-commit")
        .length,
      0,
    );
    const projection = planExecutionPipeline.projections.pause(paused);
    assert.deepEqual(projection.nextActions[0], {
      type: "resume",
      action: null,
    });
    assert.deepEqual(projection.evidence, [
      "Finalization evidence finding R1 remains unresolved.",
    ]);
    assert.equal(projection.resumeState, "FINALIZE");
    assert.deepEqual(
      planExecutionPipeline.projections.status(paused).findings,
      [{ id: "R1", summary: rejected().findings[0].problem }],
    );
    assert.doesNotThrow(() =>
      planExecutionPipeline.validateResumeAction(paused, null),
    );
    assert.throws(() =>
      planExecutionPipeline.validateResumeAction(paused, {
        type: "extra-fix-rounds",
        amount: 1,
      }),
    );
    const resumed = await fixture.run({}, null);
    assert.equal(resumed.pipelineState.workflowState, "DONE");
    assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 4);
    assert.deepEqual(resumed.counters, paused.counters);
  });

  test(`${mode} bounds repeated evidence rejection even when validation inventories stay unchanged`, async (t) => {
    const rejection = insufficientEvidence();
    const fixture = await recoveryFixture(t, {
      mode,
      initialFinalization: finalized(),
      replacements: [finalized(), finalized(), finalized()],
      rejections: [rejection, rejection, rejection],
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "finalization_evidence_rejected");
    assert.equal(paused.pause.resumeState, "FINALIZE");
    assert.equal(paused.pipelineState.finalizationRecovery.attempts, 2);
    assert.equal(paused.pipelineState.finalizationResult, null);
    assert.equal(paused.pipelineState.pendingCommit, null);
    assert.deepEqual(
      paused.counters,
      rejectionTransitions(fixture)[0].patch.counters,
    );
    assert.equal(
      fixture.transitions.filter(
        ({ options }) => options.activity?.kind === "confirmation-correction",
      ).length,
      0,
    );
    const completed = await fixture.run({}, null);
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(
      completed.pipelineState.finalizationResult.validationChanged,
      false,
    );
    assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 4);
    assert.equal(
      calls(fixture, CHECK_AND_FIX_SCHEMA).length,
      mode === "lazy" ? 1 : 0,
    );
  });
}

test("semantic pending attempt survives provider unavailability without recounting", async (t) => {
  let unavailable = false;
  const fixture = await recoveryFixture(t, {
    onRoleRun(role, request) {
      if (
        request.schema === FINALIZATION_SCHEMA &&
        request.prompt.includes("Accepted evidence findings:") &&
        !unavailable
      ) {
        unavailable = true;
        throw Object.assign(new Error("DO_NOT_PERSIST_PROVIDER_OUTPUT"), {
          code: "ERR_TEST_BACKEND_UNAVAILABLE",
          recoverable: true,
        });
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationRecovery.pending, true);
  assert.equal(paused.pipelineState.finalizationRecovery.attempts, 1);
  assert.doesNotMatch(JSON.stringify(paused), /DO_NOT_PERSIST/u);
  const resumed = await fixture.run({}, null);
  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "evidence-retry",
    ).length,
    1,
  );
});

test("semantic pending attempt reconstructs after interruption without a native session", async (t) => {
  const stop = new Error("simulated process loss");
  let stopped = false;
  let interrupted = false;
  const fixture = await recoveryFixture(t, {
    onRoleRun(role, request) {
      if (
        request.schema === FINALIZATION_SCHEMA &&
        request.prompt.includes("Accepted evidence findings:") &&
        !interrupted
      ) {
        interrupted = true;
        stopped = true;
        throw stop;
      }
    },
  });
  const finish = fixture.runtime.finishAgentTurn;
  const transition = fixture.runtime.transition;
  fixture.runtime.finishAgentTurn = (turn) => {
    if (stopped) throw stop;
    return finish(turn);
  };
  fixture.runtime.transition = (patch, options) => {
    if (stopped) throw stop;
    return transition(patch, options);
  };
  await assert.rejects(fixture.run(), (error) => error === stop);
  assert.equal(
    fixture.currentRun.pipelineState.finalizationRecovery.attempts,
    1,
  );
  assert.equal(
    fixture.currentRun.pipelineState.finalizationRecovery.pending,
    true,
  );
  stopped = false;
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "evidence-retry",
    ).length,
    1,
  );
});

test("recovery rejects omitted checks and substituted infrastructure through the separate malformed-output correction", async (t) => {
  const invalid = {
    ...finalized(SUBSTITUTED),
    requiredChecks: [{ id: "C1", command: "node --version" }],
    checks: [
      {
        checkId: "C1",
        command: "node --version",
        status: "PASS",
        evidence: ["Completed."],
      },
    ],
  };
  const fixture = await recoveryFixture(t, {
    replacements: [invalid, finalized()],
  });
  const result = await fixture.run();
  assert.equal(result.pipelineState.workflowState, "DONE");
  const finalizations = calls(fixture, FINALIZATION_SCHEMA);
  assert.equal(finalizations.length, 3);
  assert.equal(finalizations[2].access, "read-only");
  assert.match(finalizations[2].prompt, /preserves-established-checks/u);
  assert.match(
    finalizations[2].prompt,
    /preserves-established-infrastructure/u,
  );
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "evidence-retry",
    ).length,
    1,
  );
});

test("terminal evidence classification is structured, bounded, and absent from candidate review", () => {
  const valid = rejected({ mixed: true });
  for (const normalize of [
    normalizeReviewResult,
    normalizeCleanConfirmationResult,
  ]) {
    assert.deepEqual(normalize(valid).finalizationFindingIds, ["R1"]);
    for (const finalizationFindingIds of [
      ["R1", "R1"],
      ["R404"],
      Array(33).fill("R1"),
      null,
    ]) {
      assert.throws(() => normalize({ ...valid, finalizationFindingIds }));
    }
    assert.throws(() => normalize({ ...valid, validationChange: "UNCHANGED" }));
  }
  assert.throws(() =>
    normalizeReviewResult({
      ...reviewApproved(),
      finalizationFindingIds: ["R1"],
    }),
  );
  assert.throws(() =>
    normalizeCleanConfirmationResult({
      ...cleanConfirmation(),
      finalizationFindingIds: ["R1"],
    }),
  );
  const {
    validationChange,
    validationEvidence,
    finalizationFindingIds,
    ...candidate
  } = reviewApproved();
  assert.equal(normalizeCandidateReviewResult(candidate).status, "APPROVED");
  assert.throws(() =>
    normalizeCandidateReviewResult({
      ...candidate,
      finalizationFindingIds: [],
    }),
  );
});

test("version 14 migration initializes only recovery metadata and validates its durable bounds", async (t) => {
  const fixture = await recoveryFixture(t, {
    replacements: [finalized(EXPANDED), finalized(EXPANDED)],
    rejections: [rejected(), rejected(), rejected()],
  });
  const paused = await fixture.run();
  for (const state of [
    paused.pipelineState,
    { ...paused.pipelineState, finalizationRecovery: undefined },
  ]) {
    const { finalizationRecovery, ...legacy } = state;
    const migrated = migratePlanExecutionStateV14({ pipelineState: legacy });
    assert.deepEqual(
      { ...migrated, finalizationRecovery: undefined },
      { ...legacy, finalizationRecovery: undefined },
    );
    assert.deepEqual(migrated.finalizationRecovery, {
      attempts: 0,
      additionalAttempts: 0,
      required: false,
      pending: false,
      feedback: null,
    });
  }
  const recovery = paused.pipelineState.finalizationRecovery;
  for (const invalid of [
    { ...recovery, attempts: 3 },
    { ...recovery, pending: true },
    { ...recovery, additionalAttempts: -1 },
    {
      ...recovery,
      feedback: { ...recovery.feedback, nativeOutput: "not allowed" },
    },
    {
      ...recovery,
      feedback: { ...recovery.feedback, contentFingerprint: "invalid" },
    },
  ]) {
    assert.throws(() =>
      assertRun({
        ...paused,
        pipelineState: {
          ...paused.pipelineState,
          finalizationRecovery: invalid,
        },
      }),
    );
  }
});

test("whole-result overrides retain their gate while partial overrides still invalidate rejected evidence", async (t) => {
  for (const partial of [false, true]) {
    await t.test(partial ? "partial" : "whole result", async (t) => {
      let seeded = false;
      let formatted = false;
      const fixture = await recoveryFixture(t, {
        mode: "independent",
        rejections: [rejected({ mixed: partial })],
        async onRoleRun(role, request) {
          if (!formatted && request.schema === FINALIZATION_SCHEMA) {
            formatted = true;
            await writeFile(
              join(request.cwd, "formatted.txt"),
              "Formatter output.\n",
            );
          }
        },
        onTransition(run) {
          if (!seeded && run.pipelineState.workflowState === "CONFIRM") {
            seeded = true;
            assert.notEqual(
              run.pipelineState.finalizedFingerprint,
              run.pipelineState.candidateReviewedFingerprint,
            );
            run.pipelineState = {
              ...run.pipelineState,
              findingOverrides: [
                {
                  findingId: partial ? "R9" : "R1",
                  fingerprint: run.pipelineState.finalizedFingerprint,
                },
              ],
            };
          }
        },
      });
      const result = await fixture.run();
      assert.equal(result.pipelineState.workflowState, "DONE");
      assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, partial ? 2 : 1);
      assert.equal(rejectionTransitions(fixture).length, partial ? 1 : 0);
      assert.equal(calls(fixture, CANDIDATE_REVIEW_SCHEMA).length, 1);
    });
  }
});

test("unchanged-inventory rejection honors only a complete exact terminal override", async (t) => {
  const fixture = await recoveryFixture(t, {
    mode: "independent",
    initialFinalization: finalized(),
    rejections: [insufficientEvidence()],
    onTransition(run) {
      if (run.pipelineState.workflowState === "CONFIRM") {
        run.pipelineState = {
          ...run.pipelineState,
          findingOverrides: [
            {
              findingId: "R1",
              fingerprint: run.pipelineState.finalizedFingerprint,
            },
          ],
        };
      }
    },
  });
  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    completed.pipelineState.finalizationResult.validationChanged,
    false,
  );
  assert.equal(
    completed.pipelineState.reviewResult.validationChange,
    "REJECTED",
  );
  assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 1);
  assert.equal(rejectionTransitions(fixture).length, 0);
  assert.throws(() =>
    assertRun({
      ...completed,
      pipelineState: { ...completed.pipelineState, findingOverrides: [] },
    }),
  );
});

test("recovery overrides use the terminal formatter fingerprint and still require replacement finalization", async (t) => {
  let formatted = false;
  const fixture = await recoveryFixture(t, {
    mode: "independent",
    replacements: [finalized(EXPANDED), finalized(EXPANDED), finalized()],
    rejections: [rejected(), rejected(), rejected()],
    async onRoleRun(role, request) {
      if (!formatted && request.schema === FINALIZATION_SCHEMA) {
        formatted = true;
        await writeFile(
          join(request.cwd, "formatted.txt"),
          "Formatter output.\n",
        );
      }
    },
  });
  const paused = await fixture.run();
  const fingerprint =
    paused.pipelineState.finalizationRecovery.feedback.contentFingerprint;
  assert.notEqual(
    fingerprint,
    paused.pipelineState.candidateReviewedFingerprint,
  );
  assert.equal(paused.pipelineState.finalizationResult, null);
  const action = { type: "override-finding", findingId: "R1" };
  assert.doesNotThrow(() =>
    planExecutionPipeline.validateResumeAction(paused, action),
  );
  assert.ok(
    planExecutionPipeline.projections
      .pause(paused)
      .nextActions.some((next) => next.action?.findingId === "R1"),
  );
  const result = await fixture.run({}, action);
  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingOverrides, [
    { findingId: "R1", fingerprint },
  ]);
  assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 4);
  assert.equal(calls(fixture, REVIEW_SCHEMA).length, 4);
  assert.equal(calls(fixture, CANDIDATE_REVIEW_SCHEMA).length, 1);
});

test("partial recovery override remains paused until the remaining evidence is resolved or retried", async (t) => {
  const finding = rejected({ ids: ["R1", "R2"] });
  // Distinct stable concerns must not share the same problem text.
  finding.findings[1] = {
    ...finding.findings[1],
    problem: "Finalization added unauthorized infrastructure.",
  };
  const fixture = await recoveryFixture(t, {
    mode: "independent",
    replacements: [finalized(EXPANDED), finalized(EXPANDED), finalized()],
    rejections: [finding, finding, finding],
  });
  await fixture.run();
  const paused = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );
  assert.equal(paused.pause.reason, "finalization_evidence_rejected");
  assert.deepEqual(planExecutionPipeline.projections.pause(paused).evidence, [
    "Finalization evidence finding R2 remains unresolved.",
  ]);
  assert.equal(paused.pipelineState.finalizationRecovery.attempts, 2);
  assert.equal(paused.pipelineState.finalizationRecovery.additionalAttempts, 0);
  assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 3);
  assert.throws(() =>
    planExecutionPipeline.validateResumeAction(paused, {
      type: "override-finding",
      findingId: "R1",
    }),
  );
  const completed = await fixture.run(
    {},
    { type: "override-finding", findingId: "R2" },
  );
  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 4);
});

test("mixed content changes clear feedback without replenishing the step's semantic allowance", async (t) => {
  let checks = 0;
  const fixture = await recoveryFixture(t, {
    replacements: [finalized(EXPANDED), finalized(EXPANDED)],
    rejections: [rejected(), rejected({ mixed: true }), rejected()],
    work: [checkAndFix("CHANGED"), checkAndFix()],
    async onRoleRun(role, request) {
      if (request.schema === CHECK_AND_FIX_SCHEMA && ++checks === 2) {
        await writeFile(join(request.cwd, "repaired.txt"), "Content fixed.\n");
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "finalization_evidence_rejected");
  assert.equal(paused.pipelineState.finalizationRecovery.attempts, 2);
  const reservations = fixture.transitions.filter(
    ({ options }) => options.activity?.kind === "evidence-retry",
  );
  assert.equal(reservations.length, 2);
  assert.equal(
    reservations[1].patch.pipelineState.finalizationRecovery.feedback,
    null,
  );
  assert.equal(
    reservations[1].patch.pipelineState.finalizationRecovery.attempts,
    2,
  );
});

test("infrastructure scope drift discards stale feedback without losing a pending attempt", async (t) => {
  let drifted = false;
  const fixture = await recoveryFixture(t);
  const fingerprint = fixture.runtime.git.validationInfrastructureFingerprint;
  fixture.runtime.git.validationInfrastructureFingerprint = async (options) => {
    const value = await fingerprint(options);
    if (
      fixture.currentRun.pipelineState.finalizationRecovery.required &&
      !drifted
    ) {
      drifted = true;
      return "d".repeat(64);
    }
    return value;
  };
  const result = await fixture.run();
  assert.equal(drifted, true);
  assert.equal(result.pipelineState.workflowState, "DONE");
  const reservation = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "evidence-retry",
  );
  assert.equal(
    reservation.patch.pipelineState.finalizationRecovery.feedback,
    null,
  );
  assert.equal(
    reservation.patch.pipelineState.finalizationRecovery.attempts,
    1,
  );
});

test("migration preserves safe workflow positions and consumed commit authority without inferring rejection", async (t) => {
  const snapshots = [];
  const fixture = await createFixture(t, {
    onTransition(run) {
      snapshots.push(structuredClone(run));
    },
  });
  const completed = await fixture.run();
  for (const run of [
    snapshots.find(
      ({ pipelineState }) => pipelineState.workflowState === "CONFIRM",
    ),
    snapshots.find(
      ({ pipelineState }) => pipelineState.pendingCommit?.status === "consumed",
    ),
    completed,
  ]) {
    const { finalizationRecovery, ...legacy } = run.pipelineState;
    const migrated = migratePlanExecutionStateV14({
      ...run,
      pipelineState: legacy,
    });
    assert.deepEqual(migrated, run.pipelineState);
    assert.doesNotThrow(() => assertRun({ ...run, pipelineState: migrated }));
  }
});

test("a product decision retires the pending recovery attempt before implementation resumes", async (t) => {
  for (const mode of ["independent", "lazy"]) {
    await t.test(mode, async (t) => {
      const fixture = await recoveryFixture(t, {
        mode,
        work: mode === "lazy" ? [cleanConfirmation()] : [],
        replacements: [
          {
            ...finalized(),
            ...implementationProductDecision(),
            skillPath: "",
            requiredChecks: [],
            validationInfrastructure: [],
            checks: [],
          },
          compatibilityReady(),
          implementationCompleted(),
          ...(mode === "lazy" ? [checkAndFix(), cleanConfirmation()] : []),
          finalized(),
        ],
      });
      const paused = await fixture.run();
      assert.equal(paused.pause.reason, "product_decision_required");
      assert.equal(paused.pipelineState.finalizationRecovery.attempts, 1);
      fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

      const completed = await fixture.run();
      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.equal(paused.pipelineState.finalizationRecovery.pending, false);
      assert.equal(paused.pipelineState.finalizationRecovery.feedback, null);
      const reservations = fixture.transitions.filter(
        ({ options }) => options.activity?.kind === "evidence-retry",
      );
      assert.equal(reservations.length, 2);
      assert.equal(
        reservations[1].patch.pipelineState.finalizationRecovery.attempts,
        2,
      );
      assert.equal(calls(fixture, FINALIZATION_SCHEMA).length, 3);
    });
  }
});

test("repeated malformed replacement fails closed without restoring rejected evidence", async (t) => {
  const invalid = { ...finalized(), checks: [] };
  const fixture = await recoveryFixture(t, {
    replacements: [invalid, invalid],
  });
  await assert.rejects(fixture.run(), {
    code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  });
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(fixture.currentRun.pipelineState.finalizationResult, null);
  assert.equal(
    fixture.currentRun.pipelineState.finalizationRecovery.attempts,
    1,
  );
  assert.equal(fixture.currentRun.pipelineState.pendingCommit, null);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    0,
  );
});

test("replacement confirmation remains read-only and cannot commit after mutation", async (t) => {
  let confirmations = 0;
  const fixture = await recoveryFixture(t, {
    async onRoleRun(role, request) {
      if (request.schema === CLEAN_CONFIRM_SCHEMA && ++confirmations === 2) {
        await writeFile(
          join(request.cwd, "forbidden.txt"),
          "Read-only mutation.\n",
        );
      }
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(paused.pipelineState.reviewedFingerprint, null);
  assert.equal(paused.pipelineState.pendingCommit, null);
  assert.equal(
    fixture.calls.worker.filter(({ access }) => access === "local-commit")
      .length,
    0,
  );
});
