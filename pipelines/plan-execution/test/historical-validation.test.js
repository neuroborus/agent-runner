import assert from "node:assert/strict";
import test from "node:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { planExecutionPipeline } from "../src/index.js";
import {
  normalizePipelineState,
  retainWorkReport,
  normalizeImplementationResult,
  normalizeCheckAndFixResult,
  normalizeResolutionResult,
  normalizeFinalizationResult,
} from "../src/workflow-contract.js";
import {
  CANDIDATE_REVIEW_SCHEMA,
  CLEAN_CONFIRM_SCHEMA,
  REVIEW_SCHEMA,
  DISPUTE_RECONSIDERATION_SCHEMA,
  IMPLEMENTATION_SCHEMA,
  CHECK_AND_FIX_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  FINDING_RECOVERY_SCHEMA,
  FINALIZATION_SCHEMA,
} from "../src/schemas.js";
import { HISTORICAL_VALIDATION_INSTRUCTIONS } from "../src/prompts.js";
import {
  PLAN,
  cleanConfirmation,
  cleanConfirmationFindings,
  createFixture,
  implementationCompleted,
  checkAndFix,
  finalizationPassed,
  finalizationFailed,
  finalizationBlocked,
  resolution,
  reviewApproved,
  reviewFindings,
  terminalConfirmation,
  terminalLazyConfirmation,
  trustedValidationSnapshot,
  finalizationWithTrustedCheck,
  bootstrapReady,
  clarificationReady,
  compatibilityReady,
  reconciliationResolved,
  reconciliationDisagreement,
  arbitrationResolved,
  matchesSchemaSubset,
  prepareValidationMigration,
  reconsideration,
  findingArbitration,
  stagnation,
} from "./support/index.js";

for (const phase of ["ARBITRATE_BOOTSTRAP", "ARBITRATE_VALIDATION_MIGRATION"]) {
  for (const direction of ["SYNTHESIZE", "PLAN_REVISION_REQUIRED"]) {
    test(`${phase} ${direction} retains rationale-only history through publication loss and reconstruction`, async (t) => {
      const migration = phase === "ARBITRATE_VALIDATION_MIGRATION";
      const arbitrated = {
        ...arbitrationResolved(),
        direction,
        rationale:
          "Arbitration-only disclosure: a reserved synthetic check ran early; no credit is granted and all FINALIZE checks remain pending.",
        ...(direction === "PLAN_REVISION_REQUIRED"
          ? {
              summary: "",
              reason: "The current plan requires an incompatible behavior.",
              evidence: ["A revised plan and new run are required."],
            }
          : {}),
      };
      const report = {
        step: migration ? 1 : null,
        phase,
        arbitration: { direction, rationale: arbitrated.rationale },
      };
      let laterRequests = 0;
      let observeHistory = false;
      const create = migration ? prepareValidationMigration : createFixture;
      const fixture = await create(t, {
        arbiter: [arbitrated],
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          migration ? reconciliationResolved() : reconciliationDisagreement(),
        ],
        workWorker: [
          implementationCompleted(),
          finalizationPassed(),
          ...(migration
            ? [
                bootstrapReady("Worker"),
                reconciliationDisagreement(),
                finalizationPassed(),
              ]
            : []),
        ],
        reviewer: [bootstrapReady("Reviewer")],
        workReviewer: migration ? [bootstrapReady("Reviewer")] : [],
        onRoleRun(_role, request) {
          if (
            !observeHistory ||
            request.access === "local-commit" ||
            !fixture.currentRun.pipelineState.workReports.some(
              (entry) => entry.phase === phase,
            )
          )
            return;
          for (const prompt of [request.prompt, request.recoveryPrompt])
            assert.ok(prompt.includes(arbitrated.rationale));
          laterRequests++;
        },
      });
      observeHistory = true;
      const transition = fixture.runtime.transition;
      const loss = new Error(
        "Synthetic arbitration publication acknowledgement loss",
      );
      let published = null;
      fixture.runtime.transition = async (...args) => {
        const next = await transition(...args);
        if (
          published === null &&
          next.pipelineState.workReports.some((entry) => entry.phase === phase)
        ) {
          published = structuredClone(next);
          throw loss;
        }
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      assert.notEqual(published, null);
      assert.deepEqual(fixture.currentRun, published);
      assert.deepEqual(
        published.pipelineState.workReports.find(
          (entry) => entry.phase === phase,
        ),
        report,
      );
      assert.equal(published.pipelineState.finalizationResult, null);
      assert.equal(published.pipelineState.candidateReviewResult, null);
      fixture.runtime.transition = transition;
      fixture.persistPipelineState(
        JSON.parse(JSON.stringify(published.pipelineState)),
      );
      const done = await fixture.run();
      assert.equal(fixture.calls.arbiter.length, 1);
      assert.deepEqual(
        normalizePipelineState(
          JSON.parse(JSON.stringify(done.pipelineState)),
        ).workReports.find((entry) => entry.phase === phase),
        report,
      );
      if (direction === "PLAN_REVISION_REQUIRED") {
        assert.equal(done.pause.reason, "plan_revision_required");
        assert.deepEqual(done.counters, published.counters);
      } else {
        assert.equal(
          done.pipelineState.workflowState,
          "DONE",
          JSON.stringify(done.pause),
        );
        assert.ok(laterRequests > 0);
        assert.equal(
          fixture.calls.worker.filter(
            ({ schema }) => schema === FINALIZATION_SCHEMA,
          ).length,
          migration ? 2 : 1,
        );
        assert.deepEqual(
          done.pipelineState.requiredChecks,
          finalizationPassed().requiredChecks,
        );
      }
    });
  }
}

for (const mode of ["independent", "combined"]) {
  for (const kind of mode === "independent"
    ? ["finding", "stagnation", "bootstrap"]
    : ["finding", "stagnation"]) {
    test(`${mode} ${kind} product decision retains rationale-only history after answer and reconstruction`, async (t) => {
      const arbitrated =
        kind === "bootstrap"
          ? {
              ...arbitrationResolved(),
              direction: "PRODUCT_DECISION_REQUIRED",
              summary: "",
            }
          : kind === "finding"
            ? findingArbitration("REQUIREMENT_AMBIGUOUS")
            : stagnation("PRODUCT_DECISION_REQUIRED");
      Object.assign(arbitrated, {
        rationale:
          "Rationale-only disclosure: a reserved synthetic check ran early, without credit; all FINALIZE checks remain pending.",
        question: "Should behavior use variant A or variant B?",
        options: ["Variant A", "Variant B"],
        whyBlocked: "Both product variants satisfy the current requirements.",
        evidence: ["The repository does not select a variant."],
      });
      const phase =
        kind === "bootstrap"
          ? "ARBITRATE_BOOTSTRAP"
          : kind === "finding"
            ? "ARBITRATE_FINDING"
            : "ARBITRATE_STAGNATION";
      const report = {
        step: kind === "bootstrap" ? null : 1,
        phase,
        arbitration: {
          ...(kind === "finding" ? { findingId: "R1" } : {}),
          direction: arbitrated.direction,
          rationale: arbitrated.rationale,
        },
      };
      const converge = mode === "combined" ? [checkAndFix()] : [];
      let laterRequests = 0;
      const fixture = await createFixture(t, {
        mode,
        modeSettings: { maxDisputesPerFinding: 1, stagnationWindowRounds: 1 },
        plan: `${PLAN}\n\n## Commit 2: fix(test): finish behavior\n\nFinish the requested behavior.`,
        arbiter: [arbitrated],
        ...(kind === "bootstrap"
          ? {
              worker: [
                clarificationReady(),
                bootstrapReady("Worker", [1, 2]),
                reconciliationDisagreement(),
                compatibilityReady(),
                bootstrapReady("Worker", [1, 2]),
                reconciliationResolved(),
              ],
              reviewer: [
                bootstrapReady("Reviewer", [1, 2]),
                bootstrapReady("Reviewer", [1, 2]),
              ],
            }
          : {}),
        workReviewer:
          kind === "bootstrap"
            ? []
            : [
                reviewFindings("R1"),
                kind === "finding"
                  ? reconsideration("UPHOLD", "R1")
                  : reviewFindings("R2"),
              ],
        workWorker: [
          ...(kind === "bootstrap"
            ? []
            : [
                implementationCompleted(),
                ...converge,
                resolution({
                  id: "R1",
                  decision: kind === "finding" ? "DISPUTE" : "FIX",
                }),
                ...(kind === "stagnation" ? converge : []),
                compatibilityReady(),
              ]),
          implementationCompleted(),
          ...converge,
          finalizationPassed(),
          implementationCompleted(),
          ...converge,
          finalizationPassed(),
        ],
        onRoleRun(_role, request) {
          if (
            request.access === "local-commit" ||
            !fixture.currentRun.pipelineState.workReports.some(
              (entry) => entry.phase === phase,
            )
          )
            return;
          for (const prompt of [request.prompt, request.recoveryPrompt])
            assert.ok(prompt.includes(arbitrated.rationale));
          if (fixture.currentRun.pipelineState.currentStep === 1)
            assert.ok(
              fixture.currentRun.counters.fixRounds >= consumed.fixRounds,
            );
          laterRequests++;
        },
      });
      const transition = fixture.runtime.transition;
      const loss = new Error(
        "Synthetic product-decision publication acknowledgement loss",
      );
      let published = null;
      fixture.runtime.transition = async (...args) => {
        const next = await transition(...args);
        if (
          published === null &&
          next.pause?.reason === "product_decision_required"
        ) {
          published = structuredClone(next);
          throw loss;
        }
        return next;
      };
      await assert.rejects(
        fixture.run({ maxDisputesPerFinding: 1, stagnationWindowRounds: 1 }),
        (cause) => cause === loss,
      );
      assert.notEqual(published, null);
      assert.deepEqual(fixture.currentRun, published);
      assert.deepEqual(
        published.pipelineState.workReports.find(
          (entry) => entry.phase === phase,
        ),
        report,
      );
      assert.equal(published.pipelineState.finalizationResult, null);
      assert.equal(published.pipelineState.candidateReviewResult, null);
      assert.deepEqual(published.pipelineState.pendingDisputes, []);
      assert.deepEqual(published.pipelineState.findingArbitrations, []);
      const consumed = published.counters;
      fixture.runtime.transition = transition;
      fixture.persistPipelineState(
        JSON.parse(JSON.stringify(published.pipelineState)),
      );
      fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);
      const done = await fixture.run();
      assert.equal(
        done.pipelineState.workflowState,
        "DONE",
        JSON.stringify(done.pause),
      );
      assert.ok(laterRequests > 0);
      assert.equal(fixture.calls.arbiter.length, 1);
      assert.equal(done.counters.productDecisions, 1);
      assert.equal(done.pipelineState.completedCommits.length, 2);
      assert.deepEqual(done.pipelineState.findings, []);
      assert.equal(
        fixture.calls.worker.filter(
          ({ schema }) => schema === FINALIZATION_SCHEMA,
        ).length,
        2,
      );
      assert.deepEqual(
        done.pipelineState.requiredChecks,
        finalizationPassed().requiredChecks,
      );
      const restored = normalizePipelineState(
        JSON.parse(JSON.stringify(done.pipelineState)),
      );
      assert.deepEqual(
        restored.workReports.find((entry) => entry.phase === phase),
        report,
      );
      assert.throws(
        () =>
          normalizePipelineState({
            ...restored,
            ...(kind === "finding"
              ? { findingArbitrations: [report.arbitration] }
              : { stagnationDirection: report.arbitration }),
          }),
        { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
      );
    });
  }
}

for (const mode of ["independent", "combined"]) {
  for (const direction of ["WITHDRAW", "WORKER_CORRECT", "REVIEWER_CORRECT"]) {
    test(`${mode} retains ${direction} disclosures through reconstruction and plan-step advancement`, async (t) => {
      const reconsidered = reconsideration(
        direction === "WITHDRAW" ? "WITHDRAW" : "UPHOLD",
        "R1",
      );
      reconsidered.decisions[0].reason =
        "Reconsideration-only disclosure: a reserved synthetic check ran early.";
      reconsidered.decisions[0].evidence = [
        "That historical execution grants no credit; FINALIZE retains the complete pending inventory.",
      ];
      const arbitrated = findingArbitration(
        direction === "WITHDRAW" ? "WORKER_CORRECT" : direction,
      );
      arbitrated.rationale =
        "Arbitration-only disclosure: a separate reserved synthetic check ran early, without acceptance credit.";
      const converge = mode === "combined" ? [checkAndFix()] : [];
      let accepted = false;
      let laterRequests = 0;
      const fixture = await createFixture(t, {
        mode,
        modeSettings: { maxDisputesPerFinding: 1 },
        plan: `${PLAN}\n\n## Commit 2: fix(test): finish behavior\n\nFinish the requested behavior.`,
        workWorker: [
          implementationCompleted(),
          ...converge,
          resolution({ id: "R1", decision: "DISPUTE" }),
          ...(direction === "REVIEWER_CORRECT"
            ? [resolution({ id: "R1", decision: "FIX" })]
            : []),
          ...converge,
          finalizationPassed(),
          implementationCompleted(),
          ...converge,
          finalizationPassed(),
        ],
        workReviewer: [reviewFindings("R1"), reconsidered],
        arbiter: direction === "WITHDRAW" ? [] : [arbitrated],
        onRoleRun(role, request) {
          if (
            direction === "WITHDRAW"
              ? request.schema === DISPUTE_RECONSIDERATION_SCHEMA
              : role === "arbiter"
          ) {
            accepted = true;
            return;
          }
          if (!accepted || request.access === "local-commit") return;
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.ok(prompt.includes(reconsidered.decisions[0].reason));
            assert.ok(prompt.includes(reconsidered.decisions[0].evidence[0]));
            if (direction !== "WITHDRAW")
              assert.ok(prompt.includes(arbitrated.rationale));
          }
          laterRequests++;
        },
      });
      if (mode === "combined" && direction === "WORKER_CORRECT") {
        for (const phase of ["RECONSIDER_DISPUTES", "ARBITRATE_FINDING"]) {
          const transition = fixture.runtime.transition;
          const loss = new Error(
            "Synthetic adjudication publication acknowledgement loss",
          );
          let lost = false;
          fixture.runtime.transition = async (...args) => {
            const next = await transition(...args);
            if (
              !lost &&
              next.pipelineState.workReports.some(
                (report) => report.phase === phase,
              )
            ) {
              lost = true;
              throw loss;
            }
            return next;
          };
          await assert.rejects(
            fixture.run({ maxDisputesPerFinding: 1 }),
            (cause) => cause === loss,
          );
          fixture.runtime.transition = transition;
          fixture.persistPipelineState(
            JSON.parse(JSON.stringify(fixture.currentRun.pipelineState)),
          );
        }
      }
      const done = await fixture.run({ maxDisputesPerFinding: 1 });
      assert.equal(
        done.pipelineState.workflowState,
        "DONE",
        JSON.stringify(done.pause),
      );
      assert.equal(done.pipelineState.completedCommits.length, 2);
      assert.ok(laterRequests > 0);
      assert.deepEqual(done.pipelineState.disputeHistory, []);
      assert.deepEqual(done.pipelineState.findingArbitrations, []);
      assert.deepEqual(done.pipelineState.findings, []);
      assert.equal(
        fixture.calls.reviewer.filter(
          ({ schema }) => schema === DISPUTE_RECONSIDERATION_SCHEMA,
        ).length,
        1,
      );
      assert.equal(
        fixture.calls.arbiter.length,
        direction === "WITHDRAW" ? 0 : 1,
      );
      assert.equal(
        fixture.calls.worker.filter(
          ({ schema }) => schema === FINALIZATION_SCHEMA,
        ).length,
        2,
      );
      assert.deepEqual(
        done.pipelineState.requiredChecks,
        finalizationPassed().requiredChecks,
      );
      const history = JSON.parse(JSON.stringify(done.pipelineState));
      assert.deepEqual(
        normalizePipelineState(history).workReports,
        done.pipelineState.workReports,
      );
    });
  }
}

test("stagnation-only rationale remains historical context after fixes and step advancement", async (t) => {
  const arbitrated = stagnation("CONTINUE_FIXES");
  arbitrated.rationale =
    "Stagnation-only disclosure: a reserved synthetic check ran early; it grants no credit and FINALIZE retains all checks.";
  let accepted = false;
  let laterRequests = 0;
  const fixture = await createFixture(t, {
    plan: `${PLAN}\n\n## Commit 2: fix(test): finish behavior\n\nFinish the requested behavior.`,
    arbiter: [arbitrated],
    workReviewer: [reviewFindings("R1"), reviewFindings("R2")],
    workWorker: [
      implementationCompleted(),
      resolution({ id: "R1", decision: "FIX" }),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
    onRoleRun(role, request) {
      if (role === "arbiter") {
        accepted = true;
        return;
      }
      if (!accepted || request.access === "local-commit") return;
      for (const prompt of [request.prompt, request.recoveryPrompt])
        assert.ok(prompt.includes(arbitrated.rationale));
      laterRequests++;
    },
  });
  const done = await fixture.run({ stagnationWindowRounds: 1 });
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.ok(laterRequests > 0);
  assert.equal(done.pipelineState.stagnationDirection, null);
  assert.equal(done.pipelineState.completedCommits.length, 2);
  assert.deepEqual(
    done.pipelineState.requiredChecks,
    finalizationPassed().requiredChecks,
  );
});

test("a terminal plan-revision stop preserves the separate stagnation rationale", async (t) => {
  const arbitrated = stagnation("PLAN_REVISION_REQUIRED");
  Object.assign(arbitrated, {
    rationale:
      "Rationale-only disclosure: the reserved synthetic check ran early without credit.",
    reason: "The remaining requirement needs a revised plan.",
    evidence: ["The frozen plan cannot express the required change."],
  });
  const fixture = await createFixture(t, {
    arbiter: [arbitrated],
    workReviewer: [reviewFindings("R1"), reviewFindings("R2")],
    workWorker: [
      implementationCompleted(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });
  const paused = await fixture.run({ stagnationWindowRounds: 1 });
  assert.equal(paused.pause.reason, "plan_revision_required");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.completedCommits.length, 0);
  const restored = normalizePipelineState(
    JSON.parse(JSON.stringify(paused.pipelineState)),
  );
  assert.deepEqual(restored.workReports.at(-1), {
    step: 1,
    phase: "ARBITRATE_STAGNATION",
    arbitration: {
      direction: arbitrated.direction,
      rationale: arbitrated.rationale,
    },
  });
});

test("adjudication history is strict normalized context without gate authority", () => {
  const decision = {
    findingId: "R1",
    direction: "WITHDRAW",
    reason: "Containment preserves the disclosure.",
    evidence: [],
  };
  const report = {
    step: 1,
    phase: "RECONSIDER_DISPUTES",
    decisions: [decision],
  };
  assert.deepEqual(retainWorkReport([], report), [report]);
  for (const decisions of [
    [],
    [decision, decision],
    [{ ...decision, findingId: "F1" }],
    [{ ...decision, findingId: ["R1"] }],
    [{ ...decision, direction: "CLEAN" }],
    [{ ...decision, reason: "" }],
    [{ ...decision, reason: " Noncanonical reason. " }],
    [{ ...decision, evidence: ["x".repeat(4001)] }],
    [{ ...decision, evidence: [" Noncanonical evidence. "] }],
    [{ ...decision, fingerprint: "untrusted" }],
  ])
    assert.throws(() => retainWorkReport([], { ...report, decisions }), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  for (const [phase, arbitration] of [
    ...["ARBITRATE_BOOTSTRAP", "ARBITRATE_VALIDATION_MIGRATION"].flatMap(
      (phase) =>
        [
          "USE_WORKER",
          "USE_REVIEWER",
          "SYNTHESIZE",
          "PLAN_REVISION_REQUIRED",
          ...(phase === "ARBITRATE_BOOTSTRAP"
            ? ["PRODUCT_DECISION_REQUIRED"]
            : []),
        ].map((direction) => [
          phase,
          { direction, rationale: "Historical disclosure remains preserved." },
        ]),
    ),
    [
      "ARBITRATE_FINDING",
      {
        findingId: "R1",
        direction: "WORKER_CORRECT",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_FINDING",
      {
        findingId: "R1",
        direction: "REQUIREMENT_AMBIGUOUS",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_STAGNATION",
      {
        direction: "PRODUCT_DECISION_REQUIRED",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_STAGNATION",
      {
        direction: "PLAN_REVISION_REQUIRED",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
    [
      "ARBITRATE_STAGNATION",
      {
        direction: "CONTINUE_FIXES",
        rationale: "Historical disclosure remains preserved.",
      },
    ],
  ]) {
    const entry = {
      step: phase === "ARBITRATE_BOOTSTRAP" ? null : 1,
      phase,
      arbitration,
    };
    assert.deepEqual(retainWorkReport([], entry), [entry]);
    for (const step of [
      0,
      -1,
      "1",
      Number.MAX_SAFE_INTEGER + 1,
      phase === "ARBITRATE_BOOTSTRAP" ? 1 : undefined,
    ])
      assert.throws(() => retainWorkReport([], { ...entry, step }), {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      });
    if (phase === "ARBITRATE_VALIDATION_MIGRATION") {
      const runReport = { ...entry, step: null };
      assert.deepEqual(retainWorkReport([], runReport), [runReport]);
    } else if (phase !== "ARBITRATE_BOOTSTRAP")
      assert.throws(() => retainWorkReport([], { ...entry, step: null }), {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      });
    for (const invalid of [
      null,
      { ...arbitration, direction: "APPROVED" },
      ...(phase === "ARBITRATE_VALIDATION_MIGRATION"
        ? [{ ...arbitration, direction: "PRODUCT_DECISION_REQUIRED" }]
        : []),
      { ...arbitration, rationale: "" },
      { ...arbitration, rationale: " Noncanonical rationale. " },
      { ...arbitration, rationale: "x".repeat(4001) },
      {
        ...arbitration,
        direction:
          phase === "ARBITRATE_FINDING"
            ? "PRODUCT_DECISION_REQUIRED"
            : "REQUIREMENT_AMBIGUOUS",
      },
      { ...arbitration, decision: { question: "Unbound active decision" } },
      { ...arbitration, findingId: "F1" },
      { ...arbitration, findingId: ["R1"] },
      { ...arbitration, validationChange: "ACCEPTED" },
    ])
      assert.throws(
        () => retainWorkReport([], { ...entry, arbitration: invalid }),
        { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
      );
  }
});

const stop = (base = implementationCompleted()) => ({
  ...base,
  status: "VALIDATION_POLICY_BLOCKED",
  ...Object.fromEntries(
    Object.entries(base)
      .filter(([key]) => key !== "status")
      .map(([key, value]) => [key, Array.isArray(value) ? [] : ""]),
  ),
  reason: "The frozen task makes the proven execution irrecoverable.",
  evidence: [
    "The Worker disclosed executing the reserved synthetic check before FINALIZE.",
    "Task policy: execution before FINALIZE makes this run ineligible for acceptance.",
    "Disclosure and later checks cannot satisfy that explicit ineligibility rule.",
  ],
});

const contracts = [
  [
    IMPLEMENTATION_SCHEMA,
    implementationCompleted,
    normalizeImplementationResult,
  ],
  [CHECK_AND_FIX_SCHEMA, checkAndFix, normalizeCheckAndFixResult],
  [
    FINDING_RESOLUTION_SCHEMA,
    () => resolution({ id: "R1", decision: "FIX" }),
    (value) => normalizeResolutionResult(value, [], new Set()),
  ],
  [FINALIZATION_SCHEMA, finalizationPassed, normalizeFinalizationResult],
];

for (const [mode, phase] of [
  ["independent", "IMPLEMENT"],
  ["lazy", "CHECK_AND_FIX"],
  ["combined", "CHECK_AND_FIX"],
  ["independent", "RESOLVE_FINDINGS"],
  ["lazy", "RESOLVE_FINDINGS"],
  ["combined", "RESOLVE_FINDINGS"],
]) {
  test(`${mode} ${phase} retains blocked-only disclosures through retry and reconstruction`, async (t) => {
    const base =
      phase === "RESOLVE_FINDINGS"
        ? resolution({ id: "F1", decision: "FIX" })
        : implementationCompleted();
    const blocked = {
      ...base,
      status: "BLOCKED",
      reason: "A synthetic prerequisite is temporarily unavailable.",
      evidence: [
        "Historical disclosure solely in blocked evidence: the reserved synthetic check ran early without acceptance credit.",
      ],
    };
    if (phase === "RESOLVE_FINDINGS") blocked.decisions = [];
    else blocked.summary = "";
    const convergence = mode === "independent" ? [] : [checkAndFix()];
    const restated = mode === "combined" && phase === "RESOLVE_FINDINGS";
    const invalid = resolution({ id: "F1", decision: "FIX" });
    invalid.decisions[0].reason = "";
    const fixture = await createFixture(t, {
      mode,
      workWorker: [
        ...(phase === "IMPLEMENT" ? [blocked] : []),
        implementationCompleted(),
        ...(phase === "CHECK_AND_FIX" ? [blocked] : []),
        ...convergence,
        ...(phase === "RESOLVE_FINDINGS"
          ? [
              finalizationFailed("F1"),
              ...(restated ? [invalid] : []),
              blocked,
              resolution({ id: "F1", decision: "FIX" }),
              ...convergence,
            ]
          : []),
        finalizationPassed(),
      ],
      async onRoleRun(_role, request) {
        if (
          restated &&
          request.schema === FINDING_RESOLUTION_SCHEMA &&
          request.access === "workspace-write"
        )
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
      },
    });
    const paused = await fixture.run();
    assert.equal(
      paused.pause?.reason,
      "environment_blocked",
      JSON.stringify(paused.pause),
    );
    assert.deepEqual(
      paused.pipelineState.workReports.find(
        (entry) => entry.status === "BLOCKED",
      ),
      {
        step: 1,
        phase,
        status: "BLOCKED",
        reason: blocked.reason,
        evidence: blocked.evidence,
      },
    );
    assert.equal(
      paused.pipelineState.finalizationResult?.status === "PASS",
      false,
    );
    fixture.persistPipelineState(
      JSON.parse(JSON.stringify(paused.pipelineState)),
    );
    const before = Object.fromEntries(
      Object.entries(fixture.calls).map(([role, calls]) => [
        role,
        calls.length,
      ]),
    );
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    for (const role of ["worker", "reviewer"])
      for (const request of fixture.calls[role].slice(before[role])) {
        if (request.access === "local-commit") continue;
        for (const prompt of [request.prompt, request.recoveryPrompt])
          for (const fact of [blocked.reason, blocked.evidence[0]])
            assert.ok(prompt.includes(fact));
      }
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      finalizationPassed().requiredChecks,
    );
    if (restated)
      assert.deepEqual(
        fixture.calls.worker
          .filter(({ schema }) =>
            [FINDING_RESOLUTION_SCHEMA, FINDING_RECOVERY_SCHEMA].includes(
              schema,
            ),
          )
          .map(({ access }) => access),
        ["workspace-write", "read-only", "read-only"],
      );
    assert.doesNotThrow(() =>
      normalizePipelineState(JSON.parse(JSON.stringify(done.pipelineState))),
    );
  });
}

test("blocked work reports retain strict normalized context without approval fields", () => {
  const report = {
    step: 1,
    phase: "IMPLEMENT",
    status: "BLOCKED",
    reason: "A prerequisite is unavailable.",
    evidence: ["Retained disclosure."],
  };
  assert.deepEqual(retainWorkReport([], report), [report]);
  assert.deepEqual(retainWorkReport([report], report), [report]);
  for (const invalid of [
    { ...report, step: 0 },
    { ...report, phase: "CONFIRM" },
    { ...report, status: "PASS" },
    { ...report, reason: "" },
    { ...report, reason: "  Noncanonical reason. " },
    { ...report, evidence: [] },
    { ...report, evidence: ["x".repeat(4001)] },
    { ...report, evidence: ["  Noncanonical evidence. "] },
    { ...report, checks: [] },
    { ...report, decisions: [] },
  ])
    assert.throws(() => retainWorkReport([], invalid), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
});

test("policy stops strictly require inactive fields and bounded execution, requirement and disposition evidence", () => {
  for (const [schema, base, normalize] of contracts) {
    const value = stop(base());
    assert.ok(
      matchesSchemaSubset(
        schema,
        schema.properties.result ? { result: value } : value,
      ),
    );
    assert.equal(normalize(value).status, "VALIDATION_POLICY_BLOCKED");
    for (const invalid of [
      { ...stop(base()), evidence: ["unknown"] },
      { ...stop(base()), evidence: ["execution", "requirement", ""] },
      { ...stop(base()), reason: "" },
      { ...stop(base()), question: "Which policy?" },
      { ...stop(base()), extra: "untrusted" },
    ])
      assert.throws(() => normalize(invalid), {
        code: "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
      });
  }
});

for (const mode of ["independent", "lazy", "combined"]) {
  for (const phase of [
    "IMPLEMENT",
    "CHECK_AND_FIX",
    "RESOLVE_FINDINGS",
    "FINALIZE",
  ]) {
    if (
      (mode === "independent" && phase === "CHECK_AND_FIX") ||
      (mode === "lazy" && phase === "RESOLVE_FINDINGS")
    )
      continue;
    test(`${mode} ${phase} policy stop precedes gate acceptance and trusted execution`, async (t) => {
      const base =
        phase === "FINALIZE"
          ? finalizationPassed()
          : phase === "CHECK_AND_FIX"
            ? checkAndFix()
            : phase === "RESOLVE_FINDINGS"
              ? resolution({ id: "R1", decision: "FIX" })
              : implementationCompleted();
      const worker =
        phase === "IMPLEMENT"
          ? [stop(base)]
          : [
              implementationCompleted(),
              ...(phase === "CHECK_AND_FIX"
                ? []
                : mode === "independent"
                  ? []
                  : [checkAndFix()]),
              stop(base),
            ];
      let trustedRuns = 0;
      const trustedValidation = trustedValidationSnapshot();
      const bootstrap = (role) => ({
        ...bootstrapReady(role),
        requiredChecks:
          finalizationWithTrustedCheck(trustedValidation).requiredChecks,
      });
      const fixture = await createFixture(t, {
        worker: [
          clarificationReady(),
          bootstrap("Worker"),
          ...(mode === "lazy" ? [] : [reconciliationResolved()]),
        ],
        reviewer: [bootstrap("Reviewer")],
        mode,
        workWorker: worker,
        ...(phase === "RESOLVE_FINDINGS"
          ? { workReviewer: [reviewFindings("R1")] }
          : {}),
        modeSettings: { trustedChecks: ["service-check"] },
        trustedValidation,
        async onRoleRun(_role, request) {
          if (
            mode === "combined" &&
            phase === "CHECK_AND_FIX" &&
            request.schema === CHECK_AND_FIX_SCHEMA
          )
            await writeFile(
              join(request.cwd, "safe-repair.txt"),
              "safe repair\n",
            );
        },
        onTrustedValidation() {
          trustedRuns++;
          throw new Error("No checks may launch after a policy stop");
        },
      });
      const paused = await fixture.run({ trustedChecks: ["service-check"] });
      assert.equal(
        paused.pause?.reason,
        "validation_policy_blocked",
        JSON.stringify(paused.pause),
      );
      assert.equal(paused.pause.checkpoint, phase);
      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(paused.pipelineState.completedCommits.length, 0);
      assert.equal(trustedRuns, 0);
      if (phase === "CHECK_AND_FIX" && mode === "combined")
        assert.equal(paused.counters.fixRounds, 1);
      assert.equal(paused.pipelineState.finalizationResult, null);
      const projection = planExecutionPipeline.projections.pause(paused);
      assert.deepEqual(projection.nextActions, []);
      assert.deepEqual(projection.evidence, stop().evidence);
      assert.match(projection.explanation, /cannot waive/u);
      for (const action of [
        null,
        { type: "extra-fix-rounds", amount: 1 },
        { type: "override-finding", findingId: "R1" },
      ])
        assert.throws(
          () => planExecutionPipeline.validateResumeAction(paused, action),
          /no retry or override/u,
        );
      const request = fixture.calls.worker.at(-1);
      assert.ok(request.prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS));
      assert.ok(
        request.recoveryPrompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS),
      );
      assert.deepEqual(
        planExecutionPipeline.migrations[40](paused),
        paused.pipelineState,
      );
    });
  }
}

test("contained historical finding resolves without cosmetic mutation and still reaches complete later gates", async (t) => {
  const disposition = resolution({ id: "R1", decision: "FIX" });
  disposition.decisions[0].reason =
    "Retain the proven early execution as history; no coverage is credited and the full checks remain with FINALIZE.";
  const historical = reviewFindings("R1");
  historical.findings[0].problem =
    "The Worker disclosed a synthetic validation command executed before FINALIZE.";
  historical.findings[0].reason =
    "The task reserves that validation for FINALIZE.";
  historical.findings[0].suggestedAction =
    "Contain the historical violation under the current task authority, retaining disclosure and pending checks.";
  const fixture = await createFixture(t, {
    mode: "combined",
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      disposition,
      checkAndFix(),
      resolution({ id: "R2", decision: "FIX" }),
      checkAndFix(),
      finalizationPassed(),
    ],
    workReviewer: [historical, reviewFindings("R2")],
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  const resolving = fixture.calls.worker.find(
    ({ schema }) => schema === FINDING_RESOLUTION_SCHEMA,
  );
  assert.ok(resolving.prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS));
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    1,
  );
  const confirming = fixture.calls.reviewer.at(-1);
  assert.ok(confirming.prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS));
  assert.ok(confirming.recoveryPrompt.includes(historical.findings[0].problem));
  assert.ok(
    confirming.recoveryPrompt.includes(disposition.decisions[0].reason),
  );
  assert.deepEqual(
    done.pipelineState.requiredChecks,
    fixture.transitions.find(
      ({ patch }) => patch?.pipelineState.workflowState === "IMPLEMENT",
    ).patch.pipelineState.requiredChecks,
  );
});

test("a malformed policy report is restated read-only, preserving reconciled work and its consumed allowance", async (t) => {
  const report = stop(resolution({ id: "R1", decision: "FIX" }));
  const malformed = { ...report, evidence: ["insufficient"] };
  const fixture = await createFixture(t, {
    workWorker: [implementationCompleted(), malformed, report],
    workReviewer: [reviewFindings("R1")],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "validation_policy_blocked");
  const calls = fixture.calls.worker.filter(({ schema }) =>
    [FINDING_RESOLUTION_SCHEMA, FINDING_RECOVERY_SCHEMA].includes(schema),
  );
  assert.deepEqual(
    calls.map(({ access }) => access),
    ["workspace-write", "read-only"],
  );
  assert.ok(calls[1].prompt.includes(HISTORICAL_VALIDATION_INSTRUCTIONS));
  assert.match(calls[1].prompt, /exactly-three-policy-evidence-items/u);
  assert.equal(paused.pipelineState.writableResult.stage, "correcting");
  assert.equal(paused.pipelineState.writableResult.attempts, 1);
  assert.equal(paused.counters.fixRounds, 0);
  assert.deepEqual(
    paused.pipelineState.findings.map(({ id }) => id),
    ["R1"],
  );
  const settled = structuredClone(paused);
  await assert.rejects(fixture.run(), /no retry or override/u);
  assert.deepEqual(fixture.currentRun, settled);
});

test("a lazy finalization repair preserves its originating policy-stop checkpoint", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      finalizationFailed("F1"),
      stop(resolution({ id: "F1", decision: "FIX" })),
    ],
    async onRoleRun(_role, request) {
      if (request.schema === FINDING_RESOLUTION_SCHEMA)
        await writeFile(join(request.cwd, "safe-repair.txt"), "safe repair\n");
    },
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "validation_policy_blocked");
  assert.equal(paused.pause.checkpoint, "RESOLVE_FINDINGS");
  assert.equal(paused.pipelineState.finalizationResult.status, "FAIL");
  assert.deepEqual(
    paused.pipelineState.writableResult.blockers.map(({ id }) => id),
    ["F1"],
  );
  assert.equal(paused.counters.fixRounds, 2);
});

for (const phase of ["IMPLEMENT", "FINALIZE"]) {
  test(`${phase} loss after policy-pause publication retains the exact stop without replay`, async (t) => {
    const loss = new Error("Synthetic acknowledgement loss");
    const fixture = await createFixture(t, {
      workWorker:
        phase === "IMPLEMENT"
          ? [stop()]
          : [implementationCompleted(), stop(finalizationPassed())],
    });
    const transition = fixture.runtime.transition;
    let lost = false;
    fixture.runtime.transition = async (...args) => {
      const next = await transition(...args);
      if (!lost && next.pause?.reason === "validation_policy_blocked") {
        lost = true;
        throw loss;
      }
      return next;
    };
    await assert.rejects(fixture.run(), (cause) => cause === loss);
    const published = structuredClone(fixture.currentRun);
    assert.equal(published.pause.reason, "validation_policy_blocked");
    fixture.runtime.transition = transition;
    const calls = fixture.calls.worker.length;
    await assert.rejects(fixture.run(), /no retry or override/u);
    assert.equal(fixture.calls.worker.length, calls);
    assert.deepEqual(fixture.currentRun, published);
    assert.doesNotThrow(() =>
      planExecutionPipeline.workflow.validateRun(published),
    );
    const malformed = structuredClone(published);
    malformed.pause.evidence.pop();
    assert.throws(() => planExecutionPipeline.workflow.validateRun(malformed), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  });
}

test("combined primary history survives unchanged containment and independent reconstruction", async (t) => {
  const historical = cleanConfirmationFindings("R1");
  historical.findings[0].problem =
    "A synthetic reserved check was disclosed as executed before FINALIZE.";
  const containment = checkAndFix();
  containment.summary =
    "The historical execution remains disclosed; no check credit is granted and FINALIZE retains every pending check.";
  const fixture = await createFixture(t, {
    mode: "combined",
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      historical,
      containment,
      cleanConfirmation(),
      finalizationPassed(),
    ],
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.deepEqual(done.pipelineState.primaryFindings, []);
  assert.deepEqual(
    done.pipelineState.workReports.find(
      ({ phase }) => phase === "CLEAN_CONFIRM",
    ).findings,
    historical.findings,
  );
  for (const request of fixture.calls.reviewer.filter(({ schema }) =>
    [CANDIDATE_REVIEW_SCHEMA, REVIEW_SCHEMA].includes(schema),
  )) {
    for (const prompt of [request.prompt, request.recoveryPrompt]) {
      assert.ok(prompt.includes(historical.findings[0].problem));
      assert.ok(prompt.includes(containment.summary));
    }
  }
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} carries summary-only disclosure into subsequent and reconstructed requests`, async (t) => {
    const implementation = implementationCompleted();
    implementation.summary =
      "Historical disclosure: the synthetic reserved command ran early. It grants no acceptance credit; the complete checks remain pending with FINALIZE.";
    const changed = checkAndFix("CHANGED");
    changed.summary =
      "A second historical disclosure exists only in this check/fix summary; it grants no credit and leaves the full checks with FINALIZE.";
    const containment = checkAndFix();
    containment.summary =
      "Containment preserves the disclosure and the pending FINALIZE checks without content changes.";
    let repaired = false;
    const fixture = await createFixture(t, {
      mode,
      workWorker: [
        implementation,
        ...(mode === "independent" ? [] : [changed, containment]),
        finalizationPassed(),
      ],
      async onRoleRun(_role, request) {
        if (request.schema === CHECK_AND_FIX_SCHEMA && !repaired) {
          repaired = true;
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
        }
      },
    });
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    const candidate =
      mode === "lazy"
        ? fixture.calls.worker.find(
            ({ schema }) => schema === FINALIZATION_SCHEMA,
          )
        : fixture.calls.reviewer.find(
            ({ schema }) => schema === CANDIDATE_REVIEW_SCHEMA,
          );
    for (const prompt of [candidate.prompt, candidate.recoveryPrompt]) {
      assert.ok(prompt.includes(implementation.summary));
      if (mode !== "independent") {
        assert.ok(prompt.includes(changed.summary));
        assert.ok(prompt.includes(containment.summary));
      }
    }
    assert.equal(
      done.pipelineState.workReports[0].summary,
      implementation.summary,
    );
    const legacy = structuredClone(done);
    delete legacy.pipelineState.workReports;
    const migrated = planExecutionPipeline.migrations[40](legacy);
    assert.deepEqual(migrated, { ...legacy.pipelineState, workReports: [] });
    assert.doesNotThrow(() => normalizePipelineState(migrated));
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} retains a FINALIZE-only disclosure after content repair without retaining check credit`, async (t) => {
    const failed = finalizationFailed("F1");
    failed.summary =
      "Historical disclosure: the synthetic reserved check ran early; no acceptance credit is granted and all later checks remain required.";
    failed.issues[0].evidence = [
      "A separate historical disclosure appears only in the accepted finalization issue evidence.",
    ];
    failed.checks[0].evidence = [
      "A check-only disclosure: the synthetic reserved command ran early, without acceptance credit.",
    ];
    let repaired = false;
    let reconstructed = false;
    const fixture = await createFixture(t, {
      mode,
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        failed,
        resolution({ id: "F1", decision: "FIX" }),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalizationPassed(),
      ],
      async onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
          repaired = true;
        } else if (
          repaired &&
          [CHECK_AND_FIX_SCHEMA, CANDIDATE_REVIEW_SCHEMA].includes(
            request.schema,
          )
        ) {
          const current = fixture.currentRun.pipelineState;
          assert.equal(current.finalizationResult, null);
          assert.equal(current.finalizedFingerprint, null);
          assert.deepEqual(current.requiredChecks, failed.requiredChecks);
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.ok(prompt.includes(failed.summary));
            assert.ok(prompt.includes(failed.issues[0].evidence[0]));
            assert.ok(prompt.includes(failed.checks[0].evidence[0]));
          }
          reconstructed = true;
        }
      },
    });
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.ok(reconstructed);
    assert.deepEqual(
      done.pipelineState.workReports.find(({ phase }) => phase === "FINALIZE"),
      {
        step: 1,
        phase: "FINALIZE",
        summary: failed.summary,
        issues: failed.issues,
        checks: failed.checks,
      },
    );
    assert.doesNotThrow(() => normalizePipelineState(done.pipelineState));
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} retains disclosures solely in an accepted FIX reason and evidence`, async (t) => {
    const disposition = resolution({ id: "F1", decision: "FIX" });
    disposition.decisions[0].reason =
      "Historical disclosure: the reserved synthetic check ran before FINALIZE.";
    disposition.decisions[0].evidence = [
      "The early execution grants no credit; the complete inventory remains pending with its assigned FINALIZE owners.",
    ];
    let resolved = false;
    let inspected = false;
    const fixture = await createFixture(t, {
      mode,
      workWorker: [
        implementationCompleted(),
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalizationFailed("F1"),
        disposition,
        ...(mode === "independent" ? [] : [checkAndFix()]),
        finalizationPassed(),
      ],
      async onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          // Force gate invalidation so neither native history nor old finalization
          // evidence can supply the disclosure to the next review.
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
          resolved = true;
        } else if (
          resolved &&
          [
            CHECK_AND_FIX_SCHEMA,
            CANDIDATE_REVIEW_SCHEMA,
            REVIEW_SCHEMA,
          ].includes(request.schema)
        ) {
          assert.deepEqual(fixture.currentRun.pipelineState.findings, []);
          for (const prompt of [request.prompt, request.recoveryPrompt]) {
            assert.ok(prompt.includes(disposition.decisions[0].reason));
            assert.ok(prompt.includes(disposition.decisions[0].evidence[0]));
          }
          inspected = true;
        }
      },
    });
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.ok(inspected);
    assert.deepEqual(
      done.pipelineState.workReports.find(
        ({ phase }) => phase === "RESOLVE_FINDINGS",
      ),
      { step: 1, phase: "RESOLVE_FINDINGS", decisions: disposition.decisions },
    );
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      finalizationPassed().requiredChecks,
    );
    assert.doesNotThrow(() =>
      normalizePipelineState(JSON.parse(JSON.stringify(done.pipelineState))),
    );
  });
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} retains terminal validation evidence through rejection, repair and later steps`, async (t) => {
    const disclosures = [
      "Evidence-only disclosure: the reserved synthetic check ran before FINALIZE.",
      "Evidence-only disclosure: that early run grants no acceptance credit.",
      "Evidence-only disclosure: FINALIZE still owns every established check.",
    ];
    const terminal =
      mode === "lazy" ? terminalLazyConfirmation : terminalConfirmation;
    const rejection = terminal({
      ...reviewFindings("R1"),
      validationChange: "REJECTED",
      validationEvidence: [disclosures[0]],
      finalizationFindingIds: ["R1"],
    });
    const content = terminal({
      ...reviewFindings("R2"),
      validationEvidence: [disclosures[1]],
    });
    const clean = terminal({
      ...(mode === "lazy" ? cleanConfirmation() : reviewApproved()),
      validationEvidence: [disclosures[2]],
    });
    const terminalSchema =
      mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA;
    const converge = mode === "independent" ? [] : [checkAndFix()];
    const confirmationsBefore = new Map();
    let confirmations = 0;
    const fixture = await createFixture(t, {
      mode,
      plan: `${PLAN}\n\n## Commit 2: fix(test): finish behavior\n\nFinish the requested behavior.`,
      workWorker: [
        implementationCompleted(),
        ...converge,
        finalizationPassed(),
        finalizationPassed(),
        mode === "lazy"
          ? checkAndFix("CHANGED")
          : resolution({ id: "R2", decision: "FIX" }),
        ...converge,
        finalizationPassed(),
        implementationCompleted(),
        ...converge,
        finalizationPassed(),
        ...(mode === "lazy" ? [rejection, content, clean] : []),
      ],
      workReviewer: mode === "lazy" ? [] : [rejection, content, clean],
      async onRoleRun(_role, request) {
        confirmationsBefore.set(request, confirmations);
        if (request.schema === terminalSchema) confirmations++;
        // Repair the content finding so no gate evidence survives into later requests.
        if (
          request.access === "workspace-write" &&
          fixture.currentRun.pipelineState.findings.some(
            ({ id }) => id === "R2",
          )
        )
          await writeFile(
            join(request.cwd, "safe-repair.txt"),
            "safe repair\n",
          );
      },
    });
    for (const reportCount of [1, 2]) {
      const loss = new Error(
        "Synthetic terminal acceptance acknowledgement loss",
      );
      const transition = fixture.runtime.transition;
      let published = null;
      fixture.runtime.transition = async (...args) => {
        // Fail only the acknowledgement; subsequent publications remain available.
        const next = await transition(...args);
        if (
          published === null &&
          next.pipelineState.workReports.filter(
            ({ phase }) => phase === "CONFIRM",
          ).length === reportCount
        ) {
          published = structuredClone(next);
          throw loss;
        }
        return next;
      };
      await assert.rejects(fixture.run(), (cause) => cause === loss);
      assert.notEqual(published, null);
      assert.deepEqual(fixture.currentRun, published);
      fixture.runtime.transition = transition;
      fixture.persistPipelineState(
        JSON.parse(JSON.stringify(published.pipelineState)),
      );
      assert.equal(
        published.pipelineState.workflowState,
        reportCount === 1
          ? "FINALIZE"
          : mode === "lazy"
            ? "CHECK_AND_FIX"
            : "RESOLVE_FINDINGS",
      );
      assert.equal(published.pipelineState.reviewResult, null);
      assert.equal(
        published.pipelineState.workReports.filter(
          ({ phase }) => phase === "CONFIRM",
        ).length,
        reportCount,
      );
    }
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.equal(done.pipelineState.completedCommits.length, 2);
    assert.equal(confirmations, 4);
    assert.deepEqual(
      done.pipelineState.workReports.filter(({ phase }) => phase === "CONFIRM"),
      [
        {
          step: 1,
          phase: "CONFIRM",
          findings: rejection.findings,
          validationEvidence: rejection.validationEvidence,
        },
        {
          step: 1,
          phase: "CONFIRM",
          findings: content.findings,
          validationEvidence: content.validationEvidence,
        },
        {
          step: 1,
          phase: "CONFIRM",
          validationEvidence: clean.validationEvidence,
        },
      ],
    );
    // Retained evidence is no gate credit: rejection, repair and the next step each rerun FINALIZE.
    assert.equal(
      fixture.calls.worker.filter(
        ({ schema }) => schema === FINALIZATION_SCHEMA,
      ).length,
      4,
    );
    assert.deepEqual(
      done.pipelineState.requiredChecks,
      finalizationPassed().requiredChecks,
    );
    for (const request of Object.values(fixture.calls).flat()) {
      if (request.access === "local-commit") continue;
      for (const prompt of [request.prompt, request.recoveryPrompt])
        for (const disclosure of disclosures.slice(
          0,
          confirmationsBefore.get(request),
        ))
          assert.ok(prompt.includes(disclosure));
    }
    assert.deepEqual(
      normalizePipelineState(JSON.parse(JSON.stringify(done.pipelineState)))
        .workReports,
      done.pipelineState.workReports,
    );
  });
}

test("validation migration receives retained terminal history without a resolved-summary context", async (t) => {
  const report = {
    step: 1,
    phase: "CONFIRM",
    validationEvidence: [
      "Historical disclosure retained without validation credit.",
    ],
  };
  let inspected = 0;
  let fixture;
  fixture = await prepareValidationMigration(t, {
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      bootstrapReady("Migrating Worker"),
      reconciliationResolved(),
      finalizationPassed(),
    ],
    workReviewer: [bootstrapReady("Migrating Reviewer"), reviewApproved()],
    onRoleRun(_role, request) {
      if (!fixture?.currentRun.pipelineState.validationMigrationPending) return;
      for (const prompt of [request.prompt, request.recoveryPrompt])
        assert.ok(prompt.includes(report.validationEvidence[0]));
      inspected++;
    },
  });
  fixture.persistPipelineState({
    ...fixture.currentRun.pipelineState,
    workReports: [report],
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.ok(inspected > 0);
  assert.deepEqual(done.pipelineState.workReports[0], report);
});

test("terminal validation evidence reports are strict history without gate fields", () => {
  const findings = reviewFindings("R1").findings;
  const validationEvidence = ["Evidence-only disclosure retained as history."];
  for (const report of [
    { step: 1, phase: "CONFIRM", validationEvidence },
    { step: 1, phase: "CONFIRM", findings, validationEvidence },
  ])
    assert.deepEqual(retainWorkReport([], report), [report]);
  for (const invalid of [
    { step: 1, phase: "CONFIRM" },
    { step: 1, phase: "CONFIRM", validationEvidence: [] },
    {
      step: 1,
      phase: "CONFIRM",
      validationEvidence: ["  Noncanonical evidence.  "],
    },
    { step: 1, phase: "CONFIRM", validationEvidence: ["x".repeat(4001)] },
    {
      step: 1,
      phase: "CONFIRM",
      validationEvidence,
      validationChange: "ACCEPTED",
    },
    { step: 1, phase: "REVIEW", findings, validationEvidence },
    {
      step: 1,
      phase: "FINALIZE",
      summary: "Accepted report.",
      validationEvidence,
    },
  ])
    assert.throws(() => retainWorkReport([], invalid), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
});

test("resolution report context keeps normalized mixed decisions and rejects malformed facts", () => {
  const decisions = [
    {
      id: "R1",
      decision: "FIX",
      reason: "Retained historical disclosure.",
      evidence: [],
    },
    {
      id: "R2",
      decision: "DISPUTE",
      reason: "No prohibited execution established.",
      evidence: ["Source observation alone supplies no execution proof."],
    },
  ];
  const report = { step: 1, phase: "RESOLVE_FINDINGS", decisions };
  const reports = retainWorkReport([], report);
  assert.deepEqual(reports, [report]);
  assert.deepEqual(retainWorkReport(reports, report), reports);
  for (const invalid of [
    [],
    [decisions[0], decisions[0]],
    [{ ...decisions[0], id: "unknown" }],
    [{ ...decisions[0], id: ["R1"] }],
    [{ ...decisions[0], decision: "CLEAN" }],
    [{ ...decisions[0], reason: "" }],
    [{ ...decisions[0], reason: "  Noncanonical text.  " }],
    [{ ...decisions[0], evidence: ["x".repeat(4001)] }],
    [{ ...decisions[0], checks: [] }],
    [{ ...decisions[1], evidence: [] }],
  ])
    assert.throws(
      () => retainWorkReport([], { ...report, decisions: invalid }),
      { code: "ERR_INVALID_PLAN_EXECUTION_STATE" },
    );
});

test("Worker report context is bounded, strict, deduplicated and cannot carry check credit", () => {
  const report = {
    step: 1,
    phase: "IMPLEMENT",
    summary: "Retained disclosure.",
  };
  const reports = retainWorkReport([], report);
  assert.deepEqual(retainWorkReport(reports, report), reports);
  const issueReport = {
    ...report,
    phase: "FINALIZE",
    issues: finalizationFailed("F1").issues,
  };
  assert.deepEqual(retainWorkReport([], issueReport), [issueReport]);
  for (const malformed of [
    { ...report, checks: [] },
    { ...report, step: 0 },
    { ...report, phase: "COMMIT" },
    { ...report, summary: "" },
    { step: 1, phase: "CLEAN_CONFIRM", findings: [] },
    { ...issueReport, phase: "IMPLEMENT" },
    { ...issueReport, issues: [] },
    { ...issueReport, issues: [{ ...issueReport.issues[0], evidence: [] }] },
    {
      ...issueReport,
      issues: [
        { ...issueReport.issues[0], problem: "  Noncanonical issue.  " },
      ],
    },
    { ...issueReport, checks: [] },
  ])
    assert.throws(() => retainWorkReport([], malformed), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  assert.throws(
    () =>
      retainWorkReport(
        Array.from({ length: 256 }, (_, i) => ({
          ...report,
          summary: `Report ${i}`,
        })),
        report,
      ),
    /bounded context capacity/u,
  );
  const oversized = Array.from({ length: 106 }, (_, i) => ({
    ...report,
    summary: `${i}:` + "x".repeat(19_990),
  }));
  assert.throws(
    () => retainWorkReport(oversized, report),
    /bounded context capacity/u,
  );
  assert.deepEqual(reports, [report]);
});

test("historical finalization check reports are strict context without executor authority", () => {
  const checks = finalizationPassed().checks;
  const report = {
    step: 1,
    phase: "FINALIZE",
    summary: "Accepted report.",
    checks,
  };
  assert.deepEqual(retainWorkReport([], report), [report]);
  for (const invalid of [
    [],
    [checks[0], checks[0]],
    [{ ...checks[0], checkId: "unknown" }],
    [{ ...checks[0], command: " invalid command " }],
    [{ ...checks[0], status: "APPROVED" }],
    [{ ...checks[0], evidence: [] }],
    [{ ...checks[0], evidence: ["  Noncanonical evidence.  "] }],
    [{ ...checks[0], evidence: ["x".repeat(4001)] }],
    [{ ...checks[0], executor: "runner" }],
  ])
    assert.throws(() => retainWorkReport([], { ...report, checks: invalid }), {
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  assert.throws(() => retainWorkReport([], { ...report, evidence: [] }), {
    code: "ERR_INVALID_PLAN_EXECUTION_STATE",
  });
});

test("trusted placeholder disclosures survive blocked execution, retry and receipt replacement", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const first = finalizationWithTrustedCheck(trustedValidation);
  const later = finalizationWithTrustedCheck(trustedValidation);
  const disclosure =
    "Historical disclosure only in a reserved check: a synthetic command ran early and grants no credit.";
  first.checks.at(-1).evidence = [disclosure];
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks: first.requiredChecks,
  });
  let executions = 0;
  const fixture = await createFixture(t, {
    mode: "combined",
    modeSettings: { trustedChecks: ["service-check"] },
    trustedValidation,
    worker: [
      clarificationReady(),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [implementationCompleted(), checkAndFix(), first, later],
    onTrustedValidation(options) {
      executions++;
      assert.deepEqual(
        fixture.currentRun.pipelineState.workReports.find(
          ({ phase }) => phase === "FINALIZE",
        ).checks,
        first.checks,
      );
      return {
        ...options.bindings,
        commandIdentity: options.commandIdentity,
        status: executions === 1 ? "BLOCKED" : "PASS",
        exitCode: executions === 1 ? null : 0,
        signal: null,
        timedOut: false,
        evidence: ["Synthetic executor receipt."],
      };
    },
  });
  const paused = await fixture.run({ trustedChecks: ["service-check"] });
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.deepEqual(paused.pipelineState.requiredChecks, first.requiredChecks);
  assert.doesNotThrow(() =>
    normalizePipelineState(JSON.parse(JSON.stringify(paused.pipelineState))),
  );
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.equal(executions, 2);
  assert.deepEqual(
    done.pipelineState.finalizationResult.checks.at(-1).evidence,
    ["Synthetic executor receipt."],
  );
  assert.equal(
    done.pipelineState.finalizationResult.checks.at(-1).executor,
    "runner",
  );
  for (const request of fixture.calls.reviewer.filter(
    ({ schema }) => schema === REVIEW_SCHEMA,
  )) {
    assert.ok(request.prompt.includes(disclosure));
    assert.ok(request.recoveryPrompt.includes(disclosure));
  }
  assert.ok(
    fixture.calls.reviewer.some(({ schema }) => schema === REVIEW_SCHEMA),
  );
  const finalizing = fixture.calls.worker.filter(
    ({ schema }) => schema === FINALIZATION_SCHEMA,
  );
  assert.equal(finalizing.length, 2);
  assert.ok(finalizing[1].prompt.includes(disclosure));
  assert.ok(finalizing[1].recoveryPrompt.includes(disclosure));
  assert.doesNotThrow(() =>
    normalizePipelineState(JSON.parse(JSON.stringify(done.pipelineState))),
  );
});

test("accepted blocked check disclosures survive retry without check credit", async (t) => {
  const blocked = finalizationBlocked(
    "A synthetic prerequisite is unavailable.",
    "Blocker evidence.",
  );
  blocked.checks[0].evidence = [
    "A disclosure solely in blocked check evidence survives recovery without credit.",
  ];
  const fixture = await createFixture(t, {
    workWorker: [implementationCompleted(), blocked, finalizationPassed()],
  });
  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.deepEqual(
    paused.pipelineState.workReports.find(({ phase }) => phase === "FINALIZE"),
    {
      step: 1,
      phase: "FINALIZE",
      summary: blocked.reason,
      evidence: blocked.evidence,
      checks: blocked.checks,
    },
  );
  assert.doesNotThrow(() =>
    normalizePipelineState(JSON.parse(JSON.stringify(paused.pipelineState))),
  );
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  const terminal = fixture.calls.reviewer.at(-1);
  for (const prompt of [terminal.prompt, terminal.recoveryPrompt])
    assert.ok(prompt.includes(blocked.checks[0].evidence[0]));
  assert.deepEqual(done.pipelineState.requiredChecks, blocked.requiredChecks);
});
