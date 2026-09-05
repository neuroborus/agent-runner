import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import test from "node:test";

import { planExecutionPipeline } from "../src/index.js";
import { FINALIZATION_SCHEMA, REVIEW_SCHEMA } from "../src/schemas.js";
import { normalizePipelineState } from "../src/workflow-contract.js";
import {
  PLAN,
  REBOOTSTRAPPED_WORKER_SESSION,
  REQUIRED_CHECKS,
  RESTARTED_ROLE_SESSIONS,
  ROLE_SESSIONS,
  SOURCE_SESSION,
  bootstrapCorrection,
  bootstrapReady,
  checkAndFix,
  checkResults,
  clarificationReady,
  cleanConfirmation,
  cleanConfirmationFindings,
  compatibilityPlanRevision,
  compatibilityReady,
  createFixture,
  createRevision55Fixture,
  finalizationBlocked,
  finalizationFailed,
  finalizationPassed,
  finalizationUnavailable,
  finalizationWithTrustedCheck,
  findingArbitration,
  implementationCompleted,
  implementationProductDecision,
  invalidProductionFinalization,
  invalidReviewStatus,
  reconciliationProductDecision,
  reconciliationResolved,
  reconsideration,
  reconsiderationProductDecision,
  resolution,
  reviewApproved,
  reviewFindings,
  reviewProductDecision,
  reviewRejected,
  stagnation,
  terminalConfirmation,
  terminalLazyConfirmation,
  trustedValidationSnapshot,
} from "./support/index.js";

test("uses and persists a configured runner artifact root", async (t) => {
  const fixture = await createFixture(t, {
    artifactRoot: "IGNORED_RUNS",
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.artifactRoot, "IGNORED_RUNS");
  assert.equal(
    result.pipelineState.clarificationPath,
    join(
      fixture.projectPath,
      "IGNORED_RUNS",
      "agent-runner",
      "run-1",
      "clarifications.md",
    ),
  );
});

test("runs the dedicated finalization gate without skill guidance", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [implementationCompleted(), finalizationPassed("")],
  });

  const result = await fixture.run({ finalization: "none" });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, "none");
  assert.equal(result.pipelineState.finalizationResult.skillPath, null);
  assert.equal(
    result.pipelineState.finalizedFingerprint,
    result.pipelineState.reviewedFingerprint,
  );
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /No finalization skill guidance is available/u,
  );
});

test("corrects noncanonical finalization infrastructure before review", async (t) => {
  const aliasPath = ".claude/skills/finalization/SKILL.md";
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await symlink(".agents", join(projectPath, ".claude"));
    },
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationPassed(),
        validationInfrastructure: [aliasPath],
      },
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const correction = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  ).patch.pipelineState.finalizationCorrections[0];
  assert.deepEqual(correction.diagnostics, [
    {
      role: "worker",
      phase: "finalization",
      contract: "finalization",
      field: "validationInfrastructure[0]",
      constraint: "existing-canonical-repository-file",
    },
  ]);
  const reviewPrompt = fixture.calls.reviewer.find(({ prompt }) =>
    prompt.includes("Review the changes"),
  ).prompt;
  assert.doesNotMatch(reviewPrompt, /\.claude\/skills/u);
});

test("corrects narrative infrastructure in blocked finalization output", async (t) => {
  const narrativePath =
    "TMPDIR and bound HEAD values from this finalization turn";
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationBlocked(
          "The required local service is unavailable.",
          "The validation process could not connect to its service.",
        ),
        validationInfrastructure: [narrativePath],
      },
      finalizationBlocked(
        "The required local service is unavailable.",
        "The validation process could not connect to its service.",
      ),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "environment_blocked");
  assert.deepEqual(
    paused.pipelineState.finalizationCorrections[0].diagnostics,
    [
      {
        role: "worker",
        phase: "finalization",
        contract: "finalization",
        field: "validationInfrastructure[0]",
        constraint: "existing-canonical-repository-file",
      },
    ],
  );
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /TMPDIR and bound/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /TMPDIR and bound/u);
});

test("corrects the production git status finalization inventory into an environment pause", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationBlocked(
        "The required process-isolation facility is unavailable.",
        "The validation process could not start in the sandbox.",
      ),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  const correction = paused.pipelineState.finalizationCorrections[0];
  assert.match(correction.contentFingerprint, /^[a-f0-9]{64}$/u);
  assert.deepEqual(correction, {
    attempt: 1,
    step: 1,
    guidance: "resolved",
    contentFingerprint: correction.contentFingerprint,
    diagnostics: [
      {
        role: "worker",
        phase: "finalization",
        contract: "finalization",
        field: "requiredChecks[2].command",
        constraint: "staging-independent-validation-command",
      },
    ],
  });
  assert.equal(paused.pipelineState.pendingFinalizationCorrection, null);
  const finalizationCalls = fixture.calls.worker.filter(
    ({ schema }) => schema === FINALIZATION_SCHEMA,
  );
  assert.equal(finalizationCalls.length, 2);
  assert.equal(finalizationCalls[0].access, "workspace-write");
  assert.equal(finalizationCalls[1].access, "read-only");
  assert.equal(finalizationCalls[0].schema, finalizationCalls[1].schema);
  assert.match(finalizationCalls[1].prompt, /bounded read-only correction/u);
  assert.equal(finalizationCalls[1].session, undefined);
  assert.match(finalizationCalls[1].recoveryPrompt, /Current planned commit/u);
  assert.doesNotMatch(finalizationCalls[1].prompt, /git status/u);
  const correctionActivity = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  )?.options.activity;
  assert.deepEqual(correctionActivity, {
    actor: "worker",
    phase: "finalization",
    kind: "finalization-correction",
    message: "worker must correct 1 finalization contract violation.",
  });
  for (const persisted of [
    fixture.currentRun,
    fixture.transitions,
    correctionActivity,
  ]) {
    assert.doesNotMatch(JSON.stringify(persisted), /DO_NOT_PERSIST/u);
  }
});

test("routes corrected finalization PASS and FAIL through the existing gate", async (t) => {
  await t.test("PASS", async (t) => {
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        invalidProductionFinalization(),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.finalizationResult.status, "PASS");
    assert.deepEqual(completed.pipelineState.finalizationCorrections, []);
    assert.equal(
      fixture.transitions.filter(
        ({ options }) => options.activity?.kind === "finalization-correction",
      ).length,
      1,
    );
  });

  await t.test("FAIL", async (t) => {
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        invalidProductionFinalization(),
        finalizationFailed("F1"),
        resolution({ id: "F1", decision: "FIX" }),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.ok(
      fixture.transitions.some(
        ({ patch }) =>
          patch?.pipelineState?.workflowState === "RESOLVE_FINDINGS" &&
          patch.pipelineState.finalizationResult?.status === "FAIL",
      ),
    );
    assert.equal(completed.pipelineState.finalizationResult.status, "PASS");
  });
});

test("batches every staging-dependent finalization command into one correction", async (t) => {
  const rejectedCommands = [
    "git diff --check",
    "git status --short",
    "git ls-files --others --exclude-standard",
  ];
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(...rejectedCommands),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const correctionTransition = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "finalization-correction",
  );
  assert.deepEqual(
    correctionTransition.patch.pipelineState.finalizationCorrections[0]
      .diagnostics,
    rejectedCommands.map((_, index) => ({
      role: "worker",
      phase: "finalization",
      contract: "finalization",
      field: `requiredChecks[${index + 2}].command`,
      constraint: "staging-independent-validation-command",
    })),
  );
  assert.equal(
    correctionTransition.options.activity.message,
    "worker must correct 3 finalization contract violations.",
  );
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Correction diagnostic batch"),
  );
  for (const rejectedCommand of rejectedCommands) {
    assert.doesNotMatch(
      correctionCall.prompt,
      new RegExp(rejectedCommand, "u"),
    );
  }
  assert.doesNotMatch(correctionCall.prompt, /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("allows one wholly new finalization diagnostic batch", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization("git diff --check"),
      invalidProductionFinalization(
        "git diff-tree --check HEAD",
        "git ls-files --others --exclude-standard",
      ),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const corrections = fixture.transitions
    .filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    )
    .map(({ patch }) => patch.pipelineState.finalizationCorrections.at(-1));
  assert.deepEqual(
    corrections.map(({ attempt, diagnostics }) => ({ attempt, diagnostics })),
    [
      {
        attempt: 1,
        diagnostics: [
          {
            role: "worker",
            phase: "finalization",
            contract: "finalization",
            field: "requiredChecks[2].command",
            constraint: "staging-independent-validation-command",
          },
        ],
      },
      {
        attempt: 2,
        diagnostics: [
          {
            role: "worker",
            phase: "finalization",
            contract: "finalization",
            field: "requiredChecks[3].command",
            constraint: "staging-independent-validation-command",
          },
        ],
      },
    ],
  );
});

test("starts a new finalization correction scope after content changes", async (t) => {
  const fixture = await createFixture(t, {
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      invalidProductionFinalization(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const corrections = fixture.transitions
    .filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    )
    .map(({ patch }) => patch.pipelineState.finalizationCorrections.at(-1));
  assert.deepEqual(
    corrections.map(({ attempt }) => attempt),
    [1, 1],
  );
  assert.notEqual(
    corrections[0].contentFingerprint,
    corrections[1].contentFingerprint,
  );
});

test("fails closed when a correction mixes repeated and new diagnostics", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization("git diff --check", "git status --short"),
      invalidProductionFinalization(
        "git diff --check",
        "git diff-tree --check HEAD",
        "git ls-files --others --exclude-standard",
      ),
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.equal(
    fixture.currentRun.pipelineState.finalizationCorrections.length,
    1,
  );
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    ).length,
    1,
  );
});

test("fails closed after exhausting two fresh finalization corrections", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization("git diff --check"),
      invalidProductionFinalization(
        "git diff-tree --check HEAD",
        "git status --short",
      ),
      invalidProductionFinalization(
        "git diff-tree --check HEAD",
        "git diff HEAD --exit-code",
        "git ls-files --others --exclude-standard",
      ),
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(
    fixture.currentRun.pipelineState.finalizationCorrections.map(
      ({ attempt }) => attempt,
    ),
    [1, 2],
  );
  assert.equal(
    fixture.currentRun.pipelineState.pendingFinalizationCorrection.attempt,
    2,
  );
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    ).length,
    2,
  );
});

test("reconstructs finalization correction before and during interruption", async (t) => {
  await t.test("before correction", async (t) => {
    const processLoss = new Error("Process stopped before correction.");
    const fixture = await createFixture(t, {
      workWorker: [
        implementationCompleted(),
        finalizationUnavailable("SKILL_INVALID"),
        invalidProductionFinalization(),
        finalizationPassed(""),
      ],
    });
    const transition = fixture.runtime.transition;
    const startAgentTurn = fixture.runtime.startAgentTurn;
    let stopped = false;
    fixture.runtime.transition = async (patch, options) => {
      if (stopped) {
        throw processLoss;
      }
      const next = await transition(patch, options);
      if (options.activity?.kind === "finalization-correction") {
        stopped = true;
      }
      return next;
    };
    fixture.runtime.startAgentTurn = async (turn) => {
      if (stopped) {
        throw processLoss;
      }
      return startAgentTurn(turn);
    };

    await assert.rejects(fixture.run(), (error) => error === processLoss);
    assert.equal(fixture.currentRun.activeTurn, null);
    assert.notEqual(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection,
      null,
    );
    assert.equal(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection.guidance,
      "fallback",
    );
    assert.equal(
      fixture.currentRun.pipelineState.finalizationCorrections.length,
      1,
    );

    stopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.startAgentTurn = startAgentTurn;
    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    const correctionCall = fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("bounded read-only correction"),
    );
    assert.equal(correctionCall.access, "read-only");
    assert.match(
      correctionCall.prompt,
      /No finalization skill guidance is available/u,
    );
    assert.match(correctionCall.recoveryPrompt, /Resolved bootstrap context/u);
    assert.equal(correctionCall.session, undefined);
  });

  await t.test("during second correction", async (t) => {
    const processLoss = new Error("Process stopped during second correction.");
    let interruptionTriggered = false;
    let processStopped = false;
    const fixture = await createFixture(t, {
      onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("bounded read-only correction") &&
          request.prompt.includes('"attempt": 2') &&
          !interruptionTriggered
        ) {
          interruptionTriggered = true;
          processStopped = true;
          throw processLoss;
        }
      },
      workWorker: [
        implementationCompleted(),
        invalidProductionFinalization("git diff --check"),
        invalidProductionFinalization(
          "git diff-tree --check HEAD",
          "git ls-files --others --exclude-standard",
        ),
        finalizationPassed(),
      ],
    });
    const transition = fixture.runtime.transition;
    const finishAgentTurn = fixture.runtime.finishAgentTurn;
    fixture.runtime.transition = async (patch, options) => {
      if (processStopped) {
        throw processLoss;
      }
      return transition(patch, options);
    };
    fixture.runtime.finishAgentTurn = async (turn) => {
      if (processStopped) {
        throw processLoss;
      }
      return finishAgentTurn(turn);
    };

    await assert.rejects(fixture.run(), (error) => error === processLoss);
    assert.deepEqual(fixture.currentRun.activeTurn, {
      role: "worker",
      phase: "finalize",
    });
    assert.notEqual(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection,
      null,
    );
    assert.equal(
      fixture.currentRun.pipelineState.finalizationCorrections.length,
      2,
    );
    assert.equal(
      fixture.currentRun.pipelineState.pendingFinalizationCorrection.attempt,
      2,
    );
    const reconcileInterrupted = fixture.runtime.git.reconcileInterrupted;
    const reconciliation = [];
    fixture.runtime.git.reconcileInterrupted = (snapshot, options) => {
      reconciliation.push(options);
      return reconcileInterrupted.call(fixture.runtime.git, snapshot, options);
    };
    processStopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.finishAgentTurn = finishAgentTurn;

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.deepEqual(reconciliation, [{ allowWorkspaceChanges: false }]);
    const correctionCalls = fixture.calls.worker.filter(
      ({ prompt }) =>
        prompt.includes("bounded read-only correction") &&
        prompt.includes('"attempt": 2'),
    );
    assert.equal(correctionCalls.length, 2);
    assert.ok(correctionCalls.every(({ session }) => session === undefined));
  });
});

test("fails closed after a repeated invalid finalization result", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      invalidProductionFinalization(),
    ],
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );

  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
  assert.deepEqual(fixture.currentRun.pause.diagnostic, {
    role: "worker",
    phase: "finalization",
    contract: "finalization",
    field: "requiredChecks[2].command",
    constraint: "staging-independent-validation-command",
  });
  assert.deepEqual(
    fixture.currentRun.pipelineState.pendingFinalizationCorrection,
    fixture.currentRun.pipelineState.finalizationCorrections.at(-1),
  );
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("scopes finalization correction attempts to the current commit step", async (t) => {
  const plan = `${PLAN}\n\n## Commit 2: fix(test): finish behavior\n\nFinish the requested behavior.`;
  const fixture = await createFixture(t, {
    plan,
    workReviewer: [reviewApproved(), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationPassed(),
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationPassed(),
    ],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const corrections = fixture.transitions
    .filter(
      ({ options }) => options.activity?.kind === "finalization-correction",
    )
    .map(
      ({ patch }) => patch.pipelineState.finalizationCorrections.at(-1).step,
    );
  assert.deepEqual(corrections, [1, 2]);
});

test("corrects invalid terminal confirmation without retaining rejected values", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_REJECTED_REVIEW_VALUE";
  const fixture = await createFixture(t, {
    workReviewer: [
      terminalConfirmation({
        ...invalidReviewStatus(),
        evidence: [sensitiveMarker],
      }),
      terminalConfirmation(reviewApproved()),
    ],
  });

  const completed = await fixture.run();

  assert.equal(
    completed.pipelineState.workflowState,
    "DONE",
    JSON.stringify({
      pause: completed.pause,
      confirmationCorrection: completed.pipelineState.confirmationCorrection,
      pendingConfirmationCorrection:
        completed.pipelineState.pendingConfirmationCorrection,
      reviewResult: completed.pipelineState.reviewResult,
      finalizedFingerprint: completed.pipelineState.finalizedFingerprint,
      reviewedFingerprint: completed.pipelineState.reviewedFingerprint,
    }),
  );
  const correctionTransition = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "confirmation-correction",
  );
  const correction =
    correctionTransition.patch.pipelineState.confirmationCorrection;
  assert.equal(correction.attempt, 1);
  assert.equal(correction.step, 1);
  assert.equal(
    correction.contentFingerprint,
    correctionTransition.patch.pipelineState.finalizedFingerprint,
  );
  assert.equal(
    correction.validationInfrastructureFingerprint,
    correctionTransition.patch.pipelineState.finalizationResult
      .validationInfrastructureFingerprint,
  );
  assert.deepEqual(
    correctionTransition.patch.pipelineState.finalizationResult,
    completed.pipelineState.finalizationResult,
  );
  assert.deepEqual(correction.diagnostics, [
    {
      role: "reviewer",
      phase: "confirmation",
      contract: "confirmation",
      field: "evidence",
      constraint: "empty-for-review",
    },
  ]);
  const reviewCalls = fixture.calls.reviewer.filter(
    ({ schema }) =>
      schema.type === "object" && schema.properties?.validationChange,
  );
  assert.equal(reviewCalls.length, 2);
  assert.equal(reviewCalls[0].access, "read-only");
  assert.equal(reviewCalls[1].access, "read-only");
  assert.equal(reviewCalls[0].schema, reviewCalls[1].schema);
  assert.equal(reviewCalls[1].session, undefined);
  assert.match(reviewCalls[1].prompt, /pending read-only correction/u);
  assert.match(reviewCalls[1].recoveryPrompt, /Candidate validation tuple/u);
  assert.doesNotMatch(reviewCalls[1].prompt, new RegExp(sensitiveMarker, "u"));
  assert.doesNotMatch(
    JSON.stringify(fixture.currentRun),
    new RegExp(sensitiveMarker, "u"),
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    new RegExp(sensitiveMarker, "u"),
  );
});

test("corrects a classified terminal Reviewer structured-output failure", async (t) => {
  const sensitiveMarker = "DO_NOT_PERSIST_REVIEW_PROVIDER_OUTPUT";
  let rejected = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.schema === REVIEW_SCHEMA &&
        !rejected
      ) {
        rejected = true;
        const error = new Error(sensitiveMarker);
        error.code = "ERR_TEST_REVIEW_OUTPUT";
        error.failureClass = "structured-output";
        error.providerOutput = sensitiveMarker;
        throw error;
      }
    },
    workReviewer: [terminalConfirmation(reviewApproved())],
  });

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const correction = fixture.transitions.find(
    ({ options }) => options.activity?.kind === "confirmation-correction",
  ).patch.pipelineState.confirmationCorrection;
  assert.deepEqual(correction.diagnostics, [
    {
      role: "reviewer",
      phase: "confirmation",
      contract: "confirmation",
      field: "result",
      constraint: "provider-structured-output",
    },
  ]);
  assert.doesNotMatch(
    JSON.stringify(fixture.currentRun),
    new RegExp(sensitiveMarker, "u"),
  );
  assert.doesNotMatch(
    JSON.stringify(fixture.transitions),
    new RegExp(sensitiveMarker, "u"),
  );
});

test("routes corrected terminal confirmation findings, validation changes, and product decisions", async (t) => {
  await t.test("findings", async (t) => {
    const fixture = await createFixture(t, {
      workReviewer: [
        terminalConfirmation(invalidReviewStatus()),
        terminalConfirmation(reviewFindings("R1")),
        terminalConfirmation(reviewApproved()),
      ],
      workWorker: [
        implementationCompleted(),
        finalizationPassed(),
        resolution({ id: "R1", decision: "FIX" }),
        finalizationPassed(),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.ok(
      fixture.transitions.some(
        ({ patch }) =>
          patch?.pipelineState?.workflowState === "RESOLVE_FINDINGS" &&
          patch.pipelineState.findings?.[0]?.id === "R1",
      ),
    );
  });

  await t.test("validation change", async (t) => {
    const fixture = await createFixture(t, {
      async onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("Implement the changes")
        ) {
          await writeFile(
            join(request.cwd, "package.json"),
            '{"scripts":{"test":"node --test --test-reporter=spec"}}\n',
          );
        }
      },
      workReviewer: [
        terminalConfirmation(reviewApproved()),
        terminalConfirmation(reviewApproved("ACCEPTED")),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(
      completed.pipelineState.reviewResult.validationChange,
      "ACCEPTED",
    );
    const correction = fixture.transitions.find(
      ({ options }) => options.activity?.kind === "confirmation-correction",
    ).patch.pipelineState.confirmationCorrection;
    assert.deepEqual(correction.diagnostics, [
      {
        role: "reviewer",
        phase: "confirmation",
        contract: "confirmation",
        field: "validationChange",
        constraint: "matches-finalization-change",
      },
    ]);
  });

  await t.test("product decision", async (t) => {
    const processLoss = new Error(
      "Process stopped between correction and product-decision persistence.",
    );
    const fixture = await createFixture(t, {
      workReviewer: [
        terminalConfirmation(invalidReviewStatus()),
        terminalConfirmation(reviewProductDecision()),
      ],
    });
    const transition = fixture.runtime.transition;
    fixture.runtime.transition = (patch, options) => {
      const next = patch.pipelineState;
      if (
        next.workflowState === "CONFIRM" &&
        next.confirmationCorrection !== null &&
        next.pendingConfirmationCorrection === null
      ) {
        throw processLoss;
      }
      return transition(patch, options);
    };

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "product_decision_required");
    assert.equal(paused.pipelineState.pendingConfirmationCorrection, null);
    assert.equal(paused.pipelineState.confirmationCorrection, null);
    const correctionState = fixture.transitions.find(
      ({ options }) => options.activity?.kind === "confirmation-correction",
    ).patch.pipelineState;
    assert.throws(
      () =>
        normalizePipelineState({
          ...correctionState,
          pendingConfirmationCorrection: null,
        }),
      /missing its pending marker/u,
    );
  });

  await t.test("withdrawn rejected validation finding", async (t) => {
    const fixture = await createFixture(t, {
      async onRoleRun(role, request) {
        if (
          role === "worker" &&
          request.prompt.includes("Implement the changes")
        ) {
          await writeFile(
            join(request.cwd, "package.json"),
            '{"scripts":{"test":"node --test --test-reporter=spec"}}\n',
          );
        }
      },
      workReviewer: [
        terminalConfirmation(invalidReviewStatus()),
        terminalConfirmation(reviewRejected("R1")),
        reconsideration("WITHDRAW", "R1"),
        terminalConfirmation(reviewApproved("ACCEPTED")),
      ],
      workWorker: [
        implementationCompleted(),
        finalizationPassed(),
        resolution({ id: "R1", decision: "DISPUTE" }),
      ],
    });

    const completed = await fixture.run();

    assert.equal(completed.pipelineState.workflowState, "DONE");
    const reReview = fixture.transitions.find(
      ({ patch, options }) =>
        options.activity?.kind === "disputes-reconsidered" &&
        patch.pipelineState.workflowState === "CONFIRM",
    ).patch.pipelineState;
    assert.equal(reReview.confirmationCorrection, null);
    assert.equal(reReview.pendingConfirmationCorrection, null);
    assert.equal(reReview.reviewResult, null);
    assert.equal(reReview.reviewedFingerprint, null);
    assert.equal(reReview.finalizationResult.status, "PASS");
    assert.equal(
      fixture.transitions.filter(
        ({ options }) => options.activity?.kind === "confirmation-correction",
      ).length,
      1,
    );
  });
});

test("pauses repeated invalid terminal confirmation and deliberately retries it", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      terminalConfirmation(invalidReviewStatus()),
      terminalConfirmation(invalidReviewStatus()),
      terminalConfirmation(reviewApproved()),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "confirmation_output_invalid");
  assert.equal(paused.pause.resumeState, "CONFIRM");
  assert.equal(paused.pipelineState.confirmationCorrection.attempt, 1);
  assert.equal(paused.pipelineState.pendingConfirmationCorrection.attempt, 1);
  assert.equal(
    fixture.transitions.filter(
      ({ options }) => options.activity?.kind === "confirmation-correction",
    ).length,
    1,
  );
  const projection = planExecutionPipeline.projections.pause(paused);
  assert.deepEqual(projection.nextActions, [{ type: "resume", action: null }]);
  assert.match(projection.evidence[0], /nonempty-when-findings/u);
  assert.doesNotMatch(JSON.stringify(projection), /invalidReviewStatus/u);

  const completed = await fixture.run({}, null);

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.confirmationCorrection, null);
  assert.equal(completed.pipelineState.pendingConfirmationCorrection, null);
  const correctionCalls = fixture.calls.reviewer.filter(({ prompt }) =>
    prompt.includes("pending read-only correction"),
  );
  assert.equal(correctionCalls.length, 2);
  assert.ok(correctionCalls.every(({ session }) => session === undefined));
});

test("resumes a pending terminal confirmation correction across backend unavailability", async (t) => {
  let unavailable = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.prompt.includes("pending read-only correction") &&
        !unavailable
      ) {
        unavailable = true;
        const error = new Error("DO_NOT_PERSIST_BACKEND_OUTPUT");
        error.code = "ERR_TEST_BACKEND_UNAVAILABLE";
        error.recoverable = true;
        throw error;
      }
    },
    workReviewer: [
      terminalConfirmation(invalidReviewStatus()),
      terminalConfirmation(reviewApproved()),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "CONFIRM");
  assert.equal(paused.pipelineState.confirmationCorrection.attempt, 1);
  assert.equal(paused.pipelineState.pendingConfirmationCorrection.attempt, 1);
  assert.doesNotMatch(JSON.stringify(fixture.currentRun), /DO_NOT_PERSIST/u);

  const completed = await fixture.run({}, null);

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.confirmationCorrection, null);
  assert.equal(completed.pipelineState.pendingConfirmationCorrection, null);
});

test("reconstructs an interrupted pending terminal confirmation correction read-only", async (t) => {
  const processLoss = new Error("Process stopped during review correction.");
  let interrupted = false;
  let processStopped = false;
  const fixture = await createFixture(t, {
    onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.prompt.includes("pending read-only correction") &&
        !interrupted
      ) {
        interrupted = true;
        processStopped = true;
        throw processLoss;
      }
    },
    workReviewer: [
      terminalConfirmation(invalidReviewStatus()),
      terminalConfirmation(reviewApproved()),
    ],
  });
  const finishAgentTurn = fixture.runtime.finishAgentTurn;
  const transition = fixture.runtime.transition;
  fixture.runtime.finishAgentTurn = async (turn) => {
    if (processStopped) {
      throw processLoss;
    }
    return finishAgentTurn(turn);
  };
  fixture.runtime.transition = async (patch, options) => {
    if (processStopped) {
      throw processLoss;
    }
    return transition(patch, options);
  };

  await assert.rejects(fixture.run(), (cause) => cause === processLoss);
  assert.deepEqual(fixture.currentRun.activeTurn, {
    role: "reviewer",
    phase: "confirm",
  });
  assert.equal(
    fixture.currentRun.pipelineState.confirmationCorrection.attempt,
    1,
  );
  assert.equal(
    fixture.currentRun.pipelineState.pendingConfirmationCorrection.attempt,
    1,
  );

  processStopped = false;
  fixture.runtime.finishAgentTurn = finishAgentTurn;
  fixture.runtime.transition = transition;
  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const correctionCalls = fixture.calls.reviewer.filter(({ prompt }) =>
    prompt.includes("pending read-only correction"),
  );
  assert.equal(correctionCalls.length, 2);
  assert.ok(correctionCalls.every(({ access }) => access === "read-only"));
  assert.ok(correctionCalls.every(({ session }) => session === undefined));
});

test("rejects repository mutation and fingerprint drift during terminal confirmation correction", async (t) => {
  await t.test("read-only mutation", async (t) => {
    const fixture = await createFixture(t, {
      async onRoleRun(role, request) {
        if (
          role === "reviewer" &&
          request.prompt.includes("pending read-only correction")
        ) {
          await writeFile(join(request.cwd, "source.js"), "review mutation\n");
        }
      },
      workReviewer: [
        terminalConfirmation(invalidReviewStatus()),
        terminalConfirmation(reviewApproved()),
      ],
    });

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "read_only_agent_mutated_repository");
    assert.equal(paused.pipelineState.currentStep, null);
    assert.equal(paused.pipelineState.confirmationCorrection, null);
    assert.equal(paused.pipelineState.pendingConfirmationCorrection, null);
  });

  await t.test("fingerprint drift", async (t) => {
    let drifted = false;
    const fixture = await createFixture(t, {
      async onTransition(run, _patch, options) {
        if (!drifted && options.activity?.kind === "confirmation-correction") {
          drifted = true;
          await writeFile(
            join(run.projectPath, "source.js"),
            "external drift\n",
          );
        }
      },
      workReviewer: [terminalConfirmation(invalidReviewStatus())],
    });

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "unsafe_git_state");
    assert.equal(paused.pause.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
    assert.equal(paused.pipelineState.confirmationCorrection, null);
    assert.equal(paused.pipelineState.pendingConfirmationCorrection, null);
    assert.equal(
      fixture.calls.reviewer.filter(({ prompt }) =>
        prompt.includes("Review the changes"),
      ).length,
      1,
    );
  });

  await t.test("validation-infrastructure fingerprint drift", async (t) => {
    let drifted = false;
    const fixture = await createFixture(t, {
      onTransition(_run, _patch, options) {
        if (options.activity?.kind === "confirmation-correction") {
          drifted = true;
        }
      },
      workReviewer: [terminalConfirmation(invalidReviewStatus())],
    });
    const validationInfrastructureFingerprint =
      fixture.runtime.git.validationInfrastructureFingerprint;
    fixture.runtime.git.validationInfrastructureFingerprint = (options) =>
      drifted ? "c".repeat(64) : validationInfrastructureFingerprint(options);

    const paused = await fixture.run();

    assert.equal(paused.pause.reason, "unsafe_git_state");
    assert.equal(
      paused.pause.code,
      "ERR_REVIEW_VALIDATION_INFRASTRUCTURE_CHANGED",
    );
    assert.equal(paused.pipelineState.confirmationCorrection, null);
    assert.equal(paused.pipelineState.pendingConfirmationCorrection, null);
  });
});

test("corrects, blocks, and completes runner-trusted validation", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const bootstrap = (role) => ({
    ...bootstrapReady(role),
    requiredChecks,
  });
  const finalization = {
    ...finalizationPassed(),
    requiredChecks,
    checks: [
      ...checkResults("PASS"),
      {
        checkId: "C2",
        command: trustedValidation.commands[0].command,
        status: "NOT_RUN",
        evidence: ["Reserved for the runner-trusted executor."],
      },
    ],
  };
  const trustedCalls = [];
  const fixture = await createFixture(t, {
    trustedValidation,
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      bootstrap("Worker"),
      reconciliationResolved(),
    ],
    reviewer: [bootstrap("Reviewer")],
    workWorker: [implementationCompleted(), finalization, finalization],
    onTrustedValidation(options) {
      trustedCalls.push(options);
      return {
        status: trustedCalls.length === 1 ? "BLOCKED" : "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: trustedCalls.length === 1 ? null : 0,
        signal: null,
        timedOut: trustedCalls.length === 1,
        evidence: [
          trustedCalls.length === 1
            ? "The selected host service is unavailable."
            : "The temporary runner service check passed.",
        ],
        ...options.bindings,
      };
    },
  });

  const paused = await fixture.run({ trustedChecks: ["service-check"] });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.code, "ERR_TRUSTED_VALIDATION_BLOCKED");
  assert.equal(paused.pause.resumeState, "FINALIZE");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.deepEqual(paused.pipelineState.bootstrapCorrections, [
    bootstrapCorrection({
      role: "worker",
      phase: "bootstrap",
      contract: "bootstrap",
      field: "requiredChecks",
      constraint: "includes-runner-trusted-commands",
    }),
  ]);

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(trustedCalls.length, 2);
  assert.deepEqual(
    result.pipelineState.finalizationResult.checks.map(
      ({ checkId, executor, commandIdentity }) => ({
        checkId,
        executor,
        commandIdentity,
      }),
    ),
    [
      { checkId: "C1", executor: "agent", commandIdentity: null },
      {
        checkId: "C2",
        executor: "runner",
        commandIdentity: trustedValidation.commands[0].identity,
      },
    ],
  );
  assert.equal(
    result.pipelineState.finalizationResult.trustedCommandFingerprint,
    trustedValidation.commandFingerprint,
  );
  assert.match(fixture.calls.worker[1].prompt, /service-check/u);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /return NOT_RUN/u,
  );
});

test("turns a runner-trusted check failure into a bounded finalization issue", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const captured = new Error("captured trusted validation failure");
  let failedState;
  const fixture = await createFixture(t, {
    trustedValidation,
    worker: [
      clarificationReady(),
      { ...bootstrapReady("Worker"), requiredChecks },
      reconciliationResolved(),
    ],
    reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationPassed(),
        requiredChecks,
        checks: [
          ...checkResults("PASS"),
          {
            checkId: "C2",
            command: trustedValidation.commands[0].command,
            status: "NOT_RUN",
            evidence: ["Reserved for the runner-trusted executor."],
          },
        ],
      },
    ],
    onTrustedValidation(options) {
      return {
        status: "FAIL",
        commandIdentity: options.commandIdentity,
        exitCode: 7,
        signal: null,
        timedOut: false,
        evidence: ["Runner-trusted command service-check exited with code 7."],
        ...options.bindings,
      };
    },
    onTransition(run) {
      if (run.pipelineState.workflowState === "RESOLVE_FINDINGS") {
        failedState = run.pipelineState;
        throw captured;
      }
    },
  });

  await assert.rejects(
    fixture.run({ trustedChecks: ["service-check"] }),
    (cause) => cause === captured,
  );

  assert.equal(failedState.finalizationResult.status, "FAIL");
  assert.equal(failedState.finalizationResult.checks[1].executor, "runner");
  assert.deepEqual(failedState.finalizationResult.issues, [
    {
      id: "F1",
      command: trustedValidation.commands[0].command,
      problem: "A runner-trusted validation command failed.",
      evidence: ["Runner-trusted command service-check exited with code 7."],
    },
  ]);
});

test("validates runner-trusted evidence before attempting finalization advancement", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const finalization = finalizationWithTrustedCheck(trustedValidation);
  const fixture = await createFixture(t, {
    trustedValidation,
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks: finalization.requiredChecks,
      },
      reconciliationResolved(),
    ],
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks: finalization.requiredChecks,
      },
    ],
    workReviewer: [],
    workWorker: [implementationCompleted(), finalization],
    onTrustedValidation(options) {
      return {
        status: "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: 7,
        signal: null,
        timedOut: false,
        evidence: ["Invalid runner evidence must not be persisted."],
        ...options.bindings,
      };
    },
  });

  const paused = await fixture.run({ trustedChecks: ["service-check"] });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "finalization_transition_invalid");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.doesNotMatch(JSON.stringify(paused), /Invalid runner evidence/u);
  assert.equal(
    fixture.transitions.some(
      ({ patch }) =>
        patch?.pipelineState?.finalizationResult !== undefined &&
        patch.pipelineState.finalizationResult !== null,
    ),
    false,
  );
});

test("rejects trusted validation binding drift and repository mutation", async (t) => {
  for (const [name, code] of [
    ["binding drift", "ERR_TRUSTED_VALIDATION_BINDING_CHANGED"],
    ["repository mutation", "ERR_TRUSTED_VALIDATION_MUTATED_REPOSITORY"],
    ["unterminated process tree", "ERR_TRUSTED_VALIDATION_PROCESS_TREE_ACTIVE"],
  ]) {
    await t.test(name, async (t) => {
      const trustedValidation = trustedValidationSnapshot();
      const requiredChecks = [
        ...REQUIRED_CHECKS,
        { id: "C2", command: trustedValidation.commands[0].command },
      ];
      const fixture = await createFixture(t, {
        trustedValidation,
        worker: [
          clarificationReady(),
          { ...bootstrapReady("Worker"), requiredChecks },
          reconciliationResolved(),
        ],
        reviewer: [{ ...bootstrapReady("Reviewer"), requiredChecks }],
        workWorker: [
          implementationCompleted(),
          {
            ...finalizationPassed(),
            requiredChecks,
            checks: [
              ...checkResults("PASS"),
              {
                checkId: "C2",
                command: trustedValidation.commands[0].command,
                status: "NOT_RUN",
                evidence: ["Reserved for the runner-trusted executor."],
              },
            ],
          },
        ],
        onTrustedValidation() {
          const error = new Error(`Trusted executor ${name}.`);
          error.code = code;
          throw error;
        },
      });

      const result = await fixture.run({
        trustedChecks: ["service-check"],
      });

      assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(result.pause.reason, "unsafe_git_state");
      assert.equal(result.pause.code, code);
    });
  }
});

test("rejects ignored validation-infrastructure drift after trusted execution", async (t) => {
  const trustedValidation = trustedValidationSnapshot();
  const infrastructurePath = "LOCAL_ARTIFACTS/validation.json";
  const validationInfrastructure = [infrastructurePath];
  const requiredChecks = [
    ...REQUIRED_CHECKS,
    { id: "C2", command: trustedValidation.commands[0].command },
  ];
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await mkdir(join(projectPath, "LOCAL_ARTIFACTS"), { recursive: true });
      await writeFile(join(projectPath, infrastructurePath), '{"version":1}\n');
    },
    trustedValidation,
    worker: [
      clarificationReady(),
      {
        ...bootstrapReady("Worker"),
        requiredChecks,
        validationInfrastructure,
      },
      reconciliationResolved(),
    ],
    reviewer: [
      {
        ...bootstrapReady("Reviewer"),
        requiredChecks,
        validationInfrastructure,
      },
    ],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationPassed(),
        requiredChecks,
        validationInfrastructure,
        checks: [
          ...checkResults("PASS"),
          {
            checkId: "C2",
            command: trustedValidation.commands[0].command,
            status: "NOT_RUN",
            evidence: ["Reserved for the runner-trusted executor."],
          },
        ],
      },
    ],
    async onTrustedValidation(options) {
      await writeFile(
        join(fixture.projectPath, infrastructurePath),
        '{"version":2}\n',
      );
      return {
        status: "PASS",
        commandIdentity: options.commandIdentity,
        exitCode: 0,
        signal: null,
        timedOut: false,
        evidence: ["The runner-trusted check passed."],
        ...options.bindings,
      };
    },
  });

  const result = await fixture.run({ trustedChecks: ["service-check"] });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "unsafe_git_state");
  assert.equal(
    result.pause.code,
    "ERR_TRUSTED_VALIDATION_INFRASTRUCTURE_CHANGED",
  );
  assert.equal(result.pipelineState.finalizationResult, null);
});

test("falls back when automatic finalization discovery finds no skill", async (t) => {
  const fixture = await createFixture(t, {
    finalizationSkill: false,
    workWorker: [implementationCompleted(), finalizationPassed("")],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, "auto");
  assert.equal(result.pipelineState.finalizationResult.skillPath, null);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /repository instructions and project-defined checks/u,
  );
});

test("uses an explicitly configured finalization skill", async (t) => {
  const skillPath = ".agents/skills/finalization/SKILL.md";
  const fixture = await createFixture(t);

  const result = await fixture.run({ finalization: skillPath });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.finalization, skillPath);
  assert.match(
    fixture.calls.worker.find(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).prompt,
    /explicitly configured/u,
  );
});

test("defers skill-guided commit preparation to the constrained commit turn", async (t) => {
  const skillPath = ".agents/skills/finalization/SKILL.md";
  const fixture = await createFixture(t, {
    async prepareProject(projectPath) {
      await writeFile(
        join(projectPath, skillPath),
        `---
name: finalization
description: Test validation and handoff.
---

Run tests and formatting, then stage changes, inspect the cached diff, and draft a commit message.
`,
      );
    },
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({ finalization: skillPath });

  assert.equal(result.pipelineState.workflowState, "DONE");
  const implementationCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Implement the changes"),
  );
  const resolutionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("For each finding below"),
  );
  const finalizationCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Run the complete project finalization procedure"),
  );
  const commitCall = fixture.calls.worker.find(
    ({ access }) => access === "local-commit",
  );
  assert.ok(implementationCall);
  assert.ok(resolutionCall);
  assert.equal(finalizationCalls.length, 2);
  assert.ok(commitCall);
  for (const call of [implementationCall, resolutionCall]) {
    assert.match(call.prompt, /Do not run the project finalization procedure/u);
    assert.match(call.prompt, /generic commit preparation/u);
    assert.match(call.prompt, /required-check inventory is input only/u);
    assert.doesNotMatch(call.prompt, /Established required-check inventory:/u);
  }
  for (const call of finalizationCalls) {
    assert.match(call.prompt, /Follow every substantive instruction/u);
    assert.match(call.prompt, /staged\/index-relative inspection/u);
    assert.match(call.prompt, /against HEAD or explicit trees/u);
    assert.match(
      call.prompt,
      /neither a validation blocker nor a skipped required check/u,
    );
    assert.match(
      call.prompt,
      /constrained COMMIT executor alone runs git add -A/u,
    );
  }
  assert.match(commitCall.prompt, /exact supplied subject/u);
  assert.match(commitCall.prompt, /constrained executor alone stages/u);
  assert.match(
    commitCall.prompt,
    /Authorized planned commit:\nfeat\(test\): add behavior/u,
  );
});

test("pauses before invoking a missing explicit finalization skill", async (t) => {
  const fixture = await createFixture(t);

  const result = await fixture.run({
    finalization: "checks/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pause.resumeState, "FINALIZE");
  assert.equal(result.pause.skillPath, "checks/finalization/SKILL.md");
  assert.equal(
    fixture.calls.worker.some(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ),
    false,
  );
});

test("resumes finalization after an explicit skill is corrected", async (t) => {
  for (const kind of ["missing", "symlink-invalid"]) {
    await t.test(kind, async (t) => {
      const skillPath = `LOCAL_ARTIFACTS/skills/${kind}/SKILL.md`;
      const fixture = await createFixture(t, {
        workWorker: [implementationCompleted(), finalizationPassed(skillPath)],
      });
      const skillDirectory = dirname(join(fixture.projectPath, skillPath));
      if (kind === "symlink-invalid") {
        const externalSkillDirectory = await mkdtemp(
          join(tmpdir(), "agent-runner-external-skill-"),
        );
        t.after(() =>
          rm(externalSkillDirectory, { recursive: true, force: true }),
        );
        await writeFile(
          join(externalSkillDirectory, "SKILL.md"),
          "---\nname: finalization\ndescription: External validation.\n---\n",
        );
        await mkdir(dirname(skillDirectory), { recursive: true });
        await symlink(externalSkillDirectory, skillDirectory, "dir");
      }

      const paused = await fixture.run({ finalization: skillPath });

      assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
      assert.equal(
        paused.pause.reason,
        kind === "missing"
          ? "finalization_skill_missing"
          : "finalization_skill_invalid",
      );
      assert.doesNotThrow(() =>
        planExecutionPipeline.validateResumeAction(paused, null),
      );
      await rm(skillDirectory, { recursive: true, force: true });
      await mkdir(skillDirectory, { recursive: true });
      await writeFile(
        join(skillDirectory, "SKILL.md"),
        "---\nname: finalization\ndescription: Test validation.\n---\n\nRun tests.\n",
      );

      const resumed = await fixture.run();

      assert.equal(resumed.pipelineState.workflowState, "DONE");
      assert.equal(resumed.pause, null);
      assert.equal(
        resumed.pipelineState.finalizationResult.skillPath,
        skillPath,
      );
    });
  }
});

test("corrects a skill availability status without selected guidance", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      { ...finalizationUnavailable("SKILL_MISSING"), skillPath: "" },
      finalizationPassed(""),
    ],
  });

  const completed = await fixture.run({ finalization: "none" });

  assert.equal(completed.pipelineState.workflowState, "DONE");
  const correction = fixture.transitions
    .find(({ options }) => options.activity?.kind === "finalization-correction")
    .patch.pipelineState.finalizationCorrections.at(-1);
  assert.equal(correction.diagnostics[0].field, "status");
  assert.equal(
    correction.diagnostics[0].constraint,
    "selected-finalization-guidance",
  );
});

test("rejects a child session shared by Worker and Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: {
      ...ROLE_SESSIONS,
      reviewer: ROLE_SESSIONS.worker,
    },
  });

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("rejects a fresh role turn that reuses its previous session", async (t) => {
  const fixture = await createFixture(t, {
    sessionIds: {
      ...ROLE_SESSIONS,
      worker: [
        ROLE_SESSIONS.worker,
        RESTARTED_ROLE_SESSIONS.worker,
        REBOOTSTRAPPED_WORKER_SESSION,
        REBOOTSTRAPPED_WORKER_SESSION,
      ],
    },
    worker: [
      clarificationReady(),
      bootstrapReady("Worker"),
      reconciliationProductDecision(),
      compatibilityReady(),
      bootstrapReady("Worker"),
    ],
  });

  await fixture.run();
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

  await assert.rejects(
    fixture.run(),
    (error) => error.code === "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
  );
  assert.equal(fixture.currentRun.pipelineState.workflowState, "FAILED");
});

test("binds corrected candidate and finalization evidence across formatting", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [{ ...reviewApproved(), unexpected: true }],
    workWorker: [
      implementationCompleted(),
      invalidProductionFinalization(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await writeFile(join(request.cwd, "formatted.js"), "export {}\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.ok(
    fixture.transitions.some(
      ({ options }) => options.activity?.kind === "review-correction",
    ),
  );
  const confirmationState = fixture.transitions.find(
    ({ patch }) => patch?.pipelineState?.workflowState === "CONFIRM",
  ).patch.pipelineState;
  assert.notEqual(
    confirmationState.candidateReviewedFingerprint,
    confirmationState.finalizedFingerprint,
  );
  assert.equal(
    confirmationState.reviewCorrection.contentFingerprint,
    confirmationState.candidateReviewedFingerprint,
  );
  assert.equal(
    confirmationState.finalizationCorrections[0].contentFingerprint,
    confirmationState.finalizedFingerprint,
  );
});

test("runs lazy execution with one Worker source fork and no review roles", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.settings.mode, "lazy");
  assert.deepEqual(result.pipelineState.backendVersions, {
    worker: "fake-1.0.0",
  });
  assert.equal(result.pipelineState.lazySourceForkConsumed, true);
  assert.equal(
    result.pipelineState.cleanConfirmationFingerprint,
    result.pipelineState.finalizedFingerprint,
  );
  assert.equal(
    result.pipelineState.reviewedFingerprint,
    result.pipelineState.finalizedFingerprint,
  );
  assert.equal(fixture.probeCalls.worker, 1);
  assert.equal(fixture.probeCalls.reviewer, 0);
  assert.equal(fixture.probeCalls.arbiter, 0);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.deepEqual(fixture.calls.worker[0].session, {
    mode: "fork",
    id: SOURCE_SESSION,
  });
  assert.ok(
    fixture.calls.worker
      .slice(1)
      .every(({ session }) => session?.mode === "continue"),
  );
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker"],
  );
});

test("automatically corrects invalid lazy check output in a fresh session", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      { ...checkAndFix(), rejected: "not retained" },
      checkAndFix(),
      cleanConfirmation(),
    ],
  });

  const completed = await fixture.run();
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("previous structured lazy checkpoint result was rejected"),
  );
  const correctionState = fixture.transitions.find(
    ({ patch }) =>
      patch?.pipelineState?.pendingLazyCorrection !== null &&
      patch?.pipelineState?.pendingLazyCorrection !== undefined,
  ).patch.pipelineState;

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(correctionCall.session, undefined);
  assert.equal(correctionState.pendingLazyCorrection.phase, "CHECK_AND_FIX");
  assert.equal(correctionState.pendingLazyCorrection.attempt, 1);
  assert.equal(correctionState.pendingLazyCorrection.fixRoundCharged, false);
  assert.equal(correctionState.lazyCorrections.length, 1);
  assert.equal(completed.counters.fixRounds, 1);
});

test("corrects a classified lazy provider failure without retaining diagnostics", async (t) => {
  let rejected = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them") &&
        !request.prompt.includes("Pending correction diagnostic batch") &&
        !rejected
      ) {
        rejected = true;
        const error = new Error("DO_NOT_PERSIST provider details");
        error.failureClass = "structured-output";
        throw error;
      }
    },
  });

  const completed = await fixture.run();
  const correctionState = fixture.transitions.find(
    ({ patch }) =>
      patch?.pipelineState?.pendingLazyCorrection?.diagnostics?.[0]
        ?.constraint === "provider-structured-output",
  ).patch.pipelineState;

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    correctionState.pendingLazyCorrection.diagnostics[0].constraint,
    "provider-structured-output",
  );
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);
});

test("rechecks an invalid content-changing lazy result before finalization", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      { ...checkAndFix("CHANGED"), unexpected: "rejected" },
      checkAndFix(),
      cleanConfirmation(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them") &&
        !changed
      ) {
        changed = true;
        await writeFile(join(request.cwd, "invalid-lazy-fix.txt"), "fixed\n");
      }
    },
  });

  const completed = await fixture.run({ maxFixRoundsPerStep: 1 });
  const finalizations = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Run the complete project finalization procedure"),
  );

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(finalizations.length, 1);
  assert.equal(completed.counters.fixRounds, 1);
  assert.ok(
    fixture.transitions.some(
      ({ patch }) =>
        patch?.pipelineState?.pendingLazyCorrection?.fixRoundCharged === true,
    ),
  );
});

test("does not recount an invalid lazy mutation when finalization restores its fingerprint", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      { ...checkAndFix("CHANGED"), unexpected: "rejected" },
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them") &&
        !changed
      ) {
        changed = true;
        await writeFile(join(request.cwd, "restored-lazy-fix.txt"), "fixed\n");
      } else if (
        role === "worker" &&
        changed &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await rm(join(request.cwd, "restored-lazy-fix.txt"));
      }
    },
  });

  const completed = await fixture.run({ maxFixRoundsPerStep: 1 });

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.counters.fixRounds, 1);
});

test("corrects invalid lazy clean confirmation without changing its scope", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      { ...cleanConfirmation(), unexpected: "rejected" },
      cleanConfirmation(),
    ],
  });

  const completed = await fixture.run();
  const correctionCall = fixture.calls.worker.find(({ prompt }) =>
    prompt.includes("Pending correction diagnostic batch"),
  );

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(correctionCall.access, "read-only");
  assert.equal(correctionCall.session, undefined);
  assert.equal(
    completed.pipelineState.cleanConfirmationFingerprint,
    completed.pipelineState.finalizedFingerprint,
  );
});

test("keeps one lazy Worker source fork across multiple commits", async (t) => {
  const plan = `## Commit 1: feat(test): add first lazy behavior

Implement the first behavior.

## Commit 2: fix(test): add second lazy behavior

Implement the second behavior.`;
  const fixture = await createFixture(t, {
    mode: "lazy",
    plan,
    sourceSession: SOURCE_SESSION,
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.completedCommits.length, 2);
  assert.equal(
    fixture.calls.worker.filter(({ session }) => session?.mode === "fork")
      .length,
    1,
  );
  assert.deepEqual(
    result.sessionLineage.children.map(({ role }) => role),
    ["worker"],
  );
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("converges a content-changing lazy check before terminal finalization", async (t) => {
  let changed = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      checkAndFix("CHANGED"),
      checkAndFix(),
      cleanConfirmation(),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them") &&
        !changed
      ) {
        changed = true;
        await writeFile(join(request.cwd, "lazy-fix.txt"), "fixed\n");
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).length,
    1,
  );
  const phases = fixture.transitions
    .map(({ patch }) => patch?.pipelineState?.workflowState)
    .filter(Boolean);
  const candidateConfirmation = phases.indexOf(
    "CLEAN_CONFIRM",
    phases.indexOf("CHECK_AND_FIX"),
  );
  const finalization = phases.indexOf("FINALIZE", candidateConfirmation);
  assert.ok(candidateConfirmation >= 0);
  assert.ok(finalization > candidateConfirmation);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("routes lazy confirmation findings directly back to Worker fixing", async (t) => {
  let checkRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      terminalLazyConfirmation(cleanConfirmationFindings("R1")),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them")
      ) {
        checkRound += 1;
        if (checkRound === 2) {
          await writeFile(join(request.cwd, "confirmation-fix.txt"), "fixed\n");
        }
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 3);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.ok(
    fixture.transitions.some(
      ({ patch }) =>
        patch?.pipelineState?.workflowState === "CHECK_AND_FIX" &&
        patch.pipelineState.findings.some(({ id }) => id === "R1"),
    ),
  );
});

test("re-finalizes corrected evidence without requiring a content change", async (t) => {
  const omittedInventoryFinding = {
    ...cleanConfirmationFindings("R1"),
    findings: [
      {
        id: "R1",
        file: "package.json",
        problem: "The finalization inventory omitted an established test file.",
        reason:
          "The reported validation fingerprint does not cover the complete inventory.",
        suggestedAction: "Rerun finalization with the complete inventory.",
      },
    ],
  };
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      terminalLazyConfirmation(omittedInventoryFinding),
      checkAndFix(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
  });

  const result = await fixture.run();
  const finalizationCalls = fixture.calls.worker.filter(({ prompt }) =>
    prompt.includes("Run the complete project finalization procedure"),
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(finalizationCalls.length, 2);
  assert.match(finalizationCalls[1].prompt, /Current planned commit/u);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("persists repeated terminal finalization with runner-trusted PASS and FAIL evidence", async (t) => {
  for (const trustedOutcome of ["PASS", "FAIL"]) {
    await t.test(trustedOutcome, async (t) => {
      const expectedOutcomes =
        trustedOutcome === "PASS" ? ["PASS", "PASS"] : ["PASS", "FAIL", "PASS"];
      const { fixture, trustedOutcomes } = await createRevision55Fixture(t, {
        trustedOutcomes: expectedOutcomes,
      });

      const completed = await fixture.run({
        trustedChecks: ["service-check"],
      });
      const finalizationTransitions = fixture.transitions.filter(
        ({ patch, options }) =>
          options.activity?.phase === "finalization" &&
          patch?.pipelineState?.finalizationResult?.checks.some(
            ({ executor }) => executor === "runner",
          ),
      );
      const initialTransition = finalizationTransitions[0];
      const correctedTransition = finalizationTransitions[1];

      assert.equal(completed.pipelineState.workflowState, "DONE");
      assert.notEqual(initialTransition, undefined);
      assert.notEqual(correctedTransition, undefined);
      assert.equal(
        correctedTransition.patch.pipelineState.pendingFinalizationCorrection,
        null,
      );
      assert.equal(
        correctedTransition.patch.pipelineState.finalizationResult.status,
        trustedOutcome,
      );
      assert.equal(
        correctedTransition.patch.pipelineState.finalizationResult.fingerprint,
        initialTransition.patch.pipelineState.finalizationResult.fingerprint,
      );
      assert.equal(
        correctedTransition.patch.pipelineState.lazyCorrections.length,
        0,
      );
      assert.equal(
        correctedTransition.patch.pipelineState.pendingLazyCorrection,
        null,
      );
      assert.deepEqual(trustedOutcomes, expectedOutcomes);
      assert.equal(fixture.calls.reviewer.length, 0);
      assert.equal(fixture.calls.arbiter.length, 0);
    });
  }
});

test("pauses an invalid corrected finalization transition at its resumable checkpoint", async (t) => {
  const rejectedProviderSummary = "DO_NOT_PERSIST_PROVIDER_SUMMARY";
  const rejectedRunnerEvidence = "DO_NOT_PERSIST_RUNNER_EVIDENCE";
  const { fixture } = await createRevision55Fixture(t, {
    refinalizationSummary: rejectedProviderSummary,
    resumeFinalization: true,
    trustedOutcomes: ["PASS", "PASS", "PASS"],
    trustedEvidence: (call) =>
      call === 2 ? rejectedRunnerEvidence : "The runner-trusted check passed.",
  });
  const transition = fixture.runtime.transition;
  let rejectTransition = true;
  fixture.runtime.transition = (patch, options) => {
    if (
      rejectTransition &&
      options.activity?.phase === "finalization" &&
      patch.pipelineState.workflowState === "CONFIRM" &&
      patch.pipelineState.finalizationCorrections.length === 1 &&
      patch.pipelineState.finalizationResult !== null
    ) {
      rejectTransition = false;
      const error = new Error("Unexpected finalization transition invariant.");
      error.code = "ERR_INVALID_PLAN_EXECUTION_STATE";
      throw error;
    }
    return transition(patch, options);
  };

  const paused = await fixture.run({ trustedChecks: ["service-check"] });
  const projected = planExecutionPipeline.projections.pause(paused);

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pipelineState.finalizationResult, null);
  assert.equal(paused.pipelineState.finalizationCorrections.length, 1);
  assert.equal(paused.pipelineState.pendingFinalizationCorrection, null);
  assert.deepEqual(projected, {
    reason: "finalization_transition_invalid",
    code: "ERR_FINALIZATION_TRANSITION_INVALID",
    explanation:
      "The runner could not persist the validated finalization transition. The last valid FINALIZE checkpoint was retained and can be retried.",
    evidence: [
      "The rejected finalization evidence was not persisted.",
      "Resume retries the bounded FINALIZE checkpoint.",
    ],
    resumeState: "FINALIZE",
    nextActions: [{ type: "resume", action: null }],
  });
  assert.doesNotThrow(() =>
    planExecutionPipeline.validateResumeAction(paused, null),
  );
  assert.doesNotMatch(JSON.stringify(paused), /DO_NOT_PERSIST/u);
  assert.doesNotMatch(JSON.stringify(fixture.transitions), /DO_NOT_PERSIST/u);

  const completed = await fixture.run();
  assert.equal(completed.pipelineState.workflowState, "DONE");
});

test("pauses repeated unsupported lazy convergence results", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix("REFINALIZE"),
      checkAndFix("REFINALIZE"),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "lazy_output_invalid");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.deepEqual(paused.pipelineState.pendingLazyCorrection.diagnostics, [
    {
      role: "worker",
      phase: "check-and-fix",
      contract: "lazy-check-and-fix",
      field: "result",
      constraint: "semantic-contract",
    },
  ]);
});

test("rejects repository mutation during lazy clean confirmation", async (t) => {
  let mutated = false;
  const fixture = await createFixture(t, {
    mode: "lazy",
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("Return CLEAN only") &&
        !mutated
      ) {
        mutated = true;
        await writeFile(
          join(request.cwd, "invalid-confirmation.txt"),
          "changed\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
  assert.equal(result.pipelineState.cleanConfirmationFingerprint, null);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("bounds repeated lazy confirmation findings without arbitration", async (t) => {
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: {
      maxFixRoundsPerStep: 5,
      maxSameFindingRounds: 1,
      stagnationWindowRounds: 10,
    },
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 1);
  assert.deepEqual(result.pipelineState.sameFindingRounds, { R1: 1 });
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
  assert.equal(
    planExecutionPipeline.projections
      .pause(fixture.currentRun)
      .nextActions.some(({ action }) => action?.type === "override-finding"),
    false,
  );
  await assert.rejects(
    fixture.run({}, { type: "override-finding", findingId: "R1" }),
    /Finding override is not applicable/u,
  );
});

test("applies additional lazy fix rounds without resetting prior progress", async (t) => {
  let checkRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: {
      maxFixRoundsPerStep: 1,
      maxSameFindingRounds: 10,
      stagnationWindowRounds: 10,
    },
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
      checkAndFix(),
      cleanConfirmationFindings("R1"),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them")
      ) {
        checkRound += 1;
        if (checkRound === 3) {
          await writeFile(join(request.cwd, "extra-lazy-fix.txt"), "fixed\n");
        }
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(paused.counters.fixRounds, 1);
  assert.equal(paused.counters.correctionRounds, 0);

  const result = await fixture.run({}, { type: "extra-fix-rounds", amount: 3 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 3);
  assert.equal(result.counters.fixRounds, 4);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("bounds repeated content-changing lazy checks", async (t) => {
  let checkRound = 0;
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: {
      maxFixRoundsPerStep: 1,
      maxSameFindingRounds: 10,
      stagnationWindowRounds: 10,
    },
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix("CHANGED"),
      finalizationPassed(),
      checkAndFix(),
      cleanConfirmation(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("If you find any problems, fix them")
      ) {
        checkRound += 1;
        if (checkRound <= 2) {
          await writeFile(
            join(request.cwd, `bounded-lazy-fix-${checkRound}.txt`),
            "fixed\n",
          );
        }
      }
    },
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "CHECK_AND_FIX");
  assert.equal(paused.counters.fixRounds, 1);

  const result = await fixture.run({}, { type: "extra-fix-rounds", amount: 2 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 2);
  assert.equal(result.counters.fixRounds, 3);
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("routes finalization failures through a fix and the complete gate", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.counters.correctionRounds, 0);
  assert.equal(result.pipelineState.finalizationResult.status, "PASS");
  assert.equal(fixture.calls.reviewer.length, 4);
});

test("projects blockers when lazy finalization correction stagnates", async (t) => {
  const privateFailure = {
    ...finalizationFailed("F3"),
    summary: "PRIVATE_FINALIZATION_SUMMARY",
    issues: [
      {
        id: "F3",
        command: "PRIVATE_FINALIZATION_COMMAND",
        problem: "PRIVATE_FINALIZATION_PROBLEM",
        evidence: ["PRIVATE_FINALIZATION_EVIDENCE"],
      },
    ],
  };
  const fixture = await createFixture(t, {
    mode: "lazy",
    modeSettings: {
      maxFixRoundsPerStep: 10,
      maxSameFindingRounds: 10,
      stagnationWindowRounds: 1,
    },
    worker: [clarificationReady(), bootstrapReady("Worker")],
    workWorker: [
      implementationCompleted(),
      checkAndFix(),
      cleanConfirmation(),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      checkAndFix(),
      cleanConfirmation(),
      privateFailure,
      resolution({ id: "F3", decision: "FIX" }),
      checkAndFix(),
      cleanConfirmation(),
      privateFailure,
    ],
  });

  const result = await fixture.run();
  const projection = planExecutionPipeline.projections.pause(result);

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(result.counters.fixRounds, 3);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(result.pipelineState.blockedSinceStagnation, 1);
  assert.deepEqual(result.pipelineState.sameFindingRounds, {});
  assert.deepEqual(
    result.pipelineState.correctionHistory.map(
      ({ finalizationIssueIds, findingIds }) => ({
        finalizationIssueIds,
        findingIds,
      }),
    ),
    [{ finalizationIssueIds: ["F3"], findingIds: [] }],
  );
  assert.equal(
    result.pipelineState.finalizationResult.issues[0].command,
    "PRIVATE_FINALIZATION_COMMAND",
  );
  assert.deepEqual(result.pipelineState.findings, []);
  assert.deepEqual(projection, {
    reason: "no_progress",
    code: null,
    explanation: "The correction loop reached a bounded no-progress condition.",
    evidence: ["Finalization blocker F3 remains unresolved."],
    resumeState: "RESOLVE_FINDINGS",
    nextActions: [
      {
        type: "start-new-run",
        requirement: "resolved-finalization-blockers",
      },
    ],
  });
  assert.doesNotMatch(
    JSON.stringify(projection),
    /PRIVATE_FINALIZATION_(?:SUMMARY|COMMAND|PROBLEM|EVIDENCE)/u,
  );
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).length,
    2,
  );
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("For each finding below"),
    ).length,
    1,
  );
  assert.equal(fixture.calls.reviewer.length, 0);
  assert.equal(fixture.calls.arbiter.length, 0);
});

test("invalidates finalization and review after fixing a review finding", async (t) => {
  const validationStates = [];
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewApproved()],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
    onTransition(run) {
      if (run.pipelineState.workflowState === "FINALIZE") {
        validationStates.push({
          finalizationResult: run.pipelineState.finalizationResult,
          finalizedFingerprint: run.pipelineState.finalizedFingerprint,
          reviewedFingerprint: run.pipelineState.reviewedFingerprint,
        });
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.ok(
    validationStates.every(
      (entry) =>
        entry.finalizationResult === null &&
        entry.finalizedFingerprint === null &&
        entry.reviewedFingerprint === null,
    ),
  );
  assert.equal(fixture.calls.reviewer.length, 4);
});

test("preserves disputes while accepted findings are fixed", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.match(
    fixture.calls.reviewer.find(({ prompt }) =>
      prompt.includes("Worker disputes"),
    ).prompt,
    /Worker disputes[\s\S]*R2/u,
  );
  assert.match(
    fixture.calls.reviewer.findLast(({ prompt }) =>
      prompt.includes("Review the changes"),
    ).prompt,
    /Review the changes[\s\S]*Prior decisions for this step[\s\S]*R2/u,
  );
});

test("resumes the complete review after reconsidering a deferred dispute", async (t) => {
  let interruptReview = true;
  let reviewTurns = 0;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reviewApproved(),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
    async onRoleRun(role, request) {
      if (
        role === "reviewer" &&
        request.prompt.includes("Review the changes")
      ) {
        reviewTurns += 1;
        if (reviewTurns === 3 && interruptReview) {
          interruptReview = false;
          const error = new Error(
            "Reviewer backend is temporarily unavailable.",
          );
          error.code = "ERR_PLAN_EXECUTION_BACKEND_UNAVAILABLE";
          throw error;
        }
      }
    },
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "backend_unavailable");
  assert.equal(paused.pause.resumeState, "REVIEW");
  assert.equal(paused.pipelineState.pendingDisputes.length, 0);
  assert.equal(paused.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(paused.pipelineState.reviewedFingerprint, null);

  const resumed = await fixture.run();

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    resumed.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    /Prior decisions for this step[\s\S]*"findingId": "R2"/u,
  );
});

test("resolves a mixed dispute before finalization pauses", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reviewApproved(),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationUnavailable("SKILL_MISSING"),
    ],
  });

  const result = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.deepEqual(result.pipelineState.pendingDisputes, []);
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
});

test("preserves a mixed dispute through a finalization fix", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationFailed("F1"),
      resolution({ id: "F1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
});

test("preserves a mixed dispute through stagnation rework", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("WITHDRAW", "R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationFailed("F1"),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.pipelineState.disputeHistory.at(-1).findingId, "R2");
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.ok(
    fixture.calls.worker.some(({ prompt, recoveryPrompt }) =>
      /Persisted correction context[\s\S]*pendingDisputes[\s\S]*R2/u.test(
        recoveryPrompt ?? prompt,
      ),
    ),
  );
});

test("arbitrates an upheld mixed dispute after the complete re-review", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    workReviewer: [
      reviewFindings("R1", "R2"),
      reconsideration("UPHOLD", "R2"),
      reviewFindings("R2"),
    ],
    workWorker: [
      implementationCompleted(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({ maxDisputesPerFinding: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.equal(result.pipelineState.disputeHistory.at(-1).direction, "UPHOLD");
  assert.equal(result.pipelineState.findingArbitrations.at(-1).findingId, "R2");
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("lets the Reviewer withdraw an evidenced Worker dispute", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reconsideration("WITHDRAW", "R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 0);
  assert.equal(result.pipelineState.disputeCounts.R1, 1);
  assert.equal(
    result.pipelineState.disputeHistory.at(-1).direction,
    "WITHDRAW",
  );
  assert.equal(result.pipelineState.findings.length, 0);
});

test("arbitrates an upheld finding only after its dispute budget", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("WORKER_CORRECT")],
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsideration("UPHOLD", "R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R1, 2);
  assert.equal(
    result.pipelineState.findingArbitrations[0].direction,
    "WORKER_CORRECT",
  );
  assert.equal(fixture.calls.arbiter.length, 1);
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema\./u,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Do not ask questions after clarification closes\./u,
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Prior decisions for this finding[\s\S]*"findingId": "R1"/u,
  );
});

test("requires a fix after the Arbiter upholds the Reviewer", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [findingArbitration("REVIEWER_CORRECT")],
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsideration("UPHOLD", "R1"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 1);
  assert.equal(
    result.pipelineState.findingArbitrations[0].direction,
    "REVIEWER_CORRECT",
  );
  const requiredFix = fixture.calls.worker
    .filter(({ prompt }) => prompt.includes("For each finding below"))
    .at(-1);
  assert.match(requiredFix.prompt, /"direction": "REVIEWER_CORRECT"/u);
  assert.match(requiredFix.prompt, /"findingId": "R1"/u);
});

test("pauses when the same finding survives the configured correction rounds", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      reviewFindings("R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 2,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.deepEqual(result.pause.findingIds, ["R1"]);
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(result.counters.correctionRounds, 2);
});

test("tracks stable findings beyond the bounded diagnostic history", async (t) => {
  const correctionRounds = 33;
  const fixture = await createFixture(t, {
    workReviewer: Array.from({ length: correctionRounds + 1 }, () =>
      reviewFindings("R1"),
    ),
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      ...Array.from({ length: correctionRounds }, () => [
        resolution({ id: "R1", decision: "FIX" }),
        finalizationPassed(),
      ]).flat(),
    ],
  });

  const result = await fixture.run({
    maxFixRoundsPerStep: correctionRounds,
    maxSameFindingRounds: correctionRounds,
    stagnationWindowRounds: correctionRounds + 1,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pipelineState.correctionHistory.length, 32);
  assert.equal(result.pipelineState.sameFindingRounds.R1, correctionRounds);
});

test("uses one stagnation arbitration for finding churn", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("RECONSIDER_FINDINGS", ["R3"])],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewFindings("R3"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 2,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "RECONSIDER_FINDINGS",
  );
  assert.match(
    fixture.calls.arbiter[0].prompt,
    /Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema\./u,
  );
});

test("keeps terminal stagnation reconsideration inside confirmation", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("RECONSIDER_FINDINGS", ["R3"])],
    workReviewer: [
      terminalConfirmation(reviewFindings("R1")),
      terminalConfirmation(reviewFindings("R2")),
      terminalConfirmation(reviewFindings("R3")),
      terminalConfirmation(reviewApproved()),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 2,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(
    fixture.calls.worker.filter(({ schema }) => schema === FINALIZATION_SCHEMA)
      .length,
    3,
  );
  assert.match(
    fixture.calls.reviewer.at(-1).prompt,
    /Reconsider these current finding IDs as requested by the Arbiter:\nR3/u,
  );
});

test("routes stagnation rework through Worker, finalization, and review", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(
    result.pipelineState.stagnationDirection.direction,
    "REWORK_IMPLEMENTATION",
  );
  assert.match(
    fixture.calls.worker.findLast(({ prompt }) =>
      prompt.includes("Required rework direction"),
    ).prompt,
    /Required rework direction/u,
  );
});

test("preserves stagnation rework while waiting for fix budget", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("REWORK_IMPLEMENTATION")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pause.resumeState, "IMPLEMENT");
  assert.equal(
    paused.pipelineState.implementationDirection.direction,
    "REWORK_IMPLEMENTATION",
  );
  assert.equal(paused.pipelineState.stagnationArbitrationUsed, true);
  assert.equal(fixture.calls.arbiter.length, 1);

  const result = await fixture.run({}, { type: "extra-fix-rounds", amount: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.fixRounds, 2);
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("pauses after stagnation recurs following its one arbitration", async (t) => {
  const fixture = await createFixture(t, {
    arbiter: [stagnation("CONTINUE_FIXES")],
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewFindings("R3"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const result = await fixture.run({
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 1,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "no_progress");
  assert.equal(result.pause.resumeState, "RESOLVE_FINDINGS");
  assert.equal(fixture.calls.arbiter.length, 1);
});

test("accepts a finite extra fix budget only after exhaustion", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R2"),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R2", decision: "FIX" }),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const result = await fixture.run({}, { type: "extra-fix-rounds", amount: 1 });

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.additionalFixRounds, 1);
  assert.equal(result.counters.fixRounds, 2);
});

test("overrides one current finding only for its reviewed fingerprint", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.deepEqual(result.pipelineState.findingOverrides, [
    {
      findingId: "R1",
      fingerprint: result.pipelineState.reviewedFingerprint,
    },
  ]);
});

test("resolves a sole rejected validation change through its exact override", async (t) => {
  const changedInfrastructure = ["package.json", "source.js"];
  const changedFinalization = {
    ...finalizationPassed(),
    validationInfrastructure: changedInfrastructure,
  };
  const fixture = await createFixture(t, {
    workReviewer: [
      terminalConfirmation(reviewRejected("R1")),
      terminalConfirmation(reviewRejected("R1")),
      terminalConfirmation(reviewRejected("R1")),
    ],
    workWorker: [
      implementationCompleted(),
      changedFinalization,
      resolution({ id: "R1", decision: "FIX" }),
      changedFinalization,
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");

  const completed = await fixture.run(
    {},
    { type: "override-finding", findingId: "R1" },
  );

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(completed.pipelineState.reviewResult.status, "FINDINGS");
  assert.equal(
    completed.pipelineState.reviewResult.validationChange,
    "REJECTED",
  );
  assert.deepEqual(completed.pipelineState.findings, []);
  assert.deepEqual(completed.pipelineState.validationInfrastructure, [
    "package.json",
  ]);
  assert.deepEqual(completed.pipelineState.findingOverrides, [
    {
      findingId: "R1",
      fingerprint: completed.pipelineState.reviewedFingerprint,
    },
  ]);
  assert.equal(
    fixture.calls.reviewer.filter(({ prompt }) =>
      prompt.includes("Review the changes"),
    ).length,
    2,
  );
});

test("does not store or offer an applicable override twice", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1"), reviewFindings("R1")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });
  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  const override = {
    findingId: "R1",
    fingerprint: paused.pipelineState.candidateReviewedFingerprint,
  };
  fixture.persistPipelineState({
    ...paused.pipelineState,
    findingOverrides: [override],
  });

  const projection = planExecutionPipeline.projections.pause(
    fixture.currentRun,
  );
  assert.equal(
    projection.nextActions.some(
      ({ action }) => action?.type === "override-finding",
    ),
    false,
  );
  await assert.rejects(
    fixture.run({}, { type: "override-finding", findingId: "R1" }),
    /stale or inapplicable/u,
  );
  assert.deepEqual(fixture.currentRun.pipelineState.findingOverrides, [
    override,
  ]);
});

test("suppresses a regenerated exact finding without recording approval", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewFindings("R1"),
      reviewFindings("R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });
  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  const override = {
    findingId: "R1",
    fingerprint: paused.pipelineState.candidateReviewedFingerprint,
  };
  fixture.persistPipelineState(
    {
      ...paused.pipelineState,
      workflowState: "REVIEW",
      findings: [],
      pendingDisputes: [],
      findingOverrides: [override],
    },
    { pause: null },
  );

  const completed = await fixture.run();

  assert.equal(completed.pipelineState.workflowState, "DONE");
  assert.equal(
    completed.pipelineState.candidateReviewResult.status,
    "FINDINGS",
  );
  assert.deepEqual(completed.pipelineState.candidateReviewResult.findingIds, [
    "R1",
  ]);
  assert.deepEqual(completed.pipelineState.findings, []);
  assert.throws(
    () =>
      normalizePipelineState({
        ...completed.pipelineState,
        findingOverrides: [],
      }),
    /completion state is inconsistent/u,
  );
  const lastReviewPrompt = fixture.calls.reviewer.findLast(({ prompt }) =>
    prompt.includes("Review the changes"),
  ).prompt;
  assert.match(lastReviewPrompt, /"overrides"/u);
  assert.match(lastReviewPrompt, /User overrides are runner-owned/u);
  assert.ok(
    fixture.transitions.some(
      ({ options }) => options.activity?.kind === "overrides-applied",
    ),
  );
});

test("does not carry an override across a content fingerprint change", async (t) => {
  let resolutionTurns = 0;
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1", "R2"),
      reviewFindings("R1", "R2"),
      reviewFindings("R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }, { id: "R2", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }, { id: "R2", decision: "FIX" }),
      resolution({ id: "R2", decision: "FIX" }),
      resolution({ id: "R2", decision: "FIX" }),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes("For each finding below")
      ) {
        resolutionTurns += 1;
        if (resolutionTurns === 4) {
          await writeFile(
            join(request.cwd, "changed-after-override.txt"),
            "new fingerprint\n",
          );
        }
      }
    },
  });
  const settings = {
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  };
  const paused = await fixture.run(settings);
  const overriddenFingerprint =
    paused.pipelineState.candidateReviewedFingerprint;

  const overridePaused = await fixture.run(settings, {
    type: "override-finding",
    findingId: "R1",
  });
  assert.equal(overridePaused.pause.reason, "fix_limit_reached");

  const changed = await fixture.run(settings, {
    type: "extra-fix-rounds",
    amount: 1,
  });

  assert.equal(changed.pause.reason, "fix_limit_reached");
  assert.deepEqual(
    changed.pipelineState.findings.map(({ id }) => id),
    ["R1"],
  );
  assert.notEqual(
    changed.pipelineState.candidateReviewedFingerprint,
    overriddenFingerprint,
  );
  assert.deepEqual(changed.pipelineState.findingOverrides, [
    { findingId: "R1", fingerprint: overriddenFingerprint },
  ]);
});

test("preserves an unresolved dispute count when its finding is overridden", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [reviewFindings("R1", "R2"), reviewFindings("R1", "R2")],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }, { id: "R2", decision: "FIX" }),
      finalizationPassed(),
      resolution(
        { id: "R1", decision: "FIX" },
        { id: "R2", decision: "DISPUTE" },
      ),
      resolution({ id: "R1", decision: "FIX" }),
    ],
  });

  const paused = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });
  assert.equal(paused.pause.reason, "fix_limit_reached");
  assert.equal(paused.pipelineState.disputeCounts.R2, 1);
  assert.deepEqual(paused.pipelineState.disputeHistory, []);
  const overriddenFingerprint =
    paused.pipelineState.candidateReviewedFingerprint;

  const result = await fixture.run(
    {},
    { type: "override-finding", findingId: "R2" },
  );

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "fix_limit_reached");
  assert.equal(result.pipelineState.disputeCounts.R2, 1);
  assert.deepEqual(result.pipelineState.findingOverrides, [
    {
      findingId: "R2",
      fingerprint: overriddenFingerprint,
    },
  ]);
});

test("checks plan compatibility after a post-start product decision", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationProductDecision(),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.equal(paused.pipelineState.pendingEdit.suspendedState, "IMPLEMENT");
  assert.equal(paused.pipelineState.currentStep, 1);
  assert.notEqual(paused.pipelineState.resolvedSummary, null);
  const initialImplementationKey = paused.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .at(-1).contextKey;
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.counters.productDecisions, 1);
  assert.match(
    fixture.calls.worker[4].prompt,
    /Review the updated clarifications/u,
  );
  const resumedImplementation = fixture.calls.worker
    .filter(({ prompt }) => prompt.includes("Implement the changes described"))
    .at(-1);
  assert.equal(resumedImplementation.session, undefined);
  assert.equal(
    resumedImplementation.prompt,
    resumedImplementation.recoveryPrompt,
  );
  const resumedImplementationKey = result.sessionLineage.children
    .filter(({ role }) => role === "worker")
    .at(-1).contextKey;
  assert.notEqual(initialImplementationKey, resumedImplementationKey);
});

test("preserves previous findings across a review product decision", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reviewProductDecision(),
      reviewApproved(),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pipelineState.previousFindings, [
    reviewFindings("R1").findings[0],
  ]);
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.match(
    fixture.calls.reviewer[3].prompt,
    /Previous candidate findings[\s\S]*"id": "R1"/u,
  );
});

test("starts a new dispute episode after a product decision", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [
      reviewFindings("R1"),
      reconsideration("UPHOLD", "R1"),
      reconsiderationProductDecision(),
      reviewFindings("R1"),
      reconsideration("WITHDRAW", "R1"),
    ],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
      resolution({ id: "R1", decision: "DISPUTE" }),
      compatibilityReady(),
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "DISPUTE" }),
    ],
  });

  const paused = await fixture.run();
  assert.equal(paused.pause.reason, "product_decision_required");
  assert.deepEqual(paused.pipelineState.disputeCounts, {});
  assert.deepEqual(paused.pipelineState.disputeHistory, []);
  fixture.writeClarification(`${fixture.readClarification()}Behavior A.\n`);

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.disputeCounts.R1, 1);
  assert.equal(result.pipelineState.disputeHistory.length, 1);
  assert.equal(result.pipelineState.disputeHistory[0].attempt, 1);
});

test("requires a revised plan when a post-start decision is incompatible", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [implementationProductDecision(), compatibilityPlanRevision()],
  });

  await fixture.run();
  fixture.writeClarification(`${fixture.readClarification()}Behavior B.\n`);
  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "plan_revision_required");
  assert.equal(result.pipelineState.currentStep, 1);
  assert.notEqual(result.pipelineState.resolvedSummary, null);
});

test("records a blocking correction when finalization still fails", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [terminalConfirmation(reviewFindings("R1"))],
    workWorker: [
      implementationCompleted(),
      finalizationPassed(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationFailed("F1"),
    ],
  });

  const result = await fixture.run({
    maxFixRoundsPerStep: 1,
    maxSameFindingRounds: 10,
    stagnationWindowRounds: 10,
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "fix_limit_reached");
  assert.equal(result.counters.correctionRounds, 1);
  assert.deepEqual(result.pipelineState.correctionHistory.at(-1), {
    round: 1,
    fingerprint: result.pipelineState.finalizationResult.fingerprint,
    finalizationIssueIds: ["F1"],
    findingIds: [],
  });
  assert.deepEqual(result.pipelineState.sameFindingRounds, {});
});

test("pauses before finalization advances when its skill is unavailable", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_MISSING"),
    ],
  });

  const result = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_skill_missing");
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 2);
});

test("retries finalization after its environment blocker clears", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationBlocked(
        "The validation IPC endpoint is unavailable.",
        "The test runner could not open its required IPC channel.",
      ),
      finalizationPassed(),
    ],
  });

  const paused = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  assert.equal(paused.pause.resumeState, "FINALIZE");

  const resumed = await fixture.run({ finalization: "none" });

  assert.equal(resumed.pipelineState.workflowState, "DONE");
  assert.equal(
    resumed.pipelineState.settings.finalization,
    ".agents/skills/finalization/SKILL.md",
  );
});

test("falls back after an automatically discovered skill is invalid", async (t) => {
  const fixture = await createFixture(t, {
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_INVALID"),
      finalizationPassed(""),
    ],
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "DONE");
  assert.equal(result.pipelineState.finalizationResult.skillPath, null);
  assert.equal(
    fixture.calls.worker.filter(({ prompt }) =>
      prompt.includes("Run the complete project finalization procedure"),
    ).length,
    2,
  );
});

test("rejects finalization changes made before skill validation", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationUnavailable("SKILL_MISSING"),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run({
    finalization: ".agents/skills/finalization/SKILL.md",
  });

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "finalization_cannot_pass");
  assert.equal(
    result.pause.code,
    "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION",
  );
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 2);
});

test("allows project changes before finalization becomes blocked", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      finalizationBlocked(
        "The validation process cannot be isolated on this host.",
        "The required process-isolation facility is unavailable.",
      ),
    ],
    async onRoleRun(role, request) {
      if (
        role === "worker" &&
        request.prompt.includes(
          "Run the complete project finalization procedure",
        )
      ) {
        await writeFile(
          join(request.cwd, "source.js"),
          "export const value = 2;\n",
        );
      }
    },
  });

  const result = await fixture.run();

  assert.equal(result.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(result.pause.reason, "environment_blocked");
  assert.equal(result.pause.resumeState, "FINALIZE");
  assert.equal(result.pause.code, undefined);
  assert.equal(result.pipelineState.finalizationResult, null);
  assert.equal(fixture.calls.reviewer.length, 2);
});

test("corrects a missing resolved skill path when finalization is blocked", async (t) => {
  const fixture = await createFixture(t, {
    workReviewer: [],
    workWorker: [
      implementationCompleted(),
      {
        ...finalizationBlocked(
          "The validation process is externally blocked.",
          "The required validation service is unavailable.",
        ),
        skillPath: "",
      },
      finalizationBlocked(
        "The validation process is externally blocked.",
        "The required validation service is unavailable.",
      ),
    ],
  });

  const paused = await fixture.run();

  assert.equal(paused.pipelineState.workflowState, "WAITING_FOR_USER");
  assert.equal(paused.pause.reason, "environment_blocked");
  const [diagnostic] =
    paused.pipelineState.finalizationCorrections[0].diagnostics;
  assert.equal(diagnostic.field, "skillPath");
  assert.equal(diagnostic.constraint, "resolved-finalization-skill");
});
