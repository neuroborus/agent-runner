import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { runPlanExecution } from "../src/index.js";
import {
  CLEAN_CONFIRM_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
  IMPLEMENTATION_SCHEMA,
  REVIEW_SCHEMA,
} from "../src/schemas.js";
import {
  PLAN,
  SOURCE_SESSION,
  bootstrapReady,
  clarificationReady,
  checkAndFix,
  createFixture,
  finalizationFailed,
  finalizationPassed,
  implementationCompleted,
  reconciliationResolved,
  resolution,
} from "./support/index.js";

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} repair rejoins candidate convergence before its terminal confirmer`, async (t) => {
    const turns = [];
    let beforeRepair;
    const fixture = await createFixture(t, {
      mode,
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode !== "lazy" ? [reconciliationResolved()] : []),
      ],
      sourceSession: SOURCE_SESSION,
      workWorker: [
        implementationCompleted(),
        checkAndFix(),
        finalizationFailed("F1"),
        resolution({ id: "F1", decision: "FIX" }),
        checkAndFix(),
        finalizationPassed(),
      ],
      async onRoleRun(role, request) {
        turns.push([role, fixture.currentRun.activeTurn.phase, request.access]);
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          beforeRepair = structuredClone(fixture.currentRun);
          await writeFile(join(request.cwd, "repair.txt"), "fixed\n");
        }
      },
    });

    const completed = await fixture.run();
    assert.equal(completed.pipelineState.workflowState, "DONE");
    assert.equal(completed.pipelineState.completedCommits.length, 1);
    const repair = fixture.transitions.find(
      ({ patch }) => patch?.pipelineState.pendingCorrection === true,
    );
    assert.equal(
      repair.patch.counters.fixRounds,
      beforeRepair.counters.fixRounds + 1,
    );
    for (const field of [
      "candidateReviewResult",
      "candidateReviewedFingerprint",
      "candidateConfirmationFingerprint",
      "finalizationResult",
      "finalizedFingerprint",
      "reviewResult",
      "reviewedFingerprint",
      "cleanConfirmationFingerprint",
      "reviewCorrection",
      "pendingReviewCorrection",
      "confirmationCorrection",
      "pendingConfirmationCorrection",
    ]) {
      assert.equal(repair.patch.pipelineState[field], null, field);
    }
    assert.deepEqual(
      turns.slice(turns.findIndex(([, phase]) => phase === "resolve-findings")),
      mode === "lazy"
        ? [
            ["worker", "resolve-findings", "workspace-write"],
            ["worker", "check-and-fix", "workspace-write"],
            ["worker", "clean-confirm", "read-only"],
            ["worker", "finalize", "workspace-write"],
            ["worker", "confirm", "read-only"],
            ["worker", "commit", "local-commit"],
          ]
        : [
            ["worker", "resolve-findings", "workspace-write"],
            ...(mode === "combined"
              ? [
                  ["worker", "check-and-fix", "workspace-write"],
                  ["worker", "clean-confirm", "read-only"],
                ]
              : []),
            ["reviewer", "review", "read-only"],
            ["worker", "finalize", "workspace-write"],
            ["reviewer", "confirm", "read-only"],
            ["worker", "commit", "local-commit"],
          ],
    );
    assert.equal(fixture.probeCalls.arbiter, 0);
    assert.equal(fixture.calls.arbiter.length, 0);
    const workerForks = fixture.calls.worker.filter(
      ({ session }) => session?.mode === "fork",
    );
    assert.equal(
      workerForks.length,
      mode === "lazy" ? 1 : mode === "combined" ? 9 : 3,
    );
    if (mode === "lazy") {
      assert.equal(fixture.probeCalls.reviewer, 0);
      assert.equal(fixture.calls.reviewer.length, 0);
      assert.equal(completed.pipelineState.lazySourceForkConsumed, true);
    } else {
      assert.equal(fixture.probeCalls.reviewer, 1);
      assert.equal(
        fixture.calls.reviewer.filter(({ session }) => session?.mode === "fork")
          .length,
        2,
      );
    }
  });

  test(`${mode} stop reconciliation retains a partial repair and charges it once without invoking a role`, async (t) => {
    const processLoss = new Error("Process stopped during repair.");
    let interrupted = false;
    const fixture = await createFixture(t, {
      mode,
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode !== "lazy" ? [reconciliationResolved()] : []),
      ],
      sourceSession: SOURCE_SESSION,
      workWorker: [
        implementationCompleted(),
        checkAndFix(),
        finalizationFailed("F1"),
        resolution({ id: "F1", decision: "FIX" }),
      ],
      async onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          await writeFile(join(request.cwd, "partial-repair.txt"), "partial\n");
          interrupted = true;
          throw processLoss;
        }
      },
    });
    const transition = fixture.runtime.transition;
    const finishAgentTurn = fixture.runtime.finishAgentTurn;
    fixture.runtime.transition = async (...args) => {
      if (interrupted) throw processLoss;
      return transition(...args);
    };
    fixture.runtime.finishAgentTurn = async (...args) => {
      if (interrupted) throw processLoss;
      return finishAgentTurn(...args);
    };
    await assert.rejects(fixture.run(), (error) => error === processLoss);
    const before = structuredClone(fixture.currentRun);
    assert.equal(before.activeTurn.phase, "resolve-findings");
    const calls = Object.values(fixture.calls).flat().length;
    interrupted = false;
    fixture.runtime.transition = transition;
    fixture.runtime.finishAgentTurn = finishAgentTurn;

    const reconciliationOptions = [];
    const reconcileInterrupted = fixture.runtime.git.reconcileInterrupted;
    fixture.runtime.git.reconcileInterrupted = async (baseline, options) => {
      reconciliationOptions.push(options);
      return reconcileInterrupted.call(fixture.runtime.git, baseline, options);
    };
    const reconciled = await runPlanExecution({
      run: fixture.currentRun,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.equal(
      reconciled.pipelineState.workflowState,
      mode !== "independent" ? "CHECK_AND_FIX" : "REVIEW",
    );
    assert.equal(reconciled.counters.fixRounds, before.counters.fixRounds + 1);
    assert.equal(reconciled.pipelineState.pendingCorrection, true);
    assert.equal(reconciled.pipelineState.finalizationResult, null);
    assert.equal(reconciled.pipelineState.candidateReviewedFingerprint, null);
    assert.equal(reconciled.activeTurn, null);
    assert.notEqual(
      reconciled.pipelineState.repositoryBaseline.contentFingerprint,
      before.pipelineState.repositoryBaseline.contentFingerprint,
    );
    const repeated = await runPlanExecution({
      run: reconciled,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.deepEqual(repeated.counters, reconciled.counters);
    assert.deepEqual(reconciliationOptions, [
      { allowWorkspaceChanges: true, allowIndexChanges: false },
      { allowWorkspaceChanges: false, allowIndexChanges: false },
    ]);
    assert.deepEqual(repeated.sessionLineage, before.sessionLineage);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
  });

  test(`${mode} protected plan drift prevents stop reconciliation from advancing a repair`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      worker: [
        clarificationReady(),
        bootstrapReady("Worker"),
        ...(mode !== "lazy" ? [reconciliationResolved()] : []),
      ],
      workWorker: [
        implementationCompleted(),
        checkAndFix(),
        finalizationFailed("F1"),
      ],
      onRoleRun(_role, request) {
        if (request.schema === FINDING_RESOLUTION_SCHEMA) {
          const error = new Error("Repair interrupted.");
          error.recoverable = true;
          throw error;
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.resumeState, "RESOLVE_FINDINGS");
    Object.assign(fixture.currentRun, {
      activeTurn: { role: "worker", phase: "resolve-findings" },
      pause: null,
      pipelineState: {
        ...paused.pipelineState,
        workflowState: "RESOLVE_FINDINGS",
      },
    });
    await writeFile(
      join(fixture.taskPath, "plan.md"),
      `${PLAN}\nChanged plan.\n`,
    );
    const calls = Object.values(fixture.calls).flat().length;
    const rejected = await runPlanExecution({
      run: fixture.currentRun,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.equal(rejected.pause.reason, "task_input_changed");
    assert.equal(rejected.pipelineState.finalizationResult, null);
    assert.equal(rejected.counters.fixRounds, 0);
    assert.equal(rejected.counters.correctionRounds, 0);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
    assert.equal(rejected.pipelineState.completedCommits.length, 0);
  });

  for (const [checkpoint, schema] of [
    ["implementation", IMPLEMENTATION_SCHEMA],
    ["repair", FINDING_RESOLUTION_SCHEMA],
    ["confirmation", mode === "lazy" ? CLEAN_CONFIRM_SCHEMA : REVIEW_SCHEMA],
  ]) {
    test(`${mode} keeps ref changes prohibited at ${checkpoint}`, async (t) => {
      let mutated = false;
      const fixture = await createFixture(t, {
        mode,
        worker: [
          clarificationReady(),
          bootstrapReady("Worker"),
          ...(mode !== "lazy" ? [reconciliationResolved()] : []),
        ],
        workWorker: [
          implementationCompleted(),
          checkAndFix(),
          ...(schema === FINDING_RESOLUTION_SCHEMA
            ? [
                finalizationFailed("F1"),
                resolution({ id: "F1", decision: "FIX" }),
              ]
            : [finalizationPassed()]),
        ],
        onRoleRun(_role, request, _count, repository) {
          if (request.schema === schema) {
            mutated = true;
            repository.changeRefs();
          }
        },
      });
      // Read-only turns reject through the Git boundary; writable turns pause.
      let result;
      try {
        result = await fixture.run();
      } catch (error) {
        assert.equal(error.code, "ERR_GIT_STATE_CHANGED");
        result = fixture.currentRun;
      }
      assert.equal(mutated, true);
      assert.ok(
        ["FAILED", "WAITING_FOR_USER"].includes(
          result.pipelineState.workflowState,
        ),
      );
      assert.equal(result.pipelineState.completedCommits.length, 0);
      assert.equal(
        fixture.calls.worker.some(({ access }) => access === "local-commit"),
        false,
      );
    });
  }
}
