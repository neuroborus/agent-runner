import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { polishingPipeline } from "../src/index.js";
import { runPolishing } from "../src/workflow.js";
import {
  CHECK_AND_FIX_SCHEMA,
  FINDING_RESOLUTION_SCHEMA,
} from "../src/schemas.js";
import {
  SOURCE_SESSION,
  bootstrapReady,
  candidateApproved,
  candidateClean,
  checkAndFix,
  clarificationReady,
  cleanConfirmation,
  cleanConfirmationFindings,
  createFixture,
  finalizationPassed,
  polishingCompleted,
  reconciliationResolved,
  resolution,
  reviewApproved,
  reviewFindings,
} from "./support/index.js";

for (const mode of ["independent", "lazy"]) {
  const bootstrap = () => [
    clarificationReady(),
    bootstrapReady("Worker"),
    ...(mode === "independent" ? [reconciliationResolved()] : []),
  ];
  const candidate = () =>
    mode === "lazy" ? [checkAndFix(), candidateClean()] : [];

  test(`${mode} terminal repairs retain role isolation and runner-only staging`, async (t) => {
    const turns = [];
    let repaired = false;
    let originalIndex;
    const fixture = await createFixture(t, {
      mode,
      sourceSession: SOURCE_SESSION,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy"
          ? [
              cleanConfirmationFindings("R1"),
              checkAndFix("CHANGED"),
              ...candidate(),
            ]
          : [resolution("FIX", "R1")]),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        reviewFindings("R1"),
        candidateApproved(),
        reviewApproved(),
      ],
      async onRoleRun(role, request) {
        const phase = fixture.currentRun.activeTurn.phase;
        turns.push([role, phase, request.access]);
        const snapshot = await fixture.runtime.git.snapshot({
          projectPath: fixture.projectPath,
        });
        originalIndex ??= snapshot.indexFingerprint;
        assert.equal(snapshot.indexFingerprint, originalIndex);
        if (
          !repaired &&
          (request.schema === FINDING_RESOLUTION_SCHEMA ||
            (request.schema === CHECK_AND_FIX_SCHEMA &&
              fixture.currentRun.pipelineState.findings.length > 0))
        ) {
          repaired = true;
          await writeFile(join(fixture.projectPath, "repair.txt"), "fixed\n");
        }
      },
    });
    const result = await fixture.run();
    assert.equal(result.pipelineState.workflowState, "DONE");
    assert.equal(repaired, true);
    const firstFinalize = turns.findIndex(([, phase]) => phase === "finalize");
    assert.deepEqual(
      turns.slice(firstFinalize),
      mode === "lazy"
        ? [
            ["worker", "finalize", "workspace-write"],
            ["worker", "confirm", "read-only"],
            ["worker", "check-and-fix", "workspace-write"],
            ["worker", "check-and-fix", "workspace-write"],
            ["worker", "clean-confirm", "read-only"],
            ["worker", "finalize", "workspace-write"],
            ["worker", "confirm", "read-only"],
          ]
        : [
            ["worker", "finalize", "workspace-write"],
            ["reviewer", "confirm", "read-only"],
            ["worker", "resolve-findings", "workspace-write"],
            ["reviewer", "review", "read-only"],
            ["worker", "finalize", "workspace-write"],
            ["reviewer", "confirm", "read-only"],
          ],
    );
    assert.notEqual(
      result.pipelineState.repositoryBaseline.indexFingerprint,
      originalIndex,
    );
    assert.equal(fixture.calls.arbiter.length, 0);
    const workerForks = fixture.calls.worker.filter(
      ({ session }) => session?.mode === "fork",
    );
    if (mode === "lazy") {
      assert.equal(workerForks.length, 1);
      assert.equal(fixture.calls.reviewer.length, 0);
      assert.equal(fixture.probes.reviewer, 0);
      assert.equal(result.pipelineState.lazySourceForkConsumed, true);
    } else {
      assert.ok(workerForks.length > 1);
      assert.ok(
        fixture.calls.reviewer.filter(({ session }) => session?.mode === "fork")
          .length > 1,
      );
      assert.equal(result.pipelineState.lazySourceForkConsumed, false);
    }
  });

  test(`${mode} stop reconciliation charges an interrupted repair once without agent work`, async (t) => {
    const lost = new Error("Stopped before publishing repair result.");
    let stopped = false;
    const fixture = await createFixture(t, {
      mode,
      sourceSession: SOURCE_SESSION,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy"
          ? [cleanConfirmationFindings("R1"), checkAndFix("CHANGED")]
          : [resolution("FIX", "R1")]),
      ],
      reviewer: [
        bootstrapReady("Reviewer"),
        candidateApproved(),
        reviewFindings("R1"),
      ],
      async onRoleRun(role, request) {
        if (
          request.schema === FINDING_RESOLUTION_SCHEMA ||
          (request.schema === CHECK_AND_FIX_SCHEMA &&
            fixture.currentRun.pipelineState.findings.length > 0)
        ) {
          await writeFile(
            join(fixture.projectPath, "partial.txt"),
            "partial fix\n",
          );
          stopped = true;
          throw lost;
        }
      },
    });
    const transition = fixture.runtime.transition;
    const finish = fixture.runtime.finishAgentTurn;
    fixture.runtime.transition = async (...args) => {
      if (stopped) throw lost;
      return transition(...args);
    };
    fixture.runtime.finishAgentTurn = async (...args) => {
      if (stopped) throw lost;
      return finish(...args);
    };
    await assert.rejects(fixture.run(), (error) => error === lost);
    const before = structuredClone(fixture.currentRun);
    const calls = Object.values(fixture.calls).flat().length;
    stopped = false;
    fixture.runtime.transition = transition;
    fixture.runtime.finishAgentTurn = finish;
    const options = [];
    const reconcile = fixture.runtime.git.reconcileInterrupted;
    fixture.runtime.git.reconcileInterrupted = async (
      baseline,
      permissions,
    ) => {
      options.push(permissions);
      return reconcile.call(fixture.runtime.git, baseline, permissions);
    };
    const reconciled = await runPolishing({
      run: before,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.equal(
      reconciled.pipelineState.workflowState,
      mode === "lazy" ? "CHECK_AND_FIX" : "REVIEW",
    );
    assert.equal(reconciled.counters.fixRounds, before.counters.fixRounds + 1);
    assert.equal(reconciled.pipelineState.finalizationResult, null);
    assert.equal(reconciled.pipelineState.candidateReviewedFingerprint, null);
    assert.deepEqual(
      reconciled.activeTurn,
      mode === "lazy" ? before.activeTurn : null,
    );
    const repeated = await runPolishing({
      run: reconciled,
      runtime: fixture.runtime,
      operatorStop: true,
    });
    assert.deepEqual(repeated.counters, reconciled.counters);
    assert.deepEqual(options, [
      { allowWorkspaceChanges: true, allowIndexChanges: false },
      { allowWorkspaceChanges: mode === "lazy", allowIndexChanges: false },
    ]);
    assert.equal(Object.values(fixture.calls).flat().length, calls);
    assert.deepEqual(repeated.sessionLineage, before.sessionLineage);
  });

  test(`${mode} paused polishing checks protected input drift before reconstructing`, async (t) => {
    let interrupt = true;
    const fixture = await createFixture(t, {
      mode,
      sourceSession: SOURCE_SESSION,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      onRoleRun(role, request) {
        if (fixture.currentRun.activeTurn.phase === "polish" && interrupt) {
          interrupt = false;
          const error = new Error("Provider interrupted.");
          error.recoverable = true;
          throw error;
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pause.reason, "backend_unavailable");
    assert.equal(paused.pause.resumeState, "POLISH");
    assert.doesNotThrow(() =>
      polishingPipeline.validateResumeAction(paused, null),
    );
    const calls = Object.values(fixture.calls).flat().length;
    await writeFile(
      join(fixture.taskPath, "task.md"),
      "Unexpected input replacement.\n",
    );
    const blocked = await fixture.run();
    assert.equal(blocked.pause.reason, "task_input_changed");
    assert.equal(Object.values(fixture.calls).flat().length, calls);
  });

  test(`${mode} canceled checkpoint never invokes another role or stages a handoff`, async (t) => {
    const fixture = await createFixture(t, { mode });
    const before = fixture.currentRun;
    const canceled = {
      ...before,
      pipelineState: { ...before.pipelineState, workflowState: "CANCELED" },
      stopRequest: {
        kind: "cancel_requested",
        reconciledRevision: before.revision,
      },
      pause: {
        reason: "operator_canceled",
        resumeAction: null,
        operatorResume: {
          workflowState: before.pipelineState.workflowState,
          pause: before.pause,
          activeTurn: before.activeTurn,
        },
      },
    };
    const result = await runPolishing({
      run: canceled,
      runtime: fixture.runtime,
    });
    assert.equal(result, canceled);
    assert.equal(Object.values(fixture.calls).flat().length, 0);
    assert.equal(fixture.transitions.length, 0);
    assert.throws(() => polishingPipeline.validateResumeAction(canceled, null));
  });

  test(`${mode} terminal confirmation cannot mutate the repository or reach handoff`, async (t) => {
    const fixture = await createFixture(t, {
      mode,
      worker: [
        ...bootstrap(),
        polishingCompleted(),
        ...candidate(),
        finalizationPassed(),
        ...(mode === "lazy" ? [cleanConfirmation()] : []),
      ],
      async onRoleRun() {
        if (fixture.currentRun.activeTurn.phase === "confirm")
          await writeFile(
            join(fixture.projectPath, "forbidden.txt"),
            "changed\n",
          );
      },
    });
    const result = await fixture.run();
    assert.equal(result.pause.reason, "read_only_agent_mutated_repository");
    assert.equal(
      fixture.transitions.some(
        ({ patch }) => patch.pipelineState?.workflowState === "HANDOFF",
      ),
      false,
    );
    assert.equal(result.pipelineState.reviewedFingerprint, null);
  });
}

test("polishing exposes all supported modes", () => {
  assert.deepEqual(polishingPipeline.settings.mode.values, [
    "independent",
    "lazy",
    "combined",
  ]);
  assert.equal(polishingPipeline.settings.mode.validate("combined"), true);
});
