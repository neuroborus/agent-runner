import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  attachAuthentication,
  authenticationFailure,
} from "../../../test/support/authentication.js";
import {
  attachOutputExhaustion,
  outputExhaustion,
} from "../../../test/support/output-exhaustion.js";

import { getPipeline } from "../../../src/index.js";
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
    // Independent finding resolution retains its blockers in a ready report
    // checkpoint; resume restates the report instead of replaying the repair.
    assert.equal(
      reconciled.pipelineState.workflowState,
      mode === "lazy" ? "CHECK_AND_FIX" : "RESOLVE_FINDINGS",
    );
    assert.equal(
      reconciled.pipelineState.resolutionCorrection?.stage,
      mode === "lazy" ? undefined : "ready",
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
      repository: "git",
      stateStore: "disk",
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
    const staging = [];
    fixture.runtime.git = {
      ...fixture.runtime.git,
      async stagePolishingHandoff(options) {
        staging.push(options);
        throw new Error("Staging is not authorized in this test.");
      },
    };
    await fixture.run();
    const confirming = fixture.transitions.find(
      ({ patch }) => patch.pipelineState?.workflowState === "CONFIRM",
    ).patch.pipelineState;
    assert.notEqual(confirming.finalizedFingerprint, null);
    const result = await fixture.recover();
    assert.deepEqual(result.pause, {
      reason: "read_only_agent_mutated_repository",
      code: "ERR_READ_ONLY_REPOSITORY_CHANGED",
      snapshotChanges: ["untracked-content"],
    });
    assert.doesNotThrow(() => polishingPipeline.workflow.validateRun(result));
    const projected = getPipeline("polishing").projections.pause(result);
    assert.equal(projected.code, "ERR_READ_ONLY_REPOSITORY_CHANGED");
    assert.deepEqual(projected.evidence, [
      "Changed snapshot domains: untracked-content.",
    ]);
    assert.deepEqual(projected.nextActions, [
      { type: "start-new-run", requirement: "uncontaminated-worktree" },
    ]);
    assert.equal(
      fixture.transitions.at(-1).options.activity.message,
      "Polishing paused: read_only_agent_mutated_repository. Changed snapshot domains: untracked-content.",
    );
    assert.equal(
      result.pipelineState.finalizedFingerprint,
      confirming.finalizedFingerprint,
    );
    assert.deepEqual(
      result.pipelineState.finalizationResult,
      confirming.finalizationResult,
    );
    assert.equal(
      fixture.transitions.some(
        ({ patch }) => patch.pipelineState?.workflowState === "HANDOFF",
      ),
      false,
    );
    assert.equal(result.pipelineState.reviewedFingerprint, null);
    assert.equal(result.pipelineState.reviewResult, null);
    assert.deepEqual(staging, []);
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

test("an acknowledged source child remains usable after a no-turn-effect disposition", async (t) => {
  for (const kind of ["authentication", "output", "backend"]) {
    const exhausted = kind === "output";
    const f = await createFixture(t, {
      mode: "lazy",
      sourceSession: SOURCE_SESSION,
      async onRoleRun(role, request, count) {
        assert.equal(role, "worker");
        if (count === 1)
          await request.onSessionCreated("acknowledged-worker-child");
        else {
          assert.deepEqual(request.session, {
            mode: "continue",
            id: "acknowledged-worker-child",
          });
          assert.equal(request.prompt, request.recoveryPrompt);
        }
        if (kind === "backend")
          throw Object.assign(new Error("controlled pre-turn backend loss"), {
            recoverable: true,
          });
        throw exhausted
          ? outputExhaustion({ effect: "none" })
          : authenticationFailure({ effect: "none" });
      },
    });
    attachAuthentication(f);
    attachOutputExhaustion(f);
    const paused = await f.run();
    assert.equal(
      paused.pause.reason,
      kind === "backend"
        ? "backend_unavailable"
        : exhausted
          ? "output_exhausted"
          : "authentication_required",
    );
    assert.equal(paused.pipelineState.lazySourceForkConsumed, true);
    assert.equal(paused.pipelineState.authenticationSourceForkRecovery, null);
    assert.equal((await f.run()).sessionLineage.children.length, 1);
    assert.equal(f.calls.worker.length, 2);
  }
});
