import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { createGitService } from "../../../src/git/index.js";
import {
  migratePlanExecutionStateV19,
  runPlanExecution,
} from "../src/index.js";
import {
  prepareImplementationRecovery,
  recoveredImplementationEvidence,
  validImplementationEvidence,
} from "../src/implementation-evidence.js";
import {
  checkAndFix,
  cleanConfirmation,
  createRealGitFixture,
  executeFile,
  finalizationPassed,
  implementationCompleted,
  createLegacyRecoveryFixture,
  removeUnchangedEvents,
  reviewFindings,
  reviewApproved,
  resolution,
} from "./support/index.js";

const calls = (fixture) => Object.values(fixture.calls).flat();
const git = (fixture, ...args) =>
  executeFile("git", ["-C", fixture.projectPath, ...args]);
const afterImplementation = (mode) => [
  ...(mode === "independent" ? [] : [checkAndFix(), cleanConfirmation()]),
  finalizationPassed(),
];
function assertNoop(run, fixture) {
  assert.equal(
    run.pause?.reason,
    "plan_revision_required",
    JSON.stringify(run.pause),
  );
  assert.equal(run.pipelineState.currentStep, 1);
  assert.deepEqual(run.pipelineState.completedCommits, []);
  assert.equal(run.pipelineState.stepImplementation.accepted, false);
  assert.equal(
    calls(fixture).filter(({ access }) => access === "workspace-write").length,
    1,
  );
  assert.ok(
    calls(fixture).every(
      ({ prompt }) => !prompt.includes("Run the complete project finalization"),
    ),
  );
}

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} initial no-op pauses before convergence or finalization`, async (t) => {
    const fixture = await createRealGitFixture(t, {
      mode,
      implementationWrites: false,
    });
    const before = (await git(fixture, "rev-parse", "HEAD")).stdout;
    const run = await fixture.run();
    assertNoop(run, fixture);
    assert.equal((await git(fixture, "rev-parse", "HEAD")).stdout, before);
    const count = calls(fixture).length;
    assert.equal((await fixture.run()).pause.reason, "plan_revision_required");
    assert.equal(calls(fixture).length, count);
  });

  test(`${mode} already-present content under another subject is a no-op`, async (t) => {
    const fixture = await createRealGitFixture(t, { mode });
    await writeFile(
      join(fixture.projectPath, "implementation-1.txt"),
      "implemented step 1\n",
    );
    await git(fixture, "add", "implementation-1.txt");
    await git(fixture, "commit", "-qm", "chore(test): existing behavior");
    assertNoop(await fixture.run(), fixture);
  });

  test(`${mode} interrupted partial implementation retains its original baseline`, async (t) => {
    let started = false;
    const fixture = await createRealGitFixture(t, {
      mode,
      implementationWrites: false,
      workWorker: [implementationCompleted(), ...afterImplementation(mode)],
      async onRoleRun(_role, request) {
        if (request.access === "workspace-write" && !started) {
          started = true;
          assert.ok(fixture.currentRun.pipelineState.stepImplementation);
          await writeFile(
            join(request.cwd, "partial.txt"),
            "durable partial work\n",
          );
          throw new Error("interrupted implementation");
        }
      },
    });
    await assert.rejects(fixture.run(), /interrupted implementation/u);
    const paused = fixture.currentRun;
    const original = structuredClone(paused.pipelineState.stepImplementation);
    assert.equal(original.accepted, false);
    // Recreate a lost-owner turn after its mutable repository baseline was updated.
    Object.assign(fixture.currentRun, {
      activeTurn: { role: "worker", phase: "implement" },
      pause: null,
      pipelineState: { ...paused.pipelineState, workflowState: "IMPLEMENT" },
    });
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.equal(done.pipelineState.completedCommits.length, 1);
    assert.equal(done.pipelineState.stepImplementation, null);
    assert.ok(
      fixture.transitions.some(
        ({ patch }) =>
          patch?.pipelineState?.stepImplementation?.contentFingerprint ===
          original.contentFingerprint,
      ),
    );
  });
}

test("missing legacy evidence stops before any writable turn", async (t) => {
  const fixture = await createRealGitFixture(t, {
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  const paused = await fixture.run();
  fixture.runtime.trustedValidation.inspectRequirements = async () => ({
    status: "READY",
    blockers: [],
  });
  fixture.persistPipelineState(migratePlanExecutionStateV19(paused));
  const count = calls(fixture).length;
  const run = await fixture.run();
  assert.equal(run.pause.reason, "plan_revision_required");
  assert.equal(calls(fixture).length, count);
  assert.deepEqual(run.pipelineState.completedCommits, []);
});

test("stop recovery does not start evidence discovery or providers", async (t) => {
  const fixture = await createRealGitFixture(t, {
    onRequirementInspection: () => ({ status: "BLOCKED", blockers: [] }),
  });
  const paused = await fixture.run();
  fixture.persistPipelineState(migratePlanExecutionStateV19(paused));
  const count = calls(fixture).length;
  const stopped = await runPlanExecution({
    run: fixture.currentRun,
    runtime: fixture.runtime,
    operatorStop: true,
  });
  assert.equal(stopped.pipelineState.stepImplementation, null);
  assert.equal(calls(fixture).length, count);
});

test("content comparison ignores staging placement", async (t) => {
  const fixture = await createRealGitFixture(t);
  const service = createGitService();
  const options = { projectPath: fixture.projectPath };
  await writeFile(join(fixture.projectPath, "staging.txt"), "same content\n");
  const unstaged = await service.contentFingerprint(options);
  await git(fixture, "add", "staging.txt");
  assert.equal(await service.contentFingerprint(options), unstaged);
});

function recoveryHistory({ accepted = false } = {}) {
  const baseline = {
    head: "a".repeat(40),
    contentFingerprint: "b".repeat(64),
    clean: true,
  };
  const state = {
    completedCommits: [],
    canonicalPlan: "plan",
    repositoryBaseline: null,
    workflowState: "CLARIFY",
    preflightComplete: false,
    implementationDirection: null,
    implementationEvidenceLegacy: true,
    stepImplementation: null,
  };
  const run = {
    runId: "run",
    projectPath: "/project",
    taskPath: "/task",
    revision: 1,
    activeTurn: null,
    pipelineState: state,
  };
  const states = [
    run,
    {
      ...run,
      activeTurn: { role: "worker", phase: "implement" },
      pipelineState: {
        ...state,
        preflightComplete: true,
        canonicalPlan: "plan",
        workflowState: "IMPLEMENT",
        repositoryBaseline: baseline,
      },
    },
  ];
  states.push({
    ...run,
    pipelineState: {
      ...states[1].pipelineState,
      workflowState: accepted ? "REVIEW" : "IMPLEMENT",
      repositoryBaseline: {
        ...baseline,
        clean: false,
        contentFingerprint: "c".repeat(64),
      },
    },
  });
  const events = states.map((value, index) => ({
    runId: "run",
    revision: index + 1,
    state: { ...value, revision: index + 1 },
  }));
  return { run: events.at(-1).state, events };
}
for (const accepted of [false, true]) {
  test(`validated journal recovers original evidence with accepted=${accepted}`, () => {
    const history = recoveryHistory({ accepted });
    prepareImplementationRecovery(history.run, history, (run) => run);
    assert.deepEqual(recoveredImplementationEvidence(history.run), {
      step: 1,
      head: "a".repeat(40),
      contentFingerprint: "b".repeat(64),
      accepted,
    });
  });
}
test("missing, truncated, or mismatched journals cannot manufacture original evidence", () => {
  for (const alter of [
    (history) => {
      history.events.shift();
    },
    (history) => {
      history.events[1].state.activeTurn = null;
    },
    (history) => {
      history.events[1].state.pipelineState.repositoryBaseline.head =
        "d".repeat(40);
    },
  ]) {
    const history = recoveryHistory();
    alter(history);
    prepareImplementationRecovery(history.run, history, (run) => run);
    assert.equal(recoveredImplementationEvidence(history.run), null);
  }
});

test("unchanged finding fixes remain valid after initial implementation acceptance", async (t) => {
  const fixture = await createRealGitFixture(t, {
    workWorker: [
      implementationCompleted(),
      resolution({ id: "R1", decision: "FIX" }),
      finalizationPassed(),
    ],
    workReviewer: [reviewFindings(), reviewApproved()],
  });
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.equal(done.pipelineState.completedCommits.length, 1);
});

test("step evidence is persisted before implementation registration and survives a failed registration", async (t) => {
  const fixture = await createRealGitFixture(t);
  const start = fixture.runtime.startAgentTurn;
  let failed = false;
  fixture.runtime.startAgentTurn = async function (turn, options) {
    if (turn.phase === "implement" && !failed) {
      failed = true;
      assert.ok(fixture.currentRun.pipelineState.stepImplementation);
      throw Object.assign(new Error("registration failed"), {
        code: "ERR_RUN_REVISION_CHANGED",
      });
    }
    return start.call(this, turn, options);
  };
  await assert.rejects(fixture.run(), /registration failed/u);
  const original = structuredClone(
    fixture.currentRun.pipelineState.stepImplementation,
  );
  const done = await fixture.run();
  assert.equal(
    done.pipelineState.workflowState,
    "DONE",
    JSON.stringify(done.pause),
  );
  assert.ok(
    fixture.transitions.some(
      ({ patch }) =>
        patch?.pipelineState?.stepImplementation?.accepted === true &&
        patch.pipelineState.stepImplementation.contentFingerprint ===
          original.contentFingerprint,
    ),
  );
});

test("legacy accepted no-op evidence cannot authorize further writes", () => {
  const history = recoveryHistory({ accepted: true });
  history.events.at(
    -1,
  ).state.pipelineState.repositoryBaseline.contentFingerprint = "b".repeat(64);
  prepareImplementationRecovery(history.run, history, (run) => run);
  assert.equal(recoveredImplementationEvidence(history.run), null);
});

test("authentic legacy journal restores evidence before a new commit effect", async (t) => {
  const fixture = await createLegacyRecoveryFixture(t, { steps: 1 });
  await fixture.rewrite(({ events }) => {
    for (const event of events) {
      event.state.pipelineStateVersion = 19;
      delete event.state.pipelineState.stepImplementation;
      delete event.state.pipelineState.implementationEvidenceLegacy;
    }
    removeUnchangedEvents(events);
  });
  const before = await fixture.bytes();
  assert.deepEqual(await fixture.recoveryAction(), [
    { type: "resume", action: null },
  ]);
  assert.deepEqual(await fixture.bytes(), before);
  const { run } = await fixture.openRunner().resume({ runId: fixture.runId });
  assert.equal(
    run.pipelineState.workflowState,
    "DONE",
    JSON.stringify(run.pause),
  );
  const history = await fixture.history();
  const restored = history.events.find(
    ({ state }) => state.pipelineState.stepImplementation?.accepted,
  );
  assert.ok(restored);
  assert.equal(restored.state.pipelineState.stepImplementation.step, 1);
  assert.equal(run.pipelineState.completedCommits.length, 1);
});

for (const mode of ["independent", "lazy", "combined"]) {
  test(`${mode} consumed legacy commit settles before evidence discovery for the next step`, async (t) => {
    let interrupted = true;
    const fixture = await createRealGitFixture(t, {
      mode,
      plan: "## Commit 1: feat(test): add behavior\n\nFirst.\n\n## Commit 2: feat(test): extend behavior\n\nSecond.",
      workWorker: [
        implementationCompleted(),
        ...afterImplementation(mode),
        implementationCompleted(),
        ...afterImplementation(mode),
      ],
      onCommitVerify() {
        if (interrupted) {
          interrupted = false;
          throw Object.assign(new Error("Verification interrupted"), {
            code: "ERR_FAKE_COMMIT_VERIFICATION",
          });
        }
      },
    });
    const paused = await fixture.run();
    assert.equal(paused.pipelineState.pendingCommit.status, "consumed");
    fixture.persistPipelineState(migratePlanExecutionStateV19(paused));
    const done = await fixture.run();
    assert.equal(
      done.pipelineState.workflowState,
      "DONE",
      JSON.stringify(done.pause),
    );
    assert.equal(done.pipelineState.completedCommits.length, 2);
    assert.equal(
      calls(fixture).filter(({ access }) => access === "local-commit").length,
      2,
    );
    const second = fixture.transitions.find(
      ({ patch }) => patch?.pipelineState?.stepImplementation?.step === 2,
    );
    assert.equal(
      second.patch.pipelineState.stepImplementation.head,
      done.pipelineState.completedCommits[0],
    );
  });
}

test("a legacy run before preflight safely starts fresh evidence", async (t) => {
  const fixture = await createRealGitFixture(t);
  fixture.persistPipelineState(
    migratePlanExecutionStateV19(fixture.currentRun),
  );
  assert.equal(
    fixture.currentRun.pipelineState.implementationEvidenceLegacy,
    false,
  );
  assert.equal((await fixture.run()).pipelineState.workflowState, "DONE");
});

test("persisted implementation evidence rejects another step, HEAD, or malformed content", () => {
  const state = {
    completedCommits: [],
    repositoryBaseline: { head: "a".repeat(40) },
  };
  const evidence = {
    step: 1,
    head: state.repositoryBaseline.head,
    contentFingerprint: "b".repeat(64),
    accepted: false,
  };
  assert.equal(validImplementationEvidence(evidence, state), true);
  for (const change of [
    { step: 2 },
    { head: "c".repeat(40) },
    { contentFingerprint: "invalid" },
    { accepted: "yes" },
    { authority: true },
  ]) {
    assert.equal(
      validImplementationEvidence({ ...evidence, ...change }, state),
      false,
    );
  }
  assert.equal(
    validImplementationEvidence(evidence, { ...state, completedCommits: null }),
    false,
  );
});

test("legacy environment pause before implementation retains its journal-proven clean baseline", () => {
  const history = recoveryHistory();
  history.events[1].state.activeTurn = null;
  const current = history.run.pipelineState;
  current.workflowState = "WAITING_FOR_USER";
  current.repositoryBaseline = structuredClone(
    history.events[1].state.pipelineState.repositoryBaseline,
  );
  history.run.pause = {
    reason: "environment_blocked",
    resumeState: "IMPLEMENT",
  };
  prepareImplementationRecovery(history.run, history, (run) => run);
  assert.deepEqual(recoveredImplementationEvidence(history.run), {
    step: 1,
    head: "a".repeat(40),
    contentFingerprint: "b".repeat(64),
    accepted: false,
  });
});
